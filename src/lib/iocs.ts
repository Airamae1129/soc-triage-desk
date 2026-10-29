// IOC extraction with the same rules as the frontend engine (frontend/src/soc/engine.js
// analyze()), so the server and the browser agree on what counts as an indicator.

export const uniq = <T>(a: (T | null | undefined | false | "")[]): T[] => [...new Set(a.filter(Boolean) as T[])];

export const isIp = (s: string) => /^(\d{1,3}\.){3}\d{1,3}$/.test(s) && s.split(".").every((o) => +o <= 255);

/** RFC1918, loopback, link-local, CGNAT, "this network" and multicast/reserved (same as the frontend). */
export const isPrivateIp = (ip: string) =>
  /^(10\.|127\.|0\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip) ||
  /^(22[4-9]|2[3-5]\d)\./.test(ip);

export const DOMAIN_RE =
  /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|example|co|us|uk|de|ph|online|site|club|cc|tk|me|app|dev|cloud)\b/gi;
export const URL_RE = /https?:\/\/[^\s"'<>]+/gi;
export const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
export const SHA256_RE = /\b[a-f0-9]{64}\b/gi;
export const SHA1_RE = /\b[a-f0-9]{40}\b/gi;
export const MD5_RE = /\b[a-f0-9]{32}\b/gi;

const HOST_K = ["host", "hostname", "computer", "computername", "devicename", "workstationname", "shost", "endpoint.name"];
const USER_K = ["user", "username", "suser", "duser", "targetusername", "accountname", "subjectusername", "upn", "userprincipalname", "srcuser", "accountupn"];

/** key=value / JSON / CEF line parser (same as the frontend kv()). Keys are lower-cased. */
export function kv(line: string): Record<string, string> {
  const o: Record<string, string> = {};
  const t = line.trim();
  if (t.startsWith("{")) {
    try {
      const j = JSON.parse(t) as Record<string, unknown>;
      for (const k of Object.keys(j)) o[k.toLowerCase()] = String(j[k]);
      return o;
    } catch { /* not JSON, fall through */ }
  }
  let body = t;
  const cef = t.match(/CEF:\d+\|([^|]*)\|([^|]*)\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|(.*)$/);
  if (cef) { o._vendor = `${cef[1]} ${cef[2]}`.trim(); body = cef[3] ?? ""; }
  const re = /([A-Za-z_][\w.]*)=("([^"]*)"|[^\s"]*)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body))) o[m[1]!.toLowerCase()] = m[3] !== undefined ? m[3] : (m[2] ?? "");
  return o;
}
const pick = (o: Record<string, string>, keys: string[]) => { for (const k of keys) if (o[k]) return o[k]; return undefined; };

/** ATT&CK technique patterns (same regexes as the frontend RULES), used to rank log lines. */
export const TECHNIQUE_RES: RegExp[] = [
  /\b4625\b|failed (logon|login|password)|logon fail|brute.?force|invalid (password|user)|authentication fail|account failed to log on/i,
  /\b4624\b|successfully logged on|successful (logon|login)/i,
  /powershell/i,
  /mimikatz|sekurlsa|lsass|comsvcs\.dll.*minidump/i,
  /certutil.*(urlcache|-split|-f\b)|bitsadmin.*transfer|invoke-webrequest|\biwr\b|downloadfile|downloadstring|\bwget\b|curl\s+-?\S*\s*https?:/i,
  /vssadmin.*delete|wbadmin.*delete|bcdedit.*recoveryenabled|shadowcopy.*delete/i,
  /schtasks.*\/create|\b4698\b|register-scheduledtask/i,
  /currentversion\\+run|reg(\.exe)?\s+add.*\\run/i,
  /\b4720\b|net1?(\.exe)?\s+user\s+\S+.*\/add|new-localuser|user account was created/i,
  /psexec|\\\\[\w.-]+\\(admin|c|ipc)\$|\b514[05]\b/i,
  /rundll32|regsvr32|mshta|installutil|msiexec.*https?:/i,
  /set-mppreference.*disable|disablerealtimemonitoring|sc(\.exe)?\s+(stop|config)\s+(windefend|sense)|tamper/i,
  /(dstport|dpt|destinationport|dest_port|remoteport)["=: ]+(4444|1337|31337|6666|5555|9001)\b|:(4444|31337)\b/i,
];

export interface Extracted {
  ips: { external: string[]; internal: string[] };
  domains: string[];
  urls: string[];
  hashes: string[];
  hosts: string[];
  users: string[];
}

export function extractIocs(text: string): Extracted {
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const rows = lines.map(kv);
  const allIps = uniq(text.match(IPV4_RE) ?? []).filter(isIp);
  const urls = uniq((text.match(URL_RE) ?? []).map((u) => u.replace(/[),;]+$/, "")));
  const domains = uniq(
    [...(text.match(DOMAIN_RE) ?? []), ...urls.map((u) => { try { return new URL(u).hostname; } catch { return null; } })]
      .map((d) => d && d.toLowerCase()),
  ).filter((d) => !isIp(d));
  const hashes = uniq([...(text.match(SHA256_RE) ?? []), ...(text.match(SHA1_RE) ?? []), ...(text.match(MD5_RE) ?? [])].map((x) => x.toLowerCase()));
  const hosts = uniq(rows.map((r) => pick(r, HOST_K)).filter((x) => x && !isIp(x)));
  const users = uniq(rows.map((r) => pick(r, USER_K)).filter((u) => u && !["-", "n/a", "none"].includes(u.toLowerCase())));
  return { ips: { external: allIps.filter((i) => !isPrivateIp(i)), internal: allIps.filter(isPrivateIp) }, domains, urls, hashes, hosts, users };
}

/** Every IP, domain and hash in a text (used by the AI output validator). */
export function indicatorsIn(text: string): Set<string> {
  const e = extractIocs(text);
  return new Set([...e.ips.external, ...e.ips.internal, ...e.domains, ...e.hashes].map((x) => x.toLowerCase()));
}
