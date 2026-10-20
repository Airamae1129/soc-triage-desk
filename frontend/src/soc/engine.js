import { isIp, isPrivateIp, joinAnd, numWord } from "./util";

export const RULES = [
  { id: "T1110", name: "Brute Force", tactic: "Credential Access", w: 30, re: /\b4625\b|failed (logon|login|password)|logon fail|brute.?force|invalid (password|user)|authentication fail|account failed to log on/i, action: "Reset the targeted account password, enforce MFA and block the source IP", hunt: { k: "fail" } },
  { id: "T1078", name: "Valid Accounts", tactic: "Initial Access", w: 20, re: /\b4624\b|successfully logged on|successful (logon|login)/i, action: "Confirm with the account owner whether the successful logon was theirs; disable the account if not", hunt: { k: "ok" } },
  { id: "T1059.001", name: "PowerShell", tactic: "Execution", w: 25, re: /powershell/i, action: "Collect the full PowerShell command line and script block logs (Event 4104) from the host", hunt: { k: "cmd", t: ["-enc", "-EncodedCommand", "IEX", "DownloadString", "-w hidden"] } },
  { id: "T1003.001", name: "LSASS Memory", tactic: "Credential Access", w: 45, re: /mimikatz|sekurlsa|lsass|comsvcs\.dll.*minidump/i, action: "Treat all credentials used on the host as compromised; reset them, starting with privileged accounts", hunt: { k: "cmd", t: ["mimikatz", "sekurlsa", "lsass", "comsvcs.dll"] } },
  { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control", w: 25, re: /certutil.*(urlcache|-split|-f\b)|bitsadmin.*transfer|invoke-webrequest|\biwr\b|downloadfile|downloadstring|\bwget\b|curl\s+-?\S*\s*https?:/i, action: "Retrieve and hash the downloaded file; block the download URL and domain at the proxy", hunt: { k: "cmd", t: ["certutil", "urlcache", "bitsadmin", "Invoke-WebRequest", "DownloadFile"] } },
  { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact", w: 45, re: /vssadmin.*delete|wbadmin.*delete|bcdedit.*recoveryenabled|shadowcopy.*delete/i, action: "Isolate the host immediately; shadow copy deletion is a common ransomware precursor", hunt: { k: "cmd", t: ["vssadmin", "wbadmin", "bcdedit", "shadowcopy"] } },
  { id: "T1053.005", name: "Scheduled Task", tactic: "Persistence", w: 20, re: /schtasks.*\/create|\b4698\b|register-scheduledtask/i, action: "Export and remove the scheduled task after the client approves; check its action binary", hunt: { k: "cmd", t: ["schtasks", "/create", "Register-ScheduledTask"] } },
  { id: "T1547.001", name: "Registry Run Keys", tactic: "Persistence", w: 20, re: /currentversion\\+run|reg(\.exe)?\s+add.*\\run/i, action: "Remove the Run key value and the binary it points to", hunt: { k: "cmd", t: ["CurrentVersion\\Run", "reg add"] } },
  { id: "T1136", name: "Create Account", tactic: "Persistence", w: 25, re: /\b4720\b|net1?(\.exe)?\s+user\s+\S+.*\/add|new-localuser|user account was created/i, action: "Disable the newly created account and confirm whether it was authorized", hunt: { k: "cmd", t: ["net user", "/add", "New-LocalUser"] } },
  { id: "T1021.002", name: "SMB/Windows Admin Shares", tactic: "Lateral Movement", w: 25, re: /psexec|\\\\[\w.-]+\\(admin|c|ipc)\$|\b514[05]\b/i, action: "Review admin share access from the host to other systems and block SMB between workstations", hunt: { k: "cmd", t: ["psexec", "ADMIN$", "C$"] } },
  { id: "T1218", name: "System Binary Proxy Execution", tactic: "Defense Evasion", w: 20, re: /rundll32|regsvr32|mshta|installutil|msiexec.*https?:/i, action: "Review what the signed binary loaded and from where", hunt: { k: "cmd", t: ["rundll32", "regsvr32", "mshta", "installutil"] } },
  { id: "T1562.001", name: "Disable or Modify Tools", tactic: "Defense Evasion", w: 35, re: /set-mppreference.*disable|disablerealtimemonitoring|sc(\.exe)?\s+(stop|config)\s+(windefend|sense)|tamper/i, action: "Re-enable endpoint protection and confirm tamper protection is on", hunt: { k: "cmd", t: ["Set-MpPreference", "DisableRealtimeMonitoring", "WinDefend"] } },
  { id: "T1571", name: "Non-Standard Port", tactic: "Command and Control", w: 20, re: /(dstport|dpt|destinationport|dest_port|remoteport)["=: ]+(4444|1337|31337|6666|5555|9001)\b|:(4444|31337)\b/i, action: "Block the outbound non-standard port at the firewall and find the process that opened it", hunt: { k: "port", t: ["4444", "1337", "31337", "6666", "5555", "9001"] } },
];

const MITIG = /quarantin|\bblocked\b|\bdenied\b|\bdeny\b|prevented|remediated/i;
const FP_RE = /false positive|benign|expected|authori[sz]ed|legitimate|known (good|software|activity)|business (use|need)|whitelist|allowlist/i;
const TP_RE = /true positive|confirmed (malicious|compromise)|compromised|malicious activity confirmed|not authori[sz]ed|unauthori[sz]ed/i;
const FP_VERDICTS = ["False Positive", "Likely False Positive", "Benign", "Benign · Monitor"];
const NORMAL_ACTIONS = ["close", "accept", "client-rst", "server-rst", "timeout", "allow", "allowed", "built", "teardown", "pass", "permit"];

export function kv(line) {
  const o = {};
  const t = line.trim();
  if (t.startsWith("{")) {
    try {
      const j = JSON.parse(t);
      Object.keys(j).forEach((k) => (o[k.toLowerCase()] = String(j[k])));
      return o;
    } catch {}
  }
  let body = t;
  const cef = t.match(/CEF:\d+\|([^|]*)\|([^|]*)\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|(.*)$/);
  if (cef) { o._vendor = `${cef[1]} ${cef[2]}`.trim(); body = cef[3]; }
  const re = /([A-Za-z_][\w.]*)=("([^"]*)"|[^\s"]*)/g;
  let m;
  while ((m = re.exec(body))) o[m[1].toLowerCase()] = m[3] !== undefined ? m[3] : m[2];
  return o;
}
const pick = (o, keys) => { for (const k of keys) if (o[k] != null && o[k] !== "") return o[k]; return undefined; };

export function parseTs(line, o) {
  if (o.date && o.time && /^\d{4}-\d{2}-\d{2}$/.test(o.date)) {
    const tz = o.tz ? o.tz.replace(/^([+-]\d{2}):?(\d{2})$/, "$1:$2") : "+08:00";
    const d = new Date(`${o.date}T${o.time}${tz}`);
    if (!isNaN(d)) return d;
  }
  const m = line.match(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?/);
  if (m) {
    let s = m[0].replace(" ", "T");
    if (!m[2]) s += "+08:00";
    else s = s.replace(/([+-]\d{2})(\d{2})$/, "$1:$2");
    const d = new Date(s);
    if (!isNaN(d)) return d;
  }
  const rt = o.rt || o.eventtime;
  if (rt && /^\d{13}$/.test(rt)) return new Date(+rt);
  return null;
}

const uniq = (a) => [...new Set(a.filter(Boolean))];
const base = (p) => String(p).split(/[\\/]/).pop();
const PROTO = { 6: "TCP", 17: "UDP", 1: "ICMP" };

function parseFlows(rows) {
  const flows = [];
  rows.forEach(({ o }) => {
    const src = pick(o, ["srcip", "src", "sourceip", "src_ip", "source_address"]);
    const dst = pick(o, ["dstip", "dst", "destinationip", "dst_ip", "dest_ip", "destination_address"]);
    if (!src || !dst || !isIp(src) || !isIp(dst)) return;
    flows.push({
      src, dst,
      port: pick(o, ["dstport", "dpt", "destinationport", "dest_port", "destination_port"]),
      proto: pick(o, ["proto", "protocol", "transportprotocol"]),
      service: pick(o, ["service", "app", "applicationprotocol"]),
      action: pick(o, ["action", "act", "deviceaction"]),
      sent: +pick(o, ["sentbyte", "out", "sentbytes", "bytesout", "bytes_out"]) || 0,
      rcvd: +pick(o, ["rcvdbyte", "in", "receivedbytes", "bytesin", "bytes_in"]) || 0,
      appcat: pick(o, ["appcat", "applicationcategory"]),
      url: pick(o, ["url", "requesturl", "request", "hostname"]),
      user: pick(o, ["user", "suser", "sourceusername", "srcuser", "unauthuser"]),
      vendor: o.devname || o.devid ? "Fortigate" : o._vendor || (o.devicevendor ? `${o.devicevendor} ${o.deviceproduct || ""}`.trim() : undefined),
    });
  });
  return flows;
}

function summarizeFlows(flows) {
  const cnt = (arr) => { const m = {}; arr.forEach((x) => (m[x] = (m[x] || 0) + 1)); return Object.entries(m).sort((a, b) => b[1] - a[1]); };
  const extDst = cnt(flows.map((f) => f.dst).filter((d) => !isPrivateIp(d)));
  const dst = extDst.length ? extDst[0][0] : cnt(flows.map((f) => f.dst))[0][0];
  const toDst = flows.filter((f) => f.dst === dst);
  const srcMap = {};
  toDst.forEach((f) => {
    const s = (srcMap[f.src] = srcMap[f.src] || { ip: f.src, conns: 0, sent: 0, rcvd: 0 });
    s.conns++; s.sent += f.sent; s.rcvd += f.rcvd;
  });
  const sources = Object.values(srcMap).sort((a, b) => b.conns - a.conns);
  const sent = toDst.reduce((a, f) => a + f.sent, 0);
  const rcvd = toDst.reduce((a, f) => a + f.rcvd, 0);
  const appcatAll = toDst.map((f) => (f.appcat && f.appcat.toLowerCase() !== "unknown" ? f.appcat : null));
  return {
    dst, sources, total: toDst.length, sent, rcvd,
    ports: uniq(toDst.map((f) => f.port)),
    protos: uniq(toDst.map((f) => PROTO[f.proto] || (f.proto ? String(f.proto).toUpperCase() : null))),
    service: uniq(toDst.map((f) => f.service))[0] || (toDst[0]?.port === "443" ? "HTTPS" : "TCP"),
    actions: cnt(toDst.map((f) => f.action).filter(Boolean)),
    appcats: cnt(appcatAll.filter(Boolean)),
    appcatUnknown: appcatAll.filter((x) => !x).length,
    urls: uniq(toDst.map((f) => f.url)),
    users: uniq(toDst.map((f) => f.user)),
    vendor: uniq(toDst.map((f) => f.vendor))[0] || "Firewall",
    direction: rcvd > 3 * sent ? "inbound" : sent > 3 * rcvd ? "outbound" : "balanced",
    allNormal: toDst.every((f) => !f.action || NORMAL_ACTIONS.includes(f.action.toLowerCase())),
  };
}

const HOST_K = ["host", "hostname", "computer", "computername", "devicename", "workstationname", "shost", "endpoint.name"];
const USER_K = ["user", "username", "suser", "duser", "targetusername", "accountname", "subjectusername", "upn", "userprincipalname", "srcuser", "accountupn"];
const PARENT_K = ["parent", "parentprocess", "parentprocessname", "parentimage", "initiatingprocessfilename", "parentbasefilename", "parent_process"];
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|example|co|us|uk|de|ph|online|site|club|cc|tk|me|app|dev|cloud)\b/gi;

export function analyze(form) {
  const text = form.rawLogs || "";
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const rows = lines.map((raw) => {
    const o = kv(raw);
    return { raw, o, ts: parseTs(raw, o), techs: RULES.filter((r) => r.re.test(raw)).map((r) => r.id), blocked: MITIG.test(raw) };
  });
  const techniques = RULES.map((r) => ({ ...r, hits: rows.filter((x) => x.techs.includes(r.id)).length })).filter((t) => t.hits);
  const allIps = uniq(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).filter(isIp);
  const ipCount = (ip) => rows.filter((r) => r.raw.includes(ip)).length;
  const urls = uniq((text.match(/https?:\/\/[^\s"'<>]+/gi) || []).map((u) => u.replace(/[),;]+$/, "")));
  const domains = uniq([...(text.match(DOMAIN_RE) || []), ...urls.map((u) => { try { return new URL(u).hostname; } catch { return null; } })].map((d) => d && d.toLowerCase())).filter((d) => !isIp(d));
  const sha = uniq((text.match(/\b[a-f0-9]{64}\b/gi) || []).map((h) => h.toLowerCase()));
  const md5 = uniq((text.match(/\b[a-f0-9]{32}\b/gi) || []).map((h) => h.toLowerCase()));
  const hashes = [...sha.map((v) => ({ type: "SHA-256", value: v })), ...md5.map((v) => ({ type: "MD5", value: v }))];
  const hosts = uniq(rows.map((r) => pick(r.o, HOST_K)).filter((h) => h && !isIp(h)));
  const users = uniq(rows.map((r) => pick(r.o, USER_K)).filter((u) => u && !["-", "n/a", "none"].includes(u.toLowerCase())));
  const parents = uniq(rows.map((r) => pick(r.o, PARENT_K)).filter(Boolean).map(base));
  const timeline = rows.filter((r) => r.ts).sort((a, b) => a.ts - b.ts);
  const window = timeline.length ? { start: timeline[0].ts, end: timeline[timeline.length - 1].ts } : null;
  const flows = parseFlows(rows);
  const fw = flows.length && flows.length >= lines.length / 2 ? summarizeFlows(flows) : null;
  const ext = allIps.filter((i) => !isPrivateIp(i));
  const internal = allIps.filter(isPrivateIp);
  const mitigated = rows.some((r) => r.blocked);
  const findings = form.findings || "";

  let raw = techniques.reduce((a, t) => a + t.w + 4 * Math.min(t.hits - 1, 5), 0) + (ext.length ? 5 : 0);
  let score = 100 * (1 - Math.exp(-raw / 80));
  if (mitigated) score -= 8;
  if (TP_RE.test(findings)) score += 15;
  else if (FP_RE.test(findings)) score *= 0.4;
  score = Math.max(0, Math.min(100, Math.round(score)));

  const analystSet = form.verdict && form.verdict !== "Auto";
  let verdict = score >= 50 ? "Likely True Positive" : score >= 25 ? "Suspicious" : "Likely Benign";
  if (analystSet) {
    verdict = form.verdict;
    if (FP_VERDICTS.includes(verdict)) score = Math.min(score, 20);
    if (verdict === "True Positive") score = Math.max(score, 50);
  }
  const severity = score >= 75 ? "Critical" : score >= 50 ? "High" : score >= 25 ? "Medium" : "Low";
  const isFP = FP_VERDICTS.includes(verdict) || verdict === "Likely Benign";
  const confidence = analystSet ? "High" : techniques.length >= 3 ? "High" : techniques.length ? "Medium" : "Low";
  const closure = form.closure && form.closure !== "Auto" ? form.closure
    : verdict === "Benign · Monitor" ? "Monitoring for 24 hours"
    : isFP ? "Closing as NFA" : severity === "Critical" || severity === "High" ? "Escalated to client" : "Monitoring for 24 hours";

  const primaryIp = fw ? fw.dst : ext.sort((a, b) => ipCount(b) - ipCount(a))[0];
  const title = form.alertName || form.analyticsRule || "Untitled alert";
  let summary;
  if (fw) {
    summary = `${numWord(fw.sources.length)} internal host${fw.sources.length === 1 ? "" : "s"} made ${fw.total} ${fw.service} connection${fw.total === 1 ? "" : "s"} to external IP ${fw.dst}. Traffic was mostly ${fw.direction === "balanced" ? "balanced" : fw.direction === "inbound" ? "inbound (downloads)" : "outbound (uploads)"}${fw.allNormal ? " and sessions ended normally" : ""}.`;
  } else if (techniques.length) {
    summary = `Activity${hosts.length ? ` on ${joinAnd(hosts.slice(0, 2))}` : ""}${users.length ? ` by ${joinAnd(users.slice(0, 2))}` : ""} matched ${techniques.length} ATT&CK technique${techniques.length === 1 ? "" : "s"}: ${techniques.slice(0, 4).map((t) => t.name).join(", ")}${techniques.length > 4 ? " and more" : ""}.${mitigated ? " Security controls blocked part of the activity." : ""}`;
  } else {
    summary = lines.length ? `${lines.length} log line${lines.length === 1 ? "" : "s"} reviewed with no known attack technique matched${ext.length ? `; ${ext.length} external IP${ext.length === 1 ? "" : "s"} observed` : ""}.` : "No logs provided yet.";
  }

  let reason = (form.verdictReason || "").trim().split(/(?<=[.!?])\s+/)[0].replace(/[.\s]+$/, "");
  if (!reason) {
    if (fw && isFP) reason = `Traffic to \`${fw.dst}\`${form.owner ? ` (${form.owner})` : ""} matches normal ${fw.service} ${fw.direction === "inbound" ? "downloads" : "sessions"} with no malicious reputation`;
    else if (techniques.length) reason = `Logs match ${techniques.map((t) => t.id).join(", ")}${mitigated ? " and security controls only blocked part of the activity" : ""}`;
    else if (isFP) reason = "No malicious behavior was found in the logs";
    else reason = "The activity needs review against the client baseline";
  }

  const actions = [];
  const sorted = [...techniques].sort((a, b) => b.w - a.w);
  if (!isFP && hosts.length && (severity === "Critical" || severity === "High")) actions.push(`Isolate ${joinAnd(hosts.slice(0, 2))} from the network via EDR until triage completes`);
  sorted.forEach((t) => actions.push(t.action));
  if (mitigated && !isFP) actions.push("Verify the quarantine or block succeeded and no copies of the file remain");
  if (fw && isFP) {
    actions.push("Close the ticket as NFA and record the destination owner in the case notes");
    actions.push(`Add \`${fw.dst}\`${form.owner ? ` (${form.owner})` : ""} to the client's known-benign list if the client confirms it is expected`);
    actions.push(`Suggest tuning “${form.analyticsRule || title}” to suppress this destination range`);
  } else if (fw) {
    actions.push(`Confirm with the client whether traffic from ${joinAnd(fw.sources.map((s) => s.ip))} to ${fw.dst} is expected`);
    actions.push("Review the processes on the source hosts that generated the connections (MDE/EDR)");
  }
  if (!isFP && ext.length) actions.push(`Block ${joinAnd(ext.slice(0, 3))} at the perimeter firewall and proxy if no business need is confirmed`);
  if (!actions.length) actions.push("Compare the activity with the client's normal baseline", "Document findings and close or escalate per the playbook");

  const iocs = [
    ...ext.map((v) => ({ type: "IP", value: v, note: `External · ${ipCount(v)} line${ipCount(v) === 1 ? "" : "s"}` })),
    ...internal.map((v) => ({ type: "IP", value: v, note: "Internal" })),
    ...domains.map((v) => ({ type: "Domain", value: v, note: "" })),
    ...urls.map((v) => ({ type: "URL", value: v, note: "" })),
    ...hashes.map((h) => ({ type: h.type, value: h.value, note: "File hash" })),
  ];

  const warnings = [];
  const numRe = /(\d[\d,]*)\s+(?:[a-z-]+\s+){0,2}?(connections?|events?|attempts?|logons?|sign-?ins?|failures?)/i;
  const nm = title.match(numRe);
  if (nm) {
    const claimed = +nm[1].replace(/,/g, "");
    const actual = fw ? fw.total : /attempt|failure|logon|sign/i.test(nm[2]) ? techniques.find((t) => t.id === "T1110")?.hits ?? lines.length : lines.length;
    if (claimed !== actual) warnings.push(`Alert title says ${claimed} ${nm[2]}, but the logs show ${actual}.`);
  }

  return {
    lines, events: lines.length, timeline, window, spanMs: window ? window.end - window.start : null,
    ips: { external: ext, internal }, ipCount, domains, urls, hashes, hosts, users, parents,
    techniques, mitigated, score, severity, verdict, analystSet, isFP, confidence, closure, reason, fw, primaryIp,
    title, summary, actions: uniq(actions), iocs, warnings,
    extIocs: iocs.filter((i) => !(i.type === "IP" && i.note === "Internal")),
  };
}

export function buildChecklist(an) {
  const items = ["Confirm alert details (Alert ID, rule, severity) in the console"];
  an.ips.external.slice(0, 4).forEach((ip) => items.push(`Check ${ip} reputation in OSINT`));
  an.users.slice(0, 3).forEach((u) => items.push(`Review sign-in history for ${u}`));
  an.hosts.slice(0, 3).forEach((h) => items.push(`Review process tree on ${h} ±10 min around the alert`));
  an.hashes.slice(0, 3).forEach((h) => items.push(`Check prevalence of hash ${h.value.slice(0, 12)}…`));
  an.domains.slice(0, 3).forEach((d) => items.push(`Check who else contacted ${d}`));
  an.techniques.forEach((t) => items.push(`Hunt for ${t.id} ${t.name} on other hosts`));
  if (an.fw) items.push(`Confirm with the client that traffic from ${an.fw.sources.map((s) => s.ip).join(", ")} to ${an.fw.dst} is expected`);
  items.push("Check the client playbook Known benign list", "Record findings in SOC Notes", "Set the verdict and closure");
  return items;
}

export function detectSource(text) {
  if (/#event_simpleName|\baid=|ComputerName=|ParentBaseFileName/i.test(text)) return "crowdstrike";
  if (/src\.process\.|endpoint\.name|SentinelOne|tgt\.file/i.test(text)) return "s1";
  if (/DeviceProcessEvents|DeviceNetworkEvents|InitiatingProcess|DeviceName/i.test(text)) return "defender";
  if (/LEEF:|QIDNAME|\bqid\b|QRadar/i.test(text)) return "qradar";
  if (/source_json|rapid7|InsightIDR|\blogset\b/i.test(text)) return "rapid7";
  if (/sourcetype=|\bindex=|splunk/i.test(text)) return "splunk";
  if (/TimeGenerated|SigninLogs|CommonSecurityLog|CEF:|devname=|EventID|SecurityEvent/i.test(text)) return "sentinel";
  return null;
}

function decodeB64(s) {
  try {
    const bin = atob(s);
    if (/\0/.test(bin)) { let o = ""; for (let i = 0; i < bin.length; i += 2) o += String.fromCharCode(bin.charCodeAt(i) | (bin.charCodeAt(i + 1) << 8)); return o; }
    return bin;
  } catch { return null; }
}
export function findDecodable(text) {
  const out = [];
  const seen = new Set();
  const re = /(?:-e(?:nc(?:odedcommand)?)?\s+)([A-Za-z0-9+/=]{16,})|\b([A-Za-z0-9+/]{40,}={0,2})/gi;
  let m;
  while ((m = re.exec(text))) {
    const s = m[1] || m[2];
    if (seen.has(s) || /^[a-f0-9]+$/i.test(s)) continue;
    const d = decodeB64(s);
    if (d && /^[\x09\x0a\x0d\x20-\x7e]+$/.test(d) && d.length > 6) { seen.add(s); out.push({ kind: m[1] ? "PowerShell -enc" : "Base64", src: s, decoded: d }); }
  }
  (text.match(/(?:%[0-9A-F]{2}[^\s%]*){3,}/gi) || []).forEach((s) => {
    if (seen.has(s)) return;
    try { const d = decodeURIComponent(s); if (d !== s) { seen.add(s); out.push({ kind: "URL-encoded", src: s, decoded: d }); } } catch {}
  });
  return out;
}
