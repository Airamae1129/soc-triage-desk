import { isIp, isPrivateIp } from "../lib/iocs.js";
import { badRequest } from "../lib/errors.js";
import type { IndicatorType } from "./types.js";

// Indicator checks before anything is sent to a provider. Private/reserved IPs and internal
// hostnames are refused so client-internal names never leave the network.

const INTERNAL_SUFFIX = /\.(local|lan|internal|intranet|corp|home|localdomain|localhost|private|domain|test|invalid)$/i;
const DOMAIN = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

function isPrivateIpv6(ip: string) {
  const v = ip.toLowerCase();
  return v === "::1" || v === "::" || /^f[cd]/.test(v) || /^fe[89ab]/.test(v) || /^ff/.test(v) || v.startsWith("::ffff:");
}
const looksIpv6 = (s: string) => /^[0-9a-f:]+$/i.test(s) && s.includes(":") && s.split(":").length <= 8;

function checkHost(host: string, what: string) {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (isIp(h)) { if (isPrivateIp(h)) throw badRequest(`${what} uses a private or reserved IP. Internal addresses are not sent to OSINT providers.`); return; }
  if (looksIpv6(h)) { if (isPrivateIpv6(h)) throw badRequest(`${what} uses a private or reserved IPv6 address.`); return; }
  if (h === "localhost" || !h.includes(".") || INTERNAL_SUFFIX.test(h)) {
    throw badRequest(`${what} looks like an internal hostname (${h}). Internal names are not sent to OSINT providers.`);
  }
}

export function detectType(v: string): IndicatorType | null {
  if (isIp(v) || looksIpv6(v)) return "ip";
  if (/^https?:\/\//i.test(v)) return "url";
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(v)) return "hash";
  if (DOMAIN.test(v) || !v.includes("/")) return "domain";
  return null;
}

/** Returns the cleaned indicator and its type, or throws a 400 with a clear reason. */
export function validateIndicator(raw: string, type?: IndicatorType): { indicator: string; type: IndicatorType } {
  let v = String(raw ?? "").trim();
  // Accept defanged input: example[.]com, hxxps://
  v = v.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".").replace(/^hxxp/i, "http").replace(/\[@\]/g, "@");
  if (!v || v.length > 2048) throw badRequest("Enter an IP, domain, URL or hash.");
  const t = type ?? detectType(v);
  if (!t) throw badRequest("Not a recognised IP, domain, URL or hash.");

  if (t === "ip") {
    if (isIp(v)) { if (isPrivateIp(v)) throw badRequest("Private or reserved IPs (RFC1918, loopback, link-local, CGNAT, multicast) are not looked up."); }
    else if (looksIpv6(v)) { if (isPrivateIpv6(v)) throw badRequest("Private or reserved IPv6 addresses are not looked up."); }
    else throw badRequest("Not a valid IP address.");
    return { indicator: v.toLowerCase(), type: t };
  }
  if (t === "hash") {
    if (!/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(v)) throw badRequest("Hash must be MD5, SHA-1 or SHA-256 (hex).");
    return { indicator: v.toLowerCase(), type: t };
  }
  if (t === "url") {
    let u: URL;
    try { u = new URL(v); } catch { throw badRequest("Not a valid URL."); }
    if (!/^https?:$/.test(u.protocol)) throw badRequest("Only http and https URLs can be looked up.");
    if (u.username || u.password) throw badRequest("URLs with embedded credentials are not looked up.");
    checkHost(u.hostname, "This URL");
    return { indicator: v, type: t };
  }
  // domain
  const d = v.toLowerCase().replace(/\.$/, "");
  checkHost(d, "This domain");
  if (!DOMAIN.test(d)) throw badRequest("Not a valid domain name.");
  return { indicator: d, type: "domain" };
}
