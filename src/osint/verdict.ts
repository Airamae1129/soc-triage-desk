import type { AbuseData, IndicatorType, OtxData, ProviderResult, ShodanData, UrlscanData, VtData } from "./types.js";

export type Verdict = "Not checked" | "Clean" | "Low risk" | "Malicious";

const okData = <T>(results: ProviderResult[], name: string) => {
  const r = results.find((x) => x.provider === name && x.status === "ok");
  return r?.data as T | undefined;
};
const DAY = 86400e3;

/**
 * Suggested verdict (the analyst can override it):
 *  - Malicious  if VT malicious ≥ 3 OR AbuseIPDB confidence ≥ 75
 *  - Low risk   if anything flagged it below that: VT malicious 1–2 or suspicious detections,
 *               AbuseIPDB 1–74, the domain is < 30 days old, urlscan.io scans flagged malicious, OTX pulses
 *  - Clean      if every configured provider for this type answered and none flagged it
 *  - otherwise Not checked
 */
export function suggestVerdict(results: ProviderResult[], now = Date.now()): Verdict {
  const abuse = okData<AbuseData>(results, "abuseipdb");
  const vt = okData<VtData>(results, "virustotal");
  const us = okData<UrlscanData>(results, "urlscan");
  const otx = okData<OtxData>(results, "otx");
  const vtMal = vt?.found ? vt.malicious : 0;
  const score = abuse?.score ?? 0;
  if (vtMal >= 3 || score >= 75) return "Malicious";
  const young = !!vt?.creationDate && now - Date.parse(vt.creationDate) < 30 * DAY;
  const vtSus = vt?.found ? vt.suspicious : 0;
  if (vtMal >= 1 || vtSus > 0 || score >= 1 || young || (us?.malicious ?? 0) > 0 || (otx?.pulses ?? 0) > 0) return "Low risk";
  const configured = results.filter((r) => r.status !== "not_configured");
  if (configured.length && configured.every((r) => r.status === "ok")) return "Clean";
  return "Not checked";
}

/** One line for the Reputation field, e.g. "AbuseIPDB – 0 reports, 0% confidence score · VirusTotal – 0/94 malicious". */
export function summaryLine(results: ProviderResult[]): string {
  const parts: string[] = [];
  for (const r of results) {
    if (r.status !== "ok" || !r.data) continue;
    if (r.provider === "abuseipdb") { const d = r.data as AbuseData; parts.push(`AbuseIPDB – ${d.reports} report${d.reports === 1 ? "" : "s"}, ${d.score}% confidence score${d.isTor ? ", Tor exit node" : ""}`); }
    if (r.provider === "virustotal") { const d = r.data as VtData; parts.push(d.found ? `VirusTotal – ${d.malicious}/${d.total} malicious${d.suspicious ? `, ${d.suspicious} suspicious` : ""}` : "VirusTotal – not found"); }
    if (r.provider === "urlscan") { const d = r.data as UrlscanData; parts.push(`urlscan.io – ${d.hits} scan${d.hits === 1 ? "" : "s"}${d.malicious ? `, ${d.malicious} flagged malicious` : ", none flagged"}`); }
    if (r.provider === "shodan") { const d = r.data as ShodanData; parts.push(d.found ? `Shodan – ${d.ports.length ? `ports ${d.ports.slice(0, 8).join(", ")}` : "no open ports"}${d.vulns ? `, ${d.vulns} CVEs` : ""}` : "Shodan – not found"); }
    if (r.provider === "otx") { const d = r.data as OtxData; parts.push(`OTX – ${d.pulses} pulse${d.pulses === 1 ? "" : "s"}${d.tags.length ? ` (${d.tags.slice(0, 4).join(", ")})` : ""}`); }
  }
  return parts.join(" · ");
}

export interface Autofill { asn?: string; owner?: string; location?: string; ipType?: string; reputation?: string }

/** ASN / Owner, Location and IP type for the Assessment form, from VirusTotal / AbuseIPDB / Shodan. */
export function autofill(type: IndicatorType, results: ProviderResult[]): Autofill {
  const abuse = okData<AbuseData>(results, "abuseipdb");
  const vt = okData<VtData>(results, "virustotal");
  const sh = okData<ShodanData>(results, "shodan");
  const out: Autofill = {};
  const asn = vt?.asn ? `AS${vt.asn}` : sh?.asn ?? undefined;
  if (asn) out.asn = asn;
  const owner = vt?.asOwner ?? abuse?.isp ?? sh?.org ?? undefined;
  if (owner) out.owner = owner;
  const country = abuse?.country ?? vt?.country ?? sh?.country ?? undefined;
  if (country) out.location = country;
  if (type === "ip") {
    const kinds = [abuse?.usageType, abuse?.isTor ? "Tor exit node" : null].filter(Boolean);
    if (kinds.length) out.ipType = kinds.join(", ");
  }
  const rep = summaryLine(results);
  if (rep) out.reputation = rep;
  return out;
}
