import { config } from "../../config.js";
import { fetchJson } from "../http.js";
import type { Provider } from "../types.js";

interface VtResp {
  data?: { attributes?: {
    last_analysis_stats?: Record<string, number>; reputation?: number; asn?: number; as_owner?: string; country?: string;
    last_analysis_date?: number; creation_date?: number;
  } };
}
const iso = (unix?: number) => (unix ? new Date(unix * 1000).toISOString() : null);

// https://docs.virustotal.com/reference/overview (API v3): ip_addresses, domains, urls, files.
export const virustotal: Provider<"virustotal"> = {
  name: "virustotal",
  label: "VirusTotal",
  supports: () => true,
  apiKey: () => config.VIRUSTOTAL_API_KEY,
  ratePerMin: () => config.VIRUSTOTAL_RATE_PER_MIN,
  async query(value, type, { key, fetch, timeoutMs }) {
    const path =
      type === "ip" ? `ip_addresses/${encodeURIComponent(value)}`
      : type === "domain" ? `domains/${encodeURIComponent(value)}`
      : type === "url" ? `urls/${Buffer.from(value).toString("base64url")}`
      : `files/${encodeURIComponent(value)}`;
    const j = await fetchJson<VtResp>(fetch, `https://www.virustotal.com/api/v3/${path}`, { headers: { "x-apikey": key, Accept: "application/json" } }, timeoutMs);
    const a = j?.data?.attributes;
    if (!a) return { found: false, malicious: 0, suspicious: 0, harmless: 0, undetected: 0, total: 0, reputation: null, asn: null, asOwner: null, country: null, lastAnalysisDate: null, creationDate: null };
    const s = a.last_analysis_stats ?? {};
    return {
      found: true,
      malicious: s.malicious ?? 0,
      suspicious: s.suspicious ?? 0,
      harmless: s.harmless ?? 0,
      undetected: s.undetected ?? 0,
      total: Object.values(s).reduce((x, y) => x + (typeof y === "number" ? y : 0), 0),
      reputation: a.reputation ?? null,
      asn: a.asn ?? null,
      asOwner: a.as_owner ?? null,
      country: a.country ?? null,
      lastAnalysisDate: iso(a.last_analysis_date),
      creationDate: iso(a.creation_date),
    };
  },
};
