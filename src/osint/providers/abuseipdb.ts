import { config } from "../../config.js";
import { fetchJson } from "../http.js";
import type { Provider } from "../types.js";

interface AbuseResp { data?: { abuseConfidenceScore?: number; totalReports?: number; countryCode?: string; isp?: string; usageType?: string; isTor?: boolean; domain?: string; lastReportedAt?: string } }

// https://docs.abuseipdb.com/#check-endpoint (API v2). IPs only.
export const abuseipdb: Provider<"abuseipdb"> = {
  name: "abuseipdb",
  label: "AbuseIPDB",
  supports: (t) => t === "ip",
  apiKey: () => config.ABUSEIPDB_API_KEY,
  ratePerMin: () => config.ABUSEIPDB_RATE_PER_MIN,
  async query(ip, _type, { key, fetch, timeoutMs }) {
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
    const j = await fetchJson<AbuseResp>(fetch, url, { headers: { Key: key, Accept: "application/json" } }, timeoutMs);
    const d = j?.data ?? {};
    return {
      score: d.abuseConfidenceScore ?? 0,
      reports: d.totalReports ?? 0,
      country: d.countryCode ?? null,
      isp: d.isp ?? null,
      usageType: d.usageType ?? null,
      isTor: !!d.isTor,
      domain: d.domain ?? null,
      lastReportedAt: d.lastReportedAt ?? null,
    };
  },
};
