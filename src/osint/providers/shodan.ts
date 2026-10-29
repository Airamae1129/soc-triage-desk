import { config } from "../../config.js";
import { fetchJson } from "../http.js";
import type { Provider } from "../types.js";

interface ShodanResp { ports?: number[]; org?: string; asn?: string; isp?: string; country_name?: string; hostnames?: string[]; vulns?: string[] | Record<string, unknown> }

// https://developer.shodan.io/api — host information. IPs only. The key goes in the query
// string (Shodan's only option), so this URL is never logged.
export const shodan: Provider<"shodan"> = {
  name: "shodan",
  label: "Shodan",
  supports: (t) => t === "ip",
  apiKey: () => config.SHODAN_API_KEY,
  ratePerMin: () => config.SHODAN_RATE_PER_MIN,
  async query(ip, _type, { key, fetch, timeoutMs }) {
    const j = await fetchJson<ShodanResp>(fetch, `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(key)}&minify=true`, { headers: { Accept: "application/json" } }, timeoutMs);
    if (!j) return { found: false, ports: [], org: null, asn: null, isp: null, country: null, hostnames: [], vulns: 0 };
    return {
      found: true,
      ports: (j.ports ?? []).slice().sort((a, b) => a - b),
      org: j.org ?? null,
      asn: j.asn ?? null,
      isp: j.isp ?? null,
      country: j.country_name ?? null,
      hostnames: (j.hostnames ?? []).slice(0, 10),
      vulns: Array.isArray(j.vulns) ? j.vulns.length : j.vulns ? Object.keys(j.vulns).length : 0,
    };
  },
};
