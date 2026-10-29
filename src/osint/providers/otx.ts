import { config } from "../../config.js";
import { fetchJson } from "../http.js";
import type { Provider } from "../types.js";

interface OtxResp { pulse_info?: { count?: number; pulses?: { tags?: string[] }[] } }

// https://otx.alienvault.com/api — indicator "general" section: pulse count and tags.
export const otx: Provider<"otx"> = {
  name: "otx",
  label: "AlienVault OTX",
  supports: () => true,
  apiKey: () => config.OTX_API_KEY,
  ratePerMin: () => config.OTX_RATE_PER_MIN,
  async query(value, type, { key, fetch, timeoutMs }) {
    const section = type === "ip" ? (value.includes(":") ? "IPv6" : "IPv4") : type === "domain" ? "domain" : type === "url" ? "url" : "file";
    const url = `https://otx.alienvault.com/api/v1/indicators/${section}/${type === "url" ? encodeURIComponent(value) : encodeURIComponent(value)}/general`;
    const j = await fetchJson<OtxResp>(fetch, url, { headers: { "X-OTX-API-KEY": key, Accept: "application/json" } }, timeoutMs);
    const p = j?.pulse_info;
    const tags = [...new Set((p?.pulses ?? []).flatMap((x) => x.tags ?? []))].slice(0, 15);
    return { pulses: p?.count ?? 0, tags };
  },
};
