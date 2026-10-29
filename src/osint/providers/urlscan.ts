import { config } from "../../config.js";
import { fetchJson, ProviderHttpError } from "../http.js";
import type { FetchFn, Provider } from "../types.js";

interface SearchResp { total?: number; results?: { task?: { time?: string }; page?: { url?: string }; result?: string; verdicts?: { malicious?: boolean; overall?: { malicious?: boolean } } }[] }

// https://urlscan.io/docs/api/ — lookups only SEARCH existing scans. New scans are submitted
// separately (submitScan) and only when the analyst clicks "Scan".
export const urlscan: Provider<"urlscan"> = {
  name: "urlscan",
  label: "urlscan.io",
  // URLs and domains only: IP checks use AbuseIPDB + VirusTotal (team rule), which also saves quota.
  supports: (t) => t === "domain" || t === "url",
  apiKey: () => config.URLSCAN_API_KEY,
  ratePerMin: () => config.URLSCAN_RATE_PER_MIN,
  async query(value, type, { key, fetch, timeoutMs }) {
    const q = type === "ip" ? `ip:"${value}"` : type === "domain" ? `domain:${value}` : `page.url:"${value.replace(/"/g, "")}"`;
    const url = `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}&size=10`;
    const j = await fetchJson<SearchResp>(fetch, url, { headers: { "API-Key": key, Accept: "application/json" } }, timeoutMs);
    const res = j?.results ?? [];
    const latest = res[0];
    return {
      hits: j?.total ?? res.length,
      malicious: res.filter((r) => r.verdicts?.malicious || r.verdicts?.overall?.malicious).length,
      latest: latest ? { time: latest.task?.time ?? null, url: latest.page?.url ?? null, result: latest.result?.replace("/api/v1/result/", "/result/") ?? null } : null,
    };
  },
};

/** Submit a new scan. Always private (or unlisted if the plan doesn't allow private). */
export async function submitScan(url: string, f: FetchFn, key: string, timeoutMs: number): Promise<{ uuid: string; result: string; visibility: string }> {
  const send = (visibility: string) =>
    fetchJson<{ uuid?: string; result?: string }>(f, "https://urlscan.io/api/v1/scan/", {
      method: "POST",
      headers: { "API-Key": key, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ url, visibility }),
    }, timeoutMs);
  let visibility = config.URLSCAN_VISIBILITY;
  let r;
  try {
    r = await send(visibility);
  } catch (e) {
    // Private scans need a plan that allows them; fall back to unlisted (still not public).
    if (visibility === "private" && e instanceof ProviderHttpError && (e.status === 400 || e.status === 403)) {
      visibility = "unlisted";
      r = await send(visibility);
    } else throw e;
  }
  if (!r?.uuid) throw new Error("urlscan.io did not accept the scan");
  return { uuid: r.uuid, result: `https://urlscan.io/result/${r.uuid}/`, visibility };
}
