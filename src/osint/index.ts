import { config } from "../config.js";
import { logger } from "../lib/logger.js";
import { cacheGet, cacheSet } from "./cache.js";
import { ProviderHttpError, ProviderTimeoutError, RateLimitedError } from "./http.js";
import { Limiter } from "./queue.js";
import { abuseipdb } from "./providers/abuseipdb.js";
import { virustotal } from "./providers/virustotal.js";
import { urlscan } from "./providers/urlscan.js";
import { shodan } from "./providers/shodan.js";
import { otx } from "./providers/otx.js";
import { suggestVerdict, summaryLine, autofill, type Verdict, type Autofill } from "./verdict.js";
import type { FetchFn, IndicatorType, Provider, ProviderName, ProviderResult } from "./types.js";

export const PROVIDERS: Provider[] = [abuseipdb, virustotal, urlscan, shodan, otx] as Provider[];
const limiters = new Map<ProviderName, Limiter>(PROVIDERS.map((p) => [p.name, new Limiter(p.ratePerMin)]));

/** Which providers are configured (no keys, ever). */
export function providerStatus() {
  return PROVIDERS.map((p) => ({ name: p.name, label: p.label, configured: !!p.apiKey(), types: (["ip", "domain", "url", "hash"] as IndicatorType[]).filter(p.supports) }));
}

/** Test hook: swap the HTTP function used to reach providers. */
let httpFetch: FetchFn = (...a) => globalThis.fetch(...a);
export function setOsintFetch(f: FetchFn | null) { httpFetch = f ?? ((...a) => globalThis.fetch(...a)); }
export function resetLimiters() { for (const p of PROVIDERS) limiters.set(p.name, new Limiter(p.ratePerMin)); }

async function runProvider(p: Provider, indicator: string, type: IndicatorType, force: boolean): Promise<ProviderResult> {
  const base = { provider: p.name, label: p.label };
  const key = p.apiKey();
  if (!key) return { ...base, status: "not_configured" };
  const cacheKey = `${type}:${indicator.toLowerCase()}`;
  if (!force) {
    const hit = await cacheGet(p.name, cacheKey);
    if (hit) return { ...base, status: "ok", data: hit.data as never, cached: true, fetchedAt: hit.fetchedAt.toISOString() };
  }
  const limiter = limiters.get(p.name)!;
  try {
    const data = await limiter.run(() => p.query(indicator, type, { key, fetch: httpFetch, timeoutMs: config.OSINT_TIMEOUT_MS }));
    limiter.ok();
    const fetchedAt = await cacheSet(p.name, cacheKey, data);
    return { ...base, status: "ok", data: data as never, cached: false, fetchedAt: fetchedAt.toISOString() };
  } catch (e) {
    if (e instanceof RateLimitedError) return { ...base, status: "rate_limited", error: `Rate limit reached, try again in about ${e.retryAfterSec}s` };
    if (e instanceof ProviderHttpError && e.status === 429) {
      const s = limiter.backoff(e.retryAfterSec);
      return { ...base, status: "rate_limited", error: `Provider rate limit, paused for ${s}s` };
    }
    const msg = e instanceof ProviderTimeoutError || e instanceof ProviderHttpError ? e.message : "Lookup failed";
    if (e instanceof ProviderHttpError && (e.status === 401 || e.status === 403)) logger.warn({ provider: p.name, status: e.status }, "OSINT provider rejected the API key");
    else logger.warn({ provider: p.name, err: { message: (e as Error).message } }, "OSINT provider failed");
    return { ...base, status: "error", error: msg };
  }
}

export interface LookupResult {
  indicator: string;
  type: IndicatorType;
  results: ProviderResult[];
  verdict: Verdict;
  summary: string;
  autofill: Autofill;
  checkedAt: string;
}

/** Runs the applicable providers in parallel. One failing provider never fails the lookup. */
export async function lookup(indicator: string, type: IndicatorType, opts: { providers?: ProviderName[]; force?: boolean } = {}): Promise<LookupResult> {
  const chosen = PROVIDERS.filter((p) => p.supports(type) && (!opts.providers?.length || opts.providers.includes(p.name)));
  const results = await Promise.all(chosen.map((p) => runProvider(p, indicator, type, !!opts.force)));
  return { indicator, type, results, verdict: suggestVerdict(results), summary: summaryLine(results), autofill: autofill(type, results), checkedAt: new Date().toISOString() };
}

export const osintFetch = () => httpFetch;
