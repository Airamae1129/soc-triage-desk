export type IndicatorType = "ip" | "domain" | "url" | "hash";
export type ProviderName = "abuseipdb" | "virustotal" | "urlscan" | "shodan" | "otx";
export type ProviderStatus = "ok" | "error" | "not_configured" | "rate_limited";

export interface AbuseData { score: number; reports: number; country: string | null; isp: string | null; usageType: string | null; isTor: boolean; domain: string | null; lastReportedAt: string | null }
export interface VtData { found: boolean; malicious: number; suspicious: number; harmless: number; undetected: number; total: number; reputation: number | null; asn: number | null; asOwner: string | null; country: string | null; lastAnalysisDate: string | null; creationDate: string | null }
export interface UrlscanData { hits: number; malicious: number; latest: { time: string | null; url: string | null; result: string | null } | null }
export interface ShodanData { found: boolean; ports: number[]; org: string | null; asn: string | null; isp: string | null; country: string | null; hostnames: string[]; vulns: number }
export interface OtxData { pulses: number; tags: string[] }

export interface ProviderDataMap { abuseipdb: AbuseData; virustotal: VtData; urlscan: UrlscanData; shodan: ShodanData; otx: OtxData }

export interface ProviderResult<N extends ProviderName = ProviderName> {
  provider: N;
  label: string;
  status: ProviderStatus;
  data?: ProviderDataMap[N];
  error?: string;
  cached?: boolean;
  fetchedAt?: string;
}

export type FetchFn = typeof fetch;

export interface Provider<N extends ProviderName = ProviderName> {
  name: N;
  label: string;
  supports: (type: IndicatorType) => boolean;
  apiKey: () => string | undefined;
  ratePerMin: () => number;
  query: (indicator: string, type: IndicatorType, ctx: { key: string; fetch: FetchFn; timeoutMs: number }) => Promise<ProviderDataMap[N]>;
}
