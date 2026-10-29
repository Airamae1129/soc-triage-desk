import type { FetchFn } from "./types.js";

/** Provider HTTP failure. Never includes request headers or URLs that carry keys. */
export class ProviderHttpError extends Error {
  constructor(public status: number, public retryAfterSec: number | null, message: string) { super(message); }
}
export class ProviderTimeoutError extends Error {}
export class RateLimitedError extends Error {
  constructor(public retryAfterSec: number) { super(`Rate limited, retry in ${retryAfterSec}s`); }
}

function retryAfter(res: Response): number | null {
  const v = res.headers.get("retry-after") ?? res.headers.get("x-rate-limit-reset-after");
  if (!v) return null;
  const n = Number(v);
  if (Number.isFinite(n)) return Math.max(1, Math.ceil(n));
  const d = Date.parse(v);
  return Number.isNaN(d) ? null : Math.max(1, Math.ceil((d - Date.now()) / 1000));
}

/** fetch + JSON with a hard timeout. 404 returns null (indicator unknown to the provider). */
export async function fetchJson<T>(f: FetchFn, url: string, init: RequestInit, timeoutMs: number): Promise<T | null> {
  let res: Response;
  try {
    res = await f(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
  } catch (e) {
    const name = (e as Error)?.name;
    if (name === "TimeoutError" || name === "AbortError") throw new ProviderTimeoutError(`No answer within ${Math.round(timeoutMs / 1000)}s`);
    throw new Error("Network error reaching the provider");
  }
  if (res.status === 404) return null;
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = (await res.json()) as { errors?: { detail?: string }[]; error?: { message?: string } | string; message?: string; description?: string };
      const detail = body?.errors?.[0]?.detail ?? (typeof body?.error === "string" ? body.error : body?.error?.message) ?? body?.message ?? body?.description;
      if (detail) msg += `: ${String(detail).slice(0, 160)}`;
    } catch { /* not JSON */ }
    throw new ProviderHttpError(res.status, retryAfter(res), msg);
  }
  return (await res.json()) as T;
}
