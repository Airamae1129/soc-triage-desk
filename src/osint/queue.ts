import { RateLimitedError } from "./http.js";

/**
 * Per-provider request queue. Spaces calls to stay under the provider's per-minute limit,
 * and after an HTTP 429 pauses that provider until its Retry-After (or an exponential backoff).
 * A call that would have to wait longer than `maxWaitMs` fails fast as rate_limited instead of
 * hanging the request.
 */
export class Limiter {
  private nextSlot = 0;
  private cooldownUntil = 0;
  private strikes = 0;

  constructor(private perMinute: () => number, private maxWaitMs = 45_000) {}

  async run<T>(fn: () => Promise<T>): Promise<T> {
    const now = Date.now();
    const interval = Math.ceil(60_000 / Math.max(1, this.perMinute()));
    const start = Math.max(now, this.nextSlot, this.cooldownUntil);
    const wait = start - now;
    if (wait > this.maxWaitMs) throw new RateLimitedError(Math.ceil(wait / 1000));
    this.nextSlot = start + interval;
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    return fn();
  }

  /** Call when the provider answered 429. */
  backoff(retryAfterSec: number | null) {
    this.strikes = Math.min(this.strikes + 1, 6);
    const ms = retryAfterSec != null ? retryAfterSec * 1000 : 5_000 * 2 ** (this.strikes - 1);
    this.cooldownUntil = Date.now() + ms;
    return Math.ceil(ms / 1000);
  }

  ok() { this.strikes = 0; }
}
