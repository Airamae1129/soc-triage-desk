import { config } from "../config.js";
import { fetchJson } from "./http.js";
import type { FetchFn } from "./types.js";

// Screenshotbase URL-to-image (https://screenshotbase.com/docs/). response_type=json makes the
// service store the PNG and return a public image URL the analyst can paste into a ticket.
// Runs only after the analyst confirms (each screenshot uses quota).

export const screenshotConfigured = () => !!config.SCREENSHOTBASE_API_KEY;

export async function takeScreenshot(url: string, f: FetchFn): Promise<{ url: string; width?: number; height?: number }> {
  const key = config.SCREENSHOTBASE_API_KEY;
  if (!key) throw new Error("Screenshot API key not configured");
  const qs = new URLSearchParams({ url, format: "png", viewport_width: "1280", viewport_height: "800", response_type: "json" });
  const j = await fetchJson<{ url?: string; width?: number; height?: number }>(f, `https://api.screenshotbase.com/v1/take?${qs}`, { headers: { apikey: key, Accept: "application/json" } }, 90_000);
  if (!j?.url) throw new Error("Screenshot service returned no image link");
  return { url: j.url, ...(j.width ? { width: j.width } : {}), ...(j.height ? { height: j.height } : {}) };
}
