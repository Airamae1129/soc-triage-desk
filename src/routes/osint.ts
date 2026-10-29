import { Router } from "express";
import { z } from "zod";
import { Prisma } from "@prisma/client";
import { prisma } from "../db.js";
import { config } from "../config.js";
import { h, badRequest, AppError } from "../lib/errors.js";
import { audit } from "../lib/audit.js";
import { me } from "../auth/middleware.js";
import { lookup, providerStatus, osintFetch } from "../osint/index.js";
import { validateIndicator } from "../osint/validate.js";
import { submitScan } from "../osint/providers/urlscan.js";
import { takeScreenshot, screenshotConfigured } from "../osint/screenshot.js";
import { ProviderHttpError } from "../osint/http.js";
import type { ProviderName } from "../osint/types.js";

export const osintRouter = Router();

const TYPES = ["ip", "domain", "url", "hash"] as const;
const VERDICTS = ["Not checked", "Clean", "Suspicious", "Malicious"] as const;
const PROVIDER_NAMES = ["abuseipdb", "virustotal", "urlscan", "shodan", "otx"] as const;
const dayStart = () => { const d = new Date(); d.setUTCHours(0, 0, 0, 0); return d; };

/** Which providers have keys (never the keys themselves). */
osintRouter.get("/providers", h(async (_req, res) => {
  res.json({ providers: providerStatus(), screenshot: screenshotConfigured(), cacheHours: config.OSINT_CACHE_HOURS, urlscanVisibility: config.URLSCAN_VISIBILITY });
}));

/** Look up one indicator with the server-held keys. */
osintRouter.post("/lookup", h(async (req, res) => {
  const user = me(req);
  const b = z.object({
    indicator: z.string().min(1).max(2048),
    type: z.enum(TYPES).optional(),
    providers: z.array(z.enum(PROVIDER_NAMES)).max(5).optional(),
    force: z.boolean().optional(),
  }).parse(req.body);
  const { indicator, type } = validateIndicator(b.indicator, b.type);
  const out = await lookup(indicator, type, { providers: b.providers as ProviderName[] | undefined, force: b.force });

  // Keep the result in the analyst's workspace, keeping a verdict they set by hand.
  const scope = `ws:${user.id}`;
  const prev = await prisma.osintResult.findUnique({ where: { scope_indicator: { scope, indicator } } });
  const keepManual = !!prev?.manual;
  await prisma.osintResult.upsert({
    where: { scope_indicator: { scope, indicator } },
    create: { scope, userId: user.id, indicator, type, verdict: out.verdict, providerData: out as unknown as Prisma.InputJsonValue, checkedAt: new Date(), checkedBy: user.id },
    update: { providerData: out as unknown as Prisma.InputJsonValue, checkedAt: new Date(), checkedBy: user.id, ...(keepManual ? {} : { verdict: out.verdict }) },
  });
  await audit(req, "osint.lookup", `${type}:${indicator.slice(0, 200)}`, { verdict: out.verdict, statuses: Object.fromEntries(out.results.map((r) => [r.provider, r.status])) });
  res.json({ ...out, analystVerdict: keepManual ? prev?.verdict : undefined });
}));

// ---- Standalone OSINT workspace (per analyst, not tied to a ticket) ----
const wsOut = (r: { indicator: string; type: string; verdict: string; analystNote: string; manual: boolean; hidden: boolean; providerData: unknown; checkedAt: Date | null; createdAt: Date }) => ({
  value: r.indicator, type: r.type, verdict: r.verdict, note: r.analystNote, manual: r.manual, hidden: r.hidden,
  lookup: r.providerData ?? null, checkedAt: r.checkedAt?.toISOString() ?? null, addedAt: r.createdAt.toISOString(),
});

osintRouter.get("/workspace", h(async (req, res) => {
  const user = me(req);
  const [rows, shots, today] = await Promise.all([
    prisma.osintResult.findMany({ where: { scope: `ws:${user.id}` }, orderBy: { createdAt: "asc" } }),
    prisma.screenshot.findMany({ where: { userId: user.id }, orderBy: { takenAt: "asc" } }),
    prisma.screenshot.count({ where: { takenAt: { gte: dayStart() } } }),
  ]);
  res.json({ items: rows.map(wsOut), shots: shots.map((s) => ({ id: s.id, page: s.page, url: s.url, taken_at: s.takenAt.toISOString() })), screenshotsToday: today });
}));

/** Add indicators (several at once). Invalid ones come back in `rejected` with the reason. */
osintRouter.post("/workspace", h(async (req, res) => {
  const user = me(req);
  const { indicators } = z.object({ indicators: z.array(z.string().max(2048)).min(1).max(100) }).parse(req.body);
  const added: string[] = [];
  const rejected: { value: string; reason: string }[] = [];
  for (const raw of indicators) {
    try {
      const { indicator, type } = validateIndicator(raw);
      const scope = `ws:${user.id}`;
      const exists = await prisma.osintResult.findUnique({ where: { scope_indicator: { scope, indicator } } });
      if (exists) { if (exists.hidden) await prisma.osintResult.update({ where: { id: exists.id }, data: { hidden: false } }); continue; }
      await prisma.osintResult.create({ data: { scope, userId: user.id, indicator, type } });
      added.push(indicator);
    } catch (e) {
      rejected.push({ value: raw, reason: e instanceof AppError ? e.message : "Invalid" });
    }
  }
  const rows = await prisma.osintResult.findMany({ where: { scope: `ws:${user.id}` }, orderBy: { createdAt: "asc" } });
  res.json({ added, rejected, items: rows.map(wsOut) });
}));

/** Analyst verdict / note / leave-out-of-results flag. */
osintRouter.patch("/workspace/:indicator", h(async (req, res) => {
  const user = me(req);
  const indicator = decodeURIComponent(String(req.params.indicator));
  const b = z.object({ verdict: z.enum(VERDICTS).optional(), note: z.string().max(2000).optional(), hidden: z.boolean().optional() }).parse(req.body);
  const row = await prisma.osintResult.findUnique({ where: { scope_indicator: { scope: `ws:${user.id}`, indicator } } });
  if (!row) throw new AppError(404, "not_found", "Indicator is not in your OSINT list.");
  const manual = b.verdict !== undefined ? b.verdict !== "Not checked" : row.manual;
  const r = await prisma.osintResult.update({ where: { id: row.id }, data: { ...b.verdict !== undefined ? { verdict: b.verdict } : {}, ...b.note !== undefined ? { analystNote: b.note } : {}, ...b.hidden !== undefined ? { hidden: b.hidden } : {}, manual } });
  res.json({ item: wsOut(r) });
}));

osintRouter.delete("/workspace/:indicator", h(async (req, res) => {
  const user = me(req);
  await prisma.osintResult.deleteMany({ where: { scope: `ws:${user.id}`, indicator: decodeURIComponent(String(req.params.indicator)) } });
  res.json({ ok: true });
}));

/** Clear the whole workspace: indicators, results and screenshot links. */
osintRouter.delete("/workspace", h(async (req, res) => {
  const user = me(req);
  const [a, b] = await prisma.$transaction([
    prisma.osintResult.deleteMany({ where: { scope: `ws:${user.id}` } }),
    prisma.screenshot.deleteMany({ where: { userId: user.id } }),
  ]);
  await audit(req, "osint.clear", "", { indicators: a.count, screenshots: b.count });
  res.json({ ok: true });
}));

// ---- urlscan.io: new scan only on explicit click, always private/unlisted ----
osintRouter.post("/urlscan/scan", h(async (req, res) => {
  const { url, confirmed } = z.object({ url: z.string().max(2048), confirmed: z.literal(true, { error: "Scans need explicit confirmation." }) }).parse(req.body);
  void confirmed;
  const v = validateIndicator(/^https?:\/\//i.test(url) ? url : `https://${url}`, "url");
  if (!config.URLSCAN_API_KEY) throw new AppError(503, "not_configured", "urlscan.io is not configured.");
  try {
    const out = await submitScan(v.indicator, osintFetch(), config.URLSCAN_API_KEY, config.OSINT_TIMEOUT_MS);
    await audit(req, "osint.urlscan_submit", v.indicator.slice(0, 200), { visibility: out.visibility });
    res.json(out);
  } catch (e) {
    if (e instanceof ProviderHttpError && e.status === 429) throw new AppError(429, "rate_limited", "urlscan.io rate limit reached. Try again later.");
    throw new AppError(502, "provider_error", e instanceof ProviderHttpError ? `urlscan.io: ${e.message}` : "urlscan.io scan failed.");
  }
}));

// ---- Screenshotbase: URL to image, only after confirmation ----
osintRouter.get("/screenshot/usage", h(async (_req, res) => {
  res.json({ day: dayStart().toISOString().slice(0, 10), count: await prisma.screenshot.count({ where: { takenAt: { gte: dayStart() } } }) });
}));

osintRouter.post("/screenshot", h(async (req, res) => {
  const user = me(req);
  const b = z.object({ url: z.string().max(2048), confirmed: z.boolean() }).parse(req.body);
  if (!b.confirmed) throw badRequest("Screenshot needs explicit confirmation.");
  if (!screenshotConfigured()) throw new AppError(503, "not_configured", "Screenshot API key not configured.");
  const v = validateIndicator(/^https?:\/\//i.test(b.url) ? b.url : `https://${b.url}`, "url");
  let shot;
  try {
    shot = await takeScreenshot(v.indicator, osintFetch());
  } catch (e) {
    throw new AppError(502, "provider_error", e instanceof ProviderHttpError ? `Screenshot failed (${e.message})` : "Screenshot failed.");
  }
  const row = await prisma.screenshot.create({ data: { userId: user.id, page: v.indicator, url: shot.url } });
  const count = await prisma.screenshot.count({ where: { takenAt: { gte: dayStart() } } });
  await audit(req, "osint.screenshot", v.indicator.slice(0, 200));
  res.json({ id: row.id, url: shot.url, page: v.indicator, width: shot.width, height: shot.height, taken_at: row.takenAt.toISOString(), count_today: count });
}));

osintRouter.delete("/screenshot/:id", h(async (req, res) => {
  const user = me(req);
  await prisma.screenshot.deleteMany({ where: { id: Number(req.params.id), userId: user.id } });
  res.json({ ok: true });
}));
