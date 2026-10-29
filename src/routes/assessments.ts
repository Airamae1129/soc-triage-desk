import { Router } from "express";
import { z } from "zod";
import { Prisma } from "@prisma/client";
import { prisma } from "../db.js";
import { h, notFound, forbidden, badRequest } from "../lib/errors.js";
import { audit } from "../lib/audit.js";
import { me } from "../auth/middleware.js";
import { assessmentToEntry, FORM_TO_COLUMN, noteOut } from "../lib/serialize.js";
import { validateIndicator } from "../osint/validate.js";

export const assessmentsRouter = Router();

const str = (max = 2000) => z.string().max(max).optional().default("");
const FormSchema = z.object({
  client: z.string().trim().min(1, "Client is required").max(200),
  ticketId: z.string().trim().min(1, "Ticket is required").max(100),
  alertName: str(500), rawLogs: str(1_500_000), findings: str(50_000), analyst: str(200), shift: str(20),
  verdict: str(100), closure: str(200), verdictReason: str(2000), alertId: str(200), analyticsRule: str(500),
  ruleLogic: str(4000), detectionSource: str(200), serviceSource: str(200), category: str(200), mitre: str(500),
  alertSeverity: str(50), status: str(100), classification: str(200), incidentCreated: str(200), activityWindow: str(300),
  asn: str(200), owner: str(300), location: str(300), ipType: str(300), reputation: str(2000), logSource: str(300),
  edrTelemetry: str(4000), defang: z.boolean().optional(),
}).passthrough();

const SnapshotSchema = z.object({
  sev: z.string().max(20).optional(), verdict: z.string().max(100).optional(), summary: z.string().max(4000).optional(),
  score: z.number().int().min(0).max(100).optional(), confidence: z.string().max(20).optional(), isFP: z.boolean().optional(),
  iocs: z.array(z.string().max(2048)).max(500).optional(), rule: z.string().max(500).optional(), primary: z.string().max(200).optional(),
}).partial();

const UpsertSchema = z.object({ form: FormSchema, snapshot: SnapshotSchema.optional().default({}) });

function columnsFrom(form: z.infer<typeof FormSchema>) {
  const cols: Record<string, unknown> = {};
  const rest: Record<string, unknown> = {};
  const mapped = new Set(Object.keys(FORM_TO_COLUMN));
  for (const [k, v] of Object.entries(form)) {
    if (mapped.has(k)) cols[FORM_TO_COLUMN[k as keyof typeof FORM_TO_COLUMN]] = v ?? "";
    else rest[k] = v;
  }
  // The analyst's own verdict choice ("Auto", "True Positive", …) lives in extra.form.verdict;
  // the verdict column holds the computed verdict from the snapshot.
  return { cols, rest };
}

const load = async (id: number) => {
  const a = await prisma.assessment.findUnique({ where: { id } });
  if (!a) throw notFound("Assessment");
  return a;
};
const idParam = (v: unknown) => { const n = Number(v); if (!Number.isInteger(n) || n < 1) throw badRequest("Bad id."); return n; };

// List / search
assessmentsRouter.get("/", h(async (req, res) => {
  const q = z.object({ client: z.string().max(200).optional(), q: z.string().max(200).optional(), limit: z.coerce.number().int().min(1).max(500).default(200) }).parse(req.query);
  const where: Prisma.AssessmentWhereInput = {};
  if (q.client) where.client = q.client;
  if (q.q) where.OR = [{ ticket: { contains: q.q } }, { alertName: { contains: q.q } }, { client: { contains: q.q } }];
  const rows = await prisma.assessment.findMany({ where, orderBy: { updatedAt: "desc" }, take: q.limit });
  res.json({ assessments: rows.map(assessmentToEntry) });
}));

assessmentsRouter.get("/:id", h(async (req, res) => {
  res.json({ assessment: assessmentToEntry(await load(idParam(req.params.id))) });
}));

/** Create or update by (client, ticket). */
assessmentsRouter.post("/", h(async (req, res) => {
  const user = me(req);
  const { form, snapshot } = UpsertSchema.parse(req.body);
  const { cols, rest } = columnsFrom(form);
  const extra = { form: rest, snapshot: { isFP: snapshot.isFP, iocs: snapshot.iocs, rule: snapshot.rule, primary: snapshot.primary } } as Prisma.InputJsonValue;
  const data = {
    ...(cols as Record<string, string>),
    analystName: (cols.analystName as string) || user.displayName,
    severity: snapshot.sev ?? "Low", verdict: snapshot.verdict ?? "Auto", riskScore: snapshot.score ?? 0,
    confidence: snapshot.confidence ?? "Low", summary: snapshot.summary ?? "", extra,
  };
  const existing = await prisma.assessment.findUnique({ where: { client_ticket: { client: form.client, ticket: form.ticketId } } });
  const a = existing
    ? await prisma.assessment.update({ where: { id: existing.id }, data })
    : await prisma.assessment.create({ data: { ...data, client: form.client, ticket: form.ticketId, analystId: user.id } });
  await audit(req, existing ? "assessment.update" : "assessment.create", `${a.client} / ${a.ticket}`, { id: a.id, severity: a.severity, verdict: a.verdict, logLines: form.rawLogs.split("\n").length });
  res.status(existing ? 200 : 201).json({ assessment: assessmentToEntry(a) });
}));

/** Update selected fields (e.g. after "Fill from OSINT"). */
assessmentsRouter.put("/:id", h(async (req, res) => {
  const id = idParam(req.params.id);
  const before = await load(id);
  const body = z.object({ form: FormSchema.partial(), snapshot: SnapshotSchema.optional() }).parse(req.body);
  const { cols, rest } = columnsFrom(body.form as z.infer<typeof FormSchema>);
  delete cols.client; delete cols.ticket; // identity can't change here
  const oldExtra = (before.extra ?? {}) as { form?: Record<string, unknown>; snapshot?: Record<string, unknown> };
  const s = body.snapshot;
  const a = await prisma.assessment.update({
    where: { id },
    data: {
      ...(cols as Record<string, string>),
      ...(s ? { severity: s.sev ?? before.severity, verdict: s.verdict ?? before.verdict, riskScore: s.score ?? before.riskScore, confidence: s.confidence ?? before.confidence, summary: s.summary ?? before.summary } : {}),
      extra: { form: { ...(oldExtra.form ?? {}), ...rest }, snapshot: { ...(oldExtra.snapshot ?? {}), ...(s ? { isFP: s.isFP, iocs: s.iocs, rule: s.rule, primary: s.primary } : {}) } } as Prisma.InputJsonValue,
    },
  });
  await audit(req, "assessment.update", `${a.client} / ${a.ticket}`, { id, fields: Object.keys(body.form) });
  res.json({ assessment: assessmentToEntry(a) });
}));

assessmentsRouter.post("/:id/escalate", h(async (req, res) => {
  const user = me(req);
  const id = idParam(req.params.id);
  const { noteText } = z.object({ noteText: z.string().max(2000).optional() }).parse(req.body ?? {});
  const before = await load(id);
  if (before.escalatedAt) { res.json({ assessment: assessmentToEntry(before) }); return; }
  const at = new Date();
  const log = [...((before.statusLog as unknown[] | null) ?? []), { status: "Escalated", by: user.displayName, at: at.toISOString() }];
  const [a] = await prisma.$transaction([
    prisma.assessment.update({ where: { id }, data: { escalatedAt: at, escalationStatus: "Awaiting client", statusLog: log as Prisma.InputJsonValue } }),
    ...(noteText ? [prisma.note.create({ data: { assessmentId: id, type: "Client comms", text: noteText, at, authorId: user.id, authorName: user.displayName, auto: true } })] : []),
  ]);
  await audit(req, "assessment.escalate", `${a.client} / ${a.ticket}`, { id });
  res.json({ assessment: assessmentToEntry(a) });
}));

assessmentsRouter.delete("/:id/escalate", h(async (req, res) => {
  const id = idParam(req.params.id);
  const before = await load(id);
  const at = before.escalatedAt;
  const [a] = await prisma.$transaction([
    prisma.assessment.update({ where: { id }, data: { escalatedAt: null, escalationStatus: null } }),
    ...(at ? [prisma.note.deleteMany({ where: { assessmentId: id, auto: true, at } })] : []),
  ]);
  await audit(req, "assessment.unescalate", `${a.client} / ${a.ticket}`, { id });
  res.json({ assessment: assessmentToEntry(a) });
}));

assessmentsRouter.patch("/:id/status", h(async (req, res) => {
  const user = me(req);
  const id = idParam(req.params.id);
  const { status } = z.object({ status: z.enum(["Awaiting client", "Client acknowledged", "Monitoring", "Contained", "Closed"]) }).parse(req.body);
  const before = await load(id);
  const log = [...((before.statusLog as unknown[] | null) ?? []), { status, by: user.displayName, at: new Date().toISOString() }];
  const a = await prisma.assessment.update({ where: { id }, data: { escalationStatus: status, statusLog: log as Prisma.InputJsonValue } });
  await audit(req, "assessment.status", `${a.client} / ${a.ticket}`, { id, status });
  res.json({ assessment: assessmentToEntry(a) });
}));

// ---- Notes ----
const NOTE_TYPES = ["Investigation", "Assessment", "Client comms", "Containment", "Handover"] as const;

assessmentsRouter.get("/:id/notes", h(async (req, res) => {
  const id = idParam(req.params.id);
  await load(id);
  const notes = await prisma.note.findMany({ where: { assessmentId: id }, orderBy: { at: "asc" } });
  res.json({ notes: notes.map(noteOut) });
}));

assessmentsRouter.post("/:id/notes", h(async (req, res) => {
  const user = me(req);
  const id = idParam(req.params.id);
  const a = await load(id);
  const b = z.object({ type: z.enum(NOTE_TYPES), text: z.string().trim().min(1).max(20_000), time: z.string().datetime({ offset: true }).optional() }).parse(req.body);
  const n = await prisma.note.create({ data: { assessmentId: id, type: b.type, text: b.text, at: b.time ? new Date(b.time) : new Date(), authorId: user.id, authorName: user.displayName } });
  await audit(req, "note.create", `${a.client} / ${a.ticket}`, { noteId: n.id, type: n.type });
  res.status(201).json({ note: noteOut(n) });
}));

// ---- Checklist ----
assessmentsRouter.get("/:id/checklist", h(async (req, res) => {
  const id = idParam(req.params.id);
  await load(id);
  const rows = await prisma.checklistState.findMany({ where: { assessmentId: id } });
  res.json({ checklist: Object.fromEntries(rows.map((r) => [r.item, r.done])), details: rows.map((r) => ({ item: r.item, done: r.done, doneBy: r.doneBy, doneAt: r.doneAt?.toISOString() ?? null })) });
}));

assessmentsRouter.put("/:id/checklist", h(async (req, res) => {
  const user = me(req);
  const id = idParam(req.params.id);
  await load(id);
  const { item, done } = z.object({ item: z.string().trim().min(1).max(500), done: z.boolean() }).parse(req.body);
  await prisma.checklistState.upsert({
    where: { assessmentId_item: { assessmentId: id, item } },
    create: { assessmentId: id, item, done, doneBy: done ? user.id : null, doneAt: done ? new Date() : null },
    update: { done, doneBy: done ? user.id : null, doneAt: done ? new Date() : null },
  });
  const rows = await prisma.checklistState.findMany({ where: { assessmentId: id } });
  res.json({ checklist: Object.fromEntries(rows.map((r) => [r.item, r.done])) });
}));

// ---- OSINT verdicts attached to an assessment ----
assessmentsRouter.get("/:id/osint", h(async (req, res) => {
  const id = idParam(req.params.id);
  await load(id);
  const rows = await prisma.osintResult.findMany({ where: { scope: `as:${id}` } });
  res.json({ values: Object.fromEntries(rows.map((r) => [r.indicator, { verdict: r.verdict, note: r.analystNote, manual: r.manual }])) });
}));

assessmentsRouter.put("/:id/osint/:indicator", h(async (req, res) => {
  const user = me(req);
  const id = idParam(req.params.id);
  const a = await load(id);
  const { indicator, type } = validateIndicator(decodeURIComponent(String(req.params.indicator)));
  const b = z.object({ verdict: z.enum(["Not checked", "Clean", "Low risk", "Malicious"]), note: z.string().max(2000).optional().default(""), providerData: z.unknown().optional() }).parse(req.body);
  const data = { verdict: b.verdict, analystNote: b.note, manual: true, checkedAt: new Date(), checkedBy: user.id, ...(b.providerData !== undefined ? { providerData: b.providerData as Prisma.InputJsonValue } : {}) };
  await prisma.osintResult.upsert({
    where: { scope_indicator: { scope: `as:${id}`, indicator } },
    create: { scope: `as:${id}`, assessmentId: id, indicator, type, ...data },
    update: data,
  });
  await audit(req, "assessment.osint", `${a.client} / ${a.ticket}`, { id, indicator, verdict: b.verdict });
  res.json({ ok: true });
}));

assessmentsRouter.delete("/:id", h(async (req, res) => {
  const user = me(req);
  if (user.role !== "admin") throw forbidden("Only an admin can delete assessments.");
  const id = idParam(req.params.id);
  const a = await load(id);
  await prisma.assessment.delete({ where: { id } });
  await audit(req, "assessment.delete", `${a.client} / ${a.ticket}`, { id });
  res.json({ ok: true });
}));
