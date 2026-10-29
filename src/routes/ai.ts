import { Router, type Response } from "express";
import { z } from "zod";
import { prisma } from "../db.js";
import { config } from "../config.js";
import { h, notFound, AppError } from "../lib/errors.js";
import { audit } from "../lib/audit.js";
import { getAiProvider } from "../ai/provider.js";
import { draftReport, explainLine, chat, readScreenshot, pastedAssessment } from "../ai/service.js";

export const aiRouter = Router();

/** Aborts when the browser disconnects (Stop button, closed tab) before the answer is sent. */
function clientSignal(res: Response): AbortSignal {
  const c = new AbortController();
  res.on("close", () => { if (!res.writableFinished) c.abort(); });
  return c.signal;
}

aiRouter.get("/status", (_req, res) => {
  const p = getAiProvider();
  // local = nothing leaves the server, so screenshots (which can't be redacted) are safe to send.
  res.json({ enabled: p.name !== "none", provider: p.name, model: p.model, local: p.name === "ollama", maxLogLines: config.AI_MAX_LOG_LINES });
});

/** Draft the Assessment report with AI, validated and saved as an AI draft on the assessment. */
/** Alert name + logs pasted on the AI tab without a ticket. */
const PastedSchema = z.object({
  alertName: z.string().trim().max(500).default(""),
  rawLogs: z.string().max(1_500_000, "The pasted logs are too long (max about 1.5 MB)."),
  findings: z.string().max(200_000).optional(),
  client: z.string().max(200).optional(),
  severity: z.string().max(50).optional(),
  status: z.string().max(100).optional(),
  owner: z.string().max(300).optional(),
  classification: z.string().max(200).optional(),
}).refine((p) => p.rawLogs.trim() || p.findings?.trim(), { message: "Paste some logs (or findings) first." });

aiRouter.post("/draft-report", h(async (req, res) => {
  const b = z.object({ assessmentId: z.number().int().positive().optional(), pasted: PastedSchema.optional() })
    .refine((x) => !!x.assessmentId !== !!x.pasted, { message: "Send either assessmentId or pasted." }).parse(req.body);

  if (b.pasted) {
    // Pasted logs: drafted and returned, never saved. The audit entry records counts, not content.
    const out = await draftReport(pastedAssessment(b.pasted), clientSignal(res));
    await audit(req, "ai.draft_report_pasted", "", {
      model: out.model, inputTokens: out.usage.inputTokens, outputTokens: out.usage.outputTokens,
      attempts: out.attempts, redactedValues: out.redactedValues, logLinesSent: out.logLinesSent, logLinesTotal: out.logLinesTotal,
    }).catch(() => {});
    res.json({ text: out.text, aiGenerated: true, model: out.model, attempts: out.attempts, usage: out.usage, notice: "Drafted by AI – review before use" });
    return;
  }

  const a = await prisma.assessment.findUnique({ where: { id: b.assessmentId! } });
  if (!a) throw notFound("Assessment");
  try {
    const out = await draftReport(a, clientSignal(res));
    await prisma.assessment.update({ where: { id: a.id }, data: { generatedReport: out.text, aiGenerated: true } });
    await audit(req, "ai.draft_report", `${a.client} / ${a.ticket}`, {
      assessmentId: a.id, model: out.model, inputTokens: out.usage.inputTokens, outputTokens: out.usage.outputTokens,
      attempts: out.attempts, redactedValues: out.redactedValues, logLinesSent: out.logLinesSent, logLinesTotal: out.logLinesTotal,
    });
    res.json({ text: out.text, aiGenerated: true, model: out.model, attempts: out.attempts, usage: out.usage, notice: "Drafted by AI – review before use" });
  } catch (e) {
    if (e instanceof AppError && e.code === "ai_validation_failed") {
      const d = (e.details ?? {}) as { model?: string; usage?: { inputTokens: number; outputTokens: number }; issues?: string[] };
      await audit(req, "ai.draft_report_rejected", `${a.client} / ${a.ticket}`, { assessmentId: a.id, model: d.model, inputTokens: d.usage?.inputTokens, outputTokens: d.usage?.outputTokens, issues: d.issues?.length });
      throw new AppError(422, e.code, e.message, { issues: d.issues });
    }
    throw e;
  }
}));

aiRouter.post("/explain-line", h(async (req, res) => {
  const { line, assessmentId } = z.object({ line: z.string().trim().min(1).max(8000), assessmentId: z.number().int().positive().optional() }).parse(req.body);
  const a = assessmentId ? await prisma.assessment.findUnique({ where: { id: assessmentId } }) : null;
  const out = await explainLine(line, a ? { client: a.client, rawLogs: a.rawLogs, findings: a.findings } : undefined, clientSignal(res));
  await audit(req, "ai.explain_line", a ? `${a.client} / ${a.ticket}` : "", { model: out.model, inputTokens: out.usage.inputTokens, outputTokens: out.usage.outputTokens });
  res.json({ text: out.text, model: out.model });
}));

aiRouter.post("/chat", h(async (req, res) => {
  const b = z.object({
    assessmentId: z.number().int().positive().optional(),
    pasted: PastedSchema.optional(),
    messages: z.array(z.object({ role: z.enum(["user", "assistant"]), content: z.string().min(1).max(8000) })).min(1).max(40),
  }).parse(req.body);
  if (b.messages[b.messages.length - 1]?.role !== "user") throw new AppError(400, "bad_request", "The last message must be from the user.");
  const a = b.assessmentId ? await prisma.assessment.findUnique({ where: { id: b.assessmentId } }) : b.pasted ? pastedAssessment(b.pasted) : null;
  const out = await chat(a, b.messages, clientSignal(res));
  await audit(req, "ai.chat", a ? `${a.client} / ${a.ticket}` : "", { model: out.model, inputTokens: out.usage.inputTokens, outputTokens: out.usage.outputTokens, turns: b.messages.length });
  res.json({ text: out.text, model: out.model });
}));

/** Screenshot of logs / a SIEM screen → transcribed text + short analysis. The image is not stored. */
const DATA_URL = /^data:(image\/(?:png|jpeg|webp));base64,([A-Za-z0-9+/=]+)$/;
aiRouter.post("/read-screenshot", h(async (req, res) => {
  const b = z.object({
    image: z.string().max(1_900_000, "The screenshot is too large. Use one under about 1.4 MB."),
    note: z.string().max(500).optional(),
    assessmentId: z.number().int().positive().optional(),
  }).parse(req.body);
  const m = DATA_URL.exec(b.image);
  if (!m) throw new AppError(400, "bad_request", "Upload a PNG, JPEG or WebP screenshot.");
  const a = b.assessmentId ? await prisma.assessment.findUnique({ where: { id: b.assessmentId } }) : null;
  const out = await readScreenshot({ mediaType: m[1] as "image/png" | "image/jpeg" | "image/webp", data: m[2]! }, b.note, clientSignal(res));
  // The audit entry records that a screenshot was read, never its content.
  await audit(req, "ai.read_screenshot", a ? `${a.client} / ${a.ticket}` : "", {
    model: out.model, inputTokens: out.usage.inputTokens, outputTokens: out.usage.outputTokens, imageKB: Math.round((m[2]!.length * 3) / 4 / 1024),
  });
  res.json({ logText: out.logText, analysis: out.analysis, model: out.model });
}));
