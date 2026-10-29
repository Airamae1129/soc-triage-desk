import type { Assessment } from "@prisma/client";
import { config } from "../config.js";
import { extractIocs } from "../lib/iocs.js";
import { trimLogs } from "../lib/logtrim.js";
import { getAiProvider, type ChatTurn, type ImageInput, type Usage } from "./provider.js";
import { Redactor } from "./redact.js";
import { assembleReport, validateReport, type ReportJSON } from "./report.js";
import { buildDraftUserMessage, screenshotPrompt, splitScreenshotAnswer, SYSTEM_CHAT, SYSTEM_DRAFT, SYSTEM_EXPLAIN, SYSTEM_SCREENSHOT } from "./prompt.js";
import { AppError } from "../lib/errors.js";

const ENRICH: [keyof Assessment, string][] = [
  ["alertId", "Alert ID"], ["rule", "Analytics rule"], ["ruleLogic", "Rule logic"], ["detSource", "Detection source"],
  ["category", "Category"], ["alertSeverity", "Severity"], ["status", "Status"], ["created", "Incident created"],
  ["alertWindow", "Activity window (alert)"], ["asn", "ASN"], ["location", "Location"], ["ipType", "IP type"],
  ["reputation", "Reputation"], ["logSource", "Log source"], ["edrTelemetry", "MDE / EDR telemetry"],
  ["verdict", "Analyst verdict"], ["closure", "Closure"], ["verdictReason", "Verdict reason"],
];

function redactorFor(a: Pick<Assessment, "client" | "rawLogs" | "findings">) {
  const iocs = extractIocs(`${a.rawLogs}\n${a.findings}`);
  return new Redactor({ client: a.client, users: iocs.users, hosts: iocs.hosts, internalIps: iocs.ips.internal });
}

/** What the analyst pasted on the AI tab without a ticket. Never saved. */
export interface PastedInput { alertName: string; rawLogs: string; findings?: string; client?: string; severity?: string; status?: string; owner?: string; classification?: string }

/** Wraps pasted text in the shape the draft/chat pipeline reads, with every other field empty. */
export function pastedAssessment(p: PastedInput): Assessment {
  const empty = Object.fromEntries(ENRICH.map(([k]) => [k, ""]));
  return {
    ...empty, id: 0, ticket: "Pasted logs", client: p.client ?? "", alertName: p.alertName, rawLogs: p.rawLogs, findings: p.findings ?? "",
    alertSeverity: p.severity ?? "", status: p.status ?? "", extra: { owner: p.owner ?? "", classification: p.classification ?? "" },
  } as unknown as Assessment;
}

export interface DraftResult { text: string; report: ReportJSON; model: string; usage: Usage; attempts: number; redactedValues: number; logLinesSent: number; logLinesTotal: number }

/**
 * 1. trim logs to AI_MAX_LOG_LINES most relevant lines, 2. redact names/hosts/internal IPs,
 * 3. ask for JSON, 4. validate (schema, invented indicators and queries, verdict length) and retry once
 * with the errors, 5. restore real values, 6. assemble the exact report text on the server.
 */
export async function draftReport(a: Assessment, signal?: AbortSignal): Promise<DraftResult> {
  const ai = getAiProvider();
  const red = redactorFor(a);
  const trimmed = trimLogs(a.rawLogs, config.AI_MAX_LOG_LINES);
  const extra = (a.extra ?? {}) as Record<string, unknown>;
  const fields: Record<string, string> = {};
  for (const [k, label] of ENRICH) { const v = a[k]; if (typeof v === "string" && v && v !== "Auto") fields[label] = red.redact(v); }
  for (const [k, label] of [["owner", "Owner"], ["mitre", "MITRE ATT&CK"], ["serviceSource", "Service source"], ["classification", "Classification"]] as const) {
    const v = extra[k];
    if (typeof v === "string" && v) fields[label] = red.redact(v);
  }
  const input = {
    alertName: red.redact(a.alertName),
    logs: red.redact(trimmed.text),
    logNote: trimmed.kept < trimmed.total ? `${trimmed.kept} most relevant of ${trimmed.total} lines` : `${trimmed.total} lines`,
    findings: red.redact(a.findings),
    fields,
  };
  // What the validator compares against: everything the model was shown about this ticket.
  const inputText = [input.alertName, input.logs, input.findings, ...Object.values(fields)].join("\n");

  const usage: Usage = { inputTokens: 0, outputTokens: 0 };
  let errors: string[] | undefined;
  let model = ai.model ?? "";
  for (let attempt = 1; attempt <= 2; attempt++) {
    const out = await ai.draftReport({ system: SYSTEM_DRAFT, user: buildDraftUserMessage(input, errors), signal });
    usage.inputTokens += out.usage.inputTokens; usage.outputTokens += out.usage.outputTokens; model = out.model;
    const v = validateReport(out.json, inputText);
    if (v.ok) {
      const restored: ReportJSON = JSON.parse(red.restore(JSON.stringify(v.report))) as ReportJSON;
      const title = {
        ticket: a.ticket, alertName: a.alertName, severity: a.alertSeverity, status: a.status,
        owner: typeof extra.owner === "string" ? extra.owner : "", classification: typeof extra.classification === "string" ? extra.classification : "",
      };
      return { text: assembleReport(restored, title), report: restored, model, usage, attempts: attempt, redactedValues: red.size, logLinesSent: trimmed.kept, logLinesTotal: trimmed.total };
    }
    errors = v.issues;
  }
  throw new AppError(422, "ai_validation_failed", "The AI draft failed the checks twice. Write this report by hand or try again.", { issues: errors, model, usage });
}

export async function explainLine(line: string, context?: { client?: string; rawLogs?: string; findings?: string }, signal?: AbortSignal) {
  const ai = getAiProvider();
  const red = redactorFor({ client: context?.client ?? "", rawLogs: `${context?.rawLogs ?? ""}\n${line}`, findings: context?.findings ?? "" });
  const out = await ai.explainLine({ system: SYSTEM_EXPLAIN, line: red.redact(line.slice(0, 4000)), signal });
  return { text: red.restore(out.text), model: out.model, usage: out.usage, redactedValues: red.size };
}

export async function chat(a: Assessment | null, messages: ChatTurn[], signal?: AbortSignal) {
  const ai = getAiProvider();
  const red = redactorFor(a ?? { client: "", rawLogs: "", findings: "" });
  let ctx = "No ticket is loaded.";
  if (a) {
    const trimmed = trimLogs(a.rawLogs, config.AI_MAX_LOG_LINES);
    const fields = ENRICH.map(([k, label]) => [label, a[k]] as const).filter(([, v]) => typeof v === "string" && v && v !== "Auto").map(([l, v]) => `${l}: ${String(v)}`);
    ctx = [a.id ? `Ticket ${a.ticket} · alert: ${a.alertName}` : `Pasted by the analyst (no ticket) · alert: ${a.alertName || "Not given"}`, ...fields, "", "Findings:", a.findings || "(none)", "", `Logs (${trimmed.kept} of ${trimmed.total} lines):`, trimmed.text].join("\n");
  }
  const system = `${SYSTEM_CHAT}\n\n=== TICKET CONTEXT ===\n${red.redact(ctx)}`;
  const out = await ai.chat({ system, messages: messages.slice(-20).map((m) => ({ role: m.role, content: red.redact(m.content.slice(0, 8000)) })), signal });
  return { text: red.restore(out.text), model: out.model, usage: out.usage };
}

/**
 * Reads a screenshot of logs or a SIEM screen: a transcription the analyst can add to the
 * ticket (where it then goes through the normal redaction and fact checks) plus a short analysis.
 * Images can't be redacted, so the frontend warns before sending one to a cloud provider.
 */
export async function readScreenshot(image: ImageInput, note?: string, signal?: AbortSignal) {
  const ai = getAiProvider();
  const out = await ai.readImage({ system: SYSTEM_SCREENSHOT, prompt: screenshotPrompt(note), image, signal });
  return { ...splitScreenshotAnswer(out.text), model: out.model, usage: out.usage };
}
