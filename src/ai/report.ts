import { z } from "zod";
import { indicatorsIn } from "../lib/iocs.js";

// The AI returns JSON in this shape; the server turns it into the exact report text.
// The title line is not in here: the server builds it from the ticket fields.
export const ReportSchema = z.object({
  assessmentBullets: z.array(z.object({
    text: z.string().min(1),
    subBullets: z.array(z.string().min(1)).optional(),
  })).min(1),
  verdict: z.object({
    label: z.string().min(1),
    reason: z.string().min(1),
    closure: z.string().min(1),
    recommendation: z.string().optional(),
  }),
  alertDetails: z.array(z.object({ key: z.string().min(1), value: z.string() })).min(1),
  supportingEvidence: z.array(z.object({
    heading: z.string().min(1),
    lines: z.array(z.string()).optional(),
    table: z.object({ columns: z.array(z.string()).min(1), rows: z.array(z.array(z.string())) }).optional(),
  })),
  queries: z.array(z.object({ language: z.string().min(1), query: z.string().min(1) })),
});
export type ReportJSON = z.infer<typeof ReportSchema>;

export const MAX_VERDICT_SENTENCES = 4;

export interface ReportTitle { ticket: string; alertName: string; severity?: string; status?: string; owner?: string; classification?: string }

const clean = (s: string) => s.replace(/\s+/g, " ").trim();
const stripEnd = (s: string) => clean(s).replace(/[.\s]+$/, "");
const ucFirst = (s: string) => (s ? s[0]!.toUpperCase() + s.slice(1) : s);
const orNot = (s?: string) => clean(s ?? "") || "Not logged";

/** "INC 14301 – <alert> (<severity> – <status> – <owner> – <classification>)" */
export function titleLine(t: ReportTitle): string {
  const meta = [t.severity, t.status, t.owner, t.classification].map(orNot).join(" – ");
  return `${clean(t.ticket) || "Ticket"} – ${orNot(t.alertName)} (${meta})`;
}

/** "Verdict: <label>. <reason>. <Closure>, with one recommendation: <recommendation>." */
export function verdictLine(v: ReportJSON["verdict"]): string {
  // Small models fill an optional field with "none" instead of leaving it out.
  const rec = /^(none|n\/?a|no|nil|not logged|not applicable|-+)$/i.test(stripEnd(v.recommendation ?? "")) ? "" : stripEnd(v.recommendation ?? "");
  const closure = ucFirst(stripEnd(v.closure));
  return `Verdict: ${stripEnd(v.label)}. ${stripEnd(v.reason)}. ${rec ? `${closure}, with one recommendation: ${rec.replace(/^[A-Z][a-z]/, (m) => m.toLowerCase())}` : closure}.`;
}

/**
 * <title>
 *
 * Assessment:
 *
 * - bullet
 *   - sub-bullet
 *
 * Verdict: <label>. <reason>. <closure>[, with one recommendation: …].
 *
 * Alert Details / Indicators:
 *
 * Key: value
 *
 * Supporting Evidence:
 *
 * <heading>:
 * line
 * col<TAB>col
 *
 * Query Used:
 *
 * kql
 * <query>
 */
export function assembleReport(r: ReportJSON, title: ReportTitle): string {
  const L: string[] = [titleLine(title), "", "Assessment:", ""];
  for (const b of r.assessmentBullets) {
    L.push(`- ${clean(b.text)}`);
    for (const s of b.subBullets ?? []) L.push(`  - ${clean(s)}`);
  }
  L.push("", verdictLine(r.verdict), "", "Alert Details / Indicators:", "");
  for (const d of r.alertDetails) L.push(`${clean(d.key)}: ${clean(d.value) || "Not logged"}`);

  L.push("", "Supporting Evidence:", "");
  if (!r.supportingEvidence.length) L.push("Not logged");
  for (const e of r.supportingEvidence) {
    L.push(`${stripEnd(e.heading).replace(/:$/, "")}:`);
    for (const line of e.lines ?? []) if (clean(line)) L.push(clean(line));
    if (e.table) {
      L.push(e.table.columns.map(clean).join("\t"));
      for (const row of e.table.rows) L.push(row.map(clean).join("\t"));
    }
  }

  L.push("", "Query Used:", "");
  if (!r.queries.length) L.push("Not logged");
  r.queries.forEach((q, i) => {
    if (i) L.push("");
    // Keep the query's own line breaks and indentation; only trim the ends.
    L.push(clean(q.language).toLowerCase(), q.query.replace(/\r\n/g, "\n").replace(/^\n+|\s+$/g, ""));
  });
  return L.join("\n");
}

/** Sentence count that doesn't split on IPs, versions or file names ("1.2.3.4", "v2.1", "a.exe"). */
export function countSentences(text: string): number {
  const t = clean(text).replace(/`[^`]*`/g, "X");
  if (!t) return 0;
  return t.split(/(?<=[.!?])\s+(?=[A-Z0-9"“(])/).filter((s) => s.trim()).length;
}

/** Whitespace- and case-insensitive form used to check that a query was really in the input. */
const squash = (s: string) => s.replace(/\s+/g, "").toLowerCase();

/**
 * Checks the AI output against the input. Returns a list of problems (empty = OK):
 *  - any IP, domain or hash in the output that is not in the input (invented indicators)
 *  - a query under "Query Used" that the analyst didn't provide
 *  - a verdict longer than MAX_VERDICT_SENTENCES sentences
 *  - missing or empty sections
 */
export function validateReport(raw: unknown, inputText: string): { ok: true; report: ReportJSON } | { ok: false; issues: string[]; report?: ReportJSON } {
  const parsed = ReportSchema.safeParse(raw);
  if (!parsed.success) {
    return { ok: false, issues: parsed.error.issues.map((i) => `Missing or invalid section: ${i.path.join(".") || "(root)"} – ${i.message}`) };
  }
  const r = parsed.data;
  const issues: string[] = [];
  const known = indicatorsIn(inputText);
  const outText = [
    ...r.assessmentBullets.flatMap((b) => [b.text, ...(b.subBullets ?? [])]),
    r.verdict.label, r.verdict.reason, r.verdict.closure, r.verdict.recommendation ?? "",
    ...r.alertDetails.map((d) => `${d.key} ${d.value}`),
    ...r.supportingEvidence.flatMap((e) => [e.heading, ...(e.lines ?? []), ...(e.table ? [e.table.columns.join(" "), ...e.table.rows.map((x) => x.join(" "))] : [])]),
  ].join("\n");
  const invented = [...indicatorsIn(outText)].filter((x) => !known.has(x));
  if (invented.length) issues.push(`Output contains indicators that are not in the input: ${invented.slice(0, 10).join(", ")}. Use only values from the input.`);

  const input = squash(inputText);
  const madeUp = r.queries.filter((q) => !input.includes(squash(q.query)));
  if (madeUp.length) issues.push(`"Query Used" must only list queries that appear in the input, copied exactly. ${madeUp.length} quer${madeUp.length === 1 ? "y was" : "ies were"} not in the input; leave queries out if none were provided.`);

  const n = countSentences(verdictLine(r.verdict));
  if (n > MAX_VERDICT_SENTENCES) issues.push(`Verdict has ${n} sentences; keep it to at most ${MAX_VERDICT_SENTENCES} (label, reason, closure with an optional recommendation).`);
  return issues.length ? { ok: false, issues, report: r } : { ok: true, report: r };
}
