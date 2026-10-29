import type { Assessment, Note, Playbook } from "@prisma/client";

// Converts DB rows to the shapes the React app already uses, so the tabs need few changes.
// Frontend form field  <->  Assessment column
export const FORM_TO_COLUMN = {
  ticketId: "ticket", client: "client", alertName: "alertName", rawLogs: "rawLogs", findings: "findings",
  analyst: "analystName", shift: "shift", closure: "closure", verdictReason: "verdictReason", alertId: "alertId",
  analyticsRule: "rule", ruleLogic: "ruleLogic", detectionSource: "detSource", category: "category",
  alertSeverity: "alertSeverity", status: "status", incidentCreated: "created", activityWindow: "alertWindow",
  asn: "asn", location: "location", ipType: "ipType", reputation: "reputation", logSource: "logSource", edrTelemetry: "edrTelemetry",
} as const satisfies Record<string, keyof Assessment>;

export type FormKey = keyof typeof FORM_TO_COLUMN;

interface Extra { form?: Record<string, unknown>; snapshot?: Record<string, unknown> }

export function assessmentToEntry(a: Assessment) {
  const extra = (a.extra ?? {}) as Extra;
  const form: Record<string, unknown> = { ...(extra.form ?? {}) };
  for (const [f, c] of Object.entries(FORM_TO_COLUMN)) form[f] = a[c as keyof Assessment];
  return {
    id: a.id,
    form,
    savedAt: a.updatedAt.toISOString(),
    createdAt: a.createdAt.toISOString(),
    escalatedAt: a.escalatedAt?.toISOString() ?? null,
    notableStatus: a.escalationStatus ?? "Awaiting client",
    statusLog: (a.statusLog as unknown[] | null) ?? [],
    aiDraft: a.generatedReport ?? null,
    aiGenerated: a.aiGenerated,
    analystId: a.analystId,
    // snapshot fields the lists, notables and dashboard read
    sev: a.severity,
    verdict: a.verdict,
    score: a.riskScore,
    confidence: a.confidence,
    summary: a.summary,
    ...(extra.snapshot ?? {}),
  };
}

export const noteOut = (n: Note) => ({ id: n.id, type: n.type, text: n.text, time: n.at.toISOString(), author: n.authorName, authorId: n.authorId, auto: n.auto });

export const playbookOut = (p: Playbook) => ({
  name: p.client, client: p.client, industry: p.industry, reviewed: p.reviewed,
  matrix: p.matrix, contacts: p.contacts, containment: p.containment, benign: p.benign, procedures: p.procedures,
  updatedAt: p.updatedAt.toISOString(),
});
