import { describe, it, expect, beforeAll, afterEach } from "vitest";
import { XHR, makeUser, login } from "./helpers.js";
import { prisma } from "../src/db.js";
import { setAiProvider, type AiProvider } from "../src/ai/provider.js";
import type { ReportJSON } from "../src/ai/report.js";

const LOGS = "2026-06-02T05:05:40Z host=HL-WS-FIN07 EventID=4625 user=mreyes src_ip=203.0.113.47 LogonType=10";

describe("AI on pasted logs (no ticket)", () => {
  const sent: string[] = [];
  beforeAll(async () => { await makeUser("paste.analyst", "analyst"); });
  afterEach(() => { setAiProvider(null); sent.length = 0; });

  const fake = (): AiProvider => ({
    name: "ollama", model: "fake-model",
    draftReport: async ({ user }) => {
      sent.push(user);
      const report: ReportJSON = {
        assessmentBullets: [{ text: "USER_1 failed to log on to HOST_1 over RDP from `203.0.113.47`." }],
        verdict: { label: "Suspicious", reason: "Failed RDP logon from an external IP", closure: "Escalate for review" },
        alertDetails: [{ key: "Users", value: "USER_1" }, { key: "Hosts", value: "HOST_1" }],
        supportingEvidence: [], queries: [],
      };
      return { json: report, usage: { inputTokens: 10, outputTokens: 5 }, model: "fake-model" };
    },
    explainLine: async () => ({ text: "", usage: { inputTokens: 0, outputTokens: 0 }, model: "fake-model" }),
    chat: async ({ system }) => { sent.push(system); return { text: "Looks like RDP brute force against USER_1.", usage: { inputTokens: 1, outputTokens: 1 }, model: "fake-model" }; },
    readImage: async () => ({ text: "", usage: { inputTokens: 0, outputTokens: 0 }, model: "fake-model" }),
  });

  it("drafts a report from pasted logs without saving a ticket", async () => {
    setAiProvider(fake());
    const a = await login("paste.analyst");
    const before = await prisma.assessment.count();
    const r = await a.post("/api/ai/draft-report").set(XHR).send({ pasted: { alertName: "RDP Brute Force", rawLogs: LOGS } });
    expect(r.status).toBe(200);
    expect(r.body.text).toMatch(/^Pasted logs – RDP Brute Force \(Not logged – Not logged – Not logged – Not logged\)\n\nAssessment:/);
    expect(r.body.text).toContain("mreyes failed to log on to HL-WS-FIN07");
    // Still redacted on the way out, and nothing stored.
    expect(sent[0]).not.toContain("mreyes");
    expect(sent[0]).not.toContain("HL-WS-FIN07");
    expect(await prisma.assessment.count()).toBe(before);
    // The audit entry has counts but never the logs.
    const audit = await prisma.auditLog.findFirst({ where: { action: "ai.draft_report_pasted" }, orderBy: { id: "desc" } });
    expect(audit).not.toBeNull();
    expect(JSON.stringify(audit)).not.toContain("mreyes");
  });

  it("answers questions about pasted logs", async () => {
    setAiProvider(fake());
    const a = await login("paste.analyst");
    const r = await a.post("/api/ai/chat").set(XHR).send({ pasted: { alertName: "RDP Brute Force", rawLogs: LOGS }, messages: [{ role: "user", content: "What happened?" }] });
    expect(r.status).toBe(200);
    expect(r.body.text).toContain("mreyes");
    expect(sent[0]).toContain("Pasted by the analyst");
    expect(sent[0]).not.toContain("mreyes");
  });

  it("rejects an empty paste and a request with both a ticket and a paste", async () => {
    setAiProvider(fake());
    const a = await login("paste.analyst");
    expect((await a.post("/api/ai/draft-report").set(XHR).send({ pasted: { alertName: "x", rawLogs: "  " } })).status).toBe(400);
    expect((await a.post("/api/ai/draft-report").set(XHR).send({ assessmentId: 1, pasted: { alertName: "x", rawLogs: LOGS } })).status).toBe(400);
  });
});
