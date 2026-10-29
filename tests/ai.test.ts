import { describe, it, expect, afterEach } from "vitest";
import { validateReport, assembleReport, countSentences, titleLine, type ReportJSON } from "../src/ai/report.js";
import { Redactor } from "../src/ai/redact.js";
import { draftReport, readScreenshot } from "../src/ai/service.js";
import { splitScreenshotAnswer } from "../src/ai/prompt.js";
import { setAiProvider, type AiProvider } from "../src/ai/provider.js";
import { trimLogs } from "../src/lib/logtrim.js";
import type { Assessment } from "@prisma/client";

const QUERY = "Anomalies\n| where TimeGenerated > ago(15d)\n| summarize n=count() by Day=bin(TimeGenerated,1d)";
const good: ReportJSON = {
  assessmentBullets: [
    { text: "The Sentinel rule “Data Ingestion Anomaly - Z-Score Detection” flagged two tables:", subBullets: ["Anomalies: Z-score 23.59, deviation 0.4 MB, an 8.5x spike.", "IdentityInfo: Z-score 7.3, +6.9 MB, a 15.5x spike."] },
    { text: "Traffic to `101.72.194.189` stayed at normal levels." },
  ],
  verdict: { label: "Benign / operational for the ingestion alert", reason: "Both table spikes are tiny in volume and come from Sentinel’s own analytics output", closure: "close as NFA", recommendation: "Review the top-scoring Exchange anomaly users as part of normal UEBA triage" },
  alertDetails: [{ key: "Rule", value: "Data Ingestion Anomaly - Z-Score Detection" }, { key: "Destination IP", value: "101.72.194.189" }, { key: "Entities", value: "" }],
  supportingEvidence: [
    { heading: "Rule query results", lines: ["Anomalies: ZScore 23.59, DeviationMB 0.4"] },
    { heading: "MailItemsAccessed tenant trend", table: { columns: ["Day", "Events", "Users"], rows: [["Oct 20", "92,454", "1,415"], ["Oct 21 (partial)", "50,450", "1,271"]] } },
  ],
  queries: [{ language: "KQL", query: QUERY }],
};
const input = `dstip=101.72.194.189 Data Ingestion Anomaly - Z-Score Detection\nQuery used:\n${QUERY}`;
const title = { ticket: "INC 14301", alertName: "Ingestion Anomaly: Anomalies - Z-Score 23.59", severity: "Medium", status: "In Progress", owner: "analyst@soc.example", classification: "Unclassified" };

describe("AI output validator", () => {
  it("accepts a report that only uses input facts", () => {
    expect(validateReport(good, input).ok).toBe(true);
  });

  it("catches an invented IP", () => {
    const bad = structuredClone(good);
    bad.assessmentBullets.push({ text: "Also contacted 198.51.100.99 on port 4444." });
    const v = validateReport(bad, input);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.issues.join(" ")).toContain("198.51.100.99");
  });

  it("catches an invented IP inside a Supporting Evidence table", () => {
    const bad = structuredClone(good);
    bad.supportingEvidence[1]!.table!.rows.push(["Oct 22", "203.0.113.200", "1"]);
    const v = validateReport(bad, input);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.issues.join(" ")).toContain("203.0.113.200");
  });

  it("catches a query the analyst didn't provide", () => {
    const bad = structuredClone(good);
    bad.queries.push({ language: "kql", query: "SigninLogs | where ResultType != 0 | take 10" });
    const v = validateReport(bad, input);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.issues.join(" ")).toMatch(/Query Used/);
  });

  it("allows a 3-sentence verdict but catches a 5-sentence one", () => {
    // The good report's verdict is label + reason + closure-with-recommendation = 3 sentences.
    expect(validateReport(good, input).ok).toBe(true);
    const bad = structuredClone(good);
    bad.verdict.reason = "Both spikes are tiny. They come from Sentinel analytics. Nothing else changed";
    const v = validateReport(bad, input);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.issues.join(" ")).toMatch(/5 sentences/);
  });

  it("catches missing sections", () => {
    const v = validateReport({ assessmentBullets: [], verdict: { label: "x" } }, input);
    expect(v.ok).toBe(false);
  });

  it("doesn't count IP dots or file names as sentence ends", () => {
    expect(countSentences("Verdict: True Positive. Host 10.0.0.1 ran a.exe from 203.0.113.4, escalated to client.")).toBe(2);
  });
});

describe("report assembly", () => {
  it("matches the exact format", () => {
    expect(assembleReport(good, title)).toBe(
      [
        "INC 14301 – Ingestion Anomaly: Anomalies - Z-Score 23.59 (Medium – In Progress – analyst@soc.example – Unclassified)",
        "",
        "Assessment:",
        "",
        "- The Sentinel rule “Data Ingestion Anomaly - Z-Score Detection” flagged two tables:",
        "  - Anomalies: Z-score 23.59, deviation 0.4 MB, an 8.5x spike.",
        "  - IdentityInfo: Z-score 7.3, +6.9 MB, a 15.5x spike.",
        "- Traffic to `101.72.194.189` stayed at normal levels.",
        "",
        "Verdict: Benign / operational for the ingestion alert. Both table spikes are tiny in volume and come from Sentinel’s own analytics output. Close as NFA, with one recommendation: review the top-scoring Exchange anomaly users as part of normal UEBA triage.",
        "",
        "Alert Details / Indicators:",
        "",
        "Rule: Data Ingestion Anomaly - Z-Score Detection",
        "Destination IP: 101.72.194.189",
        "Entities: Not logged",
        "",
        "Supporting Evidence:",
        "",
        "Rule query results:",
        "Anomalies: ZScore 23.59, DeviationMB 0.4",
        "MailItemsAccessed tenant trend:",
        "Day\tEvents\tUsers",
        "Oct 20\t92,454\t1,415",
        "Oct 21 (partial)\t50,450\t1,271",
        "",
        "Query Used:",
        "",
        "kql",
        "Anomalies",
        "| where TimeGenerated > ago(15d)",
        "| summarize n=count() by Day=bin(TimeGenerated,1d)",
      ].join("\n"),
    );
  });

  it("drops a recommendation of \"none\"", () => {
    const r = structuredClone(good);
    r.verdict.recommendation = "None.";
    expect(assembleReport(r, title)).toContain("come from Sentinel’s own analytics output. Close as NFA.\n");
  });

  it("writes Not logged for empty title fields and sections", () => {
    expect(titleLine({ ticket: "INC-1", alertName: "RDP Brute Force" })).toBe("INC-1 – RDP Brute Force (Not logged – Not logged – Not logged – Not logged)");
    const bare = { ...structuredClone(good), supportingEvidence: [], queries: [] };
    const text = assembleReport(bare, title);
    expect(text).toContain("Supporting Evidence:\n\nNot logged");
    expect(text.endsWith("Query Used:\n\nNot logged")).toBe(true);
  });
});

describe("redaction", () => {
  it("replaces and restores client, users, hosts and internal IPs", () => {
    const r = new Redactor({ client: "Harbor Lane Bank", users: ["mreyes"], hosts: ["HL-WS-FIN07"], internalIps: ["10.40.12.27"] });
    const text = "Harbor Lane Bank host=HL-WS-FIN07 user=mreyes srcip=10.40.12.27 dst=203.0.113.47 also 10.40.12.270";
    const red = r.redact(text);
    expect(red).toBe("CLIENT_1 host=HOST_1 user=USER_1 srcip=INTIP_1 dst=203.0.113.47 also 10.40.12.270");
    expect(r.restore(red)).toBe(text);
  });

  it("keeps the most relevant log lines", () => {
    const lines = [...Array.from({ length: 50 }, (_, i) => `noise line ${i}`), "EventID=4625 failed logon src_ip=203.0.113.47"];
    const t = trimLogs(lines.join("\n"), 5);
    expect(t.kept).toBe(5);
    expect(t.text).toContain("4625");
  });
});

const noop = async () => ({ text: "", usage: { inputTokens: 0, outputTokens: 0 }, model: "fake-model" });

describe("AI draft pipeline (fake provider)", () => {
  afterEach(() => setAiProvider(null));
  const a = {
    id: 1, client: "Harbor Lane Bank", ticket: "INC-1", alertName: "RDP Brute Force", findings: "Confirmed malicious.",
    rawLogs: "2026-06-02T05:05:40Z host=HL-WS-FIN07 EventID=4624 user=mreyes src_ip=203.0.113.47 srcip=10.40.12.27",
    extra: { owner: "analyst@soc.example", classification: "True Positive" }, alertId: "", rule: "", ruleLogic: "", detSource: "", category: "", alertSeverity: "High", status: "Active", created: "", alertWindow: "",
    asn: "", location: "", ipType: "", reputation: "", logSource: "", edrTelemetry: "", verdict: "True Positive", closure: "Escalated to client", verdictReason: "",
  } as unknown as Assessment;

  it("redacts before sending, retries once on a bad answer and restores real values", async () => {
    const seen: string[] = [];
    let calls = 0;
    const fake: AiProvider = {
      name: "anthropic", model: "fake-model",
      draftReport: async ({ user }) => {
        seen.push(user);
        calls++;
        const report: ReportJSON = {
          assessmentBullets: [{ text: calls === 1 ? "USER_1 on HOST_1 logged on from 203.0.113.47 and 198.51.100.7." : "USER_1 on HOST_1 logged on from `203.0.113.47`." }],
          verdict: { label: "True Positive", reason: "Brute-forced account logged on", closure: "escalated to client" },
          alertDetails: [{ key: "Hosts", value: "HOST_1" }, { key: "Users", value: "USER_1" }, { key: "Source / internal IPs", value: "INTIP_1" }],
          supportingEvidence: [],
          queries: [],
        };
        return { json: report, usage: { inputTokens: 100, outputTokens: 50 }, model: "fake-model" };
      },
      explainLine: noop, chat: noop, readImage: noop,
    };
    setAiProvider(fake);
    const out = await draftReport(a);
    expect(calls).toBe(2);
    expect(seen[1]).toContain("198.51.100.7"); // retry message lists the problem
    for (const s of seen) { expect(s).not.toContain("Harbor Lane Bank"); expect(s).not.toContain("mreyes"); expect(s).not.toContain("HL-WS-FIN07"); expect(s).not.toContain("10.40.12.27"); }
    expect(out.text).toMatch(/^INC-1 – RDP Brute Force \(High – Active – analyst@soc\.example – True Positive\)\n\nAssessment:\n\n- /);
    expect(out.text).toContain("mreyes on HL-WS-FIN07 logged on");
    expect(out.text).toContain("Source / internal IPs: 10.40.12.27");
    expect(out.usage).toEqual({ inputTokens: 200, outputTokens: 100 });
  });
});

describe("screenshot reading", () => {
  afterEach(() => setAiProvider(null));

  it("splits the answer into log text and analysis", () => {
    expect(splitScreenshotAnswer("LOG TEXT:\nEventID 4625 | mreyes | 203.0.113.47\n\nANALYSIS:\nFailed RDP logons.")).toEqual({ logText: "EventID 4625 | mreyes | 203.0.113.47", analysis: "Failed RDP logons." });
    expect(splitScreenshotAnswer("**LOG TEXT:**\nline 1\n**ANALYSIS:**\nok")).toEqual({ logText: "line 1", analysis: "ok" });
    expect(splitScreenshotAnswer("Just a description.")).toEqual({ logText: "", analysis: "Just a description." });
  });

  it("sends the image and the analyst note to the provider", async () => {
    let got: Parameters<AiProvider["readImage"]>[0] | undefined;
    setAiProvider({
      name: "ollama", model: "fake-vision", draftReport: async () => ({ json: null, usage: { inputTokens: 0, outputTokens: 0 }, model: "fake-vision" }), explainLine: noop, chat: noop,
      readImage: async (i) => { got = i; return { text: "LOG TEXT:\nrow 1\nANALYSIS:\nBenign.", usage: { inputTokens: 1, outputTokens: 1 }, model: "fake-vision" }; },
    });
    const out = await readScreenshot({ mediaType: "image/png", data: "iVBORw0KGgo=" }, "Sentinel results");
    expect(got?.image).toEqual({ mediaType: "image/png", data: "iVBORw0KGgo=" });
    expect(got?.prompt).toContain("Sentinel results");
    expect(out).toMatchObject({ logText: "row 1", analysis: "Benign.", model: "fake-vision" });
  });
});
