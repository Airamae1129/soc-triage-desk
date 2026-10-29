import { describe, it, expect } from "vitest";
import { geminiProvider } from "../src/ai/gemini.js";
import { AppError } from "../src/lib/errors.js";

// Mocked Gemini REST API: records each request and answers with a canned response.
function fakeGemini(respond: (body: any) => { status?: number; json: unknown }) {
  const calls: { url: string; headers: Headers; body: any }[] = [];
  const fetchFn = (async (input: string | URL | Request, init?: RequestInit) => {
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    calls.push({ url: String(input instanceof Request ? input.url : input), headers: new Headers(init?.headers), body });
    const r = respond(body);
    return new Response(JSON.stringify(r.json), { status: r.status ?? 200, headers: { "Content-Type": "application/json" } });
  }) as typeof fetch;
  return { fetchFn, calls };
}
const answer = (text: string, finishReason = "STOP") => ({
  candidates: [{ content: { role: "model", parts: [{ text }] }, finishReason }],
  usageMetadata: { promptTokenCount: 120, candidatesTokenCount: 40, thoughtsTokenCount: 10 },
  modelVersion: "gemini-test-001",
});
const report = {
  assessmentBullets: [{ text: "Alert triggered on external IP `203.0.113.9`." }],
  verdict: { label: "Likely False Positive", risk: "low", reason: "Vendor update traffic", closure: "closing as NFA" },
  alertDetails: [{ key: "Alert", value: "First-Seen External IP" }],
};
const KEY = "test-gemini-key-1234567890";

async function rejects(p: Promise<unknown>): Promise<AppError> {
  try { await p; } catch (e) { expect(e).toBeInstanceOf(AppError); return e as AppError; }
  throw new Error("expected the call to fail");
}

describe("Gemini provider (mocked HTTP)", () => {
  it("asks for JSON with the report schema and returns the parsed report", async () => {
    const g = fakeGemini(() => ({ json: answer(JSON.stringify(report)) }));
    const p = geminiProvider(KEY, "gemini-test", { fetchFn: g.fetchFn });
    const out = await p.draftReport({ system: "SYSTEM RULES", user: "redacted input" });

    expect(out.json).toEqual(report);
    expect(out.usage).toEqual({ inputTokens: 120, outputTokens: 50 });
    expect(out.model).toBe("gemini-test-001");

    const { url, headers, body } = g.calls[0]!;
    expect(url).toContain("models/gemini-test:generateContent");
    // The key travels in a header, never in the URL (URLs end up in proxy logs).
    expect(url).not.toContain(KEY);
    expect(headers.get("x-goog-api-key")).toBe(KEY);
    expect(body.systemInstruction.parts[0].text).toBe("SYSTEM RULES");
    expect(body.contents).toEqual([{ role: "user", parts: [{ text: "redacted input" }] }]);
    expect(body.generationConfig.responseMimeType).toBe("application/json");
    expect(body.generationConfig.responseJsonSchema.required).toEqual(expect.arrayContaining(["assessmentBullets", "verdict", "alertDetails"]));
  });

  it("returns null JSON for a non-JSON answer so the validator can retry", async () => {
    const g = fakeGemini(() => ({ json: answer("Sure! Here is the report: ...") }));
    const out = await geminiProvider(KEY, "gemini-test", { fetchFn: g.fetchFn }).draftReport({ system: "s", user: "u" });
    expect(out.json).toBeNull();
  });

  it("maps a safety block to ai_refused and a cut-off report to ai_truncated", async () => {
    const blocked = fakeGemini(() => ({ json: answer("", "SAFETY") }));
    expect((await rejects(geminiProvider(KEY, "m", { fetchFn: blocked.fetchFn }).explainLine({ system: "s", line: "x" }))).code).toBe("ai_refused");

    const promptBlocked = fakeGemini(() => ({ json: { promptFeedback: { blockReason: "PROHIBITED_CONTENT" } } }));
    expect((await rejects(geminiProvider(KEY, "m", { fetchFn: promptBlocked.fetchFn }).chat({ system: "s", messages: [{ role: "user", content: "x" }] }))).code).toBe("ai_refused");

    const cut = fakeGemini(() => ({ json: answer('{"assessmentBullets":[', "MAX_TOKENS") }));
    expect((await rejects(geminiProvider(KEY, "m", { fetchFn: cut.fetchFn }).draftReport({ system: "s", user: "u" }))).code).toBe("ai_truncated");
  });

  it("maps API errors without leaking the key", async () => {
    const badKey = fakeGemini(() => ({ status: 400, json: { error: { code: 400, message: "API key not valid. Please pass a valid API key.", status: "INVALID_ARGUMENT" } } }));
    const e1 = await rejects(geminiProvider(KEY, "m", { fetchFn: badKey.fetchFn }).explainLine({ system: "s", line: "x" }));
    expect(e1.code).toBe("ai_auth");
    expect(e1.message).not.toContain(KEY);

    const noModel = fakeGemini(() => ({ status: 404, json: { error: { code: 404, message: "models/nope is not found", status: "NOT_FOUND" } } }));
    expect((await rejects(geminiProvider(KEY, "nope", { fetchFn: noModel.fetchFn }).explainLine({ system: "s", line: "x" }))).code).toBe("ai_model");

    const quota = fakeGemini(() => ({ status: 429, json: { error: { code: 429, message: "Resource exhausted", status: "RESOURCE_EXHAUSTED" } } }));
    expect((await rejects(geminiProvider(KEY, "m", { fetchFn: quota.fetchFn }).explainLine({ system: "s", line: "x" }))).code).toBe("ai_rate_limited");

    const daily = fakeGemini(() => ({ status: 429, json: { error: { code: 429, status: "RESOURCE_EXHAUSTED",
      message: "You exceeded your current quota.\n* Quota exceeded for metric: generativelanguage.googleapis.com/generate_content_free_tier_requests, limit: 20\nPlease retry in 12h14m56.647049082s." } } }));
    const e3 = await rejects(geminiProvider(KEY, "m", { fetchFn: daily.fetchFn }).explainLine({ system: "s", line: "x" }));
    expect(e3.code).toBe("ai_quota");
    expect(e3.message).toContain("resets in about 12h14m56s");
  });

  it("retries a busy model, then falls back to the fallback model", async () => {
    let n = 0;
    const g = fakeGemini(() => (++n <= 3
      ? { status: 503, json: { error: { code: 503, message: "This model is currently experiencing high demand.", status: "UNAVAILABLE" } } }
      : { json: answer("Fallback answer.") }));
    const out = await geminiProvider(KEY, "main-model", { fetchFn: g.fetchFn, fallbackModel: "backup-model", retryDelaysMs: [0, 0] })
      .explainLine({ system: "s", line: "x" });
    expect(out.text).toBe("Fallback answer.");
    expect(g.calls.map((c) => c.url.match(/models\/([^:]+):/)![1])).toEqual(["main-model", "main-model", "main-model", "backup-model"]);
  });

  it("goes straight to the fallback model when the main model's quota is used up", async () => {
    let n = 0;
    const g = fakeGemini(() => (++n === 1
      ? { status: 429, json: { error: { code: 429, message: "You exceeded your current quota", status: "RESOURCE_EXHAUSTED" } } }
      : { json: answer("From the fallback.") }));
    const out = await geminiProvider(KEY, "main-model", { fetchFn: g.fetchFn, fallbackModel: "backup-model", retryDelaysMs: [0, 0] })
      .explainLine({ system: "s", line: "x" });
    expect(out.text).toBe("From the fallback.");
    expect(g.calls).toHaveLength(2);
  });

  it("reports ai_busy when the model and the fallback stay busy", async () => {
    const g = fakeGemini(() => ({ status: 503, json: { error: { code: 503, message: "high demand", status: "UNAVAILABLE" } } }));
    const e = await rejects(geminiProvider(KEY, "m", { fetchFn: g.fetchFn, fallbackModel: "f", retryDelaysMs: [0] }).explainLine({ system: "s", line: "x" }));
    expect(e.code).toBe("ai_busy");
    expect(g.calls).toHaveLength(3);
  });

  it("sends chat history with Gemini's role names", async () => {
    const g = fakeGemini(() => ({ json: answer("It is a failed RDP logon.") }));
    const out = await geminiProvider(KEY, "m", { fetchFn: g.fetchFn }).chat({
      system: "s",
      messages: [{ role: "user", content: "What is 4625?" }, { role: "assistant", content: "A failed logon." }, { role: "user", content: "RDP?" }],
    });
    expect(out.text).toBe("It is a failed RDP logon.");
    expect(g.calls[0]!.body.contents.map((c: { role: string }) => c.role)).toEqual(["user", "model", "user"]);
  });
});
