import { describe, it, expect } from "vitest";
import { ollamaProvider } from "../src/ai/ollama.js";
import { AppError } from "../src/lib/errors.js";

// Mocked Ollama /api/chat: records each request and answers with a canned response.
function fakeOllama(respond: (body: any) => { status?: number; json: unknown }) {
  const calls: { url: string; body: any }[] = [];
  const fetchFn = (async (input: string | URL | Request, init?: RequestInit) => {
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    calls.push({ url: String(input), body });
    const r = respond(body);
    return new Response(JSON.stringify(r.json), { status: r.status ?? 200, headers: { "Content-Type": "application/json" } });
  }) as typeof fetch;
  return { fetchFn, calls };
}
const reply = (content: string, done_reason = "stop") => ({ model: "qwen3.5:4b", message: { role: "assistant", content }, done: true, done_reason, prompt_eval_count: 900, eval_count: 300 });
const report = {
  assessmentBullets: [{ text: "Alert triggered on external IP `203.0.113.9`." }],
  verdict: { label: "Likely False Positive", risk: "low", reason: "Vendor update traffic", closure: "closing as NFA" },
  alertDetails: [{ key: "Alert", value: "First-Seen External IP" }],
};
const BASE = "http://127.0.0.1:11434";

async function rejects(p: Promise<unknown>): Promise<AppError> {
  try { await p; } catch (e) { expect(e).toBeInstanceOf(AppError); return e as AppError; }
  throw new Error("expected the call to fail");
}

describe("Ollama provider (mocked HTTP)", () => {
  it("asks for the report schema with thinking off and returns the parsed report", async () => {
    const o = fakeOllama(() => ({ json: reply(JSON.stringify(report)) }));
    const out = await ollamaProvider(`${BASE}/`, "qwen3.5:4b", { fetchFn: o.fetchFn, numCtx: 8192 }).draftReport({ system: "RULES", user: "redacted input" });

    expect(out.json).toEqual(report);
    expect(out.usage).toEqual({ inputTokens: 900, outputTokens: 300 });
    const { url, body } = o.calls[0]!;
    expect(url).toBe(`${BASE}/api/chat`);
    expect(body).toMatchObject({ model: "qwen3.5:4b", stream: true, think: false, options: { num_ctx: 8192 } });
    expect(body.messages).toEqual([{ role: "system", content: "RULES" }, { role: "user", content: "redacted input" }]);
    expect(body.format.required).toEqual(expect.arrayContaining(["assessmentBullets", "verdict", "alertDetails"]));
  });

  it("returns null JSON for a non-JSON answer and flags a cut-off report", async () => {
    const bad = fakeOllama(() => ({ json: reply("Here is the report: ...") }));
    expect((await ollamaProvider(BASE, "m", { fetchFn: bad.fetchFn }).draftReport({ system: "s", user: "u" })).json).toBeNull();

    const cut = fakeOllama(() => ({ json: reply('{"assessmentBullets":[', "length") }));
    expect((await rejects(ollamaProvider(BASE, "m", { fetchFn: cut.fetchFn }).draftReport({ system: "s", user: "u" }))).code).toBe("ai_truncated");
  });

  it("says how to pull a missing model and when Ollama isn't running", async () => {
    const missing = fakeOllama(() => ({ status: 404, json: { error: "model 'qwen3.5:4b' not found, try pulling it first" } }));
    const e1 = await rejects(ollamaProvider(BASE, "qwen3.5:4b", { fetchFn: missing.fetchFn }).explainLine({ system: "s", line: "x" }));
    expect(e1.code).toBe("ai_model");
    expect(e1.message).toContain("ollama pull qwen3.5:4b");

    const down = (async () => { throw new TypeError("fetch failed"); }) as unknown as typeof fetch;
    const e2 = await rejects(ollamaProvider(BASE, "m", { fetchFn: down }).explainLine({ system: "s", line: "x" }));
    expect(e2.code).toBe("ai_unreachable");
  });

  it("reports a timeout from a slow local model", async () => {
    const slow = (async (_u: unknown, init?: RequestInit) => new Promise((_, rej) => {
      init?.signal?.addEventListener("abort", () => rej(init.signal!.reason));
    })) as unknown as typeof fetch;
    const e = await rejects(ollamaProvider(BASE, "m", { fetchFn: slow, timeoutMs: 50 }).explainLine({ system: "s", line: "x" }));
    expect(e.code).toBe("ai_timeout");
  });

  it("stops the Ollama request when the caller cancels (Stop button, closed tab)", async () => {
    let aborted = false;
    const slow = (async (_u: unknown, init?: RequestInit) => new Promise((_, rej) => {
      init?.signal?.addEventListener("abort", () => { aborted = true; rej(init.signal!.reason); });
    })) as unknown as typeof fetch;
    const stop = new AbortController();
    const p = ollamaProvider(BASE, "m", { fetchFn: slow, timeoutMs: 60_000 }).chat({ system: "s", messages: [{ role: "user", content: "x" }], signal: stop.signal });
    setTimeout(() => stop.abort(), 20);
    const e = await rejects(p);
    expect(e.code).toBe("ai_cancelled");
    expect(aborted).toBe(true);
  });

  it("joins a streamed (newline-delimited) answer", async () => {
    const chunks = [
      { model: "qwen3.5:4b", message: { role: "assistant", content: "A failed " }, done: false },
      { model: "qwen3.5:4b", message: { role: "assistant", content: "RDP logon." }, done: false },
      { model: "qwen3.5:4b", message: { role: "assistant", content: "" }, done: true, done_reason: "stop", prompt_eval_count: 50, eval_count: 7 },
    ];
    const fetchFn = (async () => new Response(chunks.map((c) => JSON.stringify(c)).join("\n") + "\n", { headers: { "Content-Type": "application/x-ndjson" } })) as unknown as typeof fetch;
    const out = await ollamaProvider(BASE, "m", { fetchFn }).explainLine({ system: "s", line: "x" });
    expect(out.text).toBe("A failed RDP logon.");
    expect(out.usage).toEqual({ inputTokens: 50, outputTokens: 7 });
  });

  it("passes chat history with the system prompt first", async () => {
    const o = fakeOllama(() => ({ json: reply("A failed RDP logon.") }));
    const out = await ollamaProvider(BASE, "m", { fetchFn: o.fetchFn }).chat({
      system: "s", messages: [{ role: "user", content: "4625?" }, { role: "assistant", content: "Failed logon." }, { role: "user", content: "RDP?" }],
    });
    expect(out.text).toBe("A failed RDP logon.");
    expect(o.calls[0]!.body.messages.map((m: { role: string }) => m.role)).toEqual(["system", "user", "assistant", "user"]);
  });
});
