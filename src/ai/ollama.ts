import { z } from "zod";
import { AppError } from "../lib/errors.js";
import { logger } from "../lib/logger.js";
import { ReportSchema } from "./report.js";
import { cancelled, type AiProvider, type ChatTurn, type Usage } from "./provider.js";

type OllamaMessage = { role: string; content: string; images?: string[] };

// Local models through Ollama's REST API (POST /api/chat). Nothing leaves the machine
// (or the company server Ollama runs on); there is no API key and no quota.

// Ollama constrains the answer to this JSON schema (grammar-based), so even small models
// return the right shape. The server still validates it with zod and checks the facts.
const { $schema: _drop, ...REPORT_JSON_SCHEMA } = z.toJSONSchema(ReportSchema) as Record<string, unknown>;
void _drop;

export interface OllamaOptions {
  /** Context window in tokens. Logs + instructions must fit, or Ollama silently cuts the start. */
  numCtx?: number;
  /** Per-request timeout. Local models on a CPU can take minutes for a full report. */
  timeoutMs?: number;
  /** Test hook (mocked HTTP). */
  fetchFn?: typeof fetch;
}

interface OllamaChatResponse {
  model?: string;
  message?: { role: string; content: string };
  done_reason?: string;
  prompt_eval_count?: number;
  eval_count?: number;
  error?: string;
}

export function ollamaProvider(baseUrl: string, model: string, opts: OllamaOptions = {}): AiProvider {
  const { numCtx = 8192, timeoutMs = 600_000, fetchFn = globalThis.fetch } = opts;
  const url = `${baseUrl.replace(/\/+$/, "")}/api/chat`;

  const timedOut = () => new AppError(504, "ai_timeout", `The local model took longer than ${Math.round(timeoutMs / 1000)}s. Try a smaller model or fewer log lines (AI_MAX_LOG_LINES).`);

  const call = async (messages: OllamaMessage[], extra: { format?: unknown; maxTokens: number; signal?: AbortSignal }) => {
    // Stops Ollama generating when the analyst presses Stop or closes the page, so the next
    // request isn't stuck behind an answer nobody is waiting for (Ollama runs one at a time).
    const timeout = AbortSignal.timeout(timeoutMs);
    const signal = extra.signal ? AbortSignal.any([timeout, extra.signal]) : timeout;
    const why = () => (extra.signal?.aborted ? cancelled() : timedOut());
    let res: Response;
    try {
      res = await fetchFn(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal,
        body: JSON.stringify({
          model,
          messages,
          // Streamed so the response headers arrive at once: Node's fetch gives up after 5 minutes
          // without headers, and a full report on a laptop CPU can take longer than that.
          stream: true,
          // Thinking models (qwen3.5, gemma4…) would spend minutes reasoning on a CPU first.
          think: false,
          ...(extra.format ? { format: extra.format } : {}),
          options: { num_ctx: numCtx, num_predict: extra.maxTokens, temperature: 0.2 },
          keep_alive: "15m",
        }),
      });
    } catch (e) {
      if (signal.aborted) throw why();
      throw new AppError(502, "ai_unreachable", `Could not reach Ollama at ${baseUrl}. Check that Ollama is running.`);
    }
    // Newline-delimited JSON: one object per chunk, the last one has done=true and the counts.
    // (A plain JSON body, e.g. an error, is a single line and parses the same way.)
    let raw: string;
    try {
      raw = await res.text();
    } catch (e) {
      if (signal.aborted) throw why();
      throw new AppError(502, "ai_unreachable", `Lost the connection to Ollama at ${baseUrl} while it was answering.`);
    }
    const body: OllamaChatResponse = { message: { role: "assistant", content: "" } };
    for (const line of raw.split("\n")) {
      if (!line.trim()) continue;
      let chunk: OllamaChatResponse;
      try { chunk = JSON.parse(line) as OllamaChatResponse; } catch { continue; }
      if (chunk.error) body.error = chunk.error;
      if (chunk.message?.content) body.message!.content += chunk.message.content;
      for (const k of ["model", "done_reason", "prompt_eval_count", "eval_count"] as const) if (chunk[k] !== undefined) (body as Record<string, unknown>)[k] = chunk[k];
    }
    if (!res.ok || body.error) {
      const detail = String(body.error ?? `HTTP ${res.status}`).slice(0, 300);
      logger.warn({ provider: "ollama", model, status: res.status, detail }, "AI provider error");
      if (res.status === 404 || /not found|pull/i.test(detail)) {
        throw new AppError(502, "ai_model", `The local model "${model}" isn't downloaded. Run: ollama pull ${model}`);
      }
      if (/image|vision|multimodal/i.test(detail)) {
        throw new AppError(502, "ai_no_vision", `The local model "${model}" can't read images. Use a vision model such as qwen3.5:4b or gemma4:e4b.`);
      }
      if (/memory|resources/i.test(detail)) {
        throw new AppError(503, "ai_busy", "Ollama ran out of memory for this model. Close other apps or use a smaller model.");
      }
      throw new AppError(502, "ai_error", `Ollama error: ${detail}`);
    }
    const usage: Usage = { inputTokens: body.prompt_eval_count ?? 0, outputTokens: body.eval_count ?? 0 };
    return { text: (body.message?.content ?? "").trim(), cut: body.done_reason === "length", usage, model: body.model ?? model };
  };

  const toMessages = (system: string, turns: ChatTurn[]) => [{ role: "system", content: system }, ...turns.map((t) => ({ role: t.role, content: t.content }))];

  return {
    name: "ollama",
    model,
    draftReport: async ({ system, user, signal }) => {
      const r = await call(toMessages(system, [{ role: "user", content: user }]), { format: REPORT_JSON_SCHEMA, maxTokens: 3000, signal });
      if (r.cut) throw new AppError(502, "ai_truncated", "The AI answer was cut off. Try again with fewer log lines (AI_MAX_LOG_LINES).");
      // Invalid JSON goes back as null so the validator reports it and the service retries once.
      let json: unknown = null;
      try { json = JSON.parse(r.text); } catch { json = null; }
      return { json, usage: r.usage, model: r.model };
    },
    explainLine: async ({ system, line, signal }) => {
      const r = await call(toMessages(system, [{ role: "user", content: `Explain this log line:\n${line}` }]), { maxTokens: 700, signal });
      return { text: r.text, usage: r.usage, model: r.model };
    },
    chat: async ({ system, messages, signal }) => {
      const r = await call(toMessages(system, messages), { maxTokens: 1200, signal });
      return { text: r.text, usage: r.usage, model: r.model };
    },
    readImage: async ({ system, prompt, image, signal }) => {
      const r = await call([{ role: "system", content: system }, { role: "user", content: prompt, images: [image.data] }], { maxTokens: 2500, signal });
      return { text: r.text, usage: r.usage, model: r.model };
    },
  };
}
