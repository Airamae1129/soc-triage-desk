import { ApiError, FinishReason, GoogleGenAI, type GenerateContentParameters, type GenerateContentResponse } from "@google/genai";
import { z } from "zod";
import { AppError } from "../lib/errors.js";
import { logger } from "../lib/logger.js";
import { ReportSchema } from "./report.js";
import { cancelled, type AiProvider, type Usage } from "./provider.js";

// Report JSON schema for Gemini's structured output. The server still validates the answer
// with zod (and checks facts against the input), so this only steers the model's shape.
const { $schema: _drop, ...REPORT_JSON_SCHEMA } = z.toJSONSchema(ReportSchema) as Record<string, unknown>;
void _drop;

// Finish reasons that mean Gemini's safety or policy filters stopped the answer.
const BLOCKED = new Set<string>([
  FinishReason.SAFETY, FinishReason.PROHIBITED_CONTENT, FinishReason.BLOCKLIST,
  FinishReason.SPII, FinishReason.RECITATION,
]);

// Gemini answers 500/503/504 when a model is overloaded ("high demand"); those are worth retrying.
const BUSY = new Set([500, 503, 504]);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export interface GeminiOptions {
  /** Model tried once when the main model stays busy after the retries. null = no fallback. */
  fallbackModel?: string | null;
  /** Waits before each retry of a busy model. */
  retryDelaysMs?: number[];
  /** Test hook (mocked HTTP); production uses the SDK's default fetch. */
  fetchFn?: typeof fetch;
}

/** Google Gemini through the official @google/genai SDK (Gemini Developer API, generateContent). */
export function geminiProvider(apiKey: string, model: string, opts: GeminiOptions = {}): AiProvider {
  const { fallbackModel = null, retryDelaysMs = [1500, 4000], fetchFn } = opts;
  const ai = new GoogleGenAI({ apiKey, httpOptions: { timeout: 120_000, ...(fetchFn ? { fetch: fetchFn } : {}) } });

  /** Calls the main model, retrying while it is busy, then the fallback model once. */
  const generate = async (params: Omit<GenerateContentParameters, "model">): Promise<GenerateContentResponse> => {
    const isBusy = (e: unknown) => e instanceof ApiError && BUSY.has(e.status);
    for (let attempt = 0; ; attempt++) {
      try {
        return await ai.models.generateContent({ ...params, model });
      } catch (e) {
        // A quota error (429) is per model, so skip the retries and go straight to the fallback.
        const quota = e instanceof ApiError && e.status === 429;
        if ((!isBusy(e) && !quota) || params.config?.abortSignal?.aborted) throw e;
        if (!quota && attempt < retryDelaysMs.length) { await sleep(retryDelaysMs[attempt]!); continue; }
        if (!fallbackModel || fallbackModel === model) throw e;
        try {
          return await ai.models.generateContent({ ...params, model: fallbackModel });
        } catch (e2) {
          if (e2 instanceof ApiError) logger.warn({ provider: "gemini", model: fallbackModel, status: e2.status, detail: e2.message.slice(0, 900) }, "AI fallback model error");
          throw isBusy(e2) || (e2 instanceof ApiError && e2.status === 429) ? e : e2;
        }
      }
    }
  };

  const usageOf = (r: GenerateContentResponse): Usage => ({
    // Thinking tokens are billed as output, so count them there.
    inputTokens: r.usageMetadata?.promptTokenCount ?? 0,
    outputTokens: (r.usageMetadata?.candidatesTokenCount ?? 0) + (r.usageMetadata?.thoughtsTokenCount ?? 0),
  });
  const refused = () => new AppError(422, "ai_refused", "The AI declined this request. Write this one by hand.");

  /** Throws on a blocked prompt, a filtered answer or (for reports) a cut-off answer. */
  const check = (r: GenerateContentResponse, truncatedIsError: boolean) => {
    if (r.promptFeedback?.blockReason) throw refused();
    const reason = r.candidates?.[0]?.finishReason;
    if (reason && BLOCKED.has(reason)) throw refused();
    if (truncatedIsError && reason === FinishReason.MAX_TOKENS) {
      throw new AppError(502, "ai_truncated", "The AI answer was cut off. Try again with fewer log lines (AI_MAX_LOG_LINES).");
    }
  };

  const wrap = async <T>(fn: () => Promise<T>): Promise<T> => {
    try {
      return await fn();
    } catch (e) {
      if (e instanceof AppError) throw e;
      if ((e as Error)?.name === "AbortError") throw cancelled();
      if (e instanceof ApiError) {
        // Google's message says which limit or problem it was; the logger masks any configured key.
        logger.warn({ provider: "gemini", model, status: e.status, detail: e.message.slice(0, 900) }, "AI provider error");
        // Gemini answers an invalid key with HTTP 400 "API key not valid".
        if (e.status === 401 || e.status === 403 || (e.status === 400 && /api key/i.test(e.message))) {
          throw new AppError(502, "ai_auth", "The AI provider rejected the API key. Check GEMINI_API_KEY.");
        }
        if (e.status === 404) throw new AppError(502, "ai_model", `The AI model "${model}" was not found. Check AI_MODEL.`);
        if (e.status === 429) {
          // Free-tier keys have a small daily request quota per model; say when it resets.
          const wait = e.message.match(/retry in ((?:\d+h)?(?:\d+m)?\d+(?:\.\d+)?s)/i)?.[1]?.replace(/\.\d+s$/, "s");
          if (/PerDay|per day|free_tier/i.test(e.message)) {
            throw new AppError(429, "ai_quota", `The daily AI quota for this Gemini key is used up${wait ? ` (resets in about ${wait})` : ""}. Enable billing on the Google AI project for higher limits.`);
          }
          throw new AppError(429, "ai_rate_limited", `The AI provider is rate limiting requests. Try again${wait ? ` in about ${wait}` : " in a minute"}.`);
        }
        if (e.status === 400) throw new AppError(502, "ai_bad_request", "The AI provider rejected the request.");
        if (BUSY.has(e.status)) throw new AppError(503, "ai_busy", "The AI model is busy right now (high demand at Google). Try again in a minute.");
        throw new AppError(502, "ai_error", `AI provider error (HTTP ${e.status}).`);
      }
      throw new AppError(502, "ai_unreachable", "Could not reach the AI provider.");
    }
  };

  return {
    name: "gemini",
    model,
    draftReport: ({ system, user, signal }) => wrap(async () => {
      const r = await generate({
        contents: [{ role: "user", parts: [{ text: user }] }],
        config: {
          systemInstruction: system,
          abortSignal: signal,
          responseMimeType: "application/json",
          responseJsonSchema: REPORT_JSON_SCHEMA,
          maxOutputTokens: 16000,
        },
      });
      check(r, true);
      // Invalid JSON goes back as null so the validator reports it and the service retries once.
      let json: unknown = null;
      try { json = JSON.parse(r.text ?? ""); } catch { json = null; }
      return { json, usage: usageOf(r), model: r.modelVersion ?? model };
    }),
    explainLine: ({ system, line, signal }) => wrap(async () => {
      const r = await generate({
        contents: [{ role: "user", parts: [{ text: `Explain this log line:\n${line}` }] }],
        config: { systemInstruction: system, abortSignal: signal, maxOutputTokens: 4000 },
      });
      check(r, false);
      return { text: (r.text ?? "").trim(), usage: usageOf(r), model: r.modelVersion ?? model };
    }),
    chat: ({ system, messages, signal }) => wrap(async () => {
      const r = await generate({
        // Gemini calls the assistant role "model".
        contents: messages.map((m) => ({ role: m.role === "assistant" ? "model" : "user", parts: [{ text: m.content }] })),
        config: { systemInstruction: system, abortSignal: signal, maxOutputTokens: 8000 },
      });
      check(r, false);
      return { text: (r.text ?? "").trim(), usage: usageOf(r), model: r.modelVersion ?? model };
    }),
    readImage: ({ system, prompt, image, signal }) => wrap(async () => {
      const r = await generate({
        contents: [{ role: "user", parts: [{ inlineData: { mimeType: image.mediaType, data: image.data } }, { text: prompt }] }],
        config: { systemInstruction: system, abortSignal: signal, maxOutputTokens: 4000 },
      });
      check(r, false);
      return { text: (r.text ?? "").trim(), usage: usageOf(r), model: r.modelVersion ?? model };
    }),
  };
}
