import Anthropic from "@anthropic-ai/sdk";
import { betaZodOutputFormat } from "@anthropic-ai/sdk/helpers/beta/zod";
import { config } from "../config.js";
import { AppError } from "../lib/errors.js";
import { ReportSchema } from "./report.js";
import { geminiProvider } from "./gemini.js";
import { ollamaProvider } from "./ollama.js";

export interface Usage { inputTokens: number; outputTokens: number }
export interface ChatTurn { role: "user" | "assistant"; content: string }
/** A screenshot as base64 (no data: prefix). */
export interface ImageInput { mediaType: "image/png" | "image/jpeg" | "image/webp"; data: string }

/** What the rest of the app needs from an AI backend. */
export interface AiProvider {
  name: "none" | "anthropic" | "gemini" | "ollama";
  model: string | null;
  /** Returns the raw JSON the model produced (validated by the caller). */
  draftReport(input: { system: string; user: string; signal?: AbortSignal }): Promise<{ json: unknown; usage: Usage; model: string }>;
  explainLine(input: { system: string; line: string; signal?: AbortSignal }): Promise<{ text: string; usage: Usage; model: string }>;
  chat(input: { system: string; messages: ChatTurn[]; signal?: AbortSignal }): Promise<{ text: string; usage: Usage; model: string }>;
  /** Reads a screenshot (needs a model that accepts images). */
  readImage(input: { system: string; prompt: string; image: ImageInput; signal?: AbortSignal }): Promise<{ text: string; usage: Usage; model: string }>;
}

/** The browser went away or the analyst pressed Stop; nobody is waiting for the answer. */
export const cancelled = () => new AppError(499, "ai_cancelled", "The AI request was cancelled.");

const disabled = () => new AppError(503, "ai_disabled", "AI is not configured. Set AI_PROVIDER (ollama, gemini or anthropic) in .env.");

export const noneProvider: AiProvider = {
  name: "none",
  model: null,
  draftReport: async () => { throw disabled(); },
  explainLine: async () => { throw disabled(); },
  chat: async () => { throw disabled(); },
  readImage: async () => { throw disabled(); },
};

/** Claude through the official @anthropic-ai/sdk (Messages API). */
export function anthropicProvider(apiKey: string, model: string, refusalFallback: boolean): AiProvider {
  const client = new Anthropic({ apiKey, maxRetries: 2, timeout: 120_000 });
  // If Claude declines for safety reasons, the API re-runs the request on Anthropic's
  // recommended fallback model instead of returning the refusal (AI_REFUSAL_FALLBACK).
  const fallback = refusalFallback ? { betas: ["server-side-fallback-2026-07-01"], fallbacks: "default" as const } : { betas: [] as string[] };

  const usageOf = (u: { input_tokens: number; output_tokens: number }): Usage => ({ inputTokens: u.input_tokens, outputTokens: u.output_tokens });
  const refused = () => new AppError(422, "ai_refused", "The AI declined this request. Write this one by hand.");
  const textOf = (content: { type: string }[]) => content.filter((b): b is { type: "text"; text: string } => b.type === "text").map((b) => b.text).join("").trim();

  const wrap = async <T>(fn: () => Promise<T>): Promise<T> => {
    try {
      return await fn();
    } catch (e) {
      if (e instanceof AppError) throw e;
      if (e instanceof Anthropic.APIUserAbortError) throw cancelled();
      if (e instanceof Anthropic.AuthenticationError || e instanceof Anthropic.PermissionDeniedError) throw new AppError(502, "ai_auth", "The AI provider rejected the API key. Check ANTHROPIC_API_KEY.");
      if (e instanceof Anthropic.NotFoundError) throw new AppError(502, "ai_model", `The AI model "${model}" was not found. Check AI_MODEL.`);
      if (e instanceof Anthropic.RateLimitError) throw new AppError(429, "ai_rate_limited", "The AI provider is rate limiting requests. Try again in a minute.");
      if (e instanceof Anthropic.BadRequestError) throw new AppError(502, "ai_bad_request", "The AI provider rejected the request.");
      if (e instanceof Anthropic.APIConnectionError) throw new AppError(502, "ai_unreachable", "Could not reach the AI provider.");
      if (e instanceof Anthropic.APIError) throw new AppError(502, "ai_error", `AI provider error (HTTP ${e.status ?? "?"}).`);
      throw e;
    }
  };

  return {
    name: "anthropic",
    model,
    draftReport: ({ system, user, signal }) => wrap(async () => {
      const res = await client.beta.messages.parse({
        model,
        max_tokens: 16000,
        system,
        messages: [{ role: "user", content: user }],
        output_config: { effort: "high", format: betaZodOutputFormat(ReportSchema) },
        ...fallback,
      }, { signal });
      if (res.stop_reason === "refusal") throw refused();
      if (res.stop_reason === "max_tokens") throw new AppError(502, "ai_truncated", "The AI answer was cut off. Try again with fewer log lines (AI_MAX_LOG_LINES).");
      // parsed_output is null if the JSON didn't match; fall back to the raw text so the
      // validator can report what was wrong.
      let json: unknown = res.parsed_output;
      if (json == null) { try { json = JSON.parse(textOf(res.content)); } catch { json = null; } }
      return { json, usage: usageOf(res.usage), model: res.model };
    }),
    explainLine: ({ system, line, signal }) => wrap(async () => {
      const res = await client.beta.messages.create({
        model,
        max_tokens: 4000,
        system,
        messages: [{ role: "user", content: `Explain this log line:\n${line}` }],
        output_config: { effort: "low" },
        ...fallback,
      }, { signal });
      if (res.stop_reason === "refusal") throw refused();
      return { text: textOf(res.content), usage: usageOf(res.usage), model: res.model };
    }),
    chat: ({ system, messages, signal }) => wrap(async () => {
      const res = await client.beta.messages.create({
        model,
        max_tokens: 8000,
        system,
        messages: messages.map((m) => ({ role: m.role, content: m.content })),
        output_config: { effort: "medium" },
        ...fallback,
      }, { signal });
      if (res.stop_reason === "refusal") throw refused();
      return { text: textOf(res.content), usage: usageOf(res.usage), model: res.model };
    }),
    readImage: ({ system, prompt, image, signal }) => wrap(async () => {
      const res = await client.beta.messages.create({
        model,
        max_tokens: 4000,
        system,
        messages: [{ role: "user", content: [
          { type: "image", source: { type: "base64", media_type: image.mediaType, data: image.data } },
          { type: "text", text: prompt },
        ] }],
        output_config: { effort: "low" },
        ...fallback,
      }, { signal });
      if (res.stop_reason === "refusal") throw refused();
      return { text: textOf(res.content), usage: usageOf(res.usage), model: res.model };
    }),
  };
}

/** Model used when AI_MODEL is empty. */
export const DEFAULT_MODEL = { anthropic: "claude-opus-5-5", gemini: "gemini-3.8-flash", ollama: "qwen3.5:4b" } as const;
/** Gemini model tried when the main one is busy and AI_FALLBACK_MODEL is empty. */
export const DEFAULT_FALLBACK = { gemini: "gemini-3.5-flash" } as const;

let provider: AiProvider | null = null;
export function getAiProvider(): AiProvider {
  if (!provider) {
    provider = config.AI_PROVIDER === "anthropic" && config.ANTHROPIC_API_KEY
      ? anthropicProvider(config.ANTHROPIC_API_KEY, config.AI_MODEL ?? DEFAULT_MODEL.anthropic, config.AI_REFUSAL_FALLBACK)
      : config.AI_PROVIDER === "gemini" && config.GEMINI_API_KEY
        ? geminiProvider(config.GEMINI_API_KEY, config.AI_MODEL ?? DEFAULT_MODEL.gemini, {
          fallbackModel: config.AI_FALLBACK_MODEL === "off" ? null : config.AI_FALLBACK_MODEL ?? DEFAULT_FALLBACK.gemini,
        })
        : config.AI_PROVIDER === "ollama"
          ? ollamaProvider(config.OLLAMA_URL, config.AI_MODEL ?? DEFAULT_MODEL.ollama, { numCtx: config.OLLAMA_NUM_CTX, timeoutMs: config.OLLAMA_TIMEOUT_MS })
          : noneProvider;
  }
  return provider;
}
/** Test hook. */
export function setAiProvider(p: AiProvider | null) { provider = p; }
