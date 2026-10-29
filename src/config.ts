import "dotenv/config";
import { z } from "zod";

// Reads and validates .env once at startup. Missing required values stop the server
// with a clear message instead of failing later at request time.

const emptyToUndef = (v: unknown) => (typeof v === "string" && v.trim() === "" ? undefined : v);
const optKey = z.preprocess(emptyToUndef, z.string().trim().optional());
const bool = (def: boolean) =>
  z.preprocess((v) => (v === undefined || v === "" ? def : String(v).toLowerCase() === "true" || v === "1"), z.boolean());
const int = (def: number, min = 0) => z.preprocess(emptyToUndef, z.coerce.number().int().min(min).default(def));

const schema = z.object({
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  PORT: int(3000, 1),
  SESSION_SECRET: z.string({ error: "SESSION_SECRET is required" }).min(32, "SESSION_SECRET must be at least 32 characters"),
  DATABASE_URL: z.string({ error: "DATABASE_URL is required" }).min(1, "DATABASE_URL is required"),
  COOKIE_SECURE: bool(false),
  TRUST_PROXY: int(0),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),

  ABUSEIPDB_API_KEY: optKey,
  VIRUSTOTAL_API_KEY: optKey,
  URLSCAN_API_KEY: optKey,
  SHODAN_API_KEY: optKey,
  OTX_API_KEY: optKey,
  SCREENSHOTBASE_API_KEY: optKey,
  OSINT_CACHE_HOURS: int(24),
  ABUSEIPDB_RATE_PER_MIN: int(30, 1),
  VIRUSTOTAL_RATE_PER_MIN: int(4, 1),
  URLSCAN_RATE_PER_MIN: int(60, 1),
  SHODAN_RATE_PER_MIN: int(60, 1),
  OTX_RATE_PER_MIN: int(60, 1),
  OSINT_TIMEOUT_MS: int(10000, 1000),
  URLSCAN_VISIBILITY: z.enum(["private", "unlisted"]).default("private"),

  AI_PROVIDER: z.preprocess(emptyToUndef, z.enum(["none", "anthropic", "gemini", "ollama"]).default("none")),
  ANTHROPIC_API_KEY: optKey,
  GEMINI_API_KEY: optKey,
  // Empty = the provider's default (see DEFAULT_MODEL in src/ai/provider.ts).
  AI_MODEL: optKey,
  // Gemini only: model tried when AI_MODEL stays busy. Empty = gemini-3.5-flash, "off" = none.
  AI_FALLBACK_MODEL: optKey,
  // Ollama (local models): where it runs, context window, and how long a request may take.
  OLLAMA_URL: z.preprocess(emptyToUndef, z.string().url("OLLAMA_URL must be a URL like http://127.0.0.1:11434").default("http://127.0.0.1:11434")),
  OLLAMA_NUM_CTX: int(8192, 2048),
  OLLAMA_TIMEOUT_MS: int(600000, 10000),
  AI_MAX_LOG_LINES: int(200, 10),
  AI_REFUSAL_FALLBACK: bool(true),
});

export type Config = z.infer<typeof schema>;

function load(): Config {
  const parsed = schema.safeParse(process.env);
  if (!parsed.success) {
    const lines = parsed.error.issues.map((i) => `  - ${i.path.join(".") || "env"}: ${i.message}`);
    // Never print values, only which settings are wrong.
    console.error(`\nSOC Triage Playbook cannot start. Fix these settings in .env:\n${lines.join("\n")}\n`);
    process.exit(1);
  }
  const c = parsed.data;
  if (c.AI_PROVIDER === "anthropic" && !c.ANTHROPIC_API_KEY) {
    console.error("\nSOC Triage Playbook cannot start: AI_PROVIDER=anthropic needs ANTHROPIC_API_KEY in .env (or set AI_PROVIDER=none).\n");
    process.exit(1);
  }
  if (c.AI_PROVIDER === "gemini" && !c.GEMINI_API_KEY) {
    console.error("\nSOC Triage Playbook cannot start: AI_PROVIDER=gemini needs GEMINI_API_KEY in .env (or set AI_PROVIDER=none).\n");
    process.exit(1);
  }
  return c;
}

export const config: Config = load();

/** Names of settings whose values must never be logged or returned. */
export const SECRET_SETTINGS = [
  "SESSION_SECRET", "ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY", "URLSCAN_API_KEY", "SHODAN_API_KEY",
  "OTX_API_KEY", "SCREENSHOTBASE_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
] as const;

/** All configured secret values, used by the logger and tests to make sure none leak. */
export function secretValues(): string[] {
  return SECRET_SETTINGS.map((k) => config[k]).filter((v): v is string => typeof v === "string" && v.length >= 8);
}
