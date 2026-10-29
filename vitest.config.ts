import { defineConfig } from "vitest/config";

// Tests use their own SQLite file and fake keys. Every key is set here so dotenv never
// loads the real ones from .env (dotenv does not override variables that already exist).
export default defineConfig({
  test: {
    environment: "node",
    globalSetup: ["./tests/global-setup.ts"],
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 60_000,
    env: {
      NODE_ENV: "test",
      DATABASE_URL: "file:./test.db",
      SESSION_SECRET: "test-session-secret-that-is-long-enough-1234567890",
      LOG_LEVEL: "silent",
      ABUSEIPDB_API_KEY: "test-abuseipdb-key",
      VIRUSTOTAL_API_KEY: "test-virustotal-key",
      URLSCAN_API_KEY: "test-urlscan-key",
      SHODAN_API_KEY: "",
      OTX_API_KEY: "",
      SCREENSHOTBASE_API_KEY: "",
      ANTHROPIC_API_KEY: "",
      GEMINI_API_KEY: "",
      AI_MODEL: "",
      AI_FALLBACK_MODEL: "",
      AI_PROVIDER: "none",
      OSINT_TIMEOUT_MS: "1000",
      OSINT_CACHE_HOURS: "24",
      VIRUSTOTAL_RATE_PER_MIN: "600",
      ABUSEIPDB_RATE_PER_MIN: "600",
      URLSCAN_RATE_PER_MIN: "600",
    },
  },
});
