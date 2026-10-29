import pino from "pino";
import { config, secretValues } from "../config.js";

// Structured logs. Auth headers, cookies, API keys and raw log bodies are redacted, and any
// configured secret value that slips into a message is masked as a last line of defence.

const secrets = secretValues();
const mask = (s: string) => secrets.reduce((acc, v) => acc.split(v).join("[REDACTED]"), s);

export const logger = pino({
  level: config.NODE_ENV === "test" ? "silent" : config.LOG_LEVEL,
  redact: {
    paths: [
      "req.headers.authorization", "req.headers.cookie", 'req.headers["x-api-key"]', 'req.headers["x-apikey"]',
      'res.headers["set-cookie"]',
      "*.password", "*.passwordHash", "*.apiKey", "*.apikey", "*.key", "*.token", "*.secret",
      "*.rawLogs", "*.logs", "*.line", "body", "req.body",
    ],
    censor: "[REDACTED]",
  },
  hooks: {
    logMethod(args, method) {
      method.apply(this, args.map((a) => (typeof a === "string" ? mask(a) : a)) as Parameters<typeof method>);
    },
  },
});
