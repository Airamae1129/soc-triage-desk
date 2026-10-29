import express from "express";
import session from "express-session";
import helmet from "helmet";
import { rateLimit } from "express-rate-limit";
import { pinoHttp } from "pino-http";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { config } from "./config.js";
import { prisma } from "./db.js";
import { logger } from "./lib/logger.js";
import { errorHandler, notFoundApi } from "./lib/errors.js";
import { PrismaSessionStore } from "./auth/session-store.js";
import { requireAuth, requireAdmin, requireXhrHeader } from "./auth/middleware.js";
import { authRouter } from "./auth/routes.js";
import { bootstrapAccounts } from "./auth/bootstrap.js";
import { assessmentsRouter } from "./routes/assessments.js";
import { notesRouter } from "./routes/notes.js";
import { playbooksRouter } from "./routes/playbooks.js";
import { notablesRouter } from "./routes/notables.js";
import { osintRouter } from "./routes/osint.js";
import { aiRouter } from "./routes/ai.js";
import { usersRouter } from "./routes/users.js";
import { auditRouter } from "./routes/audit.js";
import { getAiProvider } from "./ai/provider.js";

const here = path.dirname(fileURLToPath(import.meta.url));
// src/ in dev (tsx), dist/src/ when built: find the project root either way.
const ROOT = [path.resolve(here, ".."), path.resolve(here, "../..")].find((p) => existsSync(path.join(p, "package.json"))) ?? process.cwd();
export const PUBLIC_DIR = path.join(ROOT, "public");
const SESSION_TTL_MS = 12 * 3600e3;

export function createApp() {
  const app = express();
  app.disable("x-powered-by");
  if (config.TRUST_PROXY) app.set("trust proxy", config.TRUST_PROXY);

  app.use(helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        // The two hashes are the <style> tag sonner (toasts, pinned 2.0.3) injects at runtime and
        // its empty placeholder. The same CSS also ships as a file, so a new sonner version only
        // costs a console warning, never a broken page. No 'unsafe-inline'.
        styleSrc: ["'self'", "https://fonts.googleapis.com", "'sha256-7lAG9nNPimWNBky6j9qnn0jfFzu5wK96KOj/UzoG0hg='", "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='"],
        fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
        // https: for Screenshotbase image links (images only, never scripts).
        imgSrc: ["'self'", "data:", "blob:", "https:"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: config.COOKIE_SECURE ? [] : null,
      },
    },
    crossOriginEmbedderPolicy: false,
    hsts: config.COOKIE_SECURE,
  }));

  app.use(pinoHttp({
    logger,
    autoLogging: { ignore: (req) => !req.url?.startsWith("/api") || req.url === "/api/health" },
    serializers: {
      req: (req: { method: string; url: string }) => ({ method: req.method, url: req.url.split("?")[0] }),
      res: (res: { statusCode: number }) => ({ statusCode: res.statusCode }),
    },
  }));

  app.use(express.json({ limit: "2mb" }));

  const store = new PrismaSessionStore(SESSION_TTL_MS);
  app.use(session({
    name: "socdesk.sid",
    secret: config.SESSION_SECRET,
    store,
    resave: false,
    saveUninitialized: false,
    rolling: false,
    cookie: { httpOnly: true, sameSite: "strict", secure: config.COOKIE_SECURE, maxAge: SESSION_TTL_MS, path: "/" },
  }));

  const limiter = (windowMs: number, limit: number, message: string) =>
    rateLimit({ windowMs, limit, standardHeaders: "draft-7", legacyHeaders: false, skip: () => config.NODE_ENV === "test",
      handler: (_req, res) => { res.status(429).json({ error: { code: "rate_limited", message } }); } });

  const api = express.Router();
  api.use(limiter(5 * 60e3, 600, "Too many requests. Slow down for a minute."));
  api.use(requireXhrHeader);

  api.get("/health", async (_req, res) => {
    let db = true;
    try { await prisma.$queryRaw`SELECT 1`; } catch { db = false; }
    res.status(db ? 200 : 503).json({ ok: db, db, ai: getAiProvider().name !== "none", time: new Date().toISOString() });
  });

  api.use("/auth/login", limiter(15 * 60e3, 30, "Too many sign-in attempts from this address. Try again later."));
  api.use("/auth", authRouter);

  api.use(requireAuth);
  api.use("/assessments", assessmentsRouter);
  api.use("/notes", notesRouter);
  api.use("/playbooks", playbooksRouter);
  api.use("/notables", notablesRouter);
  api.use("/osint", limiter(60e3, 60, "Too many OSINT requests. Wait a minute."), osintRouter);
  api.use("/ai", limiter(60e3, 20, "Too many AI requests. Wait a minute."), aiRouter);
  api.use("/users", requireAdmin, usersRouter);
  api.use("/audit", requireAdmin, auditRouter);
  api.use(notFoundApi);

  app.use("/api", api);

  // Frontend (React build) from /public, with the SPA fallback for everything else.
  if (existsSync(path.join(PUBLIC_DIR, "index.html"))) {
    app.use(express.static(PUBLIC_DIR, { index: false, maxAge: "1h", setHeaders: (res, p) => { if (p.endsWith(".html")) res.setHeader("Cache-Control", "no-store"); } }));
    app.get(/^(?!\/api\/).*/, (_req, res) => { res.setHeader("Cache-Control", "no-store"); res.sendFile(path.join(PUBLIC_DIR, "index.html")); });
  } else {
    app.get(/^(?!\/api\/).*/, (_req, res) => {
      res.status(503).type("text").send("The frontend isn't built yet. Run: npm run build:ui");
    });
  }

  app.use(errorHandler);
  return { app, store };
}

// Start when run directly (npm run dev / npm start), not when imported by tests.
const isMain = process.argv[1] && path.resolve(process.argv[1]).replace(/\.[jt]s$/, "") === fileURLToPath(import.meta.url).replace(/\.[jt]s$/, "");
if (isMain) {
  const { app } = createApp();
  try { await bootstrapAccounts(); } catch (e) { logger.error({ err: e }, "Couldn't create the accounts from the environment"); }
  const server = app.listen(config.PORT, () => {
    logger.info(`SOC Triage Playbook running at http://localhost:${config.PORT} (AI: ${getAiProvider().name})`);
  });
  const stop = () => { server.close(() => { void prisma.$disconnect().finally(() => process.exit(0)); }); };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}
