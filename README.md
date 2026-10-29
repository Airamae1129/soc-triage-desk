# SOC Triage Playbook

_Created by Aira Mae Bugay._

Internal console for SOC analysts: assess alerts, investigate, look up indicators, keep notes and hand over shifts.

- **Backend:** Node.js 20 + Express + TypeScript (strict), Prisma on SQLite (PostgreSQL later by changing `DATABASE_URL`).
- **Frontend:** the React app in `frontend/`, built into `public/` and served by the same server. Open **http://localhost:3000**. No CORS setup is needed.
- **Data:** everything shared (assessments, notes, OSINT verdicts, playbooks, checklists, escalations) is stored on the server. The browser keeps only UI conveniences such as the last tab, theme and query language.
- **API keys** stay in `.env` on the server. They are never sent to the browser, written to logs or returned by the API.

---

## Windows setup (local testing)

1. **Install Node.js 20 LTS** from <https://nodejs.org> (the "LTS" installer). Open a new PowerShell window and check it:
   ```powershell
   node -v
   ```
2. **Install packages** in the project folder:
   ```powershell
   npm install
   ```
3. **Create your settings file.** Copy the example:
   ```powershell
   copy .env.example .env
   ```
   Open `.env` in Notepad and set `SESSION_SECRET` to a long random string. You can generate one with:
   ```powershell
   node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
   ```
4. **Add API keys** (optional; see [Adding API keys](#adding-api-keys)). Any provider left empty is turned off and shows as "Not configured".
5. **Create the database:**
   ```powershell
   npx prisma migrate dev
   ```
6. **Create the first admin.** You will be asked for the password twice. It is never echoed or stored in shell history.
   ```powershell
   npm run create-admin -- --username jdoe --display "Jane Doe"
   ```
7. **Load sample data** (optional): two fictional clients' playbooks and two sample assessments. Safe to run more than once.
   ```powershell
   npm run seed
   ```
8. **Start the app:**
   ```powershell
   npm run dev
   ```
   The first run builds the frontend into `public/`, which takes a minute or two. Then open <http://localhost:3000> and sign in.

> **Windows tip:** stop the server (Ctrl+C) before running `npm install` or `npx prisma generate`. Windows locks Prisma's engine file while the server runs, and the install fails with `EPERM ... rename`.

### Scripts

| Command | What it does |
|---|---|
| `npm run dev` | API with auto-reload, serving the built frontend from `public/` (builds it the first time). |
| `npm run dev:ui` | API plus the React dev server with hot reload on <http://localhost:3001>, which proxies `/api` to port 3000. Use it while editing the frontend. |
| `npm run build:ui` | Rebuilds the frontend into `public/`. Run it after changing frontend code if you use `npm run dev`. |
| `npm run build` | Builds the frontend and compiles the server to `dist/`. |
| `npm start` | Runs the compiled server (`dist/`). Run `npm run build` first. |
| `npm test` | Runs the tests (vitest + supertest). They use their own `test.db` and fake keys, and never call real providers. |
| `npm run seed` | Loads the fictional sample data. |
| `npm run create-admin -- --username <name>` | Creates an admin, or resets an existing user's password and makes them admin. |
| `npm run db:deploy` | Applies migrations without prompting (servers, Docker). |

---

## Adding API keys

All keys go in `.env` and nowhere else. `.env` is git-ignored; only `.env.example`, with empty values, is committed. Restart the server after changing `.env`.

| Setting | Where to get it | Used for |
|---|---|---|
| `ABUSEIPDB_API_KEY` | abuseipdb.com → Account → API | IP abuse confidence, reports, ISP, usage type, Tor |
| `VIRUSTOTAL_API_KEY` | virustotal.com → your profile → API key | IP, domain, URL and file hash reports |
| `URLSCAN_API_KEY` | urlscan.io → Settings & API | Search of existing scans. New scans run only when an analyst clicks **Scan**, and are always private (or unlisted if your plan has no private scans) |
| `SHODAN_API_KEY` | account.shodan.io | Open ports, org, ASN (optional) |
| `OTX_API_KEY` | otx.alienvault.com → Settings | Pulse count and tags (optional) |
| `SCREENSHOTBASE_API_KEY` | screenshotbase.com | URL-to-image screenshots, only after the analyst confirms (optional) |
| `GEMINI_API_KEY` + `AI_PROVIDER=gemini` | aistudio.google.com/apikey | The AI assistant with Google Gemini (Draft with AI, Explain line, chat) |
| `ANTHROPIC_API_KEY` + `AI_PROVIDER=anthropic` | console.anthropic.com → API keys | The AI assistant with Claude instead. Leave `AI_PROVIDER=none` to keep AI off; the AI buttons are then hidden |

**Rate limits.** Each provider has a request queue (`*_RATE_PER_MIN`) and backs off on HTTP 429. The defaults match the free plans, for example VirusTotal's public API at 4 requests per minute. If your key is on a paid plan, check the limit on the provider's plan page and raise the setting.

**Cache.** Answers are reused for `OSINT_CACHE_HOURS` (default 24). The app shows "cached <time>" when it reuses one. Use **Refresh** on an indicator to skip the cache.

**What is never looked up:** private and reserved IPs (RFC1918, loopback, link-local, CGNAT, multicast) and internal-looking hostnames (`.local`, `.corp`, `.internal`, single-label names and so on). The server refuses them with a clear error.

**AI and data.** Before anything goes to the AI, the server keeps the `AI_MAX_LOG_LINES` most relevant log lines and replaces the client name, usernames, internal hostnames and internal IPs with tokens (`CLIENT_1`, `USER_1`, `HOST_1`, `INTIP_1`). The mapping exists only in memory for that request. The answer is checked: any IP, domain or hash the AI invents, a verdict longer than 2 sentences, or a missing section is rejected and retried once. Drafts are marked "Drafted by AI – review before use". If `AI_MODEL` is empty, the default is `gemini-3.8-flash` for Gemini and `claude-opus-5-5` for Anthropic. With Anthropic and `AI_REFUSAL_FALLBACK=true`, a request Claude declines for safety reasons is retried on Anthropic's recommended fallback model.

### AI report format

**Draft with AI** writes the report in this layout. The server builds the title line from the ticket fields (ticket, alert name, severity, status, owner, classification), and the AI fills in the sections:

```
INC 14301 – <alert name> (<severity> – <status> – <owner> – <classification>)

Assessment:
- what the rule flagged, what drove it, the pattern in the evidence
  - per-table / per-host details

Verdict: <label>. <reason>. Close as NFA, with one recommendation: <follow-up>.

Alert Details / Indicators:
Key: value

Supporting Evidence:
<heading>:
<lines, or a tab-separated table>

Query Used:
kql
<query>
```

Put your query results and the queries you ran in **Analyst findings** (or Raw logs). The AI only lists queries that you provided, copied exactly. A draft is rejected and retried once if it contains an IP, domain or hash that isn't in the input, a query you didn't provide, or a verdict longer than 4 sentences.

### AI on pasted logs (no ticket)

On the **AI Assistant** tab, switch to **Paste logs**. Enter an alert name, paste the logs and, if you have them, your findings, query results and the queries you ran. Then:

- **Draft report** writes a report in the format above, with the same masking and checks. The title line says "Pasted logs" instead of a ticket number.
- **Ask about the pasted logs** answers questions, such as what happened, whether it's malicious, or what to check next.
- **Copy to Assessment** moves the alert name, logs and findings into the Assessment form, so you can save them as a ticket.

Pasted logs and their chat stay in the page's memory only. They aren't saved on the server or in the browser. The audit log records that a draft was made, with token counts but no log content.

### Reading screenshots

On the **AI Assistant** tab, **Read a screenshot** takes a PNG, JPEG or WebP. Upload it, drag it in, or paste it with Ctrl+V after Win+Shift+S. The AI transcribes the visible log lines and table rows and adds a short analysis. **Add to Raw logs** or **Add to Analyst findings** puts the text into the ticket, where it goes through the normal redaction and checks. The browser shrinks the image before upload, and the server doesn't store it.

Screenshots can't be redacted. With a local model nothing leaves the server. With Gemini or Anthropic the app warns first: crop out client names and users before you upload. This needs a model that reads images: `qwen3.5:4b`, `gemma4:e4b`, Gemini and Claude all do.

### Turning on the AI assistant with a local model (Ollama, free)

A local model runs on your own machine through [Ollama](https://ollama.com). It costs nothing, has no quota, and logs never leave the machine. It is slower than a cloud model: on a laptop CPU, expect about 20–40 s for Explain line and 2–5 minutes for Draft with AI with a 4B model.

1. Install Ollama for Windows from <https://ollama.com/download>. It runs in the background on `http://127.0.0.1:11434`.
2. Download a model (about 3 GB):
   ```powershell
   ollama pull qwen3.5:4b
   ```
   Alternatives: `gemma4:e4b` (similar size), or an 8B model such as `qwen3:8b` on a machine with 16 GB RAM or more (better answers, about twice as slow).
3. In `.env`, set:
   ```
   AI_PROVIDER=ollama
   AI_MODEL=qwen3.5:4b
   AI_MAX_LOG_LINES=60
   ```
4. Restart the server.

**Deploying with a local model:** run Ollama on the same server as the app (`docker compose --profile local-ai up -d`, then `docker compose exec ollama ollama pull qwen3.5:4b`), or point `OLLAMA_URL` at another machine that runs Ollama. A server with an NVIDIA GPU answers in seconds instead of minutes. Small free cloud hosts (for example the Render free tier) don't have the memory to run a model, so use the Ollama-on-your-own-machine setup there, or a cloud AI provider.

### Turning on the AI assistant with Gemini

1. Create a key at <https://aistudio.google.com/apikey>. For real client data, use a key on a Google Cloud project with **billing enabled**. On the free tier, Google may use prompts and answers to improve its products, and the rate limits are low.
2. In `.env`, set:
   ```
   AI_PROVIDER=gemini
   GEMINI_API_KEY=<your key>
   AI_MODEL=
   ```
   Leave `AI_MODEL` empty for `gemini-3.8-flash`, or set another model from <https://ai.google.dev/gemini-api/docs/models>, for example `gemini-4-argon` for harder reports.
3. Restart the server (`Ctrl+C`, then `npm run dev`). The **Draft with AI** button appears on the Assessment tab, and the AI Assistant tab turns on.

If the key is wrong, the app says "The AI provider rejected the API key." If the model name is wrong, it says "The AI model … was not found." If the free-tier quota runs out, it says "rate limiting requests or the quota is used up."

---

## Users and roles

- **admin:** everything an analyst can do, plus create, disable and reset users (**Admin** button, top right), edit playbooks, and view the audit log.
- **analyst:** assessments, notes, checklist, OSINT and AI.

Sign-in sessions last 12 hours. The session cookie is `httpOnly` and `sameSite=strict`. Set `COOKIE_SECURE=true` once the app is served over HTTPS. Five wrong passwords for one username within 15 minutes lock that username temporarily. The error message never says which part was wrong.

Every change to assessments, playbooks and users, and every OSINT lookup and AI draft, is written to the audit log (`GET /api/audit`, admin only). Audit entries never contain secrets or raw logs.

---

## Docker

```powershell
copy .env.example .env      # then fill it in (SESSION_SECRET at least)
docker compose up -d --build
docker compose exec app npm run create-admin -- --username jdoe
docker compose exec app npm run seed        # optional sample data
```

The database lives in the `socdesk-data` volume at `/data/soc.db`, so it survives rebuilds. Migrations are applied automatically each time the container starts. `.env` is passed in at run time and is never copied into the image (see `.dockerignore`).

---

## Moving to a company server

- **PostgreSQL:** in `prisma/schema.prisma` change `provider = "sqlite"` to `"postgresql"`, set `DATABASE_URL=postgresql://user:pass@host:5432/socdesk`, delete `prisma/migrations`, and run `npx prisma migrate dev --name init` once. Status, verdict and role fields are plain strings validated in code, so nothing in the schema is SQLite-specific.
- **Behind a reverse proxy** (nginx, IIS, a load balancer): set `TRUST_PROXY=1` so the audit log and rate limits see the real client IP. Serve over HTTPS and set `COOKIE_SECURE=true`.
- **Backups:** back up the database (`prisma/soc.db`, or the Docker volume). `.env` holds the keys; store it like any other secret.

---

## Project layout

```
src/
  server.ts       app setup, helmet CSP, rate limits, sessions, static files, routes
  config.ts       reads and validates .env with zod (stops at startup if something is missing)
  db.ts           Prisma client
  auth/           login, logout, session store, password hashing, role checks, create-admin
  routes/         assessments, notes, osint, playbooks, notables, ai, users, audit
  osint/          one module per provider, cache, queue, indicator validation, verdict
  ai/             provider interface, Anthropic provider, prompt, validator, redaction, report
  lib/            log trimming, IOC extraction, shifts (Asia/Manila), errors, logger, audit
prisma/           schema.prisma, migrations, seed.ts
frontend/         React source (built into public/)
public/           built frontend (generated; not committed)
tests/            vitest + supertest
```

### API overview

All endpoints return JSON. Errors use the shape `{ "error": { "code", "message" } }`. Every route except `POST /api/auth/login` and `GET /api/health` needs a session. Every state-changing request (POST, PUT, PATCH, DELETE) must send the `X-Requested-With` header (CSRF protection, alongside `sameSite=strict`).

- **Auth:** `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`
- **Users (admin):** `GET/POST /api/users`, `PATCH /api/users/:id`
- **Assessments:** `GET /api/assessments?client=&q=&limit=`, `GET/PUT /api/assessments/:id`, `POST /api/assessments` (upsert on client + ticket), `POST/DELETE /api/assessments/:id/escalate`, `PATCH /api/assessments/:id/status`
- **Notes:** `GET/POST /api/assessments/:id/notes`, `DELETE /api/notes/:id` (author or admin)
- **Checklist:** `GET/PUT /api/assessments/:id/checklist`
- **Playbooks:** `GET /api/playbooks`, `GET /api/playbooks/:client`, `PUT /api/playbooks/:client` (admin)
- **Notables:** `GET /api/notables?shift=<YYYY-MM-DD>|<Morning|Mid|Night>`. Shifts are in Asia/Manila; Night runs 22:00–06:00 and belongs to the date it started.
- **OSINT:** `GET /api/osint/providers`, `POST /api/osint/lookup { indicator, type?, providers?, force? }`, `PUT /api/assessments/:id/osint/:indicator`, plus the per-analyst workspace (`/api/osint/workspace`), `POST /api/osint/urlscan/scan` and `POST /api/osint/screenshot` (both need `confirmed: true`)
- **AI:** `GET /api/ai/status`, `POST /api/ai/draft-report { assessmentId }`, `POST /api/ai/explain-line { line }`
- **Audit (admin):** `GET /api/audit?limit=`
- **Health:** `GET /api/health` (returns no secrets)
