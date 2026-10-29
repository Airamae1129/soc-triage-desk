# SOC Triage Desk – PRD

## Original problem statement
Single-page, frontend-only "SOC Triage Desk" for SOC analysts. They use it to assess alerts, investigate, document, and hand over shifts. No backend: everything runs in the browser and is saved to localStorage. Six tabs: Assessment, Investigation, OSINT, SOC Notes, Playbook, Notables. Includes a rule-based MITRE engine, a firewall flow parser, an exact-format assessment report, a client email, a handover note, queries in 7 SIEM languages, and sample data. Visual spec: IBM Plex Sans Condensed / IBM Plex Sans / JetBrains Mono fonts, a teal accent, and light and dark themes. All times are Asia/Manila.

User choices: the theme follows the system setting and also has a manual toggle. Optional add-ons were requested; the ones that work frontend-only were built.

## Architecture
- React (CRA) frontend only. Code is in `/app/frontend/src/soc/`:
  - `util.js`: storage, Manila time, formatting, copy, masking
  - `engine.js`: analysis, MITRE rules, firewall parser, decode helper
  - `drafts.js`: report, email, handover and notables text
  - `queries.js`: query templates for 7 languages
  - `samples.js`: seed data
  - Tab components
- localStorage prefix is `socdesk.`. Every read and write is wrapped in try/catch.

## Implemented (Jun 2026)
- All 6 tabs as specified, plus the context strip, light/dark/system themes, and a responsive layout down to 400px.
- Add-ons:
  - Analyst identity input
  - JSON backup/restore and .txt exports
  - Base64 / `-enc` / URL decode helper
  - Report checklist warnings and title/log number mismatch warning
  - SLA countdown after escalation
  - Duplicate IOC/host detection
  - Rule tuning suggestions
  - Keyboard shortcuts
  - Redaction (mask) toggle with preview
- Tested by the testing agent in iteration 1: all flows passed. Minor issues were fixed afterwards.

## Iteration 2 (Jun 2026)
- Added a FastAPI backend with these endpoints:
  - `/api/ai/stream`: SSE streaming with Claude Sonnet 4.5 (`claude-sonnet-4-5-20250929`) on the Emergent LLM key. Modes are draft, chat and explain.
  - `/api/osint/lookup`: AbuseIPDB, VirusTotal and urlscan.io search, with a 24h cache in MongoDB `osint_cache`.
  - `/api/osint/screenshot` (screenshotbase.com): requires `confirmed:true` and tracks daily usage.
  - `/api/config`
- New tabs: Dashboard (7th; shift KPIs, chart and table) and AI Assistant (8th; Draft with AI, chat per ticket, Explain log line, mask before sending).
- The "Draft with AI" button on Assessment and the "Explain" button on the Investigation timeline both open the AI tab.
- OSINT: per-card and bulk Auto-fill, which keeps manual verdicts. Screenshot asks for confirmation in a dialog first.
- Header badge now reads "Local storage · AI/OSINT calls only when you click".
- The VirusTotal key is empty (the user will send it later) and shows as "API key not configured". To enable it, set `VIRUSTOTAL_API_KEY` in backend/.env.

## Backlog
- P1:
  - Shared team database with audit trail
  - IP enrichment autofill (ASN/Owner/Location from AbuseIPDB)
  - Add the VirusTotal key
- P2:
  - Per-client report templates
  - Auto-tick checklist items when an OSINT verdict is set

## Iteration 3 (Oct 2026, local)
- Tab order: Assessment, Investigation, AI Assistant, OSINT, SOC Notes, Playbook, Notables, Dashboard (shortcuts 1–8 follow it).
- OSINT keys (AbuseIPDB, VirusTotal, urlscan.io, Screenshotbase) live in `backend/.env`, which is git-ignored; `backend/.env.example` is the template.
- Backend runs without MongoDB: the OSINT cache and screenshot counter fall back to memory. AI stays off locally (no `emergentintegrations`).
- Screenshotbase panel in OSINT: the analyst types a URL, confirms in a dialog, and gets a hosted PNG link (`response_type=json`) with a Copy image URL button. Nothing runs without confirmation.
- "Results for the ticket" copy format: IP(s) Reputation (AbuseIPDB, VirusTotal), URL/Domain Reputation (VirusTotal, URLscan.io, plus a Screenshotbase line only when a screenshot was generated for that URL/domain), File Hash Reputation (VirusTotal). Screenshots of URLs that are not ticket indicators are listed at the end. IP lookups no longer call urlscan.io.
- Local ports: frontend 3011, backend 8011.
- Defang indicators: one shared checkbox on every copy box (Assessment, Investigation, AI Assistant, OSINT, SOC Notes, Notables), remembered in `socdesk.defang`. It changes the preview and the copied text: `1[.]2[.]3[.]4`, `example[.]com`, `hxxps://`, `user[@]example[.]com`. Never applied to SIEM queries, screenshot image links, file names or OSINT source names. The Ctrl+Shift+C report shortcut follows it too.
- OSINT is a standalone checker: indicators come only from what the analyst adds (several at once, separated by spaces or commas), stored under `socdesk.osint._workspace`, not per ticket. The ticket context strip is hidden on the OSINT tab.
- OSINT Results: chips with × to leave an indicator out of the copy text (+ adds it back), and a Clear button (asks first) that removes all indicators, results and screenshot links.
