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

## Backlog
- P1 (needs a backend or AI):
  - Shared team database with audit trail
  - "Draft with AI" report
  - "Explain this log line"
  - OSINT API autofill (AbuseIPDB/VT/urlscan) with a 24h cache
  - IP enrichment autofill
- P2:
  - Per-client report templates
  - Dashboard tab (shift metrics)
  - Auto-tick checklist items when an OSINT verdict is set
