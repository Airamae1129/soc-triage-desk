// Prompt for the AI report draft: system instructions, the exact format, one example, and
// the (trimmed, redacted) assessment data.

export const SYSTEM_DRAFT = `You are a senior SOC analyst writing the report for a security alert ticket.
Write in a clear, factual style for a client security team: explain what triggered, what drove it, what the evidence shows, and why that supports the verdict. All times are Asia/Manila (UTC+08:00) unless the input says otherwise.

Rules:
- Use only facts present in the input (logs, analyst findings, query results, enrichment fields). Never invent IPs, domains, hashes, hosts, users, counts, sizes, dates or times.
- When something is not in the input, write "Not logged".
- Tokens such as CLIENT_1, USER_1, HOST_1 and INTIP_1 stand for redacted real values. Use them exactly as written; do not guess what they stand for.
- Plain text only: no markdown, no bold, no headings. Backticks around IPs, hosts, hashes and users are allowed.

Return JSON with:
- assessmentBullets: the Assessment section, each { text, subBullets? }. Start with what the rule flagged (rule name, what it measures, the key numbers). Then what drove it, the pattern in the evidence (counts, time window, users or hosts, baselines and normal ranges from the input), and the conclusion each point supports. Use subBullets for per-item details (for example one per table, host or IP).
- verdict: { label, reason, closure, recommendation? }. label is the verdict with its scope, e.g. "Benign / operational for the ingestion alert", "Likely False Positive" or "True Positive – escalated". reason is 1–2 sentences on why. closure is e.g. "Close as NFA" or "Escalated to the client". recommendation (optional) is one follow-up action. The whole verdict must be at most 4 sentences.
- alertDetails: "Alert Details / Indicators" as { key, value } pairs, one per line, leaving out keys with nothing to say. Typical keys: Rule, Activity window, Incident created, Severity, Status, MITRE ATT&CK, the measured values per table/host/IP, Destination IP, ASN, Owner, Location, Reputation, Hosts, Users, Sample users, Processes, File hashes, Log source, Entities.
- supportingEvidence: the "Supporting Evidence" section as a list of { heading, lines?, table? }. Put each query result or evidence group under its own heading. Use lines for short facts, and table { columns, rows } for tabular results (for example a per-day trend). Copy numbers exactly from the input. Use an empty list if the input has no evidence beyond the logs.
- queries: the "Query Used" section as { language, query }, e.g. language "kql", "spl" or "sql". Only queries that appear in the input, copied exactly with their line breaks. Never write new queries here. Use an empty list if the input has none.`;

export const EXAMPLE_REPORT = `Example of a finished report (format reference only; its facts are not part of this ticket). The title line is added by the server.

Assessment:

- The Sentinel rule “Data Ingestion Anomaly - Z-Score Detection” flagged the SigninLogs table: Z-score 9.1, 0.02 GB today against a 0.004 GB average (+16 MB, a 5x spike).
- What drove the spike: 4,210 sign-in records from USER_1 within 3 minutes (2:10–2:13 AM on Jun 2). On a normal day this account produces 20–40 sign-ins.
  - All attempts came from \`198.51.100.23\` with result 50126 (invalid username or password).
- The pattern matches a password-spray or brute-force attempt against one account, not a logging fault.

Verdict: True Positive – escalated. The volume spike is caused by thousands of failed sign-ins from one external IP against USER_1. Escalated to the client, with one recommendation: block \`198.51.100.23\` and reset the account password.

Alert Details / Indicators:

Rule: Data Ingestion Anomaly - Z-Score Detection (scheduled detection, Microsoft Sentinel)
Activity window: Jun 1, 2026 2:30 AM to Jun 2, 2026 2:30 AM
Table SigninLogs: today 0.02 GB, average 0.004 GB, Z-score 9.1, spike ratio 5x
Source IP: 198.51.100.23
Users: USER_1

Supporting Evidence:

Sign-ins per day for USER_1:
Day	Sign-ins	Failed
Jun 1	32	1
Jun 2 (partial)	4,210	4,207

Query Used:

kql
SigninLogs
| where UserPrincipalName == "USER_1"
| summarize SignIns=count(), Failed=countif(ResultType != "0") by Day=bin(TimeGenerated, 1d)`;

export interface DraftInput {
  alertName: string;
  logs: string;
  logNote: string;
  findings: string;
  fields: Record<string, string>;
}

export function buildDraftUserMessage(d: DraftInput, validationErrors?: string[]): string {
  const fields = Object.entries(d.fields).filter(([, v]) => v && v.trim()).map(([k, v]) => `${k}: ${v}`).join("\n") || "(none)";
  const parts = [
    EXAMPLE_REPORT,
    "=== TICKET ===",
    `Alert name: ${d.alertName || "Not logged"}`,
    "",
    "=== ENRICHMENT FIELDS ===",
    fields,
    "",
    "=== ANALYST FINDINGS (may include query results and the queries used) ===",
    d.findings?.trim() || "(none)",
    "",
    `=== LOGS (${d.logNote}) ===`,
    d.logs || "(no logs)",
  ];
  if (validationErrors?.length) {
    parts.push("", "=== YOUR PREVIOUS ANSWER WAS REJECTED ===", ...validationErrors.map((e) => `- ${e}`), "Write the report again and fix these problems.");
  } else {
    parts.push("", "Write the Assessment report for this ticket now.");
  }
  return parts.join("\n");
}

export const SYSTEM_EXPLAIN = `You explain a single log line to a junior SOC analyst. Plain text, no markdown headings.
Format: 1) What it is (source / event type), 2) What it says (key fields decoded; decode Base64 / PowerShell -enc if present), 3) Why it matters, 4) What to check next. Under 160 words.
Use only what is in the line. Tokens like USER_1, HOST_1, INTIP_1, CLIENT_1 are redacted values; keep them as they are.`;

export const SYSTEM_CHAT = `You are a SOC analyst assistant inside "SOC Triage Playbook". Answer questions about the current ticket using only the ticket context provided. Be short (under 180 words unless asked for more) and factual; if something isn't in the context, say so. Suggest concrete next checks or queries when useful. Plain text only. Tokens like USER_1, HOST_1, INTIP_1, CLIENT_1 are redacted values; keep them as they are.`;

export const SYSTEM_SCREENSHOT = `You read screenshots for a SOC analyst: SIEM results (Sentinel, Splunk, QRadar), EDR consoles, firewall logs, email headers or alert pages.
Answer in exactly two parts, in this order:

LOG TEXT:
Transcribe the log lines, table rows and field values you can see, exactly as written, one record per line. Keep columns separated by " | ". Copy IPs, hostnames, users, hashes, times and numbers character for character. Do not transcribe menus, buttons or page chrome. Write [unreadable] for text you cannot read; never guess characters.

ANALYSIS:
Under 150 words: what the screenshot shows (source / event type), the notable values (IPs, users, hosts, processes, counts, time range), anything suspicious or benign about them, and what to check next. Use only what is visible.

Plain text only, no markdown.`;

export const screenshotPrompt = (note?: string) =>
  `Read this screenshot.${note?.trim() ? `\nAnalyst note: ${note.trim().slice(0, 500)}` : ""}`;

/** Splits the model's answer into the transcription and the analysis (small models sometimes skip a header). */
export function splitScreenshotAnswer(answer: string): { logText: string; analysis: string } {
  const t = answer.replace(/\r\n/g, "\n").replace(/\*\*/g, "");
  const m = t.match(/LOG TEXT:\s*([\s\S]*?)\n\s*ANALYSIS:\s*([\s\S]*)$/i);
  if (m) return { logText: m[1]!.trim(), analysis: m[2]!.trim() };
  const a = t.match(/^([\s\S]*?)\n?\s*ANALYSIS:\s*([\s\S]*)$/i);
  if (a) return { logText: a[1]!.replace(/^\s*LOG TEXT:\s*/i, "").trim(), analysis: a[2]!.trim() };
  return { logText: "", analysis: t.replace(/^\s*LOG TEXT:\s*/i, "").trim() };
}
