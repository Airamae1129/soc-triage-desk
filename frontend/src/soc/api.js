import { buildReport } from "./drafts";
import { maskText, fmtDT } from "./util";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

export async function getConfig() {
  const r = await fetch(`${API}/config`);
  if (!r.ok) throw new Error("config");
  return r.json();
}

export async function streamAi(body, onDelta, signal) {
  const r = await fetch(`${API}/ai/stream`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal });
  if (!r.ok || !r.body) throw new Error((await r.json().catch(() => ({}))).detail || `AI request failed (HTTP ${r.status})`);
  const reader = r.body.getReader();
  const dec = new TextDecoder();
  let buf = "", full = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    const parts = buf.split("\n\n");
    buf = parts.pop();
    for (const p of parts) {
      const line = p.replace(/^data:\s*/, "");
      if (!line) continue;
      const ev = JSON.parse(line);
      if (ev.error) throw new Error(ev.error);
      if (ev.t) { full += ev.t; onDelta(full); }
    }
  }
  return full;
}

export const cleanAi = (s) => s.replace(/\*\*(.+?)\*\*/g, "$1").replace(/^#{1,6}\s+/gm, "");

export async function osintLookup(type, value, force = false) {
  const r = await fetch(`${API}/osint/lookup`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ type, value, force }) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.detail || `Lookup failed (HTTP ${r.status})`);
  return j;
}

export async function screenshotUsage() {
  const r = await fetch(`${API}/osint/screenshot/usage`);
  return r.ok ? r.json() : { count: 0 };
}

export async function takeScreenshot(url) {
  const r = await fetch(`${API}/osint/screenshot`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url, confirmed: true }) });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `Screenshot failed (HTTP ${r.status})`);
  return URL.createObjectURL(await r.blob());
}

export function buildAiContext(entry, an, osintVals = {}, mask = false) {
  const f = entry?.form || {};
  const fields = Object.entries(f).filter(([k, v]) => v && typeof v === "string" && !["rawLogs", "findings"].includes(k)).map(([k, v]) => `${k}: ${v}`);
  const osint = an.extIocs.map((i) => { const o = osintVals[i.value]; return `- ${i.type} ${i.value}: ${o?.verdict || "Not checked"}${o?.note ? ` – ${o.note}` : ""}`; });
  const engine = [
    `Rule engine: score ${an.score}/100, severity ${an.severity}, verdict ${an.verdict}${an.analystSet ? " (set by analyst)" : " (auto)"}, confidence ${an.confidence}, closure ${an.closure}`,
    `Summary: ${an.summary}`,
    `Techniques: ${an.techniques.map((t) => `${t.id} ${t.name} (${t.tactic}) x${t.hits}`).join("; ") || "none"}`,
    `Window: ${an.window ? `${fmtDT(an.window.start)} – ${fmtDT(an.window.end)} (UTC+08:00)` : "n/a"}`,
    `Hosts: ${an.hosts.join(", ") || "-"} | Users: ${an.users.join(", ") || "-"} | External IPs: ${an.ips.external.join(", ") || "-"} | Internal IPs: ${an.ips.internal.join(", ") || "-"}`,
  ];
  const text = [
    "== TICKET FIELDS ==", ...fields, "", "== ANALYST FINDINGS ==", f.findings || "(none)", "",
    "== ENGINE RESULT ==", ...engine, "", "== OSINT RESULTS ==", ...(osint.length ? osint : ["(none)"]), "",
    "== RULE-BASED REPORT DRAFT ==", buildReport(an, f), "", "== RAW LOGS ==", (f.rawLogs || "").slice(0, 40000),
  ].join("\n");
  if (!mask) return { text, items: [] };
  return maskText(text, { client: f.client, users: an.users, hosts: an.hosts, ips: an.ips.internal });
}
