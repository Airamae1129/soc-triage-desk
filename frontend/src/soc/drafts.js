import { defang, fmtBytes, fmtDT, fmtTime, fmtDTm, fmtHM, fmtLong, fmtNum, joinAnd, numWord, SHIFTS, fmtDate, shiftOf } from "./util";

const sentence = (s) => { const t = String(s || "").trim(); return !t ? "" : /[.!?]$/.test(t) ? t : `${t}.`; };
const lc = (s) => s.charAt(0).toLowerCase() + s.slice(1);
const bt = (s) => `\`${s}\``;
const winText = (an) => (an.window ? `${fmtDT(an.window.start)} – ${fmtDate(an.window.start) === fmtDate(an.window.end) ? fmtTime(an.window.end) : fmtDT(an.window.end)} (UTC+08:00)` : "");
export const mitreTag = (f, an) => {
  const id = (String(f.mitre || "").match(/T\d{4}(?:\.\d{3})?/) || [])[0] || an.techniques[0]?.id;
  const tactic = f.category || an.techniques[0]?.tactic;
  return [id, tactic].filter(Boolean).join(", ");
};
export const verdictLine = (an) => `Verdict: ${an.verdict} (${an.severity.toLowerCase()} risk). ${an.reason}, ${lc(an.closure)}.`;

function details(an, f) {
  const fw = an.fw;
  const rows = [
    ["Alert", f.alertName], ["Alert ID", f.alertId], ["Analytics rule", f.analyticsRule],
    ["Detection source", f.detectionSource], ["Service source", f.serviceSource], ["Category", f.category],
    ["MITRE ATT&CK", f.mitre || an.techniques.map((t) => `${t.id} ${t.name}`).join(", ")],
    ["Severity", f.alertSeverity || an.severity], ["Status", f.status], ["Classification", f.classification],
    ["Incident created", f.incidentCreated], ["Activity window (alert)", f.activityWindow],
  ];
  if (fw) {
    rows.push(
      ["Activity window (firewall logs)", winText(an)], ["Destination IP", fw.dst], ["ASN", f.asn], ["Owner", f.owner],
      ["Location", f.location], ["IP type", f.ipType], ["Reputation", f.reputation],
      ["Source IPs (internal)", fw.sources.map((s) => s.ip).join(", ")], ["Destination port", fw.ports.join(", ")],
      ["Protocol", fw.protos.join(", ")],
      ["Total connections", `${fw.total} (${fw.sources.map((s) => `${s.ip}: ${s.conns}`).join(", ")})`],
      ["Bytes sent / received", `${fmtNum(fw.sent)} B (~${fmtBytes(fw.sent)}) / ${fmtNum(fw.rcvd)} B (~${fmtBytes(fw.rcvd)}) (mostly ${fw.direction})`],
      ["Firewall actions", fw.actions.map(([a, n]) => `${a} (${n})`).join(", ")],
      ["App category", [...fw.appcats.map(([a, n]) => `${a} (${n})`), fw.appcatUnknown ? `unknown (${fw.appcatUnknown})` : ""].filter(Boolean).join(", ")],
      ["Hostname / URL", fw.urls.join(", ")], ["User", fw.users.join(", ")],
      ["Log source", f.logSource], ["MDE telemetry", f.edrTelemetry],
    );
  } else {
    rows.push(
      ["Activity window (logs)", winText(an)], ["Hosts", an.hosts.join(", ")], ["Users", an.users.join(", ")],
      ["Source / internal IPs", an.ips.internal.join(", ")], ["External IPs", an.ips.external.join(", ")],
      ["ASN", f.asn], ["Owner", f.owner], ["Location", f.location], ["IP type", f.ipType], ["Reputation", f.reputation],
      ["Domains", an.domains.join(", ")], ["URLs", an.urls.join(", ")],
      ["File hashes", an.hashes.map((h) => `${h.type} ${h.value}`).join(", ")], ["Parent processes", an.parents.join(", ")],
      ["Security control action", an.mitigated ? "Partly blocked / quarantined (see logs)" : ""],
      ["Log source", f.logSource], ["MDE telemetry", f.edrTelemetry],
    );
  }
  return rows.filter(([, v]) => v && String(v).trim()).map(([k, v]) => `${k}: ${v}`);
}

export function buildReport(an, f) {
  const L = ["Assessment:"];
  const rule = f.analyticsRule || f.alertName || "Unnamed alert";
  const tag = mitreTag(f, an);
  const logic = f.ruleLogic ? ` ${sentence(f.ruleLogic)}` : "";
  const fw = an.fw;
  if (fw) {
    const srcs = fw.sources.map((s) => bt(s.ip));
    L.push(`- Alert “${rule}”${tag ? ` (${tag})` : ""} triggered on external IP ${bt(fw.dst)}.${logic}`);
    L.push(`- ${numWord(srcs.length)} internal host${srcs.length === 1 ? "" : "s"} contacted the IP over ${fw.service} (port${fw.ports.length > 1 ? "s" : ""} ${fw.ports.join(", ")}): ${joinAnd(srcs)}.${an.window ? ` Traffic occurred between ${fmtLong(an.window.start)} and ${fmtLong(an.window.end)}.` : ""}`);
    L.push(`- ${fw.direction === "inbound" ? "Traffic pattern indicates downloads, not exfiltration." : fw.direction === "outbound" ? "Traffic pattern indicates uploads (more sent than received); review for possible exfiltration." : "Traffic pattern is balanced; no clear download or exfiltration pattern."}`);
    fw.sources.forEach((s) => L.push(`  - ${bt(s.ip)}: ${s.conns} connection${s.conns === 1 ? "" : "s"}, ~${fmtBytes(s.sent)} sent, ~${fmtBytes(s.rcvd)} received.`));
    const cat = [...fw.appcats.map(([a]) => a), fw.appcatUnknown && !fw.appcats.length ? "unknown" : ""].filter(Boolean).join(", ");
    const urlTxt = fw.urls.length ? `Logged hostname/URL: ${fw.urls.map(bt).join(", ")}` : "No hostname/URL logged";
    L.push(`- ${fw.vendor} classified traffic as ${bt(`${cat || "unknown"} / ${fw.service}`)}. ${urlTxt}; sessions ended with ${fw.allNormal ? "normal " : ""}${joinAnd(fw.actions.map(([a]) => a))} actions.`);
    if (f.owner || f.asn) {
      const meta = [f.asn, f.location].filter(Boolean).join(", ");
      L.push(`- Destination ${bt(fw.dst)} belongs to ${f.owner || "an unlisted owner"}${meta ? ` (${meta})` : ""}.${f.ipType ? ` ${sentence(f.ipType)}` : ""}${f.reputation ? ` ${sentence(f.reputation)}` : ""}`);
    }
  } else {
    const on = an.hosts.length ? ` on host ${an.hosts.map(bt).join(", ")}` : an.primaryIp ? ` for external IP ${bt(an.primaryIp)}` : "";
    L.push(`- Alert “${rule}”${tag ? ` (${tag})` : ""} triggered${on}${an.users.length ? ` for user ${an.users.map(bt).join(", ")}` : ""}.${logic}`);
    an.techniques.forEach((t) => L.push(`- ${t.id} ${t.name} (${t.tactic}): ${t.hits} matching event${t.hits === 1 ? "" : "s"}.`));
    if (an.ips.external.length) L.push(`- External IPs observed: ${an.ips.external.map(bt).join(", ")}.${f.owner ? ` ${bt(an.primaryIp)} belongs to ${f.owner}${f.asn ? ` (${f.asn})` : ""}.` : ""}${f.reputation ? ` ${sentence(f.reputation)}` : ""}`);
    if (an.hashes.length) L.push(`- File hash${an.hashes.length > 1 ? "es" : ""}: ${an.hashes.map((h) => bt(h.value)).join(", ")}.`);
    if (an.mitigated) L.push("- Security controls blocked or quarantined part of the activity.");
    if (an.window) L.push(`- Activity occurred between ${fmtLong(an.window.start)} and ${fmtLong(an.window.end)}.`);
  }
  String(f.findings || "").split(/\r?\n/).map((l) => l.replace(/^\s*[-•*]\s*/, "").trim()).filter(Boolean).forEach((l) => L.push(`- ${l}`));
  L.push("", verdictLine(an), "", "Alert Details / Indicators:", ...details(an, f));
  return L.join("\n");
}

const iocLine = (i, osint, dfg) => {
  const o = osint?.[i.value];
  const v = dfg && i.type !== "SHA-256" && i.type !== "MD5" ? defang(i.value) : i.value;
  return `- ${i.type}: ${v}${o && o.verdict && o.verdict !== "Not checked" ? ` (OSINT: ${o.verdict}${o.note ? ` – ${o.note}` : ""})` : " (OSINT: not checked)"}`;
};

export function buildEmail(an, f, { pbRow, osint, analyst }) {
  const to = pbRow?.email || "<client contact – no playbook entry>";
  const hi = pbRow?.contact ? `Hello ${pbRow.contact},` : "Hello,";
  const subj = `Subject: [${an.severity.toUpperCase()}] Security Incident Escalation – ${an.title} – ${f.ticketId || "no ticket"}`;
  const sig = ["Regards,", analyst || f.analyst || "SOC Analyst", "Security Operations Center", "soc.analyst@ambiontech.com"];
  if (an.isFP) {
    return [`To: ${to}`, subj, "", hi, "",
      `We reviewed the alert “${an.title}” for ${f.client || "your environment"} (${f.ticketId || "no ticket"}).`,
      `Our assessment: ${an.verdict}. ${an.reason}.`, "",
      `No action is needed from your side. ${an.closure === "Monitoring for 24 hours" ? "We will keep monitoring for 24 hours." : "We are closing the ticket as no further action (NFA)."}`,
      an.window ? `Activity window: ${winText(an)}` : "", "", "Let us know if this activity was not expected.", "", ...sig].filter((l, i, a) => !(l === "" && a[i - 1] === "")).join("\n");
  }
  const assets = [...an.hosts.map((h) => `- Host: ${h}`), ...an.users.map((u) => `- User: ${u}`), ...(an.fw ? an.fw.sources.map((s) => `- Internal IP: ${s.ip}`) : an.ips.internal.map((i) => `- Internal IP: ${i}`))];
  const tech = an.techniques.length ? an.techniques.map((t) => `- ${t.id} ${t.name} (${t.tactic}) – ${t.hits} event${t.hits === 1 ? "" : "s"}`) : [f.mitre ? `- ${f.mitre}` : "- No technique matched in the logs"];
  return [`To: ${to}`, subj, "", hi, "",
    `We are escalating a ${an.severity.toLowerCase()}-severity security incident detected for ${f.client || "your environment"}.`, "",
    "SUMMARY", `${an.summary} Assessment: ${an.verdict} (${an.confidence.toLowerCase()} confidence, risk score ${an.score}/100).`, "",
    "AFFECTED ASSETS", ...(assets.length ? assets : ["- None identified in the logs"]), "",
    "OBSERVED TECHNIQUES (MITRE ATT&CK)", ...tech, "",
    "INDICATORS OF COMPROMISE", ...(an.extIocs.length ? an.extIocs.map((i) => iocLine(i, osint, f.defang)) : ["- None extracted"]), "",
    "RECOMMENDED ACTIONS", ...an.actions.map((a, i) => `${i + 1}. ${a.replace(/`/g, "")}`), "",
    "ACTIVITY WINDOW", an.window ? winText(an) : "Not available in the logs", "",
    "Please confirm receipt and let us know if you approve the containment steps above.", "", ...sig].join("\n");
}

export function buildHandover(an, f, { entry, checklist, osint, notes, pbRow }) {
  const now = new Date();
  const items = checklist.items;
  const done = items.filter((i) => checklist.state[i]);
  const pendingCk = items.filter((i) => !checklist.state[i]);
  const unchecked = an.extIocs.filter((i) => !osint?.[i.value] || osint[i.value].verdict === "Not checked");
  const shift = f.shift || shiftOf(now).name;
  const status = entry?.escalatedAt ? `Escalated to client at ${fmtHM(entry.escalatedAt)}${entry.notableStatus ? ` · ${entry.notableStatus}` : ""}` : an.closure;
  const doneL = ["- Reviewed logs and generated the assessment", `- OSINT: ${an.extIocs.length - unchecked.length} of ${an.extIocs.length} indicators checked`, `- Checklist: ${done.length} of ${items.length} done`];
  if (entry?.escalatedAt) doneL.push(`- Escalated to ${pbRow?.contact || "client"} at ${fmtHM(entry.escalatedAt)}`);
  if (notes?.length) doneL.push(`- ${notes.length} case note${notes.length === 1 ? "" : "s"} logged`);
  const pend = [];
  if (entry?.escalatedAt) pend.push("- Wait for the client reply and follow up if the SLA passes");
  else if (an.closure === "Pending client confirmation") pend.push("- Wait for client confirmation before closing");
  else if (an.closure === "Monitoring for 24 hours") pend.push("- Keep monitoring for 24 hours and re-check the indicators");
  unchecked.slice(0, 4).forEach((i) => pend.push(`- Check ${i.type} ${i.value} in OSINT`));
  pendingCk.slice(0, 5).forEach((i) => pend.push(`- ${i}`));
  if (!pend.length) pend.push("- Nothing pending");
  return [`SHIFT HANDOVER – ${fmtDTm(now)} (UTC+08:00)`, `Shift: ${shift} (${SHIFTS[shift] || ""})`, `Analyst: ${f.analyst || "—"}`,
    `Ticket: ${f.ticketId || "—"}`, `Client: ${f.client || "—"}`, `Alert: ${an.title}`,
    `Verdict: ${an.verdict} (${an.severity}, score ${an.score})`, `Status: ${status}`, "",
    "WHAT HAPPENED", `- ${an.summary}`, ...an.techniques.slice(0, 5).map((t) => `- ${t.id} ${t.name}: ${t.hits} event${t.hits === 1 ? "" : "s"}`),
    an.window ? `- Window: ${winText(an)}` : "", "",
    "DONE THIS SHIFT", ...doneL, "", "PENDING FOR NEXT SHIFT", ...pend].filter((l, i, a) => !(l === "" && a[i - 1] === "")).join("\n");
}

export function osintSummary(f, iocs, osint) {
  if (!iocs.length) return "No external indicators for this ticket.";
  return [`OSINT results – ${f.ticketId || "no ticket"}${f.client ? ` · ${f.client}` : ""}`,
    ...iocs.map((i) => { const o = osint?.[i.value] || {}; return `- ${i.type} ${i.value}: ${o.verdict || "Not checked"}${o.note ? ` – ${o.note}` : ""}`; })].join("\n");
}

export function reportChecks(an, f) {
  const w = [];
  const v = verdictLine(an).replace(/^Verdict:\s*/, "");
  const sentences = v.split(/(?<=[.!?])\s+(?=[A-Z])/).filter(Boolean).length;
  if (sentences > 2) w.push(`Verdict has ${sentences} sentences (max 2).`);
  if (!f.closure || f.closure === "Auto") w.push(`Closure is auto-picked (“${an.closure}”). Confirm it.`);
  if (!f.alertId) w.push("Alert ID is empty.");
  if (!f.analyticsRule) w.push("Analytics rule is empty.");
  return [...w, ...an.warnings];
}

export function notablesText(key, entries) {
  const [dk, name] = key.split("|");
  const d = new Date(`${dk}T12:00:00+08:00`);
  const counts = ["Critical", "High", "Medium", "Low"].map((s) => [s, entries.filter((e) => e.sev === s).length]).filter(([, n]) => n);
  const L = [`NOTABLES – ${fmtDate(d)} · ${name} shift (${SHIFTS[name]})`, `Escalations: ${entries.length}${counts.map(([s, n]) => ` · ${s} ${n}`).join("")}`, ""];
  entries.forEach((e, i) => {
    L.push(`${i + 1}) ${fmtHM(e.escalatedAt)} · ${e.sev.toUpperCase()} · ${e.form.client || "—"} · ${e.form.ticketId || "—"}`);
    L.push(`   Alert: ${e.form.alertName || "—"}`, `   What: ${e.summary}`, `   Status: ${e.notableStatus || "Awaiting client"}`);
  });
  if (!entries.length) L.push("No escalations this shift.");
  L.push("", `Analysts: ${[...new Set(entries.map((e) => e.form.analyst).filter(Boolean))].join(", ") || "—"}`);
  return L.join("\n");
}
