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

// "Alert Details / Indicators": every value is read from the pasted raw logs. A typed form field is
// used only when the logs don't carry that detail; ASN / Owner / Location / Reputation come from OSINT.
const counted = (pairs, max = 8) => {
  if (!pairs?.length) return "";
  const shown = pairs.slice(0, max).map(([v, n]) => (pairs.length > 1 || n > 1 ? `${v} (${n})` : v));
  return shown.join(", ") + (pairs.length > max ? ` and ${pairs.length - max} more` : "");
};
const first = (pairs) => pairs?.[0]?.[0] || "";
const short = (s, n = 160) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

function details(an, f) {
  const m = an.logMeta || {};
  const fw = an.fw;
  const techName = (id) => an.techniques.find((t) => t.id === id)?.name;
  const mitre = m.mitre?.length ? m.mitre.map((id) => [id, techName(id)].filter(Boolean).join(" ")).join(", ")
    : an.techniques.length ? an.techniques.map((t) => `${t.id} ${t.name}`).join(", ") : f.mitre;
  // A firewall or CEF device names itself; the SIEM guess from field names is only a fallback.
  const logSource = m.vendor || m.source;
  const rows = [
    ["Alert", first(m.alert) || f.alertName], ["Alert ID", first(m.alertId) || f.alertId], ["Analytics rule", first(m.rule) || f.analyticsRule],
    ["Detection source", first(m.detection) || f.detectionSource], ["Service source", f.serviceSource],
    ["Log source", logSource || f.logSource],
    ["Category", first(m.category) || f.category], ["Tactics", counted(m.tactics, 4)], ["MITRE ATT&CK", mitre],
    ["Severity", first(m.severity) || f.alertSeverity || `${an.severity} (estimated from the logs)`], ["Status", first(m.status) || f.status],
    ["Classification", first(m.classification) || f.classification], ["Incident created", f.incidentCreated],
    ["Activity window (logs)", winText(an) || f.activityWindow], ["Events in logs", an.events ? fmtNum(an.events) : ""],
    ["Event IDs / types", counted(m.eventIds)],
  ];
  if (fw) {
    rows.push(
      ["Destination IP", fw.dst], ["ASN", f.asn], ["Owner", f.owner], ["Location", f.location], ["IP type", f.ipType], ["Reputation", f.reputation],
      ["Source IPs (internal)", fw.sources.map((s) => `${s.ip} (${s.conns})`).join(", ")], ["Destination port", fw.ports.join(", ")],
      ["Protocol", fw.protos.join(", ")], ["Service", fw.service],
      ["Total connections", fmtNum(fw.total)],
      ["Bytes sent / received", `${fmtNum(fw.sent)} B (~${fmtBytes(fw.sent)}) / ${fmtNum(fw.rcvd)} B (~${fmtBytes(fw.rcvd)}) (mostly ${fw.direction})`],
      ["Firewall actions", fw.actions.map(([a, n]) => `${a} (${n})`).join(", ")],
      ["App category", [...fw.appcats.map(([a, n]) => `${a} (${n})`), fw.appcatUnknown ? `unknown (${fw.appcatUnknown})` : ""].filter(Boolean).join(", ")],
      ["Web category", counted(m.webcats)], ["Countries", counted(m.countries)],
      ["Hostname / URL", fw.urls.join(", ")], ["User", fw.users.join(", ")], ["Firewall device", counted(m.devices)],
    );
  } else {
    rows.push(
      ["Hosts", counted(m.hosts)], ["Users", counted(m.users)], ["Email addresses", counted(m.emails)],
      ["Source IPs", counted(m.srcIps)], ["Destination IPs", counted(m.dstIps)],
      ["External IPs", counted(m.extIps)], ["Internal IPs", counted(m.intIps)],
      ["ASN", f.asn], ["Owner", f.owner], ["Location", f.location], ["IP type", f.ipType], ["Reputation", f.reputation],
      ["Countries", counted(m.countries)], ["Destination ports", counted(m.ports)],
      ["Logon types", counted(m.logonTypes)], ["Results / failure reasons", counted(m.results, 5)],
      ["Processes", counted(m.processes)], ["Parent processes", an.parents.join(", ")],
      ["Command lines", (m.cmds || []).slice(0, 3).map(([c, n]) => `${bt(short(c))}${n > 1 ? ` (${n})` : ""}`).join("; ")],
      ["File paths", counted(m.paths, 5)],
      ["Domains", an.domains.join(", ")], ["URLs", an.urls.join(", ")],
      ["File hashes", an.hashes.map((h) => `${h.type} ${h.value}`).join(", ")],
      ["Applications / services", counted(m.apps)], ["User agents", counted(m.agents, 3)],
      ["Actions", counted(m.actions)], ["Security control action", an.mitigated ? "Partly blocked / quarantined (see logs)" : ""],
      ["Log device", counted(m.devices)],
    );
  }
  rows.push(["MDE telemetry", f.edrTelemetry]);
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

/* One source line in the OSINT copy block. Not looked up yet -> "Not checked". */
function osintSrc(name, s, err) {
  if (err) return err;
  if (!s) return "Not checked";
  if (name === "abuseipdb") return `${s.score}% abuse confidence, ${s.reports} reports${s.isp ? ` – ${s.isp}` : ""}${s.country ? ` (${s.country})` : ""}${s.usageType || s.usage ? `, ${s.usageType || s.usage}` : ""}`;
  if (name === "virustotal") return s.found ? `${s.malicious}/${s.total} malicious, ${s.suspicious} suspicious${s.asOwner || s.as_owner ? ` – ${s.asOwner || s.as_owner}` : ""}` : "Not found";
  const link = s.latest?.result?.replace("/api/v1/result/", "/result/");
  return `${s.hits} existing scans, ${s.malicious ? `${s.malicious} flagged malicious` : "none flagged malicious"}${link ? ` – latest: ${link}` : ""}`;
}

/* Does a screenshot (taken from the Screenshotbase URL field) belong to this URL/domain indicator? */
const normUrl = (u) => String(u || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/+$/, "");
const hostOf = (u) => normUrl(u).split(/[/?#]/)[0].replace(/^www\./, "");
const shotMatches = (ioc, s) => (ioc.type === "Domain" ? hostOf(s.page) === ioc.value.replace(/^www\./, "") : normUrl(s.page) === normUrl(ioc.value));

/* Sources per indicator type:
   IP -> AbuseIPDB, VirusTotal
   URL / Domain -> VirusTotal, URLscan.io, plus Screenshotbase only when the analyst generated one for it
   Hash -> VirusTotal */
export function osintSummary(f, iocs, osint, shots = []) {
  const grp = { IP: [], Web: [], Hash: [] };
  iocs.forEach((i) => grp[i.type === "IP" ? "IP" : i.type === "URL" || i.type === "Domain" ? "Web" : "Hash"].push(i));
  const used = new Set();
  const block = (i, sources) => {
    const o = osint?.[i.value] || {};
    const a = o.auto || {};
    const L = [`${i.value}${i.type !== "IP" ? ` (${i.type})` : ""}`,
      ...sources.map(([k, label]) => `${label}: ${osintSrc(k, a.sources?.[k], a.errors?.[k])}`)];
    if (i.type === "URL" || i.type === "Domain") {
      shots.filter((s) => shotMatches(i, s)).forEach((s) => { used.add(s.url); L.push(`Screenshotbase (URL to image): ${s.url}`); });
    }
    L.push(`Verdict: ${o.verdict || "Not checked"}${o.note && (o.manual || !o.auto) ? ` – ${o.note}` : ""}`);
    return L.join("\n");
  };
  const L = [];
  if (grp.IP.length) L.push("IP(s) Reputation:", grp.IP.map((i) => block(i, [["abuseipdb", "AbuseIPDB"], ["virustotal", "VirusTotal"]])).join("\n\n"), "");
  if (grp.Web.length) L.push("URL/Domain Reputation:", grp.Web.map((i) => block(i, [["virustotal", "VirusTotal"], ["urlscan", "URLscan.io"]])).join("\n\n"), "");
  if (grp.Hash.length) L.push("File Hash Reputation:", grp.Hash.map((i) => block(i, [["virustotal", "VirusTotal"]])).join("\n\n"), "");
  // Screenshots of URLs the analyst typed that aren't indicators on this ticket.
  const rest = shots.filter((s) => !used.has(s.url));
  if (rest.length) L.push("Screenshotbase (URL to image):", ...rest.map((s) => `${s.page} → ${s.url}`), "");
  return L.length ? L.join("\n").trim() : "Nothing in results yet. Add indicators to check.";
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
