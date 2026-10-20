import { useMemo, useState } from "react";
import { ExternalLink, ChevronRight, AlertTriangle, Download } from "lucide-react";
import { Panel, SevPill, VerdictPill, Pill, Chip, CopyBlock, Field, SlaTimer, escalatedLabel } from "./ui";
import { fmtDTm, fmtSpan, fmtBytes, fmtNum, sevKey, maskText, download, fmtHM } from "./util";
import { buildReport, buildEmail, buildHandover, reportChecks } from "./drafts";

const VERDICTS = ["Auto", "True Positive", "Benign", "Likely False Positive", "False Positive", "Benign · Monitor"];
const CLOSURES = ["Auto", "Closing as NFA", "Escalated to client", "Monitoring for 24 hours", "Pending client confirmation"];
const DETAILS = [
  ["alertId", "Alert ID"], ["analyticsRule", "Analytics rule"], ["ruleLogic", "Rule logic", true], ["detectionSource", "Detection source"],
  ["serviceSource", "Service source"], ["category", "Category / tactic"], ["mitre", "MITRE ATT&CK"], ["alertSeverity", "Alert severity"],
  ["status", "Status"], ["classification", "Classification"], ["incidentCreated", "Incident created"], ["activityWindow", "Activity window (alert)"],
  ["asn", "ASN"], ["owner", "Owner"], ["location", "Location"], ["ipType", "IP type"], ["reputation", "Reputation", true],
  ["logSource", "Log source"], ["edrTelemetry", "MDE/EDR telemetry", true],
];

function Intake({ app }) {
  const { form, setForm, generate, clearForm, loadSample } = app;
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  const inp = (k, ph) => <input id={`f-${k}`} className="input" value={form[k]} onChange={set(k)} placeholder={ph} data-testid={`intake-${k}-input`} />;
  return (
    <Panel title="Intake" testid="intake-panel" right={app.isSampleForm && <span className="tag-sample">Sample</span>}>
      <form className="form-grid" onSubmit={(e) => { e.preventDefault(); generate(); }}>
        <Field label="Client" htmlFor="f-client">{inp("client", "Client name")}</Field>
        <Field label="Ticket ID" htmlFor="f-ticketId">{inp("ticketId", "INC-00000")}</Field>
        <Field label="Alert name" wide htmlFor="f-alertName">{inp("alertName", "As shown in the SIEM")}</Field>
        <Field label="Raw logs (any source)" wide htmlFor="f-rawLogs">
          <textarea id="f-rawLogs" className="input mono ta-logs" value={form.rawLogs} onChange={set("rawLogs")} placeholder="Paste raw log lines here" spellCheck={false} data-testid="intake-rawLogs-input" />
        </Field>
        <Field label="Analyst findings" wide htmlFor="f-findings">
          <textarea id="f-findings" className="input ta-mid" value={form.findings} onChange={set("findings")} placeholder="One finding per line" data-testid="intake-findings-input" />
        </Field>
        <Field label="Analyst" htmlFor="f-analyst">{inp("analyst", "Your name")}</Field>
        <Field label="Shift" htmlFor="f-shift">
          <select id="f-shift" className="input" value={form.shift} onChange={set("shift")} data-testid="intake-shift-select">
            <option value="Morning">Morning 06:00–14:00</option><option value="Mid">Mid 14:00–22:00</option><option value="Night">Night 22:00–06:00</option>
          </select>
        </Field>
        <details className="fold field-wide" data-testid="intake-details-section">
          <summary data-testid="intake-details-toggle"><ChevronRight size={14} className="chev" /> Alert details &amp; enrichment</summary>
          <div className="form-grid inner">
            <Field label="Analyst verdict" htmlFor="f-verdict">
              <select id="f-verdict" className="input" value={form.verdict} onChange={set("verdict")} data-testid="intake-verdict-select">{VERDICTS.map((v) => <option key={v}>{v}</option>)}</select>
            </Field>
            <Field label="Closure" htmlFor="f-closure">
              <select id="f-closure" className="input" value={form.closure} onChange={set("closure")} data-testid="intake-closure-select">{CLOSURES.map((v) => <option key={v}>{v}</option>)}</select>
            </Field>
            <Field label="Verdict reason (optional)" wide htmlFor="f-verdictReason">{inp("verdictReason", "One sentence")}</Field>
            {DETAILS.map(([k, l, w]) => <Field key={k} label={l} wide={w} htmlFor={`f-${k}`}>{inp(k)}</Field>)}
          </div>
        </details>
        <label className="check field-wide">
          <input type="checkbox" checked={form.defang} onChange={set("defang")} data-testid="intake-defang-checkbox" /> Defang IOCs in client email (hxxp, [.])
        </label>
        <div className="btn-row field-wide">
          <button type="submit" className="btn btn-primary" data-testid="generate-assessment-btn">Generate assessment</button>
          <button type="button" className="btn" onClick={clearForm} data-testid="clear-intake-btn">Clear</button>
          <button type="button" className="btn btn-ghost" onClick={() => loadSample("A")} data-testid="sample-first-seen-btn">Sample · First-seen IP</button>
          <button type="button" className="btn btn-ghost" onClick={() => loadSample("B")} data-testid="sample-rdp-btn">Sample · RDP brute force</button>
          <span className="muted small kbd-hint">Ctrl+Enter</span>
        </div>
      </form>
    </Panel>
  );
}

function Recent({ app }) {
  const { history, loadEntry, entry } = app;
  const list = [...history].sort((a, b) => new Date(b.savedAt) - new Date(a.savedAt));
  return (
    <Panel title="Recent assessments" right={<span className="muted small">This browser only</span>} testid="recent-panel">
      {!list.length && <p className="muted">No saved assessments yet.</p>}
      <ul className="recent">
        {list.map((h) => (
          <li key={h.id}>
            <button className={`recent-row ${entry?.id === h.id ? "is-active" : ""}`} onClick={() => loadEntry(h.id)} data-testid={`recent-row-${h.id}`}>
              <span className={`dot sev-dot-${sevKey(h.sev)}`} title={h.sev} />
              <span className="recent-main"><span className="mono">{h.form.ticketId}</span> · {h.form.client || "—"} · {h.verdict}</span>
              <span className="mono small muted">{fmtDTm(h.savedAt)}</span>
            </button>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function VerdictHeader({ app }) {
  const { an, entry, pbRow, setTab } = app;
  const f = entry.form;
  return (
    <div className={`vhead sevt-${sevKey(an.severity)}`} data-testid="verdict-header">
      <div className="vhead-main">
        <div className="muted small">{f.client || "—"} · <span className="mono">{f.ticketId}</span></div>
        <div className="vhead-verdict" data-testid="result-verdict">{an.verdict}</div>
        <div className="pill-row">
          <SevPill sev={an.severity} testid="result-severity-pill" />
          <Pill testid="result-confidence-pill">{an.confidence} confidence</Pill>
          {an.mitigated && <Pill tone="medium" testid="result-partly-blocked-pill">Partly blocked</Pill>}
          {entry.escalatedAt && <Pill tone="critical" testid="result-escalated-pill">{escalatedLabel(entry)}</Pill>}
          {entry.escalatedAt && <SlaTimer escalatedAt={entry.escalatedAt} sla={pbRow?.sla} status={entry.notableStatus} testid="result-sla-timer" />}
        </div>
      </div>
      <div className="vhead-score">
        <div className="score mono" data-testid="result-risk-score">{an.score}</div>
        <div className="muted small">Risk score / 100</div>
        <div className="meter" aria-hidden><div className={`meter-fill bg-${sevKey(an.severity)}`} style={{ width: `${an.score}%` }} /><i style={{ left: "25%" }} /><i style={{ left: "50%" }} /><i style={{ left: "75%" }} /></div>
      </div>
      <div className="vhead-pb small" data-testid="result-playbook-line">
        {pbRow ? <><b>{an.severity}:</b> notify {pbRow.contact} via {pbRow.channel} within {pbRow.sla}</> : <span className="muted">No playbook row for {f.client || "this client"} at {an.severity}.</span>}
        {" "}<button className="link" onClick={() => setTab("playbook")} data-testid="open-playbook-link">Open playbook</button>
      </div>
    </div>
  );
}

function FwTable({ fw }) {
  return (
    <div className="tbl-wrap">
      <table className="tbl" data-testid="traffic-table">
        <caption className="tbl-cap">Traffic to <span className="mono">{fw.dst}</span></caption>
        <thead><tr><th>Source IP</th><th className="num">Connections</th><th className="num">Sent</th><th className="num">Received</th></tr></thead>
        <tbody>
          {fw.sources.map((s) => <tr key={s.ip}><td className="mono">{s.ip}</td><td className="num mono">{s.conns}</td><td className="num mono">{fmtBytes(s.sent)}</td><td className="num mono">{fmtBytes(s.rcvd)}</td></tr>)}
          <tr className="tot"><td>Total</td><td className="num mono">{fw.total}</td><td className="num mono">{fmtBytes(fw.sent)}</td><td className="num mono">{fmtBytes(fw.rcvd)}</td></tr>
        </tbody>
      </table>
      <p className="muted small">Mostly {fw.direction} · {fmtNum(fw.sent)} B sent / {fmtNum(fw.rcvd)} B received · actions {fw.actions.map(([a, n]) => `${a} ${n}`).join(", ")}</p>
    </div>
  );
}

function Drafts({ app }) {
  const { an, entry, toggleEscalated } = app;
  const [tab, setTab] = useState("report");
  const [mask, setMask] = useState(false);
  const f = entry.form;
  const texts = useMemo(() => ({
    report: buildReport(an, f),
    email: buildEmail(an, f, { pbRow: app.pbRow, osint: app.osintT.values, analyst: f.analyst }),
    handover: buildHandover(an, f, { entry, checklist: app.checklistInfo, osint: app.osintT.values, notes: app.ticketNotes, pbRow: app.pbRow }),
  }), [an, f, app.pbRow, app.osintT, entry, app.checklistInfo, app.ticketNotes]);
  const masked = mask ? maskText(texts[tab], { client: f.client, others: [app.pbRow?.email, app.pbRow?.contact, (app.pbRow?.email || "").split("@")[1]], users: an.users, hosts: an.hosts, ips: an.ips.internal }) : null;
  const text = masked ? masked.text : texts[tab];
  const checks = tab === "report" ? reportChecks(an, f) : [];
  const names = { report: "Assessment report", email: "Client escalation email", handover: "Shift handover note" };
  return (
    <div className="drafts" data-testid="drafts">
      <div className="seg" role="tablist">
        {Object.keys(names).map((k) => <button key={k} role="tab" aria-selected={tab === k} className={`seg-btn ${tab === k ? "on" : ""}`} onClick={() => setTab(k)} data-testid={`draft-tab-${k}`}>{names[k]}</button>)}
      </div>
      {checks.length > 0 && (
        <ul className="warn-list" data-testid="report-checks">
          {checks.map((c) => <li key={c}><AlertTriangle size={13} /> {c}</li>)}
        </ul>
      )}
      {masked && (
        <div className="mask-preview small" data-testid="mask-preview">
          Masked {masked.items.length} value{masked.items.length === 1 ? "" : "s"}: {masked.items.map((i) => <span key={i.token} className="chip mono">{i.val} → {i.token}</span>)}
        </div>
      )}
      <CopyBlock text={text} testid={`draft-${tab}-text`} maxH={520} extra={
        <>
          <label className="check small"><input type="checkbox" checked={mask} onChange={(e) => setMask(e.target.checked)} data-testid="mask-toggle" /> Mask names &amp; internal IPs</label>
          <button className="btn btn-sm" onClick={() => download(`${f.ticketId || "ticket"}-${tab}.txt`, text)} data-testid={`draft-${tab}-download`}><Download size={13} /> .txt</button>
          <button className={`btn btn-sm ${entry.escalatedAt ? "" : "btn-danger"}`} onClick={toggleEscalated} data-testid="mark-escalated-btn">{entry.escalatedAt ? "Undo escalated" : "Mark as escalated"}</button>
        </>
      } />
    </div>
  );
}

function Result({ app }) {
  const { an, entry, setTab, history, loadEntry } = app;
  if (!entry) return <Panel title="Result" testid="result-panel"><p className="muted">Fill in the intake and press Generate assessment.</p></Panel>;
  const dups = history.filter((h) => h.id !== entry.id).map((h) => ({ h, hits: [...an.ips.external, ...an.domains, ...an.hashes.map((x) => x.value), ...an.hosts].filter((v) => (h.iocs || []).includes(v)) })).filter((d) => d.hits.length);
  return (
    <Panel title="Result" testid="result-panel" right={entry.sample && <span className="tag-sample">Sample</span>}>
      <VerdictHeader app={app} />
      {dups.length > 0 && (
        <ul className="warn-list" data-testid="duplicate-warnings">
          {dups.map(({ h, hits }) => <li key={h.id}><AlertTriangle size={13} /> <span className="mono">{hits.slice(0, 2).join(", ")}</span> seen in <button className="link mono" onClick={() => loadEntry(h.id)} data-testid={`dup-link-${h.id}`}>{h.form.ticketId}</button></li>)}
        </ul>
      )}
      <h3 className="r-title" data-testid="result-alert-title">{an.title}</h3>
      <p className="r-summary" data-testid="result-summary">{an.summary}</p>
      <div className="facts" data-testid="facts-strip">
        <div><span>Events</span><b className="mono" data-testid="fact-events">{an.events}</b></div>
        <div><span>Window</span><b className="mono" data-testid="fact-window">{an.window ? `${fmtHM(an.window.start)}–${fmtHM(an.window.end)}` : "—"}</b></div>
        <div><span>Span</span><b className="mono" data-testid="fact-span">{fmtSpan(an.spanMs)}</b></div>
        <div><span>IOCs</span><b className="mono" data-testid="fact-iocs">{an.extIocs.length}</b></div>
      </div>
      {an.fw && <FwTable fw={an.fw} />}
      <div className="grid2 tight">
        <div>
          <h4 className="sub-h">MITRE ATT&amp;CK</h4>
          {!an.techniques.length && <p className="muted small">No technique matched in the logs.</p>}
          <ul className="mitre" data-testid="mitre-list">
            {an.techniques.map((t) => <li key={t.id}><span className="mono tid">{t.id}</span><span>{t.name}<br /><span className="muted small">{t.tactic}</span></span><span className="mono hits">×{t.hits}</span></li>)}
          </ul>
        </div>
        <div data-testid="affected-list">
          <h4 className="sub-h">Affected</h4>
          {[["Hosts", an.hosts], ["Users", an.users]].map(([l, a]) => a.length > 0 && <div key={l} className="aff"><span className="muted small">{l}</span><div className="chips">{a.map((v) => <Chip key={v}>{v}</Chip>)}</div></div>)}
          {(an.ips.internal.length > 0 || an.ips.external.length > 0) && <div className="aff"><span className="muted small">IPs</span><div className="chips">{an.ips.internal.map((v) => <Chip key={v}>{v}</Chip>)}{an.ips.external.map((v) => <Chip key={v} ext>{v}</Chip>)}</div></div>}
          {!an.hosts.length && !an.users.length && !an.ips.internal.length && !an.ips.external.length && <p className="muted small">Nothing extracted.</p>}
        </div>
      </div>
      <div className="sub-h-row"><h4 className="sub-h">Indicators</h4><button className="link small" onClick={() => setTab("osint")} data-testid="check-in-osint-link">Check these in OSINT <ExternalLink size={12} /></button></div>
      <div className="tbl-wrap">
        <table className="tbl" data-testid="indicators-table">
          <thead><tr><th>Type</th><th>Value</th><th>Note</th></tr></thead>
          <tbody>
            {an.iocs.map((i) => <tr key={i.value}><td>{i.type}</td><td className="mono brk">{i.value}</td><td className="muted">{i.note}</td></tr>)}
            {!an.iocs.length && <tr><td colSpan={3} className="muted">No indicators extracted.</td></tr>}
          </tbody>
        </table>
      </div>
      <h4 className="sub-h">Recommended actions</h4>
      <ol className="actions" data-testid="recommended-actions">{an.actions.map((a) => <li key={a}>{a.replace(/`/g, "")}</li>)}</ol>
      <Drafts app={app} />
    </Panel>
  );
}

export default function Assessment({ app }) {
  return (
    <div className="grid2" data-testid="assessment-tab">
      <div className="col"><Intake app={app} /><Recent app={app} /></div>
      <div className="col"><Result app={app} /></div>
    </div>
  );
}
