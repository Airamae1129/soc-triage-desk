import { useState } from "react";
import { Download } from "lucide-react";
import { Panel, CopyBtn, DefangToggle, SevPill, VerdictPill, SlaTimer } from "./ui";
import { fmtDTm, manilaInput, fromManilaInput, fmtHM, download, fmtDT } from "./util";
import { osintSummary, verdictLine } from "./drafts";
import { wsForSummary } from "./Osint";

const TYPES = ["Investigation", "Assessment", "Client comms", "Containment", "Handover"];
const typeTone = { Investigation: "accent", Assessment: "medium", "Client comms": "high", Containment: "critical", Handover: "low" };

export default function Notes({ app }) {
  const { ticketNotes, addNote, delNote, an, entry, pbRow, ws, user, isAdmin } = app;
  const [type, setType] = useState("Investigation");
  const [time, setTime] = useState(manilaInput(new Date()));
  const [text, setText] = useState("");
  const [msg, setMsg] = useState("");
  const f = entry?.form || {};
  const sorted = [...ticketNotes].sort((a, b) => new Date(a.time) - new Date(b.time));
  const allText = [`SOC NOTES – ${f.ticketId || "—"} · ${f.client || "—"}`, `Alert: ${an.title}`, "",
    ...sorted.map((n) => `[${fmtDTm(n.time)}] ${n.type.toUpperCase()}${n.author ? ` (${n.author})` : ""}\n${n.text}`)].join("\n");
  const submit = (e) => {
    e.preventDefault();
    if (!text.trim()) return setMsg("Write a note first.");
    addNote({ type, time: fromManilaInput(time).toISOString(), text: text.trim() });
    setText(""); setMsg(""); setTime(manilaInput(new Date()));
  };
  // OSINT results come from the analyst's OSINT tab (left-out indicators excluded).
  const { iocs: osintIocs, values: osintVals } = wsForSummary(ws.items);
  return (
    <div className="grid2" data-testid="notes-tab">
      <div className="col">
        <Panel title="New note" testid="new-note-panel">
          <form className="form-grid" onSubmit={submit}>
            <label className="field"><span className="field-l">Type</span>
              <select className="input" value={type} onChange={(e) => setType(e.target.value)} data-testid="note-type-select">{TYPES.map((t) => <option key={t}>{t}</option>)}</select>
            </label>
            <label className="field"><span className="field-l">Time (UTC+08:00)</span>
              <input type="datetime-local" className="input mono" value={time} onChange={(e) => setTime(e.target.value)} data-testid="note-time-input" />
            </label>
            <label className="field field-wide"><span className="field-l">Note</span>
              <textarea className="input ta-mid" value={text} onChange={(e) => setText(e.target.value)} placeholder="What did you find or do?" data-testid="note-text-input" />
            </label>
            <div className="btn-row field-wide">
              <button className="btn btn-primary" data-testid="add-note-btn">Add note</button>
              <button type="button" className="btn" onClick={() => { setType("Assessment"); setText(`${an.summary}\n${verdictLine(an)}`); }} data-testid="insert-assessment-btn">Insert assessment summary</button>
              <button type="button" className="btn" onClick={() => { setType("Investigation"); setText(osintSummary(f, osintIocs, osintVals, ws.shots)); }} data-testid="insert-osint-btn">Insert OSINT results</button>
            </div>
            {msg && <p className="muted small field-wide" data-testid="notes-msg">{msg}</p>}
          </form>
        </Panel>
        <Panel title="Case log" right={<span className="mono small muted">{sorted.length} notes</span>} testid="case-log-panel">
          {!sorted.length && <p className="muted">No notes for this ticket yet.</p>}
          <ol className="caselog">
            {sorted.map((n) => (
              <li key={n.id} data-testid={`note-${n.id}`}>
                <div className="caselog-h">
                  <span className="mono small">{fmtDTm(n.time)}</span>
                  <span className={`typelabel t-${typeTone[n.type]}`}>{n.type}</span>
                  {n.author && <span className="muted small">{n.author}</span>}
                  {(isAdmin || n.authorId === user?.id) && <button className="x" onClick={() => delNote(n.id)} aria-label="Delete note" data-testid={`delete-note-${n.id}`}>×</button>}
                </div>
                <p className="caselog-t">{n.text}</p>
              </li>
            ))}
          </ol>
        </Panel>
      </div>
      <div className="col">
        <Panel title="Ticket at a glance" testid="glance-panel">
          <dl className="kv">
            <dt>Verdict</dt><dd><VerdictPill verdict={an.verdict} /> <SevPill sev={an.severity} /></dd>
            <dt>Analyst</dt><dd>{f.analyst || "—"}</dd>
            <dt>Window</dt><dd className="mono small">{an.window ? `${fmtDT(an.window.start)} – ${fmtHM(an.window.end)}` : "—"}</dd>
            <dt>Escalated</dt><dd className="mono" data-testid="glance-escalated">{entry?.escalatedAt ? fmtDTm(entry.escalatedAt) : "Not escalated"}</dd>
            <dt>SLA</dt><dd>{pbRow ? `${pbRow.sla} · ${pbRow.channel}` : "No playbook row"} {entry?.escalatedAt && <SlaTimer escalatedAt={entry.escalatedAt} sla={pbRow?.sla} status={entry.notableStatus} testid="glance-sla-timer" />}</dd>
          </dl>
        </Panel>
        <Panel title="Export" testid="export-panel">
          <div className="btn-row">
            <DefangToggle testid="notes-defang" />
            <CopyBtn text={allText} label="Copy all notes" testid="copy-all-notes-btn" />
            <button className="btn btn-sm" onClick={() => download(`${f.ticketId || "ticket"}-notes.txt`, allText)} data-testid="download-notes-btn"><Download size={13} /> Notes .txt</button>
          </div>
          <h4 className="sub-h">Export loaded data</h4>
          <div className="btn-row">
            <button className="btn btn-sm" onClick={() => download(`soc-triage-export-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(app.exportAll(), null, 2), "application/json")} data-testid="backup-json-btn"><Download size={13} /> Export .json</button>
            <span className="muted small">Data lives on the server; this is a copy for reports.</span>
          </div>
        </Panel>
      </div>
    </div>
  );
}
