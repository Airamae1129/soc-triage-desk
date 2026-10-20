import { useEffect, useState } from "react";
import { ChevronRight } from "lucide-react";
import { Panel, SevPill } from "./ui";
import { SEVS, sevKey } from "./util";

const blank = (name) => ({ name, matrix: SEVS.map((sev) => ({ sev, contact: "", email: "", channel: "", sla: "" })), containment: "", procedures: [], contacts: [], benign: [] });
const toText = (pb) => ({
  matrix: pb.matrix.map((r) => [r.sev, r.contact, r.email, r.channel, r.sla].join(" | ")).join("\n"),
  containment: pb.containment,
  procedures: pb.procedures.map((p) => [`## ${p.title}`, ...p.steps].join("\n")).join("\n\n"),
  contacts: pb.contacts.map((c) => [c.name, c.role, c.email, c.phone].join(" | ")).join("\n"),
  benign: pb.benign.join("\n"),
});
const split = (l) => l.split("|").map((x) => x.trim());
const fromText = (name, t) => ({
  name,
  matrix: t.matrix.split("\n").filter((l) => l.trim()).map((l) => { const [sev, contact, email, channel, sla] = split(l); return { sev: SEVS.find((s) => s.toLowerCase() === (sev || "").toLowerCase()) || sev, contact, email, channel, sla }; }),
  containment: t.containment.trim(),
  procedures: t.procedures.split(/^##\s*/m).map((b) => b.trim()).filter(Boolean).map((b) => { const [title, ...steps] = b.split("\n").map((x) => x.trim()).filter(Boolean); return { title, steps }; }),
  contacts: t.contacts.split("\n").filter((l) => l.trim()).map((l) => { const [n, role, email, phone] = split(l); return { name: n, role, email, phone }; }),
  benign: t.benign.split("\n").map((x) => x.trim()).filter(Boolean),
});
export const procMatches = (title, alert) => { const a = (alert || "").toLowerCase(), t = (title || "").toLowerCase(); return !!a && !!t && (a.includes(t) || t.includes(a)); };

function Editor({ pb, onSave, onCancel }) {
  const [t, setT] = useState(toText(pb));
  const ta = (k, label, rows, hint) => (
    <label className="field field-wide"><span className="field-l">{label}{hint && <span className="muted"> · {hint}</span>}</span>
      <textarea className="input mono" rows={rows} value={t[k]} onChange={(e) => setT({ ...t, [k]: e.target.value })} data-testid={`pb-edit-${k}`} /></label>
  );
  return (
    <Panel title={`Edit playbook · ${pb.name}`} testid="playbook-editor">
      <div className="form-grid">
        {ta("matrix", "Escalation matrix", 5, "Severity | Contact | Email | Channel | SLA")}
        {ta("containment", "Containment authority", 3)}
        {ta("procedures", "Procedures", 10, "## Title, then one step per line")}
        {ta("contacts", "Contacts", 4, "Name | Role | Email | Phone")}
        {ta("benign", "Known benign activity", 4, "one per line")}
        <div className="btn-row field-wide">
          <button className="btn btn-primary" onClick={() => onSave(fromText(pb.name, t))} data-testid="pb-save-btn">Save playbook</button>
          <button className="btn" onClick={onCancel} data-testid="pb-cancel-btn">Cancel</button>
        </div>
      </div>
    </Panel>
  );
}

function Tuning({ app }) {
  const groups = {};
  app.history.filter((h) => h.isFP).forEach((h) => {
    const k = `${h.rule}|${h.primary}`;
    groups[k] = groups[k] || { rule: h.rule, ioc: h.primary, client: h.form.client, n: 0 };
    groups[k].n++;
  });
  const list = Object.values(groups);
  return (
    <Panel title="Rule tuning suggestions" testid="tuning-panel">
      <p className="muted small">Built from tickets closed as false positive or benign.</p>
      {!list.length && <p className="muted">None yet.</p>}
      <ul className="plain">
        {list.map((g) => <li key={g.rule + g.ioc} className="tune-row"><b>{g.rule}</b><span className="mono small">{g.ioc || "—"}</span><span className="muted small">{g.client} · ×{g.n}</span></li>)}
      </ul>
    </Panel>
  );
}

export default function Playbook({ app }) {
  const { playbooks, setPlaybooks, entry, an } = app;
  const names = Object.keys(playbooks);
  const ticketClient = names.find((n) => n.toLowerCase() === (entry?.form.client || "").toLowerCase());
  const [sel, setSel] = useState(ticketClient || names[0] || "");
  const [edit, setEdit] = useState(false);
  const [newName, setNewName] = useState("");
  const [adding, setAdding] = useState(false);
  useEffect(() => { if (ticketClient) setSel(ticketClient); }, [ticketClient]);
  const pb = playbooks[sel];
  const isTicket = sel === ticketClient;
  const create = (e) => {
    e.preventDefault();
    const n = newName.trim();
    if (!n || playbooks[n]) return;
    setPlaybooks({ ...playbooks, [n]: blank(n) });
    setSel(n); setNewName(""); setAdding(false); setEdit(true);
  };
  return (
    <div className="stack" data-testid="playbook-tab">
      <div className="toolbar">
        <label className="field inline"><span className="field-l">Client</span>
          <select className="input" value={sel} onChange={(e) => { setSel(e.target.value); setEdit(false); }} data-testid="pb-client-select">{names.map((n) => <option key={n}>{n}</option>)}</select>
        </label>
        <button className="btn" onClick={() => setEdit(!edit)} disabled={!pb} data-testid="pb-edit-btn">{edit ? "Close editor" : "Edit playbook"}</button>
        <button className="btn" onClick={() => setAdding(!adding)} data-testid="pb-new-client-btn">New client</button>
        {adding && (
          <form className="inline-form" onSubmit={create}>
            <input className="input" value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Client name" autoFocus data-testid="pb-new-client-input" />
            <button className="btn btn-primary" data-testid="pb-new-client-save">Create</button>
          </form>
        )}
        {!isTicket && entry && <span className="muted small">Current ticket client: {entry.form.client || "—"}{!ticketClient && " (no playbook)"}</span>}
      </div>
      {!pb && <Panel title="Playbook"><p className="muted">No playbooks yet. Create one with New client.</p></Panel>}
      {pb && edit && <Editor key={sel} pb={pb} onCancel={() => setEdit(false)} onSave={(np) => { setPlaybooks({ ...playbooks, [sel]: np }); setEdit(false); }} />}
      {pb && !edit && (
        <div className="grid2">
          <div className="col">
            <Panel title="Escalation matrix" testid="pb-matrix-panel">
              <div className="tbl-wrap">
                <table className="tbl" data-testid="pb-matrix-table">
                  <thead><tr><th>Severity</th><th>Notify</th><th>Email</th><th>Channel</th><th>SLA</th></tr></thead>
                  <tbody>
                    {pb.matrix.map((r) => (
                      <tr key={r.sev} className={isTicket && r.sev === an.severity ? `row-hl sevb-${sevKey(r.sev)}` : ""} data-testid={`pb-row-${sevKey(r.sev)}`}>
                        <td><SevPill sev={r.sev} /></td><td>{r.contact}</td><td className="mono small brk">{r.email}</td><td>{r.channel}</td><td className="mono">{r.sla}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {pb.containment && <div className="callout" data-testid="pb-containment"><b>Containment authority</b><p>{pb.containment}</p></div>}
            </Panel>
            <Panel title="Procedures" testid="pb-procedures-panel">
              {!pb.procedures.length && <p className="muted">No procedures yet.</p>}
              {pb.procedures.map((p, i) => {
                const m = isTicket && procMatches(p.title, entry?.form.alertName);
                return (
                  <details key={p.title + i} className="fold proc" open={m || undefined} data-testid={`pb-procedure-${i}`}>
                    <summary><ChevronRight size={14} className="chev" /> {p.title} {m && <span className="pill sev-accent">Matches current alert</span>}</summary>
                    <ol className="steps">{p.steps.map((s, j) => <li key={j}>{s}</li>)}</ol>
                  </details>
                );
              })}
            </Panel>
          </div>
          <div className="col">
            <Panel title="Contacts" testid="pb-contacts-panel">
              <ul className="plain contacts">
                {pb.contacts.map((c) => <li key={c.name + c.email}><b>{c.name}</b> <span className="muted small">{c.role}</span><br /><span className="mono small">{c.email}</span>{c.phone && <span className="mono small muted"> · {c.phone}</span>}</li>)}
                {!pb.contacts.length && <li className="muted">No contacts.</li>}
              </ul>
            </Panel>
            <Panel title="Known benign activity" right={<span className="muted small">Check here before escalating</span>} testid="pb-benign-panel">
              <ul className="benign">{pb.benign.map((b) => <li key={b}>{b}</li>)}{!pb.benign.length && <li className="muted">None listed.</li>}</ul>
            </Panel>
            <Tuning app={app} />
          </div>
        </div>
      )}
    </div>
  );
}
