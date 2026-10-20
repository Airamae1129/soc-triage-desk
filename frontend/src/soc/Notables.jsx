import { useEffect, useMemo, useState } from "react";
import { Download } from "lucide-react";
import { Panel, SevPill, CopyBlock, SlaTimer } from "./ui";
import { shiftOf, fmtHM, sevKey, SEVS, download, SHIFTS } from "./util";
import { notablesText } from "./drafts";

const STATUSES = ["Awaiting client", "Contained", "Monitoring", "Closed"];
const label = (k) => { const [d, n] = k.split("|"); return `${shiftOf(new Date(`${d}T12:00:00+08:00`)).date} · ${n} (${SHIFTS[n]})`; };

export default function Notables({ app }) {
  const { history, updateEntry, loadEntry, playbooks, setTab, analyst } = app;
  const esc = history.filter((h) => h.escalatedAt);
  const keys = useMemo(() => {
    const ks = [...new Set([shiftOf(new Date()).key, ...esc.map((h) => shiftOf(h.escalatedAt).key)])];
    return ks.sort((a, b) => (a < b ? 1 : a > b ? -1 : 0));
  }, [esc]);
  const latest = esc.length ? shiftOf([...esc].sort((a, b) => new Date(b.escalatedAt) - new Date(a.escalatedAt))[0].escalatedAt).key : keys[0];
  const [key, setKey] = useState(latest);
  useEffect(() => { if (!keys.includes(key)) setKey(latest); }, [keys, key, latest]);
  const order = ["Morning", "Mid", "Night"];
  const sortedKeys = [...keys].sort((a, b) => { const [da, na] = a.split("|"), [db, nb] = b.split("|"); return da !== db ? (da < db ? 1 : -1) : order.indexOf(nb) - order.indexOf(na); });
  const list = esc.filter((h) => shiftOf(h.escalatedAt).key === key).sort((a, b) => new Date(a.escalatedAt) - new Date(b.escalatedAt));
  const text = notablesText(key, list);
  const slaOf = (h) => playbooks[Object.keys(playbooks).find((n) => n.toLowerCase() === (h.form.client || "").toLowerCase())]?.matrix.find((r) => r.sev === h.sev)?.sla;
  return (
    <div className="stack" data-testid="notables-tab">
      <div className="toolbar">
        <label className="field inline"><span className="field-l">Shift</span>
          <select className="input" value={key} onChange={(e) => setKey(e.target.value)} data-testid="notables-shift-select">{sortedKeys.map((k) => <option key={k} value={k}>{label(k)}</option>)}</select>
        </label>
        <div className="pill-row" data-testid="notables-sev-counts">
          {SEVS.map((s) => <span key={s} className={`pill sev-${sevKey(s)}`}>{s} {list.filter((h) => h.sev === s).length}</span>)}
        </div>
      </div>
      <div className="grid2">
        <div className="col">
          <Panel title="Escalations" right={<span className="mono small muted">{list.length}</span>} testid="notables-list-panel">
            {!list.length && <p className="muted">No escalations in this shift. Use “Mark as escalated” on the Assessment tab.</p>}
            <ul className="notables">
              {list.map((h) => (
                <li key={h.id} className={`notable sevb-${sevKey(h.sev)}`} data-testid={`notable-${h.id}`}>
                  <div className="notable-h">
                    <span className="mono">{fmtHM(h.escalatedAt)}</span>
                    <SevPill sev={h.sev} />
                    <span>{h.form.client}</span>
                    <button className="link mono" onClick={() => { loadEntry(h.id); setTab("assessment"); }} data-testid={`notable-open-${h.id}`}>{h.form.ticketId}</button>
                  </div>
                  <div className="notable-alert">{h.form.alertName}</div>
                  <p className="muted small">{h.summary}</p>
                  <div className="notable-f">
                    <select className="input input-sm" value={h.notableStatus || "Awaiting client"} aria-label="Status"
                      onChange={(e) => updateEntry(h.id, { notableStatus: e.target.value, statusLog: [...(h.statusLog || []), { status: e.target.value, by: analyst || h.form.analyst, at: new Date().toISOString() }] })}
                      data-testid={`notable-status-${h.id}`}>{STATUSES.map((s) => <option key={s}>{s}</option>)}</select>
                    <span className="muted small">{h.form.analyst || "—"}</span>
                    <SlaTimer escalatedAt={h.escalatedAt} sla={slaOf(h)} status={h.notableStatus} testid={`notable-sla-${h.id}`} />
                    {h.statusLog?.length > 0 && <span className="muted small">Last change: {h.statusLog[h.statusLog.length - 1].by || "—"} {fmtHM(h.statusLog[h.statusLog.length - 1].at)}</span>}
                  </div>
                </li>
              ))}
            </ul>
          </Panel>
        </div>
        <div className="col">
          <Panel title="Shift notables" testid="notables-text-panel">
            <CopyBlock text={text} testid="notables-text" extra={<button className="btn btn-sm" onClick={() => download(`notables-${key.replace("|", "-")}.txt`, text)} data-testid="notables-download"><Download size={13} /> .txt</button>} />
          </Panel>
        </div>
      </div>
    </div>
  );
}
