import { useMemo, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend, CartesianGrid } from "recharts";
import { Panel, SevPill } from "./ui";
import { shiftOf, SHIFTS, SEVS, fmtSpan } from "./util";
import { analyze } from "./engine";

const ORDER = ["Morning", "Mid", "Night"];
const sortKeys = (a, b) => { const [da, na] = a.split("|"), [db, nb] = b.split("|"); return da !== db ? (da < db ? 1 : -1) : ORDER.indexOf(nb) - ORDER.indexOf(na); };
const short = (k) => { const [d, n] = k.split("|"); return `${d.slice(5)} ${n}`; };
const isTP = (h) => /true positive/i.test(h.verdict || "");
const pct = (n, d) => (d ? `${Math.round((n / d) * 100)}%` : "—");

function metrics(list) {
  const tp = list.filter(isTP).length, fp = list.filter((h) => h.isFP).length;
  const esc = list.filter((h) => h.escalatedAt);
  const times = esc.map((h) => (h.firstTs ? new Date(h.escalatedAt) - h.firstTs : null)).filter((x) => x != null && x >= 0);
  return { n: list.length, tp, fp, other: list.length - tp - fp, esc: esc.length, avg: times.length ? times.reduce((a, b) => a + b, 0) / times.length : null, sev: SEVS.map((s) => [s, list.filter((h) => h.sev === s).length]) };
}

export default function Dashboard({ app }) {
  const rows = useMemo(() => app.history.map((h) => ({ ...h, firstTs: analyze(h.form).window?.start || null, shiftKey: shiftOf(h.createdAt || h.savedAt).key })), [app.history]);
  const keys = useMemo(() => [...new Set([shiftOf(new Date()).key, ...rows.map((r) => r.shiftKey)])].sort(sortKeys), [rows]);
  const withData = keys.filter((k) => rows.some((r) => r.shiftKey === k));
  const [key, setKey] = useState(withData[0] || keys[0]);
  const list = rows.filter((r) => r.shiftKey === key);
  const m = metrics(list);
  const chart = [...keys].slice(0, 9).reverse().map((k) => { const x = metrics(rows.filter((r) => r.shiftKey === k)); return { shift: short(k), "True positive": x.tp, "False positive / benign": x.fp, Other: x.other }; });
  const top = (fn) => Object.entries(list.reduce((a, h) => { const v = fn(h); if (v) a[v] = (a[v] || 0) + 1; return a; }, {})).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const [d, n] = key.split("|");
  return (
    <div className="stack" data-testid="dashboard-tab">
      <div className="toolbar">
        <label className="field inline"><span className="field-l">Shift</span>
          <select className="input" value={key} onChange={(e) => setKey(e.target.value)} data-testid="dash-shift-select">
            {keys.map((k) => <option key={k} value={k}>{shiftOf(new Date(`${k.split("|")[0]}T12:00:00+08:00`)).date} · {k.split("|")[1]} ({SHIFTS[k.split("|")[1]]})</option>)}
          </select>
        </label>
        <span className="muted small">Alerts are counted in the shift they were assessed (Manila time).</span>
      </div>
      <div className="kpis" data-testid="dash-kpis">
        <div className="kpi" data-testid="kpi-alerts"><span>Alerts handled</span><b className="mono">{m.n}</b></div>
        <div className="kpi" data-testid="kpi-tp"><span>True positive rate</span><b className="mono">{pct(m.tp, m.n)}</b><em className="muted small">{m.tp} of {m.n}</em></div>
        <div className="kpi" data-testid="kpi-fp"><span>False positive / benign rate</span><b className="mono">{pct(m.fp, m.n)}</b><em className="muted small">{m.fp} of {m.n}</em></div>
        <div className="kpi" data-testid="kpi-escalated"><span>Escalated</span><b className="mono">{m.esc}</b></div>
        <div className="kpi" data-testid="kpi-tte"><span>Avg time to escalate</span><b className="mono">{m.avg == null ? "—" : fmtSpan(m.avg)}</b><em className="muted small">first log event → escalation</em></div>
      </div>
      <div className="grid2">
        <div className="col">
          <Panel title="Alerts per shift" right={<span className="muted small">last {chart.length} shifts</span>} testid="dash-chart-panel">
            <div style={{ width: "100%", height: 260 }}>
              <ResponsiveContainer>
                <BarChart data={chart} margin={{ top: 6, right: 8, left: -18, bottom: 0 }}>
                  <CartesianGrid stroke="var(--line)" vertical={false} />
                  <XAxis dataKey="shift" tick={{ fill: "var(--muted)", fontSize: 11 }} />
                  <YAxis allowDecimals={false} tick={{ fill: "var(--muted)", fontSize: 11 }} />
                  <Tooltip contentStyle={{ background: "var(--panel)", border: "1px solid var(--line)", fontSize: 12 }} cursor={{ fill: "var(--sunk)" }} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  <Bar dataKey="True positive" stackId="a" fill="var(--crit)" />
                  <Bar dataKey="False positive / benign" stackId="a" fill="var(--low)" />
                  <Bar dataKey="Other" stackId="a" fill="var(--med)" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Panel>
          <Panel title="Per-shift breakdown" testid="dash-table-panel">
            <div className="tbl-wrap">
              <table className="tbl" data-testid="dash-table">
                <thead><tr><th>Shift</th><th className="num">Alerts</th><th className="num">TP</th><th className="num">FP</th><th className="num">Escalated</th><th className="num">Avg to escalate</th></tr></thead>
                <tbody>
                  {withData.map((k) => { const x = metrics(rows.filter((r) => r.shiftKey === k)); return (
                    <tr key={k} className={k === key ? "row-hl" : ""}><td><button className="link" onClick={() => setKey(k)}>{short(k)}</button></td><td className="num mono">{x.n}</td><td className="num mono">{pct(x.tp, x.n)}</td><td className="num mono">{pct(x.fp, x.n)}</td><td className="num mono">{x.esc}</td><td className="num mono">{x.avg == null ? "—" : fmtSpan(x.avg)}</td></tr>
                  ); })}
                </tbody>
              </table>
            </div>
          </Panel>
        </div>
        <div className="col">
          <Panel title={`Severity mix · ${d.slice(5)} ${n}`} testid="dash-sev-panel">
            <div className="pill-row">{m.sev.map(([s, c]) => <span key={s} className="pill-row"><SevPill sev={s} /> <b className="mono">{c}</b></span>)}</div>
          </Panel>
          <Panel title="Top clients" testid="dash-clients-panel">
            <ul className="plain">{top((h) => h.form.client).map(([c, k]) => <li key={c} className="tune-row"><span>{c}</span><span className="mono small muted">×{k}</span></li>)}{!m.n && <li className="muted">No alerts in this shift.</li>}</ul>
          </Panel>
          <Panel title="Top alert rules" testid="dash-rules-panel">
            <ul className="plain">{top((h) => h.form.alertName).map(([c, k]) => <li key={c} className="tune-row"><span>{c}</span><span className="mono small muted">×{k}</span></li>)}{!m.n && <li className="muted">No alerts in this shift.</li>}</ul>
          </Panel>
          <Panel title="Analysts" testid="dash-analysts-panel">
            <ul className="plain">{top((h) => h.form.analyst).map(([c, k]) => <li key={c} className="tune-row"><span>{c}</span><span className="mono small muted">×{k}</span></li>)}{!m.n && <li className="muted">—</li>}</ul>
          </Panel>
        </div>
      </div>
    </div>
  );
}
