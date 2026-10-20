import { useEffect, useMemo, useState } from "react";
import { Sparkles } from "lucide-react";
import { Panel, Chip, CopyBlock } from "./ui";
import { analyze, detectSource, findDecodable } from "./engine";
import { buildQueries, LANGS } from "./queries";
import { fmtDT, fmtTime, fmtDate, load, save } from "./util";
import { SAMPLE_B } from "./samples";

function Pulled({ an }) {
  const groups = [
    ["Time window", an.window ? [`${fmtDT(an.window.start)} – ${fmtTime(an.window.end)}`] : []],
    ["Users", an.users], ["Hosts", an.hosts], ["External IPs", an.ips.external], ["Internal IPs", an.ips.internal],
    ["Domains & URLs", [...an.domains, ...an.urls]], ["File hashes", an.hashes.map((h) => h.value)],
    ["Parent processes", an.parents], ["MITRE techniques", an.techniques.map((t) => `${t.id} ${t.name}`)],
  ];
  return (
    <div className="pulled" data-testid="pulled-grid">
      {groups.map(([l, a]) => (
        <div key={l} className="pulled-cell">
          <span className="field-l">{l}</span>
          <div className="chips">{a.length ? a.map((v) => <Chip key={v} ext={l === "External IPs"}>{v}</Chip>) : <span className="muted small">None</span>}</div>
        </div>
      ))}
    </div>
  );
}

function Decoded({ text }) {
  const items = useMemo(() => findDecodable(text), [text]);
  if (!items.length) return null;
  return (
    <div className="decoded" data-testid="decoded-strings">
      <span className="field-l">Decoded strings</span>
      {items.map((d) => (
        <div key={d.src} className="decoded-row">
          <span className="pill sev-neutral">{d.kind}</span>
          <code className="mono brk muted small">{d.src.slice(0, 48)}{d.src.length > 48 ? "…" : ""}</code>
          <code className="mono brk decoded-out">{d.decoded}</code>
        </div>
      ))}
    </div>
  );
}

function Checklist({ app }) {
  const { items, state } = app.checklistInfo;
  const done = items.filter((i) => state[i]).length;
  return (
    <Panel title="Investigation checklist" right={<span className="mono small" data-testid="checklist-progress-text">{done} of {items.length} done</span>} testid="checklist-panel">
      <div className="meter thin" aria-hidden><div className="meter-fill bg-accent" style={{ width: `${items.length ? (done / items.length) * 100 : 0}%` }} /></div>
      <ul className="checklist">
        {items.map((it, i) => (
          <li key={it}>
            <label className={`check ${state[it] ? "is-done" : ""}`}>
              <input type="checkbox" checked={!!state[it]} onChange={() => app.toggleCheck(it)} data-testid={`checklist-item-${i}`} /> <span>{it}</span>
            </label>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function Timeline({ an, onExplain }) {
  return (
    <Panel title="Event timeline" right={<span className="muted small">UTC+08:00</span>} testid="timeline-panel">
      {!an.timeline.length && <p className="muted">No timestamps found in the logs.</p>}
      <ol className="timeline">
        {an.timeline.map((r, i) => (
          <li key={i} data-testid={`timeline-row-${i}`}>
            <span className="mono tl-t">{fmtTime(r.ts)}<br /><span className="muted">{fmtDate(r.ts)}</span></span>
            <div className="tl-body">
              <div className="pill-row">
                {r.techs.map((t) => <span key={t} className="pill sev-high mono">{t}</span>)}
                {r.blocked && <span className="pill sev-low">Blocked</span>}
                <button className="btn btn-xs tl-explain" onClick={() => onExplain(r.raw)} data-testid={`timeline-explain-${i}`}><Sparkles size={11} /> Explain</button>
              </div>
              <code className="mono brk tl-line">{r.raw}</code>
            </div>
          </li>
        ))}
      </ol>
    </Panel>
  );
}

export default function Investigation({ app }) {
  const [mode, setMode] = useState(() => load("invMode", "ticket"));
  const [paste, setPaste] = useState(() => load("invPaste", ""));
  const [applied, setApplied] = useState(() => load("invPaste", ""));
  const [lang, setLang] = useState(() => load("invLang", "sentinel"));
  const [hint, setHint] = useState("");
  useEffect(() => { save("invMode", mode); save("invLang", lang); }, [mode, lang]);
  const srcText = mode === "ticket" ? app.entry?.form.rawLogs || "" : applied;
  const an = useMemo(() => (mode === "ticket" ? app.an : analyze({ rawLogs: applied })), [mode, app.an, applied]);
  useEffect(() => {
    const d = detectSource(srcText);
    if (d) { setLang(d); setHint(`Detected ${LANGS.find((l) => l.k === d).label} logs. Switched the query language.`); } else setHint("");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [srcText]);
  const queries = useMemo(() => buildQueries(an, lang), [an, lang]);
  const suggest = () => { setApplied(paste); save("invPaste", paste); };
  return (
    <div className="stack" data-testid="investigation-tab">
      <Panel title="Alert logs" testid="alert-logs-panel" right={
        <div className="seg" role="tablist">
          <button className={`seg-btn ${mode === "paste" ? "on" : ""}`} onClick={() => setMode("paste")} data-testid="logs-mode-paste">Paste alert logs</button>
          <button className={`seg-btn ${mode === "ticket" ? "on" : ""}`} onClick={() => setMode("ticket")} data-testid="logs-mode-ticket">Use ticket logs</button>
        </div>
      }>
        {mode === "paste" ? (
          <>
            <textarea className="input mono ta-logs" value={paste} onChange={(e) => setPaste(e.target.value)} placeholder="Paste alert logs from any source" spellCheck={false} data-testid="investigation-logs-input" />
            <div className="btn-row">
              <button className="btn btn-primary" onClick={suggest} data-testid="suggest-queries-btn">Suggest queries</button>
              <button className="btn" onClick={() => { setPaste(""); setApplied(""); save("invPaste", ""); setHint(""); }} data-testid="investigation-clear-btn">Clear</button>
              <button className="btn btn-ghost" onClick={() => { setPaste(SAMPLE_B.rawLogs); setApplied(SAMPLE_B.rawLogs); }} data-testid="investigation-sample-btn">Load sample</button>
            </div>
          </>
        ) : <p className="muted small">Using the raw logs from ticket <span className="mono">{app.entry?.form.ticketId || "—"}</span> ({an.events} lines).</p>}
        {hint && <p className="hint-ok small" data-testid="source-detect-hint">{hint}</p>}
        <h4 className="sub-h">Pulled from these logs</h4>
        <Pulled an={an} />
        <Decoded text={srcText} />
      </Panel>
      <div className="grid2">
        <div className="col">
          <Panel title="Suggested queries" right={<span className="mono small muted">{queries.length} queries</span>} testid="queries-panel">
            <div className="lang-switch" role="tablist" data-testid="query-lang-switch">
              {LANGS.map((l) => <button key={l.k} className={`seg-btn ${lang === l.k ? "on" : ""}`} onClick={() => { setLang(l.k); setHint(""); }} data-testid={`lang-${l.k}`}>{l.label} <span className="muted">{l.sub}</span></button>)}
            </div>
            {!queries.length && <p className="muted">No entities found. Paste logs or load a ticket with logs.</p>}
            <div className="qcards">
              {queries.map((q, i) => (
                <article key={q.id} className="qcard" data-testid={`query-card-${i}`}>
                  <span className="basis mono">{q.basis}</span>
                  <h3 className="qtitle">{q.title}</h3>
                  <p className="muted small">{q.why}</p>
                  <CopyBlock text={q.query} testid={`query-text-${i}`} />
                  <footer className="qrun small muted">Run with · {q.run.set} · {q.run.range} · {q.run.path}</footer>
                </article>
              ))}
            </div>
          </Panel>
        </div>
        <div className="col">
          <Checklist app={app} />
          <Timeline an={an} onExplain={(line) => app.askAi({ mode: "explain", line })} />
        </div>
      </div>
    </div>
  );
}
