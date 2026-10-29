import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { Copy, Check, ChevronDown } from "lucide-react";
import { copyText, sevKey, fmtHM, parseSla, defangText, getDefang, setDefang, subscribeDefang } from "./util";

export function Panel({ title, right, children, testid, className = "", bodyClass = "" }) {
  return (
    <section className={`panel ${className}`} data-testid={testid}>
      {title && (
        <header className="panel-h">
          <h2>{title}</h2>
          {right && <div className="panel-h-right">{right}</div>}
        </header>
      )}
      <div className={`panel-b ${bodyClass}`}>{children}</div>
    </section>
  );
}

export const SevPill = ({ sev, testid }) => <span className={`pill sev-${sevKey(sev)}`} data-testid={testid}>{sev}</span>;
export const verdictTone = (v = "") =>
  /true positive/i.test(v) ? "critical" : /monitor|suspicious|pending/i.test(v) ? "medium" : /benign|false/i.test(v) ? "low" : "neutral";
export const VerdictPill = ({ verdict, testid }) => <span className={`pill sev-${verdictTone(verdict)}`} data-testid={testid}>{verdict}</span>;
export const Pill = ({ children, tone = "neutral", testid }) => <span className={`pill sev-${tone}`} data-testid={testid}>{children}</span>;
export const Chip = ({ children, ext, testid }) => <span className={`chip mono ${ext ? "chip-ext" : ""}`} data-testid={testid}>{children}</span>;

/** Shared "Defang indicators" setting: one switch for every copy box in the app. */
export const useDefang = () => useSyncExternalStore(subscribeDefang, getDefang);

export function DefangToggle({ testid = "defang-toggle" }) {
  const on = useDefang();
  return (
    <label className="defang-toggle small" title="Copy IPs, domains, URLs and emails defanged: 1.2.3[.]4, example[.]com, hxxps://, user[@]example[.]com" data-testid={testid}>
      <input type="checkbox" checked={on} onChange={(e) => setDefang(e.target.checked)} /> Defang indicators
    </label>
  );
}

/** raw: never defang (queries, image links). */
export function CopyBtn({ text, targetRef, testid, label = "Copy", small, raw }) {
  const [done, setDone] = useState(false);
  const t = useRef();
  const defang = useDefang() && !raw;
  useEffect(() => () => clearTimeout(t.current), []);
  const go = async () => {
    const s = typeof text === "function" ? text() : text;
    await copyText(defang ? defangText(s) : s, targetRef?.current);
    setDone(true);
    clearTimeout(t.current);
    t.current = setTimeout(() => setDone(false), 2000);
  };
  return (
    <button type="button" className={`btn ${small ? "btn-xs" : "btn-sm"} ${done ? "btn-done" : ""}`} onClick={go} data-testid={testid}>
      {done ? <Check size={13} /> : <Copy size={13} />} {done ? "Copied" : label}
    </button>
  );
}

/** Shows exactly what will be copied: defanged when the shared setting is on (unless raw). */
/** extra: left of the bar; actions: right, next to Copy. */
export function CopyBlock({ text, testid, extra, actions, maxH, raw }) {
  const ref = useRef();
  const defang = useDefang() && !raw;
  return (
    <div className="copyblock">
      <div className="copyblock-bar">
        {extra}
        {!raw && <DefangToggle testid={`${testid}-defang`} />}
        {actions}
        <CopyBtn text={text} targetRef={ref} testid={`${testid}-copy`} raw={raw} />
      </div>
      <pre ref={ref} className="mono pre" style={maxH ? { maxHeight: maxH } : undefined} data-testid={testid}>{defang ? defangText(text) : text}</pre>
    </div>
  );
}

export function useNow(ms = 1000) {
  const [n, setN] = useState(Date.now());
  useEffect(() => { const i = setInterval(() => setN(Date.now()), ms); return () => clearInterval(i); }, [ms]);
  return n;
}

export function SlaTimer({ escalatedAt, sla, status, testid }) {
  const now = useNow();
  const mins = parseSla(sla);
  if (!escalatedAt || !mins) return null;
  if (status === "Closed" || status === "Contained") return <span className="sla sla-ok" data-testid={testid}>SLA stopped · {status}</span>;
  const left = new Date(escalatedAt).getTime() + mins * 60000 - now;
  const abs = Math.abs(left);
  const h = Math.floor(abs / 36e5), m = Math.floor((abs % 36e5) / 6e4), s = Math.floor((abs % 6e4) / 1000);
  const txt = h >= 24 ? `${Math.floor(h / 24)}d ${h % 24}h` : `${h ? `${h}h ` : ""}${m}m ${String(s).padStart(2, "0")}s`;
  return <span className={`sla mono ${left < 0 ? "sla-bad" : "sla-ok"}`} data-testid={testid}>{left < 0 ? `SLA breached +${txt}` : `SLA ${txt} left`}</span>;
}

export function ContextStrip({ app }) {
  const [open, setOpen] = useState(false);
  const { entry, an, history, loadEntry } = app;
  const f = entry?.form || {};
  return (
    <div className={`ctx sevb-${sevKey(an.severity)}`} data-testid="context-strip">
      <div className="ctx-items">
        <span className="ctx-k">Ticket</span><span className="mono ctx-v" data-testid="ctx-ticket">{f.ticketId || "—"}</span>
        <span className="ctx-k">Client</span><span className="ctx-v" data-testid="ctx-client">{f.client || "—"}</span>
        <span className="ctx-k">Alert</span><span className="ctx-v ctx-alert" data-testid="ctx-alert">{an.title}</span>
        <SevPill sev={an.severity} testid="ctx-severity" />
        <VerdictPill verdict={an.verdict} testid="ctx-verdict" />
        {entry?.sample && <span className="tag-sample">Sample</span>}
      </div>
      <div className="ctx-change">
        <button className="btn btn-sm" onClick={() => setOpen(!open)} data-testid="ctx-change-ticket-btn" aria-expanded={open}>
          Change ticket <ChevronDown size={13} />
        </button>
        {open && (
          <div className="menu" role="menu" data-testid="ctx-ticket-menu">
            {history.length === 0 && <div className="muted small pad">No saved tickets.</div>}
            {history.map((h) => (
              <button key={h.id} role="menuitem" className="menu-item" onClick={() => { loadEntry(h.id); setOpen(false); }} data-testid={`ctx-ticket-option-${h.id}`}>
                <span className={`dot sev-dot-${sevKey(h.sev)}`} />
                <span className="mono">{h.form.ticketId}</span>
                <span className="muted small">{h.form.client}</span>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export const escalatedLabel = (e) => (e?.escalatedAt ? `Escalated ${fmtHM(e.escalatedAt)}` : null);

export function Field({ label, children, wide, htmlFor }) {
  return (
    <label className={`field ${wide ? "field-wide" : ""}`} htmlFor={htmlFor}>
      <span className="field-l">{label}</span>
      {children}
    </label>
  );
}
