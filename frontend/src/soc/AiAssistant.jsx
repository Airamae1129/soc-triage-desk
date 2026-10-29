import { useEffect, useRef, useState } from "react";
import { Send, Sparkles, Square, Trash2, AlertTriangle, MessageSquareText, ShieldCheck, ImageUp, Loader2, X, ClipboardPaste, FileText, ArrowRightToLine, Eraser } from "lucide-react";
import { toast } from "sonner";
import { Panel, CopyBlock } from "./ui";
import { aiChat, aiDraftPasted, aiExplainLine, aiReadScreenshot, cleanAi } from "./api";
import { fmtTime, fmtDTm } from "./util";

const QUICK = ["Summarize this ticket in 3 bullets", "Is this a true positive? What evidence supports it?", "What should I check next?", "Draft a short message to the client asking to confirm this activity"];
const QUICK_PASTED = ["What happened in these logs?", "Is this malicious or benign? What evidence supports it?", "List the IPs, users and hosts involved", "What should I check next?"];

/** One AI request at a time per panel, cancellable. */
function useAiRun() {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const ctl = useRef();
  const run = async (fn) => {
    ctl.current?.abort();
    const c = new AbortController();
    ctl.current = c;
    setBusy(true); setErr(null);
    try { return await fn(c.signal); }
    catch (e) { if (e.name !== "AbortError") setErr(e); return null; }
    finally { if (ctl.current === c) setBusy(false); }
  };
  const stop = () => { ctl.current?.abort(); setBusy(false); };
  return { busy, err, run, stop };
}

const ErrBox = ({ err, testid }) => err && (
  <div className="err small" data-testid={testid}>
    {err.message}
    {err.details?.issues?.length > 0 && <ul>{err.details.issues.map((i) => <li key={i}>{i}</li>)}</ul>}
  </div>
);

function Chat({ app, pasted }) {
  const { aiT, setAiT, entry, aiPaste, setAiPaste } = app;
  const [input, setInput] = useState("");
  const { busy, err, run, stop } = useAiRun();
  const endRef = useRef();
  // Ticket chats are kept per ticket in browser storage; pasted-log chats stay in memory only.
  const msgs = (pasted ? aiPaste.chat : aiT.chat) || [];
  const setMsgs = (chat) => (pasted ? setAiPaste({ chat }) : setAiT({ chat }));
  const quick = pasted ? QUICK_PASTED : QUICK;
  useEffect(() => { endRef.current?.scrollIntoView?.({ block: "nearest" }); }, [msgs.length, busy]);
  const send = async (text) => {
    const q = text.trim();
    if (!q || busy) return;
    if (pasted && !aiPaste.logs.trim() && !aiPaste.findings.trim()) { toast.error("Paste the logs first."); return; }
    const next = [...msgs, { role: "user", content: q }];
    setMsgs(next);
    setInput("");
    const ctx = pasted ? { alertName: aiPaste.alertName, rawLogs: aiPaste.logs, findings: aiPaste.findings } : undefined;
    const out = await run((signal) => aiChat(pasted ? null : entry.id, next, signal, ctx));
    if (out) setMsgs([...next, { role: "assistant", content: out.text }]);
    else { setMsgs(msgs); setInput(q); }
  };
  return (
    <Panel title={pasted ? "Ask about the pasted logs" : "Ask about this ticket"} testid="ai-chat-panel" right={msgs.length > 0 && <button className="btn btn-xs" onClick={() => setMsgs([])} data-testid="ai-chat-clear-btn"><Trash2 size={12} /> Clear chat</button>}>
      <div className="chat" data-testid="ai-chat-log">
        {!msgs.length && !busy && <p className="muted small">{pasted ? "The assistant sees the alert name, logs and notes you pasted, with names, hosts and internal IPs replaced by tokens." : "The assistant sees this ticket's most relevant log lines, findings and enrichment fields, with names, hosts and internal IPs replaced by tokens."}</p>}
        {msgs.map((m, i) => <div key={i} className={`msg msg-${m.role}`} data-testid={`ai-msg-${i}`}><span className="msg-who">{m.role === "user" ? "You" : "AI"}</span><div className="msg-t">{cleanAi(m.content)}</div></div>)}
        {busy && <div className="msg msg-assistant" data-testid="ai-msg-live"><span className="msg-who">AI</span><div className="msg-t"><span className="muted">Thinking…</span></div></div>}
        <div ref={endRef} />
      </div>
      <ErrBox err={err} testid="ai-chat-error" />
      <div className="quick">{quick.map((q, i) => <button key={q} className="btn btn-xs btn-ghost" disabled={busy} onClick={() => send(q)} data-testid={`ai-quick-${i}`}>{q}</button>)}</div>
      <form className="inline-form" onSubmit={(e) => { e.preventDefault(); send(input); }}>
        <textarea className="input ta-chat" rows={2} value={input} onChange={(e) => setInput(e.target.value)} placeholder={pasted ? "Ask a question about the pasted logs" : "Ask a question about this ticket"}
          onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(input); } }} data-testid="ai-chat-input" />
        {busy ? <button type="button" className="btn" onClick={stop} data-testid="ai-stop-btn"><Square size={13} /> Stop</button>
          : <button className="btn btn-primary" disabled={!input.trim()} data-testid="ai-send-btn"><Send size={13} /> Send</button>}
      </form>
    </Panel>
  );
}

function Draft({ app }) {
  const { entry, aiRequest, setAiRequest } = app;
  const { busy, err, run, stop } = useAiRun();
  const go = () => run((signal) => app.draftWithAi(signal));
  const consumed = useRef();
  useEffect(() => {
    if (aiRequest?.mode === "draft" && consumed.current !== aiRequest) { consumed.current = aiRequest; setAiRequest(null); go(); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [aiRequest]);
  const text = entry.aiDraft || "";
  return (
    <Panel title="Draft with AI" testid="ai-draft-panel" right={<span className="muted small">Assessment report format</span>}>
      <div className="btn-row">
        {busy ? <button className="btn" onClick={stop} data-testid="ai-draft-stop-btn"><Square size={13} /> Stop</button>
          : <button className="btn btn-primary" onClick={go} data-testid="ai-draft-btn"><Sparkles size={13} /> {text ? "Redraft with AI" : "Draft with AI"}</button>}
        {busy && <span className="muted small">{app.aiConfig?.local ? "Drafting on the local model. This can take a few minutes on a laptop…" : "Drafting and checking the answer…"}</span>}
        {!busy && text && <span className="muted small mono">Saved {fmtDTm(entry.savedAt)}</span>}
      </div>
      <ErrBox err={err} testid="ai-draft-error" />
      {text && (
        <>
          <p className="review small" data-testid="ai-review-note"><AlertTriangle size={13} /> Drafted by AI – review before use. Check every number, IP and the verdict against the logs.</p>
          <CopyBlock text={text} testid="ai-draft-text" maxH={560} />
          <p className="muted small">This draft also appears in the Assessment tab's report.</p>
        </>
      )}
    </Panel>
  );
}

function Explain({ app }) {
  const { an, aiT, setAiT, aiRequest, setAiRequest, entry } = app;
  const [sel, setSel] = useState(null);
  const { busy, err, run } = useAiRun();
  const explains = aiT.explains || {};
  const go = async (line) => {
    setSel(line);
    if (explains[line]) return;
    const out = await run((signal) => aiExplainLine(line, entry.id, signal));
    if (out) setAiT({ explains: { ...explains, [line]: cleanAi(out.text).trim() } });
  };
  const consumed = useRef();
  useEffect(() => {
    if (aiRequest?.mode === "explain" && consumed.current !== aiRequest) { consumed.current = aiRequest; const l = aiRequest.line; setAiRequest(null); go(l); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [aiRequest]);
  const rows = an.timeline.length ? an.timeline : an.lines.map((raw) => ({ raw }));
  return (
    <Panel title="Explain this log line" testid="ai-explain-panel" right={<span className="muted small">Click a line</span>}>
      {!rows.length && <p className="muted">No log lines in this ticket.</p>}
      <ol className="explain-list">
        {rows.slice(0, 80).map((r, i) => (
          <li key={i}>
            <button className={`explain-row ${sel === r.raw ? "on" : ""}`} onClick={() => go(r.raw)} data-testid={`ai-explain-line-${i}`}>
              {r.ts && <span className="mono small muted">{fmtTime(r.ts)}</span>}
              <code className="mono brk">{r.raw}</code>
              {explains[r.raw] && <MessageSquareText size={13} className="explained" aria-label="Explained" />}
            </button>
            {sel === r.raw && (
              <div className="explain-out" data-testid="ai-explain-output">
                {err && !explains[r.raw] ? <ErrBox err={err} /> : <p className="msg-t">{explains[r.raw] || (busy ? "Explaining…" : "")}</p>}
              </div>
            )}
          </li>
        ))}
      </ol>
    </Panel>
  );
}


/** Shrinks a screenshot in the browser so it fits the upload limit and uploads fast. */
async function toDataUrl(file) {
  const url = URL.createObjectURL(file);
  try {
    const img = await new Promise((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = () => rej(new Error("That file isn't an image the browser can read.")); i.src = url; });
    let max = 2000;
    for (;;) {
      const s = Math.min(1, max / Math.max(img.naturalWidth, img.naturalHeight));
      const c = document.createElement("canvas");
      c.width = Math.round(img.naturalWidth * s); c.height = Math.round(img.naturalHeight * s);
      const g = c.getContext("2d");
      g.fillStyle = "#fff"; g.fillRect(0, 0, c.width, c.height);
      g.drawImage(img, 0, 0, c.width, c.height);
      const out = c.toDataURL("image/jpeg", 0.9);
      if (out.length < 1_800_000 || max <= 800) return out;
      max = Math.round(max * 0.75);
    }
  } finally { URL.revokeObjectURL(url); }
}

function Screenshot({ app, pasted }) {
  const { entry, aiConfig, setForm, setAiPaste } = app;
  const [img, setImg] = useState(null);
  const [note, setNote] = useState("");
  const [out, setOut] = useState(null);
  const [drag, setDrag] = useState(false);
  const { busy, err, run, stop } = useAiRun();
  const fileRef = useRef();
  const take = async (file) => {
    if (!file) return;
    if (!/^image\/(png|jpeg|webp|gif|bmp)$/.test(file.type)) { toast.error("Use a PNG, JPEG or WebP screenshot."); return; }
    try { setImg(await toDataUrl(file)); setOut(null); } catch (e) { toast.error(e.message); }
  };
  // Paste a screenshot straight from the clipboard (Win+Shift+S, then Ctrl+V).
  useEffect(() => {
    const onPaste = (e) => {
      const f = [...(e.clipboardData?.items || [])].find((i) => i.type.startsWith("image/"))?.getAsFile();
      if (f) { e.preventDefault(); take(f); }
    };
    window.addEventListener("paste", onPaste);
    return () => window.removeEventListener("paste", onPaste);
  });
  const read = async () => {
    const r = await run((signal) => aiReadScreenshot(img, note, pasted ? null : entry?.id, signal));
    if (r) setOut(r);
  };
  const append = (cur, add) => (cur?.trim() ? `${cur.replace(/\s+$/, "")}\n${add}` : add);
  const addTo = (field) => {
    if (!out?.logText) return;
    if (pasted) {
      const k = field === "rawLogs" ? "logs" : "findings";
      setAiPaste((p) => ({ [k]: append(p[k], out.logText) }));
      toast.success(`Added to the pasted ${field === "rawLogs" ? "logs" : "notes"}.`);
      return;
    }
    setForm((f) => ({ ...f, [field]: append(f[field], out.logText) }));
    toast.success(`Added to ${field === "rawLogs" ? "Raw logs" : "Analyst findings"}. Press Generate on the Assessment tab to save it.`);
  };
  return (
    <Panel title="Read a screenshot" testid="ai-screenshot-panel" right={<span className="muted small">Logs, SIEM results, EDR alerts</span>}>
      {!aiConfig.local && <p className="review small" data-testid="ai-screenshot-cloud-warning"><AlertTriangle size={13} /> Screenshots can't be redacted. With {aiConfig.provider} the image leaves this server as it is, so crop out client names and users first.</p>}
      {!img ? (
        <div className={`dropzone ${drag ? "on" : ""}`} onClick={() => fileRef.current?.click()} role="button" tabIndex={0}
          onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && fileRef.current?.click()}
          onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
          onDrop={(e) => { e.preventDefault(); setDrag(false); take(e.dataTransfer.files?.[0]); }} data-testid="ai-screenshot-drop">
          <ImageUp size={22} />
          <b>Upload, drop or paste a screenshot</b>
          <span className="muted small">PNG, JPEG or WebP · paste with Ctrl+V after Win+Shift+S</span>
        </div>
      ) : (
        <div className="shot-prev">
          <img src={img} alt="Screenshot to read" data-testid="ai-screenshot-preview" />
          <button className="x" onClick={() => { setImg(null); setOut(null); }} aria-label="Remove screenshot" disabled={busy}><X size={14} /></button>
        </div>
      )}
      <input ref={fileRef} type="file" accept="image/png,image/jpeg,image/webp" hidden onChange={(e) => { take(e.target.files?.[0]); e.target.value = ""; }} data-testid="ai-screenshot-file" />
      {img && (
        <>
          <input className="input" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Optional note, e.g. “Sentinel results for the Exchange anomalies”" data-testid="ai-screenshot-note" />
          <div className="btn-row">
            {busy ? <button className="btn" onClick={stop} data-testid="ai-screenshot-stop"><Square size={13} /> Stop</button>
              : <button className="btn btn-primary" onClick={read} data-testid="ai-screenshot-read"><Sparkles size={13} /> {out ? "Read again" : "Read and analyze"}</button>}
            {busy && <span className="muted small"><Loader2 size={12} className="spin" /> {aiConfig.local ? "Reading on the local model. This can take a minute or two…" : "Reading the screenshot…"}</span>}
          </div>
        </>
      )}
      <ErrBox err={err} testid="ai-screenshot-error" />
      {out && (
        <div className="stack" data-testid="ai-screenshot-result">
          <p className="review small"><AlertTriangle size={13} /> Read by AI – check the text against the screenshot before you use it.</p>
          <div>
            <div className="field-l">Transcribed text</div>
            {out.logText ? <CopyBlock text={out.logText} testid="ai-screenshot-text" maxH={280} /> : <p className="muted small">No log text found in the screenshot.</p>}
          </div>
          {out.logText && (
            <div className="btn-row">
              <button className="btn btn-sm" onClick={() => addTo("rawLogs")} data-testid="ai-screenshot-to-logs">{pasted ? "Add to pasted logs" : "Add to Raw logs"}</button>
              <button className="btn btn-sm" onClick={() => addTo("findings")} data-testid="ai-screenshot-to-findings">{pasted ? "Add to notes" : "Add to Analyst findings"}</button>
            </div>
          )}
          <div>
            <div className="field-l">Analysis</div>
            <p className="msg-t" data-testid="ai-screenshot-analysis">{cleanAi(out.analysis) || "No analysis returned."}</p>
          </div>
        </div>
      )}
    </Panel>
  );
}

/** Alert name + logs pasted straight into the AI tab, without creating a ticket. */
function PasteLogs({ app }) {
  const { aiPaste: p, setAiPaste, aiConfig, setForm, setTab, user } = app;
  const { busy, err, run, stop } = useAiRun();
  const lines = p.logs.split("\n").filter((l) => l.trim()).length;
  const draft = async () => {
    if (!p.logs.trim() && !p.findings.trim()) { toast.error("Paste the logs first."); return; }
    const out = await run((signal) => aiDraftPasted({ alertName: p.alertName, rawLogs: p.logs, findings: p.findings }, signal));
    if (out) setAiPaste({ draft: out.text });
  };
  const toAssessment = () => {
    setForm((f) => ({ ...f, alertName: p.alertName || f.alertName, rawLogs: p.logs, findings: p.findings || f.findings, analyst: f.analyst || user?.displayName || "" }));
    setTab("assessment");
    toast.success("Copied to the Assessment form. Add the client and ticket ID, then press Generate to save it as a ticket.");
  };
  const clear = () => setAiPaste({ alertName: "", logs: "", findings: "", draft: "", chat: [] });
  return (
    <Panel title="Paste logs" testid="ai-paste-panel" right={<span className="muted small">No ticket needed · not saved</span>}>
      <div className="paste-form">
        <label className="field"><span className="field-l">Alert name</span>
          <input className="input" value={p.alertName} onChange={(e) => setAiPaste({ alertName: e.target.value })} placeholder="e.g. Data Ingestion Anomaly - Z-Score Detection" data-testid="ai-paste-alert" />
        </label>
        <label className="field">
          <span className="paste-meta"><span className="field-l">Logs</span>{lines > 0 && <span className="muted small mono">{lines} line{lines === 1 ? "" : "s"}{aiConfig.maxLogLines && lines > aiConfig.maxLogLines ? ` · the ${aiConfig.maxLogLines} most relevant are sent` : ""}</span>}</span>
          <textarea className="input ta-logs" value={p.logs} onChange={(e) => setAiPaste({ logs: e.target.value })} spellCheck={false}
            placeholder="Paste raw logs, SIEM results or an alert's JSON here" data-testid="ai-paste-logs" />
        </label>
        <label className="field"><span className="field-l">Findings, query results and queries used (optional)</span>
          <textarea className="input ta-notes" value={p.findings} onChange={(e) => setAiPaste({ findings: e.target.value })}
            placeholder="What you checked, query results, and the KQL/SPL you ran. Queries listed under Query Used come only from here or the logs." data-testid="ai-paste-findings" />
        </label>
        <div className="btn-row">
          {busy ? <button className="btn" onClick={stop} data-testid="ai-paste-stop"><Square size={13} /> Stop</button>
            : <button className="btn btn-primary" onClick={draft} data-testid="ai-paste-draft"><Sparkles size={13} /> {p.draft ? "Redraft report" : "Draft report"}</button>}
          <button className="btn" onClick={toAssessment} disabled={busy || !p.logs.trim()} title="Open these logs on the Assessment tab to save them as a ticket" data-testid="ai-paste-to-assessment"><ArrowRightToLine size={13} /> Copy to Assessment</button>
          <button className="btn btn-ghost" onClick={clear} disabled={busy || (!p.logs && !p.alertName && !p.findings && !p.draft)} data-testid="ai-paste-clear"><Eraser size={13} /> Clear</button>
          {busy && <span className="muted small"><Loader2 size={12} className="spin" /> {aiConfig.local ? "Drafting on the local model. This can take a few minutes on a laptop…" : "Drafting and checking the answer…"}</span>}
        </div>
      </div>
      <ErrBox err={err} testid="ai-paste-error" />
      {p.draft && (
        <>
          <p className="review small" data-testid="ai-paste-review-note"><AlertTriangle size={13} /> Drafted by AI – review before use. Check every number, IP and the verdict against the logs.</p>
          <CopyBlock text={p.draft} testid="ai-paste-draft-text" maxH={560} />
        </>
      )}
    </Panel>
  );
}

export default function AiAssistant({ app }) {
  const { entry, aiConfig, isAdmin, aiPaste, setAiPaste } = app;
  if (!aiConfig) return <Panel title="AI Assistant"><p className="muted">Loading…</p></Panel>;
  if (!aiConfig.ai) {
    return (
      <Panel title="AI Assistant" testid="ai-off-panel">
        <p>AI is turned off on this server.</p>
        <p className="muted small">{isAdmin ? "To turn it on, set AI_PROVIDER=ollama (local, free), gemini or anthropic in the server's .env, then restart the app." : "Ask an admin to enable it."}</p>
      </Panel>
    );
  }
  // Paste mode when chosen, or when there's no ticket to work on.
  const mode = !entry ? "paste" : aiPaste.mode || "ticket";
  const pasted = mode === "paste";
  return (
    <div className="stack" data-testid="ai-tab">
      <div className="toolbar">
        <div className="seg" role="tablist" aria-label="What the AI works on">
          <button role="tab" aria-selected={!pasted} className={!pasted ? "on" : ""} disabled={!entry} onClick={() => setAiPaste({ mode: "ticket" })}
            title={entry ? "" : "Generate or load a ticket on the Assessment tab first"} data-testid="ai-mode-ticket">
            <FileText size={13} /> {entry ? `Ticket ${entry.form.ticketId}` : "Current ticket"}
          </button>
          <button role="tab" aria-selected={pasted} className={pasted ? "on" : ""} onClick={() => setAiPaste({ mode: "paste" })} data-testid="ai-mode-paste">
            <ClipboardPaste size={13} /> Paste logs
          </button>
        </div>
        <span className="small">Model: <b className="mono">{aiConfig.model}</b></span>
        <span className="small"><ShieldCheck size={13} /> {aiConfig.local ? "Local model: nothing leaves this server. Names, hosts and internal IPs are still replaced with tokens." : "The server replaces the client name, usernames, hostnames and internal IPs with tokens before anything is sent, and puts them back in the answer."}</span>
      </div>
      {pasted ? (
        <div className="grid2">
          <div className="col"><PasteLogs app={app} /></div>
          <div className="col"><Chat app={app} pasted /><Screenshot app={app} pasted /></div>
        </div>
      ) : (
        <div className="grid2">
          <div className="col"><Draft app={app} /><Explain app={app} /></div>
          <div className="col"><Chat app={app} /><Screenshot app={app} /></div>
        </div>
      )}
    </div>
  );
}
