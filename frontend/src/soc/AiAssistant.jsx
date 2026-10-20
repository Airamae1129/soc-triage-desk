import { useEffect, useRef, useState } from "react";
import { Send, Sparkles, Square, Trash2, AlertTriangle, MessageSquareText } from "lucide-react";
import { Panel, CopyBlock } from "./ui";
import { streamAi, buildAiContext, cleanAi } from "./api";
import { fmtTime, maskText } from "./util";
import { reportChecks } from "./drafts";

const QUICK = ["Summarize this ticket in 3 bullets", "Is this a true positive? What evidence supports it?", "What should I check next?", "Draft a short message to the client asking to confirm this activity"];

function useAiRun() {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const ctl = useRef();
  const run = async (body, onDelta) => {
    ctl.current?.abort();
    ctl.current = new AbortController();
    setBusy(true); setErr("");
    try { return await streamAi(body, onDelta, ctl.current.signal); }
    catch (e) { if (e.name !== "AbortError") setErr(e.message || "AI request failed"); return null; }
    finally { setBusy(false); }
  };
  const stop = () => { ctl.current?.abort(); setBusy(false); };
  useEffect(() => () => ctl.current?.abort(), []);
  return { busy, err, run, stop };
}

function Chat({ app, ctx, mask }) {
  const { aiT, setAiT } = app;
  const [input, setInput] = useState("");
  const [live, setLive] = useState("");
  const { busy, err, run, stop } = useAiRun();
  const endRef = useRef();
  const msgs = aiT.chat || [];
  useEffect(() => { endRef.current?.scrollIntoView?.({ block: "nearest" }); }, [msgs.length, live]);
  const send = async (text) => {
    const q = text.trim();
    if (!q || busy) return;
    const next = [...msgs, { role: "user", content: q }];
    setAiT({ chat: next });
    setInput(""); setLive("");
    const out = await run({ mode: "chat", context: ctx(), messages: next }, setLive);
    if (out) setAiT({ chat: [...next, { role: "assistant", content: out }] });
    setLive("");
  };
  return (
    <Panel title="Ask about this ticket" testid="ai-chat-panel" right={msgs.length > 0 && <button className="btn btn-xs" onClick={() => setAiT({ chat: [] })} data-testid="ai-chat-clear-btn"><Trash2 size={12} /> Clear chat</button>}>
      <div className="chat" data-testid="ai-chat-log">
        {!msgs.length && !live && <p className="muted small">The assistant sees this ticket's logs, findings, enrichment, OSINT results and the rule-based report{mask ? " (masked)" : ""}.</p>}
        {msgs.map((m, i) => <div key={i} className={`msg msg-${m.role}`} data-testid={`ai-msg-${i}`}><span className="msg-who">{m.role === "user" ? "You" : "AI"}</span><div className="msg-t">{cleanAi(m.content)}</div></div>)}
        {(busy || live) && <div className="msg msg-assistant" data-testid="ai-msg-live"><span className="msg-who">AI</span><div className="msg-t">{cleanAi(live) || <span className="muted">Thinking…</span>}</div></div>}
        <div ref={endRef} />
      </div>
      {err && <p className="err small" data-testid="ai-chat-error">{err}</p>}
      <div className="quick">{QUICK.map((q, i) => <button key={q} className="btn btn-xs btn-ghost" disabled={busy} onClick={() => send(q)} data-testid={`ai-quick-${i}`}>{q}</button>)}</div>
      <form className="inline-form" onSubmit={(e) => { e.preventDefault(); send(input); }}>
        <textarea className="input ta-chat" rows={2} value={input} onChange={(e) => setInput(e.target.value)} placeholder="Ask a question about this ticket"
          onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(input); } }} data-testid="ai-chat-input" />
        {busy ? <button type="button" className="btn" onClick={stop} data-testid="ai-stop-btn"><Square size={13} /> Stop</button>
          : <button className="btn btn-primary" disabled={!input.trim()} data-testid="ai-send-btn"><Send size={13} /> Send</button>}
      </form>
    </Panel>
  );
}

function Draft({ app, ctx }) {
  const { aiT, setAiT, entry, an, aiRequest, setAiRequest } = app;
  const [live, setLive] = useState("");
  const { busy, err, run, stop } = useAiRun();
  const go = async () => {
    setLive("");
    const out = await run({ mode: "draft", context: ctx() }, setLive);
    if (out) setAiT({ draft: cleanAi(out).trim(), draftAt: new Date().toISOString() });
    setLive("");
  };
  useEffect(() => {
    if (aiRequest?.mode === "draft") { setAiRequest(null); go(); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [aiRequest]);
  const text = busy ? cleanAi(live) : aiT.draft || "";
  const checks = !busy && text ? reportChecks({ ...an, warnings: [] }, entry.form).filter((c) => !/Alert ID|Analytics rule/.test(c)) : [];
  const verdict = (text.match(/^Verdict:.*$/m) || [""])[0];
  const vCount = verdict ? verdict.replace(/^Verdict:\s*/, "").split(/(?<=[.!?])\s+(?=[A-Z])/).filter(Boolean).length : 0;
  return (
    <Panel title="Draft with AI" testid="ai-draft-panel" right={<span className="muted small">Assessment report format</span>}>
      <div className="btn-row">
        {busy ? <button className="btn" onClick={stop} data-testid="ai-draft-stop-btn"><Square size={13} /> Stop</button>
          : <button className="btn btn-primary" onClick={go} data-testid="ai-draft-btn"><Sparkles size={13} /> {aiT.draft ? "Redraft with AI" : "Draft with AI"}</button>}
        {aiT.draftAt && !busy && <span className="muted small mono">Drafted {fmtTime(aiT.draftAt)}</span>}
      </div>
      {err && <p className="err small" data-testid="ai-draft-error">{err}</p>}
      {(text || busy) && (
        <>
          <p className="review small" data-testid="ai-review-note"><AlertTriangle size={13} /> AI draft. Check every number, IP and the verdict against the logs before you use it.</p>
          {vCount > 2 && <p className="err small" data-testid="ai-verdict-warning">Verdict has {vCount} sentences (max 2). Trim it before use.</p>}
          {checks.length > 0 && <ul className="warn-list">{checks.map((c) => <li key={c}><AlertTriangle size={13} /> {c}</li>)}</ul>}
          <CopyBlock text={text || "…"} testid="ai-draft-text" maxH={560} />
        </>
      )}
    </Panel>
  );
}

function Explain({ app, mask }) {
  const { an, aiT, setAiT, aiRequest, setAiRequest } = app;
  const [sel, setSel] = useState(null);
  const [live, setLive] = useState("");
  const { busy, err, run } = useAiRun();
  const explains = aiT.explains || {};
  const go = async (line) => {
    setSel(line); setLive("");
    if (explains[line]) return;
    const ctx = buildAiContext(app.entry, an, app.osintT.values, mask).text.slice(0, 12000);
    const l = mask ? maskText(line, { client: app.entry.form.client, users: an.users, hosts: an.hosts, ips: an.ips.internal }).text : line;
    const out = await run({ mode: "explain", context: ctx, line: l }, setLive);
    if (out) setAiT({ explains: { ...explains, [line]: cleanAi(out).trim() } });
    setLive("");
  };
  useEffect(() => {
    if (aiRequest?.mode === "explain") { const l = aiRequest.line; setAiRequest(null); go(l); }
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
                {err ? <p className="err small">{err}</p> : <p className="msg-t">{explains[r.raw] || cleanAi(live) || (busy ? "Explaining…" : "")}</p>}
              </div>
            )}
          </li>
        ))}
      </ol>
    </Panel>
  );
}

export default function AiAssistant({ app }) {
  const [mask, setMask] = useState(false);
  const { entry, an, osintT, aiConfig } = app;
  if (!entry) return <Panel title="AI Assistant"><p className="muted">Generate or load a ticket first.</p></Panel>;
  const ctx = () => buildAiContext(entry, an, osintT.values, mask).text;
  const preview = mask ? buildAiContext(entry, an, osintT.values, true).items : [];
  return (
    <div className="stack" data-testid="ai-tab">
      <div className="toolbar">
        <span className="small">Model: <b className="mono">{aiConfig?.model || "claude-sonnet-4-5"}</b></span>
        {aiConfig && !aiConfig.ai && <span className="err small">AI is not configured on the server.</span>}
        <label className="check small"><input type="checkbox" checked={mask} onChange={(e) => setMask(e.target.checked)} data-testid="ai-mask-toggle" /> Mask client name, users, hosts and internal IPs before sending</label>
        {mask && <span className="mask-preview small" data-testid="ai-mask-preview">{preview.length ? preview.map((i) => <span key={i.token} className="chip mono">{i.val} → {i.token}</span>) : "Nothing to mask"}</span>}
        <span className="muted small">Sent to the AI only when you click.</span>
      </div>
      <div className="grid2">
        <div className="col"><Draft app={app} ctx={ctx} /><Explain app={app} mask={mask} /></div>
        <div className="col"><Chat app={app} ctx={ctx} mask={mask} /></div>
      </div>
    </div>
  );
}
