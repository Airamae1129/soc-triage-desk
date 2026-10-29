import { useCallback, useEffect, useMemo, useState } from "react";
import "@/App.css";
import { Sun, Moon, Monitor, LogOut, Shield, WifiOff, Loader2 } from "lucide-react";
import { Toaster, toast } from "sonner";
import { load, save, copyText, shiftOf, getDefang, defangText } from "@/soc/util";
import { analyze, buildChecklist } from "@/soc/engine";
import { buildReport } from "@/soc/drafts";
import { EMPTY_FORM, SAMPLE_A, SAMPLE_B, snapshot } from "@/soc/samples";
import { ContextStrip } from "@/soc/ui";
import Assessment from "@/soc/Assessment";
import Investigation from "@/soc/Investigation";
import Osint from "@/soc/Osint";
import Notes from "@/soc/Notes";
import Playbook from "@/soc/Playbook";
import Notables from "@/soc/Notables";
import Dashboard from "@/soc/Dashboard";
import AiAssistant from "@/soc/AiAssistant";
import Login from "@/soc/Login";
import Admin from "@/soc/Admin";
import * as API from "@/soc/api";

const TABS = [
  { k: "assessment", label: "Assessment", C: Assessment },
  { k: "investigation", label: "Investigation", C: Investigation },
  { k: "ai", label: "AI Assistant", C: AiAssistant },
  { k: "osint", label: "OSINT", C: Osint },
  { k: "notes", label: "SOC Notes", C: Notes },
  { k: "playbook", label: "Playbook", C: Playbook },
  { k: "notables", label: "Notables", C: Notables },
  { k: "dashboard", label: "Dashboard", C: Dashboard },
];

/** localStorage only for UI conveniences (theme, last tab/ticket, AI chat scratch). */
function useLocal(key, init) {
  const [v, setV] = useState(() => load(key, init));
  useEffect(() => save(key, v), [key, v]);
  return [v, setV];
}

function Logo() {
  return (
    <svg width="30" height="30" viewBox="0 0 32 32" aria-hidden="true" className="logo">
      <path d="M16 2.5 4.5 6.8v8.4c0 7.2 4.9 12.4 11.5 14.3 6.6-1.9 11.5-7.1 11.5-14.3V6.8L16 2.5Z" fill="none" stroke="currentColor" strokeWidth="2" />
      <path d="M10.5 16.2l3.6 3.6 7.4-7.6" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="square" />
    </svg>
  );
}

const fail = (e) => toast.error(e?.message || "Something went wrong.");

export default function App() {
  const [theme, setTheme] = useLocal("theme", "system");
  const [tab, setTab] = useLocal("tab", "assessment");
  const [currentId, setCurrentId] = useLocal("currentId", null);
  const [ai, setAi] = useLocal("ai", {});
  const [user, setUser] = useState(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [offline, setOffline] = useState(false);
  const [loading, setLoading] = useState(false);
  const [adminOpen, setAdminOpen] = useState(false);

  const [history, setHistory] = useState([]);
  const [playbooks, setPlaybooks] = useState({});
  const [ticketNotes, setTicketNotes] = useState([]);
  const [checkState, setCheckState] = useState({});
  const [asOsint, setAsOsint] = useState({});
  const [ws, setWs] = useState({ items: [], shots: [], screenshotsToday: 0 });
  const [aiConfig, setAiConfig] = useState(null);
  const [aiRequest, setAiRequest] = useState(null);
  // AI tab "Paste logs" mode. Memory only: pasted logs are never written to browser storage.
  const [aiPaste, setAiPasteState] = useState({ mode: null, alertName: "", logs: "", findings: "", draft: "", chat: [] });
  const setAiPaste = useCallback((patch) => setAiPasteState((p) => ({ ...p, ...(typeof patch === "function" ? patch(p) : patch) })), []);

  useEffect(() => {
    if (theme === "system") delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = theme;
  }, [theme]);

  // ---- session ----
  useEffect(() => {
    const offs = [API.onApiEvent("offline", setOffline), API.onApiEvent("unauthorized", () => { setUser(null); toast.error("Your session ended. Please sign in again."); })];
    API.getMe().then((r) => setUser(r.user)).catch(() => setUser(null)).finally(() => setAuthChecked(true));
    return () => offs.forEach((f) => f());
  }, []);

  // ---- shared data from the server ----
  const reloadHistory = useCallback(() => API.listAssessments().then((r) => setHistory(r.assessments)), []);
  const reloadWs = useCallback(() => API.getWorkspace().then(setWs), []);
  useEffect(() => {
    if (!user) return;
    setLoading(true);
    Promise.all([
      reloadHistory(),
      API.listPlaybooks().then((r) => setPlaybooks(Object.fromEntries(r.playbooks.map((p) => [p.name, p])))),
      reloadWs(),
      Promise.all([API.getProviders(), API.aiStatus()]).then(([p, a]) =>
        setAiConfig({ ai: a.enabled, model: a.model, provider: a.provider, local: !!a.local, maxLogLines: a.maxLogLines, screenshot: p.screenshot, cacheHours: p.cacheHours, providers: p.providers, osint: Object.fromEntries(p.providers.map((x) => [x.name, x.configured])) })),
    ]).catch(fail).finally(() => setLoading(false));
  }, [user, reloadHistory, reloadWs]);
  // Pick up teammates' changes when the window regains focus.
  useEffect(() => {
    if (!user) return;
    const f = () => { reloadHistory().catch(() => {}); };
    window.addEventListener("focus", f);
    return () => window.removeEventListener("focus", f);
  }, [user, reloadHistory]);

  const entry = history.find((h) => h.id === currentId) || null;
  const [form, setForm] = useState(EMPTY_FORM);
  useEffect(() => { if (entry) setForm(entry.form); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [entry?.id]);
  useEffect(() => { if (user && !entry && !form.analyst) setForm((f) => ({ ...f, analyst: user.displayName })); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [user]);

  // Per-ticket data
  useEffect(() => {
    setTicketNotes([]); setCheckState({}); setAsOsint({});
    if (!user || !entry) return;
    API.getNotes(entry.id).then((r) => setTicketNotes(r.notes)).catch(fail);
    API.getChecklist(entry.id).then((r) => setCheckState(r.checklist)).catch(fail);
    API.getAssessmentOsint(entry.id).then((r) => setAsOsint(r.values)).catch(() => {});
  }, [user, entry?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const an = useMemo(() => analyze(entry?.form || EMPTY_FORM), [entry]);
  const tk = entry?.id ?? "_none";
  const pb = playbooks[Object.keys(playbooks).find((n) => n.toLowerCase() === (entry?.form.client || "").toLowerCase())];
  const pbRow = pb?.matrix.find((r) => r.sev === an.severity);
  const items = useMemo(() => buildChecklist(an), [an]);
  const checklistInfo = useMemo(() => ({ items, state: checkState }), [items, checkState]);

  // OSINT verdicts by indicator: the analyst's workspace, overridden by ones attached to this ticket.
  const osintValues = useMemo(() => {
    const v = {};
    for (const i of ws.items) if (i.verdict !== "Not checked" || i.note) v[i.value] = { verdict: i.verdict, note: i.note || i.lookup?.summary || "" };
    return { ...v, ...asOsint };
  }, [ws.items, asOsint]);

  const replaceEntry = (e) => setHistory((hs) => [e, ...hs.filter((h) => h.id !== e.id)]);

  const generate = async () => {
    if (!form.rawLogs.trim()) { toast.error("Paste raw logs before generating an assessment."); return; }
    if (!form.client.trim()) { toast.error("Enter the client name."); return; }
    const f = { ...form, ticketId: form.ticketId.trim() || `TKT-${Date.now().toString().slice(-6)}`, analyst: form.analyst || user.displayName };
    const a = analyze(f);
    try {
      const { assessment } = await API.saveAssessment(f, { ...snapshot(f), confidence: a.confidence });
      replaceEntry(assessment);
      setCurrentId(assessment.id);
      setForm(assessment.form);
      toast.success(`Assessment saved for ${assessment.form.ticketId}`);
    } catch (e) { fail(e); }
  };
  const loadEntry = (id) => { const h = history.find((x) => x.id === id); if (h) { setCurrentId(id); setForm(h.form); } };
  const loadSample = (k) => setForm({ ...(k === "A" ? SAMPLE_A : SAMPLE_B) });
  const clearForm = () => setForm({ ...EMPTY_FORM, analyst: user?.displayName || "" });

  const toggleEscalated = async () => {
    if (!entry) return;
    try {
      const r = entry.escalatedAt
        ? await API.unescalate(entry.id)
        : await API.escalate(entry.id, `Escalated to ${pbRow?.contact || "client"}${pbRow?.email ? ` (${pbRow.email})` : ""} via ${pbRow?.channel || "email"}.`);
      replaceEntry(r.assessment);
      API.getNotes(entry.id).then((n) => setTicketNotes(n.notes)).catch(() => {});
    } catch (e) { fail(e); }
  };
  const setNotableStatus = async (id, status) => {
    try { replaceEntry((await API.setStatus(id, status)).assessment); } catch (e) { fail(e); }
  };
  const addNote = async (n) => {
    if (!entry) { toast.error("Generate or load a ticket first."); return; }
    try { const r = await API.addNote(entry.id, { type: n.type, text: n.text, time: n.time }); setTicketNotes((ns) => [...ns, r.note]); }
    catch (e) { fail(e); }
  };
  const delNote = async (id) => {
    try { await API.deleteNote(id); setTicketNotes((ns) => ns.filter((n) => n.id !== id)); } catch (e) { fail(e); }
  };
  const toggleCheck = async (it) => {
    if (!entry) return;
    const done = !checkState[it];
    setCheckState((s) => ({ ...s, [it]: done }));
    try { setCheckState((await API.setChecklistItem(entry.id, it, done)).checklist); }
    catch (e) { setCheckState((s) => ({ ...s, [it]: !done })); fail(e); }
  };
  const savePlaybook = async (name, p) => {
    const body = { industry: p.industry || "", reviewed: p.reviewed || "", matrix: p.matrix || [], contacts: p.contacts || [], containment: p.containment || "", benign: p.benign || [], procedures: p.procedures || [] };
    const r = await API.savePlaybook(name, body);
    setPlaybooks((ps) => ({ ...ps, [r.playbook.name]: r.playbook }));
    toast.success(`Playbook saved for ${r.playbook.name}`);
    return r.playbook;
  };
  const draftWithAi = async (signal) => {
    if (!entry) return null;
    const r = await API.aiDraftReport(entry.id, signal);
    replaceEntry({ ...entry, aiDraft: r.text, aiGenerated: true });
    return r;
  };
  /** Fill ASN / Owner / Location / IP type / Reputation from OSINT for the main external IP. */
  const fillFromOsint = async () => {
    const a = analyze(form);
    const ip = a.primaryIp || a.ips.external[0];
    if (!ip) { toast.error("No external IP in the logs to look up."); return; }
    const t = toast.loading(`Looking up ${ip}…`);
    try {
      const r = await API.osintLookup(ip, { type: "ip" });
      const fill = r.autofill || {};
      const keys = ["asn", "owner", "location", "ipType", "reputation"].filter((k) => fill[k]);
      if (!keys.length) { toast.error(`No OSINT data for ${ip} (${r.results.map((x) => `${x.label}: ${x.status}`).join(", ")}).`, { id: t }); return; }
      setForm((f) => ({ ...f, ...Object.fromEntries(keys.map((k) => [k, fill[k]])) }));
      reloadWs().catch(() => {});
      toast.success(`Filled ${keys.join(", ")} from OSINT for ${ip}. Review, then Generate to save.`, { id: t });
    } catch (e) { toast.error(e.message, { id: t }); }
  };
  const doLogout = async () => {
    try { await API.logout(); } catch { /* ignore */ }
    setUser(null); setHistory([]); setPlaybooks({}); setWs({ items: [], shots: [], screenshotsToday: 0 });
  };
  const exportAll = () => ({ app: "soc-triage-desk", version: 2, exportedAt: new Date().toISOString(), exportedBy: user?.username, history, playbooks, osint: ws });

  const app = {
    user, isAdmin: user?.role === "admin",
    entry, an, form, setForm, generate, loadSample, clearForm, history, loadEntry, toggleEscalated, setNotableStatus,
    playbooks, savePlaybook, pb, pbRow,
    ws, setWs, reloadWs, osintValues, attachOsint: (indicator, verdict, note) => entry && API.attachOsint(entry.id, indicator, verdict, note).then(() => setAsOsint((o) => ({ ...o, [indicator]: { verdict, note, manual: true } }))),
    aiT: ai[tk] || {}, setAiT: (patch) => setAi((a) => ({ ...a, [tk]: { ...(a[tk] || {}), ...patch } })),
    aiPaste, setAiPaste, aiRequest, setAiRequest, aiConfig, askAi: (req) => { setAiRequest(req); setTab("ai"); }, draftWithAi, fillFromOsint,
    ticketNotes, addNote, delNote, checklistInfo, toggleCheck, analyst: user?.displayName || "", setTab, exportAll,
    isSampleForm: [SAMPLE_A, SAMPLE_B].some((s) => s.ticketId === form.ticketId && s.rawLogs === form.rawLogs),
  };

  useEffect(() => {
    const onKey = (e) => {
      if (!user) return;
      const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName || "");
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter" && tab === "assessment") { e.preventDefault(); generate(); return; }
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === "C" || e.key === "c") && entry) {
        const t = buildReport(an, entry.form);
        e.preventDefault(); copyText(getDefang() ? defangText(t) : t).then(() => toast.success("Assessment report copied")); return;
      }
      if (!typing && !e.ctrlKey && !e.metaKey && !e.altKey && /^[1-8]$/.test(e.key)) setTab(TABS[+e.key - 1].k);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const ThemeIcon = theme === "light" ? Sun : theme === "dark" ? Moon : Monitor;
  const nextTheme = { system: "light", light: "dark", dark: "system" }[theme];
  const offlineBanner = offline && <div className="offline" role="alert" data-testid="offline-banner"><WifiOff size={14} /> Can't reach the server. Changes won't be saved until it's back.</div>;

  if (!authChecked) return <div className="boot"><Loader2 className="spin" size={20} /> Loading…</div>;
  if (!user) return (<>{offlineBanner}<Login onDone={setUser} offline={offline} Logo={Logo} /><Toaster position="bottom-right" theme={theme} /></>);

  const nowKey = shiftOf(new Date()).key;
  const counts = {
    assessment: history.length, investigation: checklistInfo.items.filter((i) => !checklistInfo.state[i]).length,
    ai: (ai[tk]?.chat || []).length, osint: ws.items.length,
    notes: ticketNotes.length, playbook: Object.keys(playbooks).length,
    notables: history.filter((h) => h.escalatedAt).length,
    dashboard: history.filter((h) => shiftOf(h.createdAt || h.savedAt).key === nowKey).length,
  };
  const Cur = (TABS.find((t) => t.k === tab) || TABS[0]).C;

  return (
    <div className="app" data-shift={nowKey}>
      <a href="#main" className="skip">Skip to content</a>
      {offlineBanner}
      <header className="top" data-testid="app-header">
        <div className="brand">
          <Logo />
          <div>
            <h1 className="title">SOC Triage Playbook</h1>
            <p className="subtitle">Assess alerts · investigate · document · hand over · <span className="credit">Created by Aira Mae Bugay</span></p>
          </div>
        </div>
        <div className="top-right">
          {loading && <span className="muted small"><Loader2 size={13} className="spin" /> Loading…</span>}
          <span className="user-menu" data-testid="user-menu">
            <span className="small"><b>{user.displayName}</b> <span className="muted">· {user.role}</span></span>
            {app.isAdmin && <button className="btn btn-sm" onClick={() => setAdminOpen(true)} data-testid="admin-btn"><Shield size={13} /> Admin</button>}
            <button className="btn btn-sm" onClick={doLogout} data-testid="logout-btn"><LogOut size={13} /> Log out</button>
          </span>
          <button className="btn btn-sm icon-btn" onClick={() => setTheme(nextTheme)} aria-label={`Theme: ${theme}. Switch to ${nextTheme}`} title={`Theme: ${theme}`} data-testid="theme-toggle-btn"><ThemeIcon size={15} /></button>
        </div>
      </header>
      <nav className="tabs" role="tablist" aria-label="Sections" data-testid="tab-bar">
        {TABS.map((t, i) => (
          <button key={t.k} role="tab" aria-selected={tab === t.k} className={`tab ${tab === t.k ? "on" : ""}`} onClick={() => setTab(t.k)} data-testid={`tab-${t.k}`} title={`Shortcut: ${i + 1}`}>
            {t.label} <span className="count mono" data-testid={`tab-count-${t.k}`}>{counts[t.k]}</span>
          </button>
        ))}
      </nav>
      <main id="main" className="main">
        {tab !== "assessment" && tab !== "osint" && <ContextStrip app={app} />}
        <Cur app={app} key={tab === "playbook" ? `pb-${tk}` : tab} />
      </main>
      <footer className="foot muted small">All times UTC+08:00 (Asia/Manila) · Data is saved on the SOC Triage Playbook server; OSINT and AI calls go out only when you click · Shortcuts: 1–8 tabs, Ctrl+Enter generate, Ctrl+Shift+C copy report · SOC Triage Playbook, created by Aira Mae Bugay</footer>
      {app.isAdmin && <Admin open={adminOpen} onClose={() => setAdminOpen(false)} me={user} />}
      <Toaster position="bottom-right" theme={theme} />
    </div>
  );
}
