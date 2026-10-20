import { useCallback, useEffect, useMemo, useState } from "react";
import "@/App.css";
import { Sun, Moon, Monitor } from "lucide-react";
import { Toaster, toast } from "sonner";
import { load, save, uid, copyText, shiftOf } from "@/soc/util";
import { analyze, buildChecklist } from "@/soc/engine";
import { buildReport } from "@/soc/drafts";
import { EMPTY_FORM, SAMPLE_A, SAMPLE_B, seedData, snapshot } from "@/soc/samples";
import { ContextStrip } from "@/soc/ui";
import Assessment from "@/soc/Assessment";
import Investigation from "@/soc/Investigation";
import Osint from "@/soc/Osint";
import Notes from "@/soc/Notes";
import Playbook from "@/soc/Playbook";
import Notables from "@/soc/Notables";
import Dashboard from "@/soc/Dashboard";
import AiAssistant from "@/soc/AiAssistant";
import { getConfig } from "@/soc/api";

const TABS = [
  { k: "assessment", label: "Assessment", C: Assessment },
  { k: "investigation", label: "Investigation", C: Investigation },
  { k: "osint", label: "OSINT", C: Osint },
  { k: "notes", label: "SOC Notes", C: Notes },
  { k: "playbook", label: "Playbook", C: Playbook },
  { k: "notables", label: "Notables", C: Notables },
  { k: "dashboard", label: "Dashboard", C: Dashboard },
  { k: "ai", label: "AI Assistant", C: AiAssistant },
];

const seed = load("seeded", false) ? null : seedData();
function usePersist(key, init) {
  const [v, setV] = useState(() => (seed && seed[key] !== undefined ? seed[key] : load(key, init)));
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

export default function App() {
  const [history, setHistory] = usePersist("history", []);
  const [currentId, setCurrentId] = usePersist("currentId", null);
  const [playbooks, setPlaybooks] = usePersist("playbooks", {});
  const [notes, setNotes] = usePersist("notes", {});
  const [osint, setOsint] = usePersist("osint", {});
  const [checklist, setChecklist] = usePersist("checklist", {});
  const [analyst, setAnalyst] = usePersist("analyst", "");
  const [theme, setTheme] = usePersist("theme", "system");
  const [ai, setAi] = usePersist("ai", {});
  const [tab, setTab] = useState("assessment");
  const [aiRequest, setAiRequest] = useState(null);
  const [aiConfig, setAiConfig] = useState(null);
  useEffect(() => { getConfig().then(setAiConfig).catch(() => setAiConfig({ ai: false, osint: {}, screenshot: false })); }, []);
  useEffect(() => { save("seeded", true); }, []);
  useEffect(() => {
    if (theme === "system") delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = theme;
  }, [theme]);

  const entry = history.find((h) => h.id === currentId) || null;
  const [form, setForm] = useState(() => entry?.form || { ...EMPTY_FORM, analyst });
  const an = useMemo(() => analyze(entry?.form || EMPTY_FORM), [entry]);
  const tk = entry?.id || "_none";
  const pb = playbooks[Object.keys(playbooks).find((n) => n.toLowerCase() === (entry?.form.client || "").toLowerCase())];
  const pbRow = pb?.matrix.find((r) => r.sev === an.severity);
  const osintT = useMemo(() => osint[tk] || { values: {}, extra: [] }, [osint, tk]);
  const ticketNotes = useMemo(() => notes[tk] || [], [notes, tk]);
  const items = useMemo(() => buildChecklist(an), [an]);
  const checklistInfo = useMemo(() => ({ items, state: checklist[tk] || {} }), [items, checklist, tk]);

  const updateEntry = useCallback((id, patch) => setHistory((hs) => hs.map((h) => (h.id === id ? { ...h, ...patch } : h))), [setHistory]);
  const loadEntry = (id) => { const h = history.find((x) => x.id === id); if (h) { setCurrentId(id); setForm(h.form); } };
  const addNote = (n) => setNotes((ns) => ({ ...ns, [tk]: [...(ns[tk] || []), { id: uid(), author: analyst || entry?.form.analyst || "", ...n }] }));

  const generate = () => {
    if (!form.rawLogs.trim()) { toast.error("Paste raw logs before generating an assessment."); return; }
    const f = { ...form, ticketId: form.ticketId.trim() || `TKT-${Date.now().toString().slice(-6)}`, analyst: form.analyst || analyst };
    const id = f.ticketId;
    const prev = history.find((h) => h.id === id);
    const e = { escalatedAt: null, notableStatus: "Awaiting client", ...prev, id, form: f, savedAt: new Date().toISOString(), createdAt: prev?.createdAt || prev?.savedAt || new Date().toISOString(), sample: !!prev?.sample && JSON.stringify(prev.form) === JSON.stringify(f), ...snapshot(f) };
    setHistory((hs) => [e, ...hs.filter((h) => h.id !== id)]);
    setCurrentId(id);
    setForm(f);
    toast.success(`Assessment generated for ${id}`);
  };
  const loadSample = (k) => setForm({ ...(k === "A" ? SAMPLE_A : SAMPLE_B) });
  const clearForm = () => setForm({ ...EMPTY_FORM, analyst });
  const toggleEscalated = () => {
    if (!entry) return;
    if (entry.escalatedAt) { updateEntry(entry.id, { escalatedAt: null }); setNotes((ns) => ({ ...ns, [tk]: (ns[tk] || []).filter((n) => n.auto !== entry.escalatedAt) })); return; }
    const at = new Date().toISOString();
    updateEntry(entry.id, { escalatedAt: at, notableStatus: "Awaiting client", statusLog: [...(entry.statusLog || []), { status: "Escalated", by: analyst || entry.form.analyst, at }] });
    addNote({ auto: at, type: "Client comms", time: at, text: `Escalated to ${pbRow?.contact || "client"}${pbRow?.email ? ` (${pbRow.email})` : ""} via ${pbRow?.channel || "email"}.` });
  };
  const toggleCheck = (it) => setChecklist((c) => ({ ...c, [tk]: { ...(c[tk] || {}), [it]: !(c[tk] || {})[it] } }));
  const exportAll = () => ({ app: "soc-triage-desk", version: 1, exportedAt: new Date().toISOString(), history, currentId, playbooks, notes, osint, checklist, analyst, ai });
  const importAll = (d) => {
    if (d.app !== "soc-triage-desk") throw new Error("bad");
    setHistory(d.history || []); setCurrentId(d.currentId || null); setPlaybooks(d.playbooks || {});
    setNotes(d.notes || {}); setOsint(d.osint || {}); setChecklist(d.checklist || {}); setAi(d.ai || {});
    const h = (d.history || []).find((x) => x.id === d.currentId);
    if (h) setForm(h.form);
  };

  const app = {
    entry, an, form, setForm, generate, loadSample, clearForm, history, loadEntry, updateEntry, toggleEscalated,
    playbooks, setPlaybooks, pb, pbRow, osintT, setOsintT: (v) => setOsint((o) => ({ ...o, [tk]: typeof v === "function" ? v(o[tk] || { values: {}, extra: [] }) : v })),
    aiT: ai[tk] || {}, setAiT: (patch) => setAi((a) => ({ ...a, [tk]: { ...(a[tk] || {}), ...patch } })),
    aiRequest, setAiRequest, aiConfig, askAi: (req) => { setAiRequest(req); setTab("ai"); },
    ticketNotes, addNote, delNote: (id) => setNotes((ns) => ({ ...ns, [tk]: (ns[tk] || []).filter((n) => n.id !== id) })),
    checklistInfo, toggleCheck, analyst, setTab, exportAll, importAll,
    isSampleForm: [SAMPLE_A, SAMPLE_B].some((s) => s.ticketId === form.ticketId && s.rawLogs === form.rawLogs),
  };

  useEffect(() => {
    const onKey = (e) => {
      const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName || "");
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter" && tab === "assessment") { e.preventDefault(); generate(); return; }
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === "C" || e.key === "c") && entry) {
        e.preventDefault(); copyText(buildReport(an, entry.form)).then(() => toast.success("Assessment report copied")); return;
      }
      if (!typing && !e.ctrlKey && !e.metaKey && !e.altKey && /^[1-8]$/.test(e.key)) setTab(TABS[+e.key - 1].k);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const nowKey = shiftOf(new Date()).key;
  const counts = {
    assessment: history.length, investigation: checklistInfo.items.filter((i) => !checklistInfo.state[i]).length,
    osint: an.extIocs.length + (osintT.extra || []).filter((x) => !an.extIocs.some((i) => i.value === x.value)).length,
    notes: ticketNotes.length, playbook: Object.keys(playbooks).length,
    notables: history.filter((h) => h.escalatedAt).length,
    dashboard: history.filter((h) => shiftOf(h.createdAt || h.savedAt).key === nowKey).length,
    ai: (ai[tk]?.chat || []).length,
  };
  const Cur = TABS.find((t) => t.k === tab).C;
  const ThemeIcon = theme === "light" ? Sun : theme === "dark" ? Moon : Monitor;
  const nextTheme = { system: "light", light: "dark", dark: "system" }[theme];

  return (
    <div className="app" data-shift={nowKey}>
      <a href="#main" className="skip">Skip to content</a>
      <header className="top" data-testid="app-header">
        <div className="brand">
          <Logo />
          <div>
            <h1 className="title">SOC Triage Desk</h1>
            <p className="subtitle">Assess alerts · investigate · document · hand over</p>
          </div>
        </div>
        <div className="top-right">
          <label className="who small"><span className="muted">Signed in as</span>
            <input className="input input-sm" value={analyst} onChange={(e) => setAnalyst(e.target.value)} placeholder="Analyst name" data-testid="analyst-identity-input" />
          </label>
          <span className="badge-local" data-testid="local-only-badge"><span className="dot sev-dot-low" /> Local storage · AI/OSINT calls only when you click</span>
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
        {tab !== "assessment" && <ContextStrip app={app} />}
        <Cur app={app} key={tab === "playbook" ? `pb-${tk}` : tab} />
      </main>
      <footer className="foot muted small">All times UTC+08:00 (Asia/Manila) · Data saved in this browser; AI and OSINT calls go out only when you click · Shortcuts: 1–8 tabs, Ctrl+Enter generate, Ctrl+Shift+C copy report</footer>
      <Toaster position="bottom-right" theme={theme} />
    </div>
  );
}
