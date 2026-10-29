import { useState } from "react";
import { ExternalLink, ShieldAlert, Zap, RefreshCw, Camera, Loader2, Eraser, ScanLine, Paperclip } from "lucide-react";
import { toast } from "sonner";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "../components/ui/dialog";
import { Panel, CopyBlock, CopyBtn } from "./ui";
import { fmtDTm } from "./util";
import * as API from "./api";
import { osintSummary } from "./drafts";

const e = encodeURIComponent;
const LINKS = {
  IP: (v) => [["AbuseIPDB", `https://www.abuseipdb.com/check/${v}`], ["VirusTotal", `https://www.virustotal.com/gui/ip-address/${v}`], ["urlscan.io", `https://urlscan.io/search/#ip:${v}`], ["Shodan", `https://www.shodan.io/host/${v}`], ["AlienVault OTX", `https://otx.alienvault.com/indicator/ip/${v}`], ["Cisco Talos", `https://talosintelligence.com/reputation_center/lookup?search=${v}`]],
  Domain: (v) => [["VirusTotal", `https://www.virustotal.com/gui/domain/${v}`], ["urlscan.io", `https://urlscan.io/search/#domain:${v}`], ["OTX", `https://otx.alienvault.com/indicator/domain/${v}`], ["Talos", `https://talosintelligence.com/reputation_center/lookup?search=${v}`], ["ICANN WHOIS", `https://lookup.icann.org/en/lookup?name=${v}`]],
  URL: (v) => [["VirusTotal", `https://www.virustotal.com/gui/search/${e(v)}`], ["urlscan.io", `https://urlscan.io/search/#${e(`page.url:"${v}"`)}`], ["URLhaus", `https://urlhaus.abuse.ch/browse.php?search=${e(v)}`]],
  Hash: (v) => [["VirusTotal", `https://www.virustotal.com/gui/file/${v}`], ["MalwareBazaar", `https://bazaar.abuse.ch/browse.php?search=${e(`sha256:${v}`)}`], ["Hybrid Analysis", `https://www.hybrid-analysis.com/search?query=${v}`], ["OTX", `https://otx.alienvault.com/indicator/file/${v}`]],
};
const VERDICTS = ["Not checked", "Clean", "Suspicious", "Malicious"];
const tone = { "Not checked": "neutral", Clean: "low", Suspicious: "medium", Malicious: "critical" };
const LABEL = { ip: "IP", domain: "Domain", url: "URL", hash: "Hash" };
const STATUS = { ok: "ok", error: "error", not_configured: "Not configured", rate_limited: "rate limited" };
const STATUS_TONE = { ok: "low", error: "critical", not_configured: "neutral", rate_limited: "medium" };

/** Workspace items → the { iocs, values } shape the summary/handover builders in drafts.js read. */
export function wsForSummary(items) {
  const iocs = items.filter((i) => !i.hidden).map((i) => ({ type: i.type === "hash" ? (i.value.length === 32 ? "MD5" : "SHA-256") : LABEL[i.type] || i.type, value: i.value }));
  const values = Object.fromEntries(items.map((i) => {
    const rs = i.lookup?.results || [];
    const auto = i.lookup ? {
      sources: Object.fromEntries(rs.filter((r) => r.status === "ok").map((r) => [r.provider, r.data])),
      errors: Object.fromEntries(rs.filter((r) => r.status !== "ok" && r.status !== "not_configured").map((r) => [r.provider, r.error || r.status])),
    } : null;
    return [i.value, { verdict: i.verdict, note: i.note || i.lookup?.summary || "", manual: i.manual, auto }];
  }));
  return { iocs, values };
}

/** One readable line per provider result. */
function provLine(r) {
  const d = r.data;
  if (r.status === "not_configured") return "";
  if (r.status !== "ok" || !d) return r.error || STATUS[r.status];
  switch (r.provider) {
    case "abuseipdb": return `${d.score}% confidence · ${d.reports} reports${d.isp ? ` · ${d.isp}` : ""}${d.country ? ` (${d.country})` : ""}${d.usageType ? ` · ${d.usageType}` : ""}${d.isTor ? " · Tor" : ""}`;
    case "virustotal": return d.found ? `${d.malicious}/${d.total} malicious · ${d.suspicious} suspicious · ${d.harmless} harmless${d.reputation != null ? ` · reputation ${d.reputation}` : ""}${d.asOwner ? ` · ${d.asOwner}` : ""}${d.lastAnalysisDate ? ` · analysed ${fmtDTm(d.lastAnalysisDate)}` : ""}` : "Not found";
    case "urlscan": return `${d.hits} existing scans${d.malicious ? ` · ${d.malicious} flagged malicious` : ""}`;
    case "shodan": return d.found ? `${d.ports.length ? `ports ${d.ports.slice(0, 10).join(", ")}` : "no open ports"}${d.org ? ` · ${d.org}` : ""}${d.asn ? ` · ${d.asn}` : ""}${d.vulns ? ` · ${d.vulns} CVEs` : ""}` : "Not found";
    case "otx": return `${d.pulses} pulses${d.tags?.length ? ` · ${d.tags.slice(0, 5).join(", ")}` : ""}`;
    default: return "";
  }
}
const scanLink = (d) => d?.latest?.result?.replace("/api/v1/result/", "/result/");

function ProviderRows({ lookup, i }) {
  if (!lookup) return null;
  return (
    <div className="auto-res small" data-testid={`osint-auto-result-${i}`}>
      {lookup.results.map((r) => (
        <div key={r.provider} className="prov-row" data-testid={`osint-provider-${i}-${r.provider}`}>
          <b>{r.label}</b>
          <span className={`pill vb-${STATUS_TONE[r.status]}`}>{STATUS[r.status]}</span>
          <span className={r.status === "ok" ? "" : "muted"}>{provLine(r)}</span>
          {r.provider === "urlscan" && scanLink(r.data) && <a href={scanLink(r.data)} target="_blank" rel="noopener noreferrer" className="link">latest scan</a>}
          {r.fetchedAt && <span className="muted mono">{r.cached ? "cached" : "fetched"} {fmtDTm(r.fetchedAt)}</span>}
        </div>
      ))}
      {lookup.summary && <div className="mono brk">{lookup.summary}</div>}
    </div>
  );
}

function Card({ item, i, busy, onLookup, onPatch, onRemove, onShot, onScan, onAttach, shot, canScan, entry }) {
  const [note, setNote] = useState(item.note || "");
  const kind = LABEL[item.type];
  const web = item.type === "url" || item.type === "domain";
  const suggested = item.lookup?.verdict;
  return (
    <article className={`ocard vb-${tone[item.verdict]}`} data-testid={`osint-card-${i}`}>
      <div className="ocard-h">
        <span className="chip">{kind}</span>
        <span className="mono brk ocard-v">{item.value}</span>
        <button className="x" onClick={onRemove} aria-label="Remove indicator" data-testid={`osint-remove-${i}`}>×</button>
      </div>
      <div className="btn-row">
        <button className="btn btn-xs btn-primary" onClick={() => onLookup(false)} disabled={busy} data-testid={`osint-lookup-${i}`}>{busy ? <Loader2 size={11} className="spin" /> : <Zap size={11} />} Run lookups</button>
        {item.lookup && <button className="btn btn-xs" onClick={() => onLookup(true)} disabled={busy} title="Skip the cache and ask the providers again" data-testid={`osint-refresh-${i}`}><RefreshCw size={11} /> Refresh</button>}
        {web && canScan && <button className="btn btn-xs" onClick={onScan} data-testid={`osint-scan-${i}`}><ScanLine size={11} /> Scan</button>}
        {web && <button className="btn btn-xs" onClick={onShot} data-testid={`osint-screenshot-${i}`}><Camera size={11} /> Screenshot</button>}
        {entry && <button className="btn btn-xs" onClick={() => onAttach(note)} title={`Save this verdict on ticket ${entry.form.ticketId}`} data-testid={`osint-attach-${i}`}><Paperclip size={11} /> Attach to {entry.form.ticketId}</button>}
      </div>
      <ProviderRows lookup={item.lookup} i={i} />
      {shot && <a href={shot.url} target="_blank" rel="noopener noreferrer"><img src={shot.url} alt={`Screenshot of ${item.value}`} className="shot" /></a>}
      <div className="links">
        {LINKS[kind](item.value).map(([n, u]) => <a key={n} className="btn btn-xs" href={u} target="_blank" rel="noopener noreferrer" data-testid={`osint-link-${i}-${n.replace(/\W/g, "").toLowerCase()}`}>{n} <ExternalLink size={11} /></a>)}
      </div>
      <div className="ocard-f">
        <select className="input" value={item.verdict} onChange={(ev) => onPatch({ verdict: ev.target.value })} aria-label="Verdict" data-testid={`osint-verdict-${i}`}>{VERDICTS.map((x) => <option key={x}>{x}</option>)}</select>
        <input className="input" placeholder={item.lookup?.summary || "Finding note (e.g. AbuseIPDB 0%, VT 0/94)"} value={note}
          onChange={(ev) => setNote(ev.target.value)} onBlur={() => note !== (item.note || "") && onPatch({ note })} data-testid={`osint-note-${i}`} />
      </div>
      {suggested && <p className="muted small">Suggested: <b>{suggested}</b>{item.manual && suggested !== item.verdict ? " · your verdict is kept" : ""}</p>}
    </article>
  );
}

export default function Osint({ app }) {
  const { ws, setWs, reloadWs, entry, aiConfig } = app;
  const [add, setAdd] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState({});
  const [shotUrl, setShotUrl] = useState("");
  const [confirm, setConfirm] = useState(null); // { kind: "shot" | "scan", url }
  const [confirmBusy, setConfirmBusy] = useState(false);
  const items = ws.items;
  const providers = aiConfig?.providers || [];
  const urlscanOn = providers.some((p) => p.name === "urlscan" && p.configured);

  const setItem = (it) => setWs((w) => ({ ...w, items: w.items.map((x) => (x.value === it.value ? it : x)) }));
  const fail = (what, ex) => toast.error(`${what}: ${ex.message}`);

  const lookup = async (it, force) => {
    setBusy((b) => ({ ...b, [it.value]: true }));
    try {
      const r = await API.osintLookup(it.value, { type: it.type, force });
      setItem({ ...it, lookup: r, verdict: r.analystVerdict || r.verdict, manual: !!r.analystVerdict, checkedAt: r.checkedAt });
      const bad = r.results.filter((x) => x.status === "error" || x.status === "rate_limited");
      if (bad.length) toast.warning(`${it.value}: ${bad.map((x) => `${x.label} ${STATUS[x.status]}`).join(", ")}`);
    } catch (ex) { fail(it.value, ex); }
    finally { setBusy((b) => ({ ...b, [it.value]: false })); }
  };
  // One at a time: the server queues per provider anyway, and this keeps VirusTotal's 4/min plan readable.
  const lookupAll = async () => { for (const it of items) await lookup(it, false); };

  const patch = async (it, p) => {
    try { setItem((await API.patchWorkspace(it.value, p)).item); } catch (ex) { fail(it.value, ex); }
  };
  const remove = async (it) => {
    try { await API.removeFromWorkspace(it.value); setWs((w) => ({ ...w, items: w.items.filter((x) => x.value !== it.value) })); } catch (ex) { fail(it.value, ex); }
  };
  const attach = async (it, note) => {
    try { await app.attachOsint(it.value, it.verdict, note || it.note || it.lookup?.summary || ""); toast.success(`${it.value} saved on ${entry.form.ticketId}`); } catch (ex) { fail(it.value, ex); }
  };

  const submit = async (ev) => {
    ev.preventDefault();
    const parts = add.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);
    if (!parts.length) return setErr("Enter a value.");
    try {
      const r = await API.addToWorkspace(parts);
      setWs((w) => ({ ...w, items: r.items }));
      const skipped = r.rejected.map((x) => `${x.value} (${x.reason.replace(/\.$/, "")})`);
      setAdd("");
      setErr(skipped.length ? `${r.added.length ? `Added ${r.added.length}. ` : ""}Not added: ${skipped.join("; ")}` : r.added.length ? "" : "Already in the list.");
    } catch (ex) { setErr(ex.message); }
  };

  const pageOf = (it) => (it.type === "domain" ? `https://${it.value}` : it.value);
  const shotFor = (it) => [...ws.shots].reverse().find((s) => s.page === pageOf(it));
  const ask = (kind, raw) => {
    const u = String(raw || "").trim();
    if (!u) return toast.error("Enter the URL first.");
    setConfirm({ kind, url: /^https?:\/\//i.test(u) ? u : `https://${u}` });
  };
  const runConfirmed = async () => {
    const { kind, url } = confirm;
    setConfirmBusy(true);
    try {
      if (kind === "shot") {
        const r = await API.takeScreenshot(url);
        setWs((w) => ({ ...w, shots: [...w.shots, { id: r.id, page: r.page, url: r.url, taken_at: r.taken_at }], screenshotsToday: r.count_today }));
        setShotUrl("");
      } else {
        const r = await API.urlscanScan(url);
        toast.success(`urlscan.io scan submitted (${r.visibility}). Results take about a minute; Refresh the lookup to see them.`, { action: r.result ? { label: "Open", onClick: () => window.open(r.result, "_blank", "noopener") } : undefined });
      }
      setConfirm(null);
    } catch (ex) { fail(kind === "shot" ? "Screenshot" : "urlscan.io", ex); setConfirm(null); }
    finally { setConfirmBusy(false); }
  };
  const removeShot = async (s) => {
    try { await API.deleteScreenshot(s.id); setWs((w) => ({ ...w, shots: w.shots.filter((x) => x.id !== s.id) })); } catch (ex) { fail("Screenshot", ex); }
  };
  const clearAll = async () => {
    if (!window.confirm("Clear all OSINT indicators, results and screenshot links?")) return;
    try { await API.clearWorkspace(); await reloadWs(); } catch (ex) { fail("Clear", ex); }
  };

  const tally = VERDICTS.map((v) => [v, items.filter((i) => i.verdict === v).length]);
  const { iocs, values } = wsForSummary(items);
  const anyBusy = Object.values(busy).some(Boolean);

  return (
    <div className="grid2" data-testid="osint-tab">
      <div className="col">
        <Panel title="Indicators to check" right={<span className="mono small muted">{items.length}</span>} testid="osint-cards-panel">
          {!items.length && <p className="muted">Nothing to check yet. Add IPs, domains, URLs or hashes on the right.</p>}
          <div className="ocards">
            {items.map((it, i) => (
              <Card key={it.value} i={i} item={it} busy={!!busy[it.value]} entry={entry} canScan={urlscanOn} shot={shotFor(it)}
                onLookup={(force) => lookup(it, force)} onPatch={(p) => patch(it, p)} onRemove={() => remove(it)}
                onShot={() => ask("shot", pageOf(it))} onScan={() => ask("scan", pageOf(it))} onAttach={(note) => attach(it, note)} />
            ))}
          </div>
        </Panel>
      </div>
      <div className="col">
        <Panel title="Lookups" testid="osint-autofill-panel">
          <p className="muted small">Lookups run on the server with the team's API keys and are cached{aiConfig?.cacheHours ? ` for ${aiConfig.cacheHours} hours` : ""}. urlscan.io is searched only; a new scan runs only when you click Scan, and is always private. A verdict you set by hand is kept.</p>
          <div className="btn-row">
            <button className="btn btn-primary" onClick={lookupAll} disabled={!items.length || anyBusy} data-testid="osint-lookup-all-btn">{anyBusy ? <Loader2 size={13} className="spin" /> : <Zap size={13} />} Run all ({items.length})</button>
          </div>
          {providers.length > 0 && (
            <div className="prov-status small" data-testid="osint-sources-status">
              {providers.map((p) => <span key={p.name} className={`pill vb-${p.configured ? "low" : "neutral"}`}>{p.label}: {p.configured ? "on" : "Not configured"}</span>)}
            </div>
          )}
        </Panel>
        <Panel title="Reputation tally" testid="osint-tally-panel">
          <div className="tally">{tally.map(([v, n]) => <div key={v} className={`tally-box vb-${tone[v]}`} data-testid={`tally-${v.replace(/\s/g, "-").toLowerCase()}`}><b className="mono">{n}</b><span>{v}</span></div>)}</div>
          <p className="note small"><ShieldAlert size={14} /> Do not look up or scan client-internal URLs. Private and internal addresses are refused by the server.</p>
        </Panel>
        <Panel title="Add indicators" testid="osint-add-panel">
          <form className="inline-form" onSubmit={submit}>
            <input className="input mono" value={add} onChange={(ev) => { setAdd(ev.target.value); setErr(""); }} placeholder="IPs, domains, URLs or hashes (separate with spaces or commas)" data-testid="osint-add-input" />
            <button className="btn btn-primary" data-testid="osint-add-btn">Add</button>
          </form>
          {err && <p className="err small" data-testid="osint-add-error">{err}</p>}
        </Panel>
        <Panel title="Screenshotbase (URL to image)" right={<span className="mono small muted">{ws.screenshotsToday} today</span>} testid="osint-screenshot-panel">
          <p className="muted small">Optional. Type a URL and confirm to get a hosted PNG link you can paste into the ticket. Each screenshot uses the API quota, so nothing runs until you confirm.</p>
          <form className="inline-form" onSubmit={(ev) => { ev.preventDefault(); ask("shot", shotUrl); }}>
            <input className="input mono" value={shotUrl} onChange={(ev) => setShotUrl(ev.target.value)} placeholder="https://example.com/login" data-testid="screenshot-url-input" />
            <button className="btn btn-primary" disabled={!aiConfig?.screenshot} data-testid="screenshot-run-btn"><Camera size={13} /> Generate</button>
          </form>
          {aiConfig && !aiConfig.screenshot && <p className="muted small">Screenshot API key not configured.</p>}
          {ws.shots.length > 0 && (
            <ul className="shot-list" data-testid="screenshot-list">
              {[...ws.shots].reverse().map((s, i) => (
                <li key={s.id}>
                  <a href={s.url} target="_blank" rel="noopener noreferrer"><img src={s.url} alt={`Screenshot of ${s.page}`} className="shot" /></a>
                  <div className="small mono brk">{s.page}</div>
                  <div className="btn-row">
                    <CopyBtn text={s.url} small raw label="Copy image URL" testid={`screenshot-copy-${i}`} />
                    <a className="btn btn-xs" href={s.url} target="_blank" rel="noopener noreferrer">Open <ExternalLink size={11} /></a>
                    <button type="button" className="btn btn-xs" onClick={() => removeShot(s)}>Remove</button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>
        <Panel title="Results" testid="osint-results-panel">
          {items.length > 0 && (
            <div className="result-chips" data-testid="osint-result-chips">
              <span className="muted small">In results (× to leave one out):</span>
              {items.map((it) => (
                <button type="button" key={it.value} className={`chip mono ${it.hidden ? "chip-off" : ""}`} onClick={() => patch(it, { hidden: !it.hidden })}
                  title={it.hidden ? "Add back to results" : "Remove from results"} data-testid={`osint-result-toggle-${it.value}`}>
                  {it.value} {it.hidden ? "+" : "×"}
                </button>
              ))}
            </div>
          )}
          <CopyBlock text={osintSummary(entry?.form || {}, iocs, values, ws.shots)} testid="osint-summary"
            actions={<button type="button" className="btn btn-sm" onClick={clearAll} disabled={!items.length && !ws.shots.length} title="Clear all indicators, results and screenshot links" data-testid="osint-clear-btn"><Eraser size={13} /> Clear</button>} />
        </Panel>
      </div>
      <Dialog open={!!confirm} onOpenChange={(o) => !o && !confirmBusy && setConfirm(null)}>
        <DialogContent className="dlg" data-testid="osint-confirm-dialog">
          <DialogHeader>
            <DialogTitle className="dlg-title">{confirm?.kind === "scan" ? "Submit a urlscan.io scan?" : "Take a screenshot?"}</DialogTitle>
            <DialogDescription className="dlg-desc">
              {confirm?.kind === "scan"
                ? <>urlscan.io will load <span className="mono brk">{confirm?.url}</span> from its servers. The scan is submitted as <b>private</b>, so it isn't listed publicly, but it still uses the team's scan quota. Never scan client-internal URLs.</>
                : <>This sends <span className="mono brk">{confirm?.url}</span> to screenshotbase.com, which loads the page and stores the PNG at a public link. Each screenshot uses the API quota ({ws.screenshotsToday} taken today). Don't use it on URLs that identify the client.</>}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="dlg-foot">
            <button className="btn" onClick={() => setConfirm(null)} disabled={confirmBusy} data-testid="osint-confirm-cancel">Cancel</button>
            <button className="btn btn-primary" onClick={runConfirmed} disabled={confirmBusy} data-testid="osint-confirm-ok">{confirmBusy && <Loader2 size={13} className="spin" />} {confirm?.kind === "scan" ? "Submit private scan" : "Take screenshot"}</button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
