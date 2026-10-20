import { useEffect, useState } from "react";
import { ExternalLink, ShieldAlert, Zap, RefreshCw, Camera, Loader2 } from "lucide-react";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "../components/ui/dialog";
import { Panel, CopyBlock } from "./ui";
import { isIp, isPrivateIp, fmtDTm } from "./util";
import { osintLookup, screenshotUsage, takeScreenshot } from "./api";
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
const kind = (t) => (t === "SHA-256" || t === "MD5" ? "Hash" : t);

export function detectIoc(raw) {
  const v = raw.trim();
  if (!v) return { err: "Enter a value." };
  if (isIp(v)) return isPrivateIp(v) ? { err: "Private or reserved IPs are not looked up in OSINT." } : { type: "IP", value: v };
  if (/^https?:\/\//i.test(v)) return { type: "URL", value: v };
  if (/^[a-f0-9]{64}$/i.test(v)) return { type: "SHA-256", value: v.toLowerCase() };
  if (/^[a-f0-9]{32}$/i.test(v)) return { type: "MD5", value: v.toLowerCase() };
  if (/^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i.test(v)) return { type: "Domain", value: v.toLowerCase() };
  return { err: "Not a recognised IP, domain, URL or hash." };
}

const SRC = { abuseipdb: "AbuseIPDB", virustotal: "VirusTotal", urlscan: "urlscan.io" };
function srcLine(name, s) {
  if (name === "abuseipdb") return `${s.score}% confidence · ${s.reports} reports${s.isp ? ` · ${s.isp}` : ""}${s.country ? ` (${s.country})` : ""}${s.usage ? ` · ${s.usage}` : ""}`;
  if (name === "virustotal") return s.found ? `${s.malicious} malicious / ${s.suspicious} suspicious of ${s.total} engines${s.as_owner ? ` · ${s.as_owner}` : ""}` : "Not found";
  return `${s.hits} public scans${s.malicious ? ` · ${s.malicious} flagged malicious` : ""}`;
}
const scanLink = (u) => u?.latest?.result?.replace("/api/v1/result/", "/result/");

function AutoResult({ auto, i }) {
  if (!auto) return null;
  return (
    <div className="auto-res small" data-testid={`osint-auto-result-${i}`}>
      {Object.entries(auto.sources || {}).map(([k, s]) => (
        <div key={k}><b>{SRC[k]}</b> · {srcLine(k, s)} {k === "urlscan" && scanLink(s) && <a href={scanLink(s)} target="_blank" rel="noopener noreferrer" className="link">latest scan</a>}</div>
      ))}
      {Object.entries(auto.errors || {}).map(([k, e]) => <div key={k} className="muted"><b>{SRC[k]}</b> · {e}</div>)}
      <div className="muted mono">{auto.cached ? "Cached" : "Fetched"} {fmtDTm(auto.fetched_at)} · cache 24 h</div>
    </div>
  );
}

function Card({ ioc, val, onChange, onRemove, i, onAuto, busy, onShot, shot }) {
  const v = val?.verdict || "Not checked";
  const canShot = ioc.type === "URL" || ioc.type === "Domain";
  return (
    <article className={`ocard vb-${tone[v]}`} data-testid={`osint-card-${i}`}>
      <div className="ocard-h">
        <span className="chip">{ioc.type}</span>
        <span className="mono brk ocard-v">{ioc.value}</span>
        {onRemove && <button className="x" onClick={onRemove} aria-label="Remove indicator" data-testid={`osint-remove-${i}`}>×</button>}
      </div>
      <div className="btn-row">
        <button className="btn btn-xs btn-primary" onClick={() => onAuto(false)} disabled={busy} data-testid={`osint-autofill-${i}`}>{busy ? <Loader2 size={11} className="spin" /> : <Zap size={11} />} Auto-fill</button>
        {val?.auto && <button className="btn btn-xs" onClick={() => onAuto(true)} disabled={busy} data-testid={`osint-refresh-${i}`}><RefreshCw size={11} /> Refresh</button>}
        {canShot && <button className="btn btn-xs" onClick={onShot} data-testid={`osint-screenshot-${i}`}><Camera size={11} /> Screenshot</button>}
      </div>
      <AutoResult auto={val?.auto} i={i} />
      {shot && <a href={shot} target="_blank" rel="noopener noreferrer"><img src={shot} alt={`Screenshot of ${ioc.value}`} className="shot" data-testid={`osint-screenshot-img-${i}`} /></a>}
      <div className="links">
        {LINKS[kind(ioc.type)](ioc.value).map(([n, u]) => <a key={n} className="btn btn-xs" href={u} target="_blank" rel="noopener noreferrer" data-testid={`osint-link-${i}-${n.replace(/\W/g, "").toLowerCase()}`}>{n} <ExternalLink size={11} /></a>)}
      </div>
      <div className="ocard-f">
        <select className="input" value={v} onChange={(ev) => onChange({ ...val, verdict: ev.target.value, note: val?.note || "" })} aria-label="Verdict" data-testid={`osint-verdict-${i}`}>{VERDICTS.map((x) => <option key={x}>{x}</option>)}</select>
        <input className="input" placeholder="Finding note (e.g. AbuseIPDB 0%, VT 0/94)" value={val?.note || ""} onChange={(ev) => onChange({ ...val, verdict: v, note: ev.target.value })} data-testid={`osint-note-${i}`} />
      </div>
    </article>
  );
}

export default function Osint({ app }) {
  const { osintT, setOsintT, an, entry } = app;
  const [add, setAdd] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState({});
  const [autoErr, setAutoErr] = useState("");
  const [shots, setShots] = useState({});
  const [confirm, setConfirm] = useState(null);
  const [shotBusy, setShotBusy] = useState(false);
  const [usage, setUsage] = useState(null);
  useEffect(() => { screenshotUsage().then(setUsage).catch(() => {}); }, []);
  const extra = (osintT.extra || []).filter((x) => !an.extIocs.some((i) => i.value === x.value));
  const all = [...an.extIocs, ...extra];
  const vals = osintT.values || {};
  const setVal = (v, d) => setOsintT((o) => ({ ...o, values: { ...(o.values || {}), [v]: d } }));
  const auto = async (ioc, force) => {
    setBusy((b) => ({ ...b, [ioc.value]: true })); setAutoErr("");
    try {
      const r = await osintLookup(ioc.type, ioc.value, force);
      setOsintT((o) => {
        const cur = (o.values || {})[ioc.value] || {};
        const keepManual = cur.verdict && cur.verdict !== "Not checked" && !cur.auto;
        return { ...o, values: { ...(o.values || {}), [ioc.value]: { verdict: keepManual ? cur.verdict : r.verdict, note: keepManual && cur.note ? cur.note : r.note, auto: { sources: r.sources, errors: r.errors, fetched_at: r.fetched_at, cached: r.cached } } } };
      });
    } catch (e) { setAutoErr(`${ioc.value}: ${e.message}`); }
    finally { setBusy((b) => ({ ...b, [ioc.value]: false })); }
  };
  const autoAll = async () => { for (const ioc of all) await auto(ioc, false); };
  const shoot = async () => {
    const ioc = confirm;
    setShotBusy(true);
    try {
      const url = await takeScreenshot(ioc.type === "Domain" ? `https://${ioc.value}` : ioc.value);
      setShots((s) => ({ ...s, [ioc.value]: url }));
      setConfirm(null);
      screenshotUsage().then(setUsage).catch(() => {});
    } catch (e) { setAutoErr(`Screenshot ${ioc.value}: ${e.message}`); setConfirm(null); }
    finally { setShotBusy(false); }
  };
  const tally = VERDICTS.map((v) => [v, all.filter((i) => (vals[i.value]?.verdict || "Not checked") === v).length]);
  const submit = (ev) => {
    ev.preventDefault();
    const r = detectIoc(add);
    if (r.err) return setErr(r.err);
    if (all.some((i) => i.value === r.value)) return setErr("Already in the list.");
    setOsintT({ ...osintT, extra: [...(osintT.extra || []), { type: r.type, value: r.value, note: "Added manually" }] });
    setAdd(""); setErr("");
  };
  return (
    <div className="grid2" data-testid="osint-tab">
      <div className="col">
        <Panel title="Indicators to check" right={<span className="mono small muted">{all.length}</span>} testid="osint-cards-panel">
          {!all.length && <p className="muted">No external indicators in this ticket. Add one on the right.</p>}
          <div className="ocards">
            {all.map((ioc, i) => <Card key={ioc.value} i={i} ioc={ioc} val={vals[ioc.value]} onChange={(d) => setVal(ioc.value, d)}
              onAuto={(force) => auto(ioc, force)} busy={!!busy[ioc.value]} onShot={() => setConfirm(ioc)} shot={shots[ioc.value]}
              onRemove={extra.includes(ioc) ? () => setOsintT({ ...osintT, extra: osintT.extra.filter((x) => x.value !== ioc.value) }) : null} />)}
          </div>
        </Panel>
      </div>
      <div className="col">
        <Panel title="Auto-fill" testid="osint-autofill-panel">
          <p className="muted small">Looks up AbuseIPDB (IPs), VirusTotal and urlscan.io search. Results are cached for 24 hours per indicator. urlscan.io is searched only; no new public scans are submitted. A verdict you set by hand is kept.</p>
          <div className="btn-row">
            <button className="btn btn-primary" onClick={autoAll} disabled={!all.length || Object.values(busy).some(Boolean)} data-testid="osint-autofill-all-btn"><Zap size={13} /> Auto-fill all ({all.length})</button>
            {app.aiConfig && <span className="muted small" data-testid="osint-sources-status">{Object.entries(app.aiConfig.osint).map(([k, on]) => `${SRC[k]} ${on ? "on" : "off (no key)"}`).join(" · ")}</span>}
          </div>
          {autoErr && <p className="err small" data-testid="osint-autofill-error">{autoErr}</p>}
        </Panel>
        <Panel title="Reputation tally" testid="osint-tally-panel">
          <div className="tally">{tally.map(([v, n]) => <div key={v} className={`tally-box vb-${tone[v]}`} data-testid={`tally-${v.replace(/\s/g, "-").toLowerCase()}`}><b className="mono">{n}</b><span>{v}</span></div>)}</div>
          <p className="note small"><ShieldAlert size={14} /> Public lookups can be seen by others, and urlscan.io scans may be public. Do not submit client-identifying URLs without approval.</p>
        </Panel>
        <Panel title="Add an indicator" testid="osint-add-panel">
          <form className="inline-form" onSubmit={submit}>
            <input className="input mono" value={add} onChange={(ev) => { setAdd(ev.target.value); setErr(""); }} placeholder="IP, domain, URL or hash" data-testid="osint-add-input" />
            <button className="btn btn-primary" data-testid="osint-add-btn">Add</button>
          </form>
          {err && <p className="err small" data-testid="osint-add-error">{err}</p>}
          {!err && add && !detectIoc(add).err && <p className="muted small">Detected: {detectIoc(add).type}</p>}
        </Panel>
        <Panel title="Results for the ticket" testid="osint-results-panel">
          <p className="muted small">These verdicts also feed the IOC list in the client email.</p>
          <CopyBlock text={osintSummary(entry?.form || {}, all, vals)} testid="osint-summary" />
        </Panel>
      </div>
      <Dialog open={!!confirm} onOpenChange={(o) => !o && !shotBusy && setConfirm(null)}>
        <DialogContent className="dlg" data-testid="screenshot-confirm-dialog">
          <DialogHeader>
            <DialogTitle className="dlg-title">Take a screenshot?</DialogTitle>
            <DialogDescription className="dlg-desc">
              This sends <span className="mono brk">{confirm && (confirm.type === "Domain" ? `https://${confirm.value}` : confirm.value)}</span> to screenshotbase.com, which loads the page from its servers. Each screenshot uses your API quota{usage ? ` (${usage.count} taken today)` : ""}. Don't use it on URLs that identify the client.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="dlg-foot">
            <button className="btn" onClick={() => setConfirm(null)} disabled={shotBusy} data-testid="screenshot-cancel-btn">Cancel</button>
            <button className="btn btn-primary" onClick={shoot} disabled={shotBusy} data-testid="screenshot-confirm-btn">{shotBusy ? <Loader2 size={13} className="spin" /> : <Camera size={13} />} Take screenshot</button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
