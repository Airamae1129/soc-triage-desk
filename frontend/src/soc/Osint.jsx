import { useState } from "react";
import { ExternalLink, ShieldAlert } from "lucide-react";
import { Panel, CopyBlock } from "./ui";
import { isIp, isPrivateIp } from "./util";
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

function Card({ ioc, val, onChange, onRemove, i }) {
  const v = val?.verdict || "Not checked";
  return (
    <article className={`ocard vb-${tone[v]}`} data-testid={`osint-card-${i}`}>
      <div className="ocard-h">
        <span className="chip">{ioc.type}</span>
        <span className="mono brk ocard-v">{ioc.value}</span>
        {onRemove && <button className="x" onClick={onRemove} aria-label="Remove indicator" data-testid={`osint-remove-${i}`}>×</button>}
      </div>
      <div className="links">
        {LINKS[kind(ioc.type)](ioc.value).map(([n, u]) => <a key={n} className="btn btn-xs" href={u} target="_blank" rel="noopener noreferrer" data-testid={`osint-link-${i}-${n.replace(/\W/g, "").toLowerCase()}`}>{n} <ExternalLink size={11} /></a>)}
      </div>
      <div className="ocard-f">
        <select className="input" value={v} onChange={(ev) => onChange({ verdict: ev.target.value, note: val?.note || "" })} aria-label="Verdict" data-testid={`osint-verdict-${i}`}>{VERDICTS.map((x) => <option key={x}>{x}</option>)}</select>
        <input className="input" placeholder="Finding note (e.g. AbuseIPDB 0%, VT 0/94)" value={val?.note || ""} onChange={(ev) => onChange({ verdict: v, note: ev.target.value })} data-testid={`osint-note-${i}`} />
      </div>
    </article>
  );
}

export default function Osint({ app }) {
  const { osintT, setOsintT, an, entry } = app;
  const [add, setAdd] = useState("");
  const [err, setErr] = useState("");
  const extra = (osintT.extra || []).filter((x) => !an.extIocs.some((i) => i.value === x.value));
  const all = [...an.extIocs, ...extra];
  const vals = osintT.values || {};
  const setVal = (v, d) => setOsintT({ ...osintT, values: { ...vals, [v]: d } });
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
              onRemove={extra.includes(ioc) ? () => setOsintT({ ...osintT, extra: osintT.extra.filter((x) => x.value !== ioc.value) }) : null} />)}
          </div>
        </Panel>
      </div>
      <div className="col">
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
    </div>
  );
}
