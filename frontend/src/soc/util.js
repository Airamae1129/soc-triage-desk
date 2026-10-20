const P = "socdesk.";
export const load = (k, f) => {
  try {
    const v = localStorage.getItem(P + k);
    return v == null ? f : JSON.parse(v);
  } catch {
    return f;
  }
};
export const save = (k, v) => {
  try {
    localStorage.setItem(P + k, JSON.stringify(v));
  } catch {}
};
export const STORE_KEYS = ["history", "currentId", "playbooks", "notes", "osint", "checklist", "analyst", "seeded"];

const MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
export const pad = (n) => String(n).padStart(2, "0");
const mp = (d) => {
  const x = new Date(new Date(d).getTime() + 8 * 3600e3);
  return { y: x.getUTCFullYear(), mo: x.getUTCMonth(), d: x.getUTCDate(), h: x.getUTCHours(), mi: x.getUTCMinutes(), s: x.getUTCSeconds() };
};
export const fmtHM = (d) => { const p = mp(d); return `${pad(p.h)}:${pad(p.mi)}`; };
export const fmtDate = (d) => { const p = mp(d); return `${MON[p.mo]} ${p.d}, ${p.y}`; };
export const fmtDT = (d) => `${fmtDate(d)} ${fmtHM(d)}:${pad(mp(d).s)}`;
export const fmtDTm = (d) => `${fmtDate(d)} ${fmtHM(d)}`;
export const fmtTime = (d) => `${fmtHM(d)}:${pad(mp(d).s)}`;
export const fmtLong = (d) => {
  const p = mp(d);
  return `${fmtDate(d)} at ${p.h % 12 || 12}:${pad(p.mi)} ${p.h < 12 ? "AM" : "PM"}`;
};
export const manilaInput = (d) => { const p = mp(d); return `${p.y}-${pad(p.mo + 1)}-${pad(p.d)}T${pad(p.h)}:${pad(p.mi)}`; };
export const fromManilaInput = (s) => new Date(`${s}:00+08:00`);
export const dateKey = (d) => { const p = mp(d); return `${p.y}-${pad(p.mo + 1)}-${pad(p.d)}`; };
export const fmtSpan = (ms) => {
  if (ms == null) return "—";
  const m = Math.round(ms / 60000);
  if (m < 1) return `${Math.round(ms / 1000)} s`;
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} h ${m % 60} min`;
  return `${Math.floor(h / 24)} d ${h % 24} h`;
};
export const fmtBytes = (b) => (b >= 1048576 ? `${(b / 1048576).toFixed(2)} MB` : b >= 1024 ? `${(b / 1024).toFixed(1)} KB` : `${b} B`);
export const fmtNum = (n) => Number(n).toLocaleString("en-US");
export const isIp = (s) => /^(\d{1,3}\.){3}\d{1,3}$/.test(s) && s.split(".").every((o) => +o <= 255);
export const isPrivateIp = (ip) =>
  /^(10\.|127\.|0\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip) || /^(22[4-9]|2[3-5]\d)\./.test(ip);
export const defang = (s) => s.replace(/http/gi, (m) => (m[0] === "h" ? "hxxp" : "HXXP")).replace(/\./g, "[.]");
export const joinAnd = (a) => (a.length <= 1 ? a.join("") : `${a.slice(0, -1).join(", ")} and ${a[a.length - 1]}`);
const WORDS = ["Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten"];
export const numWord = (n) => (n <= 10 ? WORDS[n] : String(n));
export const uid = () => Math.random().toString(36).slice(2, 10);
export const SEVS = ["Critical", "High", "Medium", "Low"];
export const sevKey = (s) => String(s || "low").toLowerCase();
export const SHIFTS = { Morning: "06:00–14:00", Mid: "14:00–22:00", Night: "22:00–06:00" };
export const shiftOf = (d) => {
  const p = mp(d);
  const name = p.h >= 6 && p.h < 14 ? "Morning" : p.h >= 14 && p.h < 22 ? "Mid" : "Night";
  const base = name === "Night" && p.h < 6 ? new Date(new Date(d).getTime() - 86400e3) : new Date(d);
  return { name, date: fmtDate(base), key: `${dateKey(base)}|${name}` };
};
export const parseSla = (s) => {
  const m = String(s || "").match(/(\d+(?:\.\d+)?)\s*(m|h|d)/i);
  if (!m) return null;
  const u = m[2].toLowerCase();
  return +m[1] * (u === "m" ? 1 : u === "h" ? 60 : 1440);
};
export async function copyText(text, el) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    if (el) {
      const r = document.createRange();
      r.selectNodeContents(el);
      const s = window.getSelection();
      s.removeAllRanges();
      s.addRange(r);
      try { document.execCommand("copy"); } catch {}
    }
    return false;
  }
}
export const download = (name, text, type = "text/plain") => {
  const b = new Blob([text], { type });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(b);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
};
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
export function maskText(text, { client, users = [], hosts = [], ips = [] }) {
  const items = [];
  let out = text;
  const rep = (val, token) => {
    if (!val || val.length < 2) return;
    const re = new RegExp(esc(val), "gi");
    if (re.test(out)) { items.push({ val, token }); out = out.replace(re, token); }
  };
  rep(client, "[CLIENT]");
  users.forEach((u, i) => rep(u, `[USER-${i + 1}]`));
  hosts.forEach((h, i) => rep(h, `[HOST-${i + 1}]`));
  ips.forEach((ip, i) => rep(ip, `[INT-IP-${i + 1}]`));
  return { text: out, items };
}
