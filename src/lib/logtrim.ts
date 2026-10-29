import { IPV4_RE, SHA256_RE, MD5_RE, URL_RE, DOMAIN_RE, TECHNIQUE_RES } from "./iocs.js";

/**
 * Keeps the `max` most relevant log lines for the AI: lines that hit an ATT&CK technique
 * come first, then lines with indicators, then the rest. Original order is kept inside the
 * selection so the timeline still reads top to bottom.
 */
export function trimLogs(raw: string, max: number): { text: string; kept: number; total: number } {
  const lines = raw.split(/\r?\n/).map((l) => l.trimEnd()).filter((l) => l.trim());
  if (lines.length <= max) return { text: lines.join("\n"), kept: lines.length, total: lines.length };
  const has = (re: RegExp, l: string) => { re.lastIndex = 0; return re.test(l); };
  const score = (l: string) =>
    (TECHNIQUE_RES.some((re) => re.test(l)) ? 2 : 0) +
    ([IPV4_RE, SHA256_RE, MD5_RE, URL_RE, DOMAIN_RE].some((re) => has(re, l)) ? 1 : 0);
  const keep = lines
    .map((l, i) => ({ i, s: score(l) }))
    .sort((a, b) => b.s - a.s || a.i - b.i)
    .slice(0, max)
    .map((x) => x.i)
    .sort((a, b) => a - b);
  return { text: keep.map((i) => lines[i]).join("\n"), kept: keep.length, total: lines.length };
}
