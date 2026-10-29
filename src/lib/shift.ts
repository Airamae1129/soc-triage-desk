// Shift maths in Asia/Manila (UTC+08:00, no daylight saving).
// Morning 06:00–14:00, Mid 14:00–22:00, Night 22:00–06:00. Night crosses midnight and belongs
// to the date it started on: 03:00 on Jun 3 is the Night shift of Jun 2.

export const SHIFT_NAMES = ["Morning", "Mid", "Night"] as const;
export type ShiftName = (typeof SHIFT_NAMES)[number];

const OFFSET_MS = 8 * 3600e3;
const pad = (n: number) => String(n).padStart(2, "0");
const manila = (d: Date) => new Date(d.getTime() + OFFSET_MS); // read with getUTC*

export function shiftOf(d: Date): { name: ShiftName; date: string; key: string } {
  const m = manila(d);
  const h = m.getUTCHours();
  const name: ShiftName = h >= 6 && h < 14 ? "Morning" : h >= 14 && h < 22 ? "Mid" : "Night";
  const base = name === "Night" && h < 6 ? new Date(m.getTime() - 86400e3) : m;
  const date = `${base.getUTCFullYear()}-${pad(base.getUTCMonth() + 1)}-${pad(base.getUTCDate())}`;
  return { name, date, key: `${date}|${name}` };
}

/** UTC start/end of a shift given its Manila date (YYYY-MM-DD) and name. */
export function shiftWindow(date: string, name: ShiftName): { start: Date; end: Date } {
  const startHour = name === "Morning" ? 6 : name === "Mid" ? 14 : 22;
  const start = new Date(`${date}T${pad(startHour)}:00:00+08:00`);
  if (isNaN(start.getTime())) throw new Error("bad date");
  return { start, end: new Date(start.getTime() + 8 * 3600e3) };
}
