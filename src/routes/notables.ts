import { Router } from "express";
import { z } from "zod";
import { prisma } from "../db.js";
import { h, badRequest } from "../lib/errors.js";
import { assessmentToEntry } from "../lib/serialize.js";
import { SHIFT_NAMES, shiftOf, shiftWindow, type ShiftName } from "../lib/shift.js";

export const notablesRouter = Router();

/**
 * GET /api/notables?shift=2026-06-02|Night  → escalations in that Manila shift.
 * Without ?shift, returns every escalation grouped by shift key (newest first).
 */
notablesRouter.get("/", h(async (req, res) => {
  const { shift } = z.object({ shift: z.string().max(40).optional() }).parse(req.query);
  if (shift) {
    const m = shift.match(/^(\d{4}-\d{2}-\d{2})\|(Morning|Mid|Night)$/);
    if (!m) throw badRequest("shift must look like 2026-06-02|Night (Morning, Mid or Night).");
    const { start, end } = shiftWindow(m[1]!, m[2] as ShiftName);
    const rows = await prisma.assessment.findMany({ where: { escalatedAt: { gte: start, lt: end } }, orderBy: { escalatedAt: "asc" } });
    res.json({ shift: { key: shift, date: m[1], name: m[2], start: start.toISOString(), end: end.toISOString() }, notables: rows.map(assessmentToEntry) });
    return;
  }
  const rows = await prisma.assessment.findMany({ where: { escalatedAt: { not: null } }, orderBy: { escalatedAt: "desc" }, take: 1000 });
  const groups: Record<string, ReturnType<typeof assessmentToEntry>[]> = {};
  for (const r of rows) (groups[shiftOf(r.escalatedAt!).key] ??= []).push(assessmentToEntry(r));
  res.json({ shifts: SHIFT_NAMES, groups });
}));
