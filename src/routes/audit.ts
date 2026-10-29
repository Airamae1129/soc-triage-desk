import { Router } from "express";
import { z } from "zod";
import { prisma } from "../db.js";
import { h } from "../lib/errors.js";

// Admin only (mounted behind requireAdmin).
export const auditRouter = Router();

auditRouter.get("/", h(async (req, res) => {
  const { limit, action } = z.object({ limit: z.coerce.number().int().min(1).max(1000).default(200), action: z.string().max(64).optional() }).parse(req.query);
  const rows = await prisma.auditLog.findMany({
    where: action ? { action: { startsWith: action } } : {},
    orderBy: { at: "desc" },
    take: limit,
    include: { user: { select: { username: true, displayName: true } } },
  });
  res.json({ entries: rows.map((r) => ({ id: r.id, at: r.at.toISOString(), user: r.user?.username ?? null, userName: r.user?.displayName ?? null, action: r.action, target: r.target, details: r.details, ip: r.ip })) });
}));
