import { Router } from "express";
import { z } from "zod";
import { prisma } from "../db.js";
import { h, notFound, conflict, badRequest } from "../lib/errors.js";
import { audit } from "../lib/audit.js";
import { me } from "../auth/middleware.js";
import { hashPassword, passwordRules } from "../auth/password.js";

// Admin only (mounted behind requireAdmin).
export const usersRouter = Router();

const out = (u: { id: number; username: string; displayName: string; role: string; active: boolean; createdAt: Date; lastLoginAt: Date | null }) => ({
  id: u.id, username: u.username, displayName: u.displayName, role: u.role, active: u.active,
  createdAt: u.createdAt.toISOString(), lastLoginAt: u.lastLoginAt?.toISOString() ?? null,
});
const Password = z.string().min(12, `Password must be ${passwordRules}.`).max(200);

usersRouter.get("/", h(async (_req, res) => {
  const users = await prisma.user.findMany({ orderBy: { username: "asc" } });
  res.json({ users: users.map(out) });
}));

usersRouter.post("/", h(async (req, res) => {
  const b = z.object({
    username: z.string().trim().toLowerCase().regex(/^[a-z0-9._-]{2,64}$/, "Use 2–64 letters, digits, dot, dash or underscore."),
    displayName: z.string().trim().min(1).max(100),
    password: Password,
    role: z.enum(["admin", "analyst"]).default("analyst"),
  }).parse(req.body);
  if (await prisma.user.findUnique({ where: { username: b.username } })) throw conflict("That username is taken.");
  const u = await prisma.user.create({ data: { username: b.username, displayName: b.displayName, role: b.role, passwordHash: await hashPassword(b.password) } });
  await audit(req, "user.create", u.username, { role: u.role });
  res.status(201).json({ user: out(u) });
}));

/** Disable/enable, change role or name, or reset the password. */
usersRouter.patch("/:id", h(async (req, res) => {
  const admin = me(req);
  const id = Number(req.params.id);
  const b = z.object({
    displayName: z.string().trim().min(1).max(100).optional(),
    role: z.enum(["admin", "analyst"]).optional(),
    active: z.boolean().optional(),
    password: Password.optional(),
  }).parse(req.body);
  const u = await prisma.user.findUnique({ where: { id } });
  if (!u) throw notFound("User");
  if (id === admin.id && (b.active === false || b.role === "analyst")) throw badRequest("You can't disable yourself or remove your own admin role.");
  if ((b.active === false || b.role === "analyst") && u.role === "admin") {
    const admins = await prisma.user.count({ where: { role: "admin", active: true } });
    if (admins <= 1) throw badRequest("At least one active admin is required.");
  }
  const updated = await prisma.user.update({
    where: { id },
    data: { ...b.displayName ? { displayName: b.displayName } : {}, ...b.role ? { role: b.role } : {}, ...b.active !== undefined ? { active: b.active } : {}, ...b.password ? { passwordHash: await hashPassword(b.password) } : {} },
  });
  // A disabled user or a password reset ends their sessions.
  if (b.active === false || b.password) {
    const sessions = await prisma.session.findMany({ select: { sid: true, data: true } });
    const mine = sessions.filter((s) => { try { return (JSON.parse(s.data) as { user?: { id?: number } }).user?.id === id; } catch { return false; } }).map((s) => s.sid);
    if (mine.length) await prisma.session.deleteMany({ where: { sid: { in: mine } } });
  }
  await audit(req, "user.update", u.username, { changed: Object.keys(b).map((k) => (k === "password" ? "password(reset)" : k)), active: b.active, role: b.role });
  res.json({ user: out(updated) });
}));
