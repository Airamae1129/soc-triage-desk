import { Router } from "express";
import { z } from "zod";
import { prisma } from "../db.js";
import { verifyPassword, dummyHash } from "./password.js";
import { AppError, h, unauthorized } from "../lib/errors.js";
import { audit } from "../lib/audit.js";
import { requireAuth, type Role } from "./middleware.js";

export const LOCKOUT_WINDOW_MS = 15 * 60e3;
export const LOCKOUT_MAX = 5;
const WRONG = "Wrong username or password.";

const Login = z.object({ username: z.string().trim().min(1).max(64), password: z.string().min(1).max(200) });

export const authRouter = Router();

authRouter.post("/login", h(async (req, res) => {
  const { username, password } = Login.parse(req.body);
  const uname = username.toLowerCase();
  const since = new Date(Date.now() - LOCKOUT_WINDOW_MS);

  const fails = await prisma.loginFailure.count({ where: { username: uname, at: { gte: since } } });
  if (fails >= LOCKOUT_MAX) {
    await audit(req, "auth.locked", uname);
    throw new AppError(429, "locked", "Too many failed sign-in attempts. Wait 15 minutes and try again.");
  }

  const user = await prisma.user.findUnique({ where: { username: uname } });
  const ok = await verifyPassword(password, user?.passwordHash ?? (await dummyHash()));
  if (!user || !ok || !user.active) {
    await prisma.loginFailure.create({ data: { username: uname } });
    await audit(req, "auth.login_failed", uname, undefined, user?.id);
    throw new AppError(401, "bad_credentials", WRONG);
  }

  await prisma.loginFailure.deleteMany({ where: { username: uname } });
  await prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });
  const sessionUser = { id: user.id, username: user.username, displayName: user.displayName, role: user.role as Role };

  // New session id on login (prevents session fixation).
  await new Promise<void>((resolve, reject) => req.session.regenerate((err) => (err ? reject(err) : resolve())));
  req.session.user = sessionUser;
  await new Promise<void>((resolve, reject) => req.session.save((err) => (err ? reject(err) : resolve())));
  await audit(req, "auth.login", user.username, undefined, user.id);
  res.json({ user: sessionUser });
}));

authRouter.post("/logout", h(async (req, res) => {
  const u = req.session.user;
  if (u) await audit(req, "auth.logout", u.username);
  await new Promise<void>((resolve) => req.session.destroy(() => resolve()));
  res.clearCookie("socdesk.sid");
  res.json({ ok: true });
}));

authRouter.get("/me", requireAuth, h(async (req, res) => {
  const u = req.session.user;
  if (!u) throw unauthorized();
  // Re-check the account is still active (an admin may have disabled it).
  const row = await prisma.user.findUnique({ where: { id: u.id } });
  if (!row || !row.active) {
    await new Promise<void>((resolve) => req.session.destroy(() => resolve()));
    throw unauthorized("Your account is disabled.");
  }
  res.json({ user: { id: row.id, username: row.username, displayName: row.displayName, role: row.role } });
}));
