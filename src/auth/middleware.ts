import type { RequestHandler } from "express";
import { forbidden, unauthorized, AppError } from "../lib/errors.js";

export type Role = "admin" | "analyst";
export interface SessionUser { id: number; username: string; displayName: string; role: Role }

declare module "express-session" {
  interface SessionData {
    user?: SessionUser;
  }
}

/** Every /api route except login requires a signed-in session. */
export const requireAuth: RequestHandler = (req, _res, next) => {
  if (!req.session?.user) return next(unauthorized());
  next();
};

export const requireAdmin: RequestHandler = (req, _res, next) => {
  if (!req.session?.user) return next(unauthorized());
  if (req.session.user.role !== "admin") return next(forbidden("Only an admin can do that."));
  next();
};

/**
 * CSRF guard: state-changing requests must carry X-Requested-With: XMLHttpRequest.
 * A cross-site form can't set custom headers, and the session cookie is sameSite=strict.
 */
export const requireXhrHeader: RequestHandler = (req, _res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  if (req.get("X-Requested-With") !== "XMLHttpRequest") return next(new AppError(403, "csrf", "Missing X-Requested-With header."));
  next();
};

export const me = (req: Parameters<RequestHandler>[0]): SessionUser => {
  const u = req.session?.user;
  if (!u) throw unauthorized();
  return u;
};
