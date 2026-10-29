import type { ErrorRequestHandler, RequestHandler } from "express";
import { ZodError } from "zod";
import { logger } from "./logger.js";

/** Every API error goes out as { error: { code, message } }. */
export class AppError extends Error {
  constructor(public status: number, public code: string, message: string, public details?: unknown) {
    super(message);
  }
}

export const badRequest = (message: string, details?: unknown) => new AppError(400, "bad_request", message, details);
export const unauthorized = (message = "Please sign in.") => new AppError(401, "unauthorized", message);
export const forbidden = (message = "You don't have permission to do that.") => new AppError(403, "forbidden", message);
export const notFound = (what = "Item") => new AppError(404, "not_found", `${what} not found.`);
export const conflict = (message: string) => new AppError(409, "conflict", message);

/** Wraps async route handlers so thrown errors reach the error middleware (Express 5 also does this). */
export const h =
  (fn: (...a: Parameters<RequestHandler>) => Promise<unknown> | unknown): RequestHandler =>
  (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };

export const notFoundApi: RequestHandler = (_req, res) => {
  res.status(404).json({ error: { code: "not_found", message: "Unknown API route." } });
};

export const errorHandler: ErrorRequestHandler = (err, req, res, _next) => {
  if (err instanceof ZodError) {
    res.status(400).json({
      error: { code: "validation_error", message: "Some fields are missing or invalid.", details: err.issues.map((i) => ({ path: i.path.join("."), message: i.message })) },
    });
    return;
  }
  if (err instanceof AppError) {
    res.status(err.status).json({ error: { code: err.code, message: err.message, ...(err.details !== undefined ? { details: err.details } : {}) } });
    return;
  }
  // body-parser errors
  if (err && typeof err === "object" && "type" in err) {
    if (err.type === "entity.too.large") { res.status(413).json({ error: { code: "too_large", message: "Request is larger than 2 MB." } }); return; }
    if (err.type === "entity.parse.failed") { res.status(400).json({ error: { code: "bad_json", message: "Request body is not valid JSON." } }); return; }
  }
  logger.error({ err: { message: (err as Error)?.message, name: (err as Error)?.name }, path: req.path }, "Unhandled error");
  res.status(500).json({ error: { code: "internal", message: "Something went wrong on the server." } });
};
