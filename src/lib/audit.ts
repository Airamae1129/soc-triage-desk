import type { Request } from "express";
import { Prisma } from "@prisma/client";
import { prisma } from "../db.js";
import { logger } from "./logger.js";

// Audit trail. Details must never contain secrets or raw logs: callers pass small,
// structured summaries (ids, field names, counts), and long strings are cut as a guard.

const MAX_STR = 300;
function scrub(v: unknown, depth = 0): unknown {
  if (depth > 4) return "[…]";
  if (typeof v === "string") return v.length > MAX_STR ? `${v.slice(0, MAX_STR)}…` : v;
  if (Array.isArray(v)) return v.slice(0, 50).map((x) => scrub(x, depth + 1));
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) {
      if (/pass|secret|token|key|cookie|rawlogs|logs?$/i.test(k)) continue;
      out[k] = scrub(x, depth + 1);
    }
    return out;
  }
  return v;
}

export async function audit(req: Request | null, action: string, target = "", details?: Record<string, unknown>, userId?: number) {
  try {
    await prisma.auditLog.create({
      data: {
        userId: userId ?? req?.session?.user?.id ?? null,
        action,
        target,
        details: details ? (scrub(details) as Prisma.InputJsonValue) : Prisma.JsonNull,
        ip: req?.ip ?? "",
      },
    });
  } catch (err) {
    logger.error({ err: { message: (err as Error).message }, action }, "Audit write failed");
  }
}
