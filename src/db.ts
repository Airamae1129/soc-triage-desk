import { PrismaClient } from "@prisma/client";
import { config } from "./config.js";

// One Prisma client for the whole process. Prisma only issues parameterized queries.
export const prisma = new PrismaClient({
  log: config.LOG_LEVEL === "debug" || config.LOG_LEVEL === "trace" ? ["warn", "error"] : ["error"],
});
