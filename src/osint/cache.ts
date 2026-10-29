import { Prisma } from "@prisma/client";
import { prisma } from "../db.js";
import { config } from "../config.js";
import type { ProviderName } from "./types.js";

/** Provider answers are reused for OSINT_CACHE_HOURS (successful answers only). */
export async function cacheGet(provider: ProviderName, indicator: string): Promise<{ data: unknown; fetchedAt: Date } | null> {
  if (config.OSINT_CACHE_HOURS <= 0) return null;
  const row = await prisma.osintCache.findUnique({ where: { provider_indicator: { provider, indicator } } });
  if (!row) return null;
  if (row.fetchedAt.getTime() < Date.now() - config.OSINT_CACHE_HOURS * 3600e3) return null;
  return { data: row.response, fetchedAt: row.fetchedAt };
}

export async function cacheSet(provider: ProviderName, indicator: string, data: unknown): Promise<Date> {
  const fetchedAt = new Date();
  const response = data as Prisma.InputJsonValue;
  await prisma.osintCache.upsert({
    where: { provider_indicator: { provider, indicator } },
    create: { provider, indicator, response, fetchedAt },
    update: { response, fetchedAt },
  });
  return fetchedAt;
}
