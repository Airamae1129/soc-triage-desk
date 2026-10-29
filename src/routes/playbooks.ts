import { Router } from "express";
import { z } from "zod";
import { Prisma } from "@prisma/client";
import { prisma } from "../db.js";
import { h, notFound } from "../lib/errors.js";
import { audit } from "../lib/audit.js";
import { requireAdmin } from "../auth/middleware.js";
import { playbookOut } from "../lib/serialize.js";

export const playbooksRouter = Router();

const s = (max: number) => z.string().max(max).optional().default("");
export const PlaybookSchema = z.object({
  industry: s(200),
  reviewed: s(100),
  matrix: z.array(z.object({ sev: z.enum(["Critical", "High", "Medium", "Low"]), contact: s(300), email: s(300), channel: s(200), sla: s(50) })).max(10).default([]),
  contacts: z.array(z.object({ name: s(200), role: s(200), email: s(300), phone: s(100) })).max(50).default([]),
  containment: s(10_000),
  benign: z.array(z.string().max(1000)).max(200).default([]),
  procedures: z.array(z.object({ title: z.string().max(300), steps: z.array(z.string().max(2000)).max(100) })).max(100).default([]),
});

playbooksRouter.get("/", h(async (_req, res) => {
  const rows = await prisma.playbook.findMany({ orderBy: { client: "asc" } });
  res.json({ playbooks: rows.map(playbookOut) });
}));

playbooksRouter.get("/:client", h(async (req, res) => {
  const p = await prisma.playbook.findUnique({ where: { client: String(req.params.client) } });
  if (!p) throw notFound("Playbook");
  res.json({ playbook: playbookOut(p) });
}));

playbooksRouter.put("/:client", requireAdmin, h(async (req, res) => {
  const client = z.string().trim().min(1).max(200).parse(String(req.params.client));
  const b = PlaybookSchema.parse(req.body);
  const data = { ...b, matrix: b.matrix as Prisma.InputJsonValue, contacts: b.contacts as Prisma.InputJsonValue, benign: b.benign as Prisma.InputJsonValue, procedures: b.procedures as Prisma.InputJsonValue };
  const existed = await prisma.playbook.findUnique({ where: { client } });
  const p = await prisma.playbook.upsert({ where: { client }, create: { client, ...data }, update: data });
  await audit(req, existed ? "playbook.update" : "playbook.create", client, { rows: b.matrix.length, procedures: b.procedures.length, contacts: b.contacts.length });
  res.json({ playbook: playbookOut(p) });
}));

playbooksRouter.delete("/:client", requireAdmin, h(async (req, res) => {
  const client = String(req.params.client);
  const p = await prisma.playbook.findUnique({ where: { client } });
  if (!p) throw notFound("Playbook");
  await prisma.playbook.delete({ where: { client } });
  await audit(req, "playbook.delete", client);
  res.json({ ok: true });
}));
