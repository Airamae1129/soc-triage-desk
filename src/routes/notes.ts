import { Router } from "express";
import { prisma } from "../db.js";
import { h, notFound, forbidden, badRequest } from "../lib/errors.js";
import { audit } from "../lib/audit.js";
import { me } from "../auth/middleware.js";

export const notesRouter = Router();

/** Author or admin only. */
notesRouter.delete("/:id", h(async (req, res) => {
  const user = me(req);
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) throw badRequest("Bad id.");
  const n = await prisma.note.findUnique({ where: { id }, include: { assessment: { select: { client: true, ticket: true } } } });
  if (!n) throw notFound("Note");
  if (n.authorId !== user.id && user.role !== "admin") throw forbidden("Only the note's author or an admin can delete it.");
  await prisma.note.delete({ where: { id } });
  await audit(req, "note.delete", `${n.assessment.client} / ${n.assessment.ticket}`, { noteId: id, type: n.type });
  res.json({ ok: true });
}));
