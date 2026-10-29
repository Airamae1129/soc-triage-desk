import { describe, it, expect, beforeAll } from "vitest";
import { XHR, makeUser, login } from "./helpers.js";
import { prisma } from "../src/db.js";

const playbook = { industry: "Test", matrix: [{ sev: "High", contact: "Desk", email: "desk@client.example", channel: "Email", sla: "1 hour" }], contacts: [], containment: "", benign: [], procedures: [] };

describe("role checks", () => {
  beforeAll(async () => { await makeUser("ana", "analyst"); await makeUser("root", "admin"); });

  it("analyst cannot manage users, edit playbooks or read the audit log", async () => {
    const a = await login("ana");
    expect((await a.get("/api/users")).status).toBe(403);
    expect((await a.post("/api/users").set(XHR).send({ username: "x1", displayName: "X", password: "long-enough-password" })).status).toBe(403);
    expect((await a.put("/api/playbooks/Acme%20Test").set(XHR).send(playbook)).status).toBe(403);
    expect((await a.get("/api/audit")).status).toBe(403);
    // ...but can read playbooks
    expect((await a.get("/api/playbooks")).status).toBe(200);
  });

  it("admin can create users, edit playbooks and read the audit log", async () => {
    const r = await login("root");
    const created = await r.post("/api/users").set(XHR).send({ username: "dave", displayName: "Dave", password: "long-enough-password", role: "analyst" });
    expect(created.status).toBe(201);
    expect(created.body.user.passwordHash).toBeUndefined();
    const pb = await r.put("/api/playbooks/Acme%20Test").set(XHR).send(playbook);
    expect(pb.status).toBe(200);
    expect(pb.body.playbook.client).toBe("Acme Test");
    const audit = await r.get("/api/audit?limit=50");
    expect(audit.status).toBe(200);
    expect(audit.body.entries.some((e: { action: string }) => e.action === "playbook.create")).toBe(true);
    expect(audit.body.entries.some((e: { action: string }) => e.action === "user.create")).toBe(true);
  });

  it("only the author or an admin can delete a note", async () => {
    await makeUser("eve", "analyst");
    const ana = await login("ana");
    const eve = await login("eve");
    const a = await ana.post("/api/assessments").set(XHR).send({ form: { client: "Acme Test", ticketId: "T-1", rawLogs: "x" }, snapshot: { sev: "Low" } });
    expect(a.status).toBe(201);
    const note = await ana.post(`/api/assessments/${a.body.assessment.id}/notes`).set(XHR).send({ type: "Investigation", text: "hello" });
    expect(note.status).toBe(201);
    expect((await eve.delete(`/api/notes/${note.body.note.id}`).set(XHR)).status).toBe(403);
    const root = await login("root");
    expect((await root.delete(`/api/notes/${note.body.note.id}`).set(XHR)).status).toBe(200);
  });

  it("writes audit entries for assessment changes without raw logs", async () => {
    const ana = await login("ana");
    await ana.post("/api/assessments").set(XHR).send({ form: { client: "Acme Test", ticketId: "T-2", rawLogs: "secretlogline srcip=1.2.3.4" }, snapshot: { sev: "High" } });
    const rows = await prisma.auditLog.findMany({ where: { action: { startsWith: "assessment." } } });
    expect(rows.length).toBeGreaterThan(0);
    expect(JSON.stringify(rows)).not.toContain("secretlogline");
  });
});
