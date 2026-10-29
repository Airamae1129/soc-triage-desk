import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";
import { app, XHR, makeUser, login, PASSWORD } from "./helpers.js";
import { prisma } from "../src/db.js";

describe("auth flow", () => {
  beforeAll(async () => { await makeUser("alice", "analyst"); });

  it("rejects API calls without a session", async () => {
    const res = await request(app).get("/api/assessments");
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe("unauthorized");
  });

  it("signs in, returns the user, then signs out", async () => {
    const agent = request.agent(app);
    const bad = await agent.post("/api/auth/login").set(XHR).send({ username: "alice", password: "nope-nope-nope" });
    expect(bad.status).toBe(401);
    expect(bad.body.error.message).toBe("Wrong username or password.");

    const ok = await agent.post("/api/auth/login").set(XHR).send({ username: "Alice", password: PASSWORD });
    expect(ok.status).toBe(200);
    expect(ok.body.user).toMatchObject({ username: "alice", role: "analyst" });
    const cookie = String(ok.headers["set-cookie"]);
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/SameSite=Strict/i);
    expect(ok.body.user.passwordHash).toBeUndefined();

    const me = await agent.get("/api/auth/me");
    expect(me.status).toBe(200);
    expect(me.body.user.username).toBe("alice");

    expect((await agent.post("/api/auth/logout").set(XHR)).status).toBe(200);
    expect((await agent.get("/api/auth/me")).status).toBe(401);
  });

  it("uses the same error for an unknown username", async () => {
    const res = await request(app).post("/api/auth/login").set(XHR).send({ username: "nobody", password: "whatever-123" });
    expect(res.status).toBe(401);
    expect(res.body.error.message).toBe("Wrong username or password.");
  });

  it("requires X-Requested-With on state-changing requests (CSRF)", async () => {
    const res = await request(app).post("/api/auth/login").send({ username: "alice", password: PASSWORD });
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe("csrf");
  });

  it("locks the username after 5 failed attempts in 15 minutes", async () => {
    await makeUser("bob", "analyst");
    for (let i = 0; i < 5; i++) {
      const r = await request(app).post("/api/auth/login").set(XHR).send({ username: "bob", password: `wrong-password-${i}` });
      expect(r.status).toBe(401);
    }
    // Even the right password is refused while locked.
    const locked = await request(app).post("/api/auth/login").set(XHR).send({ username: "bob", password: PASSWORD });
    expect(locked.status).toBe(429);
    expect(locked.body.error.code).toBe("locked");
    // Lockout expires: age the failures past the window.
    await prisma.loginFailure.updateMany({ where: { username: "bob" }, data: { at: new Date(Date.now() - 16 * 60e3) } });
    const ok = await request(app).post("/api/auth/login").set(XHR).send({ username: "bob", password: PASSWORD });
    expect(ok.status).toBe(200);
  });

  it("blocks a disabled account", async () => {
    await makeUser("carol", "analyst");
    const agent = await login("carol");
    await prisma.user.update({ where: { username: "carol" }, data: { active: false } });
    expect((await agent.get("/api/auth/me")).status).toBe(401);
    const r = await request(app).post("/api/auth/login").set(XHR).send({ username: "carol", password: PASSWORD });
    expect(r.status).toBe(401);
  });

  it("health endpoint has no secrets", async () => {
    const r = await request(app).get("/api/health");
    expect(r.status).toBe(200);
    const text = JSON.stringify(r.body);
    expect(text).not.toMatch(/test-.*-key|session-secret/i);
  });
});
