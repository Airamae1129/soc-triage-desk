import request from "supertest";
import { createApp } from "../src/server.js";
import { prisma } from "../src/db.js";
import { hashPassword } from "../src/auth/password.js";

export const { app, store } = createApp();
export const XHR = { "X-Requested-With": "XMLHttpRequest" };
export const PASSWORD = "correct-horse-battery";

const hashCache = new Map<string, string>();
export async function makeUser(username: string, role: "admin" | "analyst" = "analyst", password = PASSWORD) {
  const passwordHash = hashCache.get(password) ?? (await hashPassword(password));
  hashCache.set(password, passwordHash);
  return prisma.user.upsert({ where: { username }, create: { username, displayName: username.toUpperCase(), role, passwordHash }, update: { role, passwordHash, active: true } });
}

/** A supertest agent that is signed in (keeps the session cookie). */
export async function login(username: string, password = PASSWORD) {
  const agent = request.agent(app);
  const res = await agent.post("/api/auth/login").set(XHR).send({ username, password });
  if (res.status !== 200) throw new Error(`login failed: ${res.status} ${JSON.stringify(res.body)}`);
  return agent;
}

/** Minimal fetch Response for mocked providers. */
export function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}
