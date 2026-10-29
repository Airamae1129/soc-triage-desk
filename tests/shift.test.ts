import { describe, it, expect, beforeAll } from "vitest";
import { shiftOf, shiftWindow } from "../src/lib/shift.js";
import { XHR, makeUser, login } from "./helpers.js";
import { prisma } from "../src/db.js";

describe("Manila shift grouping", () => {
  it("assigns shifts in UTC+08:00", () => {
    expect(shiftOf(new Date("2026-06-02T00:30:00Z"))).toMatchObject({ name: "Morning", key: "2026-06-02|Morning" }); // 08:30 Manila
    expect(shiftOf(new Date("2026-06-02T06:00:00Z"))).toMatchObject({ name: "Mid", key: "2026-06-02|Mid" }); // 14:00
    expect(shiftOf(new Date("2026-06-02T14:30:00Z"))).toMatchObject({ name: "Night", key: "2026-06-02|Night" }); // 22:30 Jun 2
  });

  it("keeps the Night shift on the date it started, across midnight", () => {
    // 03:00 Manila on Jun 3 belongs to the Night shift of Jun 2.
    expect(shiftOf(new Date("2026-06-02T19:00:00Z"))).toMatchObject({ name: "Night", date: "2026-06-02", key: "2026-06-02|Night" });
    // 05:59 Manila Jun 3 → still Jun 2 Night; 06:00 → Jun 3 Morning
    expect(shiftOf(new Date("2026-06-02T21:59:00Z")).key).toBe("2026-06-02|Night");
    expect(shiftOf(new Date("2026-06-02T22:00:00Z")).key).toBe("2026-06-03|Morning");
    const w = shiftWindow("2026-06-02", "Night");
    expect(w.start.toISOString()).toBe("2026-06-02T14:00:00.000Z");
    expect(w.end.toISOString()).toBe("2026-06-02T22:00:00.000Z");
  });

  describe("GET /api/notables", () => {
    beforeAll(async () => {
      await makeUser("nina", "analyst");
      const base = { client: "Shift Co", rawLogs: "", findings: "" };
      await prisma.assessment.createMany({ data: [
        { ...base, ticket: "N-1", escalatedAt: new Date("2026-06-02T15:00:00Z") }, // 23:00 Jun 2 → Night Jun 2
        { ...base, ticket: "N-2", escalatedAt: new Date("2026-06-02T20:30:00Z") }, // 04:30 Jun 3 → Night Jun 2
        { ...base, ticket: "N-3", escalatedAt: new Date("2026-06-02T22:30:00Z") }, // 06:30 Jun 3 → Morning Jun 3
      ] });
    });

    it("returns the escalations of one shift", async () => {
      const a = await login("nina");
      const r = await a.get("/api/notables").query({ shift: "2026-06-02|Night" });
      expect(r.status).toBe(200);
      expect(r.body.notables.map((n: { form: { ticketId: string } }) => n.form.ticketId)).toEqual(["N-1", "N-2"]);
      const bad = await a.get("/api/notables").query({ shift: "yesterday" });
      expect(bad.status).toBe(400);
      const all = await a.get("/api/notables").set(XHR);
      expect(Object.keys(all.body.groups)).toEqual(expect.arrayContaining(["2026-06-02|Night", "2026-06-03|Morning"]));
    });
  });
});
