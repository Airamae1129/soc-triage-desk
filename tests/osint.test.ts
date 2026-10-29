import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from "vitest";
import { XHR, makeUser, login, jsonResponse } from "./helpers.js";
import { prisma } from "../src/db.js";
import { setOsintFetch, resetLimiters } from "../src/osint/index.js";
import { validateIndicator } from "../src/osint/validate.js";
import { suggestVerdict, summaryLine } from "../src/osint/verdict.js";

const vtBody = (malicious: number) => ({ data: { attributes: { last_analysis_stats: { malicious, suspicious: 0, harmless: 60, undetected: 34 }, as_owner: "Example CDN", asn: 64500, country: "SG" } } });
const abuseBody = (score: number) => ({ data: { abuseConfidenceScore: score, totalReports: score ? 12 : 0, countryCode: "SG", isp: "Example CDN", usageType: "Content Delivery Network", isTor: false } });
const urlscanBody = { total: 3, results: [{ task: { time: "2026-06-01T00:00:00Z" }, page: { url: "https://x.example/" }, result: "https://urlscan.io/api/v1/result/abc/", verdicts: { malicious: false } }] };

function route(handlers: { abuse?: () => Promise<Response> | Response; vt?: () => Promise<Response> | Response; urlscan?: () => Promise<Response> | Response }) {
  return vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const u = String(url);
    const pick = u.includes("abuseipdb") ? handlers.abuse : u.includes("virustotal") ? handlers.vt : u.includes("urlscan") ? handlers.urlscan : undefined;
    if (!pick) throw new Error(`unexpected URL ${u}`);
    // honour AbortSignal like real fetch
    return new Promise<Response>((resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "TimeoutError" })));
      Promise.resolve(pick()).then(resolve, reject);
    });
  });
}

describe("OSINT", () => {
  let agent: Awaited<ReturnType<typeof login>>;
  beforeAll(async () => { await makeUser("osa", "analyst"); agent = await login("osa"); });
  beforeEach(async () => { await prisma.osintCache.deleteMany(); resetLimiters(); });
  afterEach(() => setOsintFetch(null));

  it("refuses private, reserved and internal indicators", async () => {
    for (const bad of ["10.0.0.5", "192.168.1.10", "172.16.4.4", "127.0.0.1", "169.254.1.1", "100.64.0.1", "fileserver01", "dc01.corp.local", "http://10.1.2.3/admin", "https://intranet.lan/x", "::1"]) {
      const r = await agent.post("/api/osint/lookup").set(XHR).send({ indicator: bad });
      expect(r.status, bad).toBe(400);
      expect(r.body.error.code).toBe("bad_request");
    }
    expect(() => validateIndicator("8.8.8.8")).not.toThrow();
    expect(validateIndicator("example[.]com").indicator).toBe("example.com");
  });

  it("returns per-provider status when one provider fails", async () => {
    const f = route({ abuse: () => jsonResponse(500, { errors: [{ detail: "boom" }] }), vt: () => jsonResponse(200, vtBody(0)), urlscan: () => jsonResponse(200, urlscanBody) });
    setOsintFetch(f as unknown as typeof fetch);
    const r = await agent.post("/api/osint/lookup").set(XHR).send({ indicator: "203.0.113.10" });
    expect(r.status).toBe(200);
    const by = Object.fromEntries(r.body.results.map((x: { provider: string; status: string }) => [x.provider, x.status]));
    expect(by).toEqual({ abuseipdb: "error", virustotal: "ok", shodan: "not_configured", otx: "not_configured" });
    expect(r.body.verdict).toBe("Not checked"); // not every configured provider answered
    expect(r.body.summary).toContain("VirusTotal – 0/94 malicious");
    // keys never reach the browser
    expect(JSON.stringify(r.body)).not.toMatch(/test-(abuseipdb|virustotal|urlscan)-key/);
  });

  it("times out a slow provider without failing the lookup", async () => {
    const f = route({ abuse: () => new Promise<Response>(() => {}), vt: () => jsonResponse(200, vtBody(0)) });
    setOsintFetch(f as unknown as typeof fetch);
    const t0 = Date.now();
    const r = await agent.post("/api/osint/lookup").set(XHR).send({ indicator: "203.0.113.11", providers: ["abuseipdb", "virustotal"] });
    expect(r.status).toBe(200);
    const abuse = r.body.results.find((x: { provider: string }) => x.provider === "abuseipdb");
    expect(abuse.status).toBe("error");
    expect(abuse.error).toMatch(/No answer within/);
    expect(Date.now() - t0).toBeLessThan(5000);
  });

  it("marks HTTP 429 as rate_limited", async () => {
    const f = route({ abuse: () => jsonResponse(429, {}, { "retry-after": "30" }), vt: () => jsonResponse(200, vtBody(0)) });
    setOsintFetch(f as unknown as typeof fetch);
    const r = await agent.post("/api/osint/lookup").set(XHR).send({ indicator: "203.0.113.12", providers: ["abuseipdb", "virustotal"] });
    expect(r.body.results.find((x: { provider: string }) => x.provider === "abuseipdb").status).toBe("rate_limited");
  });

  it("serves the second lookup from cache", async () => {
    const f = route({ abuse: () => jsonResponse(200, abuseBody(0)), vt: () => jsonResponse(200, vtBody(0)), urlscan: () => jsonResponse(200, urlscanBody) });
    setOsintFetch(f as unknown as typeof fetch);
    const first = await agent.post("/api/osint/lookup").set(XHR).send({ indicator: "203.0.113.13" });
    expect(first.body.results.every((x: { status: string; cached?: boolean }) => x.status === "not_configured" || x.cached === false)).toBe(true);
    expect(first.body.verdict).toBe("Clean");
    const calls = f.mock.calls.length;
    const second = await agent.post("/api/osint/lookup").set(XHR).send({ indicator: "203.0.113.13" });
    expect(f.mock.calls.length).toBe(calls); // no new provider calls
    const ok = second.body.results.filter((x: { status: string }) => x.status === "ok");
    expect(ok.length).toBe(2);
    expect(ok.every((x: { cached: boolean; fetchedAt: string }) => x.cached === true && !!x.fetchedAt)).toBe(true);
  });

  it("suggests verdicts per the rules", () => {
    const ok = (provider: string, data: unknown) => ({ provider, label: provider, status: "ok", data }) as never;
    expect(suggestVerdict([ok("abuseipdb", { score: 80 }), ok("virustotal", { found: true, malicious: 0 })])).toBe("Malicious");
    expect(suggestVerdict([ok("virustotal", { found: true, malicious: 3 })])).toBe("Malicious");
    expect(suggestVerdict([ok("virustotal", { found: true, malicious: 1 })])).toBe("Low risk");
    expect(suggestVerdict([ok("abuseipdb", { score: 30 })])).toBe("Low risk");
    expect(suggestVerdict([ok("virustotal", { found: true, malicious: 0, creationDate: new Date(Date.now() - 5 * 86400e3).toISOString() })])).toBe("Low risk");
    expect(suggestVerdict([ok("abuseipdb", { score: 0 }), ok("virustotal", { found: true, malicious: 0 })])).toBe("Clean");
    expect(suggestVerdict([ok("abuseipdb", { score: 10 }), ok("virustotal", { found: true, malicious: 0 })])).toBe("Low risk");
    expect(suggestVerdict([ok("abuseipdb", { score: 0 }), ok("virustotal", { found: true, malicious: 0, suspicious: 1 })])).toBe("Low risk");
    expect(suggestVerdict([ok("abuseipdb", { score: 24 })])).toBe("Low risk");
    expect(summaryLine([ok("abuseipdb", { score: 0, reports: 0 }), ok("virustotal", { found: true, malicious: 0, suspicious: 0, total: 94 })]))
      .toBe("AbuseIPDB – 0 reports, 0% confidence score · VirusTotal – 0/94 malicious");
  });

  it("standalone workspace adds several, rejects private ones and clears", async () => {
    const r = await agent.post("/api/osint/workspace").set(XHR).send({ indicators: ["8.8.8.8", "example.com", "10.0.0.5"] });
    expect(r.body.added).toEqual(["8.8.8.8", "example.com"]);
    expect(r.body.rejected[0].value).toBe("10.0.0.5");
    const hide = await agent.patch(`/api/osint/workspace/${encodeURIComponent("example.com")}`).set(XHR).send({ hidden: true, verdict: "Clean" });
    expect(hide.body.item).toMatchObject({ hidden: true, verdict: "Clean", manual: true });
    expect((await agent.delete("/api/osint/workspace").set(XHR)).status).toBe(200);
    expect((await agent.get("/api/osint/workspace")).body.items).toEqual([]);
  });
});
