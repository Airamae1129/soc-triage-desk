from fastapi import FastAPI, APIRouter, HTTPException
from fastapi.responses import StreamingResponse, Response
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel
from typing import List, Literal, Optional
from datetime import datetime, timezone, timedelta
from pathlib import Path
import base64
import ipaddress
import json
import logging
import os
import uuid
import httpx
from emergentintegrations.llm.chat import LlmChat, UserMessage, TextDelta, StreamDone

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

client = AsyncIOMotorClient(os.environ["MONGO_URL"])
db = client[os.environ["DB_NAME"]]
LLM_KEY = os.environ.get("EMERGENT_LLM_KEY", "")
MODEL = ("anthropic", "claude-sonnet-4-5-20250929")
CACHE_TTL = timedelta(hours=24)

app = FastAPI()
api = APIRouter(prefix="/api")
logger = logging.getLogger("soc")
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")


def key(name: str) -> str:
    return os.environ.get(name, "").strip()


@api.get("/")
async def root():
    return {"message": "SOC Triage Desk API"}


@api.get("/config")
async def config():
    return {
        "ai": bool(LLM_KEY),
        "model": MODEL[1],
        "osint": {"abuseipdb": bool(key("ABUSEIPDB_API_KEY")), "virustotal": bool(key("VIRUSTOTAL_API_KEY")), "urlscan": bool(key("URLSCAN_API_KEY"))},
        "screenshot": bool(key("SCREENSHOTBASE_API_KEY")),
    }


# ---------------- AI ----------------
REPORT_FORMAT = """ASSESSMENT REPORT format (exact):
Assessment:
- Alert “<rule>” (<MITRE ID>, <tactic>) triggered on external IP `<ip>`. <rule logic>
- <N> internal hosts contacted the IP over <service> (port <p>): `<ip1>` and `<ip2>`. Traffic occurred between <Mon D, YYYY at h:mm AM/PM> and <...>.
- Traffic pattern indicates downloads, not exfiltration.
  - `<ip>`: <n> connections, ~<KB/MB> sent, ~<KB/MB> received.
- <Firewall vendor> classified traffic as `<appcat / service>`. No hostname/URL logged; sessions ended with normal <actions> actions.
- Destination `<ip>` belongs to <owner> (<ASN>, <location>). <IP type>. <Reputation sentence>.
- <each line of analyst findings as its own bullet>

Verdict: <verdict> (<risk> risk). <one-sentence reason>, <closure>.   <- maximum 2 sentences

Alert Details / Indicators:
One "Key: value" per line, leave out empty fields. Firewall alerts use: Alert, Alert ID, Analytics rule, Detection source, Service source, Category, MITRE ATT&CK, Severity, Status, Classification, Incident created, Activity window (alert), Activity window (firewall logs), Destination IP, ASN, Owner, Location, IP type, Reputation, Source IPs (internal), Destination port, Protocol, Total connections (per-source breakdown), Bytes sent / received (mostly inbound/outbound), Firewall actions, App category, Hostname / URL, User, Log source, MDE telemetry.
Non-firewall alerts replace the firewall-specific keys with: Hosts, Users, Source / internal IPs, External IPs, Domains, URLs, File hashes, Parent processes, Security control action.
For non-firewall alerts, the Assessment bullets describe what happened on the host/user (techniques, IPs, hashes, mitigation, time window) in the same terse bullet style."""

BASE_RULES = """You are a senior SOC analyst assistant inside "SOC Triage Desk". Be precise, terse and factual.
Never invent facts that are not in the logs, findings, enrichment or OSINT results. If something is unknown, say so.
All times are Asia/Manila (UTC+08:00). Plain text only: no markdown headings, no bold, no tables. Backticks around IPs, hosts, hashes and users are allowed."""

SYSTEMS = {
    "draft": BASE_RULES + "\n\nTask: write the Assessment report for the ticket in EXACTLY this format.\n\n" + REPORT_FORMAT
    + "\n\nA rule-based draft is included in the context. Keep its structure, keys and numbers unless the logs prove them wrong; you may improve wording and add insight drawn from the logs and findings. Verdict section: maximum 2 sentences. Output ONLY the report text, starting with 'Assessment:'.",
    "chat": BASE_RULES + "\n\nTask: answer the analyst's questions about the current ticket using the ticket context. Keep answers short (under 180 words unless asked for more). Suggest concrete next checks or queries when useful.",
    "explain": BASE_RULES + "\n\nTask: explain the single log line the analyst selected in plain language for a junior analyst. Format: 1) What it is (source / event type), 2) What it says (key fields decoded), 3) Why it matters for this alert, 4) What to check next. Under 160 words. Decode Base64 / -enc PowerShell if present.",
}


class Msg(BaseModel):
    role: Literal["user", "assistant"]
    content: str


class AiRequest(BaseModel):
    mode: Literal["draft", "chat", "explain"]
    context: str
    messages: List[Msg] = []
    line: Optional[str] = None


@api.post("/ai/stream")
async def ai_stream(req: AiRequest):
    if not LLM_KEY:
        raise HTTPException(503, "AI is not configured")
    ctx = req.context[:60000]
    system = SYSTEMS[req.mode] + "\n\n=== TICKET CONTEXT ===\n" + ctx
    history = [{"role": "system", "content": system}]
    if req.mode == "chat":
        if not req.messages or req.messages[-1].role != "user":
            raise HTTPException(400, "Last message must be from the user")
        history += [{"role": m.role, "content": m.content} for m in req.messages[-20:-1]]
        prompt = req.messages[-1].content
    elif req.mode == "explain":
        if not req.line:
            raise HTTPException(400, "line is required")
        prompt = f"Explain this log line:\n{req.line[:4000]}"
    else:
        prompt = "Write the Assessment report now."
    chat = LlmChat(api_key=LLM_KEY, session_id=str(uuid.uuid4()), system_message=system, initial_messages=history).with_model(*MODEL)

    async def gen():
        try:
            async for ev in chat.stream_message(UserMessage(text=prompt)):
                if isinstance(ev, TextDelta):
                    yield f"data: {json.dumps({'t': ev.content})}\n\n"
                elif isinstance(ev, StreamDone):
                    break
            yield "data: {\"done\": true}\n\n"
        except Exception as e:  # surface provider errors to the UI
            logger.exception("AI stream failed")
            yield f"data: {json.dumps({'error': str(e)[:300]})}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------- OSINT ----------------
class OsintRequest(BaseModel):
    type: str
    value: str
    force: bool = False


def kind_of(t: str) -> str:
    t = t.lower()
    return "hash" if t in ("sha-256", "md5", "hash", "sha256") else t


async def abuseipdb(c: httpx.AsyncClient, ip: str):
    r = await c.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": key("ABUSEIPDB_API_KEY"), "Accept": "application/json"})
    r.raise_for_status()
    d = r.json().get("data", {})
    return {"score": d.get("abuseConfidenceScore"), "reports": d.get("totalReports"), "isp": d.get("isp"), "country": d.get("countryCode"),
            "usage": d.get("usageType"), "domain": d.get("domain"), "whitelisted": d.get("isWhitelisted"), "last_reported": d.get("lastReportedAt")}


async def virustotal(c: httpx.AsyncClient, kind: str, value: str):
    if kind == "ip":
        path = f"ip_addresses/{value}"
    elif kind == "domain":
        path = f"domains/{value}"
    elif kind == "url":
        path = "urls/" + base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    else:
        path = f"files/{value}"
    r = await c.get(f"https://www.virustotal.com/api/v3/{path}", headers={"x-apikey": key("VIRUSTOTAL_API_KEY")})
    if r.status_code == 404:
        return {"found": False}
    r.raise_for_status()
    a = r.json().get("data", {}).get("attributes", {})
    s = a.get("last_analysis_stats", {})
    return {"found": True, "malicious": s.get("malicious", 0), "suspicious": s.get("suspicious", 0), "harmless": s.get("harmless", 0),
            "undetected": s.get("undetected", 0), "total": sum(v for v in s.values() if isinstance(v, int)), "as_owner": a.get("as_owner"), "asn": a.get("asn"), "country": a.get("country")}


async def urlscan(c: httpx.AsyncClient, kind: str, value: str):
    q = {"ip": f"ip:{value}", "domain": f"domain:{value}", "url": f'page.url:"{value}"'}[kind]
    r = await c.get("https://urlscan.io/api/v1/search/", params={"q": q, "size": 10}, headers={"API-Key": key("URLSCAN_API_KEY")})
    r.raise_for_status()
    j = r.json()
    res = j.get("results", [])
    mal = sum(1 for x in res if (x.get("verdicts") or {}).get("malicious") or ((x.get("verdicts") or {}).get("overall") or {}).get("malicious"))
    latest = res[0] if res else None
    return {"hits": j.get("total", len(res)), "malicious": mal,
            "latest": latest and {"time": latest.get("task", {}).get("time"), "url": latest.get("page", {}).get("url"), "result": latest.get("result")}}


def verdict_of(src: dict):
    a, v, u = src.get("abuseipdb", {}), src.get("virustotal", {}), src.get("urlscan", {})
    notes = []
    if "score" in a:
        notes.append(f"AbuseIPDB {a['score']}% ({a.get('reports', 0)} reports{', ' + a['isp'] if a.get('isp') else ''})")
    if v.get("found"):
        notes.append(f"VT {v['malicious']}/{v['total']}")
    elif v.get("found") is False:
        notes.append("VT not found")
    if "hits" in u:
        notes.append(f"urlscan {u['hits']} scans" + (f", {u['malicious']} malicious" if u.get("malicious") else ""))
    sc, vm, vs, um = a.get("score") or 0, v.get("malicious") or 0, v.get("suspicious") or 0, u.get("malicious") or 0
    checked = any(k in a for k in ("score",)) or "found" in v or "hits" in u
    if not checked:
        verdict = "Not checked"
    elif sc >= 75 or vm >= 3:
        verdict = "Malicious"
    elif sc >= 25 or vm >= 1 or vs >= 2 or um >= 1:
        verdict = "Suspicious"
    else:
        verdict = "Clean"
    return verdict, ", ".join(notes)


@api.post("/osint/lookup")
async def osint_lookup(req: OsintRequest):
    kind = kind_of(req.type)
    value = req.value.strip()
    if kind not in ("ip", "domain", "url", "hash") or not value:
        raise HTTPException(400, "Unsupported indicator type")
    if kind == "ip":
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            raise HTTPException(400, "Invalid IP")
        if not ip.is_global:
            raise HTTPException(400, "Private or reserved IPs are not looked up")
    ck = f"{kind}:{value.lower()}"
    now = datetime.now(timezone.utc)
    if not req.force:
        hit = await db.osint_cache.find_one({"key": ck}, {"_id": 0})
        if hit and datetime.fromisoformat(hit["fetched_at"]) > now - CACHE_TTL:
            return {**hit["result"], "cached": True, "fetched_at": hit["fetched_at"]}
    sources, errors = {}, {}
    jobs = []
    if kind == "ip":
        jobs.append(("abuseipdb", "ABUSEIPDB_API_KEY", lambda c: abuseipdb(c, value)))
    jobs.append(("virustotal", "VIRUSTOTAL_API_KEY", lambda c: virustotal(c, kind, value)))
    if kind != "hash":
        jobs.append(("urlscan", "URLSCAN_API_KEY", lambda c: urlscan(c, kind, value)))
    async with httpx.AsyncClient(timeout=15) as c:
        for name, env, fn in jobs:
            if not key(env):
                errors[name] = "API key not configured"
                continue
            try:
                sources[name] = await fn(c)
            except httpx.HTTPStatusError as e:
                errors[name] = f"HTTP {e.response.status_code}"
            except Exception as e:
                errors[name] = str(e)[:120] or e.__class__.__name__
    verdict, note = verdict_of(sources)
    result = {"value": value, "type": kind, "sources": sources, "errors": errors, "verdict": verdict, "note": note}
    if sources:
        await db.osint_cache.update_one({"key": ck}, {"$set": {"key": ck, "result": result, "fetched_at": now.isoformat()}}, upsert=True)
    return {**result, "cached": False, "fetched_at": now.isoformat()}


class ShotRequest(BaseModel):
    url: str
    confirmed: bool = False


@api.get("/osint/screenshot/usage")
async def shot_usage():
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    doc = await db.screenshot_usage.find_one({"day": day}, {"_id": 0})
    return {"day": day, "count": (doc or {}).get("count", 0)}


@api.post("/osint/screenshot")
async def screenshot(req: ShotRequest):
    if not req.confirmed:
        raise HTTPException(400, "Screenshot needs explicit confirmation")
    if not key("SCREENSHOTBASE_API_KEY"):
        raise HTTPException(503, "Screenshot API key not configured")
    url = req.url.strip()
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    async with httpx.AsyncClient(timeout=60) as c:
        r = await c.get("https://api.screenshotbase.com/v1/take",
                        params={"url": url, "format": "png", "viewport_width": 1280, "viewport_height": 800},
                        headers={"apikey": key("SCREENSHOTBASE_API_KEY")})
    if r.status_code != 200 or not r.headers.get("content-type", "").startswith("image"):
        raise HTTPException(502, f"Screenshot failed (HTTP {r.status_code}): {r.text[:200]}")
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    await db.screenshot_usage.update_one({"day": day}, {"$inc": {"count": 1}}, upsert=True)
    return Response(content=r.content, media_type="image/png")


app.include_router(api)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
