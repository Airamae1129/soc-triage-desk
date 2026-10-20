# Backend regression tests: config, OSINT lookup + cache, AI SSE stream, screenshot guard
import json
import os
import pytest
import requests

def _url():
    v = os.environ.get("REACT_APP_BACKEND_URL")
    if not v:
        for line in open("/app/frontend/.env"):
            if line.startswith("REACT_APP_BACKEND_URL="):
                v = line.split("=", 1)[1].strip()
    return v.rstrip("/")

BASE_URL = _url()
S = requests.Session()
CTX = "== TICKET FIELDS ==\nalertName: Outbound to rare IP\nclient: Northwind\n== RAW LOGS ==\n2025-06-02T08:01:00+08:00 srcip=10.1.1.5 dstip=203.0.113.9 dstport=443 action=accept sentbyte=1200 rcvdbyte=88000"


def sse(body, timeout=90):
    r = S.post(f"{BASE_URL}/api/ai/stream", json=body, stream=True, timeout=timeout)
    events = []
    if r.status_code != 200:
        return r, events
    for line in r.iter_lines(decode_unicode=True):
        if line and line.startswith("data:"):
            events.append(json.loads(line[5:].strip()))
    return r, events


# Config
def test_config():
    d = S.get(f"{BASE_URL}/api/config").json()
    assert d["ai"] is True
    assert d["model"] == "claude-sonnet-4-5-20250929"
    assert d["osint"] == {"abuseipdb": True, "virustotal": False, "urlscan": True}
    assert d["screenshot"] is True


# OSINT lookup
class TestOsint:
    def test_ip_lookup_and_cache(self):
        r = S.post(f"{BASE_URL}/api/osint/lookup", json={"type": "IP", "value": "8.8.8.8", "force": True}, timeout=40)
        assert r.status_code == 200
        d = r.json()
        assert d["cached"] is False
        assert "abuseipdb" in d["sources"], d
        assert "urlscan" in d["sources"], d
        assert d["errors"].get("virustotal") == "API key not configured"
        assert d["verdict"] in ("Clean", "Suspicious", "Malicious")
        assert "AbuseIPDB" in d["note"]
        r2 = S.post(f"{BASE_URL}/api/osint/lookup", json={"type": "IP", "value": "8.8.8.8"}, timeout=40).json()
        assert r2["cached"] is True
        assert r2["fetched_at"] == d["fetched_at"]
        r3 = S.post(f"{BASE_URL}/api/osint/lookup", json={"type": "IP", "value": "8.8.8.8", "force": True}, timeout=40).json()
        assert r3["cached"] is False
        assert r3["fetched_at"] != d["fetched_at"]

    @pytest.mark.parametrize("ip", ["10.0.0.1", "192.168.1.1", "127.0.0.1"])
    def test_private_ip_400(self, ip):
        r = S.post(f"{BASE_URL}/api/osint/lookup", json={"type": "IP", "value": ip})
        assert r.status_code == 400

    def test_invalid_ip_and_type(self):
        assert S.post(f"{BASE_URL}/api/osint/lookup", json={"type": "IP", "value": "999.1.1.1"}).status_code == 400
        assert S.post(f"{BASE_URL}/api/osint/lookup", json={"type": "Email", "value": "a@b.c"}).status_code == 400
        assert S.post(f"{BASE_URL}/api/osint/lookup", json={"type": "Domain", "value": "  "}).status_code == 400

    def test_domain(self):
        d = S.post(f"{BASE_URL}/api/osint/lookup", json={"type": "Domain", "value": "example.com"}, timeout=40).json()
        assert "urlscan" in d["sources"], d
        assert "abuseipdb" not in d["sources"]
        assert d["errors"].get("virustotal") == "API key not configured"
        assert d["type"] == "domain"

    def test_url(self):
        d = S.post(f"{BASE_URL}/api/osint/lookup", json={"type": "URL", "value": "https://example.com/"}, timeout=40).json()
        assert d["type"] == "url"
        assert "urlscan" in d["sources"] or "urlscan" in d["errors"], d

    def test_hash(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        d = S.post(f"{BASE_URL}/api/osint/lookup", json={"type": "SHA-256", "value": h}).json()
        assert d["type"] == "hash"
        assert d["sources"] == {}
        assert d["errors"] == {"virustotal": "API key not configured"}
        assert d["verdict"] == "Not checked"
        assert d["cached"] is False  # not cached when no sources


# AI streaming
class TestAi:
    def test_draft(self):
        r, ev = sse({"mode": "draft", "context": CTX})
        assert r.status_code == 200
        assert "text/event-stream" in r.headers["content-type"]
        assert ev and ev[-1] == {"done": True}, ev[-3:]
        text = "".join(e.get("t", "") for e in ev)
        assert "Assessment:" in text
        assert not any("error" in e for e in ev)

    def test_chat(self):
        r, ev = sse({"mode": "chat", "context": CTX, "messages": [{"role": "user", "content": "What is the destination IP? one line"}]})
        assert r.status_code == 200 and ev[-1] == {"done": True}
        assert "203.0.113.9" in "".join(e.get("t", "") for e in ev)

    def test_explain(self):
        r, ev = sse({"mode": "explain", "context": CTX, "line": "srcip=10.1.1.5 dstip=203.0.113.9 dstport=443 action=accept"})
        assert r.status_code == 200 and ev[-1] == {"done": True}
        assert len("".join(e.get("t", "") for e in ev)) > 50

    def test_chat_last_not_user_400(self):
        r = S.post(f"{BASE_URL}/api/ai/stream", json={"mode": "chat", "context": CTX, "messages": [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "x"}]})
        assert r.status_code == 400
        assert S.post(f"{BASE_URL}/api/ai/stream", json={"mode": "chat", "context": CTX, "messages": []}).status_code == 400

    def test_explain_no_line_400(self):
        assert S.post(f"{BASE_URL}/api/ai/stream", json={"mode": "explain", "context": CTX}).status_code == 400

    def test_bad_mode_422(self):
        assert S.post(f"{BASE_URL}/api/ai/stream", json={"mode": "x", "context": CTX}).status_code == 422


# Screenshot (only guard + usage; real call done separately once)
def test_screenshot_requires_confirm():
    r = S.post(f"{BASE_URL}/api/osint/screenshot", json={"url": "https://example.com"})
    assert r.status_code == 400
    assert "confirmation" in r.json()["detail"]


def test_screenshot_usage():
    d = S.get(f"{BASE_URL}/api/osint/screenshot/usage").json()
    assert isinstance(d["count"], int)
    assert "day" in d
