#!/usr/bin/env python3
"""CloudForge cross-studio e2e check (stdlib only).

Runs against services that are ALREADY running locally:
  Identity 8000 | Knowledge 8001 | Nova 8002 | Security 8003

Client secrets are read from Identity's .env (CLIENT_*_SECRET). Secrets and
tokens are never printed. Exit code 1 if any check FAILS.

Usage:
  python e2e.py --identity-env C:\\path\\to\\cloudforge-identity-service\\.env
"""
import argparse
import base64
import json
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

RESULTS = {"PASS": 0, "FAIL": 0, "WARN": 0}


def load_env(path: Path) -> dict:
    env = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, raw = line.partition("=")
        env[key.strip()] = raw.strip().strip('"').strip("'")
    return env


def call(method, url, headers=None, body=None, timeout=15):
    """Return (status, parsed_json_or_text). status 0 = connection error."""
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        status = exc.code
    except (urllib.error.URLError, OSError):
        return 0, "connection error"
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, raw


def report(kind, name, detail=""):
    RESULTS[kind] += 1
    print(f"[{kind}] {name}" + (f"  ({detail})" if detail else ""))


def check(name, got, expected):
    ok = got == expected if isinstance(expected, (tuple, list, set)) else got == expected
    report("PASS" if ok else "FAIL", name, "" if ok else f"expected {expected}, got {got}")
    return ok


def get_token(identity, secrets, client, scopes):
    basic = base64.b64encode(f"{client}:{secrets[client]}".encode()).decode()
    status, data = call(
        "POST", f"{identity}/token",
        headers={"Authorization": f"Basic {basic}"}, body={"scopes": scopes},
    )
    if status != 200 or not isinstance(data, dict) or "access_token" not in data:
        report("FAIL", f"token for {client} {scopes}", f"HTTP {status}")
        return None
    return data["access_token"]


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def tamper(token):
    head, payload, sig = token.split(".")
    return ".".join([head, payload, sig[:-1] + ("A" if sig[-1] != "A" else "B")])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--identity-env", required=True, help="path to Identity's .env")
    ap.add_argument("--identity", default="http://127.0.0.1:8000")
    ap.add_argument("--knowledge", default="http://127.0.0.1:8001")
    ap.add_argument("--nova", default="http://127.0.0.1:8002")
    ap.add_argument("--security", default="http://127.0.0.1:8003")
    args = ap.parse_args()

    env = load_env(Path(args.identity_env))
    secrets = {
        "nova-studio": env.get("CLIENT_NOVA_STUDIO_SECRET"),
        "security-studio": env.get("CLIENT_SECURITY_STUDIO_SECRET"),
        "knowledge-studio": env.get("CLIENT_KNOWLEDGE_STUDIO_SECRET"),
    }
    missing = [k for k, v in secrets.items() if not v]
    if missing:
        sys.exit(f"missing client secret(s) in .env for: {', '.join(missing)}")

    idn, kn, nv, sec = args.identity, args.knowledge, args.nova, args.security

    print("== identity")
    status, data = call("GET", f"{idn}/health")
    check("identity /health", status, 200)
    status, data = call("GET", f"{idn}/.well-known/jwks.json")
    keys = data.get("keys", []) if isinstance(data, dict) else []
    check("identity JWKS has exactly 1 RS256 key", (status, len(keys), keys[0].get("alg") if keys else None), (200, 1, "RS256"))

    tok_nova = get_token(idn, secrets, "nova-studio", ["nova:query", "knowledge:read"])
    tok_sec_r = get_token(idn, secrets, "security-studio", ["security:read"])
    tok_sec_w = get_token(idn, secrets, "security-studio", ["security:write"])
    tok_sec_rw = get_token(idn, secrets, "security-studio", ["security:read", "security:write"])
    tok_kn_w = get_token(idn, secrets, "knowledge-studio", ["knowledge:write"])
    if not all([tok_nova, tok_sec_r, tok_sec_w, tok_sec_rw, tok_kn_w]):
        print("\ncannot continue without tokens")
        sys.exit(1)

    print("\n== security")
    status, _ = call("GET", f"{sec}/health")
    check("security /health without token", status, 200)
    status, _ = call("GET", f"{sec}/findings")
    check("security /findings without Authorization", status, 401)
    status, _ = call("GET", f"{sec}/findings", headers=bearer("not.a.jwt"))
    check("security /findings malformed token", status, 401)
    status, _ = call("GET", f"{sec}/findings", headers=bearer(tamper(tok_sec_r)))
    check("security /findings tampered signature", status, 401)
    status, _ = call("GET", f"{sec}/findings", headers=bearer(tok_nova))
    check("security /findings valid token, wrong scope (nova)", status, 403)

    event = {
        "eventId": str(uuid.uuid4()),
        "eventType": "Finding.Created",
        "source": "e2e-runner",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload": {"severity": "HIGH", "title": "e2e finding", "resource": "e2e/test"},
    }
    status, _ = call("POST", f"{sec}/events", headers=bearer(tok_sec_r), body=event)
    check("security /events with security:read only", status, 403)
    status, data = call("POST", f"{sec}/events", headers=bearer(tok_sec_w), body=event)
    check("security /events with security:write", status, 202)
    status, _ = call("POST", f"{sec}/events", headers=bearer(tok_sec_w), body=event)
    check("security /events duplicate eventId", status, 409)
    status, data = call("GET", f"{sec}/findings", headers=bearer(tok_sec_rw))
    found = isinstance(data, dict) and any(f.get("eventId") == event["eventId"] for f in data.get("findings", []))
    check("security /findings returns the event we sent", (status, found), (200, True))

    print("\n== knowledge")
    status, _ = call("GET", f"{kn}/healthz")
    check("knowledge /healthz without token", status, 200)
    q = {"query": "cloudforge e2e marker", "top_k": 3}
    status, _ = call("POST", f"{kn}/api/v1/knowledge/query", body=q)
    check("knowledge /query without Authorization", status, 401)
    status, _ = call("POST", f"{kn}/api/v1/knowledge/query", headers=bearer(tamper(tok_nova)), body=q)
    check("knowledge /query tampered signature", status, 401)
    status, _ = call("POST", f"{kn}/api/v1/knowledge/ingest", headers=bearer(tok_nova),
                     body={"title": "x", "source": "e2e", "format": "text", "content": "x"})
    check("knowledge /ingest with knowledge:read only (nova token)", status, 403)
    doc = {"title": "e2e document", "source": "e2e", "format": "text",
           "content": "cloudforge e2e marker text for the knowledge store"}
    status, data = call("POST", f"{kn}/api/v1/knowledge/ingest", headers=bearer(tok_kn_w), body=doc)
    check("knowledge /ingest with knowledge:write", status, 201)
    status, data = call("POST", f"{kn}/api/v1/knowledge/query", headers=bearer(tok_nova), body=q)
    n = len(data.get("results", [])) if isinstance(data, dict) else 0
    check("knowledge /query with knowledge:read (nova token)", status, 200)
    if status == 200:
        report("PASS" if n >= 1 else "WARN", "knowledge /query returns at least 1 result", f"{n} result(s)")

    print("\n== nova")
    status, _ = call("GET", f"{nv}/health")
    check("nova /health without token", status, 200)
    body = {"question": "what is the cloudforge e2e marker?", "top_k": 3}
    status, _ = call("POST", f"{nv}/query", body=body)
    check("nova /query without Authorization", status, 401)
    status, _ = call("POST", f"{nv}/query", headers=bearer(tok_sec_r), body=body)
    check("nova /query valid token, wrong scope (security)", status, 403)
    status, _ = call("POST", f"{nv}/query", headers=bearer(tok_nova), body=body)
    if status == 200:
        report("PASS", "nova /query -> knowledge -> answer (full path)")
    else:
        report("WARN", "nova /query did not return 200", f"HTTP {status}; this step needs ANTHROPIC_API_KEY. "
               "Check the Knowledge window log for POST /api/v1/knowledge/query 200 to confirm Nova->Knowledge auth")

    print(f"\nsummary: {RESULTS['PASS']} passed, {RESULTS['FAIL']} failed, {RESULTS['WARN']} warnings")
    sys.exit(1 if RESULTS["FAIL"] else 0)


if __name__ == "__main__":
    main()
