#!/usr/bin/env python3
"""Send a GitHub-shaped `issues.labeled` webhook to the local service, signed
with the shared secret. Lets you demo the full event → Devin flow deterministically
without exposing a public URL or configuring a real GitHub webhook.

Usage:
    python scripts/simulate_webhook.py --issue 42 --title "Add request timeouts" \
        --body "requests.get() calls lack a timeout (bandit B113)."

If --issue is omitted, a synthetic issue is used (no real GitHub issue needed;
handy for exercising the wiring). To drive a REAL issue end-to-end, pass the real
issue number/title/body so Devin operates on something that exists in the repo.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os

import httpx
from dotenv import load_dotenv

load_dotenv()


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="http://localhost:8000/webhook")
    p.add_argument("--issue", type=int, default=9999)
    p.add_argument("--title", default="[demo] Add missing request timeouts")
    p.add_argument("--body", default="HTTP calls without a timeout can hang forever (bandit B113).")
    p.add_argument("--repo", default=os.getenv("TARGET_REPO", "louisgrimaldi/superset"))
    p.add_argument("--label", default=os.getenv("TRIGGER_LABEL", "devin"))
    args = p.parse_args()

    payload = {
        "action": "labeled",
        "issue": {
            "number": args.issue,
            "title": args.title,
            "body": args.body,
            "html_url": f"https://github.com/{args.repo}/issues/{args.issue}",
            "labels": [{"name": args.label}],
        },
        "repository": {"full_name": args.repo},
        "label": {"name": args.label},
    }
    raw = json.dumps(payload).encode()

    headers = {"X-GitHub-Event": "issues", "Content-Type": "application/json"}
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    if secret:
        sig = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
        headers["X-Hub-Signature-256"] = sig

    resp = httpx.post(args.url, content=raw, headers=headers, timeout=30.0)
    print(f"→ {resp.status_code} {resp.text}")


if __name__ == "__main__":
    main()
