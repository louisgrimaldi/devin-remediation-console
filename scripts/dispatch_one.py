#!/usr/bin/env python3
"""Dispatch ONE real Devin session against a real issue on the fork, then print
the session URL. Used for the live demo (keeps credit usage to a single session).

Prefer driving through the running service (simulate_webhook.py) so the reconciler
and dashboard track it. This script is the direct path for a controlled one-shot.

Usage:
    python scripts/dispatch_one.py --issue 1
    python scripts/dispatch_one.py --issue 1 --title "..." --body "..."

Reads the issue from GitHub if --title/--body are omitted.
"""
from __future__ import annotations

import argparse
import sys

import httpx

sys.path.insert(0, ".")

from app.config import settings  # noqa: E402
from app.db import Store  # noqa: E402
from app.devin import DevinClient  # noqa: E402
from app.pipeline import remediate_issue  # noqa: E402


def fetch_issue(repo: str, number: int) -> dict:
    with httpx.Client(timeout=20.0) as c:
        r = c.get(
            f"https://api.github.com/repos/{repo}/issues/{number}",
            headers={
                "Authorization": f"Bearer {settings.github_token}",
                "Accept": "application/vnd.github+json",
            },
        )
        r.raise_for_status()
        return r.json()


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--issue", type=int, required=True)
    p.add_argument("--title")
    p.add_argument("--body")
    args = p.parse_args()

    title, body, url = args.title, args.body, None
    if not (title and body):
        issue = fetch_issue(settings.target_repo, args.issue)
        title = title or issue["title"]
        body = body or (issue.get("body") or "")
        url = issue.get("html_url")
    url = url or f"https://github.com/{settings.target_repo}/issues/{args.issue}"

    store = Store(settings.db_path)
    devin = DevinClient()
    result = remediate_issue(
        store, devin, issue_number=args.issue, title=title, body=body, url=url
    )
    print(f"issue:      #{args.issue}  {title}")
    print(f"session_id: {result.get('devin_session_id')}")
    print(f"devin_url:  {result.get('devin_url')}")
    devin.close()


if __name__ == "__main__":
    main()
