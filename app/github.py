"""GitHub helpers: verify webhook signatures, comment PR links back on issues,
and poll for labeled issues (a URL-free alternative trigger for demos)."""
from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Any, Optional

import httpx

from .config import settings
from .logging_setup import log

logger = logging.getLogger("github")

_API = "https://api.github.com"


def verify_signature(body: bytes, signature_header: Optional[str]) -> bool:
    """Validate the X-Hub-Signature-256 header against the shared secret."""
    if not settings.github_webhook_secret:
        # No secret configured -> accept (explicitly opt-out, for local demos).
        return True
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(
        settings.github_webhook_secret.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {settings.github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def comment_on_issue(repo: str, issue_number: int, body: str) -> None:
    if not settings.github_token:
        log(logger, logging.WARNING, "github.comment.skipped_no_token", issue=issue_number)
        return
    with httpx.Client(timeout=20.0) as client:
        resp = client.post(
            f"{_API}/repos/{repo}/issues/{issue_number}/comments",
            headers=_headers(),
            json={"body": body},
        )
        resp.raise_for_status()
    log(logger, logging.INFO, "github.comment.posted", issue=issue_number)


def create_issue(repo: str, title: str, body: str, labels: list[str]) -> dict[str, Any]:
    """Create an issue on the fork (labeled) and return the created issue JSON.

    This is what turns a selected scan finding into a real GitHub issue — the
    event that (via webhook) kicks off the remediation half of the pipeline.
    """
    if not settings.github_token:
        raise RuntimeError("GITHUB_TOKEN is required to create issues")
    with httpx.Client(timeout=20.0) as client:
        resp = client.post(
            f"{_API}/repos/{repo}/issues",
            headers=_headers(),
            json={"title": title, "body": body, "labels": labels},
        )
        resp.raise_for_status()
    data = resp.json()
    log(logger, logging.INFO, "github.issue.created", number=data.get("number"), title=title)
    return data


def sign_payload(body: bytes) -> str:
    """HMAC-SHA256 signature header for a webhook body (production-shaped)."""
    return "sha256=" + hmac.new(
        settings.github_webhook_secret.encode(), body, hashlib.sha256
    ).hexdigest()


def list_labeled_issues(repo: str, label: str) -> list[dict[str, Any]]:
    """Open issues carrying `label`. Used by the poller trigger."""
    if not settings.github_token:
        return []
    with httpx.Client(timeout=20.0) as client:
        resp = client.get(
            f"{_API}/repos/{repo}/issues",
            headers=_headers(),
            params={"labels": label, "state": "open", "per_page": 100},
        )
        resp.raise_for_status()
        # The issues endpoint also returns PRs; filter them out.
        return [i for i in resp.json() if "pull_request" not in i]
