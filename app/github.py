"""GitHub helpers: verify webhook signatures, comment PR links back on issues,
and poll for labeled issues (a URL-free alternative trigger for demos)."""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
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


def get_pr_created_at(pr_url: str) -> Optional[str]:
    """Return a PR's real GitHub `created_at` (ISO 8601), parsed from its URL.

    Used so time-to-PR is measured from when GitHub actually opened the PR, not
    when our reconciler first happened to observe it — which makes the metric
    robust to poller/server downtime. Returns None on any failure (caller keeps
    its existing behaviour).
    """
    if not settings.github_token or not pr_url:
        return None
    # https://github.com/<owner>/<repo>/pull/<number>
    m = re.search(r"github\.com/([^/]+)/([^/]+)/pull/(\d+)", pr_url)
    if not m:
        return None
    owner, repo, number = m.group(1), m.group(2), m.group(3)
    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.get(
                f"{_API}/repos/{owner}/{repo}/pulls/{number}", headers=_headers()
            )
            resp.raise_for_status()
        return resp.json().get("created_at")
    except httpx.HTTPError as exc:
        log(logger, logging.WARNING, "github.pr_created_at.failed", pr=pr_url, error=str(exc))
        return None


def _parse_pr(pr_url: str) -> Optional[tuple[str, str, int]]:
    m = re.search(r"github\.com/([^/]+)/([^/]+)/pull/(\d+)", pr_url or "")
    return (m.group(1), m.group(2), int(m.group(3))) if m else None


def get_pr_head(pr_url: str) -> Optional[dict[str, Any]]:
    """Return {number, head_sha, state} for a PR, used as the review idempotency
    key (one review per commit SHA). None on any failure."""
    parsed = _parse_pr(pr_url)
    if not settings.github_token or not parsed:
        return None
    owner, repo, number = parsed
    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.get(f"{_API}/repos/{owner}/{repo}/pulls/{number}", headers=_headers())
            resp.raise_for_status()
        d = resp.json()
        head = d.get("head") or {}
        return {"number": number, "head_sha": head.get("sha"),
                "head_ref": head.get("ref"), "state": d.get("state")}
    except httpx.HTTPError as exc:
        log(logger, logging.WARNING, "github.pr_head.failed", pr=pr_url, error=str(exc))
        return None


def post_review_comment(pr_url: str, head_sha: str, body: str) -> bool:
    """Post ONE consolidated advisory review comment on the PR, idempotently.

    Follows the blog's loop-prevention guidance: a hidden marker keyed to the
    commit SHA means we never double-post for the same diff, and we consolidate
    everything into a single comment rather than a thread. Returns True if a
    comment was posted (False if skipped or on failure)."""
    parsed = _parse_pr(pr_url)
    if not settings.github_token or not parsed:
        return False
    owner, repo, number = parsed
    marker = f"<!-- devin-review:{head_sha} -->"
    try:
        with httpx.Client(timeout=20.0) as client:
            existing = client.get(
                f"{_API}/repos/{owner}/{repo}/issues/{number}/comments",
                headers=_headers(), params={"per_page": 100},
            )
            existing.raise_for_status()
            if any(marker in (c.get("body") or "") for c in existing.json()):
                return False  # already reviewed this exact diff — don't repeat
            resp = client.post(
                f"{_API}/repos/{owner}/{repo}/issues/{number}/comments",
                headers=_headers(), json={"body": f"{marker}\n{body}"},
            )
            resp.raise_for_status()
        log(logger, logging.INFO, "github.review_comment.posted", pr=number)
        return True
    except httpx.HTTPError as exc:
        log(logger, logging.WARNING, "github.review_comment.failed", pr=pr_url, error=str(exc))
        return False


def list_open_prs(repo: str) -> list[dict[str, Any]]:
    """Open PRs on the repo (used to sweep-review existing PRs)."""
    if not settings.github_token:
        return []
    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.get(
                f"{_API}/repos/{repo}/pulls", headers=_headers(),
                params={"state": "open", "per_page": 100},
            )
            resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError as exc:
        log(logger, logging.WARNING, "github.list_prs.failed", repo=repo, error=str(exc))
        return []


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
