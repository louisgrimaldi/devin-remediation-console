"""Core orchestration: turn a labeled issue into a dispatched Devin session,
and reconcile running sessions until a PR is opened and linked back.

This module is trigger-agnostic. Whether an issue arrives via webhook or the
poller, it funnels through `remediate_issue`. The reconciler runs on a timer.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from .config import settings
from .db import Store
from .devin import DevinClient
from . import github
from .logging_setup import log
from .prompts import (
    REMEDIATION_SCHEMA,
    SCAN_SCHEMA,
    build_prompt,
    build_scan_prompt,
    scan_title,
    title_for,
)

logger = logging.getLogger("pipeline")


# Realistic findings used when DISPATCH_ENABLED=0 so the whole console — scan
# history, ranked findings, selection — is demoable end-to-end without spending
# any ACUs. Mirrors the shape a real Devin scan returns.
MOCK_FINDINGS: list[dict[str, Any]] = [
    {
        "title": "subprocess call with shell=True",
        "category": "security", "tool": "bandit", "rule": "B602",
        "severity": "critical", "priority": 1,
        "location": "superset/utils/core.py",
        "description": "A subprocess is spawned with shell=True on a constructed "
                       "command string, exposing a shell-injection vector.",
        "recommendation": "Pass an argument list and shell=False; validate inputs.",
    },
    {
        "title": "HTTP requests issued without a timeout",
        "category": "security", "tool": "bandit", "rule": "B113",
        "severity": "high", "priority": 2,
        "location": "scripts/cancel_github_workflows.py",
        "description": "requests/httpx calls without a timeout can hang the process "
                       "indefinitely if the remote never responds.",
        "recommendation": "Add an explicit timeout=<n> to every outbound call.",
    },
    {
        "title": "Vulnerable dependency: outdated 'requests' pin",
        "category": "dependency", "tool": "pip-audit", "rule": "GHSA-xxxx",
        "severity": "high", "priority": 3,
        "location": "requirements/base.txt",
        "description": "A pinned dependency has a known advisory in the installed range.",
        "recommendation": "Bump to the patched version and re-run the test suite.",
    },
    {
        "title": "Bare `except:` clauses swallow all exceptions",
        "category": "code_quality", "tool": "flake8", "rule": "E722",
        "severity": "medium", "priority": 4,
        "location": "superset/connectors/sqla/models.py",
        "description": "Bare excepts hide real errors (including KeyboardInterrupt) "
                       "and make failures hard to diagnose.",
        "recommendation": "Catch specific exception types; re-raise or log the rest.",
    },
    {
        "title": "Use of assert for runtime validation",
        "category": "security", "tool": "bandit", "rule": "B101",
        "severity": "low", "priority": 5,
        "location": "superset/security/manager.py",
        "description": "asserts are stripped under python -O, silently removing checks.",
        "recommendation": "Replace security-relevant asserts with explicit checks.",
    },
    {
        "title": "Unsorted / unformatted imports",
        "category": "formatting", "tool": "isort", "rule": "I001",
        "severity": "low", "priority": 6,
        "location": "superset/views/base.py",
        "description": "Import ordering deviates from isort/black configuration.",
        "recommendation": "Run isort and black to normalise import blocks.",
    },
]


def remediate_issue(
    store: Store,
    devin: DevinClient,
    *,
    issue_number: int,
    title: str,
    body: str,
    url: str,
) -> dict[str, Any]:
    """Register an issue and dispatch a Devin session (idempotent per issue)."""
    is_new = store.upsert_issue(
        issue_number=issue_number, repo=settings.target_repo, title=title, url=url
    )
    # Carry severity/category/priority from the originating finding (if any) so
    # the classification stays continuous from Security through to Review.
    finding = store.get_finding_by_issue(issue_number)
    if finding:
        store.set_remediation_meta(
            issue_number, finding.get("severity"), finding.get("category"), finding.get("priority")
        )
    if not is_new:
        existing = store.get(issue_number)
        if existing and existing.get("devin_session_id"):
            # Same issue triggered again — don't dispatch twice, just float it to
            # the top of the Review list.
            store.touch(issue_number)
            log(logger, logging.INFO, "pipeline.skip.already_dispatched", issue=issue_number)
            return store.get(issue_number) or existing

    if not settings.dispatch_enabled:
        log(logger, logging.WARNING, "pipeline.dispatch_disabled", issue=issue_number)
        return store.get(issue_number) or {}

    prompt = build_prompt(issue_number, title, body)
    try:
        session = devin.create_session(
            prompt=prompt,
            title=title_for(issue_number, title),
            tags=["auto-remediation", f"issue-{issue_number}"],
            structured_output_schema=REMEDIATION_SCHEMA,
        )
    except httpx.HTTPError as exc:
        detail = getattr(getattr(exc, "response", None), "text", str(exc))
        store.mark_error(issue_number, f"dispatch failed: {detail}")
        log(logger, logging.ERROR, "pipeline.dispatch_failed", issue=issue_number, error=detail)
        raise

    store.mark_dispatched(issue_number, session["session_id"], session.get("url", ""))
    log(
        logger,
        logging.INFO,
        "pipeline.dispatched",
        issue=issue_number,
        session_id=session["session_id"],
    )
    return store.get(issue_number) or {}


def reconcile_once(store: Store, devin: DevinClient) -> None:
    """Poll every active session; persist status/PR and comment back when a PR lands."""
    for row in store.active():
        session_id = row["devin_session_id"]
        try:
            session = devin.get_session(session_id)
        except httpx.HTTPError as exc:
            log(logger, logging.WARNING, "reconcile.poll_failed", session_id=session_id, error=str(exc))
            continue

        pr_url, pr_state = DevinClient.extract_pr(session)
        store.update_from_session(
            row["issue_number"],
            status=session.get("status", row["status"]),
            status_detail=session.get("status_detail"),
            pr_url=pr_url,
            pr_state=pr_state,
            acus=float(session.get("acus_consumed") or 0),
        )

        # Once a PR exists and we haven't yet linked it, comment on the issue.
        if pr_url and not row["commented_back"]:
            try:
                github.comment_on_issue(
                    settings.target_repo,
                    row["issue_number"],
                    f"🤖 Devin opened a pull request to remediate this issue: {pr_url}\n\n"
                    f"Session: {row['devin_url']}",
                )
                store.mark_commented(row["issue_number"])
                log(logger, logging.INFO, "reconcile.pr_linked", issue=row["issue_number"], pr=pr_url)
            except httpx.HTTPError as exc:
                log(logger, logging.WARNING, "reconcile.comment_failed", issue=row["issue_number"], error=str(exc))


def start_scan(store: Store, devin: DevinClient) -> dict[str, Any]:
    """Kick off a discovery scan (Devin as auditor).

    In dry-run (DISPATCH_ENABLED=0) this ingests realistic mock findings
    immediately, so the console is fully demoable without spending ACUs. Live,
    it dispatches one Devin session that runs the scanners and returns findings
    via structured output; `reconcile_scans` ingests them when ready.
    """
    if not settings.dispatch_enabled:
        n_prev = len(store.all_scans())
        scan_id = f"dryrun-{n_prev + 1}"
        store.insert_scan(
            scan_id=scan_id, repo=settings.target_repo, session_id=None,
            devin_url="", status="exit", is_mock=True,
        )
        added = store.add_findings(scan_id, settings.target_repo, MOCK_FINDINGS)
        store.update_scan(
            scan_id, status="exit", status_detail="finished (mock)",
            acus=0.0, num_findings=added, findings_ingested=True,
        )
        log(logger, logging.INFO, "scan.mock", scan_id=scan_id, findings=added)
        return {"scan_id": scan_id, "mock": True, "findings": added}

    try:
        session = devin.create_session(
            prompt=build_scan_prompt(settings.scan_max_findings),
            title=scan_title(),
            tags=["code-scan", "discovery"],
            structured_output_schema=SCAN_SCHEMA,
        )
    except httpx.HTTPError as exc:
        detail = getattr(getattr(exc, "response", None), "text", str(exc))
        log(logger, logging.ERROR, "scan.dispatch_failed", error=detail)
        raise

    scan_id = session["session_id"]
    store.insert_scan(
        scan_id=scan_id, repo=settings.target_repo, session_id=scan_id,
        devin_url=session.get("url", ""), status=session.get("status", "running"),
        is_mock=False,
    )
    log(logger, logging.INFO, "scan.dispatched", scan_id=scan_id, url=session.get("url"))
    return {"scan_id": scan_id, "mock": False, "url": session.get("url")}


_SCHEDULE_SECONDS = {
    "hourly": 3600,
    "daily": 86_400,
    "weekly": 604_800,
    "monthly": 2_592_000,  # 30 days
}


def maybe_scheduled_scan(store: Store, devin: DevinClient) -> bool:
    """Trigger a scan if the configured schedule is due. Returns True if it ran.

    The schedule is read live from the Settings store so it can be changed
    without a restart. 'manual' (default) never auto-runs.
    """
    schedule = store.get_setting("scan_schedule", settings.scan_schedule)
    interval = _SCHEDULE_SECONDS.get(schedule)
    if not interval:
        return False  # manual / unknown -> no auto-run

    latest = store.latest_scan()
    if latest:
        # Don't stack scans: skip while one is still running.
        if latest["status"] not in {"exit", "error"}:
            return False
        try:
            last = datetime.fromisoformat(latest["started_at"])
            if (datetime.now(timezone.utc) - last).total_seconds() < interval:
                return False
        except ValueError:
            pass

    log(logger, logging.INFO, "scan.scheduled", schedule=schedule)
    start_scan(store, devin)
    return True


def reconcile_scans(store: Store, devin: DevinClient) -> None:
    """Poll running scan sessions; ingest structured findings once, and keep
    updating status until the session reaches a terminal state."""
    for scan in store.scans_to_poll():
        session_id = scan["devin_session_id"]
        if not session_id:
            continue
        try:
            session = devin.get_session(session_id)
        except httpx.HTTPError as exc:
            log(logger, logging.WARNING, "scan.poll_failed", scan_id=scan["scan_id"], error=str(exc))
            continue

        acus = float(session.get("acus_consumed") or 0)
        so = session.get("structured_output")
        findings = so.get("findings") if isinstance(so, dict) else None

        if findings and not scan["findings_ingested"]:
            # Findings delivered -> the scan is complete from our side, even
            # though the Devin session lingers in `waiting_for_user`.
            added = store.add_findings(scan["scan_id"], settings.target_repo, findings)
            store.update_scan(
                scan["scan_id"], status="complete", status_detail="findings delivered",
                acus=acus, num_findings=added, findings_ingested=True,
            )
            log(logger, logging.INFO, "scan.ingested", scan_id=scan["scan_id"], findings=added)
        elif scan["findings_ingested"]:
            # Already have findings from a prior poll -> settle to complete.
            store.update_scan(
                scan["scan_id"], status="complete", status_detail="findings delivered", acus=acus,
            )
        else:
            store.update_scan(
                scan["scan_id"], status=session.get("status", scan["status"]),
                status_detail=session.get("status_detail"), acus=acus,
            )


def _finding_issue_body(f: dict[str, Any]) -> str:
    bits = [
        f["description"] or "",
        "",
        f"- **Category:** {f.get('category')}",
        f"- **Severity:** {f.get('severity')}",
        f"- **Tool / rule:** {f.get('tool') or '—'} {f.get('rule') or ''}".rstrip(),
        f"- **Location:** `{f.get('location') or '—'}`",
    ]
    if f.get("recommendation"):
        bits += ["", f"**Recommended fix:** {f['recommendation']}"]
    bits += ["", "_Filed automatically from a Devin code scan._"]
    return "\n".join(bits)


def file_finding(store: Store, finding_id: int) -> Optional[dict[str, Any]]:
    """Create a labeled GitHub issue from an open finding. Returns the issue JSON."""
    f = store.get_finding(finding_id)
    if not f or f["status"] != "open":
        return None
    issue = github.create_issue(
        settings.target_repo,
        title=f["title"],
        body=_finding_issue_body(f),
        labels=[settings.trigger_label],
    )
    store.mark_finding_filed(finding_id, issue["number"])
    log(logger, logging.INFO, "finding.filed", finding_id=finding_id, issue=issue["number"])
    return issue


def poll_labeled_issues(store: Store, devin: DevinClient) -> int:
    """Discover open issues labeled with the trigger label and remediate new ones.

    Returns the number of newly dispatched issues. This is the URL-free trigger
    that makes the system demoable without exposing a public webhook endpoint.
    Only active in 'on_creation' mode — in 'on_comment' mode remediation waits
    for the trigger command, so the poller stays quiet to keep Review consistent.
    """
    if store.get_setting("remediation_trigger", settings.remediation_trigger) != "on_creation":
        return 0
    dispatched = 0
    for issue in github.list_labeled_issues(settings.target_repo, settings.trigger_label):
        num = issue["number"]
        if store.get(num) and store.get(num).get("devin_session_id"):
            continue
        remediate_issue(
            store,
            devin,
            issue_number=num,
            title=issue.get("title", ""),
            body=issue.get("body") or "",
            url=issue.get("html_url", ""),
        )
        dispatched += 1
    return dispatched
