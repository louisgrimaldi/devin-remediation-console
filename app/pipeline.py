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
    AUTOFIX_SCHEMA,
    REMEDIATION_SCHEMA,
    REVIEW_SCHEMA,
    SCAN_SCHEMA,
    autofix_title,
    build_autofix_prompt,
    build_prompt,
    build_review_prompt,
    build_scan_prompt,
    review_title,
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
        # The first time we see a PR, record its real GitHub creation time so
        # time-to-PR isn't inflated by how long the reconciler took to notice it
        # (e.g. after server/poller downtime). Only one extra call, once per PR.
        newly_opened = bool(pr_url) and not row.get("pr_opened_at")
        pr_opened_at = github.get_pr_created_at(pr_url) if newly_opened else None
        store.update_from_session(
            row["issue_number"],
            status=session.get("status", row["status"]),
            status_detail=session.get("status_detail"),
            pr_url=pr_url,
            pr_state=pr_state,
            acus=float(session.get("acus_consumed") or 0),
            pr_opened_at=pr_opened_at,
        )

        # Mirror Cognition's "review on PR open": the moment a remediation opens
        # a PR, dispatch an INDEPENDENT reviewer session for it. This is the
        # poll-based fallback for the pull_request webhook (same Settings gate),
        # so it also works without a public webhook URL.
        review_trigger = store.get_setting("review_trigger", settings.review_trigger)
        if newly_opened and settings.review_enabled and review_trigger == "on_pr_open":
            enqueue_review(store, devin, pr_url=pr_url, issue_number=row["issue_number"])

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


# --------------------------------------------------------------------- review
def enqueue_review(
    store: Store, devin: DevinClient, *, pr_url: str, issue_number: Optional[int],
    round_no: int = 1,
) -> Optional[int]:
    """Dispatch an INDEPENDENT Devin session to review one PR (idempotent per
    commit SHA). Advisory only — the reviewer never touches the branch; its
    verdict is consumed as structured data. Returns the review id, or None if
    already reviewed at this SHA / dispatch is disabled."""
    if not settings.dispatch_enabled:
        return None
    head = github.get_pr_head(pr_url)
    if not head or not head.get("head_sha"):
        log(logger, logging.WARNING, "review.no_head_sha", pr=pr_url)
        return None
    review_id = store.create_review(
        repo=settings.target_repo, pr_url=pr_url, pr_number=head["number"],
        issue_number=issue_number, head_sha=head["head_sha"], round_no=round_no,
    )
    if review_id is None:
        return None  # already reviewed this exact diff

    try:
        session = devin.create_session(
            prompt=build_review_prompt(
                pr_url=pr_url, pr_number=head["number"], issue_number=issue_number
            ),
            title=review_title(head["number"]),
            tags=["pr-review", f"pr-{head['number']}"],
            structured_output_schema=REVIEW_SCHEMA,
            devin_mode=settings.review_mode,
            max_acu=settings.review_max_acu,
        )
    except httpx.HTTPError as exc:
        detail = getattr(getattr(exc, "response", None), "text", str(exc))
        log(logger, logging.ERROR, "review.dispatch_failed", pr=pr_url, error=detail)
        return None

    store.mark_review_dispatched(review_id, session["session_id"], session.get("url", ""))
    log(logger, logging.INFO, "review.dispatched", pr=head["number"], review_id=review_id,
        session_id=session["session_id"])
    return review_id


def sweep_open_prs_for_review(store: Store, devin: DevinClient) -> int:
    """Kick an independent review for every open PR the console has tracked that
    hasn't been reviewed at its current commit. Used to review pre-existing PRs
    (the on-open trigger only catches new ones). Returns count dispatched."""
    dispatched = 0
    for r in store.with_prs():
        if (r.get("pr_state") or "").lower() == "merged":
            continue
        if enqueue_review(store, devin, pr_url=r["pr_url"], issue_number=r["issue_number"]):
            dispatched += 1
    return dispatched


def _review_comment_body(verdict: str, summary: str, security: str,
                         findings: list[dict[str, Any]]) -> str:
    icon = {"approve": "✅ Approve", "request_changes": "🛑 Request changes",
            "comment": "💬 Comment"}.get(verdict, verdict)
    sev = {"red": "🔴", "yellow": "🟡", "gray": "⚪"}
    lines = [f"## 🤖 Devin independent review — {icon}", "", summary]
    if security:
        lines += ["", f"**Security review:** {security}"]
    reds = [f for f in findings if f.get("severity") == "red"]
    others = [f for f in findings if f.get("severity") != "red"]
    if findings:
        lines += ["", "### Findings"]
        for f in reds + others:
            loc = f" (`{f['file']}`{':' + str(f['line']) if f.get('line') else ''})" if f.get("file") else ""
            lines.append(f"- {sev.get(f.get('severity'), '')} **{f.get('title','')}**{loc} — {f.get('detail','')}")
    lines += ["", "_Independent review by a separate Devin session. Advisory only — "
              "this reviewer does not modify the branch._"]
    return "\n".join(lines)


def reconcile_reviews(store: Store, devin: DevinClient) -> None:
    """Poll dispatched review sessions; once a verdict lands, persist it and post
    a single consolidated advisory comment on the PR (idempotent per SHA)."""
    for rev in store.reviews_to_poll():
        session_id = rev["devin_session_id"]
        try:
            session = devin.get_session(session_id)
        except httpx.HTTPError as exc:
            log(logger, logging.WARNING, "review.poll_failed", review_id=rev["id"], error=str(exc))
            continue

        so = session.get("structured_output")
        so = so if isinstance(so, dict) else {}
        verdict = so.get("verdict")
        findings = so.get("findings") if isinstance(so.get("findings"), list) else []
        counts = {"red": 0, "yellow": 0, "gray": 0}
        for f in findings:
            if f.get("severity") in counts:
                counts[f["severity"]] += 1

        store.update_review_from_session(
            rev["id"],
            status=session.get("status", rev["status"]),
            status_detail=session.get("status_detail"),
            acus=float(session.get("acus_consumed") or 0),
            verdict=verdict, summary=so.get("summary"),
            n_red=counts["red"], n_yellow=counts["yellow"], n_gray=counts["gray"],
        )

        # One consolidated advisory comment, only once we have a verdict.
        if verdict and not rev["comment_posted"]:
            posted = github.post_review_comment(
                rev["pr_url"], rev["head_sha"],
                _review_comment_body(verdict, so.get("summary", ""),
                                     so.get("security_review", ""), findings),
            )
            if posted:
                store.mark_review_commented(rev["id"])
                log(logger, logging.INFO, "review.commented", pr=rev["pr_number"], verdict=verdict)


def reconcile_autofix(store: Store, devin: DevinClient) -> None:
    """Close the loop: for a blocking review, dispatch a bounded fix session, then
    re-review the new commit — capped at `autofix_max_rounds`, then escalate to a
    human. The loop converges because each fix is scoped to just the red findings
    and the round cap is enforced here, not by the sessions negotiating."""
    autofix_on = store.get_setting("autofix", "on" if settings.autofix_enabled else "off") == "on"
    if not (settings.dispatch_enabled and autofix_on):
        return

    # (1) A review says request_changes and nothing has handled it yet.
    for rev in store.reviews_needing_autofix():
        attempts = store.autofix_attempts(rev["pr_url"])
        if attempts >= settings.autofix_max_rounds:
            # Rounds exhausted — hand off to a human rather than loop forever.
            github.post_review_comment(
                rev["pr_url"], f"{rev['head_sha']}-escalate",
                f"## 🤖 Devin autofix — ⚠️ escalating to a human\n\n"
                f"After {attempts} autofix round(s), blocking findings remain on this PR. "
                f"Stopping the automated loop and leaving this for a human reviewer — "
                f"the remaining issue likely needs a product or architecture decision.",
            )
            store.mark_review_escalated(rev["id"])
            log(logger, logging.INFO, "autofix.escalated", pr=rev["pr_number"], attempts=attempts)
            continue

        head = github.get_pr_head(rev["pr_url"])
        branch = (head or {}).get("head_ref") or ""
        try:
            reds = _red_findings_for(devin, rev)
            session = devin.create_session(
                prompt=build_autofix_prompt(
                    pr_url=rev["pr_url"], pr_number=rev["pr_number"], branch=branch,
                    round_no=attempts + 1, max_rounds=settings.autofix_max_rounds, findings=reds,
                ),
                title=autofix_title(rev["pr_number"], attempts + 1),
                tags=["autofix", f"pr-{rev['pr_number']}"],
                structured_output_schema=AUTOFIX_SCHEMA,
                devin_mode=settings.autofix_mode,
                max_acu=settings.autofix_max_acu,
            )
        except httpx.HTTPError as exc:
            detail = getattr(getattr(exc, "response", None), "text", str(exc))
            log(logger, logging.ERROR, "autofix.dispatch_failed", pr=rev["pr_number"], error=detail)
            continue
        store.set_review_autofix(rev["id"], session["session_id"], session.get("url", ""))
        log(logger, logging.INFO, "autofix.dispatched", pr=rev["pr_number"],
            round=attempts + 1, session_id=session["session_id"])

    # (2) An autofix is running — when it pushes a new commit, re-review that SHA.
    for rev in store.reviews_with_active_autofix():
        try:
            session = devin.get_session(rev["autofix_session_id"])
        except httpx.HTTPError as exc:
            log(logger, logging.WARNING, "autofix.poll_failed", review_id=rev["id"], error=str(exc))
            continue
        so = session.get("structured_output")
        so = so if isinstance(so, dict) else {}
        if so.get("status"):
            store.update_autofix_status(rev["id"], so["status"])

        head = github.get_pr_head(rev["pr_url"])
        new_sha = (head or {}).get("head_sha")
        if new_sha and new_sha != rev["head_sha"] and not store.get_review(rev["pr_url"], new_sha):
            # New commit on the branch -> re-review it (round + 1).
            enqueue_review(store, devin, pr_url=rev["pr_url"],
                           issue_number=rev["issue_number"], round_no=(rev["round"] or 1) + 1)
            store.mark_review_reviewed_next(rev["id"])
            log(logger, logging.INFO, "autofix.re_review", pr=rev["pr_number"], new_sha=new_sha[:10])
        elif so.get("status") == "cannot_fix":
            # Author couldn't resolve it and pushed nothing -> escalate.
            github.post_review_comment(
                rev["pr_url"], f"{rev['head_sha']}-cannotfix",
                "## 🤖 Devin autofix — ⚠️ could not resolve\n\n"
                f"{so.get('summary', 'The autofix session could not resolve the blocking findings.')}\n\n"
                "Escalating to a human reviewer.",
            )
            store.mark_review_escalated(rev["id"])
            log(logger, logging.INFO, "autofix.cannot_fix", pr=rev["pr_number"])


def _red_findings_for(devin: DevinClient, rev: dict[str, Any]) -> list[dict[str, Any]]:
    """Re-read the review session's structured output to recover its red findings
    (we persist only counts, so fetch the detail to scope the fix precisely)."""
    try:
        session = devin.get_session(rev["devin_session_id"])
    except httpx.HTTPError:
        return []
    so = session.get("structured_output")
    findings = so.get("findings") if isinstance(so, dict) else None
    return [f for f in (findings or []) if f.get("severity") == "red"]


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
