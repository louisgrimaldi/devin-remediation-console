"""FastAPI entrypoint for the Devin remediation console.

Three surfaces, mirroring Devin's own product, all built on the sessions API:
  * Security  (/)            — run a Devin code scan, rank findings, file issues.
  * Automations (/automations) — Devin subscribed to new issues -> opens a PR.
  * Review    (/review)       — the PRs Devin has opened, linked back to issues.

Event flow
----------
  (1) Perform Devin scan  ──►  Devin session (auditor) ──►  ranked findings
  (2) select findings     ──►  create GitHub issues (labeled `devin`)
  (3) issue created        ──►  webhook /webhook (or poller) ──►  Devin session (fixer)
  (4) reconciler loop      ──►  poll status ──►  PR ──►  comment back + Review tab
"""
from __future__ import annotations

import asyncio
import json
import logging
import urllib.parse

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

from . import github
from .config import settings
from .dashboard import render_analytics, render_review, render_security, render_settings
from .db import Store
from .devin import DevinClient
from .logging_setup import configure_logging, log
from .metrics import render_prometheus, summarize
from .pipeline import (
    file_finding,
    maybe_scheduled_scan,
    poll_labeled_issues,
    reconcile_once,
    reconcile_scans,
    remediate_issue,
    start_scan,
)

configure_logging()
logger = logging.getLogger("app")

app = FastAPI(title="Devin Remediation Console")
store = Store(settings.db_path)
devin = DevinClient()

_tasks: list[asyncio.Task] = []


async def _reconcile_loop() -> None:
    while True:
        try:
            await asyncio.to_thread(reconcile_scans, store, devin)
            await asyncio.to_thread(reconcile_once, store, devin)
        except Exception:  # noqa: BLE001 - keep the loop alive
            logger.exception("reconcile loop iteration failed")
        await asyncio.sleep(settings.reconcile_interval_seconds)


async def _poll_loop() -> None:
    while True:
        try:
            n = await asyncio.to_thread(poll_labeled_issues, store, devin)
            if n:
                log(logger, logging.INFO, "poller.dispatched", count=n)
        except Exception:  # noqa: BLE001
            logger.exception("poll loop iteration failed")
        await asyncio.sleep(settings.poll_interval_seconds)


async def _scan_scheduler_loop() -> None:
    """Trigger scans on the schedule set in Settings ('manual' = never)."""
    while True:
        try:
            await asyncio.to_thread(maybe_scheduled_scan, store, devin)
        except Exception:  # noqa: BLE001
            logger.exception("scan scheduler iteration failed")
        await asyncio.sleep(settings.scheduler_tick_seconds)


@app.on_event("startup")
async def _startup() -> None:
    _tasks.append(asyncio.create_task(_reconcile_loop()))
    _tasks.append(asyncio.create_task(_scan_scheduler_loop()))
    if settings.poll_interval_seconds > 0:
        _tasks.append(asyncio.create_task(_poll_loop()))
    log(
        logger,
        logging.INFO,
        "service.started",
        repo=settings.target_repo,
        dispatch_enabled=settings.dispatch_enabled,
        poll_interval=settings.poll_interval_seconds,
    )


@app.on_event("shutdown")
async def _shutdown() -> None:
    for t in _tasks:
        t.cancel()
    devin.close()


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True, "repo": settings.target_repo}


# ------------------------------------------------------------------ console UI
@app.get("/", response_class=HTMLResponse)
async def security(scan: str = "") -> HTMLResponse:
    return HTMLResponse(render_security(store, scan))


@app.get("/settings", response_class=HTMLResponse)
async def settings_page() -> HTMLResponse:
    return HTMLResponse(render_settings(store))


@app.post("/settings")
async def settings_save(request: Request) -> Response:
    raw = (await request.body()).decode()
    form = urllib.parse.parse_qs(raw)
    trigger = (form.get("remediation_trigger", [None])[0])
    schedule = (form.get("scan_schedule", [None])[0])
    if trigger in {"on_creation", "on_comment"}:
        store.set_setting("remediation_trigger", trigger)
    if schedule in {"manual", "hourly", "daily", "weekly", "monthly"}:
        store.set_setting("scan_schedule", schedule)
    log(logger, logging.INFO, "settings.updated", remediation_trigger=trigger, scan_schedule=schedule)
    return RedirectResponse("/settings", status_code=303)


@app.get("/automations")
async def automations_redirect() -> Response:
    return RedirectResponse("/settings", status_code=307)


@app.get("/review", response_class=HTMLResponse)
async def review() -> HTMLResponse:
    return HTMLResponse(render_review(store))


@app.get("/analytics", response_class=HTMLResponse)
async def analytics() -> HTMLResponse:
    return HTMLResponse(render_analytics(store))


@app.get("/metrics", response_class=PlainTextResponse)
async def metrics() -> PlainTextResponse:
    return PlainTextResponse(render_prometheus(store))


@app.get("/api/state")
async def api_state() -> JSONResponse:
    return JSONResponse(
        {
            "summary": summarize(store),
            "scans": store.all_scans(),
            "findings": store.all_findings(),
            "remediations": store.all(),
        }
    )


# --------------------------------------------------------------------- actions
@app.post("/scan")
async def scan_action() -> Response:
    """Trigger a Devin code scan (Security tab button)."""
    try:
        await asyncio.to_thread(start_scan, store, devin)
    except Exception as exc:  # noqa: BLE001 - surface on the dashboard, don't 500 the UI
        logger.exception("scan dispatch failed")
        log(logger, logging.ERROR, "scan.error", error=str(exc))
    return RedirectResponse("/", status_code=303)


@app.post("/findings/file")
async def findings_file(request: Request) -> Response:
    """File selected findings as GitHub issues, then trigger remediation."""
    raw = (await request.body()).decode()
    form = urllib.parse.parse_qs(raw)
    ids = [int(x) for x in form.get("finding_id", []) if x.isdigit()]
    scan_id = form.get("scan_id", [""])[0]
    for fid in ids:
        try:
            issue = await asyncio.to_thread(file_finding, store, fid)
        except Exception as exc:  # noqa: BLE001
            log(logger, logging.ERROR, "finding.file_failed", finding_id=fid, error=str(exc))
            continue
        if issue:
            await _trigger_remediation(issue)
    dest = f"/?scan={urllib.parse.quote(scan_id)}" if scan_id else "/"
    return RedirectResponse(dest, status_code=303)


@app.post("/findings/dismiss")
async def findings_dismiss(request: Request) -> Response:
    raw = (await request.body()).decode()
    form = urllib.parse.parse_qs(raw)
    for fid in (int(x) for x in form.get("finding_id", []) if x.isdigit()):
        store.mark_finding_dismissed(fid)
    scan_id = form.get("scan_id", [""])[0]
    dest = f"/?scan={urllib.parse.quote(scan_id)}" if scan_id else "/"
    return RedirectResponse(dest, status_code=303)


async def _trigger_remediation(issue: dict) -> None:
    """Fire the same webhook GitHub would, at ourselves, so the remediation
    trigger path is identical to production. The event shape matches the
    configured mode (issue creation vs a `/devin` comment). Falls back to a
    direct dispatch if the self-call fails."""
    mode = store.get_setting("remediation_trigger", settings.remediation_trigger)
    issue_obj = {
        "number": issue["number"],
        "title": issue.get("title", ""),
        "body": issue.get("body") or "",
        "html_url": issue.get("html_url", ""),
        "labels": [{"name": settings.trigger_label}],
    }
    if mode == "on_comment":
        event = "issue_comment"
        payload = {"action": "created",
                   "comment": {"body": settings.trigger_command},
                   "issue": issue_obj}
    else:
        event = "issues"
        payload = {"action": "opened", "issue": issue_obj}

    body = json.dumps(payload).encode()
    headers = {
        "X-GitHub-Event": event,
        "X-Hub-Signature-256": github.sign_payload(body),
        "Content-Type": "application/json",
    }
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            await client.post(f"{settings.self_base_url}/webhook", content=body, headers=headers)
        return
    except Exception as exc:  # noqa: BLE001 - self-call best effort; fall back
        log(logger, logging.WARNING, "trigger.self_webhook_failed", error=str(exc))
    await asyncio.to_thread(
        remediate_issue, store, devin,
        issue_number=issue["number"], title=issue.get("title", ""),
        body=issue.get("body") or "", url=issue.get("html_url", ""),
    )


@app.post("/webhook")
async def webhook(request: Request) -> Response:
    """GitHub webhook receiver.

    Honors the trigger mode set on the Settings tab:
      * on_creation — react to `issues` opened/labeled carrying the trigger label.
      * on_comment  — react to `issue_comment` created containing the command
                      (e.g. `/devin`).
    """
    raw = await request.body()
    if not github.verify_signature(raw, request.headers.get("X-Hub-Signature-256")):
        log(logger, logging.WARNING, "webhook.invalid_signature")
        return JSONResponse({"error": "invalid signature"}, status_code=401)

    event = request.headers.get("X-GitHub-Event", "")
    payload = json.loads(raw or b"{}")
    action = payload.get("action")
    issue = payload.get("issue", {})
    mode = store.get_setting("remediation_trigger", settings.remediation_trigger)

    if mode == "on_comment":
        if event != "issue_comment" or action != "created":
            return JSONResponse({"ignored": f"event={event}, action={action}"}, status_code=202)
        comment = (payload.get("comment") or {}).get("body", "")
        if settings.trigger_command.lower() not in comment.lower():
            return JSONResponse({"ignored": "no trigger command in comment"}, status_code=202)
    else:  # on_creation
        if event != "issues":
            return JSONResponse({"ignored": f"event={event}"}, status_code=202)
        labels = {l["name"] for l in issue.get("labels", [])}
        if not (settings.trigger_label in labels and action in {"labeled", "opened", "reopened"}):
            return JSONResponse(
                {"ignored": f"action={action}, labels={sorted(labels)}"}, status_code=202
            )

    result = await asyncio.to_thread(
        remediate_issue,
        store,
        devin,
        issue_number=issue["number"],
        title=issue.get("title", ""),
        body=issue.get("body") or "",
        url=issue.get("html_url", ""),
    )
    return JSONResponse(
        {
            "issue": issue["number"],
            "session_id": result.get("devin_session_id"),
            "status": result.get("status"),
        },
        status_code=202,
    )
