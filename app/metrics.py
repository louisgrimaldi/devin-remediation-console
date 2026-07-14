"""Prometheus-style metrics derived from the state store.

Rather than maintain a parallel counter set (which can drift), metrics are
computed on demand from the source of truth — the SQLite store. For a fleet
this small that is both correct and cheap.
"""
from __future__ import annotations

from .db import Store


def remediation_phase(r: dict) -> str:
    """Collapse Devin's raw session lifecycle into the only three states a user
    cares about:

      * ``success``     — a PR exists, whatever the session is doing now.
      * ``failed``      — the session errored, or terminally exited (or was
                          suspended for inactivity) without ever opening a PR.
      * ``in_progress`` — anything else still working toward a PR.

    Devin's own ``suspended``/``waiting_for_user``/``inactivity`` states are
    implementation detail; a suspended session that already opened a PR is a
    success, and one that ended without a PR is a failure.
    """
    if r.get("pr_url"):
        return "success"
    if r.get("status") in {"error", "exit", "suspended"}:
        return "failed"
    return "in_progress"


def summarize(store: Store) -> dict[str, float]:
    rows = store.all()
    phases = [remediation_phase(r) for r in rows]
    active = sum(1 for p in phases if p == "in_progress")
    prs = sum(1 for r in rows if r["pr_url"])
    failed = sum(1 for p in phases if p == "failed")
    completed = prs          # a remediation is "done" once its PR is raised
    errored = failed
    acus = sum(float(r["acus_consumed"] or 0) for r in rows)
    total = len(rows)
    # Time-to-PR (seconds): dispatch -> when the PR first appeared, averaged
    # over remediations that produced a PR. (Uses pr_opened_at, not completion,
    # so it's meaningful while the session is still running.)
    ttp_samples = []
    for r in rows:
        if r["pr_url"] and r["dispatched_at"] and r.get("pr_opened_at"):
            from datetime import datetime

            try:
                d = datetime.fromisoformat(r["dispatched_at"])
                p = datetime.fromisoformat(r["pr_opened_at"])
                ttp_samples.append((p - d).total_seconds())
            except ValueError:
                pass
    avg_ttp = sum(ttp_samples) / len(ttp_samples) if ttp_samples else 0.0
    success_rate = (prs / total) if total else 0.0

    findings = store.all_findings()
    scans = store.all_scans()
    scan_acus = sum(float(s.get("acus_consumed") or 0) for s in scans)
    prs_merged = sum(1 for r in rows if (r.get("pr_state") or "").lower() == "merged")
    return {
        "total": total,
        "active": active,
        "completed": completed,
        "errored": errored,
        "failed": failed,
        "prs_opened": prs,
        "prs_merged": prs_merged,
        "acus_consumed": round(acus + scan_acus, 2),
        "success_rate": round(success_rate, 3),
        "avg_time_to_pr_seconds": round(avg_ttp, 1),
        "scans_total": len(scans),
        "findings_total": len(findings),
        "findings_open": sum(1 for f in findings if f["status"] == "open"),
        "findings_filed": sum(1 for f in findings if f["status"] == "filed"),
        "findings_dismissed": sum(1 for f in findings if f["status"] == "dismissed"),
    }


def render_prometheus(store: Store) -> str:
    m = summarize(store)
    lines = [
        "# HELP remediation_total Total remediations tracked.",
        "# TYPE remediation_total gauge",
        f"remediation_total {m['total']}",
        "# HELP remediation_active Remediations in progress (working toward a PR).",
        "# TYPE remediation_active gauge",
        f"remediation_active {m['active']}",
        "# HELP remediation_completed Remediations that succeeded (PR raised).",
        "# TYPE remediation_completed gauge",
        f"remediation_completed {m['completed']}",
        "# HELP remediation_errored Remediations that failed (no PR).",
        "# TYPE remediation_errored gauge",
        f"remediation_errored {m['errored']}",
        "# HELP remediation_prs_opened Pull requests opened by Devin.",
        "# TYPE remediation_prs_opened counter",
        f"remediation_prs_opened {m['prs_opened']}",
        "# HELP remediation_acus_consumed Total Devin ACUs consumed.",
        "# TYPE remediation_acus_consumed counter",
        f"remediation_acus_consumed {m['acus_consumed']}",
        "# HELP remediation_success_rate PRs opened / total remediations.",
        "# TYPE remediation_success_rate gauge",
        f"remediation_success_rate {m['success_rate']}",
        "# HELP remediation_avg_time_to_pr_seconds Mean dispatch->PR latency.",
        "# TYPE remediation_avg_time_to_pr_seconds gauge",
        f"remediation_avg_time_to_pr_seconds {m['avg_time_to_pr_seconds']}",
        "# HELP scan_runs_total Devin code scans run.",
        "# TYPE scan_runs_total counter",
        f"scan_runs_total {m['scans_total']}",
        "# HELP findings_total Findings surfaced across all scans.",
        "# TYPE findings_total gauge",
        f"findings_total {m['findings_total']}",
        "# HELP findings_open Findings not yet filed or dismissed.",
        "# TYPE findings_open gauge",
        f"findings_open {m['findings_open']}",
        "# HELP findings_filed Findings converted into GitHub issues.",
        "# TYPE findings_filed gauge",
        f"findings_filed {m['findings_filed']}",
        "# HELP findings_open_backlog Open findings not yet filed or dismissed.",
        "# TYPE findings_open_backlog gauge",
        f"findings_open_backlog {m['findings_open']}",
        "# HELP remediation_prs_merged Pull requests merged.",
        "# TYPE remediation_prs_merged counter",
        f"remediation_prs_merged {m['prs_merged']}",
    ]
    return "\n".join(lines) + "\n"
