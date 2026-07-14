"""Server-rendered console — no build step, no JS framework.

Three tabs mirroring Devin's own product, each a plain self-refreshing page a
VP of Eng can read in five seconds:
  * Security   — run a Devin scan, triage ranked findings, file issues.
  * Automations— the issue->PR automation and its live fleet.
  * Review     — the PRs Devin opened, linked back to their issues.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Optional

from .config import settings
from .db import Store
from .metrics import remediation_phase, summarize

_STATUS_COLOR = {
    "queued": "#9ca3af", "running": "#2563eb", "claimed": "#2563eb",
    "resuming": "#2563eb", "suspended": "#d97706", "exit": "#16a34a",
    "complete": "#16a34a", "error": "#dc2626",
}
_SEV_COLOR = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#6b7280"}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_CAT_LABEL = {
    "security": "Security", "dependency": "Dependency", "code_quality": "Code quality",
    "lint": "Lint", "formatting": "Formatting",
}


def _esc(x) -> str:
    return html.escape(str(x if x is not None else ""))


def _ts(x: Optional[str]) -> str:
    return (x or "").replace("T", " ")[:16]


def _fmt_duration(seconds: float) -> str:
    """Human-friendly duration; em-dash when there's no sample yet."""
    s = int(seconds or 0)
    if s <= 0:
        return "—"
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    return f"{s // 3600}h {(s % 3600) // 60}m"


def _badge(status: str) -> str:
    color = _STATUS_COLOR.get(status, "#9ca3af")
    return f'<span class="badge" style="background:{color}">{_esc(status)}</span>'


# User-facing remediation phase: the only three states a leader cares about.
_PHASE = {
    "in_progress": ("In progress", "#2563eb"),
    "success": ("PR raised", "#16a34a"),
    "failed": ("Failed", "#dc2626"),
}


def _phase_badge(r: dict) -> str:
    """Badge the derived phase (In progress / PR raised / Failed), with Devin's
    raw session state demoted to a muted sub-line for the technical audience."""
    label, color = _PHASE[remediation_phase(r)]
    raw = r.get("status_detail") or r.get("status") or ""
    detail = f'<div class="detail">Devin: {_esc(raw)}</div>' if raw else ""
    return f'<span class="badge" style="background:{color}">{label}</span>{detail}'


def _sev(sev: str) -> str:
    color = _SEV_COLOR.get((sev or "").lower(), "#6b7280")
    return f'<span class="badge" style="background:{color}">{_esc(sev or "—")}</span>'


def _stat(label: str, value: str, accent: str = "#1f2328") -> str:
    return (
        f'<div class="stat"><div class="stat-value" style="color:{accent}">{value}</div>'
        f'<div class="stat-label">{_esc(label)}</div></div>'
    )


def _nav(active: str) -> str:
    items = [("/", "Security", "🛡️"), ("/review", "Review", "🔀"),
             ("/analytics", "Analytics", "📊"), ("/settings", "Settings", "⚙️")]
    links = ""
    for href, label, icon in items:
        cls = "nav-item active" if href == active else "nav-item"
        links += f'<a class="{cls}" href="{href}"><span>{icon}</span>{label}</a>'
    return links


def _layout(active: str, content: str, refresh: Optional[int]) -> str:
    meta = f'<meta http-equiv="refresh" content="{refresh}">' if refresh else ""
    live = (
        '<span class="live">● live</span>' if refresh
        else '<span class="paused">❚❚ paused while you select</span>'
    )
    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">{meta}
<title>Devin Console — {_esc(settings.target_repo)}</title>
<style>
  * {{ box-sizing:border-box; }}
  body {{ margin:0; display:flex; min-height:100vh;
         font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
         background:#ffffff; color:#1f2328; }}
  aside {{ width:230px; flex:none; background:#f7f8fa; border-right:1px solid #e5e7eb;
           padding:20px 14px; }}
  .brand {{ font-weight:700; font-size:15px; padding:4px 10px 2px; }}
  .brand .repo {{ display:block; font-weight:400; font-size:12px; color:#6b7280; margin-top:2px; }}
  nav {{ margin-top:18px; display:flex; flex-direction:column; gap:2px; }}
  .nav-item {{ display:flex; align-items:center; gap:10px; padding:9px 10px; border-radius:8px;
              color:#374151; text-decoration:none; font-size:14px; font-weight:500; }}
  .nav-item span {{ font-size:15px; }}
  .nav-item:hover {{ background:#eef0f3; }}
  .nav-item.active {{ background:#e7edfd; color:#1d4ed8; }}
  main {{ flex:1; padding:28px 34px; max-width:1100px; overflow-x:auto; }}
  .head {{ display:flex; align-items:center; gap:14px; margin-bottom:6px; }}
  .head h1 {{ font-size:22px; margin:0; font-weight:650; }}
  .head .sub {{ color:#6b7280; font-size:13px; }}
  .live {{ color:#16a34a; font-size:12px; margin-left:auto; }}
  .paused {{ color:#d97706; font-size:12px; margin-left:auto; }}
  .stats {{ display:flex; gap:12px; margin:18px 0 22px; flex-wrap:wrap; }}
  .stat {{ background:#fff; border:1px solid #e5e7eb; border-radius:12px; padding:14px 18px; min-width:110px; }}
  .stat-value {{ font-size:26px; font-weight:700; }}
  .stat-label {{ font-size:11px; color:#6b7280; margin-top:3px; text-transform:uppercase; letter-spacing:.04em; }}
  .btn {{ background:#1d4ed8; color:#fff; border:none; border-radius:8px; padding:10px 16px;
          font-size:14px; font-weight:600; cursor:pointer; }}
  .btn:hover {{ background:#1e40af; }}
  .btn.ghost {{ background:#fff; color:#374151; border:1px solid #d1d5db; }}
  .btn.ghost:hover {{ background:#f3f4f6; }}
  .card {{ background:#fff; border:1px solid #e5e7eb; border-radius:12px; padding:18px 20px; margin-bottom:20px; }}
  .card h2 {{ font-size:15px; margin:0 0 10px; }}
  .card p {{ color:#4b5563; font-size:13.5px; line-height:1.5; margin:6px 0; }}
  table {{ width:100%; border-collapse:collapse; background:#fff; border:1px solid #e5e7eb;
           border-radius:12px; overflow:hidden; }}
  th, td {{ text-align:left; padding:11px 14px; border-bottom:1px solid #eef0f3; font-size:13.5px; vertical-align:top; }}
  th {{ color:#6b7280; font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:.04em; background:#fafbfc; }}
  tr:last-child td {{ border-bottom:none; }}
  td.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
  .badge {{ display:inline-block; padding:2px 9px; border-radius:999px; color:#fff; font-size:11.5px; font-weight:650; }}
  .detail {{ color:#9ca3af; font-size:11px; margin-top:2px; }}
  .muted {{ color:#6b7280; }}
  .desc {{ color:#6b7280; font-size:12.5px; margin-top:3px; max-width:520px; }}
  .empty {{ color:#9ca3af; text-align:center; padding:30px; }}
  a {{ color:#2563eb; text-decoration:none; }}
  a:hover {{ text-decoration:underline; }}
  code {{ background:#f3f4f6; padding:1px 6px; border-radius:5px; font-size:12.5px; }}
  .toolbar {{ display:flex; gap:10px; align-items:center; margin:14px 0; }}
  .kv {{ font-size:13px; color:#4b5563; margin:4px 0; }}
  .kv b {{ color:#1f2328; font-weight:600; }}
  .sel {{ margin-top:6px; padding:8px 12px; font-size:14px; border:1px solid #d1d5db;
          border-radius:8px; background:#fff; color:#1f2328; min-width:280px; }}
  .grid2 {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; }}
  @media (max-width:820px) {{ .grid2 {{ grid-template-columns:1fr; }} }}
  .panel {{ background:#fff; border:1px solid #e5e7eb; border-radius:12px; padding:18px 20px; }}
  .panel h3 {{ font-size:13px; margin:0 0 2px; }}
  .panel .cap {{ color:#6b7280; font-size:12px; margin:0 0 14px; }}
  /* funnel */
  .frow {{ display:flex; align-items:center; gap:12px; margin:9px 0; }}
  .frow .flabel {{ width:120px; font-size:12.5px; color:#374151; flex:none; }}
  .frow .ftrack {{ flex:1; background:#f1f3f5; border-radius:6px; height:22px; overflow:hidden; }}
  .frow .fbar {{ height:100%; border-radius:6px; min-width:2px; }}
  .frow .fval {{ width:52px; text-align:right; font-variant-numeric:tabular-nums;
                 font-weight:700; font-size:13px; }}
  .frow .fpct {{ color:#9ca3af; font-size:11px; margin-left:2px; }}
  /* severity stacked bar */
  .sevbar {{ display:flex; height:26px; border-radius:7px; overflow:hidden; margin:4px 0 14px;
             background:#f1f3f5; }}
  .sevseg {{ height:100%; }}
  .legend {{ display:flex; flex-wrap:wrap; gap:14px; }}
  .legend .li {{ display:flex; align-items:center; gap:7px; font-size:12.5px; color:#374151; }}
  .legend .sw {{ width:11px; height:11px; border-radius:3px; flex:none; }}
  .legend b {{ font-variant-numeric:tabular-nums; }}
</style></head>
<body>
  <aside>
    <div class="brand">🤖 Devin Console<span class="repo">{_esc(settings.target_repo)}</span></div>
    <nav>{_nav(active)}</nav>
  </aside>
  <main>{content.replace("{{LIVE}}", live)}</main>
</body></html>"""


# ------------------------------------------------------------------- Security
def _finding_row(f: dict) -> str:
    loc = f'<code>{_esc(f["location"])}</code>' if f.get("location") else "—"
    rule = f'{_esc(f.get("tool") or "")} {_esc(f.get("rule") or "")}'.strip() or "—"
    return f"""
    <tr>
      <td><input type="checkbox" name="finding_id" value="{f['id']}"></td>
      <td class="num">{f.get('priority') or '—'}</td>
      <td>{_sev(f.get('severity'))}</td>
      <td>{_esc(_CAT_LABEL.get(f.get('category'), f.get('category')))}</td>
      <td>{_esc(f.get('title'))}<div class="desc">{_esc(f.get('description'))}</div></td>
      <td class="muted">{rule}</td>
      <td>{loc}</td>
    </tr>"""


def _sev_counts(findings: list) -> dict:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        k = (f.get("severity") or "").lower()
        if k in out:
            out[k] += 1
    return out


def _scan_stats(store: Store, scan_id: str) -> dict:
    fs = store.findings_by_scan(scan_id)
    c = _sev_counts(fs)
    # When findings landed = the real "scan complete" moment (robust to when we
    # happened to stamp the status).
    delivered_at = max((f.get("created_at") for f in fs if f.get("created_at")), default=None)
    return {
        "total": len(fs), "critical": c["critical"], "high": c["high"],
        "medium": c["medium"], "low": c["low"],
        "open": sum(1 for f in fs if f["status"] == "open"),
        "filed": sum(1 for f in fs if f["status"] == "filed"),
        "delivered_at": delivered_at,
    }


def _cnum(n: int, color: str) -> str:
    """A count cell, coloured only when non-zero."""
    style = f' style="color:{color};font-weight:700"' if n else ' class="muted"'
    return f'<td class="num"><span{style}>{n}</span></td>'


def _scan_duration(s: dict, delivered_at: Optional[str]) -> str:
    """Elapsed time: start → findings delivered (final) or → now (while running).

    Uses the findings' delivery time rather than the status-stamp time, so it
    stays accurate regardless of when the row was marked complete."""
    started = s.get("started_at")
    if not started:
        return "—"
    terminal = s.get("status") in {"exit", "error", "complete"}
    try:
        start = datetime.fromisoformat(started)
        if terminal:
            end_raw = delivered_at or s.get("completed_at")
            if not end_raw:
                return "—"
            end = datetime.fromisoformat(end_raw)
        else:
            end = datetime.now(timezone.utc)
        secs = (end - start).total_seconds()
    except ValueError:
        return "—"
    if secs < 0:
        return "—"
    txt = _fmt_duration(secs)
    return txt if terminal else (f"{txt} …" if txt != "—" else "…")


def _scan_history_row(s: dict, selected_id: str, st: dict) -> str:
    sid = s["scan_id"]
    is_sel = sid == selected_id
    session = (
        f'<a href="{_esc(s["devin_url"])}" target="_blank">session ↗</a>'
        if s.get("devin_url") else ("mock" if s.get("is_mock") else "—")
    )
    # Toggle: clicking the open scan collapses it (links back to "/").
    href = "/" if is_sel else f"/?scan={_esc(sid)}"
    started = f'<a href="{href}">{_ts(s.get("started_at"))}</a>'
    row_style = ' style="background:#eef4ff;"' if is_sel else ""
    sel_mark = ' ▼' if is_sel else ''
    return f"""
    <tr{row_style}>
      <td>{started}{sel_mark}</td>
      <td class="muted">{_scan_duration(s, st.get('delivered_at'))}</td>
      <td>{_badge(s.get('status'))}<div class="detail">{_esc(s.get('status_detail') or '')}</div></td>
      <td class="num">{st['total']}</td>
      {_cnum(st['critical'], '#dc2626')}
      {_cnum(st['high'], '#ea580c')}
      {_cnum(st['medium'], '#d97706')}
      {_cnum(st['low'], '#6b7280')}
      {_cnum(st['open'], '#d97706')}
      {_cnum(st['filed'], '#16a34a')}
      <td class="num">{float(s.get('acus_consumed') or 0):.1f}</td>
      <td>{session}</td>
    </tr>"""


def render_security(store: Store, selected_scan_id: str = "") -> str:
    scans = store.all_scans()
    # Findings/stats expand only when a scan is explicitly clicked.
    scan = store.get_scan(selected_scan_id) if selected_scan_id else None
    scan_id = scan["scan_id"] if scan else ""

    history_rows = "".join(
        _scan_history_row(s, scan_id, _scan_stats(store, s["scan_id"])) for s in scans
    ) or ('<tr><td colspan="12" class="empty">No scans yet. Click '
          '<b>Perform Devin scan</b>.</td></tr>')

    scanning_any = any(s["status"] not in {"exit", "error", "complete"} for s in scans)
    has_open = False

    # ---- selected scan detail (only when a scan is clicked) ----
    if scan:
        findings = store.findings_by_scan(scan_id)
        open_findings = [f for f in findings if f["status"] == "open"]
        has_open = bool(open_findings)
        stt = _scan_stats(store, scan_id)
        stats = "".join([
            _stat("Findings", str(stt["total"])),
            _stat("Critical", str(stt["critical"]), "#dc2626"),
            _stat("High", str(stt["high"]), "#ea580c"),
            _stat("Medium", str(stt["medium"]), "#d97706"),
            _stat("Low", str(stt["low"]), "#6b7280"),
            _stat("Open", str(stt["open"]), "#2563eb"),
            _stat("Filed", str(stt["filed"]), "#16a34a"),
        ])
        if scan["status"] not in {"exit", "error", "complete"}:
            body = ('<div class="card"><h2>⏳ Scan in progress…</h2>'
                    '<p class="muted">Devin is running the scanners and ranking findings. '
                    'This page refreshes automatically.</p></div>')
        elif open_findings:
            rows = "".join(_finding_row(f) for f in open_findings)
            body = f"""
          <form method="post" action="/findings/file">
            <input type="hidden" name="scan_id" value="{_esc(scan_id)}">
            <div class="toolbar">
              <button class="btn" type="submit">Create GitHub issues from selected →</button>
              <button class="btn ghost" type="submit" formaction="/findings/dismiss">Dismiss selected</button>
              <span class="muted">Tick the findings you want Devin to remediate.</span>
            </div>
            <table>
              <thead><tr><th></th><th>#</th><th>Severity</th><th>Category</th><th>Finding</th><th>Tool</th><th>Location</th></tr></thead>
              <tbody>{rows}</tbody>
            </table>
          </form>"""
        else:
            body = '<div class="empty">No open findings for this scan — all filed or dismissed.</div>'
        detail = (f'<h2 style="font-size:15px;margin:26px 0 10px;">'
                  f'Findings · scan {_ts(scan.get("started_at"))} {_badge(scan.get("status"))}</h2>'
                  f'<div class="stats">{stats}</div>{body}')
    else:
        detail = '<div class="empty">👆 Click a scan above to see its findings and stats.</div>'

    refresh = 4 if scanning_any else (None if has_open else 12)

    content = f"""
    <div class="head"><h1>🛡️ Security</h1>
      <span class="sub">Devin code scan · click a scan to see its findings</span>{{{{LIVE}}}}</div>
    <form method="post" action="/scan"><button class="btn" type="submit">⚡ Perform Devin scan</button></form>
    <h2 style="font-size:15px;margin:24px 0 10px;">Scan history</h2>
    <table>
      <thead><tr>
        <th>Started</th><th>Duration</th><th>Status</th><th>Findings</th><th>Crit</th><th>High</th>
        <th>Med</th><th>Low</th><th>Open</th><th>Filed</th><th>ACUs</th><th>Session</th>
      </tr></thead>
      <tbody>{history_rows}</tbody>
    </table>
    {detail}"""
    return _layout("/", content, refresh)


# --------------------------------------------------------------------- Review
_VERDICT = {
    "approve": ("✅ Approved", "#16a34a"),
    "request_changes": ("🛑 Changes", "#dc2626"),
    "comment": ("💬 Comment", "#6b7280"),
}


def _review_cell(rev: Optional[dict]) -> str:
    """Independent-reviewer verdict for a PR, including the autofix-loop state
    (reviewing → request_changes → autofixing → re-review → approved / escalated)."""
    if not rev:
        return '<span class="detail">—</span>'
    rnd = rev.get("round") or 1
    round_tag = f' · r{rnd}' if rnd > 1 else ""

    # Human escalation is terminal — surface it loudest.
    if rev.get("escalated"):
        return (f'<span class="badge" style="background:#b45309">⚠️ Escalated</span>'
                f'<div class="detail">human review needed{round_tag}</div>')
    # Autofix in flight (blocking review handed to a bounded fix session).
    if rev.get("autofix_session_id") and not rev.get("reviewed_next"):
        link = (f' <a href="{_esc(rev["autofix_url"])}" target="_blank">↗</a>'
                if rev.get("autofix_url") else "")
        return (f'<span class="badge" style="background:#7c3aed">🔁 Autofixing</span>{link}'
                f'<div class="detail">addressing red findings{round_tag}</div>')

    verdict = rev.get("verdict")
    if not verdict:
        link = (f' <a href="{_esc(rev["devin_url"])}" target="_blank">↗</a>'
                if rev.get("devin_url") else "")
        return f'<span class="badge" style="background:#2563eb">⏳ Reviewing</span>{link}<div class="detail">{round_tag.lstrip(" ·")}</div>'
    label, color = _VERDICT.get(verdict, (verdict, "#6b7280"))
    counts = []
    if rev.get("n_red"):    counts.append(f'🔴{rev["n_red"]}')
    if rev.get("n_yellow"): counts.append(f'🟡{rev["n_yellow"]}')
    if rev.get("n_gray"):   counts.append(f'⚪{rev["n_gray"]}')
    detail = " ".join(counts) + round_tag
    tail = f'<div class="detail">{detail.strip()}</div>' if detail.strip() else ""
    link = (f' <a href="{_esc(rev["devin_url"])}" target="_blank">↗</a>'
            if rev.get("devin_url") else "")
    return f'<span class="badge" style="background:{color}">{label}</span>{link}{tail}'


def _review_row(r: dict, rev: Optional[dict] = None) -> str:
    if r.get("pr_url"):
        pr = f'<a href="{_esc(r["pr_url"])}" target="_blank">PR ↗ {_esc(r.get("pr_state") or "open")}</a>'
    else:
        pr = "—"
    issue = (f'<a href="{_esc(r["issue_url"] or "#")}" target="_blank">'
             f'#{r["issue_number"]} {_esc(r.get("issue_title") or "")}</a>')
    session = (f'<a href="{_esc(r["devin_url"])}" target="_blank">session ↗</a>'
               if r.get("devin_url") else "—")
    cat = _CAT_LABEL.get(r.get("category"), r.get("category") or "")
    sev_cell = f'{_sev(r.get("severity"))}<div class="detail">{_esc(cat)}</div>' if r.get("severity") else "—"
    return f"""
    <tr>
      <td>{sev_cell}</td>
      <td>{issue}<div class="detail">updated {_ts(r.get('updated_at'))}</div></td>
      <td>{_phase_badge(r)}</td>
      <td>{session}</td>
      <td>{pr}</td>
      <td>{_review_cell(rev)}</td>
    </tr>"""


def render_review(store: Store) -> str:
    m = summarize(store)
    rows = store.all()  # every issue Devin is remediating (in-flight + PRs)
    # Keep Security's severity bucketing: critical → low (recency breaks ties,
    # since store.all() already returns rows most-recently-active first).
    rows.sort(key=lambda r: (_SEV_RANK.get((r.get("severity") or "").lower(), 9),
                             r.get("priority") if r.get("priority") is not None else 999))
    body = "".join(
        _review_row(r, store.latest_review_for_issue(r["issue_number"])) for r in rows
    ) or (
        '<tr><td colspan="6" class="empty">Nothing to review yet. '
        'File a finding on the Security tab and Devin will open a PR here.</td></tr>')
    stats = "".join([
        _stat("In flight", str(m["active"]), "#2563eb"),
        _stat("PRs opened", str(m["prs_opened"]), "#16a34a"),
        _stat("Success rate", f'{m["success_rate"] * 100:.0f}%', "#16a34a"),
        _stat("Avg time→PR", _fmt_duration(m["avg_time_to_pr_seconds"])),
    ])
    content = f"""
    <div class="head"><h1>🔀 Review</h1>
      <span class="sub">Issues Devin is remediating, the PRs it opened, and an
      independent Devin review of each</span>{{{{LIVE}}}}</div>
    <div class="stats">{stats}</div>
    <form method="post" action="/reviews/run" style="margin:0 0 14px">
      <button class="btn" type="submit">🔎 Run independent Devin review</button>
      <span class="detail" style="margin-left:8px">A fresh Devin session reviews each open PR — advisory only, never edits the branch.</span>
    </form>
    <table>
      <thead><tr><th>Severity</th><th>Issue</th><th>Status</th><th>Session</th><th>Pull request</th><th>Devin review</th></tr></thead>
      <tbody>{body}</tbody>
    </table>"""
    return _layout("/review", content, 5)


# ------------------------------------------------------------------- Settings
def _select(name: str, current: str, options: list[tuple[str, str]]) -> str:
    opts = "".join(
        f'<option value="{_esc(v)}"{" selected" if v == current else ""}>{_esc(label)}</option>'
        for v, label in options
    )
    return f'<select name="{name}" class="sel">{opts}</select>'


def render_settings(store: Store) -> str:
    trigger = store.get_setting("remediation_trigger", settings.remediation_trigger)
    schedule = store.get_setting("scan_schedule", settings.scan_schedule)
    review_trigger = store.get_setting("review_trigger", settings.review_trigger)
    autofix = store.get_setting("autofix", "on" if settings.autofix_enabled else "off")
    dispatch = "enabled" if settings.dispatch_enabled else "dry-run (no Devin sessions)"

    trigger_sel = _select("remediation_trigger", trigger, [
        ("on_creation", "On issue creation"),
        ("on_comment", f"When {settings.trigger_command} is commented"),
    ])
    review_sel = _select("review_trigger", review_trigger, [
        ("on_pr_open", "Automatically when a PR is opened"),
        ("manual", "Manually (Review tab button only)"),
    ])
    autofix_sel = _select("autofix", autofix, [
        ("on", f"On — autofix red findings, then re-review (max {settings.autofix_max_rounds} rounds)"),
        ("off", "Off — leave request-changes for a human"),
    ])
    schedule_sel = _select("scan_schedule", schedule, [
        ("manual", "Manual only"),
        ("hourly", "Every hour"),
        ("daily", "Every day"),
        ("weekly", "Every week"),
        ("monthly", "Every month"),
    ])

    content = f"""
    <div class="head"><h1>⚙️ Settings</h1>
      <span class="sub">How Devin is triggered for this repository</span>{{{{LIVE}}}}</div>

    <form method="post" action="/settings">
      <div class="card">
        <h2>Devin raises a PR on an issue</h2>
        <p>Choose the event that dispatches a remediation session. On creation fires
           the moment a labelled issue is opened; the comment mode waits for someone to
           type <code>{_esc(settings.trigger_command)}</code> on the issue.</p>
        {trigger_sel}
      </div>

      <div class="card">
        <h2>Independent review of Devin's PRs</h2>
        <p>When a remediation opens a PR, a separate Devin session reviews it
           (advisory only). <b>Automatically</b> fires from the
           <code>pull_request</code> webhook the instant the PR is opened;
           <b>Manually</b> waits for the Review-tab button.</p>
        {review_sel}
      </div>

      <div class="card">
        <h2>Close the loop — autofix review findings</h2>
        <p>When a review returns <b>request changes</b>, hand the red findings to a
           bounded fix session (scoped to just those findings, pushed to the same
           branch), then re-review the new commit. Capped rounds, then it escalates
           to a human — so it converges instead of looping.</p>
        {autofix_sel}
      </div>

      <div class="card">
        <h2>Run code scan</h2>
        <p>Schedule an automatic Devin code scan, or keep it manual and click
           <b>Perform Devin scan</b> on the Security tab yourself.</p>
        {schedule_sel}
      </div>

      <button class="btn" type="submit">Save settings</button>
    </form>

    <div class="card" style="margin-top:22px;">
      <h2>Configuration</h2>
      <div class="kv"><b>Trigger label:</b> <code>{_esc(settings.trigger_label)}</code></div>
      <div class="kv"><b>Webhook endpoint:</b> <code>POST /webhook</code> (HMAC-verified) — <code>issues</code> → remediate, <code>pull_request</code> → review</div>
      <div class="kv"><b>Dispatch:</b> {_esc(dispatch)} · <b>Max ACU/session:</b> {settings.devin_max_acu}</div>
      <div class="kv"><b>Observability:</b> <a href="/metrics">/metrics</a> · <a href="/api/state">/api/state</a></div>
    </div>"""
    return _layout("/settings", content, None)


# ------------------------------------------------------------------ Analytics
_ACCENT = "#1d4ed8"


def _svg_area(values: list) -> str:
    """A responsive area+line sparkline from a series of y-values (no JS)."""
    w, h = 560, 150
    vals = [float(v) for v in values] if values else [0.0]
    if len(vals) < 2:
        vals = vals * 2
    n = len(vals)
    mx = max(max(vals), 1.0)
    step = w / (n - 1)
    pts = [(i * step, h - 12 - (v / mx) * (h - 30)) for i, v in enumerate(vals)]
    poly = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    area = f"M0,{h} " + " ".join(f"L{x:.1f},{y:.1f}" for x, y in pts) + f" L{w},{h} Z"
    lx, ly = pts[-1]
    return (
        f'<svg viewBox="0 0 {w} {h}" width="100%" height="{h}" preserveAspectRatio="none" '
        f'style="display:block;overflow:visible">'
        f'<path d="{area}" style="fill:{_ACCENT};opacity:.12"/>'
        f'<polyline points="{poly}" style="fill:none;stroke:{_ACCENT};stroke-width:2.5;'
        f'vector-effect:non-scaling-stroke"/>'
        f'<circle cx="{lx:.1f}" cy="{ly:.1f}" r="4" style="fill:{_ACCENT}"/>'
        f'<text x="{lx:.1f}" y="{max(ly - 8, 12):.1f}" text-anchor="end" '
        f'style="fill:{_ACCENT};font:700 13px ui-monospace,monospace">{int(vals[-1])}</text>'
        f'</svg>'
    )


def _sankey(store: Store) -> str:
    """Severity-colored Sankey: scanned → severity → filed → PR opened → merged.
    Hand-rendered inline SVG (no JS); ribbon width ∝ number of findings."""
    findings = store.all_findings()
    rems = store.all()
    KEYS = ["critical", "high", "medium", "low"]
    low = lambda x: (x or "").lower()

    total_by = {k: 0 for k in KEYS}
    filed_by = {k: 0 for k in KEYS}
    for f in findings:
        s = low(f.get("severity"))
        if s in total_by:
            total_by[s] += 1
            if f["status"] == "filed":
                filed_by[s] += 1
    pr_by = {k: 0 for k in KEYS}
    merged_by = {k: 0 for k in KEYS}
    for r in rems:
        s = low(r.get("severity"))
        if s in pr_by:
            if r.get("pr_url"):
                pr_by[s] += 1
            if low(r.get("pr_state")) == "merged":
                merged_by[s] += 1

    total = len(findings)
    if total == 0:
        return '<div class="cap">No findings yet — run a scan.</div>'

    W, H, pad, nw, gap = 760, 300, 30, 12, 10
    scale = (H - 2 * pad - 3 * gap) / total
    colx = {"scan": 8, "sev": 200, "filed": 400, "pr": 560, "merged": 726}
    ncol = {"scan": "#94a3b8", "filed": "#2563eb", "pr": "#1d4ed8", "merged": "#16a34a"}

    nodes = {}  # id -> [x, y, h, color]
    nodes["scan"] = [colx["scan"], pad, total * scale, ncol["scan"]]
    y = pad
    for k in KEYS:
        h = total_by[k] * scale
        nodes["sev:" + k] = [colx["sev"], y, h, _SEV_COLOR[k]]
        y += h + gap
    for cid, vb in (("filed", filed_by), ("pr", pr_by), ("merged", merged_by)):
        h = sum(vb.values()) * scale
        nodes[cid] = [colx[cid], (H - h) / 2, h, ncol[cid]]

    out = {nid: nodes[nid][1] for nid in nodes}
    inc = {nid: nodes[nid][1] for nid in nodes}
    ribbons = []

    def ribbon(sid, tid, val, color):
        if val <= 0:
            return
        w = val * scale
        xs = nodes[sid][0] + nw
        xt = nodes[tid][0]
        ys0, ys1 = out[sid], out[sid] + w
        yt0, yt1 = inc[tid], inc[tid] + w
        out[sid], inc[tid] = ys1, yt1
        xc = (xs + xt) / 2
        d = (f"M{xs:.1f},{ys0:.1f} C{xc:.1f},{ys0:.1f} {xc:.1f},{yt0:.1f} {xt:.1f},{yt0:.1f} "
             f"L{xt:.1f},{yt1:.1f} C{xc:.1f},{yt1:.1f} {xc:.1f},{ys1:.1f} {xs:.1f},{ys1:.1f} Z")
        ribbons.append(f'<path d="{d}" style="fill:{color};opacity:.38"/>')

    for k in KEYS:
        ribbon("scan", "sev:" + k, total_by[k], _SEV_COLOR[k])
    for k in KEYS:
        ribbon("sev:" + k, "filed", filed_by[k], _SEV_COLOR[k])
    for k in KEYS:
        ribbon("filed", "pr", pr_by[k], _SEV_COLOR[k])
    for k in KEYS:
        ribbon("pr", "merged", merged_by[k], _SEV_COLOR[k])

    rects = []
    for nid, (x, ny, h, color) in nodes.items():
        if h <= 0:
            continue
        rects.append(f'<rect x="{x}" y="{ny:.1f}" width="{nw}" height="{max(h,2):.1f}" '
                     f'rx="3" style="fill:{color}"/>')

    # Name each severity band next to its node (color-matched) so the colours
    # are self-explanatory — the label doubles as the legend.
    sev_labels = []
    for k in KEYS:
        x, ny, h, color = nodes["sev:" + k]
        if h <= 0:
            continue
        sev_labels.append(
            f'<text x="{x + nw + 6}" y="{ny + h / 2 + 4:.1f}" text-anchor="start" '
            f'style="fill:{color};font:700 11px var(--m,ui-sans-serif)">'
            f'{k.capitalize()} {total_by[k]}</text>')

    def hdr(cx, title, count, anchor="middle"):
        return (f'<text x="{cx}" y="16" text-anchor="{anchor}" '
                f'style="fill:#6b7280;font:600 11px var(--m,ui-sans-serif)">{title}</text>'
                f'<text x="{cx}" y="{H-8}" text-anchor="{anchor}" '
                f'style="fill:#374151;font:700 13px ui-monospace,monospace">{count}</text>')

    labels = (
        hdr(8, "Scanned", total, "start")
        + hdr(206, "By severity", "")
        + hdr(406, "Filed", sum(filed_by.values()))
        + hdr(566, "PRs opened", sum(pr_by.values()))
        + hdr(732, "Merged", sum(merged_by.values()), "end")
    )
    return (f'<svg viewBox="0 0 {W} {H}" style="width:100%;height:auto;display:block">'
            f'{"".join(ribbons)}{"".join(rects)}{"".join(sev_labels)}{labels}</svg>')


def _funnel_row(label: str, value: int, total: int, color: str) -> str:
    pct = (value / total * 100) if total else 0
    return (
        f'<div class="frow"><div class="flabel">{_esc(label)}</div>'
        f'<div class="ftrack"><div class="fbar" style="width:{pct:.0f}%;background:{color}"></div></div>'
        f'<div class="fval">{value}<span class="fpct"> {pct:.0f}%</span></div></div>'
    )


def render_analytics(store: Store) -> str:
    m = summarize(store)
    findings = store.all_findings()

    # KPI row — the leader's glance.
    merge_rate = (m["prs_merged"] / m["prs_opened"] * 100) if m["prs_opened"] else 0
    kpis = "".join([
        _stat("Open backlog", str(m["findings_open"]), "#d97706"),
        _stat("Issues filed", str(m["findings_filed"]), "#2563eb"),
        _stat("PRs opened", str(m["prs_opened"]), "#16a34a"),
        _stat("Success rate", f'{m["success_rate"] * 100:.0f}%', "#16a34a"),
        _stat("Avg time→PR", _fmt_duration(m["avg_time_to_pr_seconds"])),
        _stat("ACU cost", f'{m["acus_consumed"]:.1f}', "#6b7280"),
    ])

    # Backlog burndown — open findings over time (+1 found, -1 filed/dismissed).
    events = []
    for f in findings:
        if f.get("created_at"):
            events.append((f["created_at"], 1))
        if f["status"] in ("filed", "dismissed") and f.get("updated_at"):
            events.append((f["updated_at"], -1))
    events.sort(key=lambda e: e[0])
    series, cur = [0], 0
    for _, delta in events:
        cur += delta
        series.append(cur)
    burndown = _svg_area(series)

    # Remediation funnel — conversion from finding to merged PR.
    found = len(findings)
    funnel = "".join([
        _funnel_row("Findings found", found, found, "#94a3b8"),
        _funnel_row("Filed as issues", m["findings_filed"], found, "#2563eb"),
        _funnel_row("PRs opened", m["prs_opened"], found, _ACCENT),
        _funnel_row("PRs merged", m["prs_merged"], found, "#16a34a"),
    ])

    # Open findings by severity — current risk posture.
    open_f = [f for f in findings if f["status"] == "open"]
    counts = _sev_counts(open_f)
    total_open = sum(counts.values())
    if total_open:
        segs = "".join(
            f'<div class="sevseg" style="width:{counts[k] / total_open * 100:.1f}%;'
            f'background:{_SEV_COLOR[k]}"></div>'
            for k in ("critical", "high", "medium", "low") if counts[k]
        )
        legend = "".join(
            f'<div class="li"><span class="sw" style="background:{_SEV_COLOR[k]}"></span>'
            f'{k.capitalize()} <b>{counts[k]}</b></div>'
            for k in ("critical", "high", "medium", "low")
        )
        sev_block = f'<div class="sevbar">{segs}</div><div class="legend">{legend}</div>'
    else:
        sev_block = '<div class="cap">No open findings — backlog clear. 🎉</div>'

    content = f"""
    <div class="head"><h1>📊 Analytics</h1>
      <span class="sub">How the remediation fleet is performing</span>{{{{LIVE}}}}</div>
    <div class="stats">{kpis}</div>
    <div class="panel" style="margin-bottom:16px;">
      <h3>Remediation flow</h3>
      <p class="cap">Every finding's journey — scanned → severity → filed as an issue → PR opened → merged.
         Ribbon width is the number of findings; most still sit in the backlog.</p>
      {_sankey(store)}
    </div>
    <div class="grid2">
      <div class="panel">
        <h3>Backlog burndown</h3>
        <p class="cap">Open findings over time — rises on each scan, falls as Devin ships fixes.</p>
        {burndown}
      </div>
      <div class="panel">
        <h3>Remediation funnel</h3>
        <p class="cap">Conversion from a raw finding to a merged pull request.</p>
        {funnel}
      </div>
    </div>
    <div class="panel" style="margin-top:16px;">
      <h3>Open findings by severity</h3>
      <p class="cap">Current risk posture across everything not yet remediated.</p>
      {sev_block}
    </div>"""
    return _layout("/analytics", content, 10)
