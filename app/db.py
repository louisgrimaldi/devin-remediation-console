"""SQLite state store for the whole console.

Three concerns, three tables:
  * `scans`        — one row per Devin scan (discovery) run; the scan history log.
  * `findings`     — ranked issues surfaced by a scan; each can be filed as a GitHub issue.
  * `remediations` — one row per filed issue -> Devin session -> PR (the fixing side).

Kept deliberately small and synchronous; the workloads here are tiny and
SQLite's simplicity is worth more than async cleverness for a demo.
"""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_LOCK = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


SCHEMA = """
CREATE TABLE IF NOT EXISTS remediations (
    issue_number     INTEGER PRIMARY KEY,
    repo             TEXT    NOT NULL,
    issue_title      TEXT,
    issue_url        TEXT,
    devin_session_id TEXT,
    devin_url        TEXT,
    status           TEXT    NOT NULL DEFAULT 'queued',
    status_detail    TEXT,
    severity         TEXT,
    category         TEXT,
    priority         INTEGER,
    pr_url           TEXT,
    pr_state         TEXT,
    acus_consumed    REAL    DEFAULT 0,
    commented_back   INTEGER DEFAULT 0,
    error            TEXT,
    created_at       TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL,
    dispatched_at    TEXT,
    pr_opened_at     TEXT,
    completed_at     TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id           TEXT PRIMARY KEY,
    repo              TEXT NOT NULL,
    devin_session_id  TEXT,
    devin_url         TEXT,
    status            TEXT NOT NULL DEFAULT 'running',
    status_detail     TEXT,
    acus_consumed     REAL DEFAULT 0,
    num_findings      INTEGER DEFAULT 0,
    findings_ingested INTEGER DEFAULT 0,
    is_mock           INTEGER DEFAULT 0,
    error             TEXT,
    started_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    completed_at      TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        TEXT NOT NULL,
    repo           TEXT NOT NULL,
    category       TEXT,
    tool           TEXT,
    rule           TEXT,
    severity       TEXT,
    priority       INTEGER DEFAULT 999,
    title          TEXT NOT NULL,
    description    TEXT,
    location       TEXT,
    recommendation TEXT,
    status         TEXT NOT NULL DEFAULT 'open',
    issue_number   INTEGER,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- One independent Devin review per PR commit SHA (idempotency key). Keeps the
-- reviewer's verdict as structured data so it never turns into a comment loop.
CREATE TABLE IF NOT EXISTS reviews (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    repo             TEXT NOT NULL,
    pr_url           TEXT NOT NULL,
    pr_number        INTEGER,
    issue_number     INTEGER,
    head_sha         TEXT NOT NULL,
    devin_session_id TEXT,
    devin_url        TEXT,
    status           TEXT NOT NULL DEFAULT 'queued',
    status_detail    TEXT,
    verdict          TEXT,
    summary          TEXT,
    n_red            INTEGER DEFAULT 0,
    n_yellow         INTEGER DEFAULT 0,
    n_gray           INTEGER DEFAULT 0,
    acus_consumed    REAL DEFAULT 0,
    comment_posted   INTEGER DEFAULT 0,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    completed_at     TEXT,
    UNIQUE(pr_url, head_sha)
);
"""

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class Store:
    def __init__(self, path: str) -> None:
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.executescript(SCHEMA)
        self._ensure_column("remediations", "pr_opened_at", "TEXT")
        self._ensure_column("remediations", "severity", "TEXT")
        self._ensure_column("remediations", "category", "TEXT")
        self._ensure_column("remediations", "priority", "INTEGER")
        # Autofix loop state, hung off the review row it belongs to.
        self._ensure_column("reviews", "round", "INTEGER DEFAULT 1")
        self._ensure_column("reviews", "autofix_session_id", "TEXT")
        self._ensure_column("reviews", "autofix_url", "TEXT")
        self._ensure_column("reviews", "autofix_status", "TEXT")
        self._ensure_column("reviews", "reviewed_next", "INTEGER DEFAULT 0")
        self._ensure_column("reviews", "escalated", "INTEGER DEFAULT 0")
        self._conn.commit()
        self._backfill_remediation_severity()

    def _ensure_column(self, table: str, column: str, decl: str) -> None:
        """Add a column to an existing table if it's missing (lightweight migration)."""
        cols = {r["name"] for r in self._conn.execute(f"PRAGMA table_info({table})")}
        if column not in cols:
            self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

    def _write(self, sql: str, params: tuple) -> None:
        with _LOCK:
            self._conn.execute(sql, params)
            self._conn.commit()

    # -------------------------------------------------------------- settings
    def get_setting(self, key: str, default: str) -> str:
        cur = self._conn.execute("SELECT value FROM app_settings WHERE key=?", (key,))
        row = cur.fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        self._write(
            "INSERT OR REPLACE INTO app_settings (key, value) VALUES (?,?)",
            (key, value),
        )

    # ------------------------------------------------------------------ scans
    def insert_scan(
        self, *, scan_id: str, repo: str, session_id: Optional[str],
        devin_url: str, status: str, is_mock: bool,
    ) -> None:
        now = _now()
        completed = now if status in {"exit", "error"} else None
        self._write(
            """INSERT OR REPLACE INTO scans
               (scan_id, repo, devin_session_id, devin_url, status, is_mock,
                started_at, updated_at, completed_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (scan_id, repo, session_id, devin_url, status, int(is_mock), now, now, completed),
        )

    def update_scan(
        self, scan_id: str, *, status: str, status_detail: Optional[str] = None,
        acus: Optional[float] = None, num_findings: Optional[int] = None,
        findings_ingested: Optional[bool] = None, error: Optional[str] = None,
    ) -> None:
        completed = _now() if status in {"exit", "error", "complete"} else None
        self._write(
            """UPDATE scans SET
                 status=?,
                 status_detail=COALESCE(?, status_detail),
                 acus_consumed=COALESCE(?, acus_consumed),
                 num_findings=COALESCE(?, num_findings),
                 findings_ingested=COALESCE(?, findings_ingested),
                 error=COALESCE(?, error),
                 updated_at=?,
                 completed_at=COALESCE(?, completed_at)
               WHERE scan_id=?""",
            (status, status_detail, acus, num_findings,
             (int(findings_ingested) if findings_ingested is not None else None),
             error, _now(), completed, scan_id),
        )

    def get_scan(self, scan_id: str) -> Optional[dict[str, Any]]:
        cur = self._conn.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def all_scans(self) -> list[dict[str, Any]]:
        cur = self._conn.execute("SELECT * FROM scans ORDER BY started_at DESC")
        return [dict(r) for r in cur.fetchall()]

    def latest_scan(self) -> Optional[dict[str, Any]]:
        cur = self._conn.execute("SELECT * FROM scans ORDER BY started_at DESC LIMIT 1")
        row = cur.fetchone()
        return dict(row) if row else None

    def scans_to_poll(self) -> list[dict[str, Any]]:
        """Real (non-mock) scans whose session hasn't reached a terminal state.

        Kept polling even after findings are ingested so the status settles to
        `exit` when the session finishes (findings are only ingested once)."""
        cur = self._conn.execute(
            """SELECT * FROM scans
               WHERE is_mock=0 AND status NOT IN ('exit','error','complete')"""
        )
        return [dict(r) for r in cur.fetchall()]

    # --------------------------------------------------------------- findings
    def add_findings(self, scan_id: str, repo: str, findings: list[dict[str, Any]]) -> int:
        """Insert findings for a scan, skipping ones whose title already exists
        (open or filed) so re-scans don't pile up duplicates. Returns count added."""
        added = 0
        with _LOCK:
            for f in findings:
                title = (f.get("title") or "").strip()
                if not title:
                    continue
                dup = self._conn.execute(
                    "SELECT 1 FROM findings WHERE title=? AND status IN ('open','filed')",
                    (title,),
                ).fetchone()
                if dup:
                    continue
                now = _now()
                self._conn.execute(
                    """INSERT INTO findings
                       (scan_id, repo, category, tool, rule, severity, priority,
                        title, description, location, recommendation, status,
                        created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?, 'open', ?, ?)""",
                    (scan_id, repo, f.get("category"), f.get("tool"), f.get("rule"),
                     (f.get("severity") or "").lower(), int(f.get("priority") or 999),
                     title, f.get("description"), f.get("location"),
                     f.get("recommendation"), now, now),
                )
                added += 1
            self._conn.commit()
        return added

    def get_finding(self, finding_id: int) -> Optional[dict[str, Any]]:
        cur = self._conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def findings_by_status(self, status: str) -> list[dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT * FROM findings WHERE status=? ORDER BY priority ASC, id ASC",
            (status,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        rows.sort(key=lambda r: (_SEVERITY_ORDER.get(r.get("severity"), 9), r.get("priority", 999)))
        return rows

    def all_findings(self) -> list[dict[str, Any]]:
        cur = self._conn.execute("SELECT * FROM findings ORDER BY priority ASC, id ASC")
        return [dict(r) for r in cur.fetchall()]

    def findings_by_scan(self, scan_id: str) -> list[dict[str, Any]]:
        cur = self._conn.execute("SELECT * FROM findings WHERE scan_id=?", (scan_id,))
        rows = [dict(r) for r in cur.fetchall()]
        rows.sort(key=lambda r: (_SEVERITY_ORDER.get(r.get("severity"), 9), r.get("priority", 999)))
        return rows

    def mark_finding_filed(self, finding_id: int, issue_number: int) -> None:
        self._write(
            "UPDATE findings SET status='filed', issue_number=?, updated_at=? WHERE id=?",
            (issue_number, _now(), finding_id),
        )

    def mark_finding_dismissed(self, finding_id: int) -> None:
        self._write(
            "UPDATE findings SET status='dismissed', updated_at=? WHERE id=?",
            (_now(), finding_id),
        )

    def get_finding_by_issue(self, issue_number: int) -> Optional[dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT * FROM findings WHERE issue_number=? ORDER BY id DESC LIMIT 1",
            (issue_number,),
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def _backfill_remediation_severity(self) -> None:
        """Populate severity/category/priority on remediations that predate
        these columns, from their originating finding (idempotent)."""
        rows = self._conn.execute(
            "SELECT issue_number FROM remediations WHERE severity IS NULL"
        ).fetchall()
        for r in rows:
            f = self.get_finding_by_issue(r["issue_number"])
            if f:
                self._conn.execute(
                    "UPDATE remediations SET severity=?, category=?, priority=? WHERE issue_number=?",
                    (f.get("severity"), f.get("category"), f.get("priority"), r["issue_number"]),
                )
        self._conn.commit()

    # ----------------------------------------------------------- remediations
    def upsert_issue(self, *, issue_number: int, repo: str, title: str, url: str) -> bool:
        """Register an issue for remediation. Returns True if newly inserted."""
        with _LOCK:
            cur = self._conn.execute(
                "SELECT 1 FROM remediations WHERE issue_number=?", (issue_number,)
            )
            if cur.fetchone():
                return False
            now = _now()
            self._conn.execute(
                """INSERT INTO remediations
                   (issue_number, repo, issue_title, issue_url, status, created_at, updated_at)
                   VALUES (?,?,?,?, 'queued', ?, ?)""",
                (issue_number, repo, title, url, now, now),
            )
            self._conn.commit()
            return True

    def set_remediation_meta(self, issue_number: int, severity, category, priority) -> None:
        """Carry the originating finding's severity/category/priority onto the
        remediation so the classification stays continuous into the Review tab."""
        self._write(
            "UPDATE remediations SET severity=?, category=?, priority=?, updated_at=? WHERE issue_number=?",
            (severity, category, priority, _now(), issue_number),
        )

    def mark_dispatched(self, issue_number: int, session_id: str, devin_url: str) -> None:
        self._write(
            """UPDATE remediations
               SET devin_session_id=?, devin_url=?, status='running',
                   dispatched_at=?, updated_at=? WHERE issue_number=?""",
            (session_id, devin_url, _now(), _now(), issue_number),
        )

    def mark_error(self, issue_number: int, error: str) -> None:
        self._write(
            "UPDATE remediations SET status='error', error=?, updated_at=? WHERE issue_number=?",
            (error, _now(), issue_number),
        )

    def update_from_session(
        self,
        issue_number: int,
        *,
        status: str,
        status_detail: Optional[str],
        pr_url: Optional[str],
        pr_state: Optional[str],
        acus: float,
        pr_opened_at: Optional[str] = None,
    ) -> None:
        completed_at = _now() if status in {"exit", "error"} else None
        # Stamp when the PR was opened (only sets once, via COALESCE). Prefer the
        # PR's real GitHub creation time when the caller supplies it, so the
        # metric doesn't count reconciler-detection lag; fall back to now.
        pr_opened_ts = (pr_opened_at or _now()) if pr_url else None
        self._write(
            """UPDATE remediations
               SET status=?, status_detail=?, pr_url=?,
                   pr_state=CASE WHEN pr_state='merged' THEN 'merged' ELSE ? END,
                   acus_consumed=?,
                   updated_at=?, pr_opened_at=COALESCE(pr_opened_at, ?),
                   completed_at=COALESCE(?, completed_at)
               WHERE issue_number=?""",
            (status, status_detail, pr_url, pr_state, acus, _now(),
             pr_opened_ts, completed_at, issue_number),
        )

    def mark_commented(self, issue_number: int) -> None:
        self._write(
            "UPDATE remediations SET commented_back=1, updated_at=? WHERE issue_number=?",
            (_now(), issue_number),
        )

    def get(self, issue_number: int) -> Optional[dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT * FROM remediations WHERE issue_number=?", (issue_number,)
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def all(self) -> list[dict[str, Any]]:
        # Ordered by recency of activity so a re-triggered issue floats to the top.
        cur = self._conn.execute(
            "SELECT * FROM remediations ORDER BY updated_at DESC"
        )
        return [dict(r) for r in cur.fetchall()]

    def touch(self, issue_number: int) -> None:
        """Bump updated_at so a re-triggered issue moves to the top of Review."""
        self._write(
            "UPDATE remediations SET updated_at=? WHERE issue_number=?",
            (_now(), issue_number),
        )

    def with_prs(self) -> list[dict[str, Any]]:
        """Remediations that have opened a PR — powers the Review tab."""
        cur = self._conn.execute(
            "SELECT * FROM remediations WHERE pr_url IS NOT NULL ORDER BY updated_at DESC"
        )
        return [dict(r) for r in cur.fetchall()]

    def active(self) -> list[dict[str, Any]]:
        """Rows with a live Devin session that still needs polling."""
        cur = self._conn.execute(
            """SELECT * FROM remediations
               WHERE devin_session_id IS NOT NULL AND status NOT IN ('exit','error')"""
        )
        return [dict(r) for r in cur.fetchall()]

    # ---------------------------------------------------------------- reviews
    def get_review(self, pr_url: str, head_sha: str) -> Optional[dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT * FROM reviews WHERE pr_url=? AND head_sha=?", (pr_url, head_sha)
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def create_review(
        self, *, repo: str, pr_url: str, pr_number: int,
        issue_number: Optional[int], head_sha: str, round_no: int = 1,
    ) -> Optional[int]:
        """Register a review intent for (pr_url, head_sha). Returns the new row id,
        or None if a review for this exact commit already exists (idempotent)."""
        if self.get_review(pr_url, head_sha):
            return None
        now = _now()
        with _LOCK:
            cur = self._conn.execute(
                """INSERT OR IGNORE INTO reviews
                   (repo, pr_url, pr_number, issue_number, head_sha, round, status, created_at, updated_at)
                   VALUES (?,?,?,?,?,?, 'queued', ?, ?)""",
                (repo, pr_url, pr_number, issue_number, head_sha, round_no, now, now),
            )
            self._conn.commit()
            return cur.lastrowid if cur.rowcount else None

    def mark_review_dispatched(self, review_id: int, session_id: str, url: str) -> None:
        self._write(
            """UPDATE reviews SET devin_session_id=?, devin_url=?, status='running', updated_at=?
               WHERE id=?""",
            (session_id, url, _now(), review_id),
        )

    def update_review_from_session(
        self, review_id: int, *, status: str, status_detail: Optional[str], acus: float,
        verdict: Optional[str], summary: Optional[str],
        n_red: int, n_yellow: int, n_gray: int,
    ) -> None:
        completed_at = _now() if verdict else None
        self._write(
            """UPDATE reviews
               SET status=?, status_detail=?, acus_consumed=?,
                   verdict=COALESCE(?, verdict), summary=COALESCE(?, summary),
                   n_red=?, n_yellow=?, n_gray=?, updated_at=?,
                   completed_at=COALESCE(?, completed_at)
               WHERE id=?""",
            (status, status_detail, acus, verdict, summary,
             n_red, n_yellow, n_gray, _now(), completed_at, review_id),
        )

    def mark_review_commented(self, review_id: int) -> None:
        self._write("UPDATE reviews SET comment_posted=1, updated_at=? WHERE id=?", (_now(), review_id))

    def reviews_to_poll(self) -> list[dict[str, Any]]:
        """Dispatched reviews still awaiting a verdict."""
        cur = self._conn.execute(
            """SELECT * FROM reviews
               WHERE devin_session_id IS NOT NULL AND verdict IS NULL
                 AND status NOT IN ('exit','error')"""
        )
        return [dict(r) for r in cur.fetchall()]

    def latest_review_for_issue(self, issue_number: int) -> Optional[dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT * FROM reviews WHERE issue_number=? ORDER BY id DESC LIMIT 1", (issue_number,)
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def all_reviews(self) -> list[dict[str, Any]]:
        cur = self._conn.execute("SELECT * FROM reviews ORDER BY id DESC")
        return [dict(r) for r in cur.fetchall()]

    # ------------------------------------------------------------ autofix loop
    def autofix_attempts(self, pr_url: str) -> int:
        """How many autofix rounds have already been dispatched for this PR."""
        cur = self._conn.execute(
            "SELECT COUNT(*) AS n FROM reviews WHERE pr_url=? AND autofix_session_id IS NOT NULL",
            (pr_url,),
        )
        return cur.fetchone()["n"]

    def reviews_needing_autofix(self) -> list[dict[str, Any]]:
        """Blocking reviews (request_changes) not yet handled by an autofix or escalation."""
        cur = self._conn.execute(
            """SELECT * FROM reviews
               WHERE verdict='request_changes' AND n_red > 0
                 AND autofix_session_id IS NULL AND escalated=0"""
        )
        return [dict(r) for r in cur.fetchall()]

    def set_review_autofix(self, review_id: int, session_id: str, url: str) -> None:
        self._write(
            """UPDATE reviews SET autofix_session_id=?, autofix_url=?, autofix_status='dispatched',
               updated_at=? WHERE id=?""",
            (session_id, url, _now(), review_id),
        )

    def reviews_with_active_autofix(self) -> list[dict[str, Any]]:
        """Reviews whose autofix is dispatched but hasn't yet produced a re-review."""
        cur = self._conn.execute(
            """SELECT * FROM reviews
               WHERE autofix_session_id IS NOT NULL AND reviewed_next=0 AND escalated=0"""
        )
        return [dict(r) for r in cur.fetchall()]

    def update_autofix_status(self, review_id: int, status: str) -> None:
        self._write(
            "UPDATE reviews SET autofix_status=?, updated_at=? WHERE id=?",
            (status, _now(), review_id),
        )

    def mark_review_reviewed_next(self, review_id: int) -> None:
        self._write("UPDATE reviews SET reviewed_next=1, updated_at=? WHERE id=?", (_now(), review_id))

    def mark_review_escalated(self, review_id: int) -> None:
        self._write(
            "UPDATE reviews SET escalated=1, reviewed_next=1, updated_at=? WHERE id=?",
            (_now(), review_id),
        )
