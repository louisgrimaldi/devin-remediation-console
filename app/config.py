"""Runtime configuration, loaded from environment (see .env.example)."""
from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, "1" if default else "0").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    devin_api_key: str = os.getenv("DEVIN_API_KEY", "")
    devin_org_id: str = os.getenv("DEVIN_ORG_ID", "")
    devin_base_url: str = os.getenv("DEVIN_BASE_URL", "https://api.devin.ai/v3").rstrip("/")
    devin_mode: str = os.getenv("DEVIN_MODE", "normal")
    devin_max_acu: int = int(os.getenv("DEVIN_MAX_ACU", "10"))

    # Independent PR review (Devin-as-reviewer). Kept cheap and capped: a review
    # reads a small diff, so it needs far fewer ACUs than a remediation. Reviews
    # auto-fire when a remediation first opens a PR (mirrors Cognition's
    # "review on PR open" pattern); `review_enabled=0` disables that.
    review_enabled: bool = _bool("REVIEW_ENABLED", True)
    review_max_acu: int = int(os.getenv("REVIEW_MAX_ACU", "3"))
    review_mode: str = os.getenv("REVIEW_MODE", "lite")
    # review_trigger: 'on_pr_open' (auto-review when a PR is opened, via the
    # pull_request webhook / reconciler) | 'manual' (only the Review button).
    # Runtime-tunable on the Settings tab.
    review_trigger: str = os.getenv("REVIEW_TRIGGER", "on_pr_open")

    # Author-side autofix loop: when a review returns request_changes, dispatch a
    # bounded fix session for the red findings, push to the same branch, and
    # re-review the new commit. Capped rounds, then escalate to a human — the
    # loop converges by shrinking scope each pass, not by negotiating.
    autofix_enabled: bool = _bool("AUTOFIX_ENABLED", True)
    autofix_max_rounds: int = int(os.getenv("AUTOFIX_MAX_ROUNDS", "2"))
    autofix_max_acu: int = int(os.getenv("AUTOFIX_MAX_ACU", "8"))
    autofix_mode: str = os.getenv("AUTOFIX_MODE", "normal")

    target_repo: str = os.getenv("TARGET_REPO", "louisgrimaldi/superset")

    github_token: str = os.getenv("GITHUB_TOKEN", "")
    github_webhook_secret: str = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    trigger_label: str = os.getenv("TRIGGER_LABEL", "devin")

    poll_interval_seconds: int = int(os.getenv("POLL_INTERVAL_SECONDS", "60"))
    reconcile_interval_seconds: int = int(os.getenv("RECONCILE_INTERVAL_SECONDS", "20"))
    db_path: str = os.getenv("DB_PATH", "/data/state.db")
    dispatch_enabled: bool = _bool("DISPATCH_ENABLED", True)

    # Scan (discovery) tuning.
    scan_max_findings: int = int(os.getenv("SCAN_MAX_FINDINGS", "15"))
    # Base URL the service uses to fire a webhook at itself when an issue is
    # filed from a finding (keeps the trigger path identical to production).
    self_base_url: str = os.getenv("SELF_BASE_URL", "http://127.0.0.1:8000").rstrip("/")

    # Runtime-tunable defaults (overridable live on the Settings tab).
    # remediation_trigger: 'on_creation' | 'on_comment'
    remediation_trigger: str = os.getenv("REMEDIATION_TRIGGER", "on_creation")
    # The comment command that triggers remediation in 'on_comment' mode.
    trigger_command: str = os.getenv("TRIGGER_COMMAND", "/devin")
    # scan_schedule: 'manual' | 'hourly' | 'daily' | 'weekly' | 'monthly'
    scan_schedule: str = os.getenv("SCAN_SCHEDULE", "manual")
    # How often the scheduler loop wakes to check whether a scan is due.
    scheduler_tick_seconds: int = int(os.getenv("SCHEDULER_TICK_SECONDS", "60"))

    @property
    def sessions_url(self) -> str:
        return f"{self.devin_base_url}/organizations/{self.devin_org_id}/sessions"


settings = Settings()
