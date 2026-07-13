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
