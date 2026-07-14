"""Thin client over the Devin v3 Organization API.

Only the handful of endpoints this pipeline needs: create a session, and
poll a session's status/PRs. See docs.devin.ai/api-reference/v3.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from .config import settings
from .logging_setup import log

logger = logging.getLogger("devin")


class DevinClient:
    def __init__(self) -> None:
        self._client = httpx.Client(
            base_url=f"{settings.devin_base_url}/organizations/{settings.devin_org_id}",
            headers={"Authorization": f"Bearer {settings.devin_api_key}"},
            timeout=30.0,
        )

    def create_session(
        self,
        *,
        prompt: str,
        title: str,
        tags: list[str],
        structured_output_schema: Optional[dict] = None,
        devin_mode: Optional[str] = None,
        max_acu: Optional[int] = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "prompt": prompt,
            "title": title,
            "tags": tags,
            "repos": [settings.target_repo],
            "devin_mode": devin_mode or settings.devin_mode,
            "max_acu_limit": max_acu or settings.devin_max_acu,
        }
        if structured_output_schema:
            body["structured_output_schema"] = structured_output_schema
        resp = self._client.post("/sessions", json=body)
        resp.raise_for_status()
        data = resp.json()
        log(
            logger,
            logging.INFO,
            "devin.session.created",
            session_id=data.get("session_id"),
            url=data.get("url"),
            title=title,
        )
        return data

    def get_session(self, session_id: str) -> dict[str, Any]:
        resp = self._client.get(f"/sessions/{session_id}")
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def extract_pr(session: dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
        """Return (pr_url, pr_state) from a session, if a PR exists yet."""
        prs = session.get("pull_requests") or []
        if not prs:
            return None, None
        pr = prs[0]
        return pr.get("pr_url") or pr.get("url"), pr.get("pr_state") or pr.get("state")

    def close(self) -> None:
        self._client.close()
