"""Builds the scoped remediation prompt and structured-output contract that
each Devin session is dispatched with.

The prompt is deliberately narrow: it hands Devin one issue, tells it to work
only within that scope, and requires it to open a PR. The structured-output
schema forces Devin to return machine-readable results the pipeline can log
and display without scraping free text.
"""
from __future__ import annotations

from .config import settings

# Devin must return an object matching this JSON Schema (Draft 7).
REMEDIATION_SCHEMA = {
    "type": "object",
    "properties": {
        "remediation_status": {
            "type": "string",
            "enum": ["fixed", "partial", "cannot_fix"],
            "description": "Outcome of the remediation attempt.",
        },
        "summary": {
            "type": "string",
            "description": "One-paragraph summary of what was changed and why.",
        },
        "files_changed": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Repo-relative paths touched by the fix.",
        },
        "pr_url": {"type": "string", "description": "URL of the opened pull request."},
        "verification": {
            "type": "string",
            "description": "How the fix was verified (lint/tests/grep) and the result.",
        },
    },
    "required": ["remediation_status", "summary"],
}


def build_prompt(issue_number: int, issue_title: str, issue_body: str) -> str:
    return f"""\
You are an autonomous remediation engineer working on the repository \
`{settings.target_repo}`.

You have been assigned ONE issue to fix. Stay strictly within its scope — do \
not refactor unrelated code or bundle other changes.

## Issue #{issue_number}: {issue_title}

{issue_body}

## Your task
1. Locate the exact code the issue refers to.
2. Implement the smallest correct fix.
3. Verify it (run the relevant linter/tests, or grep to confirm the pattern is \
gone). Do not claim success without verification.
4. Open a pull request against `{settings.target_repo}` with a clear title and \
a description that references issue #{issue_number} (e.g. "Fixes #{issue_number}").
5. Return the structured output describing the outcome, including the PR URL.

If you genuinely cannot fix it, return remediation_status="cannot_fix" with a \
clear explanation rather than opening a low-quality PR.
"""


def title_for(issue_number: int, issue_title: str) -> str:
    return f"Remediate #{issue_number}: {issue_title[:80]}"


# ---------------------------------------------------------------------------
# Discovery (scan) — Devin as the auditor.
#
# This mirrors what Devin's native Security / Code Scan product does, but built
# on the sessions API: dispatch one session that runs the standard Python
# scanners, aggregates + ranks the results, and returns them as structured data.
# ---------------------------------------------------------------------------

# Devin must return an object matching this JSON Schema (Draft 7).
SCAN_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short, specific title (e.g. 'HTTP request without timeout').",
                    },
                    "category": {
                        "type": "string",
                        "enum": ["security", "code_quality", "lint", "formatting", "dependency"],
                    },
                    "tool": {
                        "type": "string",
                        "description": "Scanner that surfaced it (bandit, flake8, pip-audit, black, isort, ...).",
                    },
                    "rule": {
                        "type": "string",
                        "description": "Rule/code id if any (e.g. B113, E722, CVE-XXX).",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                    },
                    "priority": {
                        "type": "integer",
                        "description": "Overall rank, 1 = most important, ascending.",
                    },
                    "location": {
                        "type": "string",
                        "description": "Representative file path (and line, if known).",
                    },
                    "description": {
                        "type": "string",
                        "description": "What the problem is and why it matters, in 1-2 sentences.",
                    },
                    "recommendation": {
                        "type": "string",
                        "description": "The concrete fix.",
                    },
                },
                "required": ["title", "category", "severity", "priority"],
            },
        }
    },
    "required": ["findings"],
}


def build_scan_prompt(max_findings: int) -> str:
    return f"""\
You are an autonomous code-scanning engineer auditing the repository \
`{settings.target_repo}`. This is a READ-ONLY audit — do NOT modify code, do \
NOT open a pull request.

## Your task
Run the standard Python static-analysis toolchain against the repo and \
aggregate the results into a single ranked list of findings:
  - **Security:** `bandit -r .` (e.g. B113 requests without timeout, B602 \
subprocess with shell=True, B101 assert, hardcoded secrets).
  - **Dependency vulnerabilities:** `pip-audit` / `safety` on the requirements \
files (known CVEs, unpinned or outdated packages).
  - **Code quality / lint:** `flake8` (e.g. E722 bare except, unused imports, \
undefined names).
  - **Formatting:** `black --check` / `isort --check` style deviations.

Group similar hits into one finding (don't emit one row per line). For each \
finding assign a `severity` and an overall `priority` (1 = fix first). Rank \
security and dependency vulnerabilities above lint/formatting.

Return AT MOST {max_findings} findings, highest priority first, as the \
structured output. Each finding needs a clear, actionable title, a \
representative `location`, and a one-line `recommendation`. Base every finding \
on real scanner output — do not invent issues.
"""


def scan_title() -> str:
    return f"Code scan: {settings.target_repo}"
