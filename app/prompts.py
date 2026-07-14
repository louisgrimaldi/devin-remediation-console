"""Builds the scoped remediation prompt and structured-output contract that
each Devin session is dispatched with.

The prompt is deliberately narrow: it hands Devin one issue, tells it to work
only within that scope, and requires it to open a PR. The structured-output
schema forces Devin to return machine-readable results the pipeline can log
and display without scraping free text.
"""
from __future__ import annotations

from typing import Optional

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


# ---------------------------------------------------------------------------
# Independent PR review — Devin as the reviewer of another Devin's PR.
#
# Follows Cognition's documented pattern (cognition.com/blog/devin-101...):
#   * a fresh, independent session per PR (not the author),
#   * severity buckets red / yellow / gray,
#   * a security review on every PR,
#   * advisory only — the reviewer NEVER commits, pushes, edits, or opens PRs;
#     its verdict is consumed as structured data, so it cannot start a
#     comment/edit loop with the author.
# ---------------------------------------------------------------------------

REVIEW_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["approve", "request_changes", "comment"],
            "description": "approve = safe to merge; request_changes = has a red "
                           "issue that should block; comment = only minor notes.",
        },
        "summary": {
            "type": "string",
            "description": "2-3 sentence plain-English review of the change.",
        },
        "security_review": {
            "type": "string",
            "description": "Security-specific assessment of the diff (every PR gets one).",
        },
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["red", "yellow", "gray"],
                        "description": "red = probable bug/blocker, yellow = warning, "
                                       "gray = FYI/nit.",
                    },
                    "category": {
                        "type": "string",
                        "enum": ["correctness", "security", "style", "test", "other"],
                    },
                    "title": {"type": "string"},
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                    "detail": {"type": "string", "description": "What and why, concise."},
                },
                "required": ["severity", "title", "detail"],
            },
        },
    },
    "required": ["verdict", "summary"],
}


def build_review_prompt(*, pr_url: str, pr_number: int, issue_number: Optional[int]) -> str:
    ref = f" It was opened to remediate issue #{issue_number}." if issue_number else ""
    return f"""\
You are an INDEPENDENT code reviewer for the repository `{settings.target_repo}`. \
You did NOT write this pull request — review it with fresh, skeptical eyes.

## Pull request to review
{pr_url} (PR #{pr_number}).{ref}

## Hard constraints (read-only, advisory review)
- DO NOT commit, push, edit files, open or update any pull request, or run the \
formatter/fixer on the branch. This is a review only.
- Produce NO free-form chatter on the PR yourself. Your ONLY output is the \
structured verdict below — the console posts a single consolidated comment from it.

## What to do
1. Read the PR diff and the surrounding code it touches.
2. Judge correctness: does the change actually fix the intended issue without \
introducing a regression? Check edge cases and whether it builds/tests.
3. Run a security review of the diff (every PR gets one): does it introduce or \
fail to close a vulnerability?
4. List concrete findings, each tagged `red` (probable bug / should block the \
merge), `yellow` (warning worth a look), or `gray` (FYI / nit). Cite file and \
line. Be specific — no generic advice.
5. Set `verdict`: `approve` if it is correct and safe to merge (no red \
findings), `request_changes` if there is a red issue, or `comment` for \
minor-only notes.

Return the structured output only.
"""


def review_title(pr_number: int) -> str:
    return f"Review PR #{pr_number}: {settings.target_repo}"


# ---------------------------------------------------------------------------
# Author-side autofix — close the loop by addressing the reviewer's findings.
#
# Follows Cognition's "closing the agent loop" + "instructing Devin effectively":
# convergence comes from a NARROW scope (fix only the flagged findings, nothing
# else), an explicit, measurable success criterion (findings resolved AND the
# repo's own gates green), and a hard round cap in the orchestrator — not from
# open-ended negotiation between sessions.
# ---------------------------------------------------------------------------

AUTOFIX_SCHEMA = {
    "type": "object",
    "properties": {
        "status": {
            "type": "string",
            "enum": ["fixed", "partial", "cannot_fix"],
            "description": "fixed = all flagged findings resolved and pushed; "
                           "partial = some resolved; cannot_fix = none.",
        },
        "summary": {"type": "string", "description": "What was changed to address the review."},
        "pushed": {"type": "boolean", "description": "Whether a new commit was pushed to the PR branch."},
        "verification": {"type": "string", "description": "Gates run (tests/lint/build) and their result."},
    },
    "required": ["status", "summary"],
}


def build_autofix_prompt(
    *, pr_url: str, pr_number: int, branch: str, round_no: int, max_rounds: int,
    findings: list[dict],
) -> str:
    listed = "\n".join(
        f"  {i+1}. [{f.get('severity','red')}] {f.get('title','')}"
        + (f" ({f['file']}{':' + str(f['line']) if f.get('line') else ''})" if f.get("file") else "")
        + f" — {f.get('detail','')}"
        for i, f in enumerate(findings)
    ) or "  (see the review comment on the PR)"
    return f"""\
You are addressing an independent reviewer's blocking findings on an existing \
pull request in `{settings.target_repo}`. This is autofix round {round_no} of a \
maximum {max_rounds}.

## Pull request
{pr_url} (PR #{pr_number}), branch `{branch}`.

## Fix ONLY these reviewer findings — nothing else
{listed}

## Hard constraints (so this converges)
- Stay strictly in scope: change only what these findings require. Do NOT \
refactor unrelated code, and do NOT open a new pull request.
- Commit and push your fix to the SAME branch `{branch}` so it updates this PR.
- Success criterion: every finding above is resolved AND the repo's own gates \
(tests / lint / type-check that apply to the touched files) pass. Do not claim \
success without running them.
- If a finding genuinely cannot be resolved without a product/architecture \
decision, set status="cannot_fix" (or "partial") and explain — do not guess.

Return the structured output describing the outcome.
"""


def autofix_title(pr_number: int, round_no: int) -> str:
    return f"Autofix PR #{pr_number} (round {round_no}): {settings.target_repo}"
