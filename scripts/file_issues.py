#!/usr/bin/env python3
"""Create the `devin` label and the three remediation issues on the fork.

Idempotent-ish: skips creating the label if it already exists. Re-running will
create duplicate issues, so run once. Requires the `gh` CLI authenticated to the
account that owns the fork (louisgrimaldi).

Usage:
    python scripts/file_issues.py                 # file all three
    python scripts/file_issues.py --dry-run       # print what would be filed
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

REPO = "louisgrimaldi/superset"
LABEL = "devin"

ISSUES = [
    {
        "title": "Security: HTTP requests issued without a timeout (bandit B113)",
        "body": (
            "Several outbound HTTP calls use `requests`/`httpx` without a `timeout=` "
            "argument. Without a timeout these calls can hang indefinitely if the remote "
            "host stalls, tying up a worker thread — a denial-of-service risk. This is "
            "flagged by bandit as **B113 (request_without_timeout)**.\n\n"
            "**Scope of fix**\n"
            "- Find calls to `requests.get/post/put/delete/head/patch` and `requests.request` "
            "(and equivalent `httpx` calls) that omit `timeout=`.\n"
            "- Add a sensible explicit timeout (e.g. `timeout=30`).\n"
            "- Do not change behaviour otherwise.\n\n"
            "**Verification**\n"
            "- `bandit -r superset -t B113` (or `grep -rn 'requests\\.\\(get\\|post\\|put\\|"
            "delete\\|patch\\|head\\|request\\)('`) should no longer report timeout-less calls "
            "in the touched files."
        ),
    },
    {
        "title": "Code quality: bare `except:` clauses swallow all exceptions",
        "body": (
            "Bare `except:` (or overly broad `except Exception:` that silently `pass`es) "
            "hides real errors including `KeyboardInterrupt`/`SystemExit` and makes debugging "
            "harder. Flagged by flake8 **E722 (do not use bare except)**.\n\n"
            "**Scope of fix**\n"
            "- Locate bare `except:` clauses.\n"
            "- Replace with a specific exception type where the intent is clear, or at minimum "
            "`except Exception:` while preserving/logging the error.\n"
            "- Keep the change minimal and behaviour-preserving.\n\n"
            "**Verification**\n"
            "- `flake8 --select=E722` reports no violations in the touched files."
        ),
    },
    {
        "title": "Dependency hygiene: pin an unpinned/loosely-pinned dependency",
        "body": (
            "At least one dependency is specified without an upper bound or exact pin, which "
            "allows non-reproducible builds and unexpected breakage when a new major version "
            "ships. Pick one clearly loosely-pinned dependency in the requirements files.\n\n"
            "**Scope of fix**\n"
            "- Identify a dependency in `requirements/*.txt` (or `setup.py`/`pyproject.toml`) "
            "with no version constraint or only a lower bound.\n"
            "- Pin it to the currently-resolved compatible version and add a short comment "
            "explaining the pin.\n"
            "- Change exactly one dependency; keep the diff tiny and easy to review.\n\n"
            "**Verification**\n"
            "- The dependency now has an explicit version constraint; note in the PR which one "
            "and why."
        ),
    },
]


def sh(args: list[str]) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def ensure_label() -> None:
    existing = json.loads(sh(["gh", "label", "list", "-R", REPO, "--json", "name", "-L", "200"]))
    if any(l["name"] == LABEL for l in existing):
        print(f"label '{LABEL}' already exists")
        return
    sh(["gh", "label", "create", LABEL, "-R", REPO, "--color", "5319e7",
        "--description", "Auto-remediated by the Devin pipeline"])
    print(f"created label '{LABEL}'")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    if args.dry_run:
        for i in ISSUES:
            print(f"[dry-run] would file: {i['title']}")
        return

    ensure_label()
    for issue in ISSUES:
        url = sh(["gh", "issue", "create", "-R", REPO, "--title", issue["title"],
                  "--body", issue["body"], "--label", LABEL])
        print(f"filed: {url}")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        print(e.stderr, file=sys.stderr)
        sys.exit(1)
