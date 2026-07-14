# Devin Remediation Console

Event-driven automation on the [Devin API](https://docs.devin.ai/api-reference/overview): scan a repo
for security & code-quality issues, file them as GitHub issues, and let **Devin** remediate them — each
PR is then **independently reviewed by a separate Devin session** and **autofixed** until it converges
or escalates to a human. A live console shows the whole loop.

The console has no fix logic of its own — it triggers, observes, and reports; **Devin does the
engineering.** Demo target: a fork of [apache/superset](https://github.com/apache/superset).

---

## The loop

```
(1) scan         Devin session (auditor) → ranked findings              [structured output]
(2) triage/file  selected findings → GitHub issues (labeled `devin`)
(3) trigger      issues webhook  ·  /devin comment  ·  poller → POST /webhook   [HMAC verified]
(4) remediate    Devin session (fixer) → opens a PR                      [scoped prompt + schema]
(5) reconcile    poll status + pull_requests[] → comment PR back → Review/Analytics
(6) review       PR opened (pull_request webhook) → INDEPENDENT Devin review   [advisory, red/🟡/⚪]
(7) autofix      request_changes → bounded fix → push → re-review (round+1)
                 approve ── or ── round cap reached → escalate to a human
```

**Devin as the primitive, three times:** auditor (scan), fixer (remediate), reviewer (review/autofix).
Steps 6–7 follow Cognition's own patterns — [independent PR review](https://cognition.com/blog/devin-101-automatic-pr-reviews-with-the-devin-api)
and [closing the agent loop](https://cognition.com/blog/closing-the-agent-loop-devin-autofixes-review-comments):

- The **reviewer** is a fresh session that never wrote the code and is **advisory-only** (can't
  commit/push) — its verdict is consumed as structured data, so it can't start a comment loop. One
  consolidated comment per commit SHA.
- The **autofix** is scoped to only the flagged red findings, pushes to the same branch, and the new
  commit is **re-reviewed**. It converges by shrinking scope each round; **capped**, then **escalated**.

Everything is **idempotent** — per issue (no double-dispatch) and per commit SHA (no double-review).

---

## Run it

```bash
cp .env.example .env       # DEVIN_API_KEY, DEVIN_ORG_ID, GITHUB_TOKEN, GITHUB_WEBHOOK_SECRET, TARGET_REPO
docker compose up --build  # → http://localhost:8000
```

- `GITHUB_TOKEN` needs `repo` scope (`gh auth token` works for a local demo).
- Real PRs require Devin's GitHub app connected to the repo owner (Devin UI → Settings → GitHub).

Without Docker:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload    # → http://localhost:8000
```

---

## Simulate the workflow (no ACUs, no public URL)

Set **`DISPATCH_ENABLED=0`** for a full dry-run: the pipeline ingests realistic **mock findings** and
records every event — scan history, triage, issue filing — **without creating a single Devin session**.

Drive it end-to-end:

1. **🛡️ Security** → **Perform Devin scan** → findings ranked by severity.
2. Tick findings → **Create GitHub issues from selected** — this fires a **signed webhook at `/webhook`**
   (the same path GitHub uses), so the trigger path is identical to production.
3. Watch **🔀 Review** (PR · independent-review verdict · autofix state) and **📊 Analytics** (rollup).

Helper scripts (`scripts/`): `file_issues.py` (seed + label issues), `simulate_webhook.py` (signed
webhook, no public URL needed), `dispatch_one.py` (dispatch one remediation directly).

---

## Console

| Tab | What it shows |
|-----|---------------|
| **🛡️ Security** | Run a Devin code scan; findings ranked by severity; scan-history log; select which to file. |
| **🔀 Review** | Each issue Devin is remediating, its PR, the **independent review verdict** (red/🟡/⚪), and **autofix-loop** state. |
| **📊 Analytics** | KPI row, remediation **Sankey**, backlog **burndown**, **funnel**, severity posture. |
| **⚙️ Settings** | Remediation trigger (issue / `/devin`), **review** trigger (on PR open / manual), **autofix** on/off, scan schedule. |

## Components (`app/`)

| File | Responsibility |
|------|----------------|
| `main.py` | FastAPI routes + background loops (reconcile, scan scheduler, poller); `/webhook` (issues + `pull_request`). |
| `pipeline.py` | Orchestration: scan, file, remediate, `enqueue_review`, `reconcile_autofix`. |
| `devin.py` | Devin v3 client (create/get session, mode + ACU overrides, extract PR). |
| `github.py` | HMAC verify, issues/comments, PR head SHA + real `created_at`, idempotent review comment. |
| `prompts.py` | Scan / remediation / review / autofix prompts + structured-output schemas. |
| `db.py` | SQLite state: scans, findings, remediations, reviews (+ autofix loop), settings. |
| `metrics.py` | Prometheus + summary, derived from the store (single source of truth). |
| `dashboard.py` | Server-rendered console; inline-SVG charts (no build step). |

## Observability

- **📊 Analytics** — burndown, Sankey/funnel, severity posture, KPIs (backlog · PRs · success rate · time-to-PR · cost).
- **`/metrics`** — Prometheus gauges/counters. **`/api/state`** — full JSON. **Structured JSON logs** — one line per event.

Success is concrete: a remediation succeeds when Devin opens a PR (measured against the PR's real
GitHub `created_at`), the review verdict gates the merge, and the PR link is posted back on the issue.

## Config & safety

- **`DISPATCH_ENABLED=0`** — dry-run, no sessions, no ACUs.
- ACU caps: `DEVIN_MAX_ACU`, `REVIEW_MAX_ACU`, `AUTOFIX_MAX_ACU`; loop bound: `AUTOFIX_MAX_ROUNDS`.
- HMAC (`X-Hub-Signature-256`) on `/webhook`; idempotent per issue and per commit SHA.
