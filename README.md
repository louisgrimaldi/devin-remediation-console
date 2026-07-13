# Devin Remediation Console

**Turn a detected issue into a reviewed pull request — with zero human coding.**

An event-driven automation, built on the [Devin API](https://docs.devin.ai/api-reference/overview),
that scans a repository for security & code-quality issues, lets you triage the findings,
files them as GitHub issues, and dispatches [Devin](https://devin.ai) sessions that open
remediation pull requests — with a live console for engineering leadership to see it working.

Target repo for this demo: a copy of **[apache/superset](https://github.com/apache/superset)**.

---

## Why this matters

Every engineering org sits on a backlog of small, well-understood fixes — scanner findings,
dependency bumps, lint violations. **Triage is cheap; the fix work is the toil** that clogs the
backlog and never wins priority against the roadmap. Devin changes the economics: because it can
autonomously locate code, implement a fix, verify it, and open a PR, *fixing* becomes a fleet
operation rather than human toil.

This system is the **control plane** around that primitive. It has no fix logic of its own — it
triggers, observes, and reports; **Devin does the engineering.**

---

## The console

Four tabs, mirroring Devin's own product:

| Tab | What it does |
|-----|--------------|
| **🛡️ Security** | Run a Devin **code scan** → findings ranked by severity → select which to file as issues. Full **scan history** log (duration, findings, severity breakdown). |
| **🔀 Review** | Every issue Devin is remediating and the pull requests it opened, carried through with the finding's severity. |
| **📊 Analytics** | The leader rollup: KPI row, a **Sankey** of the remediation flow, **backlog burndown**, remediation **funnel**, and **severity risk posture**. |
| **⚙️ Settings** | Configure how Devin is triggered (on issue creation, or a `/devin` comment) and an optional **scan schedule** (hourly/daily/weekly/monthly). |

---

## Architecture

```
 (1) Perform Devin scan ─► Devin session (auditor) ─► ranked findings  [structured output]
 (2) select findings     ─► create GitHub issues (labeled `devin`)
 (3) issue created / `/devin` comment ─► webhook  ──HMAC verified──►  POST /webhook
 (4) pipeline.remediate_issue ─► Devin session (fixer)  [scoped prompt + structured schema]
 (5) reconciler loop ─► poll status + pull_requests[] ─► comment PR back ─► Review + Analytics
        │
        ▼
 SQLite state ─► live console (/) · Prometheus /metrics · JSON /api/state · structured logs
```

**Devin as a primitive, twice.** Discovery is a Devin session that runs the standard Python
scanners (`bandit`, `pip-audit`, `flake8`, `black`/`isort`), aggregates and ranks the results, and
returns them as **structured output**. Remediation is a second, scoped Devin session that fixes one
issue, verifies it, and opens a PR. *(Devin's native enterprise Code Scan API is permission-gated;
this replicates its find→remediate loop on the sessions API, and would plug straight into it at scale.)*

**Event-driven, two triggers.** A GitHub webhook (`issues.opened`/`labeled`, or an `issue_comment`
containing `/devin`, HMAC-verified) is the production trigger; a scheduled scan and a labeled-issue
poller are the URL-free triggers. All converge on the same idempotent `remediate_issue`.

**Structured output as a contract.** Sessions are dispatched with a JSON-Schema so Devin returns
machine-readable results the console can rank and display without scraping free text.

### Components (`app/`)

| File | Responsibility |
|------|----------------|
| `main.py` | FastAPI app + routes (`/`, `/review`, `/analytics`, `/settings`, `/scan`, `/findings/*`, `/webhook`, `/metrics`, `/api/state`, `/healthz`) and the background loops (reconciler, scan scheduler, poller). |
| `pipeline.py` | Orchestration: start/reconcile scans, ingest findings, file findings as issues, dispatch/reconcile remediation sessions. |
| `devin.py` | Thin Devin v3 API client (create/get session, extract PR). |
| `github.py` | Webhook HMAC verification, create issues, comment PR links, poll labeled issues. |
| `prompts.py` | Scan + remediation prompts and their structured-output schemas. |
| `db.py` | SQLite state (scans, findings, remediations, settings). |
| `metrics.py` | Prometheus text + summary, computed from the store (single source of truth). |
| `dashboard.py` | Server-rendered console — the four tabs and inline-SVG charts (no build step). |
| `logging_setup.py` | Structured JSON logs for every event. |

---

## Observability — "how would I know this is working?"

- **Analytics tab** — backlog burndown, remediation Sankey/funnel, severity posture, KPI row
  (open backlog · PRs opened · success rate · time-to-PR · cost).
- **`/metrics`** — Prometheus gauges/counters, ready to scrape into Grafana.
- **`/api/state`** — full JSON state for programmatic consumers.
- **Structured JSON logs** — every scan, dispatch, PR-link and error is one JSON line.

The success signal is concrete and auditable: a remediation "succeeds" when Devin opens a PR, and
the PR link is posted back on the originating issue automatically.

---

## Quick start (Docker)

```bash
cp .env.example .env
# edit .env: DEVIN_API_KEY, DEVIN_ORG_ID, GITHUB_TOKEN, GITHUB_WEBHOOK_SECRET, TARGET_REPO
docker compose up --build
# console → http://localhost:8000
```

`GITHUB_TOKEN` needs `repo` scope (to create issues / comment / poll). For a local demo you can use
`gh auth token`.

**Prerequisite for real PRs:** Devin's GitHub app must be connected to the account that owns the repo
(done once in the Devin web UI → Settings → GitHub). Without it, sessions run but cannot open PRs.

### Without Docker

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload   # → http://localhost:8000
```

---

## Running the workflow

1. **Scan** — open the **Security** tab and click **⚡ Perform Devin scan**. A Devin session runs the
   scanners and returns ranked findings (a few minutes). Click a scan row to expand its findings.
2. **Triage** — tick the findings you want fixed and click **Create GitHub issues from selected**.
3. **Remediate** — filing an issue fires the webhook, which dispatches a Devin session that opens a PR.
   Watch it on **Review**; the aggregate story is on **Analytics**.

**Triggers** (configurable on **Settings**):
- *On issue creation* — a new labeled issue dispatches remediation.
- *On `/devin` comment* — remediation waits for a `/devin` comment on the issue.
- *Scan schedule* — run a scan automatically hourly/daily/weekly/monthly.

Helper scripts (`scripts/`): `file_issues.py` (seed issues + label), `simulate_webhook.py`
(send a signed webhook, no public URL needed), `dispatch_one.py` (dispatch one remediation directly).

---

## Safety & cost controls

- `DEVIN_MAX_ACU` caps credits (ACUs) per session.
- `DISPATCH_ENABLED=0` runs the whole pipeline in dry-run — events are recorded and visible, but no
  Devin session is created. Useful for wiring up the demo before spending credits.
- Dispatch is **idempotent** per issue — an already-dispatched issue is never double-dispatched.
- **HMAC** signature verification on the webhook endpoint (`X-Hub-Signature-256`).

---

## Next steps (in a real customer engagement)

- **Wider event surface:** wire Snyk / Dependabot / CodeQL — or Devin's native **Security Swarm**
  (`/code-scans/findings` + `/remediate`) — directly as triggers.
- **Policy & routing:** route by severity to approval gates; auto-merge trivially-safe fixes behind CI.
- **Fleet scale:** concurrency limits, per-team ACU budgets, retries with escalation.
- **Close the loop:** feed PR-review comments back so Devin iterates until approved.
