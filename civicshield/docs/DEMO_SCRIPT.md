# Demo Script (3 min) — Service Health Dashboard

0:00–0:25 The problem. Small essential-service providers lack staff to track
infrastructure, prioritize weaknesses, and prove recovery readiness.

0:25–0:55 Infrastructure visibility. Open `/` (Service Health dashboard):
sidebar groups, top metrics, tabs. Default tab Affected Assets Intelligence
Map shows Leaflet markers + synchronized affected-assets table. Note the
DEMO ENVIRONMENT banner — all records are synthetic.

0:55–1:25 Investigate impact. Filter by severity, select a red marker
(e.g. app-01), open the asset drawer: findings, dependencies, backup
readiness. Switch lens to Incident Commander to re-rank the priority queue.

1:25–1:55 AI assistance. Open a finding, generate the remediation plan
(Muse Spark or documented deterministic fallback when the API is
unavailable). Approval gate before anything simulated.

1:55–2:25 Investigate and remediate. Approve, run the simulated remediation,
re-run the assessment to verify the check flips.

2:25–2:45 Recovery readiness. Open RecoveryLab, run the app-server-loss
scenario, show restoration order and metrics.

2:45–3:00 Mission close. CivicShield helps small operators protect the
services communities depend on.

Checklist: `cd civicshield/backend; ..\.venv\Scripts\python.exe -m uvicorn
app.main:app --port 8000`; `cd civicshield/frontend; npm run dev -- --port
5173 --strictPort`; POST `/api/demo/reset` then POST
`/api/assessments/run`; screen recorder ready. AI key optional.
