# Demo Script (5 min) — full MVP workflow

0:00–0:25 The problem. Small essential-service providers lack staff to track
infrastructure, prioritize weaknesses, and prove recovery readiness.

0:25–0:55 Infrastructure visibility. Open `/` (Overview): KPIs, assessment
outcomes, service readiness. Open Infrastructure Map: real assets and
dependency edges from the database, not a static diagram. Switch the demo
environment in Settings → Demo data (A water utility, B Cloud SaaS,
C hybrid enterprise) to show the same workflow on a different estate.

0:55–1:30 Investigate risk. Open Findings & Risk: evidence-backed findings
with lifecycle states; each score shows the factors that produced it.
Open Attack Paths: entry-to-target reachability over verified edges with
per-hop assumptions, then Exclude & re-run to compare a defensive cut.

1:30–2:10 AI analysis. Ask the assistant which devices run outdated
operating systems (answers by hostname, model badged), request open-source
and paid proxy/DLP picks, and look up a CVE (live NVD + CISA KEV context
with sources, offline label when unreachable). Explain an attack path and
a change proposal from their Explain buttons.

2:10–2:50 Controlled change. Stage a proposal (add a failover link, remove
an exposed edge), simulate before/after, approve, apply. Every transition
is validated server-side and audit-logged.

2:50–3:30 Continuous protection. Open Threat Intelligence → Detection
drafts: save a DR-* rule, Test it (dry-run counts, no findings written),
Activate it; the next detection run files findings for it. Open Overview:
the protector run recorded the delta and posture notices await explicit
acknowledgement. Open Settings → Governance: verify the audit hash chain.

3:30–4:10 Recovery. Open RecoveryLab, run the app-server-loss scenario,
show restoration order, RTO/RPO accounting and the saved run record.

4:10–5:00 Mission close. Findings → impact → AI-assisted remediation →
simulated recovery → verification → audit trail → export. Core security
works with no AI provider: switch the key off and re-run an assessment.

Checklist: `cd civicshield/backend; ..\.venv\Scripts\python.exe -m uvicorn
app.main:app --port 8000`; `cd civicshield/frontend; npm run dev -- --port
5173 --strictPort`; POST `/api/demo/reset` (`{"env": "a"}`) then POST
`/api/assessments/run`; screen recorder ready. AI key optional.
Set `CIVICSHIELD_AI_PROVIDER=muse_spark` + `META_API_KEY` for live answers.
