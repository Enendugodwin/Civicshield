# CivicShield — Water Resilience Security Demo

CivicShield is a demo security-operations app for a small community water
utility: asset inventory, baseline assessments against 20 built-in rules,
CVE findings with NVD advisories, AI-assisted remediation plans
(Meta Muse Spark, with an offline template fallback), incident workflow,
and backup/recovery readiness. All records are local; nothing touches
production systems.

![Overview dashboard](civicshield/docs/screenshots/01-overview.png)

## Screens

**Overview** — assets in scope, critical/high findings, vulnerabilities,
evidence gaps, recovery readiness, and latest incidents.

**Findings & Risk** — filterable CVE and baseline findings with severity,
scores, NVD advisories, and one-click Remediate.

![Findings and Risk](civicshield/docs/screenshots/02-findings.png)

**Remediation** — pick a finding, Generate plan drafts a corrective action
with prerequisites, verification steps, rollback, and limitations; then
approve → simulate → verify, with every step in the audit log.

![Remediation plan](civicshield/docs/screenshots/03-remediation-plan.png)

**Threat Intelligence** — bundled advisory catalog correlated with declared
asset software (confirmed / potential / unevaluated), feed-health with
controlled OSV sync, search and severity filters, and per-advisory detail
with vendor links and AI analysis grounded in internal matches.

![Threat dashboard](civicshield/docs/screenshots/04-threats-dashboard.png)

**Threat detail + AI analysis** — expand any advisory for CVSS, fixed
version, affected assets with match evidence, the rules-based recommended
action, and a live-model analysis stored to the Remediation queue.

![Threat detail and AI analysis](civicshield/docs/screenshots/05-threat-detail-analysis.png)

**RecoveryLab** — dependency-aware failure simulations with readiness,
restoration order, and per-run metrics; history survives refresh so
recommendations stay available on the latest run.

![Recovery run](civicshield/docs/screenshots/06-recovery-run.png)

**Recovery AI recommendations** — one FixPilot plan per affected asset with
open findings (capped, honestly reported when findings are missing), each
reviewable on the Remediation page.

![Recovery recommendations](civicshield/docs/screenshots/07-recovery-recommendations.png)

**Remediation tasks** — assign an owner, due date, and tracking note to any
plan; task changes are audit-logged without moving the lifecycle state.

![Remediation task assignment](civicshield/docs/screenshots/08-remediation-task.png)

**Reports** — posture review plus JSON/CSV exports for posture,
assessments, recovery runs, threat exposure, and the audit log.

![Reports and exports](civicshield/docs/screenshots/09-reports-exports.png)

**Infrastructure Map** — dependency graph of the water utility (13 assets,
23 relationships) with asset-type coloring, critical-path highlighting,
and verified-link management.

![Infrastructure map](civicshield/docs/screenshots/10-infra-map.png)

**Inventory import** — paste a CSV/JSON/Mermaid estate export, review the
staged preview (node kinds, zones, links, and plain-language warnings for
anything unknown), then commit or discard. Commits match existing assets by
name/hostname, create the rest, skip identical links, and stamp every new
edge `provenance: imported` with its batch id.

![Import preview](civicshield/docs/screenshots/19-map-import-preview.png)

![Import committed](civicshield/docs/screenshots/20-map-import-committed.png)

**Add links with dropdowns** — the Relationships picker lists assets and
services by name (no more typed numeric ids) with the valid relation
vocabulary, then draws the new link on the graph immediately.

![Add link dropdowns](civicshield/docs/screenshots/31-map-link-dropdowns.png)

**Three demo environments** — the same workflow runs on three fictional
estates, switchable from Settings → Demo data or
`POST /api/demo/reset {"env": "b"}`. Environment B is a Cloud SaaS
(8 assets: public web app, API tier, cloud identity with excessive
permission, public-access storage) and environment C is a hybrid
enterprise (7 assets: on-prem identity with weak shared-admin trust,
VPN gateway, cloud workload, untested backups).

![Cloud SaaS environment](civicshield/docs/screenshots/37-map-env-b-saas.png)

![Hybrid enterprise environment](civicshield/docs/screenshots/38-map-env-c-hybrid.png)

**Service Health** — executive lens with posture strip, affected-assets
intelligence map on live geography, priority queue, region/status/severity
table, and recovery objectives.

![Service health](civicshield/docs/screenshots/11-service-health.png)

**AI Assistant** — conversational chat grounded in live records. Ask about
assets, findings, incidents, threats, and recovery; the live model rephrases
verified context (deterministic template offline). Write actions — create
incidents, draft plans, assign tasks, run assessments or recovery
simulations — always create a pending task first and execute only after
your explicit approval, with role re-checks and audit entries.

![AI assistant answering](civicshield/docs/screenshots/13-assistant-answer.png)

![AI assistant task approval](civicshield/docs/screenshots/15-assistant-task-done.png)

Every answer carries its engine badge — the live model id or `offline
template` — and the message list scrolls inside the chat card while the
composer stays put.

![AI assistant model badge](civicshield/docs/screenshots/16-assistant-model-badge.png)

Follow-up suggestions are derived from the answer's references, chats
export/import as JSON, idle threads expire after 24 hours (history stays
readable), and every finding has an **Ask AI** button that opens the
assistant with the question pre-filled.

![AI assistant follow-ups](civicshield/docs/screenshots/17-assistant-followups.png)

![Findings Ask AI button](civicshield/docs/screenshots/18-findings-ask-ai.png)

The assistant answers estate questions by hostname — outdated operating
systems, open-source and commercial proxy/DLP picks — and cites live
NVD/CISA records for CVE lookups instead of guessing.

![Assistant outdated operating systems](civicshield/docs/screenshots/32-assistant-outdated-os.png)

![Assistant tool recommendations](civicshield/docs/screenshots/33-assistant-tool-recommendations.png)

**Architecture checks** — six deterministic AR-* rules (single points of
failure, external exposure, zone hygiene, monitoring and backup coverage,
dependency cycles) evaluate the normalized graph with one click, upsert
`architecture`-source findings with risk scores, reopen still-failing items,
and resolve fixed structures. Each finding links back to the map.

![Architecture findings](civicshield/docs/screenshots/21-findings-architecture.png)

![Architecture finding detail](civicshield/docs/screenshots/22-finding-architecture-detail.png)

**Attack Paths** — defensive reachability from external/edge entry points to
high-value assets over verified relationships. Every hop cites its edge with
a connectivity label and a plain-language assumption; assumed hops are
flagged, never sold as confirmed exploits. Paths rank transparently with
blast radius, open findings on path nodes, and per-hop **Exclude & re-run**
for before/after comparison of a proposed defensive cut.

![Attack paths](civicshield/docs/screenshots/23-attack-paths.png)

![Attack paths with an exclusion](civicshield/docs/screenshots/24-attack-paths-excluded.png)

**Agent Team** — a 13-member security team as data: registry with
capabilities, read-only tool allowlists, I/O schemas, and budgets.
Deterministic routing turns a request (full assessment, incident, finding,
recovery readiness, …) into a batched plan; each specialist runs bounded
rules-based analysis over live records with attempts and timing recorded.
Failures are isolated, results merged with conflicts and missing evidence
reported, and at most one shared-model call writes the executive summary.

![Agent registry](civicshield/docs/screenshots/25-agents-registry.png)

![Agent investigation](civicshield/docs/screenshots/26-agents-investigation.png)

**Change Proposals** — stage graph edits (remove/add edges, update assets)
without touching live records, then simulate before/after: AR-* hits
resolved or added, attack paths removed or added, and explicit verification
(`must_block` pairs with no path, `must_keep` relationships surviving).
Simulations stay labeled; `draft → simulated → approved → applied` is
enforced, and applying writes live records with an audit trail.

![Proposals](civicshield/docs/screenshots/27-proposals-list.png)

![Proposal simulation](civicshield/docs/screenshots/28-proposal-simulation.png)

**AI explanations for paths and proposals** — every attack path carries an
**Explain with AI** button and every proposal header has one too. The
assistant answers from live records: entries and targets by id and name,
each hop with its relationship and assumption flag, open findings on the
path, blast-radius services, and the proposal's staged edits, simulation
diff, verification outcomes, and next lifecycle step — each answer badged
with the model that wrote it.

![Assistant explains an attack path](civicshield/docs/screenshots/29-assistant-explains-path.png)

![Assistant explains a proposal](civicshield/docs/screenshots/30-assistant-explains-proposal.png)

**Continuous protection** — estate edits (imports, topology changes,
evidence) queue an event reassessment and a scheduler re-runs detection on
an interval. Each run diffs open findings and records hostname-first
posture-change notices (opened / changed / cleared) that operators
acknowledge explicitly — they never auto-clear.

![Continuous protection](civicshield/docs/screenshots/34-overview-protection.png)

**Detection drafts** — operator-authored controls as data, not code:
a predicate over collected evidence with the same PASS / FAIL / UNKNOWN
semantics as built-in rules. Test previews never write findings; activation
honors the dual-control governance policy, and retiring a rule resolves the
findings it can no longer evaluate.

![Detection drafts](civicshield/docs/screenshots/35-threats-detection-drafts.png)

**Governance** — append-only audit log with a SHA-256 hash chain over
every insert (verifiable with one click), an admin dual-control policy for
draft activation, and protector schedule/retention settings beside the
audit trail.

![Governance and protection settings](civicshield/docs/screenshots/36-settings-governance.png)

## Guide to each tab

What every sidebar tab does, in navigation order.

**Overview** — the command deck: KPI strip, continuous-protection notices
with explicit acknowledge, assessment outcomes, service readiness, top
findings, incidents, and recent audit activity.

![Overview tab](civicshield/docs/screenshots/39-tab-overview.png)

**Service Health** — executive lens: posture strip, affected-assets
intelligence map on live geography, priority queue, region/status/severity
table, and recovery objectives.

![Service health tab](civicshield/docs/screenshots/11-service-health.png)

**Infrastructure Map** — the dependency graph from live records: assets,
services, verified links with provenance, staged CSV/JSON/Mermaid imports,
and dropdown link creation including `failover` peers.

![Infrastructure map tab](civicshield/docs/screenshots/31-map-link-dropdowns.png)

**Assets** — inventory with hostname-first labels, evidence freshness,
per-asset and estate-wide detection, CSV import with preview, and
create/edit/retire (admin) actions.

![Assets tab](civicshield/docs/screenshots/40-tab-assets.png)

**Assessments** — run deterministic detection (optional OSV.dev
enrichment), browse run history, filter rule results by outcome/severity/
area/source, and export JSON/CSV reports of any run.

![Assessments tab](civicshield/docs/screenshots/41-tab-assessments.png)

**Findings & Risk** — triage queue with priority filters and lifecycle
states, score breakdowns per finding, NVD advisory links, one-click
**Ask AI** explanations, and **Remediate** handoff.

![Findings tab](civicshield/docs/screenshots/43-tab-findings.png)

**Attack Paths** — entry-to-target reachability over verified edges with
per-hop assumptions, trust-boundary flags, blast radius, Exclude & re-run
for before/after comparison, and AI explanations.

![Attack paths tab](civicshield/docs/screenshots/23-attack-paths.png)

**Proposals** — stage graph edits as drafts, simulate before/after
(AR-* hits, attack paths, verification), then approve and apply with a
full audit trail.

![Proposals tab](civicshield/docs/screenshots/27-proposals-list.png)

**Remediation** — AI-generated fix plans with prerequisites, expected
impact, rollback, and verification steps; approve → simulate → verify →
apply, simulated-only by design.

![Remediation tab](civicshield/docs/screenshots/03-remediation-plan.png)

**AI Assistant** — grounded Q&A over live records (estate, findings,
CVE lookups with NVD/CISA context, tool picks), engine-badged answers,
chat approval for writes, exportable threads.

![AI assistant tab](civicshield/docs/screenshots/13-assistant-answer.png)

**Agent Team** — the 13-member security team as data: deterministic
routing, bounded specialist runs with attempts/timing, merged summaries,
and one shared-model synthesis at most.

![Agent team tab](civicshield/docs/screenshots/25-agents-registry.png)

**RecoveryLab** — failure scenarios, simulated runs with restoration
order and RTO/RPO accounting, readiness criteria per service, and
run comparison.

![RecoveryLab tab](civicshield/docs/screenshots/06-recovery-run.png)

**Incidents** — queue with severity/status, per-incident timelines
(observed/evidence/interpretation/suggestion/decision), finding links,
commander assignment, and AI summaries.

![Incidents tab](civicshield/docs/screenshots/42-tab-incidents.png)

**Threat Intelligence** — indicator submissions, bundled-advisory
exposure vs declared software, feed sync health, and operator-authored
detection drafts with dry-run testing.

![Threat intelligence tab](civicshield/docs/screenshots/35-threats-detection-drafts.png)

**Reports** — posture, assessment, recovery, and threat exports in JSON
and CSV (formula-injection guarded), plus audit download.

![Reports tab](civicshield/docs/screenshots/09-reports-exports.png)

**Settings & Audit** — theme, AI status, access model, protection
schedule, governance policy, one-click audit-chain verification, the
append-only audit log, and demo data/environment reset.

![Settings tab](civicshield/docs/screenshots/36-settings-governance.png)

## Appearance

Three interface themes ship with the GUI — **Vault dark** (default),
**Light**, and **High contrast** — switchable from the sidebar footer or
the Appearance card in Settings. The choice is stored on the device
(`cs_theme`) and applied before first paint, so there is no flash of the
wrong theme on reload. All surfaces, charts, maps, and badges re-skin
through CSS variables; no page code changes per theme.

![Light theme](civicshield/docs/screenshots/theme-light-overview.png)

## Quickstart

Backend (FastAPI, SQLite demo DB):

```powershell
cd civicshield/backend
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Frontend (Vite dev server, proxies `/api` to port 8000):

```powershell
cd civicshield/frontend
npm install
npm run dev
```

Open http://localhost:5173/remediation in a browser.

## AI setup (Meta Muse Spark)

Copy `civicshield/backend/.env.example` to `civicshield/backend/.env` and set:

- `CIVICSHIELD_AI_PROVIDER=muse_spark`
- `META_API_KEY=` (your key — never commit this file)
- `META_API_BASE_URL=` and `META_MODEL_ID=` (from your Meta dashboard)

Check `GET /api/remediation/ai/status`: `"mode": "live"` means connected,
otherwise plans use the offline template. Details in
[civicshield/docs/AI_INTEGRATION.md](civicshield/docs/AI_INTEGRATION.md).

## Tests

```powershell
cd civicshield/backend
.\.venv\Scripts\python -m pytest tests/test_ai_mock.py tests/test_fixpilot.py -q
```

More docs: [civicshield/docs/](civicshield/docs/) (API, detection rules,
threat model, MCP server, demo script).
