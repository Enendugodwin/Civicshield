# CivicShield — final audit (Phases 0–7)

Date: 2026-10-29 (UTC). Backend: FastAPI + SQLAlchemy + SQLite (WAL).
Frontend: React/TypeScript + Vite. AI: Meta Muse Spark (`muse-spark-1.3`)
with deterministic offline fallback. Verified: **139 backend tests pass**
(126 prior + 13 new), `tsc --noEmit` clean, `npm run build` succeeds,
live probes + screenshots for every phase.

## Status labels

- **Implemented and tested** — covered by automated tests *and* live probes.
- **Implemented and verified** — live-probed/screenshot, lighter test cover.
- **Partially implemented** — works in demo scope with documented limits.
- **Not implemented** — consciously out of MVP scope, with next action.

## Feature status

| Area | Status | Evidence |
|---|---|---|
| Architecture import (CSV/JSON/Mermaid, preview→commit) | Implemented and tested | `test_arch_import.py` (6), shots 19–20 |
| AR-* checks + finding lifecycle + reopen/resolve | Implemented and tested | `test_arch_checks.py`, shots 21–22 |
| Attack paths (exclusions, assumptions, blast radius) | Implemented and tested | `test_attack_paths.py` (5), shots 23–24 |
| Agent team (registry, orchestration, budgets) | Implemented and tested | `test_agents.py` (5), shots 25–26 |
| Proposals (stage→simulate→approve→apply) | Implemented and tested | `test_proposals.py` (4), shots 27–28 |
| AI explanations (paths, proposals, estate, CVE web ctx) | Implemented and tested | `test_assistant.py` (13+), shots 29–30, 32–33 |
| Infra map link dropdowns + failover relation | Implemented and verified | shot 31 |
| Continuous protector (scheduled + event runs, notices) | Implemented and tested | `test_protector.py`, shot 34 |
| Detection drafts (draft→active→retired, test preview) | Implemented and tested | `test_detection_rules.py`, shot 35 |
| Governance (dual control, chained audit + verify) | Implemented and tested | `test_governance.py`, `test_hardening.py`, shot 36 |
| Envs B/C (SaaS, hybrid) via reset switch | Implemented and tested | `test_seed_envs.py`, shots 37–38 |
| Versioned migrations + status endpoint | Implemented and tested | `test_migrations.py` |
| Hardening (admin reset, self-links, caps, CORS, no-traceback) | Implemented and tested | `test_hardening.py` |
| RecoveryLab scenarios + readiness | Implemented and tested | prior phases, demo script |
| Reports/exports (CSV/JSON, formula-injection guard) | Implemented and tested | prior phases |
| Real authentication (SSO/OAuth, passwords) | Not implemented | demo `X-Role` header only; see limitations |
| Multi-tenancy / tenant isolation | Not implemented | single-estate demo; next: org-scoped queries |
| Alembic / Postgres deployment | Not implemented | versioned SQLite migrations ship; next: Alembic |
| Production secret store, TLS termination | Not implemented | `.env` + gitignored keys; deploy concern |

## Test results (this audit)

- `pytest backend/tests`: **139 passed** (126 prior + 13 Phase 7: envs,
  migrations, hardening, audit-fork regression).
- `npx tsc --noEmit`: exit 0. `npm run build`: success.
- Live: `/api/health` (`mode=live`), protector scheduled run fired,
  audit-verify `ok:true` over 2200+ events, CVE-2024-21887 NVD+KEV fetch,
  outdated-OS + tool answers with hostname labels and model badge.
- 38 screenshots in `docs/screenshots/` covering every capability above.

## Security assumptions and limitations

1. Auth is a demo role header (`X-Role` + optional `X-User`); production
   must use authenticated identity and server-side sessions.
2. Audit hash chain detects tampering but is not a substitute for
   write-once storage; SQLite file must be protected by the host.
3. Scheduler/worker are in-process threads; multi-instance deployments
   need an external queue + lock.
4. Protector runs detection synchronously; very large estates may need
   chunked or queued runs.
5. AI output is untrusted: validated against schemas, never executes
   actions without chat approval; offline template is labeled fallback.
6. Seeds B/C are fictional; advisories are a bundled demo snapshot
   (OSV.dev refresh is opt-in per scan).

## Prioritized roadmap

1. Real authN/authZ + tenant isolation (blocks any shared hosting).
2. Alembic migrations + Postgres CI target.
3. External job queue for protector + notifications (email/webhook).
4. Write-capable connectors behind explicit approval (backup, SIEM).
5. PDF reports; scheduled report delivery.
6. Frontend tests (currently backend + type + build gates only).
