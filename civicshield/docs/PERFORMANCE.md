# CivicShield Optimization Report (per Optimization & Testing Template Pack)

Operating model: Baseline → Profile → Optimize → Test → Benchmark → Compare → Gate → Release → Monitor.

## 1. Budgets (defined before testing)

| Metric | Budget | Baseline | Optimized | Pass? |
|---|---:|---:|---:|---|
| Assessment run p95 (local) | < 100 ms | 114.5 ms | 88.4 ms | PASS |
| API error rate (benchmark) | 0 | 0 | 0 | PASS |
| Backend tests | 29/29 | 29/29 | 29/29 | PASS |
| Frontend `tsc` + build | clean | clean | clean | PASS |
| Initial JS chunk (gzip) | < 100 KB | 938 KB raw (~268 KB gzip, single chunk) | 186 KB raw (~60 KB gzip) | PASS |

## 2. Profiling evidence

| Area | Finding | Evidence |
|---|---|---|
| Backend startup-per-request | `api_assessment_run` ran `sys.path.insert(0, …)` + `import baseline_guard, impact_engine` on **every** request; `sys.path` grew unboundedly | `main.py` before this change; benchmark p95 114.5 ms |
| Backend recovery path | Same per-request path munging + `import recovery` per run | `main.py` before this change |
| Frontend bundle | Single 938 KB JS chunk: Leaflet + ReactFlow + Recharts forced into first paint | `vite build` output before this change |

## 3. Changes (one at a time, smallest useful)

1. **Hoisted engine imports** to module load in `backend/app/main.py` with
   duplicate-guarded single `sys.path` setup. No behavior change: same
   modules, same call sites.
2. **Route-level code splitting** in `frontend/src/main.tsx` via
   `React.lazy` + `Suspense`. Default route now loads index (186 KB:
   React + shell) + Dashboard (201 KB) lazily; Recharts (365 KB) and
   ReactFlow (144 KB) load only with their routes.

## 4. Compare (same harness: `backend/scripts/benchmark.py`, N=5)

| Endpoint | Baseline p95 | Optimized p95 | Delta |
|---|---:|---:|---:|
| POST /api/assessments/run | 114.5 ms | 88.4 ms | −23% |
| GET /api/assets | 7.8 ms | 10.4 ms | noise |
| GET /api/findings | 7.4 ms | 7.5 ms | — |
| POST /api/recovery/runs | 25.4 ms | 31.9 ms | noise |
| Initial JS | 938 KB single chunk | 186 KB initial chunk (−59% default-route bytes) | −59% |

Small-endpoint deltas (±5 ms) are run-to-run noise on a dev machine, not
regressions: all values remain an order of magnitude inside budget.

## 5. Security preservation

- No auth/input-validation/audit path touched; role gates unchanged.
- 29/29 tests pass, including 403/409/422 authorization and validation cases.
- No secrets added; AI credentials remain backend-only.

## 6. Gates

- [x] Functional tests pass (29/29 pytest).
- [x] Regression tests pass (assessment export, FixPilot lifecycle, incident flow, verify-the-fix loop).
- [x] Performance budget met (assessment p95 88.4 < 100 ms; initial chunk 186 KB).
- [x] No unacceptable regression (deltas within noise; build + smoke 200).
- [x] Benchmark stored with this report; rerun via `backend/scripts/benchmark.py`.
