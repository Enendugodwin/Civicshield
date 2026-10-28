# AI Integration (Meta Muse Spark)

Implementation: `backend/app/ai/config.py` + `backend/app/ai/muse_spark_adapter.py` +
`backend/app/ai/ai_service.py`, schemas in `backend/app/ai/schemas.py`
(`schemas2.py` kept for backward compat), fallback in `deterministic_fallback.py`.

Config via env (`civicshield/.env.example`, referenced by `docker-compose.yml`):
`CIVICSHIELD_AI_PROVIDER` (`muse_spark` | `mock` | `disabled`, default `mock`),
`META_API_KEY` (required for live `muse_spark`), `META_API_BASE_URL`
(default `https://api.meta.com/v1`), `META_MODEL_ID` (default `muse-spark`),
`AI_TIMEOUT_SECONDS`, `AI_MAX_RETRIES`.

To connect Meta: put `CIVICSHIELD_AI_PROVIDER=muse_spark` plus `META_API_KEY`
in `civicshield/.env` or `civicshield/backend/.env` (either file is auto-loaded
at request time, stdlib-only, no package needed; real env vars take precedence;
`export KEY=...` and BOM-prefixed files are accepted), restart the backend, then
check `GET /api/remediation/ai/status` (`mode: live` means connected, otherwise
`offline-fallback`). The status also reports `has_key` (key present, never its
value) and `dotenv_file` (which `.env` supplied values, or null) so a
mock/offline result is self-diagnosing. If `provider` is still `mock`, the
`CIVICSHIELD_AI_PROVIDER=muse_spark` line never reached the server process. Endpoints using it: `POST /api/remediation/propose`,
`POST /api/findings/{fid}/explain`, `POST /api/findings/{fid}/remediation-plan`,
`POST /api/incidents/{iid}/summary`. Every response carries `model_used`
(`<model-id>` live, `fallback` offline). Minimal context only
(finding+evidence+criticality+deps); JSON-schema-validated output; deterministic
template fallback when unavailable or invalid; disable via `disabled`.
Privacy: no bulk DB export to model. Tests: `backend/tests/test_ai_mock.py`
(mock provider incl. failure/malformed cases). Verify model id/endpoints against
current Meta docs before use.
