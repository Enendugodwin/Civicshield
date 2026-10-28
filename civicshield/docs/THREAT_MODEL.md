# Threat Model

Assets: asset DB, credentials, backups, audit log, API keys. Trust boundaries: browser↔API (JWT, RBAC: admin/operator/viewer), API↔Muse Spark (server-side key only, minimal context), CSV import (size/row limits, schema validation). Threats: prompt injection via imports (treated untrusted, never executed), unverified intel auto-block (prohibited), AI hallucinated commands (schema-validated, simulated only), CORS/CSRF, secret leakage (env-only keys). Residual: single-tenant SQLite demo; production needs Postgres RLS, backups, monitoring.
