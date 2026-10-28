# CivicShield — Water Utility Resilience Platform

CivicShield is a cybersecurity and cyber-resilience demo for a small water
utility. It maps infrastructure, collects read-only evidence, runs deterministic
security checks, matches known-vulnerable software versions, prioritizes risk by
service impact, guides remediation and tests recovery.

## Layout

- `backend/` — FastAPI app, detection engine, collector agent and tests
- `frontend/` — React + TypeScript dashboard (Vite)
- `docs/` — architecture, detection, recovery and demo notes
- `scripts/` — helper scripts
- `sample-data/` — sample inventory fixtures

## Quickstart

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
# Seed demo data (13 assets, including router/switch network devices):
python -m app.seed

cd ../frontend
npm install
npm run dev
```

Health: `GET /api/health`.

## Detection in one minute

```bash
# 1. Collect read-only evidence from an authorized host
python backend/agent/civicshield_agent.py collect \
  --asset-id 4 --push --run-detection \
  --api http://127.0.0.1:8000 --token operator

# 2. Or run detection against stored evidence
curl -X POST http://127.0.0.1:8000/api/detect \
  -H 'Content-Type: application/json' -d '{}'
```

The assessment engine runs 20 deterministic controls plus a bundled snapshot of
12 high-impact CVEs, and can optionally enrich declared language packages with
live OSV.dev data. Missing evidence is reported as `UNKNOWN`, never invented.

See `docs/DETECTION.md` for the evidence schema, API endpoints, operator
declarations and limitations.

## AI review through MCP

`backend/mcp_server.py` is a stdlib MCP server that lets AI agents connect to
CivicShield over stdio. It exposes asset/finding/risk/recovery tools, an
evidence-grounded `review_security_posture` tool, resources and review prompts.
Use `backend/mcp.example.json` as a client config template and see
`docs/MCP.md`.

The demo UI signs in as **Demo Owner** with the **admin** role by default. Use
the role selector in the sidebar to preview operator/viewer restrictions. This
is a demo role header, not production authentication.

## Demo estate

The seed includes a small utility with:

- Edge router `rtr-edge01`, gateway firewall `gw01`, core switch `sw-core01`
  and plant distribution switch `sw-plant01`
- Identity, application, database, backup and logging servers
- Office, plant and external assets
- Essential services, dependency relationships, backups and recovery scenarios

The Infrastructure Map displays the network devices and the service dependency
graph. Existing databases can be upgraded with
`ensure_network_assets()` and `ensure_demo_evidence()` from `app.seed`.

## Safety

All assets and evidence are synthetic demo data unless an operator explicitly
collects from an authorized host. The collector is read-only and does not scan
networks. Destructive recovery or remediation actions remain simulated and
require human approval.
