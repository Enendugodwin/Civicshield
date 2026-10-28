# CivicShield MCP server

`backend/mcp_server.py` exposes CivicShield to MCP-compatible AI agents over
stdio. It is a thin client of the running CivicShield API and uses only the
Python standard library.

## Start the API first

```bash
cd backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## Configure an MCP client

Use `backend/mcp.example.json` as a template. On Windows:

```json
{
  "mcpServers": {
    "civicshield": {
      "command": "C:/Users/you/Metaproject/civicshield/.venv/Scripts/python.exe",
      "args": ["C:/Users/you/Metaproject/civicshield/backend/mcp_server.py"],
      "env": {
        "CIVICSHIELD_API": "http://127.0.0.1:8000",
        "CIVICSHIELD_ROLE": "admin"
      }
    }
  }
}
```

`CIVICSHIELD_ROLE` controls the demo role header (`admin`, `operator` or
`viewer`). `CIVICSHIELD_TOKEN` is optional; when set it is sent as a bearer
token. The seed/API do not implement real authentication, so the role is a demo
control, not a security boundary.

## Tools

| Tool | What it does |
|---|---|
| `civicshield_overview` | Estate counts, evidence coverage, latest run, service readiness |
| `list_assets` | Assets, optionally filtered by kind/zone/criticality |
| `get_asset` | Evidence metadata, open findings and service impact |
| `list_findings` | Open findings by severity/source/asset, sorted by risk |
| `get_finding` | Finding, risk factors, service impact and optional remediation plan |
| `run_detection` | Configuration checks + CVE matching, optionally OSV enrichment |
| `service_impact` | Downstream assets and essential services for a failure |
| `recovery_readiness` | Per-service readiness criteria and gaps |
| `list_incidents` | Incident queue |
| `get_incident` | Timeline, linked findings and containment steps |
| `list_threat_indicators` | Shared indicators with source, confidence and expiry |
| `review_security_posture` | Evidence-grounded review in markdown plus structured summary |
| `explain_finding` | Plain-language explanation from the AI service/fallback |
| `propose_remediation` | Corrective action, prerequisites, impact and verification |

## Resources

- `civicshield://estate/overview`
- `civicshield://assets`
- `civicshield://findings/open`
- `civicshield://assessments/latest`
- `civicshield://recovery/readiness`
- `civicshield://threat-intelligence`
- `civicshield://audit/recent`
- `civicshield://review/latest`

## Prompts

- `security_review` — focus and audience arguments
- `finding_triage` — finding id
- `incident_review` — incident id

## Example agent flow

1. `review_security_posture` with `focus="all"` and `audience="executive"`.
2. `list_findings` with `source="vulnerability"` to isolate CVE matches.
3. `get_finding` with `include_plan=true` for the highest-risk finding.
4. `service_impact` for the affected asset.
5. `propose_remediation` and present the plan for human approval.
6. If approved, use the web UI to simulate and verify; the MCP server never
   claims a fix is verified without evidence.

## Review contract

The review uses recorded findings, risk scores, assessment outcomes and
recovery criteria. It explicitly states that:

- vulnerability matches are version evidence, not proof of exploitation;
- missing evidence is `UNKNOWN`, not a pass;
- the bundled advisory set is a demo snapshot;
- no production changes were made.

## Test the server

```bash
cd backend
..\.venv\Scripts\python.exe -m pytest tests/test_mcp_server.py -q
```
