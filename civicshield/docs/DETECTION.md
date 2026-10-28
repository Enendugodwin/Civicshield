# CivicShield — detection and advisory

CivicShield has two evidence paths that feed one deterministic assessment:

1. **Configuration controls** — `baseline_guard.py` runs 20 read-only checks over
   collected evidence (ownership, OS lifecycle, patching, exposure, firewall,
   privileged accounts, MFA, endpoint protection, logging, backups, recovery).
   Missing information produces `UNKNOWN`, never a fabricated pass or failure.
2. **Known-vulnerability matching** — `backend/app/vuln_intel.py` matches declared
   software versions against a versioned advisory snapshot of real high-impact
   CVEs, and can optionally enrich language packages with live OSV.dev results.

Both paths are triggered by the same detection run and produce one evidence
trail, one risk score per issue and one finding.

## 1. Collect evidence (authorized hosts only)

The collector is read-only. It uses allow-listed local commands and does **not**
scan the network, brute force, open ports or change the host.

```bash
# Print evidence JSON only (safe default)
python backend/agent/civicshield_agent.py collect --asset-id 4 --quick

# Push to CivicShield and immediately run detection for that asset
python backend/agent/civicshield_agent.py collect \
  --asset-id 4 --push --run-detection \
  --api http://127.0.0.1:8000 --token operator \
  --exposure internal
```

`--exposure` is an operator declaration of whether remote administration is
reachable from the internet/WAN. If it is omitted, `remote_admin_exposed` stays
unknown instead of being guessed from a listening socket.

The agent collects:

- OS name/version and a small lifecycle support determination
- last patch/update evidence, with its source
- firewall state where readable
- listening sockets (for evidence, not scanning)
- privileged accounts; MFA and last-login are reported as unknown when not
  readable locally
- endpoint protection and logging service state
- a narrow allow-list of installed packages relevant to the advisory set

## 2. Run detection

```bash
# API (all assets, offline advisory snapshot)
curl -X POST http://127.0.0.1:8000/api/detect -H 'Content-Type: application/json' -d '{}'

# One asset
curl -X POST http://127.0.0.1:8000/api/assets/4/detect -H 'Content-Type: application/json' -d '{}'

# Optional live OSV.dev enrichment
curl -X POST http://127.0.0.1:8000/api/detect -H 'Content-Type: application/json' -d '{"online":true}'
```

| Endpoint | Purpose |
|---|---|
| `POST /api/detect` | Detect all or selected assets (`asset_ids`, `online`) |
| `POST /api/assets/{id}/detect` | Detect one asset, scoped run |
| `POST /api/assets/{id}/evidence` | Collector push (operator role) |
| `GET /api/assets/{id}/evidence` | Stored evidence and collection metadata |
| `GET /api/detection/posture` | Coverage, advisory snapshot, last run |
| `GET /api/assessments/{id}` | Stored results, including CVE matches |
| `GET /api/findings` | Open findings, including vulnerability source |

## 3. Evidence schema

```json
{
  "collector": {
    "source": "civicshield-agent",
    "version": "1.1.0",
    "collected_at": 1793131776.9,
    "hostname": "app01"
  },
  "owner": "it-team",
  "os": {"name": "Ubuntu 20.04", "version": "20.04", "supported": false},
  "patch": {"last_applied": "2026-10-20T00:00:00Z", "max_age_days": 30},
  "network": {"remote_admin_exposed": false},
  "firewall": {"ingress": "restricted"},
  "identity": {"privileged_accounts": [{"name": "ops", "mfa": null}]},
  "endpoint": {"edr_installed": true, "logging_enabled": true},
  "software": [
    {"name": "log4j-core", "version": "2.14.1", "ecosystem": "maven",
     "package": "org.apache.logging.log4j:log4j-core"}
  ]
}
```

## 4. Interpreting results

- `PASS` / `FAIL` require recorded evidence.
- `UNKNOWN` means evidence is missing. It is a prompt to collect, not a failure.
- A CVE finding is a **version match**, not proof of exploitability. Every match
  records its advisory source, confidence and limitation.
- Only `FAIL` controls and vulnerability matches become findings. When a control
  starts passing, its previous open finding is marked resolved with a reason.
- The bundled advisory snapshot is a demo set (12 CVEs), not a complete
  vulnerability database. Enable OSV enrichment for live language-package data.

## 5. Network devices in the demo estate

The seed includes first-class network assets so the Infrastructure Map shows the
path from the ISP edge into the plant:

- `rtr-edge01` — Edge Router (RouterOS)
- `sw-core01` — Core Network Switch (Cisco IOS)
- `sw-plant01` — Plant Distribution Switch (Cisco IOS)
- `gw01` — Gateway Firewall

Existing demo databases can be upgraded without deleting records:

```bash
cd backend
python -c "from app.seed import ensure_network_assets, ensure_demo_evidence; print(ensure_network_assets()); print(ensure_demo_evidence())"
```

The topology links router → firewall → core switch → plant switch, with servers
and workstations attached to the appropriate switch.

## 6. AI review and MCP

`GET /api/review/posture?focus=all&audience=technical` builds an evidence-grounded
review from stored findings, risk scores, assessment outcomes and recovery
criteria. The Reports page renders the same result. `backend/mcp_server.py`
exposes it to MCP clients as `review_security_posture` and also provides tools
for assets, findings, impact, recovery, incidents, threat indicators and
remediation. See `docs/MCP.md`.

## 7. Limits

This is a hackathon MVP, not a scanner or SIEM. It does not perform network
discovery, exploitation, intrusion detection or automatic production changes.
The collector must be run only on hosts you are authorized to inspect.
