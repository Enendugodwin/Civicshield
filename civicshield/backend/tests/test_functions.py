"""Functions.md gaps: finding workflow, risk/impact/identity, incident fields, import dedup, finding upsert."""
from fastapi.testclient import TestClient

from app.main import app
from app.seed import seed

client = TestClient(app)
OP = {"X-Role": "operator"}


def _assessed():
    seed()
    assert client.post("/api/assessments/run").status_code == 200
    return client.get("/api/findings").json()


def test_demo_account_roles():
    admin = client.get("/api/me", headers={"X-Role": "admin"}).json()
    assert admin["role"] == "admin" and admin["demo"] is True
    assert "reset_demo" in admin["permissions"] and "read" in admin["permissions"]
    viewer = client.get("/api/me", headers={"X-Role": "viewer"}).json()
    assert viewer["role"] == "viewer" and viewer["permissions"] == ["read"]
    operator = client.get("/api/me", headers={"X-Role": "operator"}).json()
    assert "detect" in operator["permissions"] and "reset_demo" not in operator["permissions"]


def test_finding_workflow_and_reopen():
    findings = _assessed()
    fid = findings[0]["id"]
    assert findings[0]["workflow"] == "open"
    r = client.patch(f"/api/findings/{fid}", json={"workflow": "resolved"}, headers=OP)
    assert r.status_code == 422  # reason required
    r = client.patch(f"/api/findings/{fid}", json={"workflow": "investigating", "assignee": "ana"}, headers=OP)
    assert r.json()["workflow"] == "investigating"
    r = client.patch(f"/api/findings/{fid}", json={"workflow": "false_positive", "reason": "lab host"}, headers=OP)
    assert r.json()["workflow"] == "false_positive"
    assert client.patch(f"/api/findings/{fid}", json={"workflow": "bogus"}, headers=OP).status_code == 422
    assert client.patch(f"/api/findings/{fid}", json={"workflow": "open"}).status_code == 403  # viewer
    # Reassessment reopens a dismissed finding that is still present.
    assert client.post("/api/assessments/run").status_code == 200
    again = [f for f in client.get("/api/findings").json() if f["id"] == fid]
    assert again and again[0]["workflow"] == "open"


def test_findings_upsert_stable_ids():
    _assessed()
    first = sorted(f["id"] for f in client.get("/api/findings").json())
    assert client.post("/api/assessments/run").status_code == 200
    second = sorted(f["id"] for f in client.get("/api/findings").json())
    assert first == second


def test_risk_impact_identity():
    findings = _assessed()
    fid = findings[0]["id"]
    risk = client.get(f"/api/risk/{fid}").json()
    assert risk["factors"] and risk["model"] == "impact-1.0"
    assert abs(sum(risk["factors"].values()) - risk["score"]) < 1e-6
    assert client.get("/api/risk/999999").status_code == 404
    impact = client.get("/api/impact", params={"asset_id": "4"}).json()
    assert impact["affected_service_count"] == len(impact["affected_services"])
    assert all("path" in s for s in impact["affected_services"])
    ident = client.get("/api/identity").json()
    assert ident["accounts"] and ident["mfa_coverage"] is not None
    assert all(a["mfa"] in ("enabled", "disabled", "unknown") for a in ident["accounts"])


def test_incident_severity_commander():
    seed()
    r = client.post("/api/incidents", json={"title": "t", "severity": "critical", "commander": "ana"})
    assert r.json()["severity"] == "critical"
    iid = r.json()["id"]
    assert client.post("/api/incidents", json={"title": "t", "severity": "extreme"}).status_code == 422
    p = client.patch(f"/api/incidents/{iid}", json={"commander": "bob", "severity": "high"}, headers=OP)
    assert p.json()["commander"] == "bob"
    detail = client.get(f"/api/incidents/{iid}").json()
    assert detail["severity"] == "high" and any("commander=bob" in e["detail"] for e in detail["events"])


def test_recovery_scenarios_and_readiness():
    seed()
    specs = client.post("/api/recovery/scenarios", json={}).json()
    assert {s["id"] for s in specs} >= {"gateway-loss", "monitoring-loss", "backup-loss", "dual-failure"}
    gw = client.post("/api/recovery/runs", json={"scenario_id": "gateway-loss"}).json()
    assert "6" in gw["affected_assets"]
    assert client.post("/api/recovery/runs", json={"scenario_id": "nope"}).status_code == 404
    ready = client.get("/api/recovery/readiness").json()
    by_name = {s["service"]: s for s in ready["services"]}
    assert by_name["Billing Service"]["ready"] is False  # no recovery procedure documented
    assert "recovery_procedure" in by_name["Billing Service"]["failed_criteria"]
    assert by_name["Safe Water Delivery"]["ready"] is True


def test_incident_summary_and_posture_report():
    seed()
    assert client.post("/api/assessments/run").status_code == 200
    fid = client.get("/api/findings").json()[0]["id"]
    iid = client.post("/api/incidents", json={"title": "t"}).json()["id"]
    client.post(f"/api/incidents/{iid}/findings/{fid}", headers=OP)
    s = client.post(f"/api/incidents/{iid}/summary", json={}).json()
    assert s["incident_id"] == iid and isinstance(s["model_used"], str) and s["model_used"]
    assert "missing_evidence" in s and "never invented" in s["note"]
    assert client.post("/api/incidents/999999/summary", json={}).status_code == 404
    posture = client.get("/api/reports/posture").json()
    assert posture["report"] == "executive-posture" and posture["simulated"] is True
    assert posture["findings_total"] > 0 and len(posture["top_risks"]) <= 5
    assert "generated_at" in posture and "limitations" in posture


def test_csv_formula_guard():
    assert _csv("=cmd") == "'=cmd" and _csv("+1") == "'+1" and _csv("ok") == "ok"
    seed()
    assert client.post("/api/assessments/run").status_code == 200
    rid = client.get("/api/assessments").json()[-1]["id"]
    csv_text = client.get(f"/api/assessments/{rid}/export", params={"format": "csv"}).text
    assert csv_text.splitlines()[0] == "rule_id,asset_id,outcome,severity"


def _csv(v):
    from app.main import _csv_cell
    return _csv_cell(v)


def test_remediation_reopen():
    seed()
    assert client.post("/api/assessments/run").status_code == 200
    fid = client.get("/api/findings").json()[0]["id"]
    pid = client.post("/api/remediation/propose", json={"finding_id": str(fid)}).json()["id"]
    assert client.post(f"/api/remediation/{pid}/reopen", json={"actor": "op"}).status_code == 409
    client.post(f"/api/remediation/{pid}/approve", json={"actor": "op"})
    client.post(f"/api/remediation/{pid}/simulate", json={"actor": "op"})
    client.post(f"/api/remediation/{pid}/verify", json={"checks_passed": True, "actor": "op"})
    r = client.post(f"/api/remediation/{pid}/reopen", json={"actor": "op"})
    assert r.json()["status"] == "approved"
    trail = [e["action"] for e in client.get(f"/api/remediation/{pid}/audit").json()["events"]]
    assert "plan_verified" in trail and "plan_approved" in trail


def test_import_duplicate_detection():
    seed()
    csv_text = "name,kind\nAdmin Workstation,server\nbrand-new-01,server\nbrand-new-01,server\n"
    dry = client.post("/api/assets/import", json={"csv_text": csv_text, "dry_run": True}, headers=OP).json()
    assert dry["valid"] == 1 and len(dry["errors"]) == 2
    before = len(client.get("/api/assets").json())
    commit = client.post("/api/assets/import", json={"csv_text": csv_text, "dry_run": False}, headers=OP).json()
    assert len(commit["created_ids"]) == 1
    assert len(client.get("/api/assets").json()) == before + 1
