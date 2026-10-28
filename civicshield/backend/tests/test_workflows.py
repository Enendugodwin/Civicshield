"""CSV import, relationship CRUD, and the verify-the-fix loop."""
from fastapi.testclient import TestClient

from app.main import app
from app.seed import seed

client = TestClient(app)
OP = {"X-Role": "operator"}


def test_csv_import_preview_and_commit():
    seed()
    before = len(client.get("/api/assets").json())
    bad = client.post("/api/assets/import", json={"csv_text": "kind,zone\nserver,central\n"}, headers=OP)
    assert bad.status_code == 422
    csv_text = "name,kind,owner,criticality\nimport-01,server,ops-team,high\n,server,ops-team,high\n"
    preview = client.post("/api/assets/import", json={"csv_text": csv_text, "dry_run": True}, headers=OP)
    assert preview.status_code == 200, preview.text
    body = preview.json()
    assert body["valid"] == 1 and len(body["errors"]) == 1
    assert len(client.get("/api/assets").json()) == before
    commit = client.post("/api/assets/import", json={"csv_text": csv_text, "dry_run": False}, headers=OP)
    assert commit.json()["valid"] == 1 and len(commit.json()["created_ids"]) == 1
    assert len(client.get("/api/assets").json()) == before + 1
    denied = client.post("/api/assets/import", json={"csv_text": csv_text, "dry_run": True})
    assert denied.status_code == 403


def test_relationship_crud():
    seed()
    r = client.post("/api/relationships", json={"source_type": "asset", "source_id": 1,
                                                "target_type": "service", "target_id": 1, "rel": "supplies"}, headers=OP)
    assert r.status_code == 201, r.text
    dup = client.post("/api/relationships", json={"source_type": "asset", "source_id": 1,
                                                  "target_type": "service", "target_id": 1, "rel": "supplies"}, headers=OP)
    assert dup.status_code == 409
    rid = r.json()["id"]
    assert any(x["id"] == rid for x in client.get("/api/relationships").json())
    assert client.delete(f"/api/relationships/{rid}", headers=OP).json()["deleted"] is True
    assert all(x["id"] != rid for x in client.get("/api/relationships").json())


def test_verify_the_fix_loop():
    seed()
    assert client.post("/api/assessments/run").status_code == 200
    findings = client.get("/api/findings").json()
    target = next(f for f in findings if f["rule_id"] == "BG-ASSET-001" and f["asset_id"] == "1")
    assert target["detail"]  # FAIL before fix
    before = client.get(f"/api/assessments/{target['id'] and 1}").json()
    assert any(r["outcome"] == "FAIL" for r in before if r["rule_id"] == "BG-ASSET-001" and r["asset_id"] == "1")

    plan = client.post("/api/remediation/propose", json={"finding_id": str(target["id"]), "rule_id": target["rule_id"],
                                                         "severity": target["severity"], "asset_id": "1"},
                       headers=OP).json()
    pid = plan["id"]
    assert client.post(f"/api/remediation/{pid}/approve", json={"actor": "operator"}, headers=OP).status_code == 200
    assert client.post(f"/api/remediation/{pid}/simulate", json={"actor": "operator"}, headers=OP).status_code == 200
    applied = client.post(f"/api/remediation/{pid}/apply", headers=OP)
    assert applied.status_code == 200, applied.text
    assert applied.json()["simulated"] is True

    assert client.post("/api/assessments/run").status_code == 200
    runs = client.get("/api/assessments").json()
    latest = client.get(f"/api/assessments/{runs[-1]['id']}").json()
    fixed = [r for r in latest if r["rule_id"] == "BG-ASSET-001" and r["asset_id"] == "1"]
    assert fixed and all(r["outcome"] == "PASS" for r in fixed)
