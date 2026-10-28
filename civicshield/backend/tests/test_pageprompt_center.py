"""pageprompt.md center: asset threats, sync + health, task assignment, reports, rate limits."""
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import _RATE_BUCKETS, _check_rate, _csv_cell, app
from app.seed import seed

client = TestClient(app)
OP = {"X-Role": "operator"}

CTX = {"finding_id": "F-TASK", "rule_id": "R-TASK", "title": "Task tracking",
       "severity": "medium", "asset_hostname": "h1",
       "evidence": ["stale evidence"], "service_impact": "ops"}


def test_asset_threats_shape_and_404():
    seed()
    assert client.get("/api/assets/999999/threats").status_code == 404
    assets = client.get("/api/assets").json()
    assert assets, "seed must provide assets"
    body = client.get(f"/api/assets/{assets[0]['id']}/threats").json()
    for key in ("asset_id", "asset_name", "software", "inventory_empty",
                "inventory_note", "matches"):
        assert key in body, key
    assert isinstance(body["inventory_empty"], bool)
    if body["inventory_empty"]:
        assert "cannot be evaluated" in body["inventory_note"]
    for m in body["matches"]:
        assert m["id"] and m["recommended_action"] and m["url"]
        for e in m["confirmed"] + m["potential"]:
            assert str(e["asset_id"]) == str(body["asset_id"])


def test_sync_status_and_controlled_sync():
    seed()
    st = client.get("/api/threats/sync-status").json()
    for key in ("never_synced", "bundled_snapshot", "bundled_advisories",
                "osv_cache_entries", "setup_note"):
        assert key in st, key
    assert st["bundled_advisories"] > 0
    assert client.post("/api/threats/sync").status_code == 403
    r = client.post("/api/threats/sync", headers=OP)
    assert r.status_code == 200, r.text
    rec = r.json()
    assert isinstance(rec["ok"], bool) and isinstance(rec["warnings"], list)
    assert rec["assets_scanned"] >= 0 and rec["finished_at"] >= rec["started_at"]
    again = client.get("/api/threats/sync-status").json()
    assert again["never_synced"] is False
    assert again["last_sync"]["assets_scanned"] == rec["assets_scanned"]


def test_task_assignment_lifecycle():
    seed()
    pid = client.post("/api/remediation/propose", json=CTX, headers=OP).json()["id"]
    assert client.post(f"/api/remediation/{pid}/task",
                       json={"owner": "net-team"}).status_code == 403
    assert client.post("/api/remediation/no-such-plan/task",
                       json={"owner": "x"}, headers=OP).status_code == 404
    bad = client.post(f"/api/remediation/{pid}/task",
                      json={"owner": "x", "due_date": "next Friday"}, headers=OP)
    assert bad.status_code == 422
    r = client.post(f"/api/remediation/{pid}/task",
                    json={"owner": "net-team", "due_date": "2026-11-30",
                          "note": "Patch during window", "actor": "alice"}, headers=OP)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "proposed"  # task metadata never moves lifecycle state
    assert body["payload"]["task"]["owner"] == "net-team"
    assert body["payload"]["task"]["due_date"] == "2026-11-30"
    actions = [e["action"] for e in
               client.get(f"/api/remediation/{pid}/audit").json()["events"]]
    assert "task_assigned" in actions


def test_threats_report_json_csv_and_escape():
    seed()
    assert _csv_cell("=cmd|'/c calc'!A0") == "'=cmd|'/c calc'!A0"
    assert _csv_cell("normal text") == "normal text"
    assert _csv_cell(None) == ""
    body = client.get("/api/reports/threats").json()
    assert body["generated_at"] and body["snapshot"] and body["advisories"]
    assert client.get("/api/reports/threats?format=xml").status_code == 422
    r = client.get("/api/reports/threats?format=csv")
    assert r.status_code == 200 and "text/csv" in r.headers["content-type"]
    lines = r.text.splitlines()
    assert lines[0].startswith("advisory_id,title,severity")
    assert len(lines) > 1  # seeded software matches bundled advisories


def test_rate_limiter_blocks_and_resets():
    _RATE_BUCKETS.pop("test:endpoint", None)
    _check_rate("test:endpoint", limit=2, window=60.0)
    _check_rate("test:endpoint", limit=2, window=60.0)
    with pytest.raises(HTTPException) as exc:
        _check_rate("test:endpoint", limit=2, window=60.0)
    assert exc.value.status_code == 429
    assert exc.value.headers and "Retry-After" in exc.value.headers
    _RATE_BUCKETS.pop("test:endpoint", None)
