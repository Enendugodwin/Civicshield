"""Phase 6b: continuous protector — manual runs, diffs, config, ack, events."""
from fastapi.testclient import TestClient

from app import protector
from app.main import app
from app.seed import seed

client = TestClient(app)
OP = {"X-Role": "operator"}
ADMIN = {"X-Role": "admin"}
VIEWER = {"X-Role": "viewer"}


def test_status_shape_and_defaults():
    seed()
    s = client.get("/api/protection/status")
    assert s.status_code == 200, s.text
    body = s.json()
    assert set(body) >= {"enabled", "interval_seconds", "keep_runs",
                         "pending_events", "unacked_notifications", "last_run"}


def _make_rule(rule_id, active=False):
    from app.database import SessionLocal
    from app.models.models import DetectionRule
    db = SessionLocal()
    try:
        db.query(DetectionRule).filter(DetectionRule.rule_id == rule_id).delete()
        db.commit()
    finally:
        db.close()
    r = client.post("/api/detection/rules", json={
        "rule_id": rule_id, "name": f"protector probe {rule_id}",
        "description": "Fails where collector heartbeat evidence is absent.",
        "category": "custom", "severity": "medium",
        "predicate": {"kind": "evidence_missing", "path": "collector.heartbeat"},
    }, headers=OP)
    assert r.status_code == 201, r.text
    row = r.json()
    if active:
        a = client.post(f"/api/detection/rules/{row['id']}/activate", headers=OP)
        assert a.status_code == 200, a.text
    return row


def test_manual_run_records_deltas_and_notifications():
    seed()
    rule = _make_rule("DR-PROT-001")
    try:
        # baseline: draft emits nothing, diffs settle
        r0 = client.post("/api/protection/run", json={}, headers=OP)
        assert r0.status_code == 200, r0.text
        first = r0.json()
        assert first["status"] == "complete" and first["trigger"] == "manual"
        assert client.post("/api/protection/run", json={}, headers=VIEWER).status_code == 403
        # activate the draft: the next run must open its findings as a delta
        client.post(f"/api/detection/rules/{rule['id']}/activate", headers=OP)
        r2 = client.post("/api/protection/run", json={}, headers=OP).json()
        assert r2["opened"] >= 1, r2
        notes = client.get("/api/protection/notifications").json()["notifications"]
        mine = [n for n in notes if n["run_id"] == r2["run_id"]]
        kinds = {n["kind"] for n in mine}
        assert "finding_opened" in kinds, mine
        opened = next(n for n in mine if n["kind"] == "finding_opened")
        assert "asset #" not in opened["title"].lower()  # hostname-first labels
        # ack flow is operator-explicit
        ack = client.post(f"/api/protection/notifications/{opened['id']}/ack", headers=OP)
        assert ack.status_code == 200 and ack.json()["ack"] is True
        assert client.post(f"/api/protection/notifications/{opened['id']}/ack",
                           headers=VIEWER).status_code == 403
        assert client.post("/api/protection/notifications/999999/ack",
                           headers=OP).status_code == 404
    finally:
        client.post(f"/api/detection/rules/{rule['id']}/retire", headers=OP)


def test_event_hook_queues_and_drains_into_run():
    seed()
    import time as _time
    assets = client.get("/api/assets").json()
    a, b = assets[0]["id"], assets[1]["id"]
    before_top = client.get("/api/protection/runs").json()["runs"][0]["id"]
    rel = client.post("/api/relationships",
                      json={"source_type": "asset", "source_id": a,
                            "target_type": "asset", "target_id": b, "rel": "monitors"},
                      headers=OP)
    assert rel.status_code == 201, rel.text
    # request path only enqueues; drain until the event run lands (bounded)
    run_id = None
    for _ in range(100):
        protector.process_queue_sync()
        top = client.get("/api/protection/runs").json()["runs"][0]
        if top["id"] != before_top and top["trigger"].startswith("event"):
            run_id = top["id"]
            break
        _time.sleep(0.1)
    assert run_id is not None, "event run never recorded"
    client.delete(f"/api/relationships/{rel.json()['id']}", headers=ADMIN)


def test_config_validation_and_roles():
    seed()
    bad = client.patch("/api/protection/config", json={"interval_seconds": 5},
                       headers=OP)
    assert bad.status_code == 422
    denied = client.patch("/api/protection/config", json={"enabled": False},
                          headers=VIEWER)
    assert denied.status_code == 403
    ok = client.patch("/api/protection/config",
                      json={"enabled": True, "interval_seconds": 3600,
                            "keep_runs": 50, "notify_retention_days": 30},
                      headers=OP)
    assert ok.status_code == 200, ok.text
    assert ok.json()["enabled"] is True
    assert ok.json()["interval_seconds"] == 3600
