"""Phase 6c: detection drafts — lifecycle, test preview, activation, retirement."""
from fastapi.testclient import TestClient

from app.main import app
from app.seed import seed

client = TestClient(app)
OP = {"X-Role": "operator"}
ADMIN = {"X-Role": "admin"}
VIEWER = {"X-Role": "viewer"}

RULE = {
    "rule_id": "DR-TEST-001",
    "name": "Collector heartbeat present",
    "description": "Collector evidence must include a heartbeat timestamp.",
    "category": "custom",
    "severity": "medium",
    "predicate": {"kind": "evidence_missing", "path": "collector.heartbeat"},
}


def _create(rule_id="DR-TEST-001", **overrides):
    seed()
    from app.database import SessionLocal
    from app.models.models import DetectionRule
    db = SessionLocal()
    try:
        db.query(DetectionRule).filter(DetectionRule.rule_id == rule_id).delete()
        db.commit()
    finally:
        db.close()
    payload = {**RULE, "rule_id": rule_id, **overrides}
    r = client.post("/api/detection/rules", json=payload, headers=OP)
    assert r.status_code == 201, r.text
    return r.json()


def test_rule_id_shape_and_duplicates():
    seed()
    bad = client.post("/api/detection/rules", json={**RULE, "rule_id": "nope"},
                      headers=OP)
    assert bad.status_code == 422
    _create("DR-TEST-001")
    dup = client.post("/api/detection/rules", json={**RULE, "rule_id": "DR-TEST-001"},
                      headers=OP)
    assert dup.status_code == 409
    bad_pred = client.post("/api/detection/rules",
                           json={**RULE, "rule_id": "DR-TEST-002",
                                 "predicate": {"kind": "nope", "path": "x"}},
                           headers=OP)
    assert bad_pred.status_code == 422
    denied = client.post("/api/detection/rules", json={**RULE, "rule_id": "DR-X"},
                         headers=VIEWER)
    assert denied.status_code == 403


def test_draft_test_preview_writes_no_findings():
    row = _create("DR-TEST-010")
    assert row["status"] == "draft"
    before = {f["id"] for f in client.get("/api/findings").json()}
    t = client.post(f"/api/detection/rules/{row['id']}/test", headers=OP)
    assert t.status_code == 200, t.text
    body = t.json()
    assert body["fail_count"] + body["pass_count"] + body["unknown_count"] == body["assets"]
    assert body["assets"] > 0
    after = {f["id"] for f in client.get("/api/findings").json()}
    assert before == after  # preview is read-only
    assert all("hostname" in f or "label" in f for f in body["fails"])


def test_lifecycle_draft_active_retired_terminal():
    row = _create("DR-TEST-011")
    rid = row["id"]
    # patch allowed on drafts
    p = client.patch(f"/api/detection/rules/{rid}", json={"severity": "high"},
                     headers=OP)
    assert p.status_code == 200 and p.json()["severity"] == "high"
    # activate
    a = client.post(f"/api/detection/rules/{rid}/activate", headers=OP)
    assert a.status_code == 200, a.text
    assert a.json()["status"] == "active"
    assert a.json()["activated_by"] != ""
    # draft-only guards
    assert client.post(f"/api/detection/rules/{rid}/activate", headers=OP).status_code == 409
    assert client.patch(f"/api/detection/rules/{rid}", json={"severity": "low"},
                        headers=OP).status_code == 409
    # retire is terminal
    r = client.post(f"/api/detection/rules/{rid}/retire", headers=OP)
    assert r.status_code == 200 and r.json()["status"] == "retired"
    assert client.post(f"/api/detection/rules/{rid}/retire", headers=OP).status_code == 409
    assert client.post(f"/api/detection/rules/{rid}/activate", headers=OP).status_code == 409


def test_active_rule_emits_findings_then_resolves_on_retire():
    row = _create("DR-TEST-012")
    rid = row["id"]
    client.post(f"/api/detection/rules/{rid}/activate", headers=OP)
    det = client.post("/api/detect", json={}, headers=OP)
    assert det.status_code == 200, det.text
    hits = [f for f in det.json()["findings"] if f["rule_id"] == "DR-TEST-012"]
    assert hits, "active draft must emit findings on detection run"
    assert all(h["outcome"] == "FAIL" for h in hits)
    stored = [f for f in client.get("/api/findings").json()
              if f["rule_id"] == "DR-TEST-012" and (f.get("workflow") or "open") == "open"]
    assert stored, "custom findings persist like built-in ones"
    client.post(f"/api/detection/rules/{rid}/retire", headers=OP)
    det2 = client.post("/api/detect", json={}, headers=OP)
    assert det2.status_code == 200
    still_open = [f for f in client.get("/api/findings").json()
                  if f["rule_id"] == "DR-TEST-012" and (f.get("workflow") or "open") == "open"]
    assert not still_open, "retired rules stop matching; stale findings resolve"


def test_dual_control_blocks_self_activation_when_enabled():
    row = _create("DR-TEST-013")
    rid = row["id"]
    try:
        pol = client.patch("/api/governance/policies",
                           json={"require_distinct_approver": True}, headers=ADMIN)
        assert pol.status_code == 200, pol.text
        # author defaults to role string "operator"; same actor activates -> 409
        blocked = client.post(f"/api/detection/rules/{rid}/activate", headers=OP)
        assert blocked.status_code == 409, blocked.text
        # a different named user may activate
        ok = client.post(f"/api/detection/rules/{rid}/activate", headers={
            "X-Role": "operator", "X-User": "second.reviewer"})
        assert ok.status_code == 200, ok.text
        assert ok.json()["activated_by"] == "second.reviewer"
    finally:
        client.post(f"/api/detection/rules/{rid}/retire", headers=ADMIN)
        client.patch("/api/governance/policies",
                     json={"require_distinct_approver": False}, headers=ADMIN)
