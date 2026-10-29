"""Phase 6d: governance — policies, dual control, audit-chain verification."""
from fastapi.testclient import TestClient

from app import governance
from app.database import SessionLocal
from app.main import app
from app.seed import seed

client = TestClient(app)
OP = {"X-Role": "operator"}
ADMIN = {"X-Role": "admin"}
VIEWER = {"X-Role": "viewer"}


def test_policy_read_update_roles():
    seed()
    g = client.get("/api/governance/policies")
    assert g.status_code == 200, g.text
    assert g.json()["require_distinct_approver"] is False
    assert client.patch("/api/governance/policies",
                        json={"require_distinct_approver": True},
                        headers=VIEWER).status_code == 403
    assert client.patch("/api/governance/policies",
                        json={"require_distinct_approver": True},
                        headers=OP).status_code == 403  # admin only
    ok = client.patch("/api/governance/policies",
                      json={"require_distinct_approver": True}, headers=ADMIN)
    assert ok.status_code == 200 and ok.json()["require_distinct_approver"] is True
    back = client.patch("/api/governance/policies",
                        json={"require_distinct_approver": False}, headers=ADMIN)
    assert back.json()["require_distinct_approver"] is False


def test_audit_chain_verifies_after_mutations():
    seed()
    client.post("/api/detect", json={}, headers=OP)
    client.post("/api/protection/run", json={}, headers=OP)
    db = SessionLocal()
    try:
        assert governance.backfill_audit_chain(db) >= 0
        result = governance.verify_audit_chain(db)
    finally:
        db.close()
    assert result["ok"] is True, result
    assert result["checked"] == result["total"] > 0
    v = client.get("/api/governance/audit-verify")
    assert v.status_code == 200, v.text
    assert v.json()["ok"] is True


def test_multi_row_flush_chains_without_fork():
    """Several audit rows committed in one flush must not fork the chain
    (regression: proposals apply writes remove+applied in one commit)."""
    seed()
    from app.models.models import AuditEvent
    db = SessionLocal()
    try:
        for i in range(3):
            db.add(AuditEvent(actor="fork-probe", action=f"probe_{i}",
                              detail=f"row {i}"))
        db.commit()
        result = governance.verify_audit_chain(db)
        assert result["ok"] is True, result
    finally:
        db.close()


def test_audit_log_is_append_only():
    seed()
    allowed = {(r.path, tuple(sorted(r.methods or []))) for r in app.routes
               if hasattr(r, "path") and r.path == "/api/audit"}
    assert allowed, "audit endpoint must exist"
    for path, methods in allowed:
        assert set(methods) <= {"GET", "HEAD", "OPTIONS"}, methods


def test_actor_identity_prefers_named_user():
    assert governance.actor_of("x", "operator", " jane.doe ") == "jane.doe"
    assert governance.actor_of(None, "operator", None) == "operator"
    assert governance.actor_of(None, "operator", "!!!") == "operator"
