"""FixPilot endpoint tests: approve/simulate/verify + audit logging."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import fixpilot_router  # noqa: E402
import fixpilot_store  # noqa: E402

DB = Path(__file__).resolve().parent / "tmp_fixpilot_test.db"
if DB.exists():
    DB.unlink()
fixpilot_store.DB_PATH = DB

app = FastAPI()
app.include_router(fixpilot_router.router)
client = TestClient(app)

CTX = {"finding_id": "F-1", "rule_id": "R-1", "title": "Missing MFA",
       "severity": "high", "asset_hostname": "dc01",
       "evidence": ["no MFA evidence"], "service_impact": "auth"}


def test_full_lifecycle():
    r = client.post("/api/remediation/propose", json=CTX)
    assert r.status_code == 200, r.text
    pid = r.json()["id"]

    r = client.post(f"/api/remediation/{pid}/approve", json={"actor": "alice"})
    assert r.json()["status"] == "approved"

    r = client.post(f"/api/remediation/{pid}/simulate", json={"actor": "alice"})
    body = r.json()
    assert body["status"] == "simulated" and body["simulated"] is True
    assert body["payload"]["simulation"]["simulated"] is True

    r = client.post(f"/api/remediation/{pid}/verify",
                    json={"checks_passed": False, "actor": "alice"})
    assert r.status_code == 409  # must not claim success

    r = client.post(f"/api/remediation/{pid}/verify",
                    json={"checks_passed": True, "actor": "alice", "evidence": "re-ran rule: PASS"})
    assert r.json()["status"] == "verified"

    r = client.get(f"/api/remediation/{pid}/audit")
    actions = [e["action"] for e in r.json()["events"]]
    for expected in ("plan_saved", "plan_approved", "plan_simulated", "plan_verified"):
        assert expected in actions, actions


def test_simulate_requires_approval_state():
    r = client.post("/api/remediation/propose", json=CTX)
    pid = r.json()["id"]
    client.post(f"/api/remediation/{pid}/reject", json={"actor": "bob"})
    r = client.post(f"/api/remediation/{pid}/simulate", json={"actor": "bob"})
    assert r.status_code == 409
