"""Phase 2: AR-* architecture checks + Findings wiring."""
from fastapi.testclient import TestClient

from app.main import app
from app.seed import seed

client = TestClient(app)
OP = {"X-Role": "operator"}
ADMIN = {"X-Role": "admin"}
VIEWER = {"X-Role": "viewer"}


def setup_function(_):
    seed()


def _mk_asset(name, kind="server", zone="central", criticality="low", owner="test"):
    r = client.post("/api/assets", json={"name": name, "kind": kind, "zone": zone,
                                         "criticality": criticality, "owner": owner},
                    headers=OP)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _mk_rel(src, tgt, rel="depends_on"):
    r = client.post("/api/relationships",
                    json={"source_type": "asset", "source_id": src,
                          "target_type": "asset", "target_id": tgt, "rel": rel},
                    headers=OP)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def test_catalog_lists_six_deterministic_rules():
    p = client.get("/api/architecture/checks").json()
    assert p["rule_version"] == "1.0.0"
    ids = [r["rule_id"] for r in p["rules"]]
    assert ids == ["AR-SPF-01", "AR-EXP-01", "AR-SEG-01",
                   "AR-MON-01", "AR-BKP-01", "AR-CYC-01"]
    for r in p["rules"]:
        assert r["name"] and r["description"] and r["remediation"]


def test_seed_preview_flags_core_switch_and_unmonitored_stores():
    p = client.get("/api/architecture/checks").json()
    by_rule: dict[str, list] = {}
    for h in p["hits"]:
        by_rule.setdefault(h["rule_id"], []).append(h)
    spf = [h for h in by_rule.get("AR-SPF-01", []) if h["asset_name"] == "Core Network Switch"]
    assert spf, p["hits"]
    assert spf[0]["confidence"] == "high" and spf[0]["status"] == "confirmed"
    assert "relationship:" in spf[0]["evidence_ref"] and spf[0]["remediation"]
    mon_names = {h["asset_name"] for h in by_rule.get("AR-MON-01", [])}
    assert {"Database Server", "Identity Server"} <= mon_names
    assert all(h["status"] == "inferred" for h in by_rule["AR-MON-01"])
    # No cycles or workstations-in-core in the seed estate.
    assert "AR-CYC-01" not in by_rule and "AR-SEG-01" not in by_rule


def test_raise_creates_scored_architecture_findings_idempotently():
    first = client.post("/api/architecture/checks/raise", json={}, headers=OP)
    assert first.status_code == 201, first.text
    assert first.json()["created"] >= 3
    items = client.get("/api/findings").json()
    arch = [f for f in (items["items"] if isinstance(items, dict) else items)
            if str(f["rule_id"]).startswith("AR-")]
    assert arch
    assert all(f["source"] == "architecture" for f in arch)
    assert all(f["score"] > 0 and f["priority"] for f in arch)
    again = client.post("/api/architecture/checks/raise", json={}, headers=OP)
    assert again.json()["created"] == 0 and again.json()["reopened"] == 0
    n = len(client.get("/api/findings").json())
    assert len(client.get("/api/findings").json()) == n  # no duplicates
    assert client.post("/api/architecture/checks/raise", json={},
                       headers=VIEWER).status_code == 403


def test_cycle_and_exposure_detected_and_raised_selectively():
    a = _mk_asset("Cycle A")
    b = _mk_asset("Cycle B")
    _mk_rel(a, b)
    _mk_rel(b, a)
    ext = _mk_asset("Evil ISP", kind="external", zone="external", criticality="low")
    db01 = next(x["id"] for x in client.get("/api/assets", headers=OP).json()
                if x.get("hostname") == "db01")
    _mk_rel(ext, db01, rel="connects_to")
    p = client.get("/api/architecture/checks").json()
    cyc = [h for h in p["hits"] if h["rule_id"] == "AR-CYC-01"]
    assert cyc and {cyc[0]["asset_id"]} <= {str(a), str(b)}
    exp = [h for h in p["hits"] if h["rule_id"] == "AR-EXP-01"
           and h["asset_name"] == "Database Server"]
    assert exp and exp[0]["severity"] in ("high", "critical")
    res = client.post("/api/architecture/checks/raise",
                      json={"rule_ids": ["AR-CYC-01"]}, headers=OP).json()
    assert res["created"] == 1 and res["hit_count"] == 1


def test_failover_peer_clears_spf_and_self_link_rejected():
    sw = next(x["id"] for x in client.get("/api/assets", headers=OP).json()
              if x.get("hostname") == "sw-core01")
    assert any(h["rule_id"] == "AR-SPF-01" and h["asset_name"] == "Core Network Switch"
               for h in client.get("/api/architecture/checks").json()["hits"])
    peer = _mk_asset("Core Switch Standby", kind="switch", zone="core", criticality="high")
    _mk_rel(sw, peer, rel="failover")
    assert not [h for h in client.get("/api/architecture/checks").json()["hits"]
                 if h["rule_id"] == "AR-SPF-01" and h["asset_name"] == "Core Network Switch"]
    assert client.post("/api/relationships",
                       json={"source_type": "asset", "source_id": sw,
                             "target_type": "asset", "target_id": sw,
                             "rel": "failover"}, headers=OP).status_code == 422
    pid = client.post("/api/architecture/proposals", json={"title": "self failover"},
                      headers=OP).json()["id"]
    assert client.post(f"/api/architecture/proposals/{pid}/changes",
                       json={"op": "add_edge",
                             "payload": {"source_type": "asset", "source_id": sw,
                                         "target_type": "asset", "target_id": sw,
                                         "rel": "failover"}}, headers=OP).status_code == 422


def test_resolved_stale_when_structure_fixed():
    ws = _mk_asset("Core WS", kind="workstation", zone="core", criticality="medium")
    assert client.post("/api/architecture/checks/raise",
                       json={"rule_ids": ["AR-SEG-01"]}, headers=OP).json()["created"] == 1
    assert client.delete(f"/api/assets/{ws}", headers=ADMIN).status_code == 200
    res = client.post("/api/architecture/checks/raise",
                      json={"rule_ids": ["AR-SEG-01"]}, headers=OP).json()
    assert res["created"] == 0 and res["resolved_stale"] == 1
    items = client.get("/api/findings").json()
    seg = [f for f in (items["items"] if isinstance(items, dict) else items)
           if f["rule_id"] == "AR-SEG-01"]
    assert seg and all(f["workflow"] == "resolved" for f in seg)
