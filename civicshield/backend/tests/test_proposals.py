"""Phase 5: architecture proposals + change simulation."""
from fastapi.testclient import TestClient

from app.main import app
from app.seed import seed

client = TestClient(app)
OP = {"X-Role": "operator"}
VIEWER = {"X-Role": "viewer"}


def setup_function(_):
    seed()


def _assets():
    rows = client.get("/api/assets", headers=OP).json()
    return rows["items"] if isinstance(rows, dict) else rows


def _by_hostname(name):
    return next(a["id"] for a in _assets() if a.get("hostname") == name)


def _rels():
    return client.get("/api/relationships", headers=OP).json()


def _propose(title="Test proposal"):
    r = client.post("/api/architecture/proposals", json={"title": title}, headers=OP)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def test_change_validation_and_lifecycle_guards():
    pid = _propose()
    assert client.post("/api/architecture/proposals", json={"title": "x"},
                       headers=VIEWER).status_code == 403
    bad = client.post(f"/api/architecture/proposals/{pid}/changes",
                      json={"op": "teleport", "payload": {}}, headers=OP)
    assert bad.status_code == 422
    assert client.post(f"/api/architecture/proposals/{pid}/changes",
                       json={"op": "remove_edge", "payload": {"relationship_id": 99999}},
                       headers=OP).status_code == 422
    assert client.post(f"/api/architecture/proposals/{pid}/changes",
                       json={"op": "update_asset", "payload": {"asset_id": 1, "zone": "moon"}},
                       headers=OP).status_code == 422
    assert client.post(f"/api/architecture/proposals/{pid}/approve",
                       json={}, headers=OP).status_code == 409
    assert client.post(f"/api/architecture/proposals/{pid}/apply",
                       headers=OP).status_code == 409
    assert client.get("/api/architecture/proposals/99999").status_code == 404


def test_cut_leaf_edge_blocks_path_and_applies():
    leaf = client.post(
        "/api/assets",
        json={"name": "Leaf Box", "kind": "server", "zone": "edge",
              "criticality": "low"},
        headers=OP).json()["id"]
    gw = _by_hostname("gw01")
    edge = client.post("/api/relationships",
                       json={"source_type": "asset", "source_id": leaf,
                             "target_type": "asset", "target_id": gw,
                             "rel": "depends_on"}, headers=OP).json()["id"]
    pid = _propose("Cut leaf uplink")
    client.post(f"/api/architecture/proposals/{pid}/changes",
                json={"op": "remove_edge", "payload": {"relationship_id": edge}},
                headers=OP)
    sim = client.post(f"/api/architecture/proposals/{pid}/simulate",
                      json={"must_block": [{"entry_asset_id": leaf,
                                           "target_asset_id": gw}]}, headers=OP)
    assert sim.status_code == 200, sim.text
    res = sim.json()
    assert res["label"].startswith("simulation")
    assert res["paths_removed"] >= 1
    assert res["verification"] and res["verification"][0]["passed"] is True
    assert res["verification_passed"] is True
    assert client.post(f"/api/architecture/proposals/{pid}/approve",
                       json={"note": "verified cut"}, headers=OP).json()["status"] == "approved"
    applied = client.post(f"/api/architecture/proposals/{pid}/apply", headers=OP)
    assert applied.status_code == 200, applied.text
    assert applied.json()["status"] == "applied"
    assert edge not in {r["id"] for r in _rels()}
    assert client.post(f"/api/architecture/proposals/{pid}/changes",
                       json={"op": "remove_edge", "payload": {"relationship_id": 1}},
                       headers=OP).status_code == 422  # no longer draft


def test_add_monitoring_link_resolves_structural_hit():
    pid = _propose("Watch the database")
    log01, db01 = _by_hostname("log01"), _by_hostname("db01")
    assert client.post(f"/api/architecture/proposals/{pid}/changes",
                       json={"op": "add_edge",
                             "payload": {"source_type": "asset", "source_id": log01,
                                         "target_type": "asset", "target_id": db01,
                                         "rel": "monitors"}}, headers=OP).status_code == 201
    res = client.post(f"/api/architecture/proposals/{pid}/simulate",
                      json={"must_keep": [{"relationship_id": 1}]}, headers=OP).json()
    assert ["AR-MON-01", str(db01)] in res["hits_resolved"]
    assert res["verification"][0]["passed"] is True
    assert client.post(f"/api/architecture/proposals/{pid}/reject",
                       json={"note": "demo only"}, headers=OP).json()["status"] == "rejected"


def test_move_workstation_into_core_adds_segmentation_hit():
    pid = _propose("Bad move")
    adm = _by_hostname("adm-ws01")
    assert client.post(f"/api/architecture/proposals/{pid}/changes",
                       json={"op": "update_asset",
                             "payload": {"asset_id": adm, "zone": "core"}},
                       headers=OP).status_code == 201
    res = client.post(f"/api/architecture/proposals/{pid}/simulate",
                      json={}, headers=OP).json()
    assert ["AR-SEG-01", str(adm)] in res["hits_added"]
    assert res["verification"] == [] and res["verification_passed"] is True
    assert client.get(f"/api/architecture/proposals/{pid}").json()["status"] == "simulated"
