"""Phase 3: attack-path service (defensive reachability, labeled assumptions)."""
from fastapi.testclient import TestClient

from app.main import app
from app.seed import seed

client = TestClient(app)
OP = {"X-Role": "operator"}


def setup_function(_):
    seed()


def _analyze(payload):
    r = client.post("/api/analysis/attack-paths", json=payload)
    assert r.status_code == 200, r.text
    return r.json()


def _asset_id(hostname):
    rows = client.get("/api/assets", headers=OP).json()
    rows = rows["items"] if isinstance(rows, dict) else rows
    return next(x["id"] for x in rows if x.get("hostname") == hostname)


def test_entries_targets_and_labeled_seed_path():
    out = _analyze({})
    assert out["analysis_version"] == "1.0.0"
    assert {"billing.vendor.example", "gw01", "rtr-edge01"} <= {e["hostname"] for e in out["entries"]}
    assert any(t["criticality"] in ("critical", "high") for t in out["targets"])
    assert out["path_count"] == 5 and all(
        p["rank"] >= 1 and p["rank_score"] and p["length"] >= 1 for p in out["paths"])
    db01 = _asset_id("db01")
    deep = _analyze({"target_asset_id": db01, "max_paths": 10})
    db_paths = [p for p in deep["paths"] if p["target_name"] == "Database Server"]
    assert db_paths, deep["path_count"]
    top = db_paths[0]
    assert top["length"] >= 1 and top["rank"] >= 1 and top["rank_score"]
    assert set(top["rank_factors"]) == {"hops", "critical_high_findings",
                                        "target_criticality", "boundary_crossings",
                                        "assumed_hops"}
    for h in top["hops"]:
        assert h["rel"] and h["connectivity"] in (
            "confirmed", "configured", "inferred", "hypothetical")
        assert h["note"]  # every hop carries its assumption in plain language
    assert top["blast_radius"]["asset_count"] >= 0
    assert "service_ids" in top["blast_radius"]
    assert all("name" in s for s in top["blast_radius"]["services"])


def test_unknown_entry_404_and_bad_depth_422():
    assert client.post("/api/analysis/attack-paths",
                       json={"entry_asset_id": 99999}).status_code == 404
    assert client.post("/api/analysis/attack-paths",
                       json={"max_depth": 99}).status_code == 422
    assert client.post("/api/analysis/attack-paths",
                       json={"max_paths": 0}).status_code == 422


def test_exclude_edge_comparison():
    rels = client.get("/api/relationships", headers=OP).json()
    router = _asset_id("rtr-edge01")
    incident = [r["id"] for r in rels
                if r["source_type"] == "asset" and r["target_type"] == "asset"
                and (r["source_id"] == router or r["target_id"] == router)]
    assert incident
    base = _analyze({"max_paths": 10})
    base_from_router = [p for p in base["paths"] if p["entry_id"] == router]
    assert base_from_router
    cut = _analyze({"exclude_edge_ids": incident, "max_paths": 10})
    assert cut["excluded"] == {"edge_ids": sorted(incident), "asset_ids": []}
    assert not [p for p in cut["paths"] if p["entry_id"] == router]
    assert cut["path_count"] < base["path_count"]


def test_connects_to_hop_flagged_as_assumed_lateral():
    a = client.post("/api/assets", json={"name": "Rogue AP", "kind": "external",
                                         "zone": "external"}, headers=OP).json()["id"]
    db01 = _asset_id("db01")
    client.post("/api/relationships",
                json={"source_type": "asset", "source_id": a,
                      "target_type": "asset", "target_id": db01,
                      "rel": "connects_to"}, headers=OP)
    out = _analyze({"entry_asset_id": a})
    assert out["paths"]
    hop = out["paths"][0]["hops"][0]
    assert hop["assumed"] is True and "lateral" in hop["note"]


def test_open_findings_surface_on_path_nodes():
    raise_r = client.post("/api/architecture/checks/raise", json={}, headers=OP)
    assert raise_r.status_code == 201
    out = _analyze({})
    with_findings = [p for p in out["paths"] if p["open_findings_count"] > 0]
    assert with_findings
    assert all("rule_id" in f and "severity" in f
               for f in with_findings[0]["open_findings"])
