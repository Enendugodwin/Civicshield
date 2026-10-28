"""pageprompt.md mapping: threat exposure correlation + AI analysis, recovery recommendations."""
from fastapi.testclient import TestClient

from app.main import app
from app.seed import seed

client = TestClient(app)
OP = {"X-Role": "operator"}


def test_threat_exposure_shape():
    seed()
    r = client.get("/api/threats/exposure")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["source"] == "bundled" and body["snapshot"]
    assert body["advisories"], "bundled advisory catalog must not be empty"
    assets = {str(a["id"]) for a in client.get("/api/assets").json()}
    for adv in body["advisories"]:
        for key in ("id", "title", "severity", "fixed", "recommended_action",
                    "confirmed", "potential", "unevaluated"):
            assert key in adv, key
        assert adv["recommended_action"] and adv["fixed"]
        for m in adv["confirmed"] + adv["potential"]:
            assert m["asset_id"] in assets
            assert m["package"] and m["version"]


def test_threat_analysis_flow_and_guards():
    seed()
    assert client.post("/api/threats/analysis",
                       json={"advisory_id": "CVE-2021-44228"}).status_code == 403
    bad = client.post("/api/threats/analysis", json={"advisory_id": "CVE-NOPE-00000"}, headers=OP)
    assert bad.status_code == 404
    adv_id = client.get("/api/threats/exposure").json()["advisories"][0]["id"]
    r = client.post("/api/threats/analysis", json={"advisory_id": adv_id}, headers=OP)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["plan_id"] and body["model_used"]
    assert body["plan"]["plain_language"] and body["plan"]["verification_steps"]
    audit = client.get(f"/api/remediation/{body['plan_id']}/audit")
    assert audit.status_code == 200


def _check_rec(rec, expect_planned=None):
    assert rec["asset_id"] and rec["step_id"]
    assert rec["status"] in ("planned", "no_findings"), rec
    if rec["status"] == "planned":
        assert rec["plan_id"] and rec["finding_id"] is not None and rec["model_used"]
        assert rec["plain_language"] and rec["corrective_action"]
        assert client.get(f"/api/remediation/{rec['plan_id']}/audit").status_code == 200
    else:
        assert "finding" in rec["note"].lower() or "cap" in rec["note"].lower(), rec
    if expect_planned is not None:
        assert (rec["status"] == "planned") is expect_planned, rec


def test_recovery_recommendations_contract():
    seed()
    assert client.post("/api/assessments/run").status_code == 200
    # privilege-compromise takes down asset 1, which seeded detection flags
    # (BG-ASSET-001) -> exercises the planned path end to end.
    run = client.post("/api/recovery/runs", json={"scenario_id": "privilege-compromise"}).json()
    run_id = run["run_id"]
    assert client.post(f"/api/recovery/runs/{run_id}/recommendations").status_code == 403
    assert client.post("/api/recovery/runs/999999/recommendations", headers=OP).status_code == 404
    body = client.post(f"/api/recovery/runs/{run_id}/recommendations", headers=OP).json()
    assert body["run_id"] == run_id
    by_asset = {r["asset_id"]: r for r in body["recommendations"]}
    assert "1" in by_asset
    _check_rec(by_asset["1"], expect_planned=True)
    # gateway-loss covers the honest no-findings path contract as well.
    gw = client.post("/api/recovery/runs", json={"scenario_id": "gateway-loss"}).json()
    gw_body = client.post(f"/api/recovery/runs/{gw['run_id']}/recommendations", headers=OP).json()
    assert {r["asset_id"] for r in gw_body["recommendations"]} >= set(gw["scenario"]["failed_assets"])
    for rec in gw_body["recommendations"]:
        _check_rec(rec)
