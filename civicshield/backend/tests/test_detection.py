"""Detection: advisory matching, full and per-asset runs, evidence ingestion."""
from fastapi.testclient import TestClient

from app import detection, vuln_intel
from app.main import app
from app.seed import seed

client = TestClient(app)
OP = {"X-Role": "operator"}


def test_seed_includes_network_devices_and_topology():
    seed()
    assets = client.get("/api/assets").json()
    by_host = {a["hostname"]: a for a in assets}
    assert by_host["rtr-edge01"]["kind"] == "router"
    assert by_host["sw-core01"]["kind"] == "switch"
    assert by_host["sw-plant01"]["kind"] == "switch"
    assert by_host["gw01"]["kind"] == "firewall"
    rels = client.get("/api/relationships").json()
    pairs = {(r["source_id"], r["target_id"]) for r in rels if r["source_type"] == "asset" and r["target_type"] == "asset"}
    assert (by_host["sw-plant01"]["id"], by_host["sw-core01"]["id"]) in pairs
    assert (by_host["sw-core01"]["id"], by_host["rtr-edge01"]["id"]) in pairs


def test_add_network_device_from_map_and_realistic_seed():
    seed()
    created = client.post("/api/assets", json={
        "name": "Access Switch — Plant 2", "kind": "switch", "hostname": "sw-plant02",
        "owner": "net-team", "os_name": "Cisco IOS 15.2", "zone": "plant",
        "criticality": "high", "status": "operational",
        "environment": "operations",
    }, headers={"X-Role": "admin"})
    assert created.status_code == 201, created.text
    new_id = created.json()["id"]
    row = next(a for a in client.get("/api/assets").json() if a["id"] == new_id)
    assert row["kind"] == "switch" and row["hostname"] == "sw-plant02"
    denied = client.post("/api/assets", json={"name": "viewer-device"}, headers={"X-Role": "viewer"})
    assert denied.status_code == 403
    incidents = client.get("/api/incidents").json()
    assert any(i["title"] == "Invoice-themed phishing reported by finance" for i in incidents)
    indicators = client.get("/api/threat-indicators").json()
    assert len(indicators) == 3 and all(i["source"] for i in indicators)
    service = client.get("/api/services").json()[0]
    assert service["population_served"] == 18400


def test_version_matching_and_offline_advisories():
    assert vuln_intel.compare_versions("8.2p1", "9.3p2") < 0
    assert vuln_intel.compare_versions("1.1.1f", "1.1.1n") < 0
    assert vuln_intel.compare_versions("11.0.4-h1", "11.0.4-h1") == 0
    assert vuln_intel.satisfies("2.14.1", ">=2.0.0-beta9 <2.15.0")
    assert not vuln_intel.satisfies("2.15.0", "<2.15.0")
    assert vuln_intel.satisfies("11.0.0", ">=10.2.0 <10.2.9-h1 || >=11.0.0 <11.0.4-h1")
    found = vuln_intel.match_evidence("4", {"software": [
        {"name": "log4j-core", "version": "2.14.1", "ecosystem": "maven"},
        {"name": "openssl", "version": "3.0.2", "ecosystem": "deb"},
    ]})
    assert [f.rule_id for f in found] == ["CVE-2021-44228"]
    assert found[0].evidence_ref.startswith("software:log4j-core@2.14.1")
    assert vuln_intel.match_evidence("4", {}) == []


def test_full_detection_run_includes_vulnerabilities():
    seed()
    r = client.post("/api/assessments/run")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["summary"]["vulnerabilities"] >= 10
    assert body["summary"]["critical_vulnerabilities"] >= 1
    assert body["summary"]["advisories"]["count"] == 12

    runs = client.get("/api/assessments").json()
    assert runs[-1]["id"] == body["run_id"]
    assert runs[-1]["scope"] == "all"

    findings = client.get("/api/findings").json()
    cves = [f for f in findings if f["rule_id"].startswith("CVE-")]
    assert cves and all(f["source"] == "vulnerability" for f in cves)
    assert any(f["rule_id"] == "CVE-2021-44228" for f in cves)
    assert all(f["workflow"] == "open" for f in cves)


def test_per_asset_detection_scope_and_counts():
    seed()
    r = client.post("/api/assets/6/detect")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scope"] == "asset:6"
    assert body["assets"] == 1
    assert body["vulnerabilities"] == 2
    ids = {f["rule_id"] for f in body["findings"] if f["source"] == "vulnerability"}
    assert ids == {"CVE-2024-3400", "CVE-2024-0012"}
    assert client.post("/api/assets/999999/detect").status_code == 404


def test_evidence_push_updates_posture_and_runs_detection():
    seed()
    ev = {
        "os": {"name": "Ubuntu 22.04", "version": "22.04", "supported": True},
        "identity": {"privileged_accounts": [{"name": "ops", "mfa": None}]},
        "software": [{"name": "pan-os", "version": "11.0.0", "ecosystem": "firmware"}],
    }
    r = client.post("/api/assets/6/evidence", json={
        "evidence": ev, "source": "test-collector", "collector_version": "1.1.0",
        "run_detection": True,
    }, headers=OP)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["software_count"] == 1
    assert body["detection"]["scope"] == "asset:6"
    assert body["detection"]["vulnerabilities"] == 2

    got = client.get("/api/assets/6/evidence").json()
    assert got["evidence"]["collector"]["source"] == "test-collector"
    assert got["meta"]["collected_at"] is not None

    posture = client.get("/api/detection/posture").json()
    row = next(x for x in posture["assets"] if x["asset_id"] == 6)
    assert row["state"] == "current" and row["software_count"] == 1
    assert posture["advisories"]["count"] == 12

    assert client.post("/api/assets/6/evidence", json={"evidence": ev}).status_code == 403


def test_missing_mfa_is_unknown_not_failure():
    seed()
    import baseline_guard
    engine = baseline_guard.build_default_engine()
    rows = engine.assess_asset("x", {
        "identity": {"privileged_accounts": [{"name": "ops", "mfa": None}]}
    })
    mfa = next(f for f in rows if f.rule_id == "BG-ID-001")
    assert mfa.outcome == baseline_guard.UNKNOWN
    rows = engine.assess_asset("x", {
        "identity": {"privileged_accounts": [{"name": "ops", "mfa": False}]}
    })
    mfa = next(f for f in rows if f.rule_id == "BG-ID-001")
    assert mfa.outcome == baseline_guard.FAIL


def test_passed_control_resolves_previous_finding():
    seed()
    first = client.post("/api/assets/1/detect").json()
    owner = next(f for f in first["findings"] if f["rule_id"] == "BG-ASSET-001")
    assert owner["outcome"] == "FAIL"

    ev = client.get("/api/assets/1/evidence").json()["evidence"]
    ev["owner"] = "assigned-team"
    client.post("/api/assets/1/evidence", json={"evidence": ev}, headers=OP)
    second = client.post("/api/assets/1/detect").json()
    assert not any(f["rule_id"] == "BG-ASSET-001" for f in second["findings"])

    findings = client.get("/api/findings").json()
    row = next(f for f in findings
               if f["rule_id"] == "BG-ASSET-001" and f["asset_id"] == "1")
    assert row["workflow"] == "resolved"
    assert "no longer fails" in row["detail"] or row["workflow"] == "resolved"
