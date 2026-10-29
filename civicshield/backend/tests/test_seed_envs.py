"""Phase 7: environments B/C seeding, reset policy, determinism."""
from fastapi.testclient import TestClient

from app import detection
from app.main import app
from app.seed import seed

client = TestClient(app)
OP = {"X-Role": "operator"}
ADMIN = {"X-Role": "admin"}
VIEWER = {"X-Role": "viewer"}


def _hostnames():
    return {a["hostname"] for a in client.get("/api/assets").json()}


def test_env_a_unchanged_default():
    out = seed()
    assert out["env"] == "a" and out["assets"] == 13 and out["services"] == 3
    assert out["relationships"] == 23
    assert "rtr-edge01" in _hostnames()


def test_env_b_shape_and_seeded_weakness():
    out = seed("b")
    assert out["env"] == "b" and out["assets"] == 8 and out["services"] == 2
    hosts = _hostnames()
    assert {"web-pub01", "api01", "idp-cloud01", "db-cloud01"} <= hosts
    det = client.post("/api/detect", json={}, headers=OP)
    assert det.status_code == 200, det.text
    rules = {(f["rule_id"], f["asset_id"]) for f in det.json()["findings"]}
    web_id = next(a["id"] for a in client.get("/api/assets").json()
                  if a["hostname"] == "web-pub01")
    assert ("BG-ASSET-001", str(web_id)) in rules  # unowned public app
    assert any(r.startswith("CVE-") for r, _ in rules)  # log4j/openssl versions


def test_env_c_shape_and_seeded_weakness():
    out = seed("c")
    assert out["env"] == "c" and out["assets"] == 7 and out["services"] == 2
    hosts = _hostnames()
    assert {"idp-onprem01", "vpn-gw01", "cloudvm01", "erp01", "siem01"} <= hosts
    det = client.post("/api/detect", json={}, headers=OP)
    assert det.status_code == 200, det.text
    rules = {(f["rule_id"], f["asset_id"]) for f in det.json()["findings"]}
    fin_id = next(a["id"] for a in client.get("/api/assets").json()
                  if a["hostname"] == "fin-ws01")
    assert ("BG-ASSET-001", str(fin_id)) in rules
    assert any(r.startswith("CVE-") for r, _ in rules)
    seed("a")  # leave the shared demo DB on the default estate


def test_reset_requires_admin_and_validates_env():
    assert client.post("/api/demo/reset", json={}, headers=VIEWER).status_code == 403
    assert client.post("/api/demo/reset", json={}).status_code == 403
    bad = client.post("/api/demo/reset", json={"env": "zzz"}, headers=ADMIN)
    assert bad.status_code == 422
    ok = client.post("/api/demo/reset", json={"env": "b"}, headers=ADMIN)
    assert ok.status_code == 200 and ok.json()["env"] == "b"
    assert "web-pub01" in _hostnames()
    back = client.post("/api/demo/reset", json={"env": "a"}, headers=ADMIN)
    assert back.json()["env"] == "a" and back.json()["assets"] == 13
