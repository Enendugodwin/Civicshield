"""Phase 7 hardening: CORS, error hygiene, upload caps, self-links, reset policy."""
from fastapi.testclient import TestClient

from app.main import app
from app.seed import seed

client = TestClient(app)
OP = {"X-Role": "operator"}
ADMIN = {"X-Role": "admin"}
VIEWER = {"X-Role": "viewer"}


def test_cors_allows_only_local_dev_origins():
    origins = set()
    for m in app.user_middleware:
        if m.cls.__name__ == "CORSMiddleware":
            origins = set(m.kwargs.get("allow_origins", []))
    assert origins == {"http://localhost:5173", "http://127.0.0.1:5173"}, origins


def test_error_bodies_never_leak_tracebacks():
    seed()
    assert "Traceback" not in client.get("/api/no-such-route").text
    bad = client.post("/api/relationships",
                      json={"source_type": "asset", "source_id": 1,
                            "target_type": "nope", "target_id": 2,
                            "rel": "depends_on"}, headers=OP)
    assert bad.status_code == 422 and "Traceback" not in bad.text
    missing = client.get("/api/findings/999999")
    assert missing.status_code == 404 and "Traceback" not in missing.text


def test_oversized_uploads_rejected_with_limits():
    seed()
    big_csv = "name,kind,hostname\n" + ("x,server,h\n" * 40000)
    r = client.post("/api/assets/import", json={"csv_text": big_csv},
                    headers=OP)
    assert r.status_code == 413
    big_arch = "x" * (1_000_001)
    r2 = client.post("/api/architecture/import",
                     json={"filename": "big.json", "content": big_arch},
                     headers=OP)
    # Pydantic schema cap (1000000 chars) fires before the parser's 1MB cap;
    # either way oversized uploads are rejected, never parsed.
    assert r2.status_code == 422 and "1000000" in r2.text
    bad_fmt = client.post("/api/architecture/import",
                          json={"filename": "evil.exe", "content": "MZ..."},
                          headers=OP)
    assert bad_fmt.status_code == 422


def test_self_links_rejected_for_every_relation():
    seed()
    assets = client.get("/api/assets").json()
    aid = assets[0]["id"]
    for rel in ("depends_on", "monitors", "failover"):
        r = client.post("/api/relationships",
                        json={"source_type": "asset", "source_id": aid,
                              "target_type": "asset", "target_id": aid,
                              "rel": rel}, headers=OP)
        assert r.status_code == 422, (rel, r.text)


def test_reset_is_admin_only():
    seed("a")
    assert client.post("/api/demo/reset", json={"env": "a"},
                       headers=OP).status_code == 403
    assert client.post("/api/demo/reset", json={"env": "a"},
                       headers=VIEWER).status_code == 403
    ok = client.post("/api/demo/reset", json={"env": "a"}, headers=ADMIN)
    assert ok.status_code == 200 and ok.json()["env"] == "a"


def test_viewer_cannot_mutate_or_approve():
    seed("a")
    assert client.post("/api/assets", json={"name": "x"}, headers=VIEWER).status_code == 403
    assert client.post("/api/protection/run", json={}, headers=VIEWER).status_code == 403
    assert client.patch("/api/governance/policies",
                        json={"require_distinct_approver": True},
                        headers=VIEWER).status_code == 403
    assert client.get("/api/governance/audit-verify").status_code == 200  # read ok
    assert client.get("/api/protection/status").status_code == 200  # read ok
