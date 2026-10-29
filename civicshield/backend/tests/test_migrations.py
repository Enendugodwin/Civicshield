"""Phase 7: versioned migrations are ordered, current and idempotent."""
from fastapi.testclient import TestClient

from app import migrations
from app.database import SessionLocal
from app.main import app
from app.seed import seed

client = TestClient(app)


def test_migrate_is_current_and_idempotent():
    seed("a")
    db = SessionLocal()
    try:
        first = migrations.migrate(db)
        assert first["current"] is True and first["version"] == migrations.LATEST
        second = migrations.migrate(db)
        assert second["applied"] == [] and second["version"] == migrations.LATEST
        assert migrations.current_version(db) == migrations.LATEST
    finally:
        db.close()


def test_migrations_endpoint_reports_status():
    r = client.get("/api/governance/migrations")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["current"] is True and body["version"] == migrations.LATEST
    assert len(body["migrations"]) == migrations.LATEST
    assert all(m["applied"] for m in body["migrations"])
    assert body["migrations"][0]["id"] == "001_initial"
