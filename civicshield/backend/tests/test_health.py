from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_assets_endpoint():
    r = client.get("/assets")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_services_endpoint():
    r = client.get("/services")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_relationships_endpoint():
    r = client.get("/relationships")
    assert r.status_code == 200
    assert isinstance(r.json(), list)
