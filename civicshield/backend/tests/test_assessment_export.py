"""Assessment export regression: JSON and CSV reflect the stored run results."""
from fastapi.testclient import TestClient

from app.main import app
from app.seed import seed

client = TestClient(app)


def test_assessment_export_matches_run():
    seed()
    r = client.post("/api/assessments/run")
    assert r.status_code == 200, r.text
    run_id = r.json()["run_id"]
    assert run_id > 0

    detail = client.get(f"/api/assessments/{run_id}")
    assert detail.status_code == 200, detail.text
    assert len(detail.json()) > 0

    js = client.get(f"/api/assessments/{run_id}/export", params={"format": "json"})
    assert js.status_code == 200, js.text
    body = js.json()
    assert body["run_id"] == run_id
    assert len(body["results"]) == len(detail.json())

    csv_resp = client.get(f"/api/assessments/{run_id}/export", params={"format": "csv"})
    assert csv_resp.status_code == 200, csv_resp.text
    lines = csv_resp.text.strip().splitlines()
    assert lines[0] == "rule_id,asset_id,outcome,severity"
    assert len(lines) == len(detail.json()) + 1
