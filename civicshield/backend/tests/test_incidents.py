"""Incident workspace: events, finding links, containment report, status flow."""
from fastapi.testclient import TestClient

from app.main import app
from app.seed import seed

client = TestClient(app)
OP = {"X-Role": "operator"}


def _finding_id():
    seed()
    assert client.post("/api/assessments/run").status_code == 200
    findings = client.get("/api/findings").json()
    assert len(findings) > 0
    return findings[0]["id"]


def test_incident_workspace_flow():
    fid = _finding_id()
    inc = client.post("/api/incidents", json={"title": "Suspected intrusion"}).json()
    iid = inc["id"]

    assert client.get(f"/api/incidents/{iid}").json()["events"] == []

    kinds = ["observed", "evidence", "interpretation", "suggestion", "decision"]
    for k in kinds:
        r = client.post(f"/api/incidents/{iid}/events", json={"kind": k, "detail": f"{k} note"}, headers=OP)
        assert r.status_code == 201, r.text
    bad = client.post(f"/api/incidents/{iid}/events", json={"kind": "guess", "detail": "x"}, headers=OP)
    assert bad.status_code == 422

    r = client.post(f"/api/incidents/{iid}/findings/{fid}", headers=OP)
    assert r.status_code == 201, r.text
    dup = client.post(f"/api/incidents/{iid}/findings/{fid}", headers=OP)
    assert dup.status_code == 409

    detail = client.get(f"/api/incidents/{iid}").json()
    assert len(detail["events"]) == len(kinds)
    assert [f["id"] for f in detail["findings"]] == [fid]

    report = client.get(f"/api/incidents/{iid}/report").json()
    assert len(report["containment"]) > 0
    assert report["decisions"] == ["decision note"]
    assert "synthetic_note" in report

    r = client.patch(f"/api/incidents/{iid}", json={"status": "contained"}, headers=OP)
    assert r.json()["status"] == "contained"
    bad_status = client.patch(f"/api/incidents/{iid}", json={"status": "closed"}, headers=OP)
    assert bad_status.status_code == 422

    viewer_denied = client.post(f"/api/incidents/{iid}/events", json={"kind": "observed", "detail": "x"})
    assert viewer_denied.status_code == 403

    assert client.delete(f"/api/incidents/{iid}/findings/{fid}", headers=OP).status_code == 200
    assert client.get(f"/api/incidents/{iid}").json()["findings"] == []
