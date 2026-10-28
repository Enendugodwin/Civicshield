"""The evidence-grounded review endpoint used by the dashboard/MCP server."""
from fastapi.testclient import TestClient

from app.main import app
from app.seed import seed

client = TestClient(app)


def test_review_endpoint_is_evidence_grounded():
    seed()
    assert client.post("/api/assessments/run").status_code == 200
    body = client.get("/api/review/posture", params={"focus": "all", "audience": "technical"}).json()
    assert body["assets"] == 13
    assert body["open_findings"] > 0
    assert body["known_vulnerabilities"] > 0
    assert body["latest_run"]["id"] > 0
    assert body["latest_run"]["outcomes"]["UNKNOWN"] > 0
    assert body["recommendations"]
    assert body["readiness"] and len(body["readiness"]) == 3
    assert "Security review" in body["markdown"] or "security review" in body["markdown"]
    assert "not proof" in body["markdown"]
    assert "No production changes" in body["markdown"]


def test_executive_review_and_focus_filter():
    seed()
    assert client.post("/api/assessments/run").status_code == 200
    exec_review = client.get("/api/review/posture", params={"audience": "executive"}).json()
    assert all(f["source"] in ("configuration", "vulnerability") for f in exec_review["top_findings"])
    vuln = client.get("/api/review/posture", params={"focus": "vulnerability"}).json()
    assert all(f["source"] == "vulnerability" for f in vuln["top_findings"])
    assert vuln["known_vulnerabilities"] > 0
