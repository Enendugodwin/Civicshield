"""MCP protocol and tool behaviour with a stubbed CivicShield API."""
from __future__ import annotations

import importlib.util
from pathlib import Path

MCP = Path(__file__).resolve().parents[1] / "mcp_server.py"


def _load():
    spec = importlib.util.spec_from_file_location("civicshield_mcp", MCP)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


class FakeClient:
    def __init__(self):
        self.calls = []

    def get(self, path, **params):
        self.calls.append(("GET", path, params))
        if path == "/api/assets":
            return [{"id": 11, "name": "Core Switch", "kind": "switch", "zone": "core", "criticality": "critical"},
                    {"id": 4, "name": "Application Server", "kind": "server", "zone": "core", "criticality": "high"}]
        if path == "/api/review/posture":
            return {"assets": 13, "open_findings": 4, "known_vulnerabilities": 2,
                    "critical_vulnerabilities": 1, "services_ready": "2/3",
                    "evidence_coverage": 1.0, "top_findings": [], "recommendations": ["Patch"],
                    "latest_run": {"id": 3}, "markdown": "# Review\n\nEvidence only."}
        if path == "/api/assessments":
            return [{"id": 3, "started_at": 1, "scope": "all"}]
        if path == "/api/assessments/3":
            return [{"outcome": "FAIL"}, {"outcome": "PASS"}]
        if path == "/api/threat-indicators":
            return [{"value": "billing-verify.example", "confidence": "high"}]
        if path == "/api/audit":
            return [{"action": "detection_run"}]
        if path == "/api/recovery/readiness":
            return {"services": []}
        if path.startswith("/api/assets/"):
            return {"name": "Core Switch", "meta": {"source": "seed-fixture"}, "evidence": {}}
        if path == "/api/impact":
            return {"affected_service_count": 1, "affected_services": []}
        if path == "/api/findings":
            return [{"id": 1, "rule_id": "CVE-2021-44228", "asset_id": "4",
                     "severity": "critical", "workflow": "open", "source": "vulnerability", "score": 90}]
        if path == "/api/findings/1":
            return {"id": 1, "rule_id": "CVE-2021-44228", "asset_id": "4"}
        if path == "/api/risk/1":
            return {"score": 90, "priority": "Critical", "factors": {}}
        if path == "/api/incidents":
            return [{"id": 1, "title": "Phishing report"}]
        if path.startswith("/api/incidents/"):
            return {"id": 1, "title": "Phishing report", "events": []}
        return {}

    def post(self, path, body=None):
        self.calls.append(("POST", path, body))
        if path == "/api/detect":
            return {"run_id": 4, "scope": "all", "assets": 13, "results": 281,
                    "outcomes": {"FAIL": 3, "PASS": 10, "UNKNOWN": 20},
                    "vulnerabilities": 2, "critical_vulnerabilities": 1,
                    "warnings": [], "findings": []}
        if path.endswith("/remediation-plan"):
            return {"corrective_action": "Upgrade", "verification_steps": ["Rescan"]}
        return {}


def test_mcp_initialize_and_catalog():
    mcp = _load()
    server = mcp.MCPServer(FakeClient())
    init = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                          "params": {"protocolVersion": "2024-11-05"}})
    assert init["result"]["serverInfo"]["name"] == "civicshield"
    assert "tools" in init["result"]["capabilities"]
    tools = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
    names = {t["name"] for t in tools}
    assert {"review_security_posture", "list_assets", "run_detection", "get_finding"} <= names
    for tool in tools:
        assert tool["inputSchema"]["type"] == "object"


def test_mcp_tools_call_and_resources():
    mcp = _load()
    fake = FakeClient()
    server = mcp.MCPServer(fake)

    assets = server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                            "params": {"name": "list_assets",
                                       "arguments": {"kind": "switch"}}})["result"]
    assert assets["isError"] is False
    assert "Core Switch" in assets["content"][0]["text"]
    assert "Application Server" not in assets["content"][0]["text"]

    review = server.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                            "params": {"name": "review_security_posture",
                                       "arguments": {"focus": "all", "audience": "executive"}}})["result"]
    assert review["isError"] is False
    assert "Evidence only" in review["content"][0]["text"]
    assert review["structuredContent"]["known_vulnerabilities"] == 2

    resources = server.handle({"jsonrpc": "2.0", "id": 5, "method": "resources/list"})["result"]["resources"]
    assert any(r["uri"] == "civicshield://review/latest" for r in resources)
    read = server.handle({"jsonrpc": "2.0", "id": 6, "method": "resources/read",
                          "params": {"uri": "civicshield://assessments/latest"}})["result"]
    assert "latest" not in read["contents"][0]["text"] or "outcomes" in read["contents"][0]["text"]

    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_mcp_unknown_tool_is_marked_error():
    mcp = _load()
    server = mcp.MCPServer(FakeClient())
    result = server.handle({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                            "params": {"name": "delete_everything", "arguments": {}}})["result"]
    assert result["isError"] is True


def test_mcp_prompts():
    mcp = _load()
    server = mcp.MCPServer(FakeClient())
    prompts = server.handle({"jsonrpc": "2.0", "id": 8, "method": "prompts/list"})["result"]["prompts"]
    assert {p["name"] for p in prompts} == {"security_review", "finding_triage", "incident_review"}
    got = server.handle({"jsonrpc": "2.0", "id": 9, "method": "prompts/get",
                         "params": {"name": "finding_triage",
                                    "arguments": {"finding_id": 1}}})["result"]
    assert "get_finding" in got["messages"][0]["content"]["text"]
