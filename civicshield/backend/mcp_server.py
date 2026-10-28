#!/usr/bin/env python3
"""CivicShield MCP server (stdio, stdlib only).

Exposes the CivicShield estate to MCP-compatible AI agents. It is a thin,
read-mostly client of the CivicShield API: agents can inspect assets,
findings, risk, service impact, assessments, recovery readiness and incidents,
run detection, propose/verify remediation, and generate an evidence-grounded
security review.

Start the CivicShield API first, then configure an MCP client:

    {
      "mcpServers": {
        "civicshield": {
          "command": "C:/path/to/civicshield/.venv/Scripts/python.exe",
          "args": ["C:/path/to/civicshield/backend/mcp_server.py"],
          "env": {
            "CIVICSHIELD_API": "http://127.0.0.1:8000",
            "CIVICSHIELD_ROLE": "admin"
          }
        }
      }
    }

Only JSON-RPC messages go to stdout; logs go to stderr.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "civicshield"
SERVER_VERSION = "1.2.0"


def log(message: str) -> None:
    print(f"[civicshield-mcp] {message}", file=sys.stderr, flush=True)


class CivicShieldAPIError(RuntimeError):
    pass


class CivicShieldAPI:
    """Small JSON-over-HTTP client with the demo role header."""

    def __init__(self, base_url: str | None = None, role: str | None = None,
                 token: str | None = None, timeout: float = 20.0):
        self.base_url = (base_url or os.getenv("CIVICSHIELD_API", "http://127.0.0.1:8000")).rstrip("/")
        self.role = role or os.getenv("CIVICSHIELD_ROLE", "admin")
        self.token = token or os.getenv("CIVICSHIELD_TOKEN", "")
        self.timeout = float(os.getenv("CIVICSHIELD_TIMEOUT", timeout))

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   "X-Role": self.role}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def request(self, method: str, path: str, body: Any = None,
                params: Optional[Dict[str, Any]] = None) -> Any:
        url = f"{self.base_url}{path}"
        if params:
            clean = {k: v for k, v in params.items() if v not in (None, "", [])}
            if clean:
                url += "?" + urllib.parse.urlencode(clean, doseq=True)
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method, headers=self._headers())
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:600]
            raise CivicShieldAPIError(f"{method} {path} -> HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise CivicShieldAPIError(
                f"CivicShield API unavailable at {self.base_url}: {exc}"
            ) from exc
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"text": raw}

    def get(self, path: str, **params: Any) -> Any:
        return self.request("GET", path, params=params)

    def post(self, path: str, body: Any = None) -> Any:
        return self.request("POST", path, body=body if body is not None else {})


def _text_result(text: str, structured: Any = None, is_error: bool = False) -> Dict[str, Any]:
    result: Dict[str, Any] = {"content": [{"type": "text", "text": text}],
                              "isError": is_error}
    if structured is not None:
        result["structuredContent"] = structured
    return result


def _json_result(value: Any) -> Dict[str, Any]:
    return _text_result(json.dumps(value, indent=2, ensure_ascii=False), value)


class MCPServer:
    TOOLS = [
        {
            "name": "civicshield_overview",
            "description": "Summarize the estate: assets, open findings, known vulnerabilities, evidence coverage, latest detection run and service readiness.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "list_assets",
            "description": "List active assets, optionally filtered by kind (router, switch, firewall, server, workstation...), zone or criticality.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "kind": {"type": "string"},
                    "zone": {"type": "string"},
                    "criticality": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "get_asset",
            "description": "Get one asset with its stored evidence metadata, open findings and downstream service impact.",
            "inputSchema": {
                "type": "object",
                "properties": {"asset_id": {"type": "integer", "minimum": 1}},
                "required": ["asset_id"], "additionalProperties": False,
            },
        },
        {
            "name": "list_findings",
            "description": "List findings, defaulting to open findings. Filter by severity, source (configuration or vulnerability), asset, or workflow.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow": {"type": "string", "default": "open"},
                    "severity": {"type": "string"},
                    "source": {"type": "string", "enum": ["configuration", "vulnerability"]},
                    "asset_id": {"type": "integer"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 25},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "get_finding",
            "description": "Get a finding with its risk factors, service impact and optional remediation plan.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "integer", "minimum": 1},
                    "include_plan": {"type": "boolean", "default": False},
                },
                "required": ["finding_id"], "additionalProperties": False,
            },
        },
        {
            "name": "run_detection",
            "description": "Run configuration checks and known-vulnerability matching against stored evidence. Optionally restrict to assets and enable OSV.dev enrichment.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "asset_ids": {"type": "array", "items": {"type": "integer"}},
                    "online": {"type": "boolean", "default": False},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "service_impact",
            "description": "Show downstream assets and essential services affected by a simulated asset failure.",
            "inputSchema": {
                "type": "object",
                "properties": {"asset_id": {"type": "integer", "minimum": 1}},
                "required": ["asset_id"], "additionalProperties": False,
            },
        },
        {
            "name": "recovery_readiness",
            "description": "Return recovery readiness criteria and failed criteria for each essential service.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "list_incidents",
            "description": "List incidents with status, severity and commander.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "get_incident",
            "description": "Get an incident timeline, linked findings and containment steps.",
            "inputSchema": {
                "type": "object",
                "properties": {"incident_id": {"type": "integer", "minimum": 1}},
                "required": ["incident_id"], "additionalProperties": False,
            },
        },
        {
            "name": "list_threat_indicators",
            "description": "List shared threat indicators with source, confidence and expiry.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "review_security_posture",
            "description": "Generate an evidence-grounded security review for the estate or a focus area. Returns markdown plus structured summary.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "focus": {"type": "string", "default": "all",
                              "description": "all, vulnerability, identity, backup, network, or an asset kind"},
                    "audience": {"type": "string", "enum": ["technical", "executive"], "default": "technical"},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "explain_finding",
            "description": "Ask CivicShield's AI service to explain a finding in plain language using its recorded evidence.",
            "inputSchema": {
                "type": "object",
                "properties": {"finding_id": {"type": "integer", "minimum": 1}},
                "required": ["finding_id"], "additionalProperties": False,
            },
        },
        {
            "name": "propose_remediation",
            "description": "Create a remediation plan for a finding, including corrective action, prerequisites, operational impact and verification steps.",
            "inputSchema": {
                "type": "object",
                "properties": {"finding_id": {"type": "integer", "minimum": 1}},
                "required": ["finding_id"], "additionalProperties": False,
            },
        },
    ]

    RESOURCES = [
        {"uri": "civicshield://estate/overview", "name": "Estate overview",
         "description": "Asset, finding, evidence and recovery summary.", "mimeType": "application/json"},
        {"uri": "civicshield://assets", "name": "Asset inventory",
         "description": "Active assets including network devices.", "mimeType": "application/json"},
        {"uri": "civicshield://findings/open", "name": "Open findings",
         "description": "Open configuration and vulnerability findings sorted by risk.", "mimeType": "application/json"},
        {"uri": "civicshield://assessments/latest", "name": "Latest assessment summary",
         "description": "Latest detection run with PASS/FAIL/UNKNOWN counts.", "mimeType": "application/json"},
        {"uri": "civicshield://recovery/readiness", "name": "Recovery readiness",
         "description": "Readiness criteria and gaps per essential service.", "mimeType": "application/json"},
        {"uri": "civicshield://threat-intelligence", "name": "Threat indicators",
         "description": "Community threat indicators with provenance.", "mimeType": "application/json"},
        {"uri": "civicshield://audit/recent", "name": "Recent audit events",
         "description": "Recent recorded actions, with actor and detail.", "mimeType": "application/json"},
        {"uri": "civicshield://review/latest", "name": "Security review",
         "description": "Deterministic security review in markdown.", "mimeType": "text/markdown"},
    ]

    PROMPTS = [
        {"name": "security_review", "description": "Review the CivicShield estate for a technical or executive audience.",
         "arguments": [{"name": "focus", "required": False}, {"name": "audience", "required": False}]},
        {"name": "finding_triage", "description": "Triage one finding using evidence, risk and service impact.",
         "arguments": [{"name": "finding_id", "required": True}]},
        {"name": "incident_review", "description": "Review an incident timeline and recommend containment/next steps.",
         "arguments": [{"name": "incident_id", "required": True}]},
    ]

    def __init__(self, client: CivicShieldAPI | None = None):
        self.client = client or CivicShieldAPI()

    # ------------------------------------------------------------ protocol ---
    def handle(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return self._error(None, -32600, "invalid JSON-RPC request")
        method = message.get("method")
        request_id = message.get("id")
        is_notification = "id" not in message
        try:
            if method == "initialize":
                params = message.get("params") or {}
                result = {
                    "protocolVersion": params.get("protocolVersion", PROTOCOL_VERSION),
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                        "prompts": {"listChanged": False},
                    },
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                    "instructions": (
                        "CivicShield exposes a synthetic municipal water-utility estate. "
                        "Use review_security_posture for an evidence-grounded review; never "
                        "claim a vulnerability is confirmed without checking its evidence."
                    ),
                }
            elif method in ("notifications/initialized", "notifications/cancelled"):
                return None
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": self.TOOLS}
            elif method == "resources/list":
                result = {"resources": self.RESOURCES}
            elif method == "resources/read":
                uri = (message.get("params") or {}).get("uri", "")
                result = {"contents": self._read_resource(uri)}
            elif method == "prompts/list":
                result = {"prompts": self.PROMPTS}
            elif method == "prompts/get":
                params = message.get("params") or {}
                result = self._get_prompt(str(params.get("name", "")), params.get("arguments") or {})
            elif method == "tools/call":
                params = message.get("params") or {}
                result = self._call_tool(str(params.get("name", "")), params.get("arguments") or {})
            elif method == "logging/setLevel":
                result = {}
            else:
                if is_notification:
                    return None
                return self._error(request_id, -32601, f"method not found: {method}")
        except CivicShieldAPIError as exc:
            if method == "tools/call":
                result = _text_result(str(exc), {"error": str(exc)}, is_error=True)
            else:
                return self._error(request_id, -32000, str(exc))
        except Exception as exc:  # noqa: BLE001 - protocol boundary
            log(f"internal error: {type(exc).__name__}: {exc}")
            if method == "tools/call":
                result = _text_result(f"Internal error: {exc}", {"error": str(exc)}, is_error=True)
            else:
                return self._error(request_id, -32603, f"internal error: {exc}")
        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id,
                "error": {"code": code, "message": message}}

    # --------------------------------------------------------------- tools ---
    def _call_tool(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        fn = {
            "civicshield_overview": self.tool_overview,
            "list_assets": self.tool_list_assets,
            "get_asset": self.tool_get_asset,
            "list_findings": self.tool_list_findings,
            "get_finding": self.tool_get_finding,
            "run_detection": self.tool_run_detection,
            "service_impact": self.tool_service_impact,
            "recovery_readiness": self.tool_recovery,
            "list_incidents": self.tool_list_incidents,
            "get_incident": self.tool_get_incident,
            "list_threat_indicators": self.tool_threats,
            "review_security_posture": self.tool_review,
            "explain_finding": self.tool_explain,
            "propose_remediation": self.tool_remediation,
        }.get(name)
        if not fn:
            return _text_result(f"Unknown tool: {name}", {"error": "unknown_tool"}, is_error=True)
        return fn(args or {})

    def tool_overview(self, args: Dict[str, Any]) -> Dict[str, Any]:
        review = self.client.get("/api/review/posture", focus="all", audience="technical")
        summary = {k: review.get(k) for k in (
            "assets", "open_findings", "critical_high_findings", "known_vulnerabilities",
            "critical_vulnerabilities", "services_ready", "evidence_coverage",
            "evidence_current", "latest_run")}
        return _text_result(json.dumps(summary, indent=2), summary)

    def tool_list_assets(self, args: Dict[str, Any]) -> Dict[str, Any]:
        assets = self.client.get("/api/assets") or []
        if isinstance(assets, dict):
            assets = assets.get("items", [])
        for key in ("kind", "zone", "criticality"):
            if args.get(key):
                assets = [a for a in assets if str(a.get(key, "")).lower() == str(args[key]).lower()]
        return _json_result(assets)

    def tool_get_asset(self, args: Dict[str, Any]) -> Dict[str, Any]:
        asset_id = int(args["asset_id"])
        evidence = self.client.get(f"/api/assets/{asset_id}/evidence")
        impact = self.client.get("/api/impact", asset_id=asset_id)
        findings = self.client.get("/api/findings") or []
        if isinstance(findings, dict):
            findings = findings.get("items", [])
        open_for_asset = [f for f in findings
                          if str(f.get("asset_id")) == str(asset_id)
                          and (f.get("workflow") or "open") not in ("resolved", "false_positive")]
        result = {"asset": evidence.get("name"), "hostname": evidence.get("hostname"),
                  "evidence_meta": evidence.get("meta"), "evidence": evidence.get("evidence"),
                  "impact": impact, "open_findings": open_for_asset}
        return _json_result(result)

    def tool_list_findings(self, args: Dict[str, Any]) -> Dict[str, Any]:
        findings = self.client.get("/api/findings") or []
        if isinstance(findings, dict):
            findings = findings.get("items", [])
        workflow = str(args.get("workflow", "open") or "open").lower()
        if workflow not in ("all", "any"):
            findings = [f for f in findings if (f.get("workflow") or "open") == workflow]
        if args.get("severity"):
            findings = [f for f in findings
                        if str(f.get("severity", "")).lower() == str(args["severity"]).lower()]
        if args.get("source"):
            findings = [f for f in findings
                        if str(f.get("source", "")).lower() == str(args["source"]).lower()]
        if args.get("asset_id"):
            findings = [f for f in findings if str(f.get("asset_id")) == str(args["asset_id"])]
        findings.sort(key=lambda f: float(f.get("score") or 0), reverse=True)
        limit = max(1, min(200, int(args.get("limit", 25))))
        return _json_result(findings[:limit])

    def tool_get_finding(self, args: Dict[str, Any]) -> Dict[str, Any]:
        finding_id = int(args["finding_id"])
        finding = self.client.get(f"/api/findings/{finding_id}")
        risk = self.client.get(f"/api/risk/{finding_id}")
        impact = self.client.get("/api/impact", asset_id=finding.get("asset_id"))
        result: Dict[str, Any] = {"finding": finding, "risk": risk, "impact": impact}
        if args.get("include_plan"):
            result["remediation"] = self.client.post(f"/api/findings/{finding_id}/remediation-plan")
        return _json_result(result)

    def tool_run_detection(self, args: Dict[str, Any]) -> Dict[str, Any]:
        body: Dict[str, Any] = {"online": bool(args.get("online", False))}
        if args.get("asset_ids"):
            body["asset_ids"] = [int(x) for x in args["asset_ids"]]
        detection = self.client.post("/api/detect", body)
        summary = {k: detection.get(k) for k in (
            "run_id", "scope", "assets", "results", "outcomes", "vulnerabilities",
            "critical_vulnerabilities", "warnings")}
        top = [{"rule_id": f.get("rule_id"), "asset_id": f.get("asset_id"),
                "severity": f.get("severity"), "priority": f.get("priority"),
                "source": f.get("source")}
               for f in (detection.get("findings") or [])[:8]]
        summary["top_findings"] = top
        return _json_result(summary)

    def tool_service_impact(self, args: Dict[str, Any]) -> Dict[str, Any]:
        return _json_result(self.client.get("/api/impact", asset_id=int(args["asset_id"])))

    def tool_recovery(self, args: Dict[str, Any]) -> Dict[str, Any]:
        return _json_result(self.client.get("/api/recovery/readiness"))

    def tool_list_incidents(self, args: Dict[str, Any]) -> Dict[str, Any]:
        return _json_result(self.client.get("/api/incidents"))

    def tool_get_incident(self, args: Dict[str, Any]) -> Dict[str, Any]:
        incident_id = int(args["incident_id"])
        return _json_result({
            "incident": self.client.get(f"/api/incidents/{incident_id}"),
            "report": self.client.get(f"/api/incidents/{incident_id}/report"),
        })

    def tool_threats(self, args: Dict[str, Any]) -> Dict[str, Any]:
        return _json_result(self.client.get("/api/threat-indicators"))

    def tool_review(self, args: Dict[str, Any]) -> Dict[str, Any]:
        review = self.client.get("/api/review/posture",
                                 focus=args.get("focus", "all"),
                                 audience=args.get("audience", "technical"))
        text = review.get("markdown") or json.dumps(
            {k: review.get(k) for k in ("open_findings", "known_vulnerabilities")}, indent=2)
        structured = {k: review.get(k) for k in (
            "generated_at", "focus", "audience", "assets", "open_findings",
            "critical_high_findings", "known_vulnerabilities", "critical_vulnerabilities",
            "services_ready", "evidence_coverage", "latest_run", "recommendations",
            "top_findings", "limitations")}
        return _text_result(text, structured)

    def tool_explain(self, args: Dict[str, Any]) -> Dict[str, Any]:
        return _json_result(self.client.post(f"/api/findings/{int(args['finding_id'])}/explain"))

    def tool_remediation(self, args: Dict[str, Any]) -> Dict[str, Any]:
        return _json_result(self.client.post(
            f"/api/findings/{int(args['finding_id'])}/remediation-plan"))

    # ----------------------------------------------------------- resources ---
    def _read_resource(self, uri: str) -> List[Dict[str, Any]]:
        if uri == "civicshield://estate/overview":
            data = self.client.get("/api/review/posture", focus="all", audience="technical")
            text = json.dumps({k: data.get(k) for k in (
                "generated_at", "assets", "open_findings", "critical_high_findings",
                "known_vulnerabilities", "critical_vulnerabilities", "services_ready",
                "evidence_coverage", "evidence_current", "latest_run",
                "recommendations", "limitations")}, indent=2)
            mime = "application/json"
        elif uri == "civicshield://assets":
            data = self.client.get("/api/assets")
            text = json.dumps(data, indent=2)
            mime = "application/json"
        elif uri == "civicshield://findings/open":
            data = self.tool_list_findings({"workflow": "open", "limit": 200})
            text = data["content"][0]["text"]
            mime = "application/json"
        elif uri == "civicshield://assessments/latest":
            runs = self.client.get("/api/assessments") or []
            latest = runs[-1] if runs else None
            if latest:
                results = self.client.get(f"/api/assessments/{latest['id']}") or []
                counts: Dict[str, int] = {}
                for row in results:
                    counts[row.get("outcome", "UNKNOWN")] = counts.get(row.get("outcome", "UNKNOWN"), 0) + 1
                data = {"run": latest, "outcomes": counts, "results": len(results)}
            else:
                data = {"run": None, "outcomes": {}, "results": 0}
            text = json.dumps(data, indent=2)
            mime = "application/json"
        elif uri == "civicshield://recovery/readiness":
            data = self.client.get("/api/recovery/readiness")
            text = json.dumps(data, indent=2)
            mime = "application/json"
        elif uri == "civicshield://threat-intelligence":
            data = self.client.get("/api/threat-indicators")
            text = json.dumps(data, indent=2)
            mime = "application/json"
        elif uri == "civicshield://audit/recent":
            data = self.client.get("/api/audit")
            text = json.dumps(data, indent=2)
            mime = "application/json"
        elif uri == "civicshield://review/latest":
            data = self.client.get("/api/review/posture", focus="all", audience="technical")
            text = data.get("markdown", "")
            mime = "text/markdown"
        else:
            raise CivicShieldAPIError(f"unknown resource: {uri}")
        return [{"uri": uri, "mimeType": mime, "text": text}]

    # ------------------------------------------------------------- prompts ---
    def _get_prompt(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if name == "security_review":
            focus = args.get("focus", "all")
            audience = args.get("audience", "technical")
            text = (
                f"Act as a defensive cybersecurity reviewer for a small municipal water utility. "
                f"Call review_security_posture with focus='{focus}' and audience='{audience}'. "
                "Use only recorded evidence. Separate observed evidence from inference, do not "
                "invent CVEs, and state where evidence is missing. Prioritize findings by "
                "consequence for essential services, then give a short remediation sequence "
                "with verification steps. Do not recommend automatic production changes."
            )
            description = "Evidence-grounded estate review prompt"
        elif name == "finding_triage":
            fid = args.get("finding_id")
            text = (
                f"Call get_finding for finding_id={fid} with include_plan=true. Explain the "
                "evidence, the affected asset and likely service consequence, then propose a "
                "safe remediation and a verification step. Mark any unknown evidence explicitly."
            )
            description = "Finding triage prompt"
        elif name == "incident_review":
            iid = args.get("incident_id")
            text = (
                f"Call get_incident for incident_id={iid}. Summarize the recorded timeline, "
                "separate observation from interpretation, identify evidence gaps, and propose "
                "containment and recovery next steps that require human approval."
            )
            description = "Incident review prompt"
        else:
            raise CivicShieldAPIError(f"unknown prompt: {name}")
        return {"description": description,
                "messages": [{"role": "user", "content": {"type": "text", "text": text}}]}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="CivicShield MCP server (stdio)")
    parser.add_argument("--api", default=None, help="CivicShield API base URL")
    parser.add_argument("--role", default=None, help="demo role: admin, operator or viewer")
    parser.add_argument("--token", default=None, help="optional bearer token")
    parser.add_argument("--print-tools", action="store_true",
                        help="print tool names to stderr and exit")
    args = parser.parse_args(argv)
    client = CivicShieldAPI(args.api, args.role, args.token)
    server = MCPServer(client)
    if args.print_tools:
        print("\n".join(t["name"] for t in server.TOOLS), file=sys.stderr)
        return 0
    log(f"stdio server ready; API={client.base_url} role={client.role}")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            response = MCPServer._error(None, -32700, "parse error")
        else:
            response = server.handle(message)
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
