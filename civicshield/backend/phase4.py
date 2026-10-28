"""Phase 4: auth roles (admin/operator/viewer) + demo mode, reports/CSV export (stdlib)."""
from __future__ import annotations
import csv, io, json
from dataclasses import dataclass
from typing import Dict, List, Optional

ROLES = ("admin", "operator", "viewer")
# action -> roles allowed
POLICY: Dict[str, tuple] = {
    "asset.write": ("admin", "operator"),
    "asset.read": ("admin", "operator", "viewer"),
    "assess.run": ("admin", "operator"),
    "remediate.approve": ("admin",),
    "recovery.run": ("admin", "operator"),
    "incident.write": ("admin", "operator"),
    "incident.read": ("admin", "operator", "viewer"),
    "intel.import": ("admin",),
    "intel.read": ("admin", "operator", "viewer"),
    "report.export": ("admin", "operator", "viewer"),
}


@dataclass
class User:
    name: str
    role: str


def can(user: User, action: str) -> bool:
    return user.role in POLICY.get(action, ())


def demo_users() -> List[User]:
    return [User("demo-admin", "admin"), User("demo-operator", "operator"),
            User("demo-viewer", "viewer")]


def demo_mode_enabled(env_flag: str = "1") -> bool:
    return env_flag == "1"


def incidents_csv(incidents: list) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "title", "status", "assets", "services", "events"])
    for i in incidents:
        d = i if isinstance(i, dict) else i.__dict__
        w.writerow([d.get("id"), d.get("title"), d.get("status"),
                    ";".join(d.get("assets", [])), ";".join(d.get("services", [])),
                    len(d.get("events", []))])
    return buf.getvalue()


def intel_csv(indicators: list) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "type", "value", "confidence", "source", "expires", "recommendation"])
    for x in indicators:
        d = x if isinstance(x, dict) else x.__dict__
        w.writerow([d.get("id"), d.get("i_type"), d.get("value"), d.get("confidence"),
                    d.get("source"), d.get("expires"), d.get("recommendation")])
    return buf.getvalue()


def recovery_report_md(result: dict) -> str:
    m = result["metrics"]
    lines = [f"# Recovery report — {result['scenario']['id']}",
             f"Affected assets: {m['affected_assets']}, services: {m['affected_services']}",
             f"Simulated time: {m['simulated_minutes']} min; "
             f"success {m['steps_success']}, failed {m['steps_failed']}",
             f"Essential service objective met: {m['essential_service_met']}",
             "", "## Restoration order",
             ", ".join(result["order"]) or "(none)",
             "", "## Steps"]
    for s in result["steps"]:
        lines.append(f"- {s['id']} {s['asset']}: {s['status']} — {s['note']}")
    if m["blockers"]:
        lines.append("")
        lines.append("Blockers: " + ", ".join(m["blockers"]))
    lines.append("")
    lines.append("_Simulated times are estimates, not real-world evidence._")
    return "\n".join(lines)
