"""Phase 4: RecoveryLab dependency-aware recovery simulator (stdlib only)."""
from __future__ import annotations
import csv, io, json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional


@dataclass
class Step:
    id: str
    asset: str
    action: str
    requires: List[str] = field(default_factory=list)
    needs_backup: bool = False
    est_minutes: int = 15
    status: str = "pending"  # pending|success|failed|blocked
    note: str = ""


@dataclass
class Scenario:
    id: str
    name: str
    failed_asset: str
    description: str = ""


def build_graph(assets: List[dict], depends_on: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """depends_on: asset_id -> list of asset_ids it requires."""
    graph = {a["id"]: list(depends_on.get(a["id"], [])) for a in assets}
    return graph


def dependents(graph: Dict[str, List[str]], failed: str) -> List[str]:
    """All assets transitively depending on `failed`."""
    rev: Dict[str, List[str]] = {}
    for a, deps in graph.items():
        for d in deps:
            rev.setdefault(d, []).append(a)
    out, stack, seen = [], [failed], {failed}
    # BFS over reverse edges; exclude the failed node itself
    queue = list(rev.get(failed, []))
    while queue:
        n = queue.pop(0)
        if n in seen:
            continue
        seen.add(n)
        out.append(n)
        queue.extend(rev.get(n, []))
    return out


def restoration_order(graph: Dict[str, List[str]], affected: List[str]) -> List[str]:
    """Topological order (dependencies first) restricted to affected+deps."""
    closure = set(affected)
    stack = list(affected)
    while stack:
        n = stack.pop()
        for d in graph.get(n, []):
            if d not in closure:
                closure.add(d)
                stack.append(d)
    order, temp, perm = [], set(), set()

    def visit(n):
        if n in perm:
            return
        if n in temp:
            return  # cycle: break deterministically
        temp.add(n)
        for d in sorted(graph.get(n, [])):
            if d in closure:
                visit(d)
        temp.discard(n)
        perm.add(n)
        order.append(n)
    for n in sorted(closure):
        visit(n)
    return order


def plan_steps(order: List[str], backups: Dict[str, bool]) -> List[Step]:
    steps = []
    for i, asset in enumerate(order):
        steps.append(Step(
            id=f"step-{i+1:02d}", asset=asset,
            action=f"Restore and verify {asset}",
            requires=[], needs_backup=bool(backups.get(asset, False)),
            est_minutes=15,
        ))
    # chain prerequisites in restoration order
    for i in range(1, len(steps)):
        steps[i].requires = [steps[i-1].id]
    return steps


def verify_step(step: Step, done: Dict[str, str], backups_avail: Dict[str, bool]) -> Step:
    for r in step.requires:
        if done.get(r) != "success":
            step.status, step.note = "blocked", f"Prerequisite {r} not successful."
            return step
    if step.needs_backup and not backups_avail.get(step.asset, False):
        step.status, step.note = "failed", f"No usable backup for {step.asset}."
        return step
    step.status, step.note = "success", "Prerequisites met; simulated checks passed."
    return step


def run_simulation(scenario: Scenario, graph, services: Dict[str, List[str]],
                   backups: Dict[str, bool], rto_minutes: Dict[str, int] | None = None):
    affected_assets = [scenario.failed_asset] + dependents(graph, scenario.failed_asset)
    order = restoration_order(graph, affected_assets)
    steps = plan_steps(order, backups)
    done: Dict[str, str] = {}
    total, ok, fail = 0, 0, 0
    for s in steps:
        verify_step(s, done, backups)
        done[s.id] = s.status
        total += s.est_minutes
        if s.status == "success":
            ok += 1
        else:
            fail += 1
    affected_services = [svc for svc, req in services.items()
                         if any(a in affected_assets for a in req)]
    rto_minutes = rto_minutes or {}
    rto_met = {svc: total <= rto_minutes.get(svc, 240) for svc in affected_services}
    blockers = [s.id for s in steps if s.status != "success"]
    metrics = {
        "scenario": scenario.id,
        "affected_assets": len(affected_assets),
        "affected_services": len(affected_services),
        "dependencies_required": len(order),
        "backups_available": sum(1 for a in order if backups.get(a)),
        "steps_success": ok, "steps_failed": fail,
        "simulated_minutes": total,
        "blockers": blockers,
        "rto_met": rto_met,
        "essential_service_met": all(rto_met.values()) if rto_met else True,
    }
    return {"scenario": asdict(scenario), "order": order,
            "affected_assets": affected_assets, "affected_services": affected_services,
            "steps": [asdict(s) for s in steps], "metrics": metrics}


def export_json(result: dict) -> str:
    return json.dumps(result, indent=2)


def export_csv(result: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["step", "asset", "action", "status", "note", "est_minutes"])
    for s in result["steps"]:
        w.writerow([s["id"], s["asset"], s["action"], s["status"], s["note"], s["est_minutes"]])
    w.writerow([])
    w.writerow(["metric", "value"])
    for k, v in result["metrics"].items():
        w.writerow([k, json.dumps(v)])
    return buf.getvalue()
