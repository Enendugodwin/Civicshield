"""ImpactEngine: deterministic weighted 0-100 risk scoring + graph traversal.

Weights sum to 100:
  severity 30 | criticality 20 | exposure 15 | confidence 10 |
  exploitability 10 | privilege 5 | dependency blast-radius 5 | compensating controls 5
Priority: >=85 Critical, >=65 High, >=40 Moderate, >=15 Low, else Informational.
Stdlib only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Sequence

WEIGHTS = {
    "severity": 30.0,
    "criticality": 20.0,
    "exposure": 15.0,
    "confidence": 10.0,
    "exploitability": 10.0,
    "privilege": 5.0,
    "blast_radius": 5.0,
    "controls": 5.0,
}

SEVERITY_SCORE = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25, "info": 0.0}
CRITICALITY_SCORE = {"critical": 1.0, "high": 0.75, "moderate": 0.5, "low": 0.25}
CONFIDENCE_SCORE = {"high": 1.0, "medium": 0.6, "low": 0.3}


def priority_for(score: float) -> str:
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Moderate"
    if score >= 15:
        return "Low"
    return "Informational"


def split_relationships(rows: Sequence[Any]) -> tuple[Dict[str, List[str]], Dict[str, List[str]]]:
    """Split relationship rows into asset->asset edges and service->assets maps.

    Single owner for the graph-building loop previously inlined in both
    /api/impact and /api/recovery/runs. Keys are stringified ids.
    """
    edges: Dict[str, List[str]] = {}
    svc_deps: Dict[str, List[str]] = {}
    for r in rows:
        s, t = str(r.source_id), str(r.target_id)
        if r.source_type == "asset" and r.target_type == "asset":
            edges.setdefault(s, []).append(t)
        elif r.source_type == "asset" and r.target_type == "service":
            svc_deps.setdefault(t, []).append(s)
    return edges, svc_deps


def traverse_service_impact(start_asset: str,
                            edges: Mapping[str, Sequence[str]],
                            services: Mapping[str, Sequence[str]] | None = None) -> Dict[str, Any]:
    """BFS downstream from start_asset. edges: asset -> [dependents].

    services maps service name -> assets it depends on; a service is
    impacted when any visited asset is in its dependency set.
    """
    visited: List[str] = []
    queue = [start_asset]
    seen = {start_asset}
    while queue:
        node = queue.pop(0)
        visited.append(node)
        for dep in edges.get(node, []):
            if dep not in seen:
                seen.add(dep)
                queue.append(dep)
    impacted_services: List[str] = []
    if services:
        downstream = set(visited)
        for svc, deps in services.items():
            if downstream & set(deps):
                impacted_services.append(svc)
    return {"visited_assets": visited,
            "blast_radius": max(0, len(visited) - 1),
            "impacted_services": sorted(impacted_services)}


@dataclass
class ScoredFinding:
    finding_id: str
    asset_id: str
    score: float
    priority: str
    factors: Dict[str, float] = field(default_factory=dict)
    impacted_services: List[str] = field(default_factory=list)
    blast_radius: int = 0
    status: str = "confirmed"  # confirmed | inferred | simulated

    def to_dict(self) -> Dict[str, Any]:
        return {"finding_id": self.finding_id, "asset_id": self.asset_id,
                "score": self.score, "priority": self.priority,
                "factors": dict(self.factors),
                "impacted_services": list(self.impacted_services),
                "blast_radius": self.blast_radius, "status": self.status}


class ImpactEngine:
    def __init__(self, edges: Mapping[str, Sequence[str]] | None = None,
                 services: Mapping[str, Sequence[str]] | None = None):
        self.edges: Dict[str, List[str]] = {k: list(v) for k, v in (edges or {}).items()}
        self.services: Dict[str, List[str]] = {k: list(v) for k, v in (services or {}).items()}

    def score_finding(self, finding: Mapping[str, Any],
                      context: Mapping[str, Any] | None = None) -> ScoredFinding:
        ctx: Dict[str, Any] = dict(context or {})
        sev = SEVERITY_SCORE.get(str(finding.get("severity", "info")).lower(), 0.0)
        crit = CRITICALITY_SCORE.get(str(ctx.get("criticality", "low")).lower(), 0.25)
        expo = 1.0 if ctx.get("exposed", False) else (0.5 if ctx.get("internet_facing") else 0.0)
        conf = CONFIDENCE_SCORE.get(str(finding.get("confidence", "low")).lower(), 0.3)
        expl = 1.0 if ctx.get("known_exploited", False) else (0.6 if ctx.get("exploit_available") else 0.0)
        priv = 1.0 if ctx.get("privileged", False) else 0.0
        impact = traverse_service_impact(str(finding.get("asset_id", "")),
                                         self.edges, self.services or None)
        blast_norm = min(1.0, impact["blast_radius"] / 5.0)
        controls = 0.0 if ctx.get("compensating_controls") else 1.0
        factors = {"severity": round(sev * WEIGHTS["severity"], 2),
                   "criticality": round(crit * WEIGHTS["criticality"], 2),
                   "exposure": round(expo * WEIGHTS["exposure"], 2),
                   "confidence": round(conf * WEIGHTS["confidence"], 2),
                   "exploitability": round(expl * WEIGHTS["exploitability"], 2),
                   "privilege": round(priv * WEIGHTS["privilege"], 2),
                   "blast_radius": round(blast_norm * WEIGHTS["blast_radius"], 2),
                   "controls": round(controls * WEIGHTS["controls"], 2)}
        score = round(min(100.0, sum(factors.values())), 2)
        status = str(ctx.get("status", finding.get("status", "confirmed")))
        if status not in ("confirmed", "inferred", "simulated"):
            status = "confirmed"
        return ScoredFinding(
            finding_id=str(finding.get("rule_id", "UNKNOWN")) + ":" + str(finding.get("asset_id", "")),
            asset_id=str(finding.get("asset_id", "")),
            score=score, priority=priority_for(score), factors=factors,
            impacted_services=impact["impacted_services"],
            blast_radius=impact["blast_radius"], status=status)

    def prioritize(self, findings: Sequence[Mapping[str, Any]],
                   contexts: Mapping[str, Mapping[str, Any]] | None = None) -> List[ScoredFinding]:
        contexts = contexts or {}
        scored = [self.score_finding(f, contexts.get(str(f.get("asset_id", "")), {}))
                  for f in findings]
        return sorted(scored, key=lambda s: s.score, reverse=True)
