"""Attack-path analysis: plausible defensive paths from entry points to
high-value assets over verified relationships with labeled assumptions.

Read-only and deterministic: analyses are recomputed over the live graph on
every call, never stored. Before/after comparison for a proposed change is
done by re-running with `exclude_edge_ids` / `exclude_asset_ids` (the UI
offers per-hop "exclude & re-run"); stored analyses arrive with proposals
in Phase 5.

Traversal rules (documented, no ML):
- connects_to ............ bidirectional, lateral movement possible (assumed).
- depends_on A->B ........ B->A "downstream impact" (affects A, control of A
                            NOT implied); A->B "dependency targeting" (assumed).
- authenticates_via A->I . A->I "credential path" (assumed); I->A "identity
                            grants access to dependents" (assumed).
- manages M->T ........... M->T "declared control path"; T->M assumed.
- serves/supplies/monitors/backs_up/backed_by/unknown: not traversable for
  movement (supplies is used for blast-radius service mapping instead).
- failover: never a movement path either — it marks the standby that takes
  over, so it clears single-point-of-failure findings instead of extending
  reachability.

A hop is "confirmed" only when the edge provenance is observed; every other
hop carries its assumption in plain language. Hypothetical (simulated)
edges are included but flagged, never presented as confirmed exploits.
"""
from __future__ import annotations

from collections import deque

ANALYSIS_VERSION = "1.0.0"
ENTRY_ZONES = {"external", "edge"}
TARGET_CRITICALITIES = {"critical", "high"}
MAX_DEPTH_LIMIT = 8
MAX_PATHS_LIMIT = 10


def _assumed(provenance: str) -> bool:
    return (provenance or "").lower() != "observed"


def _connectivity(provenance: str) -> str:
    p = (provenance or "manual").lower()
    if p == "observed":
        return "confirmed"
    if p in ("configured", "manual", "imported"):
        return "configured"
    if p == "inferred":
        return "inferred"
    return "hypothetical"


def _moves(rel: dict, assets: dict[int, dict]) -> list[dict]:
    """Directed attacker moves derivable from one relationship row."""
    if rel.get("source_type") != "asset" or rel.get("target_type") != "asset":
        return []
    try:
        src, tgt = int(rel["source_id"]), int(rel["target_id"])
    except (TypeError, ValueError):
        return []
    if src not in assets or tgt not in assets:
        return []
    kind = str(rel.get("rel") or "").lower()
    prov = str(rel.get("provenance") or "manual")
    conn = _connectivity(prov)
    hyp = conn == "hypothetical"
    out: list[dict] = []

    def hop(frm: int, to: int, note: str, assumed: bool) -> dict:
        a, b = assets[frm], assets[to]
        return {"from_id": frm, "from_name": a["name"], "to_id": to,
                "to_name": b["name"], "rel": rel.get("rel") or "",
                "relationship_id": rel.get("id"), "provenance": prov,
                "connectivity": conn, "assumed": assumed or hyp, "note": note,
                "trust_boundary": a["zone"] != b["zone"],
                "zone_from": a["zone"], "zone_to": b["zone"]}

    if kind == "connects_to":
        note = ("lateral movement is possible over this link, not proven — "
                "validate with network evidence")
        out += [hop(src, tgt, note, True), hop(tgt, src, note, True)]
    elif kind == "depends_on":
        out.append(hop(tgt, src,
                       "reaching the dependency affects its dependents; "
                       "control of the dependent is NOT implied",
                       True))
        out.append(hop(src, tgt, "dependency targeting (assumed)", True))
    elif kind == "authenticates_via":
        out.append(hop(src, tgt, "credential path toward identity control (assumed)", True))
        out.append(hop(tgt, src,
                       "identity control grants access to its dependents (assumed)", True))
    elif kind == "manages":
        out.append(hop(src, tgt, "declared control path", _assumed(prov)))
        out.append(hop(tgt, src, "reverse of a management link (assumed)", True))
    return out


def _snapshot(db) -> tuple[dict[int, dict], list[dict]]:
    from app.models.models import Asset, AssetRelationship  # local: keeps import light
    assets = {}
    for a in db.query(Asset).filter(Asset.retired == 0).order_by(Asset.id).all():
        assets[a.id] = {"name": a.name or "", "hostname": a.hostname or "",
                        "kind": a.kind or "", "zone": a.zone or "",
                        "criticality": a.criticality or "low"}
    rels = [{"id": r.id, "source_type": r.source_type, "source_id": r.source_id,
             "target_type": r.target_type, "target_id": r.target_id,
             "rel": r.rel or "", "provenance": getattr(r, "provenance", "") or ""}
            for r in db.query(AssetRelationship).order_by(AssetRelationship.id).all()]
    try:
        from app.models.models import Service
        svc_names = {s.id: (s.name or f"service {s.id}")
                     for s in db.query(Service).all()}
    except Exception:
        svc_names = {}
    for r in rels:
        if r.get("target_type") == "service":
            try:
                r["target_name"] = svc_names.get(int(r["target_id"]),
                                                 f"service {r['target_id']}")
            except (TypeError, ValueError):
                r["target_name"] = f"service {r.get('target_id')}"
    return assets, rels


def _open_findings(db) -> dict[str, list[dict]]:
    from app.models.models import Finding
    by_asset: dict[str, list[dict]] = {}
    for f in db.query(Finding).all():
        if (f.workflow or "open") in ("resolved", "false_positive"):
            continue
        by_asset.setdefault(str(f.asset_id), []).append(
            {"finding_id": f.id, "rule_id": f.rule_id, "severity": f.severity})
    return by_asset


def _blast_radius(target: int, assets: dict[int, dict], rels: list[dict]) -> dict:
    downstream: set[int] = set()
    queue = deque([target])
    while queue:
        node = queue.popleft()
        for r in rels:
            if r.get("source_type") != "asset" or r.get("target_type") != "asset":
                continue
            try:
                s, t = int(r["source_id"]), int(r["target_id"])
            except (TypeError, ValueError):
                continue
            if t == node and s in assets and s not in downstream and s != target:
                if str(r.get("rel") or "").lower() in (
                        "depends_on", "connects_to", "manages", "authenticates_via"):
                    downstream.add(s)
                    queue.append(s)
    services: dict[str, str] = {}
    for r in rels:
        if r.get("target_type") == "service" and r.get("source_type") == "asset":
            try:
                if int(r["source_id"]) in downstream | {target}:
                    sid = str(r["target_id"])
                    services[sid] = r.get("target_name") or f"service {sid}"
            except (TypeError, ValueError):
                continue
    return {"asset_count": len(downstream),
            "assets": sorted(assets[i]["name"] for i in downstream if i in assets)[:20],
            "service_ids": sorted(services),
            "services": [{"id": sid, "name": services[sid]}
                         for sid in sorted(services)]}


def analyze(db, entry_asset_id: int | None = None, target_asset_id: int | None = None,
            max_depth: int = 5, max_paths: int = 5,
            exclude_edge_ids: list[int] | None = None,
            exclude_asset_ids: list[int] | None = None) -> dict:
    assets, rels = _snapshot(db)
    findings = _open_findings(db)
    return analyze_snapshot(assets, rels, findings,
                            entry_asset_id=entry_asset_id,
                            target_asset_id=target_asset_id,
                            max_depth=max_depth, max_paths=max_paths,
                            exclude_edge_ids=exclude_edge_ids,
                            exclude_asset_ids=exclude_asset_ids)


def analyze_snapshot(assets: dict[int, dict], rels: list[dict],
                     findings: dict[str, list[dict]],
                     entry_asset_id: int | None = None,
                     target_asset_id: int | None = None,
                     max_depth: int = 5, max_paths: int = 5,
                     exclude_edge_ids: list[int] | None = None,
                     exclude_asset_ids: list[int] | None = None) -> dict:
    """Same analysis over caller-supplied graph dicts (powers simulations)."""
    if not 1 <= int(max_depth) <= MAX_DEPTH_LIMIT:
        raise ValueError(f"max_depth must be 1..{MAX_DEPTH_LIMIT}")
    if not 1 <= int(max_paths) <= MAX_PATHS_LIMIT:
        raise ValueError(f"max_paths must be 1..{MAX_PATHS_LIMIT}")
    assets = {aid: dict(a) for aid, a in assets.items()}
    rels = [dict(r) for r in rels]
    excluded_edges = {int(x) for x in (exclude_edge_ids or []) if str(x).isdigit()}
    excluded_assets = {int(x) for x in (exclude_asset_ids or []) if str(x).isdigit()}
    for x in excluded_assets:
        assets.pop(x, None)
    live_rels = [r for r in rels if r["id"] not in excluded_edges]

    if entry_asset_id is not None and int(entry_asset_id) not in assets:
        raise KeyError(f"entry asset {entry_asset_id} not found")
    if target_asset_id is not None and int(target_asset_id) not in assets:
        raise KeyError(f"target asset {target_asset_id} not found")
    entries = ([int(entry_asset_id)] if entry_asset_id is not None
               else sorted(a for a, d in assets.items()
                           if d["zone"] in ENTRY_ZONES or d["kind"] == "external"))
    targets = ([int(target_asset_id)] if target_asset_id is not None
               else sorted(a for a, d in assets.items()
                           if d["criticality"] in TARGET_CRITICALITIES))

    adj: dict[int, list[dict]] = {}
    for r in live_rels:
        for m in _moves(r, assets):
            adj.setdefault(m["from_id"], []).append(m)

    crit_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    candidates: list[dict] = []
    for entry in entries:
        dist: dict[int, list[dict]] = {entry: []}
        queue: deque[int] = deque([entry])
        while queue:
            node = queue.popleft()
            if len(dist[node]) >= int(max_depth):
                continue
            for m in sorted(adj.get(node, []), key=lambda h: h["to_id"]):
                nxt = m["to_id"]
                if any(h["to_id"] == nxt for h in dist[node]) or nxt == entry:
                    continue  # simple paths only
                path = dist[node] + [m]
                if nxt not in dist:
                    dist[nxt] = path
                    queue.append(nxt)
        for tgt in targets:
            if tgt == entry or tgt not in dist:
                continue
            hops = dist[tgt]
            node_ids = [entry] + [h["to_id"] for h in hops]
            path_findings = [f for nid in node_ids for f in findings.get(str(nid), [])]
            crit_hi = sum(1 for f in path_findings
                           if str(f["severity"]).lower() in ("critical", "high"))
            assumed = sum(1 for h in hops if h["assumed"])
            boundary = sum(1 for h in hops if h["trust_boundary"])
            tcrit = assets[tgt]["criticality"]
            score = (50 - 10 * (len(hops) - 1) + 6 * min(crit_hi, 3)
                     + (8 if tcrit == "critical" else 4 if tcrit == "high" else 0)
                     + (5 if boundary else 0) - 4 * assumed)
            blast = _blast_radius(tgt, assets, live_rels)
            candidates.append({
                "entry_id": entry, "entry_name": assets[entry]["name"],
                "target_id": tgt, "target_name": assets[tgt]["name"],
                "target_criticality": tcrit, "hops": hops, "length": len(hops),
                "boundary_crossings": boundary, "assumed_hops": assumed,
                "open_findings": path_findings,
                "open_findings_count": len(path_findings),
                "blast_radius": blast,
                "rank_score": score,
                "rank_factors": {"hops": len(hops), "critical_high_findings": crit_hi,
                                 "target_criticality": tcrit,
                                 "boundary_crossings": boundary,
                                 "assumed_hops": assumed},
                "tiebreak": [tgt] + node_ids})
    candidates.sort(key=lambda c: (-c["rank_score"], c["tiebreak"]))
    paths = candidates[:int(max_paths)]
    for i, p in enumerate(paths):
        p["rank"] = i + 1
        del p["tiebreak"]
    return {"analysis_version": ANALYSIS_VERSION,
            "entries": [{"id": e, "name": assets[e]["name"],
                         "hostname": assets[e].get("hostname", ""),
                         "zone": assets[e]["zone"]} for e in entries],
            "targets": [{"id": t, "name": assets[t]["name"],
                         "hostname": assets[t].get("hostname", ""),
                         "criticality": assets[t]["criticality"]} for t in targets],
            "path_count": len(paths),
            "excluded": {"edge_ids": sorted(excluded_edges),
                         "asset_ids": sorted(excluded_assets)},
            "paths": paths}
