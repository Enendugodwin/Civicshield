"""Specialist implementations: deterministic analysis over live records.

Every handler reads the same database the UI reads, returns a typed result,
and never invents evidence. Budgets are enforced by capping list outputs.
model_used is always "rules" here: the single shared-provider call per
investigation happens in service.merge, never per agent.
"""
from __future__ import annotations

import json
from typing import Any

from app.models.models import (
    AssessmentResult,
    Asset,
    AssetRelationship,
    BackupRecord,
    Finding,
    Incident,
    IncidentEvent,
    IncidentFindingLink,
    RecoveryRun,
    RecoveryScenario,
    RemediationPlan,
    Service,
    ThreatIndicator,
)

CAP = 10


def _result(summary: str, stats: dict | None = None, items: list | None = None,
            recommendations: list | None = None,
            evidence_refs: list | None = None) -> dict:
    return {"summary": summary, "stats": stats or {},
            "items": (items or [])[:CAP],
            "recommendations": (recommendations or [])[:CAP],
            "evidence_refs": sorted(set(evidence_refs or []))[:CAP * 2],
            "model_used": "rules"}


def _open_findings(db) -> list:
    return db.query(Finding).all()


def _live_open(db) -> list:
    return [f for f in _open_findings(db)
            if (f.workflow or "open") not in ("resolved", "false_positive")]


def _evidence(a) -> dict:
    try:
        v = json.loads(a.evidence_json or "{}")
        return v if isinstance(v, dict) else {}
    except (TypeError, ValueError):
        return {}


def architecture(db, ctx: dict) -> dict:
    from app.arch_checks import service as checks
    prev = checks.preview(db)
    hits = prev["hits"][:CAP]
    by_rule: dict[str, int] = {}
    for h in prev["hits"]:
        by_rule[h["rule_id"]] = by_rule.get(h["rule_id"], 0) + 1
    return _result(
        f"{prev['asset_count']} assets, {prev['relationship_count']} links, "
        f"{prev['hit_count']} structural hits across {len(by_rule)} rules.",
        {"assets": prev["asset_count"], "relationships": prev["relationship_count"],
         "hits": prev["hit_count"], "by_rule": by_rule},
        [{"rule_id": h["rule_id"], "asset": h["asset_name"],
          "severity": h["severity"], "status": h["status"],
          "evidence_ref": h["evidence_ref"], "detail": h["detail"][:300]} for h in hits],
        [h["remediation"] for h in prev["hits"][:3]],
        [h["evidence_ref"] for h in hits])


def exposure(db, ctx: dict) -> dict:
    live = _live_open(db)
    vuln = [f for f in live if str(f.rule_id).startswith("CVE-")]
    crit = [f for f in vuln if str(f.severity).lower() in ("critical", "high")]
    groups: dict[str, dict] = {}
    for f in vuln:
        g = groups.setdefault(f.rule_id, {"rule_id": f.rule_id, "count": 0,
                                          "assets": [], "severity": f.severity})
        g["count"] += 1
        if len(g["assets"]) < 5:
            g["assets"].append(str(f.asset_id))
    top = sorted(groups.values(), key=lambda g: (-g["count"], g["rule_id"]))[:CAP]
    by_asset: dict[str, int] = {}
    for f in crit:
        by_asset[str(f.asset_id)] = by_asset.get(str(f.asset_id), 0) + 1
    worst = sorted(by_asset.items(), key=lambda kv: -kv[1])[:3]
    names = {str(a.id): (a.name or "") for a in db.query(Asset).all()}
    return _result(
        f"{len(vuln)} open vulnerability findings ({len(crit)} critical/high) "
        f"in {len(groups)} advisories.",
        {"vuln_findings": len(vuln), "critical_high": len(crit),
         "advisories": len(groups)},
        [{"rule_id": g["rule_id"], "assets": g["assets"], "count": g["count"],
          "severity": g["severity"]} for g in top],
        [f"Patch {names.get(aid, aid)}: {n} critical/high CVEs open" for aid, n in worst],
        [f.rule_id for f in crit[:CAP]])


def identity(db, ctx: dict) -> dict:
    gaps = []
    for a in db.query(Asset).filter(Asset.retired == 0).all():
        ident = _evidence(a).get("identity")
        if not isinstance(ident, dict):
            continue
        priv = ident.get("privileged_accounts") or []
        no_mfa = [p.get("name", "?") for p in priv
                  if isinstance(p, dict) and not p.get("mfa")]
        if no_mfa:
            gaps.append({"asset": a.name, "gap": "privileged_without_mfa",
                         "accounts": no_mfa[:5],
                         "evidence_ref": "identity.privileged_accounts"})
        try:
            if int(ident.get("admin_count", 0)) > int(ident.get("max_admins", 999)):
                gaps.append({"asset": a.name, "gap": "admin_count_over_policy",
                             "evidence_ref": "identity.admin_count;identity.max_admins"})
        except (TypeError, ValueError):
            pass
        if ident.get("shared_admin_accounts"):
            gaps.append({"asset": a.name, "gap": "shared_admin_accounts",
                         "evidence_ref": "identity.shared_admin_accounts"})
        if ident.get("least_privilege_enforced") is False:
            gaps.append({"asset": a.name, "gap": "least_privilege_not_enforced",
                         "evidence_ref": "identity.least_privilege_enforced"})
    return _result(
        f"{len(gaps)} identity gaps across inventoried assets.",
        {"gaps": len(gaps)},
        gaps[:CAP],
        ["Enforce MFA on privileged accounts",
         "Remove shared admin accounts"] if gaps else [],
        [g["evidence_ref"] for g in gaps[:CAP]])


def cloud(db, ctx: dict) -> dict:
    ext = [a for a in db.query(Asset).filter(Asset.retired == 0).all()
           if str(a.kind).lower() == "external" or str(a.zone).lower() == "external"]
    high = [a for a in ext if str(a.criticality).lower() in ("critical", "high")]
    zones = sorted({str(a.zone) for a in ext})
    return _result(
        f"{len(ext)} external/SaaS dependencies tracked"
        + (f", {len(high)} of them high-value." if high else "."),
        {"external": len(ext), "high_value": len(high), "zones": zones},
        [{"asset": a.name, "criticality": a.criticality, "zone": a.zone} for a in ext],
        [f"Confirm vendor SLA and recovery path for {a.name}" for a in high[:3]],
        [f"asset:{a.id}" for a in ext[:CAP]])


def network(db, ctx: dict) -> dict:
    from app import attack_paths
    assets = db.query(Asset).filter(Asset.retired == 0).all()
    per_zone: dict[str, int] = {}
    for a in assets:
        per_zone[str(a.zone)] = per_zone.get(str(a.zone), 0) + 1
    ot = [a.name for a in assets if str(a.zone).lower() == "plant"]
    ana = attack_paths.analyze(db, max_depth=3, max_paths=3)
    seg = [p for p in ana["paths"] if p["boundary_crossings"] > 0]
    return _result(
        f"{len(assets)} assets across {len(per_zone)} zones; "
        f"{len(ot)} OT (plant) assets; {len(seg)} sampled paths cross a trust boundary.",
        {"assets": len(assets), "zones": per_zone, "ot_assets": len(ot),
         "boundary_paths": len(seg)},
        [{"entry": p["entry_name"], "target": p["target_name"],
          "crossings": p["boundary_crossings"]} for p in seg],
        ["Segment OT from office networks with a monitored DMZ"] if ot else [],
        [f"analysis:{ana['analysis_version']}"])


def threat(db, ctx: dict) -> dict:
    import time as _time
    now = _time.time()
    active = [t for t in db.query(ThreatIndicator).all()
              if not t.expires_at or t.expires_at > now]
    live = _live_open(db)
    cve_rules = {str(f.rule_id) for f in live if str(f.rule_id).startswith("CVE-")}
    return _result(
        f"{len(active)} active indicators; {len(cve_rules)} advisories match open findings.",
        {"indicators": len(active), "matching_advisories": len(cve_rules)},
        [{"value": t.value, "kind": t.kind, "confidence": t.confidence,
          "source": t.source} for t in active[:CAP]],
        [f"Prioritize patching for {r}: known-affecting advisory with open findings"
         for r in sorted(cve_rules)[:3]],
        sorted(cve_rules)[:CAP])


def detection(db, ctx: dict) -> dict:
    poor = []
    for a in db.query(Asset).filter(Asset.retired == 0).all():
        ep = _evidence(a).get("endpoint")
        cov = ep.get("monitoring_coverage") if isinstance(ep, dict) else None
        try:
            cov_f = float(cov) if cov is not None else None
        except (TypeError, ValueError):
            cov_f = None
        if cov_f is None or cov_f < 0.8:
            poor.append({"asset": a.name, "coverage": cov,
                         "evidence_ref": "endpoint.monitoring_coverage"})
    objectives = [{"objective": f"Detect lateral movement toward {p['asset']}",
                   "log_sources": ["endpoint EDR", "authentication logs"],
                   "covers": p["evidence_ref"]} for p in poor[:CAP]]
    return _result(
        f"{len(poor)} assets below 0.8 monitoring coverage (or unreported).",
        {"gaps": len(poor)},
        poor[:CAP], objectives,
        [p["evidence_ref"] for p in poor[:3]])


def incident(db, ctx: dict) -> dict:
    open_inc = [i for i in db.query(Incident).all() if i.status == "open"]
    items = []
    for i in open_inc[:CAP]:
        evts = db.query(IncidentEvent).filter(
            IncidentEvent.incident_id == i.id).order_by(IncidentEvent.ts).all()
        links = db.query(IncidentFindingLink).filter(
            IncidentFindingLink.incident_id == i.id).all()
        items.append({"incident_id": i.id, "title": i.title, "severity": i.severity,
                      "commander": i.commander, "events": len(evts),
                      "linked_findings": len(links),
                      "confirmed": sum(1 for e in evts if e.kind == "observed"),
                      "suspected": sum(1 for e in evts if e.kind != "observed")})
    timeline = [{"incident_id": i.id, "kind": "opened", "detail": i.title}
                for i in open_inc[:3]]
    return _result(
        f"{len(open_inc)} open incidents; confirmed observations kept separate "
        f"from suspicion in every timeline.",
        {"open": len(open_inc)},
        items, timeline,
        [f"incident:{i.id}" for i in open_inc[:CAP]])


def advisor(db, ctx: dict) -> dict:
    from app.arch_checks import service as checks
    from app import attack_paths
    prev = checks.preview(db)
    ana = attack_paths.analyze(db, max_depth=4, max_paths=3)
    recs = []
    for h in prev["hits"][:5]:
        recs.append({"area": h["rule_id"], "asset": h["asset_name"],
                     "weakness": h["detail"][:200], "proposal": h["remediation"],
                     "benefit": f"Removes a {h['severity']} structural risk",
                     "validation": "Re-run architecture checks after the change"})
    for p in ana["paths"][:3]:
        recs.append({"area": "attack-path", "asset": p["target_name"],
                     "weakness": f"Reachable from {p['entry_name']} in {p['length']} hops",
                     "proposal": f"Break hop 1 ({p['hops'][0]['rel']}) or add monitoring",
                     "benefit": "Cuts the highest-ranked defensive path",
                     "validation": "Re-run attack-path analysis with the exclusion"})
    return _result(
        f"{len(prev['hits'])} structural hits and {len(ana['paths'])} sampled "
        f"paths converted to prioritized proposals.",
        {"structural_hits": len(prev["hits"]), "paths": len(ana["paths"])},
        recs[:CAP], [r["proposal"] for r in recs[:3]],
        [h["evidence_ref"] for h in prev["hits"][:5]])


def remediation(db, ctx: dict) -> dict:
    live = _live_open(db)
    planned = {str(p.finding_id) for p in db.query(RemediationPlan).all()}
    unplanned = [f for f in live if str(f.id) not in planned]
    by_sev: dict[str, int] = {}
    for f in unplanned:
        by_sev[str(f.severity)] = by_sev.get(str(f.severity), 0) + 1
    workplan = [{"finding_id": f.id, "rule_id": f.rule_id,
                 "asset_id": str(f.asset_id), "severity": f.severity,
                 "step": "Draft FixPilot plan, approve, simulate, verify"}
                for f in sorted(unplanned, key=lambda x: -_sev_rank(x))[:CAP]]
    return _result(
        f"{len(unplanned)} open findings without a remediation plan.",
        {"unplanned": len(unplanned), "by_severity": by_sev},
        workplan,
        ["Draft plans oldest-critical-first; every plan needs verification evidence"],
        [f"finding:{w['finding_id']}" for w in workplan[:CAP]])


def _sev_rank(f) -> float:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return float(order.get(str(f.severity).lower(), 0))


def recovery(db, ctx: dict) -> dict:
    runs = db.query(RecoveryRun).order_by(RecoveryRun.id.desc()).all()
    last = None
    if runs:
        try:
            last = json.loads(runs[0].result_json or "{}")
        except (TypeError, ValueError):
            last = {}
    backups = db.query(BackupRecord).all()
    immutable = sum(1 for b in backups if b.immutable_backup)
    scenarios = db.query(RecoveryScenario).count()
    ok = bool(last) and not str(last.get("status", "")).lower().startswith("fail")
    return _result(
        ("Last recovery simulation " + ("passed." if ok else "has no passing run."))
        + f" {immutable}/{len(backups)} backup records immutable; "
        f"{scenarios} scenarios catalogued.",
        {"runs": len(runs), "last_ok": ok, "immutable": immutable,
         "total_backups": len(backups), "scenarios": scenarios},
        ([{"run_id": runs[0].id, "scenario": runs[0].scenario_id,
           "result": str(last)[:200]}] if runs else []),
        [] if ok else ["Run a RecoveryLab scenario for the least-tested service"],
        ["recovery:latest"] if runs else [])


def governance(db, ctx: dict) -> dict:
    FAMILIES = {"BG-ASSET": "Asset Management", "BG-ID": "Identity",
                "BG-ENDP": "Endpoint", "BG-BKP": "Backup & Recovery",
                "CVE-": "Vulnerability Management", "AR-": "Architecture"}
    assessed = {r.rule_id for r in db.query(AssessmentResult.rule_id).distinct()}
    live = _live_open(db)
    coverage = []
    for prefix, family in FAMILIES.items():
        rules = sorted({r for r in assessed if r.startswith(prefix)})
        open_n = sum(1 for f in live if str(f.rule_id).startswith(prefix))
        coverage.append({"family": family, "assessed_controls": len(rules),
                         "open_findings": open_n,
                         "note": "Coverage of assessed controls, not a compliance claim."})
    return _result(
        f"{len(assessed)} controls assessed across {len(FAMILIES)} families; "
        f"{len(live)} findings open.",
        {"assessed": len(assessed), "open": len(live)},
        coverage, [],
        ["assessment:latest"])


HANDLERS = {"architecture": architecture, "exposure": exposure,
            "identity": identity, "cloud": cloud, "network": network,
            "threat": threat, "detection": detection, "incident": incident,
            "advisor": advisor, "remediation": remediation,
            "recovery": recovery, "governance": governance}


def run(agent_id: str, db, ctx: dict) -> dict:
    fn = HANDLERS.get(agent_id)
    if fn is None:
        raise KeyError(f"no specialist implementation for '{agent_id}'")
    return fn(db, ctx or {})
