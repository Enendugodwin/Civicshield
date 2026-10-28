"""Detection orchestration: evidence -> deterministic checks + CVE matching.

The configurable assessment engine (baseline_guard) answers "is this control
configured safely?" The vulnerability engine answers "is this declared software
version known to be vulnerable?" Both consume the same collected evidence, so a
single run produces one evidence trail, one risk score per issue, and one set
of findings.

Only FAIL results and vulnerability matches become findings. PASS and UNKNOWN
stay in AssessmentResult for audit, and any previously open finding that now
passes is marked resolved with a reason instead of silently disappearing.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.models import (
    AssessmentResult,
    AssessmentRun,
    Asset,
    AssetRelationship,
    AuditEvent,
    Finding,
    RiskAssessment,
)
from app import vuln_intel

_HERE = Path(__file__).resolve()
for _p in (_HERE.parents[2], _HERE.parents[1]):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import baseline_guard  # noqa: E402
import impact_engine  # noqa: E402

STALE_AFTER_SECONDS = 7 * 24 * 3600
RULE_VERSION = "1.1.0"


def _evidence(asset: Asset) -> Dict[str, Any]:
    try:
        value = json.loads(asset.evidence_json or "{}")
        return value if isinstance(value, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def evidence_meta(evidence: Dict[str, Any]) -> Dict[str, Any]:
    collector = evidence.get("collector") if isinstance(evidence, dict) else None
    if not isinstance(collector, dict):
        collector = {}
    collected = collector.get("collected_at")
    try:
        collected = float(collected) if collected is not None else None
    except (TypeError, ValueError):
        collected = None
    return {
        "source": collector.get("source", "seed-fixture"),
        "collector_version": collector.get("version", ""),
        "collected_at": collected,
        "hostname": collector.get("hostname", ""),
        "age_seconds": (time.time() - collected) if collected else None,
    }


def _scope_for(asset_ids: Optional[Iterable[int]]) -> str:
    if asset_ids:
        return "asset:" + ",".join(str(x) for x in asset_ids)
    return "all"


def _impact_engine(db: Session) -> impact_engine.ImpactEngine:
    edges: Dict[str, List[str]] = {}
    services: Dict[str, List[str]] = {}
    for rel in db.query(AssetRelationship).all():
        if rel.source_type == "asset" and rel.target_type == "asset":
            edges.setdefault(str(rel.source_id), []).append(str(rel.target_id))
        elif rel.source_type == "asset" and rel.target_type == "service":
            services.setdefault(f"service:{rel.target_id}", []).append(str(rel.source_id))
    return impact_engine.ImpactEngine(edges=edges, services=services)


def _context(asset: Asset, finding: baseline_guard.Finding,
             evidence: Dict[str, Any], advisory: Optional[vuln_intel.Advisory]) -> Dict[str, Any]:
    network = evidence.get("network") if isinstance(evidence.get("network"), dict) else {}
    exposed = bool(network.get("remote_admin_exposed"))
    if finding.category == "vulnerability" and str(asset.zone).lower() in ("edge", "external", "wan"):
        exposed = True
    return {
        "criticality": asset.criticality or "low",
        "exposed": exposed,
        "privileged": finding.category == "identity",
        "known_exploited": bool(advisory.known_exploited) if advisory else False,
        "exploit_available": bool(advisory.exploit_available) if advisory else False,
        "status": "confirmed",
    }


def run_detection(db: Session, asset_ids: Optional[List[int]] = None, online: bool = False,
                  actor: str = "system", scope: Optional[str] = None) -> Dict[str, Any]:
    """Collect, assess and score every selected asset. Returns a run summary."""
    query = db.query(Asset).filter(Asset.retired == 0)
    if asset_ids:
        query = query.filter(Asset.id.in_(asset_ids))
    assets = query.order_by(Asset.id).all()
    evidence = {str(a.id): _evidence(a) for a in assets}

    engine = baseline_guard.build_default_engine()
    config = engine.assess_all(evidence)
    config_findings = list(config.findings)

    vuln_findings: List[baseline_guard.Finding] = []
    warnings: List[str] = []
    for asset in assets:
        found, warns = vuln_intel.scan(str(asset.id), evidence[str(asset.id)], online=online)
        vuln_findings.extend(found)
        warnings.extend(warns)

    findings = config_findings + vuln_findings
    scope = scope or _scope_for(asset_ids)
    run = AssessmentRun(rule_version=RULE_VERSION, scope=scope)
    db.add(run)
    db.flush()

    ie = _impact_engine(db)
    by_asset = {str(a.id): a for a in assets}
    current_vulns = {(str(f.asset_id), f.rule_id) for f in vuln_findings}
    outcomes = {"PASS": 0, "FAIL": 0, "UNKNOWN": 0, "NOT_APPLICABLE": 0}
    emitted: List[Dict[str, Any]] = []
    critical_vulns = 0

    for f in findings:
        outcomes[f.outcome] = outcomes.get(f.outcome, 0) + 1
        db.add(AssessmentResult(
            run_id=run.id, rule_id=f.rule_id, asset_id=f.asset_id,
            outcome=f.outcome, severity=f.severity, evidence_ref=f.evidence_ref,
        ))
        asset = by_asset.get(str(f.asset_id))
        if not asset:
            continue
        existing = (db.query(Finding)
                    .filter(Finding.rule_id == f.rule_id, Finding.asset_id == f.asset_id)
                    .first())

        if f.outcome != baseline_guard.FAIL:
            # The control now passes or is unknown: close an earlier open
            # finding rather than leaving stale open work in the queue.
            if existing and (existing.workflow or "open") not in ("resolved", "false_positive"):
                existing.workflow = "resolved"
                existing.resolution_reason = (
                    "reassessed by detection: control no longer fails "
                    f"({f.outcome.lower()})"
                )
            continue

        advisory = vuln_intel.advisory_for(f.rule_id) if f.category == "vulnerability" else None
        scored = ie.score_finding(
            {"rule_id": f.rule_id, "asset_id": f.asset_id, "severity": f.severity,
             "confidence": f.confidence},
            _context(asset, f, evidence[str(f.asset_id)], advisory),
        )
        key = f"{f.rule_id}:{f.asset_id}"
        risk = db.query(RiskAssessment).filter(RiskAssessment.finding_id == key).first()
        if risk:
            risk.score, risk.priority = scored.score, scored.priority
            risk.factors_json, risk.created_at = json.dumps(scored.factors), time.time()
        else:
            db.add(RiskAssessment(finding_id=key, score=scored.score,
                                  priority=scored.priority,
                                  factors_json=json.dumps(scored.factors)))

        if existing:
            existing.run_id = run.id
            existing.severity = f.severity
            existing.detail = f.detail
            if (existing.workflow or "open") in ("resolved", "false_positive"):
                existing.workflow = "open"
                existing.resolution_reason = "reopened by detection: evidence still fails"
            finding_id = existing.id
        else:
            row = Finding(run_id=run.id, rule_id=f.rule_id, asset_id=f.asset_id,
                          severity=f.severity, status="confirmed", detail=f.detail)
            db.add(row)
            db.flush()
            finding_id = row.id

        if f.category == "vulnerability" and f.severity == "critical":
            critical_vulns += 1
        emitted.append({
            "finding_id": finding_id,
            "rule_id": f.rule_id,
            "asset_id": f.asset_id,
            "outcome": f.outcome,
            "severity": f.severity,
            "source": "vulnerability" if f.category == "vulnerability" else "configuration",
            "detail": f.detail,
            "evidence_ref": f.evidence_ref,
            "confidence": f.confidence,
            "score": scored.score,
            "priority": scored.priority,
            "impacted_services": scored.impacted_services,
        })

    # Resolve CVE findings that no longer match the current software inventory.
    for asset in assets:
        for old in (db.query(Finding)
                    .filter(Finding.asset_id == str(asset.id),
                            Finding.rule_id.like("CVE-%")).all()):
            if (str(asset.id), old.rule_id) not in current_vulns and \
                    (old.workflow or "open") not in ("resolved", "false_positive"):
                old.workflow = "resolved"
                old.resolution_reason = "reassessed by detection: software no longer matches advisory"

    db.add(AuditEvent(
        actor=actor,
        action="detection_run",
        detail=(f"run={run.id} scope={scope} assets={len(assets)} "
                f"fail={outcomes['FAIL']} vulnerable={len(vuln_findings)} online={online}"),
    ))
    db.commit()

    return {
        "run_id": run.id,
        "scope": scope,
        "rule_version": RULE_VERSION,
        "assets": len(assets),
        "results": len(findings),
        "outcomes": outcomes,
        "vulnerabilities": len(vuln_findings),
        "critical_vulnerabilities": critical_vulns,
        "findings": emitted,
        "advisories": vuln_intel.snapshot(),
        "online": online,
        "warnings": sorted(set(warnings)),
    }


def posture(db: Session) -> Dict[str, Any]:
    """Collector coverage and the inputs available to the detection engine."""
    assets = db.query(Asset).filter(Asset.retired == 0).order_by(Asset.id).all()
    now = time.time()
    rows: List[Dict[str, Any]] = []
    current = stale = never = 0
    for asset in assets:
        ev = _evidence(asset)
        meta = evidence_meta(ev)
        age = meta["age_seconds"]
        if age is None:
            state = "never"
            never += 1
        elif age > STALE_AFTER_SECONDS:
            state = "stale"
            stale += 1
        else:
            state = "current"
            current += 1
        software = vuln_intel.normalize_software(ev)
        rows.append({
            "asset_id": asset.id,
            "name": asset.name,
            "hostname": asset.hostname or "",
            "criticality": asset.criticality or "low",
            "state": state,
            "source": meta["source"],
            "collector_version": meta["collector_version"],
            "collected_at": meta["collected_at"],
            "age_hours": (round(age / 3600, 1) if age is not None else None),
            "software_count": len(software),
            "evidence_keys": sorted(k for k in ev.keys() if not k.startswith("_")),
        })

    last_run = db.query(AssessmentRun).order_by(AssessmentRun.id.desc()).first()
    total = len(assets) or 1
    return {
        "generated_at": now,
        "assets_total": len(assets),
        "assets_current": current,
        "assets_stale": stale,
        "assets_never": never,
        "coverage": round(current / total, 3),
        "stale_after_hours": STALE_AFTER_SECONDS // 3600,
        "assets": rows,
        "advisories": vuln_intel.snapshot(),
        "last_run": ({"id": last_run.id, "started_at": last_run.started_at,
                      "scope": getattr(last_run, "scope", "all") or "all"} if last_run else None),
        "limitations": (
            "A current evidence record is not a guarantee of safety. Checks are read-only, "
            "version matching does not prove exploitability, and the bundled advisory set is a demo snapshot."
        ),
    }


def detect_one(db: Session, asset_id: int, online: bool = False, actor: str = "system") -> Dict[str, Any]:
    return run_detection(db, [asset_id], online=online, actor=actor, scope=f"asset:{asset_id}")
