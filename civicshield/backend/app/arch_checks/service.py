"""Staged architecture checks: preview first, explicit raise, idempotent.

Raise mirrors detection.run_detection bookkeeping so AR-* findings flow
through the same queue, risk scores, workflow transitions, and audit trail:
dedupe on (rule_id, asset_id), reopen resolved rows that still fail, and
resolve open rows that no longer fail instead of deleting them.
"""
from __future__ import annotations

import json
import time

from app.arch_checks import rules
from app.models.models import (
    AssessmentResult,
    AssessmentRun,
    Asset,
    AssetRelationship,
    AuditEvent,
    Finding,
    RiskAssessment,
)


def snapshot(db) -> tuple[dict[int, dict], list[dict]]:
    assets: dict[int, dict] = {}
    for a in db.query(Asset).filter(Asset.retired == 0).order_by(Asset.id).all():
        assets[a.id] = {"name": a.name or "", "kind": a.kind or "",
                       "zone": a.zone or "", "criticality": a.criticality or "low",
                       "owner": a.owner or "", "status": a.status or ""}
    rels = [{"id": r.id, "source_type": r.source_type, "source_id": r.source_id,
             "target_type": r.target_type, "target_id": r.target_id,
             "rel": r.rel or "", "provenance": getattr(r, "provenance", "") or ""}
            for r in db.query(AssetRelationship).order_by(AssetRelationship.id).all()]
    return assets, rels


def _hit_dict(h: rules.ArchHit) -> dict:
    return {"rule_id": h.rule_id, "severity": h.severity, "confidence": h.confidence,
            "status": h.status, "asset_id": h.asset_id, "asset_name": h.asset_name,
            "evidence_ref": h.evidence_ref, "detail": h.detail,
            "remediation": h.remediation}


def preview(db, rule_ids: list[str] | None = None) -> dict:
    assets, rels = snapshot(db)
    hits = [_hit_dict(h) for h in rules.evaluate(assets, rels, rule_ids)]
    return {"rule_version": rules.ARCH_RULE_VERSION, "rules": rules.describe(),
            "asset_count": len(assets), "relationship_count": len(rels),
            "hit_count": len(hits), "hits": hits}


def raise_findings(db, rule_ids: list[str] | None = None, actor: str = "system") -> dict:
    from app import detection  # lazy: detection owns the scoring engine

    assets, rels = snapshot(db)
    by_id = {str(aid): a for aid, a in assets.items()}
    hits = rules.evaluate(assets, rels, rule_ids)
    evaluated = {h.rule_id for h in hits} | set(rule_ids or [])

    run = AssessmentRun(rule_version=f"arch-{rules.ARCH_RULE_VERSION}", scope="architecture")
    db.add(run)
    db.flush()

    engine = detection._impact_engine(db)
    wanted = set(rule_ids or [])
    live_keys = {(h.rule_id, h.asset_id) for h in hits}
    created = reopened = 0
    emitted: list[dict] = []

    for h in hits:
        db.add(AssessmentResult(run_id=run.id, rule_id=h.rule_id, asset_id=h.asset_id,
                               outcome="FAIL", severity=h.severity,
                               evidence_ref=h.evidence_ref))
        asset = by_id.get(str(h.asset_id), {})
        scored = engine.score_finding(
            {"rule_id": h.rule_id, "asset_id": h.asset_id,
             "severity": h.severity, "confidence": h.confidence},
            {"criticality": asset.get("criticality", "low"),
             "exposed": h.rule_id == "AR-EXP-01",
             "privileged": False, "known_exploited": False,
             "exploit_available": False, "status": h.status})
        key = f"{h.rule_id}:{h.asset_id}"
        risk = db.query(RiskAssessment).filter(RiskAssessment.finding_id == key).first()
        if risk:
            risk.score, risk.priority = scored.score, scored.priority
            risk.factors_json, risk.created_at = json.dumps(scored.factors), time.time()
        else:
            db.add(RiskAssessment(finding_id=key, score=scored.score,
                                  priority=scored.priority,
                                  factors_json=json.dumps(scored.factors)))
        existing = (db.query(Finding)
                    .filter(Finding.rule_id == h.rule_id, Finding.asset_id == h.asset_id)
                    .first())
        if existing:
            existing.run_id = run.id
            existing.severity = h.severity
            existing.detail = h.detail
            existing.status = h.status
            if (existing.workflow or "open") in ("resolved", "false_positive"):
                existing.workflow = "open"
                existing.resolution_reason = "reopened by architecture checks: structure still fails"
                reopened += 1
            finding_id = existing.id
        else:
            row = Finding(run_id=run.id, rule_id=h.rule_id, asset_id=h.asset_id,
                          severity=h.severity, status=h.status, detail=h.detail)
            db.add(row)
            db.flush()
            finding_id = row.id
            created += 1
        emitted.append({"finding_id": finding_id, "rule_id": h.rule_id,
                        "asset_id": h.asset_id, "asset_name": h.asset_name,
                        "severity": h.severity, "source": "architecture",
                        "detail": h.detail, "evidence_ref": h.evidence_ref,
                        "confidence": h.confidence, "score": scored.score,
                        "priority": scored.priority,
                        "impacted_services": scored.impacted_services,
                        "remediation": h.remediation})

    resolved_stale = 0
    for old in db.query(Finding).filter(Finding.rule_id.like("AR-%")).all():
        if wanted and old.rule_id not in wanted:
            continue
        if (old.rule_id, old.asset_id) not in live_keys and \
                (old.workflow or "open") not in ("resolved", "false_positive"):
            old.workflow = "resolved"
            old.resolution_reason = ("reassessed by architecture checks: "
                                    "structure no longer fails")
            resolved_stale += 1

    db.add(AuditEvent(actor=actor, action="arch_checks_raised",
                      detail=(f"run={run.id} rules={len(evaluated)} hits={len(hits)} "
                              f"created={created} reopened={reopened} "
                              f"resolved_stale={resolved_stale}")))
    db.commit()
    return {"run_id": run.id, "rule_version": f"arch-{rules.ARCH_RULE_VERSION}",
            "hit_count": len(hits), "created": created, "reopened": reopened,
            "resolved_stale": resolved_stale, "findings": emitted}
