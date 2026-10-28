"""Deterministic security-review builder for the API and MCP server.

The review is assembled only from stored records: assets, findings, risk
scores, assessment results and recovery criteria. It does not invent a
vulnerability or claim that a control passed without evidence.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from app.models.models import (
    AssessmentResult,
    AssessmentRun,
    Asset,
    AssetRelationship,
    Finding,
    RiskAssessment,
    Service,
)
from app import detection

DONE = {"resolved", "false_positive"}
SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "moderate": 3, "low": 2, "info": 1}


def _open_finding(row: Finding, risk: RiskAssessment | None) -> Dict[str, Any]:
    return {
        "id": row.id,
        "rule_id": row.rule_id,
        "asset_id": row.asset_id,
        "severity": row.severity,
        "detail": row.detail,
        "workflow": row.workflow or "open",
        "source": ("vulnerability" if str(row.rule_id).startswith("CVE-") else "configuration"),
        "score": round(risk.score, 1) if risk else 0,
        "priority": risk.priority if risk else "Informational",
    }


def _readiness(db: Session) -> List[Dict[str, Any]]:
    out = []
    for service in db.query(Service).order_by(Service.id).all():
        deps = (db.query(AssetRelationship)
                .filter(AssetRelationship.source_type == "asset",
                        AssetRelationship.target_type == "service",
                        AssetRelationship.target_id == service.id).all())
        criteria = {
            "recovery_procedure": bool((service.recovery_procedure or "").strip()),
            "backup_dependency": len(deps) > 0,
            "rto_configured": (service.rto_minutes or 0) > 0,
        }
        failed = [key for key, ok in criteria.items() if not ok]
        out.append({"service_id": service.id, "service": service.name,
                    "rto_minutes": service.rto_minutes, "criteria": criteria,
                    "ready": not failed, "failed_criteria": failed})
    return out


def _recommendations(open_rows: List[Dict[str, Any]], readiness: List[Dict[str, Any]],
                     coverage: Dict[str, Any]) -> List[str]:
    recs: List[str] = []
    cves = [f for f in open_rows if f["source"] == "vulnerability"]
    if cves:
        top = ", ".join(sorted({f["rule_id"] for f in cves})[:3])
        recs.append(f"Patch or mitigate the highest-risk vulnerable software first ({top}); "
                    "verify the installed version after the change.")
    if any(f["rule_id"].startswith("BG-ID") for f in open_rows):
        recs.append("Reduce privileged access: enforce MFA, remove shared admin accounts and "
                    "review dormant administrator identities.")
    if any(f["rule_id"].startswith("BG-ASSET-004") or f["rule_id"].startswith("BG-ASSET-005")
           for f in open_rows):
        recs.append("Restrict remote administration and ingress to the documented management "
                    "network; remove any-address firewall rules.")
    if any(f["rule_id"].startswith("BG-BKP") for f in open_rows):
        recs.append("Repair backup coverage and run a restore test; an untested backup is not "
                    "evidence that recovery works.")
    not_ready = [r["service"] for r in readiness if not r["ready"]]
    if not_ready:
        recs.append("Complete recovery documentation and dependencies for: " + ", ".join(not_ready) + ".")
    if coverage.get("assets_stale", 0) or coverage.get("assets_never", 0):
        recs.append("Collect fresh evidence from assets with stale or missing records before "
                    "treating the posture as current.")
    if not recs:
        recs.append("No open findings were recorded. Continue scheduled detection and recovery testing.")
    return recs[:6]


def build_review(db: Session, focus: str = "all", audience: str = "technical") -> Dict[str, Any]:
    assets = db.query(Asset).filter(Asset.retired == 0).order_by(Asset.id).all()
    asset_by_id = {str(a.id): a for a in assets}
    risks = {r.finding_id: r for r in db.query(RiskAssessment).all()}
    rows: List[Dict[str, Any]] = []
    for finding in db.query(Finding).order_by(Finding.id).all():
        if (finding.workflow or "open") in DONE:
            continue
        if str(finding.asset_id) not in asset_by_id:
            continue  # retired or deleted asset
        rows.append(_open_finding(finding, risks.get(f"{finding.rule_id}:{finding.asset_id}")))
    rows.sort(key=lambda f: (SEV_RANK.get(str(f["severity"]).lower(), 0), f["score"]), reverse=True)

    for row in rows:
        asset = asset_by_id.get(str(row["asset_id"]))
        row["asset_name"] = (asset.hostname or asset.name) if asset else f"asset {row['asset_id']}"
        row["asset_kind"] = asset.kind if asset else "unknown"

    focus_text = (focus or "all").strip().lower()
    focused = rows
    if focus_text not in ("", "all", "estate"):
        focused = [f for f in rows
                   if focus_text in f["rule_id"].lower()
                   or focus_text in f["asset_kind"].lower()
                   or focus_text in str(f["detail"]).lower()
                   or (focus_text in ("cve", "vulnerability", "vulnerabilities")
                       and f["source"] == "vulnerability")]

    latest = db.query(AssessmentRun).order_by(AssessmentRun.id.desc()).first()
    results = (db.query(AssessmentResult)
               .filter(AssessmentResult.run_id == latest.id).all() if latest else [])
    outcomes = {"PASS": 0, "FAIL": 0, "UNKNOWN": 0, "NOT_APPLICABLE": 0}
    for result in results:
        outcomes[result.outcome] = outcomes.get(result.outcome, 0) + 1
    coverage = detection.posture(db)
    readiness = _readiness(db)
    cves = [f for f in rows if f["source"] == "vulnerability"]
    high = [f for f in rows if str(f["severity"]).lower() in ("critical", "high")]
    ready = sum(1 for r in readiness if r["ready"])
    recommendations = _recommendations(rows, readiness, coverage)

    summary = {
        "generated_at": time.time(),
        "focus": focus or "all",
        "audience": audience or "technical",
        "assets": len(assets),
        "open_findings": len(rows),
        "critical_high_findings": len(high),
        "known_vulnerabilities": len(cves),
        "critical_vulnerabilities": sum(1 for f in cves if str(f["severity"]).lower() == "critical"),
        "services_ready": f"{ready}/{len(readiness)}",
        "evidence_coverage": coverage.get("coverage", 0),
        "evidence_current": f"{coverage.get('assets_current', 0)}/{coverage.get('assets_total', 0)}",
        "latest_run": ({"id": latest.id, "started_at": latest.started_at,
                        "scope": getattr(latest, "scope", "all") or "all",
                        "outcomes": outcomes} if latest else None),
    }

    top = focused[:10]
    lines = [
        f"# CivicShield security review — {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}",
        "",
        f"**Scope:** {summary['assets']} active assets in a small municipal water utility. "
        f"**Focus:** {summary['focus']}. **Audience:** {summary['audience']}.",
        "",
        "## Executive summary",
        "",
        f"- **{summary['open_findings']}** open findings, including "
        f"**{summary['critical_high_findings']}** critical/high and "
        f"**{summary['known_vulnerabilities']}** known-vulnerability matches "
        f"({summary['critical_vulnerabilities']} critical).",
        f"- Essential-service recovery readiness: **{summary['services_ready']}** services meet the recorded criteria.",
        f"- Evidence coverage: **{summary['evidence_current']}** assets current"
        f"{' (stale records exist)' if coverage.get('assets_stale') else ''}.",
        "",
        "## Priority findings",
        "",
    ]
    if not top:
        lines.append("No open findings matched the requested focus.")
    else:
        lines += ["| Finding | Asset | Severity | Risk | Source |", "|---|---|---|---|---|"]
        for f in top:
            lines.append(f"| {f['rule_id']} | {f['asset_name']} | {f['severity']} | "
                         f"{f['priority']} ({f['score']}) | {f['source']} |")
        if audience != "executive":
            lines += ["", "Evidence detail:"]
            for f in top[:5]:
                lines.append(f"- `{f['rule_id']}` — {f['detail']}")

    lines += ["", "## Service readiness", ""]
    for r in readiness:
        state = "ready" if r["ready"] else "not ready"
        detail = "" if r["ready"] else f" (missing: {', '.join(r['failed_criteria'])})"
        lines.append(f"- **{r['service']}** — {state}{detail}; RTO {r['rto_minutes']} min.")

    lines += ["", "## Recommended next actions", ""]
    lines += [f"{i}. {rec}" for i, rec in enumerate(recommendations, 1)]

    lines += [
        "",
        "## Evidence and limitations",
        "",
        f"- Detection run: {('#' + str(latest.id) + ' · ' + time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(latest.started_at))) if latest else 'none recorded'}.",
        f"- Controls: {outcomes['PASS']} pass, {outcomes['FAIL']} fail, {outcomes['UNKNOWN']} unknown.",
        "- Vulnerability matches are version-based evidence, not proof of exploitability; verify vendor backports.",
        "- The bundled advisory set is a demo snapshot. This review does not claim that the estate is attack-proof.",
        "- No production changes were made by this review.",
    ]
    return {**summary, "top_findings": top, "recommendations": recommendations,
            "readiness": readiness, "limitations": (
                "Synthetic demo data; version matches require validation; missing evidence is UNKNOWN."),
            "markdown": "\n".join(lines)}
