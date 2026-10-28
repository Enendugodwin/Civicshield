"""CivicShield full backend API (SQLite default)."""
from __future__ import annotations

import csv
import io
import json
import re
import time
import uuid

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import Base, SessionLocal, engine, get_db
from app.models.models import (
    AITask,
    AssessmentResult,
    AssessmentRun,
    Asset,
    AssetRelationship,
    AuditEvent,
    BackupRecord,
    ChatMessage,
    Conversation,
    Finding,
    Incident,
    IncidentEvent,
    RiskAssessment,
    Service,
    ThreatIndicator,
)
from app.schemas.schemas import AssetOut, RelationshipOut, ServiceOut
from app import detection, review, vuln_intel

# Hoisted engine imports (Optimization: previously re-resolved per request,
# growing sys.path unboundedly on every assessment/recovery call).
import sys as _sys
from pathlib import Path as _Path

_HERE = _Path(__file__).resolve()
for _p in (_HERE.parents[2], _HERE.parents[1]):
    if str(_p) not in _sys.path:
        _sys.path.insert(0, str(_p))
import baseline_guard  # noqa: E402
import impact_engine  # noqa: E402
import recovery as _recovery_sim  # noqa: E402

Base.metadata.create_all(bind=engine)

# Lightweight additive migration for existing demo DBs (no-op when current).
def _ensure_columns():
    import sqlite3
    with sqlite3.connect(engine.url.database or "./civicshield.db") as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(findings)").fetchall()}
        for name, ddl in (("workflow", "TEXT DEFAULT 'open'"), ("assignee", "TEXT DEFAULT ''"),
                          ("resolution_reason", "TEXT DEFAULT ''")):
            if name not in cols:
                conn.execute(f"ALTER TABLE findings ADD COLUMN {name} {ddl}")
        icols = {r[1] for r in conn.execute("PRAGMA table_info(incidents)").fetchall()}
        for name, ddl in (("severity", "TEXT DEFAULT 'medium'"), ("commander", "TEXT DEFAULT ''")):
            if name not in icols:
                conn.execute(f"ALTER TABLE incidents ADD COLUMN {name} {ddl}")
        rcols = {r[1] for r in conn.execute("PRAGMA table_info(assessment_runs)").fetchall()}
        if rcols and "scope" not in rcols:
            conn.execute("ALTER TABLE assessment_runs ADD COLUMN scope TEXT DEFAULT 'all'")
        conn.commit()

try:
    _ensure_columns()
except Exception:
    pass

app = FastAPI(title="CivicShield")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Role"],
)

try:
    from app.fixpilot_router import router as fixpilot_router
    app.include_router(fixpilot_router)
except Exception:
    pass


def role_of(authorization: str | None = None, x_role: str | None = None) -> str:
    from app.security import role_of as _role_of
    return _role_of(authorization, x_role)


def require_role(minimum: str, role: str):
    from app.security import require_role as _require_role
    _require_role(minimum, role)


@app.get("/api/me")
def api_me(authorization: str | None = Header(default=None),
           x_role: str | None = Header(default=None)):
    """Demo account descriptor. This is a role header, not real authentication."""
    role = role_of(authorization, x_role)
    can = {
        "viewer": ["read"],
        "operator": ["read", "assess", "detect", "workflow", "recovery", "remediation"],
        "admin": ["read", "assess", "detect", "workflow", "recovery", "remediation",
                  "retire_assets", "reset_demo", "manage_access"],
    }[role]
    return {"username": "Demo Owner", "role": role, "permissions": can,
            "demo": True,
            "note": "Demo role header. Production deployments must use authenticated accounts."}


def audit(db: Session, actor: str, action: str, detail: str = ""):
    db.add(AuditEvent(actor=actor, action=action, detail=detail[:2000]))
    db.commit()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/health")
def api_health():
    try:
        from app.ai import ai_service
        ai = ai_service.status()
    except Exception:
        ai = {"mode": "offline-fallback", "model_available": False}
    return {"status": "ok", "ai": {"available": bool(ai.get("model_available")), "mode": ai.get("mode", "offline-fallback")}}

# ---- assets ----
class AssetIn(BaseModel):
    name: str = Field(min_length=1)
    kind: str = "server"
    hostname: str = ""
    owner: str = ""
    os_name: str = ""
    environment: str = "production"
    zone: str = "central"
    criticality: str = "low"
    criticality_reason: str = ""
    status: str = "operational"
    evidence_json: str = "{}"


@app.get("/api/assets", response_model=list[AssetOut])
def api_assets(db: Session = Depends(get_db)):
    rows = db.query(Asset).filter(Asset.retired == 0).order_by(Asset.id).all()
    return [AssetOut(id=r.id, name=r.name, kind=r.kind, zone=r.zone, status=r.status,
                      hostname=r.hostname or "", owner=r.owner or "", criticality=r.criticality or "low") for r in rows]


@app.get("/assets", response_model=list[AssetOut])
def legacy_assets(db: Session = Depends(get_db)):
    return api_assets(db)


@app.get("/services", response_model=list[ServiceOut])
def legacy_services(db: Session = Depends(get_db)):
    return api_services(db)


@app.get("/relationships", response_model=list[RelationshipOut])
def legacy_relationships(db: Session = Depends(get_db)):
    return api_relationships(db)


@app.get("/api/assets/{asset_id}")
def api_asset_one(asset_id: int, db: Session = Depends(get_db)):
    r = db.query(Asset).filter(Asset.id == asset_id).first()
    if not r:
        raise HTTPException(404, "asset not found")
    rels = db.query(AssetRelationship).filter(
        ((AssetRelationship.source_id == asset_id) | (AssetRelationship.target_id == asset_id))
    ).all()
    return {"id": r.id, "name": r.name, "kind": r.kind, "hostname": r.hostname, "owner": r.owner,
            "os_name": r.os_name, "environment": r.environment, "zone": r.zone,
            "criticality": r.criticality, "criticality_reason": r.criticality_reason,
            "status": r.status, "evidence": json.loads(r.evidence_json or "{}"),
            "relationships": [{"id": x.id, "source_type": x.source_type, "source_id": x.source_id,
                               "target_type": x.target_type, "target_id": x.target_id, "rel": x.rel} for x in rels]}


@app.post("/api/assets", status_code=201)
def api_asset_create(body: AssetIn, db: Session = Depends(get_db),
                     authorization: str | None = Header(default=None), x_role: str | None = Header(default=None)):
    require_role("operator", role_of(authorization, x_role))
    r = Asset(**body.model_dump())
    db.add(r)
    db.commit()
    db.refresh(r)
    audit(db, role_of(authorization, x_role), "asset_created", f"id={r.id}")
    return {"id": r.id}


@app.patch("/api/assets/{asset_id}")
def api_asset_patch(asset_id: int, body: dict, db: Session = Depends(get_db),
                    authorization: str | None = Header(default=None), x_role: str | None = Header(default=None)):
    require_role("operator", role_of(authorization, x_role))
    r = db.query(Asset).filter(Asset.id == asset_id).first()
    if not r:
        raise HTTPException(404, "asset not found")
    # "retired" is admin-only (DELETE endpoint); "evidence_json" is written
    # only through the validated collector endpoint below. Allowing either
    # here would let an operator bypass retirement policy or forge evidence
    # that makes future rules evaluate to PASS.
    allowed = {"name", "kind", "hostname", "owner", "os_name", "environment", "zone",
               "criticality", "criticality_reason", "status"}
    for k, v in body.items():
        if k in allowed:
            if isinstance(v, str) and len(v) > 120:
                raise HTTPException(422, f"{k} too long (max 120 chars)")
            setattr(r, k, v)
    r.updated_at = time.time()
    db.commit()
    audit(db, role_of(authorization, x_role), "asset_updated", f"id={asset_id}")
    return {"id": asset_id}


@app.delete("/api/assets/{asset_id}")
def api_asset_delete(asset_id: int, db: Session = Depends(get_db),
                     authorization: str | None = Header(default=None), x_role: str | None = Header(default=None)):
    require_role("admin", role_of(authorization, x_role))
    r = db.query(Asset).filter(Asset.id == asset_id).first()
    if not r:
        raise HTTPException(404, "asset not found")
    r.retired = 1
    db.commit()
    audit(db, "admin", "asset_retired", f"id={asset_id}")
    return {"id": asset_id, "retired": True}


@app.get("/api/services", response_model=list[ServiceOut])
def api_services(db: Session = Depends(get_db)):
    rows = db.query(Service).order_by(Service.id).all()
    return [ServiceOut(id=r.id, name=r.name, zone=r.zone, population_served=r.population_served) for r in rows]


@app.get("/api/relationships", response_model=list[RelationshipOut])
def api_relationships(db: Session = Depends(get_db)):
    rows = db.query(AssetRelationship).order_by(AssetRelationship.id).all()
    return [RelationshipOut(id=r.id, source_type=r.source_type, source_id=r.source_id,
                            target_type=r.target_type, target_id=r.target_id, rel=r.rel) for r in rows]


class RelationshipIn(BaseModel):
    source_type: str = "asset"
    source_id: int = 0
    target_type: str = "asset"
    target_id: int = 0
    rel: str = Field(min_length=1)


@app.post("/api/relationships", status_code=201)
def api_relationship_create(body: RelationshipIn, db: Session = Depends(get_db),
                            authorization: str | None = Header(default=None), x_role: str | None = Header(default=None)):
    require_role("operator", role_of(authorization, x_role))
    if body.source_type not in ("asset", "service") or body.target_type not in ("asset", "service"):
        raise HTTPException(422, "source/target type must be asset or service")
    for side, kind, rid in (("source", body.source_type, body.source_id),
                            ("target", body.target_type, body.target_id)):
        exists = (db.query(Asset).filter(Asset.id == rid).first() if kind == "asset"
                  else db.query(Service).filter(Service.id == rid).first())
        if not exists:
            raise HTTPException(404, f"{side} {kind} {rid} not found")
    if db.query(AssetRelationship).filter(
            AssetRelationship.source_type == body.source_type, AssetRelationship.source_id == body.source_id,
            AssetRelationship.target_type == body.target_type, AssetRelationship.target_id == body.target_id,
            AssetRelationship.rel == body.rel).first():
        raise HTTPException(409, "relationship already exists")
    r = AssetRelationship(**body.model_dump(), source_note="verified", confidence="high")
    db.add(r)
    db.commit()
    db.refresh(r)
    audit(db, role_of(authorization, x_role), "relationship_created", f"id={r.id}")
    return {"id": r.id}


@app.delete("/api/relationships/{rid}")
def api_relationship_delete(rid: int, db: Session = Depends(get_db),
                            authorization: str | None = Header(default=None), x_role: str | None = Header(default=None)):
    require_role("operator", role_of(authorization, x_role))
    r = db.query(AssetRelationship).filter(AssetRelationship.id == rid).first()
    if not r:
        raise HTTPException(404, "relationship not found")
    db.delete(r)
    db.commit()
    audit(db, role_of(authorization, x_role), "relationship_deleted", f"id={rid}")
    return {"id": rid, "deleted": True}


CSV_COLUMNS = ["name", "kind", "hostname", "owner", "os_name", "environment",
               "zone", "criticality", "criticality_reason", "status"]


class CsvImportIn(BaseModel):
    csv_text: str = Field(min_length=1)
    dry_run: bool = True


@app.post("/api/assets/import")
def api_assets_import(body: CsvImportIn, db: Session = Depends(get_db),
                      authorization: str | None = Header(default=None), x_role: str | None = Header(default=None)):
    """CSV import with validation. dry_run=true previews without writing."""
    require_role("operator", role_of(authorization, x_role))
    if len(body.csv_text.encode()) > 256 * 1024:
        raise HTTPException(413, "CSV exceeds 256 KB limit")
    try:
        reader = csv.DictReader(io.StringIO(body.csv_text))
        headers = [h.strip() if h else "" for h in (reader.fieldnames or [])]
    except Exception:
        raise HTTPException(422, "could not parse CSV header")
    if "name" not in headers:
        raise HTTPException(422, "CSV must include a 'name' column")
    rows, errors = [], []
    for i, raw in enumerate(reader, start=2):
        if i - 1 > 200:
            errors.append({"row": i, "error": "row limit of 200 exceeded; remaining rows ignored"})
            break
        row = {(k.strip() if k else ""): (v.strip() if isinstance(v, str) else v) for k, v in raw.items()}
        if not (row.get("name") or "").strip():
            errors.append({"row": i, "error": "name is required"})
            continue
        clean = {c: row.get(c, "") or "" for c in CSV_COLUMNS}
        if not clean["kind"]:
            clean["kind"] = "server"
        if not clean["zone"]:
            clean["zone"] = "central"
        if not clean["criticality"]:
            clean["criticality"] = "low"
        rows.append(clean)
    existing = {n for (n,) in db.query(Asset.name).all()}
    fresh, skipped = [], 0
    for clean in rows:
        if clean["name"] in existing:
            errors.append({"row": "?", "error": f"duplicate of existing asset '{clean['name']}' (skipped)"})
            skipped += 1
            continue
        existing.add(clean["name"])
        fresh.append(clean)
    created = []
    if not body.dry_run:
        for clean in fresh:
            a = Asset(**{**clean, "evidence_json": "{}"})
            db.add(a)
        db.commit()
        created = [a.id for a in db.query(Asset).order_by(Asset.id.desc()).limit(len(fresh)).all()][::-1]
        audit(db, role_of(authorization, x_role), "assets_imported", f"count={len(fresh)} skipped={skipped}")
    return {"valid": len(fresh), "errors": errors, "preview": fresh[:10], "created_ids": created}


# ---- assessments / findings / risk ----
@app.get("/api/risk/{fid}")
def api_risk_detail(fid: int, db: Session = Depends(get_db)):
    """Backend-calculated risk score with contributing factors (v1 model)."""
    f = db.query(Finding).filter(Finding.id == fid).first()
    if not f:
        raise HTTPException(404, "finding not found")
    rk = db.query(RiskAssessment).filter(RiskAssessment.finding_id == f"{f.rule_id}:{f.asset_id}").first()
    return {"finding_id": fid, "rule_id": f.rule_id, "asset_id": f.asset_id,
            "score": (rk.score if rk else 0), "priority": (rk.priority if rk else "Informational"),
            "factors": (json.loads(rk.factors_json) if rk and rk.factors_json else {}),
            "model": "impact-1.0", "weights": {"severity": 30, "criticality": 20, "exposure": 15,
            "confidence": 10, "exploitability": 10, "privilege": 5, "blast_radius": 5, "controls": 5}}


@app.get("/api/impact")
def api_impact(asset_id: str, db: Session = Depends(get_db)):
    """Direct + downstream service impact for a simulated asset failure."""
    edges, svc_of = impact_engine.split_relationships(db.query(AssetRelationship).all())
    seen = {asset_id}
    parent: dict[str, str] = {}
    queue = [asset_id]
    order = []
    while queue:
        node = queue.pop(0)
        order.append(node)
        for dep in edges.get(node, []):
            if dep not in seen:
                seen.add(dep)
                parent[dep] = node
                queue.append(dep)
    downstream = [a for a in order if a != asset_id]
    affected: dict[str, dict] = {}
    for sid, deps in svc_of.items():
        hit = [d for d in deps if d in seen]
        if hit:
            svc = db.query(Service).filter(Service.id == int(sid)).first() if sid.isdigit() else None
            chain = []
            d = hit[0]
            while d != asset_id:
                chain.append(d)
                d = parent.get(d, asset_id)
            chain.append(asset_id)
            affected[sid] = {"service_id": sid, "service": (svc.name if svc else sid),
                             "direct": hit, "path": list(reversed(chain))}
    return {"asset_id": asset_id, "downstream_assets": downstream,
            "affected_services": sorted(affected.values(), key=lambda x: x["service_id"]),
            "affected_service_count": len(affected),
            "note": "Services counted once by unique ID even when multiple assets support them."}


@app.get("/api/identity")
def api_identity(db: Session = Depends(get_db)):
    """Privileged-account inventory aggregated from asset evidence (read-only)."""
    accounts, known_mfa, total = [], 0, 0
    for a in db.query(Asset).filter(Asset.retired == 0).all():
        try:
            ident = json.loads(a.evidence_json or "{}").get("identity", {})
        except ValueError:
            continue
        for acct in ident.get("privileged_accounts", []):
            mfa = acct.get("mfa")
            entry = {"asset_id": a.id, "asset": a.hostname or a.name,
                     "account": acct.get("name", "unknown"),
                     "mfa": ("enabled" if mfa is True else ("disabled" if mfa is False else "unknown"))}
            if mfa is not None:
                total += 1
                known_mfa += 1 if mfa else 0
            accounts.append(entry)
    return {"accounts": accounts,
            "mfa_coverage": (round(known_mfa / total, 3) if total else None),
            "mfa_unknown": sum(1 for x in accounts if x["mfa"] == "unknown"),
            "note": "Missing MFA evidence is reported as unknown, never as disabled."}


class DetectIn(BaseModel):
    asset_ids: list[int] | None = None
    online: bool = False


class EvidenceIn(BaseModel):
    evidence: dict
    collected_at: float | None = None
    collector_version: str = ""
    source: str = "collector"
    run_detection: bool = False


@app.post("/api/assessments/run")
def api_assessment_run(db: Session = Depends(get_db)):
    """Full detection run: deterministic controls + known-vulnerability matching."""
    result = detection.run_detection(db, scope="all", actor="system")
    return {"run_id": result["run_id"], "findings": result["findings"],
            "summary": {k: result[k] for k in (
                "assets", "results", "outcomes", "vulnerabilities",
                "critical_vulnerabilities", "advisories", "warnings")}}


@app.post("/api/detect")
def api_detect(body: DetectIn | None = None, db: Session = Depends(get_db),
               authorization: str | None = Header(default=None),
               x_role: str | None = Header(default=None)):
    """Run detection for all assets or a selected set, with optional OSV enrichment."""
    body = body or DetectIn()
    return detection.run_detection(
        db, asset_ids=body.asset_ids, online=body.online,
        actor=role_of(authorization, x_role),
    )


@app.get("/api/detection/posture")
def api_detection_posture(db: Session = Depends(get_db)):
    """Evidence coverage, advisory snapshot and last detection run."""
    return detection.posture(db)


@app.post("/api/assets/{asset_id}/detect")
def api_asset_detect(asset_id: int, body: DetectIn | None = None, db: Session = Depends(get_db),
                     authorization: str | None = Header(default=None),
                     x_role: str | None = Header(default=None)):
    asset = db.query(Asset).filter(Asset.id == asset_id, Asset.retired == 0).first()
    if not asset:
        raise HTTPException(404, "asset not found")
    body = body or DetectIn()
    return detection.detect_one(db, asset_id, online=body.online,
                                actor=role_of(authorization, x_role))


@app.get("/api/assets/{asset_id}/evidence")
def api_asset_evidence_get(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id, Asset.retired == 0).first()
    if not asset:
        raise HTTPException(404, "asset not found")
    ev = detection._evidence(asset)
    return {"asset_id": asset.id, "name": asset.name, "hostname": asset.hostname or "",
            "evidence": ev, "meta": detection.evidence_meta(ev)}


@app.post("/api/assets/{asset_id}/evidence")
def api_asset_evidence_push(asset_id: int, body: EvidenceIn, db: Session = Depends(get_db),
                            authorization: str | None = Header(default=None),
                            x_role: str | None = Header(default=None)):
    """Accept read-only evidence from the CivicShield collector agent."""
    role = role_of(authorization, x_role)
    require_role("operator", role)
    asset = db.query(Asset).filter(Asset.id == asset_id, Asset.retired == 0).first()
    if not asset:
        raise HTTPException(404, "asset not found")
    if not isinstance(body.evidence, dict):
        raise HTTPException(422, "evidence must be an object")
    try:
        size = len(json.dumps(body.evidence))
    except (TypeError, ValueError):
        raise HTTPException(422, "evidence must be JSON-serialisable")
    if size > 512_000:
        raise HTTPException(413, "evidence payload too large (limit 512 KB)")
    evidence = dict(body.evidence)
    evidence["collector"] = {
        "source": (body.source or "collector")[:40],
        "version": (body.collector_version or "unknown")[:40],
        "collected_at": body.collected_at or time.time(),
        "hostname": evidence.get("hostname") or asset.hostname or "",
        "received_at": time.time(),
    }
    asset.evidence_json = json.dumps(evidence)
    asset.updated_at = time.time()
    db.commit()
    audit(db, role, "evidence_collected",
          f"asset={asset.id} source={evidence['collector']['source']} bytes={size} "
          f"software={len(vuln_intel.normalize_software(evidence))}")
    out = {"asset_id": asset.id, "collected_at": evidence["collector"]["collected_at"],
           "bytes": size, "accepted_keys": sorted(evidence.keys()),
           "software_count": len(vuln_intel.normalize_software(evidence))}
    if body.run_detection:
        out["detection"] = detection.detect_one(db, asset.id, actor=role)
    return out


@app.get("/api/assessments")
def api_assessments(db: Session = Depends(get_db)):
    return [{"id": r.id, "started_at": r.started_at, "rule_version": r.rule_version,
             "scope": getattr(r, "scope", "all") or "all", "status": r.status}
            for r in db.query(AssessmentRun).order_by(AssessmentRun.id).all()]


@app.get("/api/assessments/{run_id}")
def api_assessment_one(run_id: int, db: Session = Depends(get_db)):
    rows = db.query(AssessmentResult).filter(AssessmentResult.run_id == run_id).all()
    return [{"rule_id": r.rule_id, "asset_id": r.asset_id, "outcome": r.outcome,
             "severity": r.severity, "evidence_ref": r.evidence_ref,
             "source": ("vulnerability" if str(r.rule_id).startswith("CVE-") else "configuration")}
            for r in rows]


@app.get("/api/findings")
def api_findings(db: Session = Depends(get_db)):
    risks = {r.finding_id: r for r in db.query(RiskAssessment).all()}
    out = []
    for f in db.query(Finding).order_by(Finding.id).all():
        key = f"{f.rule_id}:{f.asset_id}"
        rk = risks.get(key)
        out.append({"id": f.id, "rule_id": f.rule_id, "asset_id": f.asset_id, "severity": f.severity,
                    "status": f.status, "detail": f.detail, "workflow": f.workflow or "open",
                    "assignee": f.assignee or "",
                    "source": ("vulnerability" if str(f.rule_id).startswith("CVE-") else "configuration"),
                    "score": (rk.score if rk else 0), "priority": (rk.priority if rk else "Informational")})
    return out


class FindingPatch(BaseModel):
    workflow: str = Field(min_length=1)
    assignee: str = ""
    reason: str = ""


@app.patch("/api/findings/{fid}")
def api_finding_patch(fid: int, body: FindingPatch, db: Session = Depends(get_db),
                      authorization: str | None = Header(default=None), x_role: str | None = Header(default=None)):
    """Acknowledge, assign, investigate, resolve, or mark false positive â€” with a recorded reason."""
    require_role("operator", role_of(authorization, x_role))
    f = db.query(Finding).filter(Finding.id == fid).first()
    if not f:
        raise HTTPException(404, "finding not found")
    if body.workflow not in ("open", "acknowledged", "investigating", "resolved", "false_positive"):
        raise HTTPException(422, "unknown workflow state")
    if body.workflow in ("resolved", "false_positive") and not body.reason.strip():
        raise HTTPException(422, "resolving or dismissing a finding requires a reason")
    f.workflow, f.assignee, f.resolution_reason = body.workflow, body.assignee, body.reason[:2000]
    db.commit()
    audit(db, role_of(authorization, x_role), "finding_workflow",
          f"id={fid} workflow={body.workflow} assignee={body.assignee} reason={body.reason[:200]}")
    return {"id": fid, "workflow": f.workflow, "assignee": f.assignee}


@app.get("/api/findings/{fid}")
def api_finding_one(fid: int, db: Session = Depends(get_db)):
    f = db.query(Finding).filter(Finding.id == fid).first()
    if not f:
        raise HTTPException(404, "finding not found")
    return {"id": f.id, "rule_id": f.rule_id, "asset_id": f.asset_id, "severity": f.severity,
            "status": f.status, "detail": f.detail}


@app.post("/api/findings/{fid}/explain")
def api_explain(fid: int, db: Session = Depends(get_db)):
    f = db.query(Finding).filter(Finding.id == fid).first()
    if not f:
        raise HTTPException(404, "finding not found")
    try:
        from app.ai import ai_service
        from app.ai.schemas import FindingContext
        plan = ai_service.generate_remediation(FindingContext(finding_id=str(f.id), rule_id=f.rule_id,
                                                              title=f.rule_id, severity=f.severity,
                                                              asset_id=str(f.asset_id), evidence=[f.detail]))
        return {"finding_id": str(f.id), "explanation": plan.plain_language, "model_used": plan.model_used}
    except Exception as e:
        return {"finding_id": str(f.id), "explanation": f"{f.rule_id}: {f.detail}", "model_used": "fallback"}


@app.post("/api/findings/{fid}/remediation-plan")
def api_remediation_plan(fid: int, db: Session = Depends(get_db)):
    f = db.query(Finding).filter(Finding.id == fid).first()
    if not f:
        raise HTTPException(404, "finding not found")
    try:
        from app.ai import ai_service
        from app.ai.schemas import FindingContext
        plan = ai_service.generate_remediation(FindingContext(finding_id=str(f.id), rule_id=f.rule_id,
                                                              title=f.rule_id, severity=f.severity,
                                                              asset_id=str(f.asset_id), evidence=[f.detail]))
        return plan.model_dump()
    except Exception:
        # Schema-validated offline fallback: never return a hand-built dict
        # missing required plan fields.
        from app.ai.deterministic_fallback import fallback_plan
        from app.ai.schemas import FindingContext as Ctx
        return fallback_plan(Ctx(finding_id=str(f.id), rule_id=f.rule_id,
                                 title=f.rule_id, severity=f.severity,
                                 asset_id=str(f.asset_id),
                                 evidence=[f.detail] if f.detail else [])).model_dump()


# ---- remediation lifecycle lives in app.fixpilot_router (single API) ----
# Finding-scoped helpers (explain + remediation-plan preview) stay here because
# the MCP server and the Findings page use them directly.


# ---- recovery ----
class ScenarioIn(BaseModel):
    scenario_id: str = "app-outage"


SCENARIO_DEFS = {
    "app-loss": {"name": "Loss of application server", "failed_assets": ["4"]},
    "privilege-compromise": {"name": "Privileged account compromise", "failed_assets": ["1"]},
    "ransomware-sim": {"name": "Simulated ransomware (non-production)", "failed_assets": ["5"]},
    "gateway-loss": {"name": "Network gateway failure", "failed_assets": ["6"]},
    "monitoring-loss": {"name": "Loss of monitoring visibility", "failed_assets": ["9"]},
    "backup-loss": {"name": "Backup server unavailable", "failed_assets": ["7"]},
    "dual-failure": {"name": "Simultaneous failure of two dependent components", "failed_assets": ["4", "5"]},
}


@app.post("/api/recovery/scenarios")
def api_recovery_scenarios():
    return [{"id": sid, **spec} for sid, spec in SCENARIO_DEFS.items()]


@app.get("/api/recovery/readiness")
def api_recovery_readiness(db: Session = Depends(get_db)):
    return {"services": review.service_readiness(db),
            "note": "A service without a documented procedure, backup dependency, or RTO is not shown as ready."}


@app.post("/api/recovery/runs")
def api_recovery_run(body: ScenarioIn, db: Session = Depends(get_db)):
    sim = _recovery_sim
    spec = SCENARIO_DEFS.get(body.scenario_id)
    if not spec:
        raise HTTPException(404, "unknown scenario")
    graph, svc_deps = impact_engine.split_relationships(db.query(AssetRelationship).all())
    affected: set[str] = set()
    for fa in spec["failed_assets"]:
        affected.add(fa)
        affected.update(sim.dependents(graph, fa))
    order = sim.restoration_order(graph, sorted(affected))
    backups = {b.asset_id: bool(b.immutable_backup) for b in db.query(BackupRecord).all()}
    svc_names = {str(s.id): s.name for s in db.query(Service).all()}
    affected_services = sorted(sid for sid, deps in svc_deps.items() if any(d in affected for d in deps))
    steps = sim.plan_steps(order, backups)
    done: dict[str, str] = {}
    ok = fail = 0
    for st in steps:
        sim.verify_step(st, done, backups)
        done[st.id] = st.status
        ok, fail = ok + (st.status == "success"), fail + (st.status != "success")
    rto = {str(s.id): (s.rto_minutes or 240) for s in db.query(Service).all()}
    total = sum(s.est_minutes for s in steps)
    res = {"scenario": {"id": body.scenario_id, "name": spec["name"], "failed_assets": spec["failed_assets"]},
           "order": order, "affected_assets": sorted(affected),
           "affected_services": [svc_names.get(sid, sid) for sid in affected_services],
           "steps": [{"id": s.id, "asset": s.asset, "action": s.action, "status": s.status,
                      "note": s.note, "est_minutes": s.est_minutes} for s in steps],
           "metrics": {"scenario": body.scenario_id, "affected_assets": len(affected),
                       "affected_services": len(affected_services), "dependencies_required": len(order),
                       "backups_available": sum(1 for a in order if backups.get(a)),
                       "steps_success": ok, "steps_failed": fail, "simulated_minutes": total,
                       "blockers": [s.id for s in steps if s.status != "success"],
                       "rto_met": {svc_names.get(sid, sid): total <= rto.get(sid, 240) for sid in affected_services}}}
    from app.models.models import RecoveryRun as RR
    row = RR(scenario_id=body.scenario_id, result_json=json.dumps(res))
    db.add(row)
    db.commit()
    db.refresh(row)
    audit(db, "operator", "recovery_run", f"scenario={body.scenario_id}")
    return {"run_id": row.id, **res}


@app.get("/api/recovery/runs/{run_id}")
def api_recovery_one(run_id: int, db: Session = Depends(get_db)):
    from app.models.models import RecoveryRun as RR
    r = db.query(RR).filter(RR.id == run_id).first()
    if not r:
        raise HTTPException(404, "run not found")
    return {"run_id": r.id, "result": json.loads(r.result_json)}


@app.post("/api/recovery/runs/{run_id}/recommendations")
def api_recovery_recommendations(run_id: int, db: Session = Depends(get_db),
                                 authorization: str | None = Header(default=None),
                                 x_role: str | None = Header(default=None)):
    """AI-assisted remediation for assets taken down in a recovery scenario.

    For each scenario failed asset (plus any non-success step asset) with open
    findings, generates and stores one FixPilot plan (cap 5 plans per call).
    Assets without findings are reported honestly instead of inventing
    recommendations.
    """
    require_role("operator", role_of(authorization, x_role))
    _check_rate("recovery:recommendations")
    import uuid
    from app.ai import ai_service
    from app.ai.schemas import FindingContext
    from app.fixpilot_store import PlanRecord, save_plan
    from app.models.models import RecoveryRun as RR
    r = db.query(RR).filter(RR.id == run_id).first()
    if not r:
        raise HTTPException(404, "run not found")
    res = json.loads(r.result_json)
    steps = {str(s.get("asset") or ""): s for s in res.get("steps", [])}
    targets = list(dict.fromkeys(
        [str(a) for a in res.get("scenario", {}).get("failed_assets", [])]
        + [aid for aid, s in steps.items() if s.get("status") != "success"]))
    names = {str(a.id): (a.name or "") for a in db.query(Asset).all()}
    recs: list = []
    planned = 0
    for aid in targets:
        s = steps.get(aid, {})
        base = {"asset_id": aid, "asset_name": names.get(aid, aid),
                "step_id": s.get("id", ""), "step_status": s.get("status", ""),
                "step_note": s.get("note", ""), "finding_id": None,
                "plan_id": None, "status": "no_findings"}
        if planned >= 5:
            base["note"] = "Plan cap reached (5); review the remaining findings manually."
            recs.append(base)
            continue
        f = (db.query(Finding)
             .filter(Finding.asset_id == aid,
                     ~Finding.workflow.in_(("resolved", "false_positive")))
             .order_by(Finding.id).first())
        if f is None:
            base["note"] = ("No open findings recorded for this asset - run evidence "
                            "collection/detection first; no recommendation invented.")
            recs.append(base)
            continue
        plan = ai_service.generate_remediation(FindingContext(
            finding_id=str(f.id), rule_id=f.rule_id or "UNKNOWN",
            title=f.rule_id or "", severity=f.severity or "unknown",
            asset_id=str(f.asset_id or ""),
            evidence=[f.detail or "",
                      f"recovery step {s.get('id', '')}: {s.get('note', '')}"]))
        rec = save_plan(PlanRecord(id=f"plan-{uuid.uuid4().hex[:8]}",
                                   finding_id=str(f.id), payload=plan.model_dump()))
        planned += 1
        base.update({"finding_id": f.id, "rule_id": f.rule_id, "plan_id": rec.id,
                     "status": "planned",
                     "plain_language": rec.payload.get("plain_language", ""),
                     "corrective_action": rec.payload.get("corrective_action", ""),
                     "model_used": rec.payload.get("model_used", "unknown"),
                     "note": ""})
        recs.append(base)
    return {"run_id": run_id, "recommendations": recs}


# ---- incidents / threat intel / audit / reports ----
class IncidentIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    severity: str = "medium"
    commander: str = Field(default="", max_length=120)


@app.post("/api/incidents", status_code=201)
def api_incident_create(body: IncidentIn, db: Session = Depends(get_db)):
    if body.severity not in ("critical", "high", "medium", "low"):
        raise HTTPException(422, "unknown severity")
    r = Incident(title=body.title, severity=body.severity, commander=body.commander)
    db.add(r)
    db.commit()
    db.refresh(r)
    audit(db, "operator", "incident_created", f"id={r.id} severity={r.severity}")
    return {"id": r.id, "title": r.title, "severity": r.severity, "commander": r.commander}


@app.get("/api/incidents")
def api_incidents(db: Session = Depends(get_db)):
    return [{"id": r.id, "title": r.title, "status": r.status,
             "severity": r.severity or "medium", "commander": r.commander or ""} for r in db.query(Incident).all()]


CONTAINMENT_BY_CATEGORY = {
    "identity": ["Disable or scope the affected privileged accounts", "Force credential rotation on linked identities", "Require MFA before re-enabling access"],
    "asset": ["Restrict remote administration to the management network", "Tighten firewall ingress to required sources", "Disable unnecessary services on the host"],
    "endpoint": ["Verify endpoint protection is installed and current", "Confirm centralized logging captures the host", "Extend monitoring coverage before closing"],
    "backup": ["Verify an offline or immutable backup copy exists", "Run a recovery test and record the result", "Confirm the recovery procedure is documented"],
}


def _incident_or_404(db: Session, iid: int) -> Incident:
    r = db.query(Incident).filter(Incident.id == iid).first()
    if not r:
        raise HTTPException(404, "incident not found")
    return r


@app.get("/api/incidents/{iid}")
def api_incident_detail(iid: int, db: Session = Depends(get_db)):
    from app.models.models import IncidentFindingLink as Link
    inc = _incident_or_404(db, iid)
    events = db.query(IncidentEvent).filter(IncidentEvent.incident_id == iid).order_by(IncidentEvent.ts).all()
    links = db.query(Link).filter(Link.incident_id == iid).all()
    findings = []
    for lk in links:
        f = db.query(Finding).filter(Finding.id == lk.finding_id).first()
        if f:
            findings.append({"id": f.id, "rule_id": f.rule_id, "asset_id": f.asset_id,
                             "severity": f.severity, "status": f.status, "detail": f.detail})
    return {"id": inc.id, "title": inc.title, "status": inc.status,
            "severity": inc.severity or "medium", "commander": inc.commander or "",
            "events": [{"id": e.id, "ts": e.ts, "kind": e.kind, "detail": e.detail} for e in events],
            "findings": findings}


class IncidentPatch(BaseModel):
    status: str | None = None
    commander: str | None = Field(default=None, max_length=120)
    severity: str | None = None


@app.patch("/api/incidents/{iid}")
def api_incident_patch(iid: int, body: IncidentPatch, db: Session = Depends(get_db),
                       authorization: str | None = Header(default=None), x_role: str | None = Header(default=None)):
    require_role("operator", role_of(authorization, x_role))
    inc = _incident_or_404(db, iid)
    changes = []
    if body.status is not None:
        if body.status not in ("open", "contained", "resolved"):
            raise HTTPException(422, "status must be open, contained, or resolved")
        inc.status = body.status
        changes.append(f"status={body.status}")
    if body.commander is not None:
        inc.commander = body.commander
        changes.append(f"commander={body.commander}")
    if body.severity is not None:
        if body.severity not in ("critical", "high", "medium", "low"):
            raise HTTPException(422, "unknown severity")
        inc.severity = body.severity
        changes.append(f"severity={body.severity}")
    if not changes:
        raise HTTPException(422, "nothing to update")
    db.add(IncidentEvent(incident_id=iid, kind="decision", detail="Updated: " + ", ".join(changes)))
    db.commit()
    audit(db, role_of(authorization, x_role), "incident_status", f"id={iid} " + " ".join(changes))
    return {"id": iid, "status": inc.status, "severity": inc.severity, "commander": inc.commander}


class IncidentEventIn(BaseModel):
    kind: str = Field(default="observed")
    detail: str = Field(min_length=1)


@app.post("/api/incidents/{iid}/events", status_code=201)
def api_incident_event(iid: int, body: IncidentEventIn, db: Session = Depends(get_db),
                       authorization: str | None = Header(default=None), x_role: str | None = Header(default=None)):
    require_role("operator", role_of(authorization, x_role))
    _incident_or_404(db, iid)
    if body.kind not in ("observed", "interpretation", "suggestion", "decision", "evidence"):
        raise HTTPException(422, "kind must be observed, interpretation, suggestion, decision, or evidence")
    e = IncidentEvent(incident_id=iid, kind=body.kind, detail=body.detail[:2000])
    db.add(e)
    db.commit()
    db.refresh(e)
    return {"id": e.id, "ts": e.ts, "kind": e.kind, "detail": e.detail}


@app.post("/api/incidents/{iid}/findings/{fid}", status_code=201)
def api_incident_link(iid: int, fid: int, db: Session = Depends(get_db),
                      authorization: str | None = Header(default=None), x_role: str | None = Header(default=None)):
    from app.models.models import IncidentFindingLink as Link
    require_role("operator", role_of(authorization, x_role))
    _incident_or_404(db, iid)
    if not db.query(Finding).filter(Finding.id == fid).first():
        raise HTTPException(404, "finding not found")
    if db.query(Link).filter(Link.incident_id == iid, Link.finding_id == fid).first():
        raise HTTPException(409, "finding already linked")
    db.add(Link(incident_id=iid, finding_id=fid))
    db.commit()
    audit(db, role_of(authorization, x_role), "incident_link", f"incident={iid} finding={fid}")
    return {"incident_id": iid, "finding_id": fid}


@app.delete("/api/incidents/{iid}/findings/{fid}")
def api_incident_unlink(iid: int, fid: int, db: Session = Depends(get_db),
                        authorization: str | None = Header(default=None), x_role: str | None = Header(default=None)):
    from app.models.models import IncidentFindingLink as Link
    require_role("operator", role_of(authorization, x_role))
    lk = db.query(Link).filter(Link.incident_id == iid, Link.finding_id == fid).first()
    if not lk:
        raise HTTPException(404, "link not found")
    db.delete(lk)
    db.commit()
    return {"incident_id": iid, "finding_id": fid, "unlinked": True}


@app.post("/api/incidents/{iid}/summary")
def api_incident_summary(iid: int, db: Session = Depends(get_db)):
    """AI-assisted incident summary grounded in recorded events and linked findings."""
    detail = api_incident_detail(iid, db)
    facts = [f"{f['rule_id']} on asset {f['asset_id']} ({f['severity']})" for f in detail["findings"]]
    observed = [e["detail"] for e in detail["events"] if e["kind"] in ("observed", "evidence")]
    gaps = [] if detail.get("commander") else ["No commander assigned"]
    if any("BG-ID" in f["rule_id"] for f in detail["findings"]):
        gaps.append("Unknown MFA status on some linked identity evidence")
    try:
        from app.ai import ai_service
        from app.ai.schemas import FindingContext
        plan = ai_service.generate_remediation(FindingContext(
            finding_id=f"incident-{iid}", rule_id="INCIDENT-SUMMARY",
            title=detail["title"], severity=detail.get("severity", "medium"),
            asset_id="", evidence=observed + facts))
        summary, model = plan.plain_language, plan.model_used
    except Exception:
        summary = (f"Incident #{iid} '{detail['title']}' [{detail['status']}]: "
                   f"{len(detail['events'])} recorded events, {len(detail['findings'])} linked findings. " +
                   ("Key facts: " + "; ".join(facts) + ". " if facts else "No findings linked yet. "))
        model = "fallback"
    return {"incident_id": iid, "summary": summary, "model_used": model,
            "missing_evidence": gaps, "simulated": True,
            "note": "Summary only â€” timestamps and events are never invented."}


@app.get("/api/incidents/{iid}/report")
def api_incident_report(iid: int, db: Session = Depends(get_db)):
    """Structured incident report: status, timeline, linked findings, derived containment."""
    detail = api_incident_detail(iid, db)
    steps: list[str] = []
    for f in detail["findings"]:
        cat = "identity" if f["rule_id"].startswith("BG-ID") else (
            "endpoint" if f["rule_id"].startswith("BG-ENDP") else (
                "backup" if f["rule_id"].startswith("BG-BKP") else "asset"))
        for s in CONTAINMENT_BY_CATEGORY[cat]:
            if s not in steps:
                steps.append(s)
    decisions = [e["detail"] for e in detail["events"] if e["kind"] == "decision"]
    return {**detail, "containment": steps, "decisions": decisions,
            "synthetic_note": "Demo records are simulated; disruptive actions require human approval and never execute automatically."}


@app.get("/api/audit")
def api_audit(db: Session = Depends(get_db)):
    return [{"id": r.id, "actor": r.actor, "action": r.action, "detail": r.detail}
            for r in db.query(AuditEvent).order_by(AuditEvent.id.desc()).limit(200).all()]


@app.get("/api/assessments/{run_id}/export")
def api_assessment_export(run_id: int, format: str = "json", db: Session = Depends(get_db)):
    rows = db.query(AssessmentResult).filter(AssessmentResult.run_id == run_id).all()
    data = [{"rule_id": r.rule_id, "asset_id": r.asset_id, "outcome": r.outcome,
             "severity": r.severity, "evidence_ref": r.evidence_ref} for r in rows]
    if format == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["rule_id", "asset_id", "outcome", "severity"])
        for d in data:
            w.writerow([_csv_cell(d["rule_id"]), _csv_cell(d["asset_id"]), _csv_cell(d["outcome"]), _csv_cell(d["severity"])])
        return PlainTextResponse(buf.getvalue(), media_type="text/csv")
    return {"run_id": run_id, "results": data}


def _csv_cell(v: object) -> str:
    """Formula-injection guard: neutralize spreadsheet formulas in exported text."""
    s = "" if v is None else str(v)
    return ("'" + s) if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


@app.get("/api/review/posture")
def api_review_posture(focus: str = "all", audience: str = "technical",
                       db: Session = Depends(get_db)):
    """Evidence-grounded review for the dashboard and AI/MCP agents."""
    return review.build_review(db, focus=focus, audience=audience)


@app.get("/api/reports/posture")
def api_reports_posture(db: Session = Depends(get_db)):
    """Executive posture report: aggregate counts, top risks, readiness â€” with provenance metadata."""
    findings = api_findings(db)
    services = api_services(db)
    ready = api_recovery_readiness(db)["services"]
    top = sorted(findings, key=lambda f: f["score"], reverse=True)[:5]
    open_wf = sum(1 for f in findings if f.get("workflow") == "open")
    return {"report": "executive-posture", "generated_at": time.time(), "source": "civicshield-demo",
            "simulated": True,
            "assets": db.query(Asset).filter(Asset.retired == 0).count(),
            "findings_total": len(findings), "findings_open": open_wf,
            "services": [{"service": s.name, "zone": s.zone, "population_served": s.population_served} for s in services],
            "top_risks": [{"rule_id": f["rule_id"], "asset_id": f["asset_id"], "score": f["score"],
                           "priority": f["priority"], "workflow": f.get("workflow")} for f in top],
            "recovery_readiness": [{"service": s["service"], "ready": s["ready"],
                                    "failed_criteria": s["failed_criteria"]} for s in ready],
            "limitations": "Synthetic demo data. Scores are deterministic v1 model outputs, not CVSS."}


@app.get("/api/reports/threats")
def api_reports_threats(format: str = "json", db: Session = Depends(get_db)):
    """Threat exposure report: JSON by default, CSV with formula-guard (?format=csv)."""
    import csv
    import io
    from fastapi.responses import PlainTextResponse
    from app import vuln_intel
    advisories = []
    for adv in vuln_intel._advisories():
        confirmed, potential, unevaluated = _advisory_exposure(db, adv)
        advisories.append({
            "id": adv.id, "title": adv.title, "severity": adv.severity,
            "cvss": adv.cvss, "known_exploited": adv.known_exploited,
            "fixed": adv.fixed, "url": adv.url,
            "confirmed": confirmed, "potential": potential, "unevaluated": unevaluated,
        })
    if format == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["advisory_id", "title", "severity", "cvss", "known_exploited",
                    "match", "asset_id", "asset_name", "package", "version", "fixed", "url"])
        for adv in advisories:
            for match, entries in (("confirmed", adv["confirmed"]), ("potential", adv["potential"])):
                for e in entries:
                    w.writerow([_csv_cell(adv["id"]), _csv_cell(adv["title"]),
                                _csv_cell(adv["severity"]), adv["cvss"],
                                adv["known_exploited"], match,
                                _csv_cell(e["asset_id"]), _csv_cell(e["asset_name"]),
                                _csv_cell(e["package"]), _csv_cell(e["version"]),
                                _csv_cell(adv["fixed"]), _csv_cell(adv["url"])])
        return PlainTextResponse(buf.getvalue(), media_type="text/csv")
    if format != "json":
        raise HTTPException(422, "format must be json or csv")
    return {"generated_at": time.time(), "snapshot": vuln_intel.snapshot()["snapshot"],
            "source": "bundled", "advisories": advisories}


@app.get("/api/reports/{rtype}")
def api_reports(rtype: str, db: Session = Depends(get_db)):
    if rtype not in ("assessment", "recovery"):
        raise HTTPException(404, "unknown report type")
    if rtype == "assessment":
        rows = db.query(AssessmentResult).all()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["rule_id", "asset_id", "outcome", "severity"])
        for r in rows:
            w.writerow([_csv_cell(r.rule_id), _csv_cell(r.asset_id), _csv_cell(r.outcome), _csv_cell(r.severity)])
        return PlainTextResponse(buf.getvalue(), media_type="text/csv")
    from app.models.models import RecoveryRun as RR
    rows = db.query(RR).all()
    runs = []
    for r in rows:
        item = json.loads(r.result_json)
        item["run_id"] = r.id
        runs.append(item)
    return {"runs": runs}


class IndicatorIn(BaseModel):
    value: str = Field(min_length=1)
    kind: str = "domain"
    confidence: str = "medium"
    source: str = ""


@app.post("/api/threat-indicators", status_code=201)
def api_indicator_add(body: IndicatorIn, db: Session = Depends(get_db),
                      authorization: str | None = Header(default=None),
                      x_role: str | None = Header(default=None)):
    require_role("operator", role_of(authorization, x_role))
    if body.kind not in ("domain", "url", "hash", "campaign", "ip"):
        raise HTTPException(422, "kind must be domain, url, hash, campaign, or ip")
    if body.confidence not in ("low", "medium", "high"):
        raise HTTPException(422, "confidence must be low, medium, or high")
    if len(body.value) > 512 or len(body.source) > 120:
        raise HTTPException(422, "indicator value/source too long")
    if db.query(ThreatIndicator).filter(ThreatIndicator.value == body.value).first():
        raise HTTPException(409, "duplicate indicator")
    r = ThreatIndicator(**body.model_dump(), expires_at=time.time() + 90 * 86400)
    db.add(r)
    db.commit()
    return {"value": r.value}


@app.get("/api/threat-indicators")
def api_indicators(db: Session = Depends(get_db)):
    now = time.time()
    return [{"value": r.value, "kind": r.kind, "confidence": r.confidence, "source": r.source or "",
             "expired": r.expires_at < now, "expires_at": r.expires_at}
            for r in db.query(ThreatIndicator).all()]


_RATE_BUCKETS: dict = {}


def _check_rate(key: str, limit: int = 10, window: float = 60.0) -> None:
    """In-memory fixed-window rate limiter for expensive endpoints."""
    now = time.monotonic()
    count, start = _RATE_BUCKETS.get(key, (0, now))
    if now - start >= window:
        count, start = 0, now
    count += 1
    _RATE_BUCKETS[key] = (count, start)
    if count > limit:
        retry = int(window - (now - start)) + 1
        raise HTTPException(429, f"rate limit exceeded for {key}; retry in {retry}s",
                            headers={"Retry-After": str(retry)})


def _match_packages(adv, pkgs: list, aid: str, aname: str) -> tuple[list, list]:
    """Split declared packages into confirmed/potential matches for one advisory."""
    from app import vuln_intel
    confirmed, potential = [], []
    for p in pkgs:
        if not any(adv.matches_product(n) for n in (p["name"], p.get("package") or "")):
            continue
        entry = {"asset_id": aid, "asset_name": aname,
                 "package": p["name"], "version": p["version"]}
        if vuln_intel.satisfies(p["version"], adv.affected):
            confirmed.append(entry)
        else:
            potential.append(entry)
    return confirmed, potential


def _advisory_exposure(db: Session, adv) -> tuple[list, list, list]:
    """Correlate one bundled advisory with declared asset software.

    Returns (confirmed, potential, unevaluated). Confirmed = product matches
    and the declared version falls in the advisory affected range. Potential =
    product matches but no declared version can be evaluated. Unevaluated =
    the asset declares no software inventory at all.
    """
    from app import vuln_intel
    confirmed, potential, unevaluated = [], [], []
    for a in db.query(Asset).filter(Asset.retired == 0).all():
        aid, aname = str(a.id), a.name or ""
        pkgs = vuln_intel.normalize_software(detection._evidence(a))
        if not pkgs:
            unevaluated.append({"asset_id": aid, "asset_name": aname})
            continue
        c, p = _match_packages(adv, pkgs, aid, aname)
        confirmed.extend(c)
        potential.extend(p)
    return confirmed, potential, unevaluated


@app.get("/api/threats/exposure")
def api_threat_exposure(db: Session = Depends(get_db)):
    """Exposure of active assets to bundled threat advisories (offline-safe)."""
    from app import vuln_intel
    advisories = []
    for adv in vuln_intel._advisories():
        confirmed, potential, unevaluated = _advisory_exposure(db, adv)
        advisories.append({
            "id": adv.id, "title": adv.title, "severity": adv.severity,
            "cvss": adv.cvss, "known_exploited": adv.known_exploited,
            "fixed": adv.fixed, "url": adv.url, "limitation": adv.limitation,
            "recommended_action": (
                f"Upgrade {adv.product} to {adv.fixed} or later following the vendor "
                f"advisory. Compensating control until patched: {adv.limitation}"),
            "confirmed": confirmed, "potential": potential, "unevaluated": unevaluated,
        })
    return {"snapshot": vuln_intel.snapshot()["snapshot"], "source": "bundled",
            "advisories": advisories}


class ThreatAnalysisIn(BaseModel):
    advisory_id: str


@app.post("/api/threats/analysis", status_code=201)
def api_threat_analysis(body: ThreatAnalysisIn, db: Session = Depends(get_db),
                        authorization: str | None = Header(default=None),
                        x_role: str | None = Header(default=None)):
    """AI-assisted analysis of one advisory, grounded in exposure evidence.

    The plan is stored in the FixPilot queue (finding_id = advisory id) so it
    follows the normal approve -> simulate -> verify workflow.
    """
    require_role("operator", role_of(authorization, x_role))
    _check_rate("threats:analysis")
    import uuid
    from app import vuln_intel
    from app.ai import ai_service
    from app.ai.schemas import FindingContext
    from app.fixpilot_store import PlanRecord, save_plan
    adv = vuln_intel.advisory_for((body.advisory_id or "").strip())
    if adv is None:
        raise HTTPException(404, "unknown advisory")
    confirmed, potential, unevaluated = _advisory_exposure(db, adv)
    evidence = (
        [f"confirmed: {c['package']}@{c['version']} on {c['asset_name']} ({c['asset_id']})"
         for c in confirmed[:10]]
        + [f"potential: {p['package']} on {p['asset_name']} ({p['asset_id']})"
           for p in potential[:10]]
        + [f"advisory:{adv.source}", f"fixed:{adv.fixed}"]
    )
    if unevaluated:
        evidence.append(f"{len(unevaluated)} asset(s) have no software inventory; scope unconfirmed there")
    if not confirmed and not potential:
        evidence.append("No asset in inventory declares the affected product")
    plan = ai_service.generate_remediation(FindingContext(
        finding_id=adv.id, rule_id=adv.id, title=adv.title,
        severity=adv.severity, asset_id="",
        evidence=evidence,
        service_impact=(f"Confirmed on {len(confirmed)} asset(s), "
                        f"potential on {len(potential)} asset(s).")))
    rec = save_plan(PlanRecord(id=f"plan-{uuid.uuid4().hex[:8]}",
                               finding_id=adv.id, payload=plan.model_dump()))
    return {"plan_id": rec.id,
            "model_used": rec.payload.get("model_used", "unknown"),
            "plan": rec.payload}


@app.get("/api/assets/{asset_id}/threats")
def api_asset_threats(asset_id: int, db: Session = Depends(get_db)):
    """Advisories affecting one asset, with match evidence (confirmed/potential)."""
    from app import vuln_intel
    a = db.query(Asset).filter(Asset.id == asset_id, Asset.retired == 0).first()
    if not a:
        raise HTTPException(404, "asset not found")
    pkgs = vuln_intel.normalize_software(detection._evidence(a))
    matches = []
    for adv in vuln_intel._advisories():
        confirmed, potential = _match_packages(adv, pkgs, str(a.id), a.name or "")
        if confirmed or potential:
            matches.append({
                "id": adv.id, "title": adv.title, "severity": adv.severity,
                "cvss": adv.cvss, "known_exploited": adv.known_exploited,
                "fixed": adv.fixed, "url": adv.url,
                "recommended_action": (
                    f"Upgrade {adv.product} to {adv.fixed} or later following the vendor "
                    f"advisory. Compensating control until patched: {adv.limitation}"),
                "confirmed": confirmed, "potential": potential,
            })
    return {"asset_id": a.id, "asset_name": a.name or "", "hostname": a.hostname or "",
            "criticality": a.criticality or "",
            "software": pkgs, "inventory_empty": not pkgs,
            "inventory_note": ("No software inventory declared for this asset; exposure "
                               "cannot be evaluated." if not pkgs else ""),
            "matches": matches}


_SYNC_FILE = _Path(__file__).resolve().parent.parent / "data" / "threat_sync.json"


def _read_sync() -> dict:
    try:
        return json.loads(_SYNC_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_sync(record: dict) -> dict:
    _SYNC_FILE.parent.mkdir(parents=True, exist_ok=True)
    _SYNC_FILE.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


@app.get("/api/threats/sync-status")
def api_threat_sync_status():
    """Feed health: last controlled sync, bundled snapshot, OSV cache size."""
    from app import vuln_intel
    rec = _read_sync()
    try:
        cache_entries = len(vuln_intel._load_cache())
    except OSError:
        cache_entries = 0
    return {"last_sync": rec or None,
            "never_synced": not bool(rec),
            "bundled_snapshot": vuln_intel.snapshot()["snapshot"],
            "bundled_advisories": len(vuln_intel._advisories()),
            "osv_cache_entries": cache_entries,
            "setup_note": ("No live sync has run yet. Bundled advisories are always available; "
                           "POST /api/threats/sync (operator) refreshes OSV.dev data for "
                           "declared packages. Sync failures are recorded, never hidden.")}


@app.post("/api/threats/sync")
def api_threat_sync(db: Session = Depends(get_db),
                    authorization: str | None = Header(default=None),
                    x_role: str | None = Header(default=None)):
    """Controlled feed sync: OSV.dev refresh for declared software (cached, capped).

    Never touches assets; only enriches the local vulnerability cache. Failures
    are recorded in the sync record with ok=false.
    """
    require_role("operator", role_of(authorization, x_role))
    _check_rate("threats:sync", limit=5, window=300.0)
    import time as _time
    from app import vuln_intel
    started = _time.time()
    seen: dict = {}
    for a in db.query(Asset).filter(Asset.retired == 0).all():
        for p in vuln_intel.normalize_software(detection._evidence(a)):
            seen[(p.get("ecosystem") or "", p["name"], p["version"])] = p
    findings, warnings = vuln_intel.osv_query(list(seen.values()))
    record = {"started_at": started, "finished_at": _time.time(),
              "assets_scanned": db.query(Asset).filter(Asset.retired == 0).count(),
              "packages_queried": len(seen),
              "osv_findings": len(findings),
              "warnings": warnings,
              "ok": not warnings,
              "note": "" if not warnings else "OSV.dev unreachable or incomplete; bundled advisories still apply."}
    return _write_sync(record)


# ================= AI assistant (reommendations.md) =================
# Conversational, environment-grounded assistant. Deterministic intent router
# over real backend data; the live model only rephrases verified context and
# the offline template answers when the provider is unavailable. Write tools
# execute only after explicit approval and re-validated authorization.


_ASSIST_SUGGESTIONS = [
    "Give me an overview of my environment.",
    "Which assets require attention?",
    "Show me the latest critical findings.",
    "What threats affect my assets?",
    "Is recovery ready? Show the last run.",
    "What can I ask you to do?",
]


def _assist_actor(authorization, x_role) -> str:
    return role_of(authorization, x_role)


def _assist_get_conv(db: Session, cid: int, user: str) -> Conversation:
    conv = db.query(Conversation).filter(Conversation.id == cid,
                                        Conversation.user_id == user).first()
    if not conv:
        raise HTTPException(404, "conversation not found")
    return conv


def _assist_audit(db: Session, actor: str, action: str, detail: str = "") -> None:
    db.add(AuditEvent(actor=actor, action=action, detail=detail[:2000]))
    db.commit()


def _assist_msg(db: Session, cid: int, role: str, content: str, meta: dict | None = None) -> ChatMessage:
    m = ChatMessage(conversation_id=cid, role=role, content=content,
                    meta_json=json.dumps(meta or {}))
    db.add(m)
    conv = db.query(Conversation).filter(Conversation.id == cid).first()
    if conv:
        conv.updated_at = time.time()
    db.commit()
    db.refresh(m)
    return m


def _assist_last_asset(db: Session, conv: Conversation) -> int | None:
    try:
        return (json.loads(conv.summary or "{}") or {}).get("last_asset_id")
    except (ValueError, AttributeError):
        return None


def _assist_remember_asset(db: Session, conv: Conversation, aid: int) -> None:
    try:
        data = json.loads(conv.summary or "{}") or {}
    except ValueError:
        data = {}
    data["last_asset_id"] = aid
    conv.summary = json.dumps(data)
    db.commit()


def _assist_resolve_asset(db: Session, ref: str):
    """Resolve an asset reference to (asset, candidates). Never guesses."""
    ref = (ref or "").strip().strip("#")
    if not ref:
        return None, []
    if ref.isdigit():
        a = db.query(Asset).filter(Asset.id == int(ref), Asset.retired == 0).first()
        return (a, []) if a else (None, [])
    lowered = ref.lower()
    exact = db.query(Asset).filter(Asset.retired == 0).all()
    hosts = [a for a in exact if (a.hostname or "").lower() == lowered
             or (a.name or "").lower() == lowered]
    if len(hosts) == 1:
        return hosts[0], []
    if len(hosts) > 1:
        return None, hosts
    partial = [a for a in exact if lowered in (a.hostname or "").lower()
               or lowered in (a.name or "").lower()]
    if len(partial) == 1:
        return partial[0], []
    return None, partial


def _assist_open_findings(db: Session):
    return (db.query(Finding)
            .filter(~Finding.workflow.in_(("resolved", "false_positive")))
            .order_by(Finding.id).all())


# ---- read tools (viewer and above, execute immediately) ---------------------

def _tool_environment_overview(db: Session, args: dict) -> dict:
    assets = db.query(Asset).filter(Asset.retired == 0).all()
    findings = _assist_open_findings(db)
    crit = [f for f in findings if str(f.severity).lower() in ("critical", "high")]
    incidents = db.query(Incident).all()
    active_inc = [i for i in incidents if str(getattr(i, "status", "open")).lower() != "closed"]
    from app import vuln_intel
    confirmed = potential = 0
    for adv in vuln_intel._advisories():
        c, p, _u = _advisory_exposure(db, adv)
        confirmed += len(c)
        potential += len(p)
    degraded = [a for a in assets if str(a.status).lower() != "operational"]
    return {
        "assets": len(assets), "degraded_assets": [a.name or a.hostname for a in degraded[:10]],
        "open_findings": len(findings), "critical_high": len(crit),
        "incidents": len(incidents), "active_incidents": len(active_inc),
        "confirmed_exposure": confirmed, "potential_exposure": potential,
        "advisories": len(vuln_intel._advisories()),
    }


def _tool_search_assets(db: Session, args: dict) -> dict:
    q = str(args.get("query", "")).strip().lower()
    if not q:
        raise ValueError("query is required")
    assets = db.query(Asset).filter(Asset.retired == 0).all()
    hits = [a for a in assets if q in (a.name or "").lower()
            or q in (a.hostname or "").lower() or q in (a.kind or "").lower()
            or q in (a.zone or "").lower()][:20]
    return {"matches": [{"id": a.id, "name": a.name, "hostname": a.hostname,
                         "kind": a.kind, "status": a.status,
                         "criticality": a.criticality} for a in hits]}


def _tool_asset_details(db: Session, args: dict) -> dict:
    asset, candidates = _assist_resolve_asset(db, str(args.get("ref", "")))
    if asset is None:
        return {"asset": None,
                "candidates": [{"id": a.id, "name": a.name, "hostname": a.hostname}
                               for a in candidates[:8]]}
    ev = detection._evidence(asset)
    findings = (db.query(Finding).filter(Finding.asset_id == str(asset.id)).all())
    rels = (db.query(AssetRelationship)
            .filter((AssetRelationship.source_id == str(asset.id))
                    | (AssetRelationship.target_id == str(asset.id))).all())
    return {"asset": {"id": asset.id, "name": asset.name, "hostname": asset.hostname,
                      "kind": asset.kind, "zone": asset.zone, "status": asset.status,
                      "owner": asset.owner, "criticality": asset.criticality,
                      "os": (ev.get("os") or {}) if isinstance(ev, dict) else {}},
            "open_findings": [{"id": f.id, "rule_id": f.rule_id, "severity": f.severity,
                               "detail": (f.detail or "")[:300]} for f in findings
                              if f.workflow not in ("resolved", "false_positive")][:10],
            "relationships": len(rels)}


def _tool_list_findings(db: Session, args: dict) -> dict:
    sev = str(args.get("severity", "")).strip().lower()
    asset_ref = str(args.get("asset", "")).strip()
    findings = _assist_open_findings(db)
    if sev:
        findings = [f for f in findings if str(f.severity).lower() == sev]
    if asset_ref:
        asset, _c = _assist_resolve_asset(db, asset_ref)
        if asset is None:
            raise ValueError(f"unknown asset '{asset_ref}'")
        findings = [f for f in findings if str(f.asset_id) == str(asset.id)]
    out = [{"id": f.id, "rule_id": f.rule_id, "severity": f.severity,
            "asset_id": f.asset_id, "detail": (f.detail or "")[:240]}
           for f in findings[:25]]
    return {"count": len(findings), "findings": out}


def _tool_list_incidents(db: Session, args: dict) -> dict:
    items = db.query(Incident).order_by(Incident.id.desc()).limit(20).all()
    return {"incidents": [{"id": i.id, "title": i.title, "severity": i.severity,
                           "status": getattr(i, "status", "open"),
                           "commander": getattr(i, "commander", "")} for i in items]}


def _tool_incident_details(db: Session, args: dict) -> dict:
    try:
        iid = int(str(args.get("id", "")).strip().strip("#"))
    except ValueError:
        raise ValueError("incident id must be a number")
    i = db.query(Incident).filter(Incident.id == iid).first()
    if not i:
        raise ValueError(f"incident {iid} not found")
    events = db.query(IncidentEvent).filter(IncidentEvent.incident_id == iid).all()
    return {"incident": {"id": i.id, "title": i.title, "severity": i.severity,
                         "status": getattr(i, "status", "open"),
                         "commander": getattr(i, "commander", "")},
            "events": len(events),
            "recent": [{"kind": e.kind, "detail": (e.detail or "")[:200]} for e in events[-5:]]}


def _tool_recovery_status(db: Session, args: dict) -> dict:
    from app.models.models import RecoveryRun as RR
    runs = db.query(RR).order_by(RR.id.desc()).limit(1).all()
    last = None
    if runs:
        res = json.loads(runs[0].result_json)
        m = res.get("metrics", {})
        last = {"run_id": runs[0].id, "scenario": res.get("scenario", {}).get("id"),
                "steps_success": m.get("steps_success"), "steps_failed": m.get("steps_failed"),
                "rto_met": m.get("rto_met")}
    ready = review.service_readiness(db)
    ok = [s for s in ready if s.get("ready")]
    return {"services_ready": f"{len(ok)}/{len(ready)}",
            "not_ready": [s.get("service") for s in ready if not s.get("ready")][:8],
            "last_run": last}


def _tool_threats_summary(db: Session, args: dict) -> dict:
    from app import vuln_intel
    rows = []
    for adv in vuln_intel._advisories():
        c, p, _u = _advisory_exposure(db, adv)
        if c or p:
            rows.append({"id": adv.id, "title": adv.title, "severity": adv.severity,
                         "known_exploited": adv.known_exploited,
                         "confirmed": len(c), "potential": len(p),
                         "assets": sorted({e["asset_name"] for e in c + p})[:6]})
    rows.sort(key=lambda r: (not r["known_exploited"],
                             {"critical": 0, "high": 1, "medium": 2, "low": 3}
                             .get(str(r["severity"]).lower(), 4)))
    return {"affecting_environment": len(rows), "top": rows[:8]}


_ASSIST_READ_TOOLS = {
    "environment_overview": {"level": 1, "confirm": False,
                             "description": "Counts of assets, findings, incidents and threat exposure."},
    "search_assets": {"level": 1, "confirm": False,
                      "description": "Find assets by name, hostname, kind or zone."},
    "asset_details": {"level": 1, "confirm": False,
                      "description": "Full details, open findings and relationship count for one asset."},
    "list_findings": {"level": 1, "confirm": False,
                      "description": "Open findings, filterable by severity and asset."},
    "list_incidents": {"level": 1, "confirm": False,
                       "description": "Recent incidents with status and commander."},
    "incident_details": {"level": 1, "confirm": False,
                         "description": "One incident with event count and recent events."},
    "recovery_status": {"level": 1, "confirm": False,
                        "description": "Recovery readiness and the last simulation run."},
    "threats_summary": {"level": 1, "confirm": False,
                        "description": "Advisories affecting this environment, known-exploited first."},
}

_ASSIST_READ_FNS = {
    "environment_overview": _tool_environment_overview,
    "search_assets": _tool_search_assets,
    "asset_details": _tool_asset_details,
    "list_findings": _tool_list_findings,
    "list_incidents": _tool_list_incidents,
    "incident_details": _tool_incident_details,
    "recovery_status": _tool_recovery_status,
    "threats_summary": _tool_threats_summary,
}


# ---- write tools (operator+, always confirmed, executed on approval) --------

def _wtool_create_incident(db: Session, actor: str, args: dict) -> dict:
    title = str(args.get("title", "")).strip()
    if not title:
        raise ValueError("title is required")
    severity = str(args.get("severity", "medium")).strip().lower()
    if severity not in ("critical", "high", "medium", "low"):
        raise ValueError("severity must be critical, high, medium or low")
    row = Incident(title=title[:200], severity=severity)
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"incident_id": row.id, "title": row.title, "severity": row.severity}


def _wtool_propose_plan(db: Session, actor: str, args: dict) -> dict:
    try:
        fid = int(str(args.get("finding_id", "")).strip().strip("#"))
    except ValueError:
        raise ValueError("finding_id must be a number")
    f = db.query(Finding).filter(Finding.id == fid).first()
    if not f:
        raise ValueError(f"finding {fid} not found")
    from app.fixpilot_router import ProposeRequest
    from app.fixpilot_router import propose as _propose
    rec = _propose(ProposeRequest(
        finding_id=str(f.id), rule_id=f.rule_id or "UNKNOWN", title=f.rule_id or "",
        severity=f.severity or "unknown", asset_id=str(f.asset_id or ""),
        evidence=[f.detail] if f.detail else []), x_role=actor)
    return {"plan_id": rec.id, "finding_id": f.id, "status": rec.status}


def _wtool_assign_task(db: Session, actor: str, args: dict) -> dict:
    pid = str(args.get("plan_id", "")).strip()
    owner = str(args.get("owner", "")).strip()
    if not pid or not owner:
        raise ValueError("plan_id and owner are required")
    from app.fixpilot_router import TaskRequest
    from app.fixpilot_router import set_task as _set_task
    rec = _set_task(pid, TaskRequest(owner=owner,
                                    due_date=str(args.get("due_date", "")).strip(),
                                    note=str(args.get("note", "")).strip(),
                                    actor=actor), x_role=actor)
    if rec is None:
        raise ValueError(f"plan {pid} not found")
    return {"plan_id": rec.id, "owner": owner}


def _wtool_run_assessment(db: Session, actor: str, args: dict) -> dict:
    result = detection.run_detection(db, scope="all", actor=actor)
    return {"run_id": result.get("run_id"), "assets": result.get("assets"),
            "fail": result.get("fail"), "vulnerabilities": result.get("vulnerabilities")}


def _wtool_run_recovery(db: Session, actor: str, args: dict) -> dict:
    sid = str(args.get("scenario_id", "")).strip()
    if sid not in SCENARIO_DEFS:
        raise ValueError(f"unknown scenario '{sid}'")
    res = api_recovery_run(ScenarioIn(scenario_id=sid), db)
    m = res.get("metrics", {})
    return {"run_id": res.get("run_id"), "scenario": sid,
            "steps_success": m.get("steps_success"), "steps_failed": m.get("steps_failed")}


_ASSIST_WRITE_TOOLS = {
    "create_incident": {"level": 2, "confirm": True, "min_role": "operator",
                        "description": "Open a new incident with title and severity.",
                        "impact": "Adds one incident record; nothing else changes."},
    "propose_plan": {"level": 2, "confirm": True, "min_role": "operator",
                     "description": "Draft a FixPilot remediation plan for an open finding.",
                     "impact": "Creates a draft plan in proposed status; no execution."},
    "assign_task": {"level": 2, "confirm": True, "min_role": "operator",
                    "description": "Assign a remediation plan to an owner with optional due date.",
                    "impact": "Updates plan task metadata; lifecycle status unchanged."},
    "run_assessment": {"level": 3, "confirm": True, "min_role": "operator",
                       "description": "Run a full detection assessment across all assets.",
                       "impact": "Creates a new assessment run and findings; read-only against assets."},
    "run_recovery": {"level": 3, "confirm": True, "min_role": "operator",
                     "description": "Run a recovery simulation scenario.",
                     "impact": "Simulated only; never touches production systems."},
}

_ASSIST_WRITE_FNS = {
    "create_incident": _wtool_create_incident,
    "propose_plan": _wtool_propose_plan,
    "assign_task": _wtool_assign_task,
    "run_assessment": _wtool_run_assessment,
    "run_recovery": _wtool_run_recovery,
}


def _assist_run_read_tool(db: Session, tool_id: str, args: dict) -> dict:
    fn = _ASSIST_READ_FNS.get(tool_id)
    if not fn:
        raise ValueError(f"unknown tool '{tool_id}'")
    return fn(db, args or {})


def _assist_execute_write(db: Session, actor: str, task: AITask) -> dict:
    """Execute an approved write tool. Re-checks role immediately before acting."""
    spec = _ASSIST_WRITE_TOOLS.get(task.task_type)
    if not spec:
        raise ValueError(f"unknown task type '{task.task_type}'")
    require_role(spec["min_role"], actor)
    args = json.loads(task.target_json or "{}")
    return _ASSIST_WRITE_FNS[task.task_type](db, actor, args)


# ---- deterministic intent router --------------------------------------------

def _assist_route(db: Session, conv: Conversation, text: str) -> dict:
    """Route a message to an answer and optional task proposal.

    Returns {kind, answer, refs, task?: {type, args, summary, impact}}.
    Never invents data: every entity is resolved against the database first.
    """
    t = (text or "").strip()
    low = t.lower()
    if not t:
        return {"kind": "answer",
                "answer": "Tell me what to look into — for example: 'overview', "
                          "'which assets need attention', or 'critical findings'.",
                "refs": {}}

    if re.search(r"\b(what can you (do|help)|capabilit|help\b|how do (you|this) work)", low):
        lines = ["I can query this environment and, with your approval, act on it.",
                 "", "Read (no confirmation needed):"]
        for tid, spec in _ASSIST_READ_TOOLS.items():
            lines.append(f"- {tid}: {spec['description']}")
        lines.append("")
        lines.append("Write (I always ask first, then you approve in chat):")
        for tid, spec in _ASSIST_WRITE_TOOLS.items():
            lines.append(f"- {tid} (level {spec['level']}): {spec['description']}")
        lines += ["", "Try: 'overview', 'asset app01', 'critical findings', "
                  "'run assessment', or 'create incident titled X'."]
        return {"kind": "answer", "answer": "\n".join(lines), "refs": {}}

    m = re.search(r"create (?:an? )?incident(?: titled | called | for |:)?(.+?)(?: severity (\w+))?\s*$", low)
    if m and ("incident" in low):
        title = (m.group(1) or "").strip().strip("\"'") or t
        sev = (m.group(2) or "medium").lower()
        if sev not in ("critical", "high", "medium", "low"):
            sev = "medium"
        return {"kind": "propose",
                "answer": f"I'll open incident '{title}' with severity {sev}. Approve to create it.",
                "refs": {},
                "task": {"type": "create_incident",
                         "args": {"title": title[:200], "severity": sev},
                         "summary": f"Create incident '{title}' ({sev})",
                         "impact": _ASSIST_WRITE_TOOLS["create_incident"]["impact"]}}

    if re.search(r"\brun\b.{0,30}\b(assessment|assess|scan)\b", low) and "incident" not in low:
        return {"kind": "propose",
                "answer": "I'll run a full detection assessment across all assets. Approve to start it.",
                "refs": {},
                "task": {"type": "run_assessment", "args": {},
                         "summary": "Run full detection assessment",
                         "impact": _ASSIST_WRITE_TOOLS["run_assessment"]["impact"]}}

    m = re.search(r"run (?:scenario|simulation|recovery)\s+([a-z0-9\-]+)", low)
    if m or ("run" in low and "scenario" in low):
        sid = (m.group(1) if m else "").strip()
        if sid in SCENARIO_DEFS:
            spec = SCENARIO_DEFS[sid]
            return {"kind": "propose",
                    "answer": f"I'll run the '{spec['name']}' simulation. Approve to start it.",
                    "refs": {},
                    "task": {"type": "run_recovery", "args": {"scenario_id": sid},
                             "summary": f"Run recovery scenario '{sid}'",
                             "impact": _ASSIST_WRITE_TOOLS["run_recovery"]["impact"]}}
        known = ", ".join(sorted(SCENARIO_DEFS))
        return {"kind": "answer",
                "answer": f"Which scenario? Available: {known}. For example: 'run scenario gateway-loss'.",
                "refs": {}}

    m = re.search(r"(?:propose|generate|draft|create).{0,50}plan.{0,50}finding\s*#?(\d+)", low)
    if not m:
        m = re.search(r"plan for finding\s*#?(\d+)", low)
    if m:
        return {"kind": "propose",
                "answer": f"I'll draft a remediation plan for finding #{m.group(1)}. Approve to generate it.",
                "refs": {"finding_id": int(m.group(1))},
                "task": {"type": "propose_plan", "args": {"finding_id": int(m.group(1))},
                         "summary": f"Draft remediation plan for finding #{m.group(1)}",
                         "impact": _ASSIST_WRITE_TOOLS["propose_plan"]["impact"]}}

    m = re.search(r"assign\s+(plan-\S+)\s+(?:to\s+)?(.+?)(?:\s+due\s+(\d{4}-\d{2}-\d{2}))?\s*$", low)
    if m:
        return {"kind": "propose",
                "answer": f"I'll assign {m.group(1)} to '{m.group(2).strip()}'. Approve to record it.",
                "refs": {},
                "task": {"type": "assign_task",
                         "args": {"plan_id": m.group(1), "owner": m.group(2).strip(),
                                  "due_date": m.group(3) or ""},
                         "summary": f"Assign {m.group(1)} to {m.group(2).strip()}",
                         "impact": _ASSIST_WRITE_TOOLS["assign_task"]["impact"]}}

    m = re.search(r"\basset\s+#?([A-Za-z0-9_.\-]+)", low)
    if not m or m.group(1).lower() in ("health", "status", "list", "all", "details"):
        m = re.search(r"(?:host|server|machine|investigate|tell me about|details?(?: of| for| on)?)\s+([A-Za-z0-9_.\-]+)", low)
    pron = re.search(r"\b(this|that|it|the asset|the server|the machine)\b", low)
    ref = None
    if m and m.group(1).lower() not in ("health", "status", "list", "all"):
        ref = m.group(1)
    elif pron:
        last = _assist_last_asset(db, conv)
        ref = str(last) if last else None
        if not ref:
            return {"kind": "answer",
                    "answer": "Which asset? Give me a name, hostname, or id — for example 'asset app01'.",
                    "refs": {}}
    if ref:
        asset, candidates = _assist_resolve_asset(db, ref)
        if asset is None:
            if candidates:
                names = ", ".join(f"{a.name or a.hostname} (#{a.id})" for a in candidates[:8])
                return {"kind": "answer",
                        "answer": f"Multiple assets match '{ref}': {names}. Which one?",
                        "refs": {}}
            return {"kind": "answer",
                    "answer": f"No asset matches '{ref}'. Search known names with 'search assets'.",
                    "refs": {}}
        d = _tool_asset_details(db, {"ref": str(asset.id)})
        a = d["asset"]
        lines = [f"{a['name']} ({a['hostname'] or 'no hostname'}) — {a['kind']}, "
                 f"zone {a['zone']}, status {a['status']}, criticality {a['criticality']}.",
                 f"Owner: {a['owner'] or 'unassigned'}. Relationships: {d['relationships']}."]
        if d["open_findings"]:
            lines.append(f"Open findings ({len(d['open_findings'])}):")
            for f in d["open_findings"][:6]:
                lines.append(f"- #{f['id']} {f['rule_id']} [{f['severity']}] {f['detail'][:140]}")
        else:
            lines.append("No open findings recorded for this asset.")
        _assist_remember_asset(db, conv, asset.id)
        return {"kind": "answer", "answer": "\n".join(lines),
                "refs": {"asset_id": asset.id}}

    if re.search(r"attention|unhealthy|offline|degraded|at.?risk|\bdown\b|needs?", low):
        assets = db.query(Asset).filter(Asset.retired == 0).all()
        bad = [a for a in assets if str(a.status).lower() != "operational"]
        findings = _assist_open_findings(db)
        crit_assets: dict[str, int] = {}
        for f in findings:
            if str(f.severity).lower() in ("critical", "high"):
                crit_assets[str(f.asset_id)] = crit_assets.get(str(f.asset_id), 0) + 1
        names = {str(a.id): (a.name or a.hostname) for a in assets}
        lines = []
        if bad:
            lines.append(f"Non-operational assets ({len(bad)}): " +
                         ", ".join(f"{a.name or a.hostname} ({a.status})" for a in bad[:10]))
        else:
            lines.append("All assets report operational status.")
        if crit_assets:
            lines.append("Assets with critical/high findings:")
            for aid, n in sorted(crit_assets.items(), key=lambda x: -x[1])[:8]:
                lines.append(f"- {names.get(aid, aid)}: {n}")
        else:
            lines.append("No critical or high findings open.")
        return {"kind": "answer", "answer": "\n".join(lines),
                "refs": {"asset_ids": [a.id for a in bad[:10]]}}

    if "finding" in low:
        msev = re.search(r"\b(critical|high|medium|low)\b", low)
        mid = re.search(r"finding\s*#?(\d+)", low)
        args: dict = {}
        if msev:
            args["severity"] = msev.group(1)
        if mid:
            f = db.query(Finding).filter(Finding.id == int(mid.group(1))).first()
            if not f:
                return {"kind": "answer",
                        "answer": f"Finding #{mid.group(1)} does not exist.", "refs": {}}
            return {"kind": "answer",
                    "answer": f"Finding #{f.id}: {f.rule_id} [{f.severity}] on asset {f.asset_id}, "
                              f"workflow {f.workflow}. Detail: {(f.detail or '')[:400]}",
                    "refs": {"finding_id": f.id, "asset_id": f.asset_id}}
        d = _tool_list_findings(db, args)
        lines = [f"Open findings: {d['count']}."]
        for f in d["findings"][:8]:
            lines.append(f"- #{f['id']} {f['rule_id']} [{f['severity']}] asset {f['asset_id']}")
        if d["count"] > 8:
            lines.append(f"... and {d['count'] - 8} more. Narrow with a severity or asset.")
        return {"kind": "answer", "answer": "\n".join(lines),
                "refs": {"finding_ids": [f["id"] for f in d["findings"][:8]]}}

    if "incident" in low:
        mid = re.search(r"incident\s*#?(\d+)", low)
        if mid:
            try:
                d = _tool_incident_details(db, {"id": mid.group(1)})
            except ValueError:
                return {"kind": "answer",
                        "answer": f"Incident #{mid.group(1)} does not exist.", "refs": {}}
            i = d["incident"]
            return {"kind": "answer",
                    "answer": f"Incident #{i['id']}: {i['title']} [{i['severity']}, {i['status']}], "
                              f"commander: {i['commander'] or 'unassigned'}. "
                              f"{d['events']} recorded events.",
                    "refs": {"incident_id": i["id"]}}
        d = _tool_list_incidents(db, {})
        if not d["incidents"]:
            return {"kind": "answer", "answer": "No incidents recorded.", "refs": {}}
        lines = ["Recent incidents:"]
        for i in d["incidents"][:8]:
            lines.append(f"- #{i['id']} {i['title']} [{i['severity']}, {i['status']}]")
        return {"kind": "answer", "answer": "\n".join(lines),
                "refs": {"incident_ids": [i["id"] for i in d["incidents"][:8]]}}

    if re.search(r"recover|readiness|rto|last (recovery )?run", low):
        d = _tool_recovery_status(db, {})
        lines = [f"Recovery readiness: {d['services_ready']} services ready."]
        if d["not_ready"]:
            lines.append("Not ready: " + ", ".join(d["not_ready"]))
        if d["last_run"]:
            lr = d["last_run"]
            lines.append(f"Last run #{lr['run_id']} ({lr['scenario']}): "
                         f"{lr['steps_success']} ok / {lr['steps_failed']} failed.")
        else:
            lines.append("No recovery run recorded yet.")
        return {"kind": "answer", "answer": "\n".join(lines),
                "refs": {"run_id": (d["last_run"] or {}).get("run_id")}}

    if re.search(r"threat|advis|cve|kev|exploit|vulnerab", low):
        d = _tool_threats_summary(db, {})
        if not d["affecting_environment"]:
            return {"kind": "answer",
                    "answer": "No bundled advisory matches declared asset software. "
                              "Assets without software inventory cannot be evaluated — "
                              "see the Threats page for the full exposure table.",
                    "refs": {}}
        lines = [f"{d['affecting_environment']} advisories affect this environment. Top:"]
        for r in d["top"][:6]:
            kev = " (known exploited)" if r["known_exploited"] else ""
            lines.append(f"- {r['id']} [{r['severity']}]{kev}: {r['confirmed']} confirmed, "
                         f"{r['potential']} potential — {', '.join(r['assets'])}")
        return {"kind": "answer", "answer": "\n".join(lines),
                "refs": {"advisory_ids": [r["id"] for r in d["top"][:6]]}}

    if re.search(r"overview|posture|summary|summary|status|environment|health|how are we", low):
        d = _tool_environment_overview(db, {})
        lines = [f"Environment: {d['assets']} assets "
                 f"({len(d['degraded_assets'])} non-operational), "
                 f"{d['open_findings']} open findings ({d['critical_high']} critical/high), "
                 f"{d['active_incidents']} active incidents.",
                 f"Threat exposure: {d['confirmed_exposure']} confirmed, "
                 f"{d['potential_exposure']} potential across {d['advisories']} advisories."]
        return {"kind": "answer", "answer": "\n".join(lines), "refs": {}}

    return {"kind": "answer",
            "answer": "I can't do that with the connected systems. I can query assets, findings, "
                      "incidents, recovery and threats, and — with your approval — create incidents, "
                      "draft remediation plans, assign tasks, run assessments, or run recovery "
                      "simulations. Ask 'what can you do' for the full list.",
            "refs": {}}


def _assist_polish(question: str, context_answer: str) -> tuple[str, str]:
    """Rephrase verified context with the live model; fall back to template."""
    from app.ai import ai_service
    from app.ai.muse_spark_adapter import ASSISTANT_SYSTEM, complete_text
    from app.ai.config import load_ai_config
    try:
        res = complete_text(ASSISTANT_SYSTEM,
                            f"Question: {question}\nVerified context:\n{context_answer}",
                            load_ai_config())
    except Exception:
        return context_answer, "fallback"
    if not res.ok:
        return context_answer, "fallback"
    return res.text, res.model_used


def _assist_answer(db: Session, conv: Conversation, user_text: str,
                   actor: str) -> tuple[str, dict | None, dict, str]:
    """Run the router, create a pending task when proposed, return
    (answer_text, task_row_or_None, refs, engine). Enforces role gates on
    write tools. Engine is the live model id or 'fallback'."""
    route = _assist_route(db, conv, user_text)
    task_row = None
    if route.get("kind") == "propose":
        proposal = route["task"]
        spec = _ASSIST_WRITE_TOOLS[proposal["type"]]
        if actor not in ("admin", "operator") and spec["min_role"] == "operator":
            return (f"That action needs an operator role — you are '{actor}'. "
                    "Switch roles in the sidebar to proceed.", None, {}, "policy")
        task_row = AITask(conversation_id=conv.id, requested_by=actor,
                          task_type=proposal["type"],
                          target_json=json.dumps(proposal["args"]),
                          status="pending_approval", requires_approval=1,
                          correlation_id=f"task-{uuid.uuid4().hex[:8]}")
        db.add(task_row)
        db.commit()
        db.refresh(task_row)
        _assist_audit(db, actor, "ai_task_proposed",
                      f"{proposal['type']} corr={task_row.correlation_id}")
        answer = route["answer"] + " Reply Approve (or use the task card) to proceed."
    else:
        answer = route["answer"]
    refs = route.get("refs", {})
    polished, model_used = _assist_polish(user_text, answer)
    if task_row is not None:
        polished += f"\n\nTask {task_row.correlation_id} is waiting for approval."
    return polished, task_row, refs, model_used


class AIConversationIn(BaseModel):
    title: str = Field(default="", max_length=120)


class AIMessageIn(BaseModel):
    content: str = Field(min_length=1, max_length=4000)


class AIRenameIn(BaseModel):
    title: str = Field(min_length=1, max_length=120)


def _assist_conv_out(db: Session, conv: Conversation) -> dict:
    last = (db.query(ChatMessage).filter(ChatMessage.conversation_id == conv.id)
            .order_by(ChatMessage.id.desc()).first())
    return {"id": conv.id, "title": conv.title, "updated_at": conv.updated_at,
            "preview": ((last.content if last else "")[:120])}


@app.get("/api/ai/health")
def api_ai_health():
    """Assistant + provider availability. No secrets exposed."""
    from app.ai import ai_service
    st = ai_service.status()
    tools = {**{k: {"level": v["level"], "confirm": v["confirm"]} for k, v in _ASSIST_READ_TOOLS.items()},
             **{k: {"level": v["level"], "confirm": v["confirm"]} for k, v in _ASSIST_WRITE_TOOLS.items()}}
    return {"assistant": "ready", "provider": st.get("provider"), "model_id": st.get("model_id"),
            "model_available": st.get("model_available"), "mode": st.get("mode"),
            "tools": tools}


@app.get("/api/ai/capabilities")
def api_ai_capabilities():
    read = {k: {"description": v["description"], "level": v["level"],
                "confirm": v["confirm"], "min_role": "viewer"}
            for k, v in _ASSIST_READ_TOOLS.items()}
    write = {k: {"description": v["description"], "level": v["level"],
                 "confirm": v["confirm"], "min_role": v["min_role"],
                 "impact": v["impact"]} for k, v in _ASSIST_WRITE_TOOLS.items()}
    return {"read": read, "write": write,
            "note": "Write tools require operator role and explicit approval in chat."}


@app.post("/api/ai/conversations", status_code=201)
def api_ai_conv_create(body: AIConversationIn | None = None,
                       db: Session = Depends(get_db),
                       authorization: str | None = Header(default=None),
                       x_role: str | None = Header(default=None)):
    user = _assist_actor(authorization, x_role)
    conv = Conversation(user_id=user, title=(body.title if body and body.title else "New conversation")[:120])
    db.add(conv)
    db.commit()
    db.refresh(conv)
    return _assist_conv_out(db, conv)


@app.get("/api/ai/conversations")
def api_ai_conv_list(db: Session = Depends(get_db),
                     authorization: str | None = Header(default=None),
                     x_role: str | None = Header(default=None)):
    user = _assist_actor(authorization, x_role)
    convs = (db.query(Conversation).filter(Conversation.user_id == user)
             .order_by(Conversation.updated_at.desc()).all())
    return [_assist_conv_out(db, c) for c in convs]


@app.get("/api/ai/conversations/{cid}")
def api_ai_conv_get(cid: int, db: Session = Depends(get_db),
                    authorization: str | None = Header(default=None),
                    x_role: str | None = Header(default=None)):
    conv = _assist_get_conv(db, cid, _assist_actor(authorization, x_role))
    msgs = (db.query(ChatMessage).filter(ChatMessage.conversation_id == cid)
            .order_by(ChatMessage.id).all())
    return {"id": conv.id, "title": conv.title, "updated_at": conv.updated_at,
            "messages": [{"id": m.id, "role": m.role, "content": m.content,
                          "meta": json.loads(m.meta_json or "{}")} for m in msgs]}


@app.patch("/api/ai/conversations/{cid}")
def api_ai_conv_rename(cid: int, body: AIRenameIn, db: Session = Depends(get_db),
                       authorization: str | None = Header(default=None),
                       x_role: str | None = Header(default=None)):
    conv = _assist_get_conv(db, cid, _assist_actor(authorization, x_role))
    conv.title = body.title.strip()[:120]
    conv.updated_at = time.time()
    db.commit()
    return _assist_conv_out(db, conv)


@app.delete("/api/ai/conversations/{cid}")
def api_ai_conv_delete(cid: int, db: Session = Depends(get_db),
                       authorization: str | None = Header(default=None),
                       x_role: str | None = Header(default=None)):
    conv = _assist_get_conv(db, cid, _assist_actor(authorization, x_role))
    db.query(ChatMessage).filter(ChatMessage.conversation_id == cid).delete()
    db.query(AITask).filter(AITask.conversation_id == cid).delete()
    db.delete(conv)
    db.commit()
    return {"deleted": True}


@app.post("/api/ai/conversations/{cid}/messages")
def api_ai_message(cid: int, body: AIMessageIn, db: Session = Depends(get_db),
                   authorization: str | None = Header(default=None),
                   x_role: str | None = Header(default=None)):
    actor = _assist_actor(authorization, x_role)
    _check_rate(f"ai:{actor}")
    conv = _assist_get_conv(db, cid, actor)
    _assist_msg(db, cid, "user", body.content.strip())
    if conv.title == "New conversation":
        conv.title = body.content.strip()[:60] or "New conversation"
        db.commit()
    answer, task_row, refs, engine = _assist_answer(db, conv, body.content.strip(), actor)
    meta = {"model_used": engine, "refs": refs}
    if task_row is not None:
        meta["task"] = {"id": task_row.id, "type": task_row.task_type,
                        "status": task_row.status,
                        "correlation_id": task_row.correlation_id}
    m = _assist_msg(db, cid, "assistant", answer, meta)
    return {"message": {"id": m.id, "role": "assistant", "content": answer, "meta": meta}}


@app.get("/api/ai/conversations/{cid}/stream")
def api_ai_stream(cid: int, message: str, db: Session = Depends(get_db),
                  authorization: str | None = Header(default=None),
                  x_role: str | None = Header(default=None)):
    """SSE delivery of the assistant answer (EventSource-compatible)."""
    from fastapi.responses import StreamingResponse
    actor = _assist_actor(authorization, x_role)
    _check_rate(f"ai:{actor}")
    if not message or len(message) > 4000:
        raise HTTPException(422, "message must be 1-4000 characters")
    conv = _assist_get_conv(db, cid, actor)
    _assist_msg(db, cid, "user", message.strip())
    if conv.title == "New conversation":
        conv.title = message.strip()[:60] or "New conversation"
        db.commit()
    answer, task_row, refs, engine = _assist_answer(db, conv, message.strip(), actor)
    meta = {"model_used": engine, "refs": refs}
    if task_row is not None:
        meta["task"] = {"id": task_row.id, "type": task_row.task_type,
                        "status": task_row.status,
                        "correlation_id": task_row.correlation_id}
    _assist_msg(db, cid, "assistant", answer, meta)

    def gen():
        for i in range(0, len(answer), 60):
            yield f"data: {json.dumps({'chunk': answer[i:i + 60]})}\n\n"
        yield f"data: {json.dumps({'done': True, 'meta': meta})}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/ai/tasks/{tid}")
def api_ai_task_get(tid: int, db: Session = Depends(get_db),
                    authorization: str | None = Header(default=None),
                    x_role: str | None = Header(default=None)):
    actor = _assist_actor(authorization, x_role)
    task = db.query(AITask).filter(AITask.id == tid).first()
    if not task:
        raise HTTPException(404, "task not found")
    _assist_get_conv(db, task.conversation_id, actor)
    return {"id": task.id, "type": task.task_type, "status": task.status,
            "target": json.loads(task.target_json or "{}"),
            "result": json.loads(task.result_json or "{}"),
            "error": task.error_summary, "correlation_id": task.correlation_id,
            "approved_by": task.approved_by}


@app.post("/api/ai/tasks/{tid}/approve")
def api_ai_task_approve(tid: int, db: Session = Depends(get_db),
                        authorization: str | None = Header(default=None),
                        x_role: str | None = Header(default=None)):
    """Approve and execute a pending task. Role re-checked at execution time."""
    actor = _assist_actor(authorization, x_role)
    task = db.query(AITask).filter(AITask.id == tid).first()
    if not task:
        raise HTTPException(404, "task not found")
    conv = _assist_get_conv(db, task.conversation_id, actor)
    if task.status != "pending_approval":
        raise HTTPException(409, f"task is {task.status}, not pending approval")
    spec = _ASSIST_WRITE_TOOLS.get(task.task_type)
    if not spec:
        raise HTTPException(422, "unknown task type")
    require_role(spec["min_role"], actor)
    task.status = "running"
    task.started_at = time.time()
    task.approved_by = actor
    db.commit()
    try:
        result = _assist_execute_write(db, actor, task)
    except (ValueError, HTTPException) as e:
        task.status = "failed"
        task.error_summary = getattr(e, "detail", str(e))[:500]
        task.completed_at = time.time()
        db.commit()
        _assist_audit(db, actor, "ai_task_failed",
                      f"{task.task_type} corr={task.correlation_id} err={task.error_summary[:200]}")
        _assist_msg(db, conv.id, "tool",
                    f"Task {task.correlation_id} failed: {task.error_summary}",
                    {"task_id": task.id, "status": "failed"})
        raise HTTPException(422, task.error_summary)
    task.status = "completed"
    task.result_json = json.dumps(result)
    task.completed_at = time.time()
    db.commit()
    _assist_audit(db, actor, "ai_task_executed",
                  f"{task.task_type} corr={task.correlation_id} result={json.dumps(result)[:300]}")
    _assist_msg(db, conv.id, "tool",
                f"Task {task.correlation_id} completed: {json.dumps(result)[:500]}",
                {"task_id": task.id, "status": "completed", "result": result})
    return {"id": task.id, "status": "completed", "result": result}


@app.post("/api/ai/tasks/{tid}/cancel")
def api_ai_task_cancel(tid: int, db: Session = Depends(get_db),
                       authorization: str | None = Header(default=None),
                       x_role: str | None = Header(default=None)):
    actor = _assist_actor(authorization, x_role)
    task = db.query(AITask).filter(AITask.id == tid).first()
    if not task:
        raise HTTPException(404, "task not found")
    _assist_get_conv(db, task.conversation_id, actor)
    if task.status != "pending_approval":
        raise HTTPException(409, f"task is {task.status}, cannot cancel")
    task.status = "cancelled"
    task.completed_at = time.time()
    db.commit()
    _assist_audit(db, actor, "ai_task_cancelled",
                  f"{task.task_type} corr={task.correlation_id}")
    return {"id": task.id, "status": "cancelled"}


@app.post("/api/demo/reset")
def api_reset(db: Session = Depends(get_db)):
    from app.seed import seed
    return seed()
