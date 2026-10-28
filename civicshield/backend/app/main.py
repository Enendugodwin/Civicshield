"""CivicShield full backend API (SQLite default)."""
from __future__ import annotations

import csv
import io
import json
import time

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import Base, SessionLocal, engine, get_db
from app.models.models import (
    AssessmentResult,
    AssessmentRun,
    Asset,
    AssetRelationship,
    AuditEvent,
    BackupRecord,
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


@app.post("/api/demo/reset")
def api_reset(db: Session = Depends(get_db)):
    from app.seed import seed
    return seed()
