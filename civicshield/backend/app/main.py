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

from app.database import Base, SessionLocal, engine
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
    VerificationResult,
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


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


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
    edges: dict[str, list[str]] = {}
    svc_of: dict[str, list[str]] = {}
    for r in db.query(AssetRelationship).all():
        s, t = str(r.source_id), str(r.target_id)
        if r.source_type == "asset" and r.target_type == "asset":
            edges.setdefault(s, []).append(t)
        elif r.source_type == "asset" and r.target_type == "service":
            svc_of.setdefault(t, []).append(s)
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
    """Acknowledge, assign, investigate, resolve, or mark false positive — with a recorded reason."""
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


# ---- remediation aliases (spec paths) ----
@app.post("/api/remediation-plans/{plan_id}/approve")
def api_plan_approve(plan_id: str, db: Session = Depends(get_db),
                     authorization: str | None = Header(default=None), x_role: str | None = Header(default=None)):
    require_role("operator", role_of(authorization, x_role))
    from app.fixpilot_store import set_status
    rec = set_status(plan_id, "approved", actor=role_of(authorization, x_role))
    if not rec:
        raise HTTPException(404, "plan not found")
    audit(db, role_of(authorization, x_role), "plan_approved", plan_id)
    return rec.model_dump()


def _apply_evidence_fix(rule_id: str, ev: dict) -> tuple[dict, str]:
    """Simulated remediation: mutate stored evidence so the rule re-evaluates to PASS."""
    import copy
    from datetime import datetime, timezone
    ev = copy.deepcopy(ev)
    now = datetime.now(timezone.utc).isoformat()
    note = ""
    if rule_id == "BG-ASSET-001":
        ev["owner"] = ev.get("owner") or "assigned-team"; note = "owner assigned"
    elif rule_id == "BG-ASSET-004":
        ev.setdefault("network", {})["remote_admin_exposed"] = False; note = "remote admin restricted"
    elif rule_id == "BG-ASSET-005":
        ev.setdefault("firewall", {})["ingress"] = "restricted"; note = "ingress restricted"
    elif rule_id == "BG-ASSET-006":
        ev.setdefault("services", {})["unnecessary"] = []; note = "unneeded services disabled"
    elif rule_id == "BG-ID-001":
        for a in ev.get("identity", {}).get("privileged_accounts", []): a["mfa"] = True
        note = "MFA enforced on privileged accounts"
    elif rule_id == "BG-ID-002":
        ident = ev.setdefault("identity", {}); ident["admin_count"] = ident.get("max_admins", ident.get("admin_count", 1)); note = "excess admin grants removed"
    elif rule_id == "BG-ID-003":
        ev.setdefault("identity", {})["shared_admin_accounts"] = []; note = "shared accounts replaced"
    elif rule_id == "BG-ID-004":
        for a in ev.get("identity", {}).get("privileged_accounts", []): a["last_login"] = now
        note = "stale accounts rotated"
    elif rule_id == "BG-ID-005":
        ev.setdefault("identity", {})["least_privilege_enforced"] = True; note = "least privilege enforced"
    elif rule_id == "BG-ENDP-001":
        ev.setdefault("endpoint", {})["edr_installed"] = True; note = "endpoint protection installed"
    elif rule_id == "BG-ENDP-002":
        ev.setdefault("endpoint", {})["logging_enabled"] = True; note = "logging enabled"
    elif rule_id == "BG-ENDP-003":
        ev.setdefault("endpoint", {})["monitoring_coverage"] = 0.9; note = "monitoring coverage extended"
    elif rule_id == "BG-ENDP-004":
        ev.setdefault("endpoint", {})["baseline_verified"] = True; note = "baseline verified"
    elif rule_id in ("BG-ASSET-003", "BG-BKP-001"):
        key = "patch" if rule_id == "BG-ASSET-003" else "backup"
        stamp = "last_applied" if rule_id == "BG-ASSET-003" else "last_success"
        ev.setdefault(key, {})[stamp] = now; note = "fresh patch/backup recorded"
    elif rule_id == "BG-BKP-002":
        ev.setdefault("backup", {})["immutable_backup"] = True; note = "immutable backup configured"
    elif rule_id == "BG-BKP-003":
        bkp = ev.setdefault("backup", {}); bkp["last_recovery_test"] = now; note = "recovery test recorded"
    elif rule_id == "BG-BKP-004":
        ev.setdefault("backup", {})["backup_target"] = "backup-server"; note = "backup dependency recorded"
    elif rule_id == "BG-BKP-005":
        ev.setdefault("backup", {})["recovery_procedure"] = "Restore from backup-server per runbook"; note = "recovery procedure documented"
    else:
        ev["remediated_note"] = f"simulated fix applied for {rule_id}"; note = "generic fix marker recorded"
    return ev, note


@app.post("/api/remediation/{plan_id}/apply")
def api_plan_apply(plan_id: str, db: Session = Depends(get_db),
                   authorization: str | None = Header(default=None), x_role: str | None = Header(default=None)):
    """Apply a SIMULATED fix to stored evidence (demo only). Re-run the assessment to verify."""
    require_role("operator", role_of(authorization, x_role))
    from app.fixpilot_store import get_plan, save_plan
    rec = get_plan(plan_id)
    if not rec:
        raise HTTPException(404, "plan not found")
    if rec.status not in ("approved", "simulated"):
        raise HTTPException(409, "approve and simulate the plan before applying")
    try:
        fid = int(rec.finding_id)
    except (TypeError, ValueError):
        raise HTTPException(422, "plan finding is not a stored finding")
    f = db.query(Finding).filter(Finding.id == fid).first()
    if not f:
        raise HTTPException(404, "finding not found")
    asset = db.query(Asset).filter(Asset.id == int(f.asset_id)).first() if str(f.asset_id).isdigit() else None
    if not asset:
        raise HTTPException(404, "finding asset not found")
    fixed, note = _apply_evidence_fix(f.rule_id, json.loads(asset.evidence_json or "{}"))
    asset.evidence_json = json.dumps(fixed)
    asset.updated_at = time.time()
    db.add(VerificationResult(plan_id=plan_id, passed=0, evidence=f"simulated fix applied: {note}; rerun assessment to verify"))
    db.commit()
    rec.payload["applied_fix"] = {"simulated": True, "rule_id": f.rule_id, "asset_id": f.asset_id, "note": note}
    save_plan(rec)
    audit(db, role_of(authorization, x_role), "fix_applied", f"plan={plan_id} rule={f.rule_id} asset={f.asset_id} (simulated)")
    return {"plan_id": plan_id, "rule_id": f.rule_id, "asset_id": f.asset_id, "note": note, "simulated": True}


@app.post("/api/remediation-plans/{plan_id}/simulate")
def api_plan_simulate(plan_id: str, db: Session = Depends(get_db),
                      authorization: str | None = Header(default=None), x_role: str | None = Header(default=None)):
    require_role("operator", role_of(authorization, x_role))
    from app.fixpilot_store import get_plan, save_plan, set_status
    rec = get_plan(plan_id)
    if not rec:
        raise HTTPException(404, "plan not found")
    rec.payload["simulation"] = {"simulated": True, "outcome": "simulated-success (advisory only)"}
    save_plan(rec)
    out = set_status(plan_id, "simulated", actor=role_of(authorization, x_role), simulated=True)
    audit(db, role_of(authorization, x_role), "plan_simulated", plan_id)
    return out.model_dump() if out else {}


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
    """Per-service recovery readiness against documented criteria (Function 14)."""
    services = db.query(Service).order_by(Service.id).all()
    out = []
    for s in services:
        deps = db.query(AssetRelationship).filter(
            AssetRelationship.source_type == "asset", AssetRelationship.target_type == "service",
            AssetRelationship.target_id == s.id).all()
        criteria = {
            "recovery_procedure": bool((s.recovery_procedure or "").strip()),
            "backup_dependency": len(deps) > 0,
            "rto_configured": (s.rto_minutes or 0) > 0,
        }
        failed = [k for k, v in criteria.items() if not v]
        out.append({"service_id": s.id, "service": s.name, "rto_minutes": s.rto_minutes,
                    "criteria": criteria, "ready": not failed, "failed_criteria": failed})
    return {"services": out,
            "note": "A service without a documented procedure, backup dependency, or RTO is not shown as ready."}


@app.post("/api/recovery/runs")
def api_recovery_run(body: ScenarioIn, db: Session = Depends(get_db)):
    sim = _recovery_sim
    spec = SCENARIO_DEFS.get(body.scenario_id)
    if not spec:
        raise HTTPException(404, "unknown scenario")
    graph: dict[str, list[str]] = {}
    svc_deps: dict[str, list[str]] = {}
    for r in db.query(AssetRelationship).all():
        s, t = str(r.source_id), str(r.target_id)
        if r.source_type == "asset" and r.target_type == "asset":
            graph.setdefault(s, []).append(t)
        elif r.source_type == "asset" and r.target_type == "service":
            svc_deps.setdefault(t, []).append(s)
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
            "note": "Summary only — timestamps and events are never invented."}


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
    """Executive posture report: aggregate counts, top risks, readiness — with provenance metadata."""
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
    return {"runs": [json.loads(r.result_json) for r in rows]}


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


@app.post("/api/demo/reset")
def api_reset(db: Session = Depends(get_db)):
    from app.seed import seed
    return seed()
