"""FixPilot router: the single remediation plan lifecycle API.

propose/approve/reject/simulate/verify/reopen/apply + audit. AI-backed with
deterministic fallback; apply is simulated-only and mutates stored evidence in
the demo DB so the rule re-evaluates to PASS on the next assessment run.
"""
from __future__ import annotations

import json
import time
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

try:
    from .ai import ai_service
    from .ai.schemas import FindingContext
    from .database import get_db
    from .fixpilot_store import PlanRecord, audit, get_plan, list_audit, save_plan, set_status
    from .security import require_role, role_of
    _MODELS_PKG = ".models.models"
except ImportError:  # allow flat sys.path import in tests
    from ai import ai_service
    from ai.schemas import FindingContext
    from database import get_db
    from fixpilot_store import PlanRecord, audit, get_plan, list_audit, save_plan, set_status
    from security import require_role, role_of
    _MODELS_PKG = "models.models"


def _models():
    """Import ORM models lazily so a flat test import of this router never
    registers tables under a second module name (SQLAlchemy conflict)."""
    import importlib
    mod = importlib.import_module(_MODELS_PKG, __package__ or "app")
    return mod.Asset, mod.AuditEvent, mod.Finding, mod.VerificationResult

router = APIRouter(prefix="/api/remediation", tags=["remediation"])


class ProposeRequest(FindingContext):
    pass


class ActorRequest(BaseModel):
    actor: str = Field(default="operator")


@router.post("/propose", response_model=PlanRecord)
def propose(req: ProposeRequest, authorization: str | None = Header(default=None),
             x_role: str | None = Header(default=None)):
    require_role("operator", role_of(authorization, x_role))
    plan = ai_service.generate_remediation(FindingContext(**req.model_dump()))
    rec = PlanRecord(id=f"plan-{uuid.uuid4().hex[:8]}", finding_id=req.finding_id,
                     payload=plan.model_dump())
    return save_plan(rec)


@router.post("/{plan_id}/approve", response_model=PlanRecord)
def approve(plan_id: str, req: ActorRequest | None = None,
            authorization: str | None = Header(default=None),
            x_role: str | None = Header(default=None)):
    require_role("operator", role_of(authorization, x_role))
    rec = set_status(plan_id, "approved", actor=(req.actor if req else "operator"))
    if not rec:
        raise HTTPException(404, "plan not found")
    return rec


@router.post("/{plan_id}/reject", response_model=PlanRecord)
def reject(plan_id: str, req: ActorRequest | None = None,
           authorization: str | None = Header(default=None),
           x_role: str | None = Header(default=None)):
    require_role("operator", role_of(authorization, x_role))
    rec = set_status(plan_id, "rejected", actor=(req.actor if req else "operator"))
    if not rec:
        raise HTTPException(404, "plan not found")
    return rec


@router.post("/{plan_id}/simulate", response_model=PlanRecord)
def simulate(plan_id: str, req: ActorRequest | None = None,
             authorization: str | None = Header(default=None),
             x_role: str | None = Header(default=None)):
    """Simulated execution only: labels result simulated, records outcome."""
    require_role("operator", role_of(authorization, x_role))
    rec = get_plan(plan_id)
    if not rec:
        raise HTTPException(404, "plan not found")
    if rec.status not in ("approved", "proposed", "simulated"):
        raise HTTPException(409, "approve the plan before simulating")
    steps = rec.payload.get("verification_steps", [])
    rec.payload["simulation"] = {
        "simulated": True,
        "steps_executed": steps,
        "outcome": "simulated-success (advisory only; no production change)",
    }
    save_plan(rec)
    return set_status(plan_id, "simulated",
                      actor=(req.actor if req else "operator"),
                      detail="simulated execution; no production change",
                      simulated=True)


class VerifyRequest(BaseModel):
    checks_passed: bool = False
    actor: str = "operator"
    evidence: str = ""


@router.post("/{plan_id}/verify", response_model=PlanRecord)
def verify(plan_id: str, req: VerifyRequest,
           authorization: str | None = Header(default=None),
           x_role: str | None = Header(default=None)):
    """Never claims success until checks actually pass: requires checks_passed."""
    require_role("operator", role_of(authorization, x_role))
    rec = get_plan(plan_id)
    if not rec:
        raise HTTPException(404, "plan not found")
    if not req.checks_passed:
        raise HTTPException(409, "verification checks did not pass; success not claimed")
    rec.payload["verification"] = {"passed": True, "evidence": req.evidence}
    save_plan(rec)
    return set_status(plan_id, "verified", actor=req.actor,
                      detail=req.evidence or "checks passed")


@router.post("/{plan_id}/reopen", response_model=PlanRecord)
def reopen(plan_id: str, req: ActorRequest | None = None,
           authorization: str | None = Header(default=None),
           x_role: str | None = Header(default=None)):
    """Reopen a verified plan for rework; retains history via the audit log."""
    require_role("operator", role_of(authorization, x_role))
    rec = get_plan(plan_id)
    if not rec:
        raise HTTPException(404, "plan not found")
    if rec.status != "verified":
        raise HTTPException(409, "only a verified plan can be reopened")
    return set_status(plan_id, "approved", actor=(req.actor if req else "operator"),
                      detail="reopened for rework; prior verification retained in audit")


class TaskRequest(BaseModel):
    owner: str = Field(default="", max_length=120)
    due_date: str = Field(default="", max_length=10)
    note: str = Field(default="", max_length=1000)
    actor: str = Field(default="operator")


@router.post("/{plan_id}/task", response_model=PlanRecord)
def set_task(plan_id: str, req: TaskRequest,
             authorization: str | None = Header(default=None),
             x_role: str | None = Header(default=None)):
    """Assign an owner / due date / tracking note to a plan (remediation task).

    Task metadata lives in the plan payload and every change is audit-logged;
    it never alters the plan lifecycle status.
    """
    require_role("operator", role_of(authorization, x_role))
    rec = get_plan(plan_id)
    if not rec:
        raise HTTPException(404, "plan not found")
    owner = (req.owner or "").strip()
    due = (req.due_date or "").strip()
    if due:
        import datetime as _dt
        try:
            _dt.date.fromisoformat(due)
        except ValueError:
            raise HTTPException(422, "due_date must be YYYY-MM-DD")
    payload = dict(rec.payload)
    payload["task"] = {"owner": owner, "due_date": due,
                       "note": (req.note or "").strip(),
                       "updated_by": (req.actor or "operator").strip() or "operator",
                       "updated_at": time.time()}
    rec.payload = payload
    rec = save_plan(rec)
    audit("task_assigned", plan_id, actor=(req.actor or "operator"),
          detail=f"owner={owner or '-'} due={due or '-'}")
    return rec


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


@router.post("/{plan_id}/apply")
def apply(plan_id: str, db: Session = Depends(get_db),
          authorization: str | None = Header(default=None),
          x_role: str | None = Header(default=None)):
    """Apply a SIMULATED fix to stored evidence (demo only). Re-run the assessment to verify."""
    role = role_of(authorization, x_role)
    require_role("operator", role)
    Asset, AuditEvent, Finding, VerificationResult = _models()
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
    db.add(AuditEvent(actor=role, action="fix_applied",
                      detail=f"plan={plan_id} rule={f.rule_id} asset={f.asset_id} (simulated)"[:2000]))
    db.commit()
    return {"plan_id": plan_id, "rule_id": f.rule_id, "asset_id": f.asset_id, "note": note, "simulated": True}


@router.get("/{plan_id}/audit")
def plan_audit(plan_id: str):
    return {"plan_id": plan_id, "events": list_audit(plan_id)}


@router.get("/audit-all")
def all_audit():
    return {"events": list_audit()}


@router.get("/ai/status")
def ai_status():
    return ai_service.status()
