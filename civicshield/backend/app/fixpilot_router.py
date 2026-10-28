"""FixPilot router: propose/approve/simulate/verify endpoints + audit log."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

try:
    from .ai import ai_service
    from .ai.schemas import FindingContext
    from .fixpilot_store import PlanRecord, get_plan, list_audit, save_plan, set_status
except ImportError:  # allow flat sys.path import in tests
    from ai import ai_service
    from ai.schemas import FindingContext
    from fixpilot_store import PlanRecord, get_plan, list_audit, save_plan, set_status

router = APIRouter(prefix="/api/remediation", tags=["remediation"])


class ProposeRequest(FindingContext):
    pass


class ActorRequest(BaseModel):
    actor: str = Field(default="operator")


@router.post("/propose", response_model=PlanRecord)
def propose(req: ProposeRequest):
    plan = ai_service.generate_remediation(FindingContext(**req.model_dump()))
    rec = PlanRecord(id=f"plan-{uuid.uuid4().hex[:8]}", finding_id=req.finding_id,
                     payload=plan.model_dump())
    return save_plan(rec)


@router.post("/{plan_id}/approve", response_model=PlanRecord)
def approve(plan_id: str, req: ActorRequest | None = None):
    rec = set_status(plan_id, "approved", actor=(req.actor if req else "operator"))
    if not rec:
        raise HTTPException(404, "plan not found")
    return rec


@router.post("/{plan_id}/reject", response_model=PlanRecord)
def reject(plan_id: str, req: ActorRequest | None = None):
    rec = set_status(plan_id, "rejected", actor=(req.actor if req else "operator"))
    if not rec:
        raise HTTPException(404, "plan not found")
    return rec


@router.post("/{plan_id}/simulate", response_model=PlanRecord)
def simulate(plan_id: str, req: ActorRequest | None = None):
    """Simulated execution only: labels result simulated, records outcome."""
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
def verify(plan_id: str, req: VerifyRequest):
    """Never claims success until checks actually pass: requires checks_passed."""
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
def reopen(plan_id: str, req: ActorRequest | None = None):
    """Reopen a verified plan for rework; retains history via the audit log."""
    rec = get_plan(plan_id)
    if not rec:
        raise HTTPException(404, "plan not found")
    if rec.status != "verified":
        raise HTTPException(409, "only a verified plan can be reopened")
    return set_status(plan_id, "approved", actor=(req.actor if req else "operator"),
                      detail="reopened for rework; prior verification retained in audit")


@router.get("/{plan_id}/audit")
def plan_audit(plan_id: str):
    return {"plan_id": plan_id, "events": list_audit(plan_id)}


@router.get("/audit-all")
def all_audit():
    return {"events": list_audit()}


@router.get("/ai/status")
def ai_status():
    return ai_service.status()
