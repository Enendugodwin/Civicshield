"""Phase 6 governance HTTP surface: policies + audit chain verification."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import governance
from app.database import get_db
from app.models.models import AuditEvent
from app.security import require_role, role_of

router = APIRouter(prefix="/api/governance", tags=["governance"])


class PoliciesIn(BaseModel):
    require_distinct_approver: bool | None = None


@router.get("/policies", response_model=None)
def get_policies(db: Session = Depends(get_db)):
    return {
        "require_distinct_approver": governance.distinct_approver_required(db),
        "note": ("When on, activating a detection draft needs an approver other "
                 "than its author. Enforced server-side."),
    }


@router.patch("/policies", response_model=None)
def set_policies(body: PoliciesIn, db: Session = Depends(get_db),
                 authorization: str | None = Header(default=None),
                 x_role: str | None = Header(default=None),
                 x_user: str | None = Header(default=None)):
    require_role("admin", role_of(authorization, x_role))
    actor = governance.actor_of(authorization, x_role, x_user)
    changed = {}
    if body.require_distinct_approver is not None:
        changed["governance.require_distinct_approver"] = (
            "1" if body.require_distinct_approver else "0")
    for key, value in changed.items():
        governance.set_setting(db, key, value, actor)
    db.add(AuditEvent(actor=actor, action="governance_policy_changed",
                      detail=",".join(f"{k}={v}" for k, v in changed.items()) or "noop"))
    db.commit()
    return {"changed": changed, **get_policies(db)}


@router.get("/audit-verify", response_model=None)
def audit_verify(db: Session = Depends(get_db)):
    """Recompute the audit hash chain. Read-only; reports first break, if any."""
    return governance.verify_audit_chain(db)


@router.get("/migrations", response_model=None)
def migration_status(db: Session = Depends(get_db)):
    """Versioned schema state. Migrations apply at startup; this is read-only."""
    from app import migrations
    return migrations.describe(db)
