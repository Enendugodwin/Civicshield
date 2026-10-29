"""Phase 6 protector HTTP surface: status, manual runs, config, notifications."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import governance, protector
from app.database import get_db
from app.models.models import AuditEvent, ProtectionNotification, ProtectionRun
from app.security import require_role, role_of

router = APIRouter(prefix="/api/protection", tags=["protection"])


class ConfigIn(BaseModel):
    enabled: bool | None = None
    interval_seconds: int | None = Field(default=None, ge=60, le=86400)
    keep_runs: int | None = Field(default=None, ge=5, le=500)
    notify_retention_days: int | None = Field(default=None, ge=1, le=365)


def _role(authorization, x_role):
    return role_of(authorization, x_role)


@router.get("/status", response_model=None)
def protection_status(db: Session = Depends(get_db)):
    return protector.status(db)


@router.post("/run", response_model=None)
def protection_run_now(db: Session = Depends(get_db),
                       authorization: str | None = Header(default=None),
                       x_role: str | None = Header(default=None),
                       x_user: str | None = Header(default=None)):
    require_role("operator", _role(authorization, x_role))
    actor = governance.actor_of(authorization, x_role, x_user)
    return protector.run_protection(db, trigger="manual", actor=actor)


@router.patch("/config", response_model=None)
def protection_config(body: ConfigIn, db: Session = Depends(get_db),
                      authorization: str | None = Header(default=None),
                      x_role: str | None = Header(default=None),
                      x_user: str | None = Header(default=None)):
    require_role("operator", _role(authorization, x_role))
    actor = governance.actor_of(authorization, x_role, x_user)
    changed = {}
    if body.enabled is not None:
        changed["protector.enabled"] = "1" if body.enabled else "0"
    if body.interval_seconds is not None:
        changed["protector.interval_seconds"] = int(body.interval_seconds)
    if body.keep_runs is not None:
        changed["protector.keep_runs"] = int(body.keep_runs)
    if body.notify_retention_days is not None:
        changed["protector.notify_retention_days"] = int(body.notify_retention_days)
    for key, value in changed.items():
        governance.set_setting(db, key, value, actor)
    db.add(AuditEvent(actor=actor, action="protection_config",
                      detail=",".join(f"{k}={v}" for k, v in changed.items()) or "noop"))
    db.commit()
    return {"changed": changed, **protector.status(db)}


@router.get("/runs", response_model=None)
def protection_runs(limit: int = 20, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 100))
    rows = (db.query(ProtectionRun).order_by(ProtectionRun.id.desc())
            .limit(limit).all())
    return {"runs": [{
        "id": r.id, "trigger": r.trigger, "status": r.status,
        "opened": r.findings_opened, "reopened": r.findings_reopened,
        "resolved": r.findings_resolved, "actor": r.actor,
        "started_at": r.started_at, "finished_at": r.finished_at} for r in rows]}


@router.get("/notifications", response_model=None)
def protection_notifications(unacked_only: bool = False, limit: int = 50,
                             db: Session = Depends(get_db)):
    limit = max(1, min(limit, 200))
    q = db.query(ProtectionNotification).order_by(ProtectionNotification.id.desc())
    if unacked_only:
        q = q.filter(ProtectionNotification.ack == 0)
    rows = q.limit(limit).all()
    return {"notifications": [{
        "id": n.id, "kind": n.kind, "title": n.title, "detail": n.detail,
        "finding_id": n.finding_id, "run_id": n.run_id, "ack": bool(n.ack),
        "created_at": n.created_at} for n in rows]}


@router.post("/notifications/{nid}/ack", response_model=None)
def protection_ack(nid: int, db: Session = Depends(get_db),
                   authorization: str | None = Header(default=None),
                   x_role: str | None = Header(default=None),
                   x_user: str | None = Header(default=None)):
    require_role("operator", _role(authorization, x_role))
    n = db.query(ProtectionNotification).filter(ProtectionNotification.id == nid).first()
    if not n:
        raise HTTPException(404, "notification not found")
    actor = governance.actor_of(authorization, x_role, x_user)
    n.ack = 1
    db.commit()
    db.add(AuditEvent(actor=actor, action="protection_notification_acked",
                      detail=f"id={nid} kind={n.kind}"))
    db.commit()
    return {"id": nid, "ack": True}
