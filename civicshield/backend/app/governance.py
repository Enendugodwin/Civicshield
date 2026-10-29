"""Phase 6 governance: settings, actor identity, audit hash chain, policies.

- AppSetting rows hold protector + policy configuration (no new tables per knob).
- Actor identity prefers the demo `X-User` header and falls back to the role;
  both are demo-grade and documented as such in /api/me.
- Audit integrity: a mapper listener chains every AuditEvent insert
  (prev_hash -> entry_hash) regardless of which module wrote it. Legacy rows
  are backfilled once in id order; verify recomputes the full chain.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from typing import Any

from sqlalchemy import event, text
from sqlalchemy.orm import Session

from app.models.models import AppSetting, Asset, AuditEvent

GENESIS = "GENESIS"

DEFAULTS = {
    "protector.enabled": "1",
    "protector.interval_seconds": "3600",
    "protector.keep_runs": "50",
    "protector.notify_retention_days": "30",
    "protector.last_scheduled": "0",
    "protector.last_stale_count": "-1",
    "governance.require_distinct_approver": "0",
}

_USER_RE = re.compile(r"^[A-Za-z0-9 _.\-@]{1,64}$")


def actor_of(authorization: str | None = None, x_role: str | None = None,
             x_user: str | None = None) -> str:
    """Best-effort demo identity: explicit user header, else role string."""
    if x_user and _USER_RE.match(x_user.strip()):
        return x_user.strip()
    from app.security import role_of
    return role_of(authorization, x_role)


def asset_label(asset: Asset | None, asset_id: Any = None) -> str:
    """Hostname-first label; never a bare 'asset N'."""
    if asset is not None:
        if getattr(asset, "hostname", ""):
            return str(asset.hostname)
        if getattr(asset, "name", ""):
            return str(asset.name)
        asset_id = getattr(asset, "id", asset_id)
    return f"asset #{asset_id}"


def get_setting(db: Session, key: str, default: Any = None) -> Any:
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    if row is None:
        return DEFAULTS.get(key, default)
    try:
        return json.loads(row.value_json or "null")
    except (ValueError, TypeError):
        return DEFAULTS.get(key, default)


def set_setting(db: Session, key: str, value: Any, actor: str = "") -> Any:
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    payload = json.dumps(value)
    if row is None:
        db.add(AppSetting(key=key, value_json=payload, updated_by=actor,
                          updated_at=time.time()))
    else:
        row.value_json = payload
        row.updated_by = actor
        row.updated_at = time.time()
    db.commit()
    return value


def _chain(ts: float, actor: str, action: str, detail: str, prev: str) -> str:
    body = f"{prev}\n{float(ts or 0):.3f}\n{actor}\n{action}\n{detail}".encode()
    return hashlib.sha256(body).hexdigest()


_CHAIN_LOCK = threading.Lock()


@event.listens_for(AuditEvent, "after_insert")
def _chain_audit_row(mapper, connection, target) -> None:  # noqa: ANN001, ANN201
    """Chain every audit insert no matter which module wrote it.

    after_insert (not before_insert): the row already has its id, so each
    entry chains onto its immediate id-predecessor. This keeps multi-row
    single-flush writers (e.g. proposals apply) fork-free, since ordering
    follows emission order rather than listener scheduling. A process-wide
    lock narrows the cross-thread window; SQLite serializes the writers.
    """
    with _CHAIN_LOCK:
        if getattr(target, "entry_hash", ""):
            return  # already chained (backfill path sets hashes explicitly)
        try:
            prev = connection.execute(
                text("SELECT entry_hash FROM audit_events "
                     "WHERE id < :i ORDER BY id DESC LIMIT 1"),
                {"i": target.id}).scalar() or GENESIS
        except Exception:
            prev = GENESIS
        if not prev:
            prev = GENESIS
        try:
            row = connection.execute(
                text("SELECT ts, actor, action, detail FROM audit_events "
                     "WHERE id = :i"), {"i": target.id}).first()
        except Exception:
            row = None
        ts, actor, action, detail = (tuple(row) if row else
                                     (time.time(), "", "", ""))
        digest = _chain(ts, actor or "", action or "", detail or "", prev)
        try:
            connection.execute(
                text("UPDATE audit_events SET prev_hash = :p, entry_hash = :h "
                     "WHERE id = :i"), {"p": prev, "h": digest, "i": target.id})
        except Exception:
            return
        target.prev_hash = prev
        target.entry_hash = digest


def backfill_audit_chain(db: Session) -> int:
    """One-time migration: if ANY row is unchained, rebuild the whole chain
    in id order from GENESIS. New rows always carry the max id, so once the
    rebuild has run, the listener appends correctly and verify stays strict."""
    rows = db.query(AuditEvent).order_by(AuditEvent.id).all()
    if not rows:
        return 0
    if verify_audit_chain(db)["ok"]:
        return 0
    # Chain is missing, mis-ordered, or forked (e.g. a legacy multi-row
    # flush): rebuild the whole chain in id order from GENESIS. This is a
    # startup/migration repair; afterwards the listener appends correctly.
    prev = GENESIS
    for r in rows:
        if not r.ts:
            r.ts = time.time()
        r.prev_hash = prev
        r.entry_hash = _chain(r.ts, r.actor or "", r.action or "", r.detail or "", prev)
        prev = r.entry_hash
    db.commit()
    return len(rows)


def verify_audit_chain(db: Session) -> dict:
    """Recompute the full chain. Read-only: never mutates."""
    rows = db.query(AuditEvent).order_by(AuditEvent.id).all()
    prev = GENESIS
    for r in rows:
        if not getattr(r, "entry_hash", ""):
            return {"ok": False, "checked": r.id - 1 if r.id else 0,
                    "total": len(rows), "broken_at": r.id,
                    "reason": "unchained legacy row (run backfill at startup)"}
        if (r.prev_hash or GENESIS) != prev:
            return {"ok": False, "checked": r.id - 1, "total": len(rows),
                    "broken_at": r.id, "reason": "prev_hash linkage broken"}
        expect = _chain(r.ts, r.actor or "", r.action or "", r.detail or "",
                        r.prev_hash or GENESIS)
        if expect != r.entry_hash:
            return {"ok": False, "checked": r.id - 1, "total": len(rows),
                    "broken_at": r.id, "reason": "entry hash mismatch (tampered?)"}
        prev = r.entry_hash
    return {"ok": True, "checked": len(rows), "total": len(rows),
            "broken_at": None, "head": prev, "reason": ""}


def distinct_approver_required(db: Session) -> bool:
    return str(get_setting(db, "governance.require_distinct_approver", "0")) == "1"


def check_dual_control(db: Session, author: str, approver: str, what: str) -> None:
    """Raise 409 when policy requires a second pair of eyes and gets the same one."""
    from fastapi import HTTPException
    if distinct_approver_required(db) and (author or "") == (approver or ""):
        raise HTTPException(
            409, f"dual control: {what} requires an approver other than the author "
                 f"({author or 'unknown'})")
