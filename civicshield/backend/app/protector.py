"""Phase 6 continuous protector: scheduled + event-driven reassessment.

- Event hooks (`notify_event`) are non-blocking: the request path only
  enqueues, a daemon worker coalesces bursts and runs one reassessment.
- The scheduler thread runs a full reassessment every
  `protector.interval_seconds` when `protector.enabled` is set.
- Every run diffs open findings before/after and records posture-change
  notifications (opened / reopened / resolved) plus stale-evidence drift.
- Threads are stdlib only; tests call `run_protection` synchronously and
  drain the queue with `process_queue_sync`.
"""
from __future__ import annotations

import json
import os
import queue
import threading
import time
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app import governance
from app.database import SessionLocal
from app.models.models import (Asset, AuditEvent, Finding, ProtectionNotification,
                               ProtectionRun)

_Q: "queue.Queue[Dict[str, Any]]" = queue.Queue()
_LOCK = threading.Lock()
_STARTED = False
_LAST_EVENT_RUN = 0.0
EVENT_COALESCE_SECONDS = 5.0


def _open_keys(db: Session) -> Dict[tuple, Dict[str, Any]]:
    rows = db.query(Finding).all()
    out = {}
    for f in rows:
        if (f.workflow or "open") in ("resolved", "false_positive"):
            continue
        out[(f.rule_id or "", str(f.asset_id or ""))] = {
            "id": f.id, "severity": f.severity or ""}
    return out


def _asset_map(db: Session) -> Dict[str, Asset]:
    return {str(a.id): a for a in db.query(Asset).all()}


def _notify(db: Session, kind: str, title: str, detail: str = "",
            finding_id: int = 0, run_id: int = 0) -> ProtectionNotification:
    n = ProtectionNotification(kind=kind, title=title[:500], detail=detail[:2000],
                               finding_id=finding_id, run_id=run_id,
                               created_at=time.time())
    db.add(n)
    db.flush()
    return n


def run_protection(db: Session, trigger: str = "manual", actor: str = "system") -> Dict[str, Any]:
    """One full reassessment: detection + architecture checks, diff, notify."""
    from app import detection  # lazy: avoid import cycles
    from app.arch_checks import service as arch_checks

    started = time.time()
    run = ProtectionRun(trigger=trigger, status="running", actor=actor,
                        started_at=started)
    db.add(run)
    db.flush()

    before = _open_keys(db)
    assets = _asset_map(db)
    detail: Dict[str, Any] = {"before_open": len(before)}
    try:
        det = detection.run_detection(db, scope="all",
                                      actor=f"protector:{actor or 'system'}")
        arch = arch_checks.raise_findings(db, None, actor=f"protector:{actor or 'system'}")
        detail["detection"] = {
            "run_id": det.get("run_id"), "assets": det.get("assets"),
            "outcomes": det.get("outcomes"), "vulnerabilities": det.get("vulnerabilities")}
        detail["arch_checks"] = {
            "created": arch.get("created", 0), "reopened": arch.get("reopened", 0),
            "resolved_stale": arch.get("resolved_stale", 0)}
    except Exception as e:  # never leave a run stuck in "running"
        run.status = "failed"
        run.finished_at = time.time()
        run.detail_json = json.dumps({**detail, "error": str(e)[:500]})
        db.commit()
        db.refresh(run)
        _notify(db, "run_failed", f"Protection run failed ({trigger})",
                str(e)[:500], run_id=run.id)
        db.add(AuditEvent(actor=actor, action="protection_run_failed",
                          detail=f"run={run.id} trigger={trigger} error={str(e)[:200]}"))
        db.commit()
        return {"run_id": run.id, "trigger": trigger, "status": "failed",
                "error": str(e)[:500]}

    after = _open_keys(db)
    opened = reopened = resolved = 0
    for key, info in after.items():
        if key not in before:
            opened += 1
            a = assets.get(key[1])
            _notify(db, "finding_opened",
                    f"New finding {key[0]} on {governance.asset_label(a, key[1])}",
                    f"severity={info['severity']} trigger={trigger}",
                    finding_id=info["id"], run_id=run.id)
        elif before[key]["severity"] != info["severity"]:
            reopened += 1
            a = assets.get(key[1])
            _notify(db, "finding_reopened",
                    f"Finding {key[0]} changed on {governance.asset_label(a, key[1])}",
                    (f"severity {before[key]['severity']} -> {info['severity']} "
                     f"trigger={trigger}"),
                    finding_id=info["id"], run_id=run.id)
    for key, info in before.items():
        if key not in after:
            resolved += 1
            a = assets.get(key[1])
            _notify(db, "finding_resolved",
                    f"Finding {key[0]} cleared on {governance.asset_label(a, key[1])}",
                    f"trigger={trigger}", finding_id=info["id"], run_id=run.id)

    # Stale-evidence drift: notify only when the count changes since last run.
    try:
        stale_now = int(detection.posture(db).get("assets_stale", 0))
    except Exception:
        stale_now = -1
    last_stale_raw = governance.get_setting(db, "protector.last_stale_count", -1)
    try:
        last_stale = int(last_stale_raw)
    except (TypeError, ValueError):
        last_stale = -1
    if stale_now >= 0 and stale_now != last_stale:
        _notify(db, "evidence_stale",
                f"Stale evidence on {stale_now} asset(s)",
                f"was={last_stale if last_stale >= 0 else 'unknown'} trigger={trigger}",
                run_id=run.id)
        governance.set_setting(db, "protector.last_stale_count", stale_now, actor)

    run.status = "complete"
    run.findings_opened = opened
    run.findings_reopened = reopened
    run.findings_resolved = resolved
    run.finished_at = time.time()
    run.detail_json = json.dumps({**detail, "after_open": len(after)})
    db.commit()
    db.refresh(run)
    db.add(AuditEvent(actor=actor, action="protection_run",
                      detail=(f"run={run.id} trigger={trigger} opened={opened} "
                              f"reopened={reopened} resolved={resolved}")))
    db.commit()

    # Retention: cap runs, drop old acked notifications.
    try:
        keep = int(governance.get_setting(db, "protector.keep_runs", 50))
        ids = [r.id for r in db.query(ProtectionRun.id)
               .order_by(ProtectionRun.id.desc()).all()]
        for stale_id in ids[max(keep, 1):]:
            db.query(ProtectionRun).filter(ProtectionRun.id == stale_id).delete()
        days = float(governance.get_setting(db, "protector.notify_retention_days", 30))
        cutoff = time.time() - days * 86400
        db.query(ProtectionNotification).filter(
            ProtectionNotification.ack == 1,
            ProtectionNotification.created_at < cutoff).delete()
        db.commit()
    except Exception:
        db.rollback()
    return {"run_id": run.id, "trigger": trigger, "status": "complete",
            "opened": opened, "reopened": reopened, "resolved": resolved,
            "stale_assets": stale_now}


def notify_event(kind: str, detail: str = "") -> None:
    """Non-blocking hook for mutation endpoints. Never raises."""
    try:
        _Q.put_nowait({"kind": kind, "detail": detail[:200], "at": time.time()})
        ensure_started()
    except Exception:
        pass


def process_queue_sync(db: Optional[Session] = None) -> List[Dict[str, Any]]:
    """Drain pending events into one reassessment. Used by tests and the worker."""
    pending: List[Dict[str, Any]] = []
    while True:
        try:
            pending.append(_Q.get_nowait())
        except queue.Empty:
            break
    if not pending:
        return []
    kinds = sorted({p.get("kind", "event") for p in pending})
    own = db is None
    if own:
        db = SessionLocal()
    try:
        return [run_protection(db, trigger=f"event:{'+'.join(kinds)}",
                               actor="protector")]
    finally:
        if own:
            db.close()


def queue_depth() -> int:
    return _Q.qsize()


def _worker_loop() -> None:
    global _LAST_EVENT_RUN
    while True:
        try:
            _Q.get(timeout=1.0)
        except queue.Empty:
            continue
        # Coalesce bursts: drain the rest, run at most every few seconds.
        drained = 1
        while True:
            try:
                _Q.get_nowait()
                drained += 1
            except queue.Empty:
                break
        wait = EVENT_COALESCE_SECONDS - (time.time() - _LAST_EVENT_RUN)
        if wait > 0:
            time.sleep(wait)
        try:
            db = SessionLocal()
            try:
                run_protection(db, trigger="event", actor="protector")
            finally:
                db.close()
        except Exception:
            pass
        _LAST_EVENT_RUN = time.time()


def _scheduler_loop() -> None:
    while True:
        try:
            time.sleep(5)
            db = SessionLocal()
            try:
                enabled = str(governance.get_setting(db, "protector.enabled", "1")) == "1"
                if os.getenv("PROTECTOR_ENABLED", "").lower() in ("0", "false", "off"):
                    enabled = False
                if not enabled:
                    continue
                try:
                    interval = max(60, min(86400, int(float(
                        os.getenv("PROTECTOR_INTERVAL_SECONDS", "") or
                        governance.get_setting(db, "protector.interval_seconds", 3600)))))
                except (TypeError, ValueError):
                    interval = 3600
                try:
                    last = float(governance.get_setting(db, "protector.last_scheduled", 0))
                except (TypeError, ValueError):
                    last = 0
                if time.time() - last < interval:
                    continue
                governance.set_setting(db, "protector.last_scheduled", time.time(),
                                       "protector")
                run_protection(db, trigger="scheduled", actor="protector")
            finally:
                db.close()
        except Exception:
            pass


def ensure_started() -> bool:
    """Start worker + scheduler daemons once. Safe to call repeatedly."""
    global _STARTED
    if os.getenv("CIVICSHIELD_NO_THREADS", "").lower() in ("1", "true", "yes"):
        return False  # tests drive run_protection/process_queue_sync directly
    with _LOCK:
        if _STARTED:
            return True
        for target, name in ((_worker_loop, "protector-events"),
                            (_scheduler_loop, "protector-schedule")):
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
        _STARTED = True
    return True


def enable_wal() -> str:
    """WAL + busy timeout so the worker and request threads do not lock each other."""
    from sqlalchemy import text as _text
    try:
        with SessionLocal() as db:
            mode = db.execute(_text("PRAGMA journal_mode=WAL")).scalar()
            db.execute(_text("PRAGMA busy_timeout=5000"))
            db.commit()
        return str(mode)
    except Exception as e:
        return f"unavailable: {e}"[:200]


def status(db: Session) -> Dict[str, Any]:
    last = db.query(ProtectionRun).order_by(ProtectionRun.id.desc()).first()
    unacked = db.query(ProtectionNotification).filter(
        ProtectionNotification.ack == 0).count()
    return {
        "enabled": str(governance.get_setting(db, "protector.enabled", "1")) == "1",
        "interval_seconds": governance.get_setting(db, "protector.interval_seconds", 3600),
        "keep_runs": governance.get_setting(db, "protector.keep_runs", 50),
        "pending_events": queue_depth(),
        "unacked_notifications": unacked,
        "last_run": ({
            "id": last.id, "trigger": last.trigger, "status": last.status,
            "opened": last.findings_opened, "reopened": last.findings_reopened,
            "resolved": last.findings_resolved, "started_at": last.started_at,
            "finished_at": last.finished_at} if last else None),
    }
