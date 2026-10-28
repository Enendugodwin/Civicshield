"""FixPilot remediation plan store + audit log (SQLite/SQLAlchemy-free minimal).

Uses a tiny sqlite3-backed store so dependencies stay minimal (stdlib +
fastapi/pydantic only). Advisory/simulated only: never touches production.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "fixpilot.db"
_lock = threading.Lock()


class PlanRecord(BaseModel):
    id: str = Field(min_length=1)
    finding_id: str = Field(min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)
    status: str = Field(default="proposed")  # proposed|approved|rejected|simulated|verified
    simulated: bool = False
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)


def _connect(db_path: Path | None = None) -> sqlite3.Connection:
    path = Path(db_path) if db_path else DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute(
        "CREATE TABLE IF NOT EXISTS plans"
        "(id TEXT PRIMARY KEY, finding_id TEXT, payload TEXT, status TEXT,"
        " simulated INTEGER, created_at REAL, updated_at REAL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS audit"
        "(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT,"
        " action TEXT, plan_id TEXT, detail TEXT)"
    )
    return conn


def audit(action: str, plan_id: str, actor: str = "operator",
          detail: str = "", db_path: Path | None = None) -> None:
    with _lock, _connect(db_path) as conn:
        conn.execute(
            "INSERT INTO audit(ts, actor, action, plan_id, detail) VALUES(?,?,?,?,?)",
            (time.time(), actor, action, plan_id, detail),
        )
        conn.commit()


def save_plan(rec: PlanRecord, db_path: Path | None = None) -> PlanRecord:
    with _lock, _connect(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO plans VALUES(?,?,?,?,?,?,?)",
            (rec.id, rec.finding_id, json.dumps(rec.payload), rec.status,
             int(rec.simulated), rec.created_at, time.time()),
        )
        conn.commit()
    audit("plan_saved", rec.id, detail=f"status={rec.status}", db_path=db_path)
    return rec


def get_plan(plan_id: str, db_path: Path | None = None) -> PlanRecord | None:
    with _lock, _connect(db_path) as conn:
        row = conn.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
    if not row:
        return None
    return PlanRecord(id=row[0], finding_id=row[1], payload=json.loads(row[2]),
                      status=row[3], simulated=bool(row[4]),
                      created_at=row[5], updated_at=row[6])


def set_status(plan_id: str, status: str, actor: str = "operator",
               detail: str = "", simulated: bool | None = None,
               db_path: Path | None = None) -> PlanRecord | None:
    rec = get_plan(plan_id, db_path)
    if not rec:
        return None
    rec.status = status
    rec.updated_at = time.time()
    if simulated is not None:
        rec.simulated = simulated
    with _lock, _connect(db_path) as conn:
        conn.execute(
            "UPDATE plans SET status=?, simulated=?, updated_at=? WHERE id=?",
            (rec.status, int(rec.simulated), rec.updated_at, rec.id),
        )
        conn.commit()
    audit(f"plan_{status}", plan_id, actor=actor, detail=detail, db_path=db_path)
    return rec


def list_audit(plan_id: str | None = None, db_path: Path | None = None) -> list[dict]:
    with _lock, _connect(db_path) as conn:
        if plan_id:
            rows = conn.execute(
                "SELECT ts, actor, action, plan_id, detail FROM audit WHERE plan_id=? ORDER BY ts",
                (plan_id,)).fetchall()
        else:
            rows = conn.execute(
                "SELECT ts, actor, action, plan_id, detail FROM audit ORDER BY ts").fetchall()
    return [{"ts": r[0], "actor": r[1], "action": r[2], "plan_id": r[3], "detail": r[4]} for r in rows]
