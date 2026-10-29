"""Phase 7 versioned database migrations.

New tables are created by Base.metadata.create_all; this runner owns every
*alteration* of an existing table plus one-time data backfills. Each
migration is idempotent (PRAGMA-guarded) and recorded in the
``schema.version`` setting, so an old demo DB converges to the current
schema without silent drift. Add new schema changes here — never as ad-hoc
ALTERs elsewhere.
"""
from __future__ import annotations

import time
from typing import Callable, Dict, List

from sqlalchemy import text
from sqlalchemy.orm import Session

from app import governance
from app.database import Base, SessionLocal, engine

VERSION_KEY = "schema.version"


def _cols(conn, table: str) -> set:
    try:
        return {r[1] for r in conn.execute(
            text(f"PRAGMA table_info({table})")).fetchall()}
    except Exception:
        return set()


def _add_columns(conn, table: str, columns: List[tuple]) -> int:
    cols = _cols(conn, table)
    n = 0
    for name, ddl in columns:
        if cols and name not in cols:
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
            n += 1
    return n


def m002_findings_workflow(conn) -> str:
    n = _add_columns(conn, "findings", [
        ("workflow", "TEXT DEFAULT 'open'"),
        ("assignee", "TEXT DEFAULT ''"),
        ("resolution_reason", "TEXT DEFAULT ''")])
    return f"findings workflow columns (+{n})"


def m003_incidents_meta(conn) -> str:
    n = _add_columns(conn, "incidents", [
        ("severity", "TEXT DEFAULT 'medium'"),
        ("commander", "TEXT DEFAULT ''")])
    return f"incidents severity/commander (+{n})"


def m004_runs_scope(conn) -> str:
    n = _add_columns(conn, "assessment_runs", [("scope", "TEXT DEFAULT 'all'")])
    return f"assessment_runs scope (+{n})"


def m005_relationship_provenance(conn) -> str:
    n = _add_columns(conn, "relationships", [
        ("provenance", "TEXT DEFAULT 'manual'"),
        ("evidence_ref", "TEXT DEFAULT ''"),
        ("created_at", "REAL DEFAULT 0"),
        ("updated_at", "REAL DEFAULT 0")])
    return f"relationships provenance/evidence/timestamps (+{n})"


def m006_audit_chain(conn) -> str:
    return f"audit hash-chain columns (+{_add_columns(conn, 'audit_events', [("prev_hash", "TEXT DEFAULT ''"), ('entry_hash', "TEXT DEFAULT ''")])})"


def m007_phase6_tables(conn) -> str:
    Base.metadata.create_all(bind=engine)
    return "phase6 tables ensured (app_settings, detection_rules, protection_runs, protection_notifications)"


def m008_demo_env(conn) -> str:
    db = SessionLocal()
    try:
        if governance.get_setting(db, "demo.env", None) is None:
            governance.set_setting(db, "demo.env", "a", "migrate")
            return "demo.env defaulted to a"
        return "demo.env already set"
    finally:
        db.close()


MIGRATIONS: List[Dict] = [
    {"version": 1, "id": "001_initial",
     "description": "Baseline tables via create_all.", "fn": None},
    {"version": 2, "id": "002_findings_workflow",
     "description": "findings: workflow lifecycle columns.", "fn": m002_findings_workflow},
    {"version": 3, "id": "003_incidents_meta",
     "description": "incidents: severity + commander.", "fn": m003_incidents_meta},
    {"version": 4, "id": "004_runs_scope",
     "description": "assessment_runs: scope column.", "fn": m004_runs_scope},
    {"version": 5, "id": "005_relationship_provenance",
     "description": "relationships: provenance/evidence/timestamps.", "fn": m005_relationship_provenance},
    {"version": 6, "id": "006_audit_chain",
     "description": "audit_events: prev_hash/entry_hash chain columns.", "fn": m006_audit_chain},
    {"version": 7, "id": "007_phase6_tables",
     "description": "Phase 6 tables + audit backfill.", "fn": m007_phase6_tables},
    {"version": 8, "id": "008_demo_env",
     "description": "demo.env setting default.", "fn": m008_demo_env},
]

LATEST = MIGRATIONS[-1]["version"]


def current_version(db: Session) -> int:
    try:
        return int(governance.get_setting(db, VERSION_KEY, 0))
    except (TypeError, ValueError):
        return 0


def migrate(db: Session | None = None) -> dict:
    """Apply pending migrations in order. Idempotent; safe to run every boot."""
    own = db is None
    if own:
        db = SessionLocal()
    try:
        Base.metadata.create_all(bind=engine)
        applied: List[dict] = []
        cur = current_version(db)
        with engine.begin() as conn:
            for m in MIGRATIONS:
                if m["version"] <= cur:
                    continue
                fn: Callable | None = m["fn"]
                note = fn(conn) if fn else "create_all"
                applied.append({"version": m["version"], "id": m["id"],
                                "note": note})
                cur = m["version"]
        if applied:
            governance.set_setting(db, VERSION_KEY, cur, "migrate")
            if cur >= 7:
                governance.backfill_audit_chain(db)
        return {"version": cur, "latest": LATEST, "current": cur == LATEST,
                "applied": applied}
    finally:
        if own:
            db.close()


def describe(db: Session) -> dict:
    cur = current_version(db)
    return {"version": cur, "latest": LATEST, "current": cur == LATEST,
            "migrations": [
                {"version": m["version"], "id": m["id"],
                 "description": m["description"],
                 "applied": m["version"] <= cur} for m in MIGRATIONS]}
