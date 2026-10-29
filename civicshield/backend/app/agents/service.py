"""Multi-agent orchestration service: deterministic routing, bounded execution.

An investigation runs the router's plan batch by batch (in-process,
sequential within a batch — documented, not parallel threads against
SQLite). Each specialist gets at most two attempts; a failure is recorded
and the run continues with the remaining valid results. Cancellation is
honored between batches; tasks already running finish but their results
are discarded.

The merged outcome deduplicates recommendations, reports severity
disagreements and failures as conflicts, tracks missing evidence, and ends
with exactly one shared-provider synthesis call for the executive summary
— offline template when the provider is unavailable.
"""
from __future__ import annotations

import json
import time

from app.agents import registry, router, specialists
from app.models.models import AgentRun, AgentTask, AuditEvent

MAX_ATTEMPTS = 2
CANCELLED = "cancelled"


def _task_out(t: AgentTask) -> dict:
    try:
        result = json.loads(t.result_json or "{}")
    except (TypeError, ValueError):
        result = {}
    return {"id": t.id, "agent_id": t.agent_id, "batch": t.batch,
            "status": t.status, "attempts": t.attempts,
            "elapsed_ms": t.elapsed_ms, "error": t.error or "",
            "result": result}


def _run_out(run: AgentRun, tasks: list[AgentTask]) -> dict:
    try:
        summary = json.loads(run.summary_json or "{}")
    except (TypeError, ValueError):
        summary = {}
    try:
        plan = json.loads(run.plan_json or "[]")
    except (TypeError, ValueError):
        plan = []
    return {"id": run.id, "kind": run.kind, "ref": run.ref or "",
            "actor": run.actor or "", "status": run.status,
            "plan": plan, "tasks": [_task_out(t) for t in tasks],
            "summary": summary, "created_at": run.created_at}


def _synthesize(kind: str, merged: dict) -> dict:
    """One shared-provider call for the executive summary; template fallback."""
    facts = merged["facts"]
    deterministic = (
        f"Investigation '{kind}': {merged['done']} specialist(s) completed, "
        f"{merged['failed']} failed. Key facts: "
        + ("; ".join(facts[:6]) if facts else "no new facts")
        + f". Open recommendations: {len(merged['recommendations'])}.")
    try:
        from app.ai.config import load_ai_config
        from app.ai import muse_spark_adapter as adapter
        config = load_ai_config()
        if not config.model_enabled:
            raise RuntimeError("model-disabled")
        res = adapter.complete_text(
            "You are a defensive security coordinator. Summarize the merged "
            "specialist results below in 3 short sentences for an operator. "
            "State only what the results support; name unknowns as unknowns.",
            json.dumps({"kind": kind, "facts": facts[:12],
                        "recommendations": merged["recommendations"][:8],
                        "conflicts": merged["conflicts"][:6]})[:6000],
            config)
        if res.ok and res.text:
            return {"text": res.text.strip()[:2000],
                    "model_used": config.model_id}
    except Exception:
        pass
    return {"text": deterministic, "model_used": "rules"}


def _merge(kind: str, results: dict[str, dict]) -> dict:
    facts: list[str] = []
    recommendations: list[dict] = []
    missing: list[str] = []
    for agent_id, r in results.items():
        facts.append(f"{agent_id}: {r.get('summary', '')}")
        for rec in r.get("recommendations", []) or []:
            recommendations.append({"agent_id": agent_id,
                                    "text": str(rec if isinstance(rec, str)
                                                else rec.get("proposal") or rec.get("objective")
                                                or rec.get("step") or rec)[:500]})
        items = r.get("items", []) or []
        if not items and agent_id in ("threat", "incident"):
            missing.append(f"{agent_id}: no live records to analyze")
    seen: dict[str, dict] = {}
    dupes = 0
    for rec in recommendations:
        key = rec["text"].lower()
        if key in seen:
            dupes += 1
            continue
        seen[key] = rec
    recommendations = list(seen.values())
    sev_by_asset: dict[str, dict[str, str]] = {}
    for agent_id, r in results.items():
        for it in r.get("items", []) or []:
            asset = str(it.get("asset") or it.get("asset_id") or "")
            sev = str(it.get("severity") or "")
            if asset and sev:
                sev_by_asset.setdefault(asset, {})[agent_id] = sev
    conflicts = []
    for asset, votes in sev_by_asset.items():
        if len(set(votes.values())) > 1:
            conflicts.append({"type": "severity_disagreement", "asset": asset,
                              "votes": votes,
                              "note": "Agents disagree on severity; use the higher "
                                      "one until evidence decides."})
    if dupes:
        conflicts.append({"type": "duplicate_recommendations", "count": dupes,
                          "note": "Identical recommendations from multiple "
                                  "agents were merged into one."})
    merged = {"facts": facts, "recommendations": recommendations,
              "missing_evidence": sorted(set(missing)), "conflicts": conflicts,
              "done": len(results), "failed": 0}
    merged["executive"] = _synthesize(kind, merged)
    return merged


def run_investigation(db, kind: str, ref: str = "", actor: str = "system") -> dict:
    steps = router.plan(kind)  # KeyError/ValueError -> 4xx in the endpoint
    seen_inputs: set[tuple] = set()
    run = AgentRun(kind=kind, ref=(ref or "")[:200], actor=actor or "",
                   status="running", plan_json=json.dumps(steps))
    db.add(run)
    db.flush()
    tasks: list[AgentTask] = []
    for s in steps:
        key = (s["agent_id"], ref or "")
        if key in seen_inputs:
            continue  # duplicate-task suppression within a run
        seen_inputs.add(key)
        tasks.append(AgentTask(run_id=run.id, agent_id=s["agent_id"],
                              batch=s["batch"], status="pending"))
    db.add_all(tasks)
    db.commit()

    results: dict[str, dict] = {}
    failures = 0
    for batch in sorted({t.batch for t in tasks}):
        if db.query(AgentRun).filter(AgentRun.id == run.id).first().status == CANCELLED:
            for t in tasks:
                if t.status in ("pending", "running"):
                    t.status = CANCELLED
            db.commit()
            break
        for t in [x for x in tasks if x.batch == batch]:
            if t.status == CANCELLED:
                continue
            t.status = "running"
            db.commit()
            started = time.time()
            outcome: dict | None = None
            err = ""
            while t.attempts < MAX_ATTEMPTS and outcome is None:
                t.attempts += 1
                try:
                    outcome = specialists.run(
                        t.agent_id, db, {"ref": ref or "", "kind": kind})
                except Exception as exc:  # noqa: BLE001 - recorded, run continues
                    err = f"{type(exc).__name__}: {exc}"[:500]
            t.elapsed_ms = int((time.time() - started) * 1000)
            if outcome is None:
                t.status = "failed"
                t.error = err or "unknown error"
                failures += 1
            else:
                t.status = "done"
                t.result_json = json.dumps(outcome)[:20000]
                results[t.agent_id] = outcome
            t.updated_at = time.time()
            db.commit()

    still_running = db.query(AgentRun).filter(AgentRun.id == run.id).first()
    if still_running.status == CANCELLED:
        final = CANCELLED
    elif failures and not results:
        final = "failed"
    elif failures:
        final = "partial"
    else:
        final = "complete"
    merged = _merge(kind, results)
    merged["failed"] = failures
    run.status = final
    run.summary_json = json.dumps(merged)[:60000]
    run.updated_at = time.time()
    db.add(AuditEvent(actor=actor or "system", action="agents_investigation",
                      detail=(f"run={run.id} kind={kind} ref={ref or '-'} "
                              f"status={final} done={len(results)} failed={failures}")))
    db.commit()
    db.refresh(run)
    for t in tasks:
        db.refresh(t)
    return _run_out(run, tasks)


def cancel_run(db, run_id: int, actor: str) -> dict:
    run = db.query(AgentRun).filter(AgentRun.id == run_id).first()
    if not run:
        raise KeyError(f"investigation {run_id} not found")
    if run.status not in ("running",):
        raise ValueError(f"investigation {run_id} is {run.status}, nothing to cancel")
    run.status = CANCELLED
    run.updated_at = time.time()
    n = 0
    for t in db.query(AgentTask).filter(AgentTask.run_id == run.id).all():
        if t.status in ("pending", "running"):
            t.status = CANCELLED
            n += 1
    db.add(AuditEvent(actor=actor or "system", action="agents_cancel",
                      detail=f"run={run_id} cancelled_tasks={n}"))
    db.commit()
    tasks = db.query(AgentTask).filter(AgentTask.run_id == run.id).all()
    return _run_out(run, tasks)
