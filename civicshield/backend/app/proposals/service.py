"""Proposal lifecycle: draft -> simulated -> approved -> applied.

Simulations run on in-memory copies of the inventory snapshot: AR-* checks
and attack-path analysis are recomputed for baseline and proposed graphs and
diffed. must_block criteria assert an (entry, target) pair has no path in the
simulated graph; must_keep criteria assert a relationship still exists.
"""
from __future__ import annotations

import json
import time

from app import attack_paths
from app.arch_checks import rules as arch_rules
from app.arch_checks import service as arch_checks
from app.arch_import import normalize as normalize
from app.models.models import (ArchProposal, ArchProposalChange, ArchSimRun,
                               Asset, AssetRelationship, AuditEvent, Service)

OPS = ("remove_edge", "add_edge", "update_asset")
DIFF_CAP = 50


def _payload(change: ArchProposalChange) -> dict:
    try:
        v = json.loads(change.payload_json or "{}")
        return v if isinstance(v, dict) else {}
    except (TypeError, ValueError):
        return {}


def _change_out(c: ArchProposalChange) -> dict:
    return {"id": c.id, "op": c.op, "payload": _payload(c)}


def _proposal_out(p: ArchProposal, db) -> dict:
    changes = (db.query(ArchProposalChange)
               .filter(ArchProposalChange.proposal_id == p.id)
               .order_by(ArchProposalChange.id).all())
    sims = (db.query(ArchSimRun).filter(ArchSimRun.proposal_id == p.id)
            .order_by(ArchSimRun.id).all())
    return {"id": p.id, "title": p.title, "status": p.status,
            "actor": p.actor or "", "rationale": p.rationale or "",
            "changes": [_change_out(c) for c in changes],
            "sim_runs": [{"id": s.id, "request": json.loads(s.request_json or "{}"),
                          "result": json.loads(s.result_json or "{}")}
                         for s in sims],
            "created_at": p.created_at}


def _get(db, pid: int) -> ArchProposal:
    p = db.query(ArchProposal).filter(ArchProposal.id == pid).first()
    if not p:
        raise KeyError(f"proposal {pid} not found")
    return p


def create(db, title: str, rationale: str = "", actor: str = "system") -> dict:
    title = (title or "").strip()
    if not title:
        raise ValueError("title is required")
    p = ArchProposal(title=title[:200], status="draft", actor=actor or "",
                     rationale=(rationale or "")[:2000])
    db.add(p)
    db.commit()
    db.refresh(p)
    db.add(AuditEvent(actor=actor or "system", action="proposal_created",
                      detail=f"proposal={p.id} title={p.title[:80]}"))
    db.commit()
    return _proposal_out(p, db)


def _validate_change(db, op: str, payload: dict) -> dict:
    """Normalize + validate now so stale references fail at entry, not at apply."""
    if op == "remove_edge":
        try:
            rid = int(payload.get("relationship_id"))
        except (TypeError, ValueError):
            raise ValueError("remove_edge needs an integer relationship_id")
        r = db.query(AssetRelationship).filter(AssetRelationship.id == rid).first()
        if not r:
            raise ValueError(f"relationship {rid} not found")
        return {"relationship_id": rid, "rel": r.rel,
                "source_id": r.source_id, "target_id": r.target_id}
    if op == "add_edge":
        st, tt = str(payload.get("source_type", "asset")), str(payload.get("target_type", "asset"))
        if st not in ("asset", "service") or tt not in ("asset", "service"):
            raise ValueError("source/target type must be asset or service")
        try:
            sid, tid = int(payload.get("source_id")), int(payload.get("target_id"))
        except (TypeError, ValueError):
            raise ValueError("add_edge needs integer source_id and target_id")
        for kind, rid in ((st, sid), (tt, tid)):
            exists = (db.query(Asset).filter(Asset.id == rid).first() if kind == "asset"
                      else db.query(Service).filter(Service.id == rid).first())
            if not exists:
                raise ValueError(f"{kind} {rid} not found")
        rel = str(payload.get("rel") or "").strip()
        if not rel:
            raise ValueError("add_edge needs a rel name")
        if (rel.lower() == "failover" and st == "asset" and tt == "asset" and sid == tid):
            raise ValueError("a device cannot fail over to itself")
        dup = db.query(AssetRelationship).filter(
            AssetRelationship.source_type == st, AssetRelationship.source_id == sid,
            AssetRelationship.target_type == tt, AssetRelationship.target_id == tid,
            AssetRelationship.rel == rel).first()
        if dup:
            raise ValueError("identical relationship already exists")
        return {"source_type": st, "source_id": sid, "target_type": tt,
                "target_id": tid, "rel": rel}
    if op == "update_asset":
        try:
            aid = int(payload.get("asset_id"))
        except (TypeError, ValueError):
            raise ValueError("update_asset needs an integer asset_id")
        a = db.query(Asset).filter(Asset.id == aid, Asset.retired == 0).first()
        if not a:
            raise ValueError(f"asset {aid} not found")
        out: dict = {"asset_id": aid}
        if "zone" in payload:
            z = str(payload.get("zone") or "").strip().lower()
            if z not in normalize.CANONICAL_ZONES:
                raise ValueError(f"unknown zone '{payload.get('zone')}'")
            out["zone"] = z
        if "criticality" in payload:
            c = str(payload.get("criticality") or "").strip().lower()
            if c not in normalize.CANONICAL_CRITICALITY:
                raise ValueError(f"unknown criticality '{payload.get('criticality')}'")
            out["criticality"] = c
        if len(out) == 1:
            raise ValueError("update_asset needs zone and/or criticality")
        return out
    raise ValueError(f"unknown op '{op}'; expected one of {', '.join(OPS)}")


def add_change(db, pid: int, op: str, payload: dict, actor: str = "system") -> dict:
    p = _get(db, pid)
    if p.status != "draft":
        raise ValueError(f"proposal {pid} is {p.status}; changes need draft status")
    clean = _validate_change(db, op, payload or {})
    c = ArchProposalChange(proposal_id=pid, op=op, payload_json=json.dumps(clean))
    db.add(c)
    db.add(AuditEvent(actor=actor or "system", action="proposal_change",
                      detail=f"proposal={pid} op={op} {json.dumps(clean)[:160]}"))
    db.commit()
    db.refresh(c)
    return _change_out(c)


def remove_change(db, pid: int, cid: int) -> dict:
    p = _get(db, pid)
    if p.status != "draft":
        raise ValueError(f"proposal {pid} is {p.status}; changes need draft status")
    c = db.query(ArchProposalChange).filter(
        ArchProposalChange.id == cid, ArchProposalChange.proposal_id == pid).first()
    if not c:
        raise KeyError(f"change {cid} not found in proposal {pid}")
    db.delete(c)
    db.commit()
    return {"proposal_id": pid, "removed": cid}


def _apply_to_snapshot(assets: dict[int, dict], rels: list[dict],
                       changes: list[dict]) -> tuple[dict[int, dict], list[dict], list[str]]:
    """Apply staged edits to snapshot copies. Returns (assets, rels, warnings)."""
    warnings: list[str] = []
    assets = {aid: dict(a) for aid, a in assets.items()}
    rels = [dict(r) for r in rels]
    by_id = {r["id"]: r for r in rels}
    new_seq = 0
    for ch in changes:
        op, pay = ch["op"], ch["payload"] if isinstance(ch.get("payload"), dict) else {}
        if op == "remove_edge":
            rid = pay.get("relationship_id")
            if rid in by_id:
                rels = [r for r in rels if r["id"] != rid]
                del by_id[rid]
            else:
                warnings.append(f"remove_edge: relationship {rid} already absent")
        elif op == "add_edge":
            new_seq += 1
            rels.append({"id": f"new-{new_seq}",
                         "source_type": pay.get("source_type", "asset"),
                         "source_id": pay.get("source_id"),
                         "target_type": pay.get("target_type", "asset"),
                         "target_id": pay.get("target_id"),
                         "rel": pay.get("rel", ""), "provenance": "configured"})
        elif op == "update_asset":
            aid = pay.get("asset_id")
            if aid in assets:
                for k in ("zone", "criticality"):
                    if k in pay:
                        assets[aid][k] = pay[k]
            else:
                warnings.append(f"update_asset: asset {aid} absent from snapshot")
    return assets, rels, warnings


def _hit_key(h: dict) -> tuple:
    return (h["rule_id"], str(h["asset_id"]))


def _path_sig(p: dict) -> tuple:
    return (p["entry_id"], p["target_id"],
            tuple((h.get("from_id"), h.get("to_id"), h.get("rel")) for h in p["hops"]))


def simulate(db, pid: int, must_block: list[dict] | None = None,
             must_keep: list[dict] | None = None,
             actor: str = "system") -> dict:
    p = _get(db, pid)
    if p.status not in ("draft", "simulated"):
        raise ValueError(f"proposal {pid} is {p.status}; simulate needs draft/simulated")
    changes = (db.query(ArchProposalChange)
               .filter(ArchProposalChange.proposal_id == pid)
               .order_by(ArchProposalChange.id).all())
    if not changes:
        raise ValueError("proposal has no changes to simulate")
    must_block = must_block or []
    must_keep = must_keep or []
    assets, rels = arch_checks.snapshot(db)
    findings = attack_paths._open_findings(db)

    base_hits = arch_checks.rules.evaluate(assets, rels)
    base_paths = attack_paths.analyze_snapshot(assets, rels, findings,
                                               max_depth=5, max_paths=10)["paths"]
    sim_assets, sim_rels, warnings = _apply_to_snapshot(
        assets, rels, [{"op": c.op, "payload": _payload(c)} for c in changes])
    sim_hits = arch_checks.rules.evaluate(sim_assets, sim_rels)
    sim_paths = attack_paths.analyze_snapshot(sim_assets, sim_rels, findings,
                                              max_depth=5, max_paths=10)["paths"]

    base_keys = {_hit_key(h) for h in ({"rule_id": h.rule_id, "asset_id": h.asset_id}
                                       for h in base_hits)}
    sim_keys = {_hit_key(h) for h in ({"rule_id": h.rule_id, "asset_id": h.asset_id}
                                      for h in sim_hits)}
    base_sigs = {_path_sig(p) for p in base_paths}
    sim_sigs = {_path_sig(p) for p in sim_paths}
    _anames = {}
    for _a in db.query(Asset).filter(Asset.retired == 0).all():
        _anames[_a.id] = _a.hostname or _a.name or f"#{_a.id}"

    verification = []
    for i, c in enumerate(must_block):
        try:
            entry, tgt = int(c["entry_asset_id"]), int(c["target_asset_id"])
        except (TypeError, ValueError, KeyError):
            raise ValueError(f"must_block[{i}] needs integer entry_asset_id/target_asset_id")
        blocked = not any(p["entry_id"] == entry and p["target_id"] == tgt for p in sim_paths)
        verification.append({"criterion": "must_block", "entry_asset_id": entry,
                             "target_asset_id": tgt, "passed": blocked,
                             "note": ("no simulated path remains" if blocked
                                      else "a simulated path still reaches the target")})
    live_ids = {r["id"] for r in sim_rels}
    for i, c in enumerate(must_keep):
        try:
            rid = int(c["relationship_id"])
        except (TypeError, ValueError, KeyError):
            raise ValueError(f"must_keep[{i}] needs an integer relationship_id")
        kept = rid in live_ids
        verification.append({"criterion": "must_keep", "relationship_id": rid,
                             "passed": kept,
                             "note": ("dependency still present" if kept
                                      else "dependency was removed by the proposal")})
    all_pass = all(v["passed"] for v in verification)

    result = {
        "proposal_id": pid, "change_count": len(changes),
        "warnings": warnings[:DIFF_CAP],
        "baseline": {"hits": len(base_hits), "paths": len(base_paths)},
        "simulated": {"hits": len(sim_hits), "paths": len(sim_paths)},
        "hits_resolved": sorted([list(k) for k in base_keys - sim_keys])[:DIFF_CAP],
        "hits_added": sorted([list(k) for k in sim_keys - base_keys])[:DIFF_CAP],
        "paths_removed": len(base_sigs - sim_sigs),
        "paths_added": len(sim_sigs - base_sigs),
        "removed_path_endpoints": sorted(
            [[_anames.get(p[0], f"#{p[0]}"), _anames.get(p[1], f"#{p[1]}")]
             for p in base_sigs - sim_sigs])[:DIFF_CAP],
        "verification": verification,
        "verification_passed": all_pass,
        "label": "simulation — not a production change",
    }
    run = ArchSimRun(proposal_id=pid,
                     request_json=json.dumps({"must_block": must_block,
                                             "must_keep": must_keep})[:4000],
                     result_json=json.dumps(result)[:60000])
    db.add(run)
    if p.status == "draft":
        p.status = "simulated"
    p.updated_at = time.time()
    db.add(AuditEvent(actor=actor or "system", action="proposal_simulated",
                      detail=(f"proposal={pid} resolved_hits={len(base_keys - sim_keys)} "
                              f"removed_paths={len(base_sigs - sim_sigs)} "
                              f"verify={'pass' if all_pass else 'fail'}")))
    db.commit()
    db.refresh(run)
    return {"sim_run_id": run.id, **result}


def approve(db, pid: int, actor: str = "system", note: str = "") -> dict:
    p = _get(db, pid)
    if p.status != "simulated":
        raise ValueError(f"proposal {pid} is {p.status}; approve needs simulated status")
    p.status = "approved"
    p.updated_at = time.time()
    db.add(AuditEvent(actor=actor or "system", action="proposal_approved",
                      detail=f"proposal={pid} note={note[:200]}"))
    db.commit()
    return _proposal_out(p, db)


def apply(db, pid: int, actor: str = "system") -> dict:
    p = _get(db, pid)
    if p.status != "approved":
        raise ValueError(f"proposal {pid} is {p.status}; apply needs approved status")
    changes = (db.query(ArchProposalChange)
               .filter(ArchProposalChange.proposal_id == pid)
               .order_by(ArchProposalChange.id).all())
    applied = []
    for c in changes:
        pay = _payload(c)
        if c.op == "remove_edge":
            r = db.query(AssetRelationship).filter(
                AssetRelationship.id == pay.get("relationship_id")).first()
            if not r:
                raise ValueError(f"relationship {pay.get('relationship_id')} no longer exists")
            db.delete(r)
            applied.append({"op": c.op, "relationship_id": r.id})
            db.add(AuditEvent(actor=actor or "system", action="proposal_apply_remove",
                              detail=f"proposal={pid} rel={r.id} {r.rel}"))
        elif c.op == "add_edge":
            dup = db.query(AssetRelationship).filter(
                AssetRelationship.source_type == pay["source_type"],
                AssetRelationship.source_id == pay["source_id"],
                AssetRelationship.target_type == pay["target_type"],
                AssetRelationship.target_id == pay["target_id"],
                AssetRelationship.rel == pay["rel"]).first()
            if dup:
                raise ValueError("identical relationship appeared while staged")
            for kind, rid in ((pay["source_type"], pay["source_id"]),
                              (pay["target_type"], pay["target_id"])):
                exists = (db.query(Asset).filter(Asset.id == rid).first()
                          if kind == "asset"
                          else db.query(Service).filter(Service.id == rid).first())
                if not exists:
                    raise ValueError(f"{kind} {rid} no longer exists")
            row = AssetRelationship(
                source_type=pay["source_type"], source_id=pay["source_id"],
                target_type=pay["target_type"], target_id=pay["target_id"],
                rel=pay["rel"], source_note="proposal", confidence="medium",
                provenance="configured", evidence_ref=f"proposal:{pid}",
                created_at=time.time(), updated_at=time.time())
            db.add(row)
            db.flush()
            applied.append({"op": c.op, "relationship_id": row.id})
            db.add(AuditEvent(actor=actor or "system", action="proposal_apply_add",
                              detail=f"proposal={pid} rel={row.id} {row.rel}"))
        elif c.op == "update_asset":
            a = db.query(Asset).filter(Asset.id == pay.get("asset_id")).first()
            if not a:
                raise ValueError(f"asset {pay.get('asset_id')} no longer exists")
            for k in ("zone", "criticality"):
                if k in pay:
                    setattr(a, k, pay[k])
            a.updated_at = time.time()
            applied.append({"op": c.op, "asset_id": a.id})
            db.add(AuditEvent(actor=actor or "system", action="proposal_apply_update",
                              detail=f"proposal={pid} asset={a.id} {pay}"))
    p.status = "applied"
    p.updated_at = time.time()
    db.add(AuditEvent(actor=actor or "system", action="proposal_applied",
                      detail=f"proposal={pid} changes={len(applied)}"))
    db.commit()
    return {"proposal_id": pid, "status": "applied", "applied": applied}


def reject(db, pid: int, actor: str = "system", note: str = "") -> dict:
    p = _get(db, pid)
    if p.status not in ("draft", "simulated", "approved"):
        raise ValueError(f"proposal {pid} is {p.status}; nothing to reject")
    p.status = "rejected"
    p.updated_at = time.time()
    db.add(AuditEvent(actor=actor or "system", action="proposal_rejected",
                      detail=f"proposal={pid} note={note[:200]}"))
    db.commit()
    return _proposal_out(p, db)
