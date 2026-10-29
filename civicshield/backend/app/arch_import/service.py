"""Staged import service: preview first, explicit commit, never partial.

Commit matches nodes to existing assets by name (case-insensitive) and
reuses them; identical edges are skipped so re-imports are idempotent.
Every committed edge carries provenance='imported' with the batch id.
"""
from __future__ import annotations

import json
import time

from app.arch_import import normalize as norm
from app.arch_import import parsers
from app.models.models import ArchImportBatch, Asset, AssetRelationship


def build_preview(filename: str, content: str) -> dict:
    fmt, nodes, edges, parse_warnings = parsers.parse_upload(filename, content)
    staged_nodes, staged_edges, norm_warnings = norm.normalize(nodes, edges)
    return {"format": fmt, "nodes": staged_nodes, "edges": staged_edges,
            "warnings": parse_warnings + norm_warnings}


def save_preview(db, filename: str, content: str, actor: str) -> ArchImportBatch:
    preview = build_preview(filename, content)
    batch = ArchImportBatch(
        filename=(filename or "")[:200], format=preview["format"], status="preview",
        node_count=len(preview["nodes"]), edge_count=len(preview["edges"]),
        warnings_json=json.dumps(preview["warnings"][:100]),
        payload_json=json.dumps({"nodes": preview["nodes"], "edges": preview["edges"]}),
        actor=actor or "")
    db.add(batch)
    db.commit()
    db.refresh(batch)
    return batch


def commit_batch(db, batch_id: int) -> dict:
    batch = db.query(ArchImportBatch).filter(ArchImportBatch.id == batch_id).first()
    if not batch:
        raise KeyError("batch not found")
    if batch.status != "preview":
        raise ValueError(f"batch is {batch.status}, only preview batches can commit")
    payload = json.loads(batch.payload_json or "{}")
    nodes = {n["name"].lower(): n for n in payload.get("nodes", [])}
    asset_ids: dict[str, int] = {}
    created_assets = reused_assets = 0
    for key, n in nodes.items():
        existing = (db.query(Asset).filter(Asset.retired == 0).all())
        match = next((a for a in existing
                      if (a.name or "").lower() == key
                      or (a.hostname or "").lower() == (n.get("hostname") or "").lower()
                      and n.get("hostname")), None)
        if match:
            asset_ids[key] = match.id
            reused_assets += 1
        else:
            row = Asset(name=n["name"], kind=n.get("kind") or "other",
                        hostname=n.get("hostname") or "", zone=n.get("zone") or "central",
                        owner=n.get("owner") or "", os_name=n.get("os_name") or "",
                        criticality=n.get("criticality") or "low")
            db.add(row)
            db.flush()
            asset_ids[key] = row.id
            created_assets += 1
    created_edges = skipped_edges = 0
    for e in payload.get("edges", []):
        src = asset_ids.get(str(e["source"]).lower())
        tgt = asset_ids.get(str(e["target"]).lower())
        if not src or not tgt:
            skipped_edges += 1
            continue
        dup = (db.query(AssetRelationship)
               .filter(AssetRelationship.source_type == "asset",
                       AssetRelationship.source_id == src,
                       AssetRelationship.target_type == "asset",
                       AssetRelationship.target_id == tgt,
                       AssetRelationship.rel == e["rel"]).first())
        if dup:
            skipped_edges += 1
            continue
        db.add(AssetRelationship(
            source_type="asset", source_id=src, target_type="asset", target_id=tgt,
            rel=e["rel"], source_note="imported", confidence="medium",
            provenance="imported", evidence_ref=f"import-batch:{batch.id}",
            created_at=time.time(), updated_at=time.time()))
        created_edges += 1
    batch.status = "committed"
    db.commit()
    return {"batch_id": batch.id, "created_assets": created_assets,
            "reused_assets": reused_assets, "created_edges": created_edges,
            "skipped_edges": skipped_edges}
