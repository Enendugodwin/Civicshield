"""Parsers for supported architecture input formats.

Each returns (nodes, edges, warnings) where nodes are dicts with at least
a display name and edges reference nodes by the file-local ids.
"""
from __future__ import annotations

import csv
import io
import json
import re

MAX_CONTENT_CHARS = 1_000_000


def _warn(warnings: list, msg: str) -> None:
    if len(warnings) < 100:
        warnings.append(msg[:300])


def parse_inventory_csv(text: str) -> tuple[list, list, list]:
    """CSV with header. Columns: name (required), kind (or `type` alias),
    hostname, zone, owner, os_name, criticality, plus edge columns
    depends_on / authenticates_via / connects_to (semicolon-separated names)."""
    warnings: list = []
    try:
        rows = list(csv.DictReader(io.StringIO(text)))
    except csv.Error as e:
        return [], [], [f"csv parse error: {e}"]
    if not rows:
        return [], [], ["csv is empty"]
    if "name" not in (rows[0] or {}):
        return [], [], ["csv needs a 'name' column"]
    nodes, edges = [], []
    for i, r in enumerate(rows, start=2):
        name = (r.get("name") or "").strip()
        if not name:
            _warn(warnings, f"row {i}: skipped (no name)")
            continue
        nodes.append({"file_id": name, "name": name,
                      "kind": (r.get("kind") or r.get("type") or "").strip(),
                      "hostname": (r.get("hostname") or "").strip(),
                      "zone": (r.get("zone") or "").strip(),
                      "owner": (r.get("owner") or "").strip(),
                      "os_name": (r.get("os_name") or "").strip(),
                      "criticality": (r.get("criticality") or "").strip()})
        for col, rel in (("depends_on", "depends_on"),
                         ("authenticates_via", "authenticates_via"),
                         ("connects_to", "connects_to")):
            for target in (r.get(col) or "").split(";"):
                target = target.strip()
                if target:
                    edges.append({"source": name, "target": target, "rel": rel})
    return nodes, edges, warnings


def parse_inventory_json(text: str) -> tuple[list, list, list]:
    """{"nodes":[{...same fields as csv...}], "edges":[{source,target,rel}]}."""
    warnings: list = []
    try:
        doc = json.loads(text)
    except ValueError as e:
        return [], [], [f"json parse error: {e}"]
    if not isinstance(doc, dict):
        return [], [], ["json root must be an object with nodes/edges"]
    raw_nodes = doc.get("nodes", [])
    raw_edges = doc.get("edges", [])
    if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
        return [], [], ["nodes and edges must be lists"]
    nodes = []
    for i, n in enumerate(raw_nodes):
        if not isinstance(n, dict) or not str(n.get("name", "")).strip():
            _warn(warnings, f"node {i}: skipped (needs a name)")
            continue
        nodes.append({"file_id": str(n.get("id", n["name"])).strip(),
                      "name": str(n["name"]).strip(),
                      "kind": str(n.get("kind", n.get("type", ""))).strip(),
                      "hostname": str(n.get("hostname", "")).strip(),
                      "zone": str(n.get("zone", "")).strip(),
                      "owner": str(n.get("owner", "")).strip(),
                      "os_name": str(n.get("os_name", "")).strip(),
                      "criticality": str(n.get("criticality", "")).strip()})
    edges = []
    for i, e in enumerate(raw_edges):
        if not isinstance(e, dict) or not e.get("source") or not e.get("target"):
            _warn(warnings, f"edge {i}: skipped (needs source and target)")
            continue
        edges.append({"source": str(e["source"]).strip(),
                      "target": str(e["target"]).strip(),
                      "rel": str(e.get("rel", "depends_on")).strip() or "depends_on"})
    return nodes, edges, warnings


_MERMAID_EDGE = re.compile(
    r"^\s*([A-Za-z0-9_]+)(?:[\[\({][^\]\)\}]*[\]\)\}])?\s*"
    r"(?:-->\s*|---\s*|-\.-\s*|==>\s*)"
    r"(?:\|([^|]*)\|\s*)?"
    r"([A-Za-z0-9_]+)")


def parse_mermaid(text: str) -> tuple[list, list, list]:
    """Subset of Mermaid flowchart/graph: `A[Label] -->|rel| B(Label)`.
    Node display text becomes the name; the id stays file-local."""
    warnings: list = []
    if "graph" not in text and "flowchart" not in text:
        _warn(warnings, "no graph/flowchart header found; attempting best-effort parse")
    labels: dict[str, str] = {}
    for m in re.finditer(r"([A-Za-z0-9_]+)[\[\({]([^\]\)\}]*)[\]\)\}]", text):
        labels.setdefault(m.group(1), m.group(2).strip() or m.group(1))
    nodes = [{"file_id": fid, "name": label, "kind": "", "hostname": "",
              "zone": "", "owner": "", "criticality": ""}
             for fid, label in labels.items()]
    edges = []
    for line in text.splitlines():
        m = _MERMAID_EDGE.match(line)
        if m:
            edges.append({"source": m.group(1), "target": m.group(3),
                          "rel": (m.group(2) or "depends_on").strip() or "depends_on"})
    if not nodes and not edges:
        return [], [], warnings + ["no nodes or edges recognized as Mermaid flowchart"]
    return nodes, edges, warnings


def parse_upload(filename: str, content: str) -> tuple[str, list, list, list]:
    """Detect format by extension/content, parse, enforce size cap."""
    if len(content) > MAX_CONTENT_CHARS:
        raise ValueError("upload exceeds 1MB limit")
    name = (filename or "").lower()
    if name.endswith(".csv"):
        fmt = "csv"
        nodes, edges, warnings = parse_inventory_csv(content)
    elif name.endswith((".json", ".jsonc")):
        fmt = "json"
        nodes, edges, warnings = parse_inventory_json(content)
    elif name.endswith((".mmd", ".mermaid")) or "graph " in content or "flowchart" in content:
        fmt = "mermaid"
        nodes, edges, warnings = parse_mermaid(content)
    else:
        raise ValueError("unsupported format: use .csv, .json, or .mmd Mermaid")
    return fmt, nodes, edges, warnings
