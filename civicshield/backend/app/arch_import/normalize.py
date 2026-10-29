"""Normalization: file-local graphs -> canonical CivicShield vocabulary.

Unknown values never fail the import; they become warnings and fall back
to safe defaults so preview always shows what would be committed.
"""
from __future__ import annotations

CANONICAL_KINDS = {"router", "switch", "firewall", "server", "database",
                   "workstation", "identity", "monitoring", "backup",
                   "gateway", "service", "external", "other"}
KIND_ALIASES = {
    "idp": "identity", "ad": "identity", "ldap": "identity", "iam": "identity",
    "db": "database", "sql": "database", "postgres": "database",
    "vm": "server", "host": "server", "app": "server",
    "fw": "firewall", "ids": "monitoring", "ips": "monitoring",
    "siem": "monitoring", "log": "monitoring",
    "saas": "external", "vendor": "external", "cloud": "external",
    "pc": "workstation", "laptop": "workstation", "desktop": "workstation",
    "web": "server", "api": "server",
}
CANONICAL_ZONES = {"core", "office", "plant", "dmz", "central", "edge", "external"}
CANONICAL_RELS = {"depends_on", "authenticates_via", "monitors", "backs_up",
                  "serves", "connects_to", "manages", "failover"}
REL_ALIASES = {
    "requires": "depends_on", "needs": "depends_on", "uses": "depends_on",
    " healedby": "depends_on", "login": "authenticates_via", "auth": "authenticates_via",
    "watches": "monitors", "backup": "backs_up", "provides": "serves",
    "linked": "connects_to", "connected": "connects_to", "administers": "manages",
    "fail_over": "failover", "fail-over": "failover", "standby": "failover",
}
CANONICAL_CRITICALITY = {"critical", "high", "medium", "low"}


def _canon(value: str, canonical: set, aliases: dict, default: str,
           warnings: list, what: str, name: str) -> str:
    v = (value or "").strip().lower().replace(" ", "_").replace("-", "_")
    if not v:
        return default
    if v in canonical:
        return v
    if v in aliases:
        return aliases[v]
    warnings.append(f"{what}: unknown value '{value}', using '{default}'")
    return default


def normalize(nodes: list, edges: list) -> tuple[list, list, list]:
    """Return (staged_nodes, staged_edges, warnings)."""
    warnings: list[str] = []
    staged = []
    by_key: dict[str, dict] = {}
    for n in nodes:
        name = str(n.get("name", "")).strip()
        if not name:
            if len(warnings) < 100:
                warnings.append("node skipped (no name)")
            continue
        kind = _canon(str(n.get("kind", "")), CANONICAL_KINDS, KIND_ALIASES,
                      "other", warnings, f"node '{name}' kind", name)
        zone = _canon(str(n.get("zone", "")), CANONICAL_ZONES, {},
                      "central", warnings, f"node '{name}' zone", name)
        crit = _canon(str(n.get("criticality", "")), CANONICAL_CRITICALITY, {},
                      "low", warnings, f"node '{name}' criticality", name)
        staged.append({"key": name.lower(), "name": name, "kind": kind,
                       "hostname": str(n.get("hostname", "")).strip(),
                       "zone": zone, "owner": str(n.get("owner", "")).strip(),
                       "os_name": str(n.get("os_name", "")).strip(),
                       "criticality": crit,
                       "file_id": str(n.get("file_id", name))})
    for s in staged:
        by_key.setdefault(s["key"], s)
        by_key.setdefault(str(s["file_id"]).lower(), s)
    staged_edges = []
    for e in edges:
        src = by_key.get(str(e.get("source", "")).strip().lower())
        tgt = by_key.get(str(e.get("target", "")).strip().lower())
        if not src or not tgt:
            if len(warnings) < 100:
                warnings.append(
                    f"edge {e.get('source')} -> {e.get('target')}: "
                    "endpoint not in file, skipped")
            continue
        rel = _canon(str(e.get("rel", "depends_on")), CANONICAL_RELS, REL_ALIASES,
                     "depends_on", warnings,
                     f"edge {src['name']} -> {tgt['name']} relation",
                     str(e.get("rel", "")))
        if src["key"] == tgt["key"]:
            if len(warnings) < 100:
                warnings.append(f"edge {src['name']} -> itself: skipped (self-loop)")
            continue
        staged_edges.append({"source": src["name"], "target": tgt["name"], "rel": rel})
    # Deduplicate identical edges, keep first.
    seen, deduped = set(), []
    for e in staged_edges:
        k = (e["source"], e["target"], e["rel"])
        if k not in seen:
            seen.add(k)
            deduped.append(e)
    return staged, deduped, warnings
