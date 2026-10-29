"""Deterministic architecture checks (AR-* family).

Each rule inspects the normalized inventory graph — assets plus declared
relationships — and reports structural weaknesses. Rules never execute
anything and never claim live compromise: edge-based hits are reported as
confirmed structure, absence-based hits as inferred gaps that may also mean
the inventory is incomplete. Every hit carries the exact asset/edge evidence
so the Finding detail can quote it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

ARCH_RULE_VERSION = "1.0.0"

DEPENDENCY_RELS = {"depends_on", "connects_to", "manages", "serves"}
BACKUP_RELS = {"backs_up", "backed_by"}
SENSITIVE_KINDS = {"database", "identity", "directory", "backup"}
SPF_MIN_DEPENDENTS = 3


@dataclass(frozen=True)
class ArchRule:
    rule_id: str
    name: str
    description: str
    severity: str  # critical | high | medium | low
    remediation: str


@dataclass
class ArchHit:
    rule_id: str
    severity: str
    confidence: str  # high (edge evidence) | medium (absence may be inventory gap)
    status: str  # confirmed | inferred
    asset_id: str
    asset_name: str
    evidence_ref: str
    detail: str
    remediation: str


RuleFn = Callable[[dict[int, dict], list[dict]], list[ArchHit]]


def _asset(assets: dict[int, dict], aid: Any) -> dict:
    try:
        return assets.get(int(aid), {})
    except (TypeError, ValueError):
        return {}


def _crit(a: dict) -> str:
    return str(a.get("criticality") or "low").lower()


def _high_value(a: dict) -> bool:
    return _crit(a) in ("high", "critical")


def _edge_ids(rels: list[dict], pred) -> list[int]:
    return [r["id"] for r in rels if pred(r)]


def _failover_peers(assets: dict[int, dict], rels: list[dict], aid: int) -> list[int]:
    """Asset ids sharing a failover (active/standby) link with aid."""
    peers = []
    for r in rels:
        if str(r.get("rel")).lower() != "failover":
            continue
        if r.get("source_type") != "asset" or r.get("target_type") != "asset":
            continue
        try:
            s, t = int(r["source_id"]), int(r["target_id"])
        except (TypeError, ValueError):
            continue
        if s == aid and t in assets:
            peers.append(t)
        elif t == aid and s in assets:
            peers.append(s)
    return sorted(set(peers))


def rule_spf(assets: dict[int, dict], rels: list[dict]) -> list[ArchHit]:
    """AR-SPF-01: high-value asset many others depend on (single point of failure).

    An asset with a recorded failover peer is not a single point of failure:
    the peer takes over when it is down, so the rule stays silent.
    """
    dependents: dict[int, list[int]] = {}
    for r in rels:
        if r.get("source_type") != "asset" or r.get("target_type") != "asset":
            continue
        if str(r.get("rel")) not in DEPENDENCY_RELS:
            continue
        try:
            dependents.setdefault(int(r["target_id"]), []).append(int(r["id"]))
        except (TypeError, ValueError):
            continue
    hits = []
    for aid, edge_ids in dependents.items():
        a = _asset(assets, aid)
        if not a or not _high_value(a):
            continue
        if _failover_peers(assets, rels, aid):
            continue  # recorded redundancy: peer takes over when this one is down
        if len(set(edge_ids)) < SPF_MIN_DEPENDENTS:
            continue
        dep_names = sorted({str(_asset(assets, s).get("name") or s)
                            for r in rels if r["id"] in edge_ids
                            for s in [r["source_id"]]})
        hits.append(ArchHit(
            rule_id="AR-SPF-01", severity="high", confidence="high", status="confirmed",
            asset_id=str(aid), asset_name=str(a.get("name") or aid),
            evidence_ref=";".join(f"relationship:{i}" for i in sorted(set(edge_ids))),
            detail=(f"{a.get('name')} ({a.get('kind')}, {a.get('criticality')} criticality) "
                    f"has {len(edge_ids)} recorded dependents: "
                    f"{', '.join(dep_names[:8])}. If it fails, all of them lose "
                    f"their dependency path. No redundancy is recorded in the inventory."),
            remediation=("Add a redundant peer or a documented failover path, record it "
                         "as a relationship, and re-run the checks.")))
    return hits


def rule_exp(assets: dict[int, dict], rels: list[dict]) -> list[ArchHit]:
    """AR-EXP-01: external entry point reaching a high-value asset directly."""
    hits = []
    for r in rels:
        if r.get("source_type") != "asset" or r.get("target_type") != "asset":
            continue
        src, tgt = _asset(assets, r.get("source_id")), _asset(assets, r.get("target_id"))
        if not src or not tgt:
            continue
        external_src = (str(src.get("zone")).lower() == "external"
                        or str(src.get("kind")).lower() == "external")
        if not external_src or not _high_value(tgt) or str(tgt.get("kind")).lower() == "external":
            continue
        hits.append(ArchHit(
            rule_id="AR-EXP-01",
            severity="critical" if _crit(tgt) == "critical" else "high",
            confidence="high", status="confirmed",
            asset_id=str(r["target_id"]), asset_name=str(tgt.get("name") or r["target_id"]),
            evidence_ref=f"relationship:{r['id']}",
            detail=(f"External asset {src.get('name')} connects directly to "
                    f"{tgt.get('name')} ({tgt.get('kind')}, {tgt.get('criticality')} "
                    f"criticality) via '{r.get('rel')}'. There is no firewall, gateway, "
                    f"or filtering hop recorded on this path."),
            remediation=("Place a firewall or gateway between the external entry point "
                         "and the asset, record the hops as relationships, and re-run "
                         "the checks.")))
    for aid, a in assets.items():
        if str(a.get("zone")).lower() == "external" and _high_value(a):
            hits.append(ArchHit(
                rule_id="AR-EXP-01",
                severity="critical" if _crit(a) == "critical" else "high",
                confidence="high", status="confirmed",
                asset_id=str(aid), asset_name=str(a.get("name") or aid),
                evidence_ref=f"asset:{aid}",
                detail=(f"{a.get('name')} is a {_crit(a)}-criticality asset sitting "
                        f"directly in the external zone. External-zone assets are "
                        f"reachable by definition; move it behind the boundary or "
                        f"record the protecting controls."),
                remediation=("Move the asset out of the external zone or record the "
                             "boundary controls that protect it.")))
    return hits


def rule_seg(assets: dict[int, dict], rels: list[dict]) -> list[ArchHit]:
    """AR-SEG-01: operator workstation placed in a core/dmz network zone."""
    hits = []
    for aid, a in assets.items():
        if str(a.get("kind")).lower() != "workstation":
            continue
        if str(a.get("zone")).lower() not in ("core", "dmz"):
            continue
        hits.append(ArchHit(
            rule_id="AR-SEG-01", severity="medium", confidence="high", status="confirmed",
            asset_id=str(aid), asset_name=str(a.get("name") or aid),
            evidence_ref=f"asset:{aid}",
            detail=(f"Workstation {a.get('name')} lives in the {a.get('zone')} zone. "
                    f"Interactive endpoints in core/dmz widen the blast radius of "
                    f"phishing or endpoint compromise toward the most sensitive systems."),
            remediation=("Move operator workstations to office/plant zones and reach "
                         "core systems through a jump host or remote-access gateway "
                         "recorded as a relationship.")))
    return hits


def rule_mon(assets: dict[int, dict], rels: list[dict]) -> list[ArchHit]:
    """AR-MON-01: sensitive store with no monitoring edge (or incomplete inventory)."""
    hits = []
    for aid, a in assets.items():
        if _crit(a) != "critical" or str(a.get("kind")).lower() not in SENSITIVE_KINDS:
            continue
        def _watched(r: dict) -> bool:
            if str(r.get("rel")).lower() != "monitors":
                return False
            if r.get("source_type") != "asset" or r.get("target_type") != "asset":
                return False
            if str(r.get("source_id")) != str(aid) and str(r.get("target_id")) != str(aid):
                return False
            pair = {_asset(assets, r.get("source_id")).get("kind"),
                    _asset(assets, r.get("target_id")).get("kind")}
            return "monitoring" in {str(k).lower() for k in pair}

        watched = any(_watched(r) for r in rels)
        if watched:
            continue
        hits.append(ArchHit(
            rule_id="AR-MON-01", severity="medium", confidence="medium", status="inferred",
            asset_id=str(aid), asset_name=str(a.get("name") or aid),
            evidence_ref=f"asset:{aid}",
            detail=(f"{a.get('name')} ({a.get('kind')}, critical criticality) has no "
                    f"'monitors' relationship with a monitoring asset. Either nothing "
                    f"watches it, or the monitoring link is missing from the inventory."),
            remediation=("Record the monitoring coverage as a 'monitors' relationship "
                         "from the monitoring asset, or add the coverage and re-run "
                         "the checks.")))
    return hits


def rule_bkp(assets: dict[int, dict], rels: list[dict]) -> list[ArchHit]:
    """AR-BKP-01: database with no backup relationship (or incomplete inventory)."""
    hits = []
    for aid, a in assets.items():
        if str(a.get("kind")).lower() != "database" or not _high_value(a):
            continue
        def _covers(r: dict) -> bool:
            if str(r.get("rel")).lower() not in BACKUP_RELS:
                return False
            if r.get("source_type") != "asset" or r.get("target_type") != "asset":
                return False
            if str(r.get("source_id")) != str(aid) and str(r.get("target_id")) != str(aid):
                return False
            pair = {_asset(assets, r.get("source_id")).get("kind"),
                    _asset(assets, r.get("target_id")).get("kind")}
            return "backup" in {str(k).lower() for k in pair}

        covered = any(_covers(r) for r in rels)
        if covered:
            continue
        hits.append(ArchHit(
            rule_id="AR-BKP-01",
            severity="high" if _crit(a) == "critical" else "medium",
            confidence="medium", status="inferred",
            asset_id=str(aid), asset_name=str(a.get("name") or aid),
            evidence_ref=f"asset:{aid}",
            detail=(f"Database {a.get('name')} ({_crit(a)} criticality) has no "
                    f"backup relationship with a backup asset. Either it cannot be "
                    f"restored, or the backup link is missing from the inventory."),
            remediation=("Record the backup coverage as a 'backs_up' relationship from "
                         "the backup asset, verify a restore, and re-run the checks.")))
    return hits


def _cycles(nodes: list[int], adj: dict[int, list[int]]) -> list[list[int]]:
    found: list[list[int]] = []
    seen: set[tuple] = set()
    stack: list[int] = []
    on_stack: set[int] = set()

    def visit(n: int) -> None:
        stack.append(n)
        on_stack.add(n)
        for m in adj.get(n, []):
            if m in on_stack:
                cyc = stack[stack.index(m):]
                key = tuple(sorted(cyc))
                if key not in seen:
                    seen.add(key)
                    found.append(cyc)
            elif m not in done:
                visit(m)
        stack.pop()
        on_stack.discard(n)
        done.add(n)

    done: set[int] = set()
    for n in nodes:
        if n not in done:
            visit(n)
    return found


def rule_cyc(assets: dict[int, dict], rels: list[dict]) -> list[ArchHit]:
    """AR-CYC-01: dependency cycle — failure impact cannot be ordered."""
    adj: dict[int, list[int]] = {}
    for r in rels:
        if r.get("source_type") != "asset" or r.get("target_type") != "asset":
            continue
        if str(r.get("rel")).lower() not in DEPENDENCY_RELS | {"authenticates_via"}:
            continue
        try:
            adj.setdefault(int(r["source_id"]), []).append(int(r["target_id"]))
        except (TypeError, ValueError):
            continue
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    hits = []
    for cyc in _cycles(sorted(assets), adj):
        names = [str(_asset(assets, n).get("name") or n) for n in cyc]
        primary = min(cyc, key=lambda n: (order.get(_crit(_asset(assets, n)), 4), n))
        pa = _asset(assets, primary)
        hits.append(ArchHit(
            rule_id="AR-CYC-01", severity="high", confidence="high", status="confirmed",
            asset_id=str(primary), asset_name=str(pa.get("name") or primary),
            evidence_ref=";".join(f"asset:{n}" for n in cyc),
            detail=(f"Dependency cycle: {' -> '.join(names)} -> {names[0]}. A cycle "
                    f"means no safe restoration order exists and impact analysis can "
                    f"loop; one of these links is misdeclared."),
            remediation=("Break the cycle by correcting the misdeclared dependency "
                         "relationship, then re-run the checks.")))
    return hits


@dataclass(frozen=True)
class _Registered:
    meta: ArchRule
    evaluate: RuleFn


def _reg(rule_id: str, name: str, description: str, severity: str,
         remediation: str, fn: RuleFn) -> _Registered:
    return _Registered(ArchRule(rule_id, name, description, severity, remediation), fn)


CATALOG: list[_Registered] = [
    _reg("AR-SPF-01", "Single point of failure",
         "High-value asset with 3+ recorded dependents and no redundant peer.",
         "high",
         "Add a redundant peer or documented failover path and record it.",
         rule_spf),
    _reg("AR-EXP-01", "External exposure path",
         "Direct path from an external asset (or external zone) to a high-value asset.",
         "high",
         "Insert a firewall/gateway hop and record it as relationships.",
         rule_exp),
    _reg("AR-SEG-01", "Workstation in core/dmz zone",
         "Interactive endpoint inside a sensitive network zone.",
         "medium",
         "Move workstations to office/plant zones behind a jump host.",
         rule_seg),
    _reg("AR-MON-01", "Sensitive store without monitoring",
         "Critical database/identity/backup asset with no monitoring relationship.",
         "medium",
         "Record monitoring coverage as a 'monitors' relationship.",
         rule_mon),
    _reg("AR-BKP-01", "Database without backup path",
         "High-value database with no backup relationship to a backup asset.",
         "high",
         "Record backup coverage and verify a restore.",
         rule_bkp),
    _reg("AR-CYC-01", "Dependency cycle",
         "Circular dependency chain; no safe restoration order exists.",
         "high",
         "Correct the misdeclared relationship to break the cycle.",
         rule_cyc),
]


def describe() -> list[dict]:
    return [{"rule_id": r.meta.rule_id, "name": r.meta.name,
             "description": r.meta.description, "severity": r.meta.severity,
             "remediation": r.meta.remediation, "version": ARCH_RULE_VERSION}
            for r in CATALOG]


def evaluate(assets: dict[int, dict], rels: list[dict],
             rule_ids: list[str] | None = None) -> list[ArchHit]:
    wanted = set(rule_ids or [])
    hits: list[ArchHit] = []
    for reg in CATALOG:
        if wanted and reg.meta.rule_id not in wanted:
            continue
        try:
            hits.extend(reg.evaluate(assets, rels))
        except Exception:
            continue  # one bad rule never blocks the family
    return hits
