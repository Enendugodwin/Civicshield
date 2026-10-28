"""Vulnerability intelligence for CivicShield detection.

Two evidence sources:
  1. A bundled, versioned advisory snapshot of real high-impact CVEs (offline,
     deterministic, used by the demo and by tests).
  2. Optional live OSV.dev enrichment for language packages (Maven, npm, PyPI,
     Go, crates.io, NuGet, RubyGems, Packagist). Disabled by default so a demo
     without internet still produces the same result.

A version match is evidence to investigate, not proof of exploitability. Every
match carries its source, confidence and limitation so the UI can show them.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

_HERE = Path(__file__).resolve()
_ROOT = _HERE.parents[2]  # civicshield/
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import baseline_guard  # noqa: E402

ADVISORY_PATH = _HERE.parent / "advisories.json"
CACHE_PATH = _HERE.parents[1] / "data" / "osv_cache.json"
CACHE_TTL_SECONDS = 7 * 24 * 3600
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

_OSV_ECOSYSTEMS = {
    "maven": "Maven",
    "npm": "npm",
    "pypi": "PyPI",
    "pip": "PyPI",
    "go": "Go",
    "golang": "Go",
    "crates.io": "crates.io",
    "cargo": "crates.io",
    "nuget": "NuGet",
    "rubygems": "RubyGems",
    "packagist": "Packagist",
}


@dataclass(frozen=True)
class Advisory:
    id: str
    title: str
    product: str
    aliases: Tuple[str, ...]
    ecosystem: str
    affected: str
    fixed: str
    severity: str
    cvss: float
    known_exploited: bool
    exploit_available: bool
    confidence: str
    published: str
    source: str
    url: str
    limitation: str

    def matches_product(self, name: str) -> bool:
        n = (name or "").strip().lower()
        if not n:
            return False
        names = {self.product.lower(), *(a.lower() for a in self.aliases)}
        if n in names:
            return True
        # Package names often carry a suffix (openssh-server-8.2p1) or a path.
        return any(n.endswith("-" + x) or n.endswith("/" + x) or n.startswith(x + "@")
                   for x in names)


@dataclass
class VulnMatch:
    advisory: Advisory
    package: str
    version: str
    confidence: str
    source: str = ""
    url: str = ""
    limitation: str = ""

    def as_finding(self, asset_id: str) -> baseline_guard.Finding:
        a = self.advisory
        detail = (
            f"{a.title}. Declared software {self.package} {self.version} falls within "
            f"the affected range ({a.affected}); fixed in {a.fixed}."
        )
        evidence = (
            f"software:{self.package}@{self.version};"
            f"advisory:{self.source or a.source};"
            f"snapshot:{snapshot()['snapshot']}"
        )
        return baseline_guard.Finding(
            rule_id=a.id,
            rule_version=f"advisory-{snapshot()['snapshot']}",
            rule_name=a.title,
            category="vulnerability",
            severity=a.severity,
            outcome="FAIL",
            confidence=self.confidence,
            asset_id=str(asset_id),
            evidence_ref=evidence,
            detail=detail,
            remediation=(
                f"Upgrade {a.product} to {a.fixed} or later, following the vendor advisory. "
                f"Compensating control until patched: {self.limitation}"
            ),
        )


_ADVISORIES: Optional[List[Advisory]] = None
_OSV_CACHE: Optional[Dict[str, Any]] = None


def snapshot() -> Dict[str, Any]:
    raw = _load_raw()
    return {
        "snapshot": raw.get("snapshot", "unknown"),
        "source": raw.get("source", ""),
        "count": len(_advisories()),
        "online_enrichment": "OSV.dev (optional)",
    }


def _load_raw() -> Dict[str, Any]:
    try:
        with ADVISORY_PATH.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {"snapshot": "unavailable", "advisories": []}


def _advisories() -> List[Advisory]:
    global _ADVISORIES
    if _ADVISORIES is not None:
        return _ADVISORIES
    out: List[Advisory] = []
    for row in _load_raw().get("advisories", []):
        try:
            out.append(Advisory(
                id=str(row["id"]),
                title=str(row.get("title", row["id"])),
                product=str(row.get("product", "")),
                aliases=tuple(str(x) for x in row.get("aliases", [])),
                ecosystem=str(row.get("ecosystem", "")),
                affected=str(row.get("affected", "")),
                fixed=str(row.get("fixed", "")),
                severity=str(row.get("severity", "medium")).lower(),
                cvss=float(row.get("cvss", 0) or 0),
                known_exploited=bool(row.get("known_exploited")),
                exploit_available=bool(row.get("exploit_available")),
                confidence=str(row.get("confidence", "high")),
                published=str(row.get("published", "")),
                source=str(row.get("source", "")),
                url=str(row.get("url", "")),
                limitation=str(row.get("limitation", "")),
            ))
        except (KeyError, TypeError, ValueError):
            continue
    _ADVISORIES = out
    return out


# --------------------------------------------------------------- versions ---

def _tokens(version: str) -> List[Tuple[int, Any]]:
    """Tokenise a version into comparable (kind, value) pairs.

    Handles semver, OpenSSH (8.2p1), OpenSSL letters (1.1.1f), Debian epochs
    (1:8.2p1-4ubuntu0.5) and PAN-OS hotfixes (11.0.4-h1).
    """
    value = str(version or "").strip().lower()
    if ":" in value:
        value = value.split(":", 1)[1]  # drop Debian epoch
    if value.startswith("v"):
        value = value[1:]
    out: List[Tuple[int, Any]] = []
    for tok in re.findall(r"\d+|[a-z]+", value):
        if tok.isdigit():
            out.append((0, int(tok)))
        else:
            out.append((1, tok))
    return out


def compare_versions(left: str, right: str) -> int:
    """Return -1, 0 or 1. Missing tokens compare as zero."""
    a, b = _tokens(left), _tokens(right)
    for i in range(max(len(a), len(b))):
        x = a[i] if i < len(a) else (0, 0)
        y = b[i] if i < len(b) else (0, 0)
        if x == y:
            continue
        if x[0] != y[0]:
            # A letter suffix is newer than an absent/numeric suffix.
            return 1 if x[0] > y[0] else -1
        return 1 if x[1] > y[1] else -1
    return 0


_CLAUSE = re.compile(r"^(<=|>=|<|>|==|=)?\s*([0-9a-z][0-9a-z.\-_+]*)$", re.I)


def satisfies(version: str, expression: str) -> bool:
    """Evaluate an advisory range such as '>=8.5p1 <9.8p1' or 'a || b'."""
    if not expression:
        return False
    for group in expression.split("||"):
        clauses = group.strip().split()
        if not clauses:
            continue
        ok = True
        for clause in clauses:
            m = _CLAUSE.match(clause)
            if not m:
                ok = False
                break
            op = m.group(1) or "="
            target = m.group(2)
            cmp = compare_versions(version, target)
            if op in ("=", "=="):
                ok = cmp == 0
            elif op == "<":
                ok = cmp < 0
            elif op == "<=":
                ok = cmp <= 0
            elif op == ">":
                ok = cmp > 0
            elif op == ">=":
                ok = cmp >= 0
            if not ok:
                break
        if ok:
            return True
    return False


# -------------------------------------------------------------- software ---

def normalize_software(evidence: Dict[str, Any]) -> List[Dict[str, str]]:
    """Read declared software from collector evidence.

    Accepted shapes:
      "software": [{"name": "...", "version": "...", "ecosystem": "deb"}]
      "software": {"installed": [...]}
      "software": ["openssh-server 8.2p1"]
    """
    raw = evidence.get("software") if isinstance(evidence, dict) else None
    if isinstance(raw, dict):
        raw = raw.get("installed") or []
    if not isinstance(raw, list):
        return []
    out: List[Dict[str, str]] = []
    seen = set()
    for item in raw:
        name = version = ecosystem = package = ""
        if isinstance(item, str):
            parts = item.strip().rsplit(" ", 1)
            name = parts[0].strip()
            version = parts[1].strip() if len(parts) == 2 else ""
        elif isinstance(item, dict):
            name = str(item.get("name") or "").strip()
            version = str(item.get("version") or "").strip()
            ecosystem = str(item.get("ecosystem") or "").strip().lower()
            package = str(item.get("package") or "").strip()
        if not name or not version:
            continue
        key = (name.lower(), version, ecosystem)
        if key in seen:
            continue
        seen.add(key)
        entry = {"name": name, "version": version, "ecosystem": ecosystem}
        if package:
            entry["package"] = package
        out.append(entry)
    return out


def match_evidence(asset_id: str, evidence: Dict[str, Any]) -> List[baseline_guard.Finding]:
    """Offline advisory matching. One finding per CVE per asset."""
    software = normalize_software(evidence)
    if not software:
        return []
    findings: List[baseline_guard.Finding] = []
    seen = set()
    for pkg in software:
        names = [pkg["name"]]
        if pkg.get("package"):
            names.append(pkg["package"])
        for adv in _advisories():
            if adv.id in seen:
                continue
            if not any(adv.matches_product(n) for n in names):
                continue
            if not satisfies(pkg["version"], adv.affected):
                continue
            seen.add(adv.id)
            match = VulnMatch(
                advisory=adv,
                package=pkg["name"],
                version=pkg["version"],
                confidence=adv.confidence,
                source=adv.source,
                url=adv.url,
                limitation=adv.limitation,
            )
            findings.append(match.as_finding(asset_id))
    return findings


# -------------------------------------------------------------------- OSV ---

def _load_cache() -> Dict[str, Any]:
    global _OSV_CACHE
    if _OSV_CACHE is not None:
        return _OSV_CACHE
    try:
        with CACHE_PATH.open("r", encoding="utf-8") as fh:
            _OSV_CACHE = json.load(fh)
    except (OSError, json.JSONDecodeError):
        _OSV_CACHE = {}
    return _OSV_CACHE


def _save_cache(cache: Dict[str, Any]) -> None:
    try:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with CACHE_PATH.open("w", encoding="utf-8") as fh:
            json.dump(cache, fh)
    except OSError:
        pass


def _osv_severity(vuln: Dict[str, Any]) -> str:
    db = vuln.get("database_specific") or {}
    eco = vuln.get("ecosystem_specific") or {}
    for value in (db.get("severity"), eco.get("severity")):
        if isinstance(value, str) and value:
            v = value.lower()
            return {"moderate": "medium", "important": "high", "low": "low",
                    "medium": "medium", "high": "high", "critical": "critical"}.get(v, "medium")
    return "medium"


def _osv_fixed(vuln: Dict[str, Any], package: str) -> str:
    for affected in vuln.get("affected") or []:
        pkg = (affected.get("package") or {}).get("name", "")
        if package and pkg and pkg.lower() != package.lower():
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if event.get("fixed"):
                    return str(event["fixed"])
    return "vendor-fixed release"


def osv_query(software: Iterable[Dict[str, str]], timeout: float = 3.0) -> Tuple[List[baseline_guard.Finding], List[str]]:
    """Live OSV.dev lookup for language packages. Returns findings + warnings."""
    warnings: List[str] = []
    cache = _load_cache()
    now = time.time()
    queries: List[Dict[str, Any]] = []
    meta: List[Tuple[str, str, str]] = []
    for pkg in software:
        eco = _OSV_ECOSYSTEMS.get((pkg.get("ecosystem") or "").lower())
        if not eco:
            continue
        name = pkg.get("package") or pkg.get("name")
        version = pkg.get("version")
        if not name or not version:
            continue
        key = f"{eco}:{name}@{version}"
        cached = cache.get(key)
        if cached and now - float(cached.get("ts", 0)) < CACHE_TTL_SECONDS:
            continue
        queries.append({"package": {"name": name, "ecosystem": eco}, "version": version})
        meta.append((key, name, version))
    if not queries:
        return [], warnings
    payload = json.dumps({"queries": queries[:50]}).encode("utf-8")
    req = urllib.request.Request(
        OSV_BATCH_URL, data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "CivicShield/1.1"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        warnings.append(f"OSV.dev enrichment unavailable: {type(exc).__name__}")
        return [], warnings

    results = body.get("results") or []
    findings: List[baseline_guard.Finding] = []
    seen = set()
    for (key, name, version), result in zip(meta, results):
        cache[key] = {"ts": now, "vulns": result.get("vulns") or []}
        for vuln in result.get("vulns") or []:
            aliases = [str(a) for a in (vuln.get("aliases") or [])]
            cve = next((a for a in aliases if a.startswith("CVE-")), "")
            vuln_id = cve or str(vuln.get("id") or "")
            if not vuln_id or vuln_id in seen:
                continue
            seen.add(vuln_id)
            severity = _osv_severity(vuln)
            fixed = _osv_fixed(vuln, name)
            title = str(vuln.get("summary") or vuln.get("details") or vuln_id).strip()
            adv = Advisory(
                id=vuln_id, title=title[:240], product=name,
                aliases=tuple(aliases), ecosystem="osv", affected="declared version",
                fixed=fixed, severity=severity, cvss=0.0, known_exploited=False,
                exploit_available=False, confidence="high", published="",
                source="OSV.dev", url=f"https://osv.dev/vulnerability/{vuln.get('id', vuln_id)}",
                limitation="Live OSV.dev match for the declared package version; verify vendor backports.",
            )
            findings.append(VulnMatch(adv, name, version, "high", "OSV.dev", adv.url,
                                      adv.limitation).as_finding(""))
    _save_cache(cache)
    return findings, warnings


def scan(asset_id: str, evidence: Dict[str, Any], online: bool = False) -> Tuple[List[baseline_guard.Finding], List[str]]:
    """Offline-first scan with optional OSV enrichment, de-duplicated by CVE."""
    findings = match_evidence(asset_id, evidence)
    warnings: List[str] = []
    if online:
        live, warnings = osv_query(normalize_software(evidence))
        known = {f.rule_id for f in findings}
        for f in live:
            f.asset_id = str(asset_id)
            if f.rule_id not in known:
                findings.append(f)
                known.add(f.rule_id)
    return findings, warnings


def advisory_for(cve: str) -> Optional[Advisory]:
    for adv in _advisories():
        if adv.id.lower() == (cve or "").lower():
            return adv
    return None
