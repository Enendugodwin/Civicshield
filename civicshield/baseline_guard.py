"""BaselineGuard deterministic security assessment rules engine.

Stdlib only. Rules evaluate structured asset evidence dicts and return
PASS / FAIL / UNKNOWN / NOT_APPLICABLE. Missing information yields
UNKNOWN, never an invented failure or pass.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

PASS = "PASS"
FAIL = "FAIL"
UNKNOWN = "UNKNOWN"
NOT_APPLICABLE = "NOT_APPLICABLE"


class Outcome:
    PASS = PASS
    FAIL = FAIL
    UNKNOWN = UNKNOWN
    NOT_APPLICABLE = NOT_APPLICABLE


@dataclass(frozen=True)
class Rule:
    rule_id: str
    version: str
    name: str
    description: str
    category: str  # asset | identity | endpoint | backup
    severity: str  # critical | high | medium | low | info
    required_evidence: List[str]
    remediation: str


@dataclass
class Finding:
    rule_id: str
    rule_version: str
    rule_name: str
    category: str
    severity: str
    outcome: str
    confidence: str  # high | medium | low
    asset_id: str
    evidence_ref: str
    detail: str
    remediation: str
    assessed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {k: getattr(self, k) for k in (
            "rule_id", "rule_version", "rule_name", "category", "severity",
            "outcome", "confidence", "asset_id", "evidence_ref", "detail",
            "remediation", "assessed_at")}


@dataclass
class AssessmentResult:
    findings: List[Finding]

    def by_outcome(self, outcome: str) -> List[Finding]:
        return [f for f in self.findings if f.outcome == outcome]

    def to_dict(self) -> Dict[str, Any]:
        return {"findings": [f.to_dict() for f in self.findings]}


RuleFn = Callable[[Dict[str, Any]], Optional[bool]]
# RuleFn returns True=fail condition present, False=no fail, None=insufficient evidence.


@dataclass
class _RegisteredRule:
    meta: Rule
    evaluate: RuleFn
    confidence_fn: Callable[[Dict[str, Any]], str] | None = None


def _get(evidence: Dict[str, Any], *keys: str) -> Any:
    cur: Any = evidence
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def _missing(*values: Any) -> bool:
    return any(v is None for v in values)


def _mk(rule: Rule, fn: RuleFn) -> _RegisteredRule:
    return _RegisteredRule(meta=rule, evaluate=fn)


class BaselineGuard:
    """Deterministic rule registry + executor."""

    def __init__(self, rules: Optional[List[_RegisteredRule]] = None):
        self._rules: List[_RegisteredRule] = list(rules or [])

    def register(self, rule: _RegisteredRule) -> None:
        if any(r.meta.rule_id == rule.meta.rule_id for r in self._rules):
            raise ValueError(f"duplicate rule id: {rule.meta.rule_id}")
        self._rules.append(rule)

    @property
    def rules(self) -> List[Rule]:
        return [r.meta for r in self._rules]

    def assess_asset(self, asset_id: str, evidence: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        for reg in self._rules:
            verdict = reg.evaluate(evidence)
            if verdict is True:
                outcome, confidence = FAIL, "high"
            elif verdict is False:
                outcome, confidence = PASS, "high"
            else:
                outcome, confidence = UNKNOWN, "low"
            findings.append(Finding(
                rule_id=reg.meta.rule_id,
                rule_version=reg.meta.version,
                rule_name=reg.meta.name,
                category=reg.meta.category,
                severity=reg.meta.severity,
                outcome=outcome,
                confidence=confidence,
                asset_id=asset_id,
                evidence_ref=";".join(reg.meta.required_evidence),
                detail=reg.meta.description,
                remediation=reg.meta.remediation,
            ))
        return findings

    def assess_all(self, assets: Dict[str, Dict[str, Any]]) -> AssessmentResult:
        findings: List[Finding] = []
        for asset_id, evidence in assets.items():
            findings.extend(self.assess_asset(asset_id, evidence))
        return AssessmentResult(findings=findings)


# ---------------------------------------------------------------- rules ---

def build_default_engine() -> BaselineGuard:
    engine = BaselineGuard()
    R = [
        # ---- asset & exposure (6) ----
        _mk(Rule("BG-ASSET-001", "1.0.0", "Asset ownership assigned",
                 "Asset must declare an owner; missing owner is a FAIL.",
                 "asset", "medium", ["owner"], "Assign an accountable owner."),
            lambda e: None if _get(e, "owner") is None and "owner" not in e
            else (True if not _get(e, "owner") else False)),
        _mk(Rule("BG-ASSET-002", "1.0.0", "Supported operating system",
                 "OS in unsupported list (evidence os.name, os.supported) is FAIL; "
                 "absent lifecycle evidence is UNKNOWN.",
                 "asset", "high", ["os.name", "os.supported"], "Upgrade to a supported OS."),
            lambda e: None if _get(e, "os") is None
            else (False if _get(e, "os", "supported") is True
                  else (True if _get(e, "os", "supported") is False else None))),
        _mk(Rule("BG-ASSET-003", "1.0.0", "Security patch evidence current",
                 "patch_last_applied older than policy max age days is FAIL.",
                 "asset", "high", ["patch.last_applied", "patch.max_age_days"],
                 "Apply outstanding security patches."),
            lambda e: None if (_missing(_get(e, "patch", "last_applied"),
                                        _get(e, "patch", "max_age_days"))
            or _parse_dt(_get(e, "patch", "last_applied")) is None)
            else (True if _age_days(_parse_dt(_get(e, "patch", "last_applied")))
                  > float(_get(e, "patch", "max_age_days")) else False)),
        _mk(Rule("BG-ASSET-004", "1.0.0", "Remote admin not unexpectedly exposed",
                 "Remote admin (rdp/ssh/winrm) reachable from internet/wan is FAIL.",
                 "asset", "critical", ["network.remote_admin_exposed", "network.zone"],
                 "Restrict remote admin to management network / VPN."),
            lambda e: None if _get(e, "network", "remote_admin_exposed") is None
            else bool(_get(e, "network", "remote_admin_exposed"))),
        _mk(Rule("BG-ASSET-005", "1.0.0", "Firewall policy not overly broad",
                 "Ingress policy 'allow-all' or 0.0.0.0/0 on sensitive ports is FAIL.",
                 "asset", "high", ["firewall.ingress"],
                 "Restrict ingress to required sources and ports."),
            lambda e: None if _get(e, "firewall", "ingress") is None
            else ("0.0.0.0/0" in str(_get(e, "firewall", "ingress"))
                  or "allow-all" in str(_get(e, "firewall", "ingress")))),
        _mk(Rule("BG-ASSET-006", "1.0.0", "No unnecessary services",
                 "Declared unnecessary services list non-empty is FAIL.",
                 "asset", "low", ["services.unnecessary"],
                 "Disable unneeded services."),
            lambda e: None if _get(e, "services", "unnecessary") is None
            else bool(_get(e, "services", "unnecessary"))),
        # ---- identity & access (5) ----
        _mk(Rule("BG-ID-001", "1.0.0", "MFA for privileged accounts",
                 "Any privileged account without MFA evidence is FAIL.",
                 "identity", "critical", ["identity.privileged_accounts"],
                 "Enforce MFA on all privileged accounts."),
            lambda e: None if _get(e, "identity", "privileged_accounts") is None
            or any(a.get("mfa") is None
                   for a in _get(e, "identity", "privileged_accounts"))
            else any(a.get("mfa") is False
                     for a in _get(e, "identity", "privileged_accounts"))),
        _mk(Rule("BG-ID-002", "1.0.0", "No excessive admin permissions",
                 "Admin count above max_admins threshold is FAIL.",
                 "identity", "high", ["identity.admin_count", "identity.max_admins"],
                 "Remove unnecessary admin grants."),
            lambda e: None if _missing(_get(e, "identity", "admin_count"),
                                       _get(e, "identity", "max_admins"))
            else (_get(e, "identity", "admin_count") > _get(e, "identity", "max_admins"))),
        _mk(Rule("BG-ID-003", "1.0.0", "No shared privileged accounts",
                 "Shared/generic admin account indicators present is FAIL.",
                 "identity", "high", ["identity.shared_admin_accounts"],
                 "Replace shared accounts with named accounts."),
            lambda e: None if _get(e, "identity", "shared_admin_accounts") is None
            else bool(_get(e, "identity", "shared_admin_accounts"))),
        _mk(Rule("BG-ID-004", "1.0.0", "No stale privileged accounts",
                 "Privileged login older than max_idle_days is FAIL.",
                 "identity", "medium", ["identity.privileged_accounts"],
                 "Disable or rotate stale privileged accounts."),
            lambda e: None if _get(e, "identity", "privileged_accounts") is None
            or any(a.get("last_login") is None and "max_idle_days" not in a
                   for a in _get(e, "identity", "privileged_accounts"))
            or not any("last_login" in a and "max_idle_days" in a
                       for a in _get(e, "identity", "privileged_accounts"))
            else any(_parse_dt(a.get("last_login")) is not None
                     and _age_days(_parse_dt(a.get("last_login"))) > float(a["max_idle_days"])
                     for a in _get(e, "identity", "privileged_accounts")
                     if "last_login" in a and "max_idle_days" in a)),
        _mk(Rule("BG-ID-005", "1.0.0", "Least-privilege enforcement evidenced",
                 "Explicit least_privilege_enforced=false is FAIL; absent is UNKNOWN.",
                 "identity", "medium", ["identity.least_privilege_enforced"],
                 "Document and enforce least privilege."),
            lambda e: None if _get(e, "identity", "least_privilege_enforced") is None
            else (not bool(_get(e, "identity", "least_privilege_enforced")))),
        # ---- endpoint & monitoring (4) ----
        _mk(Rule("BG-ENDP-001", "1.0.0", "Endpoint protection present",
                 "edr_installed=false is FAIL; absent evidence is UNKNOWN.",
                 "endpoint", "high", ["endpoint.edr_installed"],
                 "Install and verify endpoint protection."),
            lambda e: None if _get(e, "endpoint", "edr_installed") is None
            else (not bool(_get(e, "endpoint", "edr_installed")))),
        _mk(Rule("BG-ENDP-002", "1.0.0", "Logging enabled",
                 "logging_enabled=false is FAIL; absent is UNKNOWN.",
                 "endpoint", "medium", ["endpoint.logging_enabled"],
                 "Enable and centralize logging."),
            lambda e: None if _get(e, "endpoint", "logging_enabled") is None
            else (not bool(_get(e, "endpoint", "logging_enabled")))),
        _mk(Rule("BG-ENDP-003", "1.0.0", "Monitoring coverage adequate",
                 "monitoring_coverage below 0.8 is FAIL.",
                 "endpoint", "medium", ["endpoint.monitoring_coverage"],
                 "Extend monitoring coverage to this asset."),
            lambda e: None if _get(e, "endpoint", "monitoring_coverage") is None
            else (float(_get(e, "endpoint", "monitoring_coverage")) < 0.8)),
        _mk(Rule("BG-ENDP-004", "1.0.0", "Security baseline verified",
                 "baseline_verified=false is FAIL; absent is UNKNOWN.",
                 "endpoint", "low", ["endpoint.baseline_verified"],
                 "Verify asset against the security baseline."),
            lambda e: None if _get(e, "endpoint", "baseline_verified") is None
            else (not bool(_get(e, "endpoint", "baseline_verified")))),
        # ---- backup & recovery (5) ----
        _mk(Rule("BG-BKP-001", "1.0.0", "Backups within policy age",
                 "Latest backup older than max_backup_age_days is FAIL.",
                 "backup", "high", ["backup.last_success", "backup.max_age_days"],
                 "Run a fresh backup and investigate failures."),
            lambda e: None if (_missing(_get(e, "backup", "last_success"),
                                        _get(e, "backup", "max_age_days"))
            or _parse_dt(_get(e, "backup", "last_success")) is None)
            else (_age_days(_parse_dt(_get(e, "backup", "last_success")))
                  > float(_get(e, "backup", "max_age_days")))),
        _mk(Rule("BG-BKP-002", "1.0.0", "Immutable/protected backup exists",
                 "immutable_backup=false is FAIL; absent is UNKNOWN.",
                 "backup", "high", ["backup.immutable_backup"],
                 "Configure immutable or offline backup copies."),
            lambda e: None if _get(e, "backup", "immutable_backup") is None
            else (not bool(_get(e, "backup", "immutable_backup")))),
        _mk(Rule("BG-BKP-003", "1.0.0", "Recovery test current",
                 "Recovery test older than max_test_age_days (or never) is FAIL.",
                 "backup", "medium", ["backup.last_recovery_test", "backup.max_test_age_days"],
                 "Execute and record a recovery test."),
            lambda e: None if _missing(_get(e, "backup", "max_test_age_days"))
            or (_get(e, "backup", "last_recovery_test") is not None
                and _parse_dt(_get(e, "backup", "last_recovery_test")) is None)
            else (True if _get(e, "backup", "last_recovery_test") is None
                  else _age_days(_parse_dt(_get(e, "backup", "last_recovery_test")))
                  > float(_get(e, "backup", "max_test_age_days")))),
        _mk(Rule("BG-BKP-004", "1.0.0", "Backup dependency recorded",
                 "backup_target absent/empty is FAIL only when backups_required=true; "
                 "UNKNOWN when requirement unknown.",
                 "backup", "medium", ["backup.backup_target", "backup.backups_required"],
                 "Record the asset backup dependency."),
            lambda e: None if _get(e, "backup", "backups_required") is None
            else (False if not _get(e, "backup", "backups_required")
                  else (not _get(e, "backup", "backup_target")))),
        _mk(Rule("BG-BKP-005", "1.0.0", "Critical service has recovery procedure",
                 "Critical asset without documented recovery_procedure is FAIL.",
                 "backup", "high", ["criticality", "backup.recovery_procedure"],
                 "Document a recovery procedure for the critical service."),
            lambda e: None if _missing(_get(e, "criticality"),
                                       _get(e, "backup", "recovery_procedure")
                                       if "backup" in e else None)
            and ("backup" not in e or _get(e, "backup", "recovery_procedure") is None)
            else (False if str(_get(e, "criticality")).lower() != "critical"
                  else (not _get(e, "backup", "recovery_procedure")
                        if "backup" in e else None))),
    ]
    for reg in R:
        engine.register(reg)
    return engine


def _parse_dt(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _age_days(ts: datetime) -> float:
    now = datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (now - ts).total_seconds() / 86400.0
