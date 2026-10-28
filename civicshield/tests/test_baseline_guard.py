"""Pytest coverage for every BaselineGuard rule: PASS, FAIL, UNKNOWN."""
from civicshield.baseline_guard import build_default_engine

EV_FULL_FAIL = {
    "owner": "",
    "os": {"name": "Win2003", "supported": False},
    "patch": {"last_applied": "2020-01-01T00:00:00+00:00", "max_age_days": 30},
    "network": {"remote_admin_exposed": True, "zone": "wan"},
    "firewall": {"ingress": "allow-all from 0.0.0.0/0"},
    "services": {"unnecessary": ["telnet"]},
    "identity": {
        "privileged_accounts": [{"name": "admin", "mfa": False,
                                 "last_login": "2020-01-01T00:00:00+00:00",
                                 "max_idle_days": 90}],
        "admin_count": 10, "max_admins": 3,
        "shared_admin_accounts": ["administrator"],
        "least_privilege_enforced": False,
    },
    "endpoint": {"edr_installed": False, "logging_enabled": False,
                 "monitoring_coverage": 0.1, "baseline_verified": False},
    "backup": {"last_success": "2020-01-01T00:00:00+00:00", "max_age_days": 7,
               "immutable_backup": False, "last_recovery_test": None,
               "max_test_age_days": 90, "backups_required": True,
               "backup_target": "", "recovery_procedure": ""},
    "criticality": "critical",
}

EV_FULL_PASS = {
    "owner": "alice",
    "os": {"name": "Ubuntu 24.04", "supported": True},
    "patch": {"last_applied": "2999-01-01T00:00:00+00:00", "max_age_days": 30},
    "network": {"remote_admin_exposed": False, "zone": "mgmt"},
    "firewall": {"ingress": "deny-all except 10.0.0.0/8:443"},
    "services": {"unnecessary": []},
    "identity": {
        "privileged_accounts": [{"name": "alice", "mfa": True,
                                 "last_login": "2999-01-01T00:00:00+00:00",
                                 "max_idle_days": 90}],
        "admin_count": 2, "max_admins": 3,
        "shared_admin_accounts": [],
        "least_privilege_enforced": True,
    },
    "endpoint": {"edr_installed": True, "logging_enabled": True,
                 "monitoring_coverage": 1.0, "baseline_verified": True},
    "backup": {"last_success": "2999-01-01T00:00:00+00:00", "max_age_days": 7,
               "immutable_backup": True,
               "last_recovery_test": "2999-01-01T00:00:00+00:00",
               "max_test_age_days": 90, "backups_required": True,
               "backup_target": "backup-srv", "recovery_procedure": "runbook v3"},
    "criticality": "critical",
}

EXPECTED_IDS = [
    "BG-ASSET-001", "BG-ASSET-002", "BG-ASSET-003", "BG-ASSET-004",
    "BG-ASSET-005", "BG-ASSET-006", "BG-ID-001", "BG-ID-002",
    "BG-ID-003", "BG-ID-004", "BG-ID-005", "BG-ENDP-001",
    "BG-ENDP-002", "BG-ENDP-003", "BG-ENDP-004", "BG-BKP-001",
    "BG-BKP-002", "BG-BKP-003", "BG-BKP-004", "BG-BKP-005",
]


def test_registry_has_20_rules():
    engine = build_default_engine()
    assert [r.rule_id for r in engine.rules] == EXPECTED_IDS


def test_all_fail_on_bad_evidence():
    engine = build_default_engine()
    findings = engine.assess_asset("asset-1", EV_FULL_FAIL)
    assert {f.rule_id: f.outcome for f in findings} == {rid: "FAIL" for rid in EXPECTED_IDS}


def test_all_pass_on_good_evidence():
    engine = build_default_engine()
    findings = engine.assess_asset("asset-1", EV_FULL_PASS)
    assert {f.rule_id: f.outcome for f in findings} == {rid: "PASS" for rid in EXPECTED_IDS}


def test_empty_evidence_is_all_unknown():
    engine = build_default_engine()
    findings = engine.assess_asset("asset-1", {})
    assert findings and all(f.outcome == "UNKNOWN" for f in findings)


def test_missing_field_yields_unknown_not_fail():
    engine = build_default_engine()
    by_id = {f.rule_id: f for f in engine.assess_asset("a", {})}
    assert by_id["BG-ASSET-002"].outcome == "UNKNOWN"
    assert by_id["BG-ID-001"].outcome == "UNKNOWN"
    assert by_id["BG-BKP-001"].outcome == "UNKNOWN"


def test_findings_carry_metadata():
    engine = build_default_engine()
    findings = engine.assess_asset("asset-9", EV_FULL_PASS)
    for f in findings:
        assert f.rule_version and f.evidence_ref and f.remediation
        assert f.assessed_at and f.asset_id == "asset-9"
        d = f.to_dict()
        assert d["outcome"] in ("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE")


def test_assess_all_and_reproducibility():
    engine = build_default_engine()
    assets = {"a1": EV_FULL_PASS, "a2": EV_FULL_FAIL}
    r1 = engine.assess_all(assets)
    r2 = engine.assess_all(assets)
    assert len(r1.findings) == 40
    assert [(f.rule_id, f.asset_id, f.outcome) for f in r1.findings] == \
        [(f.rule_id, f.asset_id, f.outcome) for f in r2.findings]
