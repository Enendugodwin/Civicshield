"""Tool catalog: deterministic gap -> recommendation mapping."""
from app import tool_catalog as tc


def test_gaps_derive_from_evidence_only():
    ev = {"os": {"name": "Windows 10"},
          "endpoint": {"edr_installed": False, "monitoring_coverage": 0.5},
          "backup": {"backups_required": True, "backup_target": "",
                     "immutable_backup": False},
          "identity": {"privileged_accounts": [{"name": "admin", "mfa": False}],
                       "shared_admin_accounts": ["administrator"]},
          "network": {"remote_admin_exposed": True},
          "services": {"unnecessary": ["telnet"]}}
    gaps = tc.gaps_for_evidence(ev, False, zone="office", kind="workstation")
    assert {"unsupported_os", "missing_edr", "low_monitoring", "no_backup",
            "missing_mfa", "shared_admin", "remote_admin",
            "unnecessary_services"} <= set(gaps)


def test_clean_asset_yields_no_gaps():
    ev = {"os": {"name": "Ubuntu 22.04"},
          "endpoint": {"edr_installed": True, "monitoring_coverage": 0.95},
          "backup": {"backups_required": False}}
    assert tc.gaps_for_evidence(ev, True, zone="core", kind="server") == []


def test_recommendations_bounded_and_labeled():
    recs = tc.recommend(["unsupported_os", "missing_edr", "low_monitoring",
                         "no_backup", "missing_mfa"], limit=2)
    assert len(recs) == 2
    for r in recs:
        assert r["category"] and r["why"] and r["note"]
        assert r["open_source"] and r["commercial"]
    assert tc.describe()[0]["gap"]
