"""Phase 7 demo environments B (Cloud SaaS) and C (Hybrid Enterprise).

Reproducible, entirely fictional estates in the same dict shape as the
Environment A constants in seed.py. Each estate seeds one documented
weakness so detection, attack paths, proposals and the protector behave
deterministically on every environment:

- B "Northbridge Analytics" (Cloud SaaS): excessive permission on the
  cloud identity provider + public-access configuration on the API tier.
- C "Harborview Manufacturing" (Hybrid Enterprise): weak cross-environment
  trust (cloud workload on on-prem identity with shared admin accounts) +
  incomplete recovery dependency (untested, non-immutable backups).

Evidence shapes mirror Environment A so every built-in control evaluates
them; software versions reuse products from the bundled advisory snapshot
so CVE matching fires deterministically.
"""
from __future__ import annotations

import json
import time

ENVS = {
    "b": {
        "meta": {
            "id": "b",
            "name": "Northbridge Analytics (Cloud SaaS)",
            "blurb": "Fictional SaaS: public web app, API tier, cloud identity, "
                     "object storage, database, logging and backup.",
            "weakness": "Excessive permission on the identity provider "
                        "(8 admins, no least privilege) and public-access "
                        "API configuration (0.0.0.0/0 ingress).",
        },
    },
}


def _ev(owner="", os_name="Ubuntu 22.04", supported=True, **extra):
    """Compact evidence builder with sane healthy defaults."""
    evidence = {
        "owner": owner,
        "os": {"name": os_name, "supported": supported},
        "criticality": extra.pop("criticality", "high"),
        "endpoint": {"edr_installed": True, "logging_enabled": True,
                     "monitoring_coverage": 0.9, "baseline_verified": True},
        "backup": {"backups_required": True, "backup_target": "bkp01",
                   "recovery_procedure": "Redeploy from image"},
    }
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(evidence.get(key), dict):
            evidence[key].update(value)
        else:
            evidence[key] = value
    return evidence


def _asset(aid, name, kind, hostname, owner, os_name, environment, zone,
           criticality, reason, evidence, status="operational"):
    return {"id": aid, "name": name, "kind": kind, "hostname": hostname,
            "owner": owner, "os_name": os_name, "environment": environment,
            "zone": zone, "criticality": criticality,
            "criticality_reason": reason, "status": status,
            "evidence_json": json.dumps(evidence)}


ENVS["b"]["assets"] = [
    _asset(1, "Public Web App", "web", "web-pub01", "", "Ubuntu 22.04",
           "production", "external", "high", "Internet-facing storefront",
           _ev(owner="", firewall={"ingress": "0.0.0.0/0"},
               network={"remote_admin_exposed": False, "zone": "wan"})),
    _asset(2, "API Service", "server", "api01", "platform-team", "Ubuntu 22.04",
           "production", "core", "critical", "Serves all customer data",
           _ev(owner="platform-team", firewall={"ingress": "0.0.0.0/0"},
               network={"remote_admin_exposed": True, "zone": "wan"},
               patch={"last_applied": "2026-09-28T02:10:00Z", "max_age_days": 30})),
    _asset(3, "Cloud Identity Provider", "directory", "idp-cloud01",
           "platform-team", "Ubuntu 22.04", "production", "core", "critical",
           "Authenticates customers, staff and the API tier",
           _ev(owner="platform-team",
               identity={"privileged_accounts": [
                   {"name": "superadmin", "mfa": False,
                    "last_login": "2026-09-01T00:00:00Z", "max_idle_days": 90}],
                   "admin_count": 8, "max_admins": 3,
                   "shared_admin_accounts": ["sa-deploy"],
                   "least_privilege_enforced": False})),
    _asset(4, "Object Storage", "storage", "obj01", "platform-team",
           "n/a", "production", "core", "high", "Customer uploads and exports",
           _ev(owner="platform-team", firewall={"ingress": "0.0.0.0/0"},
               backup={"backups_required": True, "backup_target": "",
                       "recovery_procedure": ""})),
    _asset(5, "Customer Database", "database", "db-cloud01", "platform-team",
           "Ubuntu 22.04", "production", "core", "critical",
           "Billing records and customer data",
           _ev(owner="platform-team",
               backup={"last_success": "2026-09-20T01:30:00Z", "max_age_days": 7,
                       "immutable_backup": False, "last_recovery_test": None,
                       "max_test_age_days": 90, "backups_required": True,
                       "backup_target": "bkp01",
                       "recovery_procedure": "Restore from bkp01"})),
    _asset(6, "Admin Console", "workstation", "adm-cloud01", "",
           "Windows 11", "office", "office", "high",
           "Staff access to the admin API",
           _ev(owner="", os_name="Windows 11",
               identity={"privileged_accounts": [
                   {"name": "admin", "mfa": False,
                    "last_login": "2026-08-12T09:15:00Z", "max_idle_days": 90}],
                   "admin_count": 5, "max_admins": 3,
                   "least_privilege_enforced": False},
               endpoint={"edr_installed": False, "logging_enabled": True,
                         "monitoring_coverage": 0.5, "baseline_verified": False})),
    _asset(7, "Logging Service", "monitoring", "log-svc01", "platform-team",
           "Ubuntu 22.04", "production", "core", "moderate",
           "Central log aggregation",
           _ev(owner="platform-team",
               endpoint={"edr_installed": True, "logging_enabled": True,
                         "monitoring_coverage": 0.2, "baseline_verified": False})),
    _asset(8, "Backup Vault", "backup", "bkp01", "platform-team",
           "Ubuntu 22.04", "production", "core", "high",
           "All restores depend on it",
           _ev(owner="platform-team", criticality="high",
               backup={"last_success": "2026-10-25T00:00:00Z", "max_age_days": 7,
                       "immutable_backup": True,
                       "last_recovery_test": "2026-09-05T00:00:00Z",
                       "max_test_age_days": 90, "backups_required": False,
                       "backup_target": "",
                       "recovery_procedure": "Rebuild from offsite copy"})),
]

ENVS["b"]["software"] = {
    2: [
        {"name": "openssh-server", "version": "8.2p1-4ubuntu0.5", "ecosystem": "deb"},
        {"name": "log4j-core", "version": "2.14.1", "ecosystem": "maven",
         "package": "org.apache.logging.log4j:log4j-core"},
    ],
    5: [
        {"name": "openssl", "version": "1.1.1f-1ubuntu2.20", "ecosystem": "deb"},
        {"name": "postgresql-14", "version": "14.5-0ubuntu0.22.04.1", "ecosystem": "deb"},
    ],
    1: [{"name": "nginx", "version": "1.18.0-6ubuntu14", "ecosystem": "deb"}],
    8: [{"name": "openssh-server", "version": "9.0p1-1ubuntu0.1", "ecosystem": "deb"}],
}

ENVS["b"]["services"] = [
    {"id": 1, "name": "Customer Portal", "zone": "central",
     "population_served": 45200, "rto_minutes": 240,
     "recovery_procedure": "Restore db-cloud01 then api01 then web-pub01; validate login before reopening"},
    {"id": 2, "name": "Analytics API", "zone": "central",
     "population_served": 45200, "rto_minutes": 480,
     "recovery_procedure": "Redeploy api01 from image and re-run contract tests"},
]

ENVS["b"]["relationships"] = [
    {"source_type": "asset", "source_id": 2, "target_type": "asset",
     "target_id": 1, "rel": "depends_on"},
    {"source_type": "asset", "source_id": 2, "target_type": "asset",
     "target_id": 5, "rel": "depends_on"},
    {"source_type": "asset", "source_id": 2, "target_type": "asset",
     "target_id": 3, "rel": "authenticates_via"},
    {"source_type": "asset", "source_id": 6, "target_type": "asset",
     "target_id": 3, "rel": "authenticates_via"},
    {"source_type": "asset", "source_id": 5, "target_type": "asset",
     "target_id": 8, "rel": "backed_by"},
    {"source_type": "asset", "source_id": 7, "target_type": "asset",
     "target_id": 2, "rel": "monitors"},
    {"source_type": "asset", "source_id": 1, "target_type": "service",
     "target_id": 1, "rel": "supplies"},
    {"source_type": "asset", "source_id": 3, "target_type": "service",
     "target_id": 1, "rel": "supplies"},
    {"source_type": "asset", "source_id": 2, "target_type": "service",
     "target_id": 2, "rel": "supplies"},
    {"source_type": "asset", "source_id": 5, "target_type": "service",
     "target_id": 2, "rel": "supplies"},
]

ENVS["b"]["backup_records"] = [
    {"asset_id": "5", "last_success": "2026-09-20T01:30:00Z", "immutable_backup": 0},
    {"asset_id": "8", "last_success": "2026-10-25T00:00:00Z", "immutable_backup": 1},
]

ENVS["b"]["incidents"] = [
    {"title": "Admin API key found in client-side bundle", "status": "investigating",
     "severity": "high", "commander": "Platform On-Call", "age_hours": 9,
     "events": [
         ("observed", "A customer reported that the web app ships an admin-scoped API key."),
         ("evidence", "The key has write access to the analytics API and no expiry."),
         ("interpretation", "Excessive permission shipped to browsers; rotation alone does not fix the scope."),
         ("suggestion", "Scope the key to read-only, rotate it, and move admin calls server-side."),
     ]},
    {"title": "Storage export link shared externally", "status": "open",
     "severity": "medium", "commander": "", "age_hours": 30,
     "events": [
         ("observed", "An object-storage export link was shared outside the company."),
         ("evidence", "The bucket allows public reads; access logs are incomplete."),
         ("suggestion", "Disable public reads and re-issue signed links with expiry."),
     ]},
]

ENVS["b"]["indicators"] = [
    {"value": "portal-refresh.example", "kind": "domain", "confidence": "medium",
     "source": "SaaS abuse desk observation", "days": 30},
    {"value": "fake invoice SaaS lure", "kind": "campaign", "confidence": "medium",
     "source": "Cross-sector sharing group", "days": 90},
]

ENVS["c"] = {
    "meta": {
        "id": "c",
        "name": "Harborview Manufacturing (Hybrid Enterprise)",
        "blurb": "Fictional manufacturer: on-prem identity, VPN gateway, cloud "
                 "workload, SIEM, backup service and ERP database.",
        "weakness": "Weak cross-environment trust (cloud workload on on-prem "
                    "identity with shared admin accounts, no least privilege) "
                    "and incomplete recovery dependency (untested, "
                    "non-immutable backups).",
    },
}

ENVS["c"]["assets"] = [
    _asset(1, "On-Prem Identity", "directory", "idp-onprem01", "it-team",
           "Windows Server 2019", "production", "core", "critical",
           "Authenticates staff, plant and the cloud workload",
           _ev(owner="it-team", os_name="Windows Server 2019",
               identity={"privileged_accounts": [
                   {"name": "shift-lead", "mfa": False,
                    "last_login": "2026-07-02T06:00:00Z", "max_idle_days": 90}],
                   "admin_count": 7, "max_admins": 3,
                   "shared_admin_accounts": ["shift-lead"],
                   "least_privilege_enforced": False})),
    _asset(2, "VPN Gateway", "firewall", "vpn-gw01", "net-team",
           "PAN-OS 10.1.0", "production", "edge", "critical",
           "Only remote path into the plant network",
           _ev(owner="net-team", os_name="PAN-OS 10.1.0", supported=False,
               firewall={"ingress": "restricted"},
               network={"remote_admin_exposed": True, "zone": "edge"})),
    _asset(3, "Cloud Workload", "server", "cloudvm01", "platform-team",
           "Ubuntu 22.04", "production", "cloud", "high",
           "Runs order sync against on-prem identity",
           _ev(owner="platform-team",
               network={"remote_admin_exposed": False, "zone": "cloud"})),
    _asset(4, "SIEM", "monitoring", "siem01", "soc-team", "Ubuntu 22.04",
           "production", "core", "high", "Detects plant and cloud threats",
           _ev(owner="soc-team",
               endpoint={"edr_installed": True, "logging_enabled": True,
                         "monitoring_coverage": 0.3, "baseline_verified": False})),
    _asset(5, "Backup Service", "backup", "bkp-ent01", "it-team",
           "Ubuntu 22.04", "production", "core", "high",
           "All restores depend on it",
           _ev(owner="it-team", criticality="high",
               backup={"last_success": "2026-10-24T00:00:00Z", "max_age_days": 7,
                       "immutable_backup": False, "last_recovery_test": None,
                       "max_test_age_days": 90, "backups_required": False,
                       "backup_target": "",
                       "recovery_procedure": "Rebuild from offsite copy"})),
    _asset(6, "ERP Database", "database", "erp01", "it-team",
           "Ubuntu 20.04", "production", "core", "critical",
           "Orders, inventory and payroll",
           _ev(owner="it-team", os_name="Ubuntu 20.04", supported=False,
               backup={"last_success": "2026-10-23T01:30:00Z", "max_age_days": 7,
                       "immutable_backup": False, "last_recovery_test": None,
                       "max_test_age_days": 90, "backups_required": True,
                       "backup_target": "bkp-ent01",
                       "recovery_procedure": "Restore from bkp-ent01"},
               patch={"last_applied": "2026-08-30T02:10:00Z", "max_age_days": 30})),
    _asset(7, "Finance Workstation", "workstation", "fin-ws01", "",
           "Windows 11", "office", "office", "high",
           "Order entry and invoicing",
           _ev(owner="", os_name="Windows 11",
               endpoint={"edr_installed": False, "logging_enabled": True,
                         "monitoring_coverage": 0.5, "baseline_verified": False})),
]

ENVS["c"]["software"] = {
    3: [
        {"name": "openssh-server", "version": "8.2p1-4ubuntu0.5", "ecosystem": "deb"},
        {"name": "curl", "version": "7.81.0-1ubuntu1.14", "ecosystem": "deb"},
    ],
    6: [
        {"name": "openssl", "version": "1.1.1f-1ubuntu2.20", "ecosystem": "deb"},
        {"name": "postgresql-14", "version": "14.5-0ubuntu0.22.04.1", "ecosystem": "deb"},
    ],
    1: [{"name": "Windows Server 2019", "version": "10.0.17763", "ecosystem": "windows"}],
}

ENVS["c"]["services"] = [
    {"id": 1, "name": "Order Processing", "zone": "central",
     "population_served": 9800, "rto_minutes": 240,
     "recovery_procedure": "Restore erp01 then cloudvm01; validate order queue before reopening"},
    {"id": 2, "name": "Shop Floor Monitoring", "zone": "plant",
     "population_served": 9800, "rto_minutes": 120, "recovery_procedure": ""},
]

ENVS["c"]["relationships"] = [
    {"source_type": "asset", "source_id": 3, "target_type": "asset",
     "target_id": 1, "rel": "authenticates_via"},
    {"source_type": "asset", "source_id": 7, "target_type": "asset",
     "target_id": 1, "rel": "authenticates_via"},
    {"source_type": "asset", "source_id": 6, "target_type": "asset",
     "target_id": 1, "rel": "authenticates_via"},
    {"source_type": "asset", "source_id": 6, "target_type": "asset",
     "target_id": 5, "rel": "backed_by"},
    {"source_type": "asset", "source_id": 3, "target_type": "asset",
     "target_id": 5, "rel": "backed_by"},
    {"source_type": "asset", "source_id": 1, "target_type": "asset",
     "target_id": 2, "rel": "depends_on"},
    {"source_type": "asset", "source_id": 4, "target_type": "asset",
     "target_id": 6, "rel": "monitors"},
    {"source_type": "asset", "source_id": 4, "target_type": "asset",
     "target_id": 3, "rel": "monitors"},
    {"source_type": "asset", "source_id": 6, "target_type": "service",
     "target_id": 1, "rel": "supplies"},
    {"source_type": "asset", "source_id": 1, "target_type": "service",
     "target_id": 1, "rel": "supplies"},
    {"source_type": "asset", "source_id": 2, "target_type": "service",
     "target_id": 1, "rel": "supplies"},
    {"source_type": "asset", "source_id": 3, "target_type": "service",
     "target_id": 2, "rel": "supplies"},
]

ENVS["c"]["backup_records"] = [
    {"asset_id": "6", "last_success": "2026-10-23T01:30:00Z", "immutable_backup": 0},
    {"asset_id": "5", "last_success": "2026-10-24T00:00:00Z", "immutable_backup": 0},
]

ENVS["c"]["incidents"] = [
    {"title": "VPN login from unusual country", "status": "investigating",
     "severity": "high", "commander": "SOC Lead", "age_hours": 14,
     "events": [
         ("observed", "A VPN login for a shared admin account came from an unusual country."),
         ("evidence", "The account has no MFA and is shared across the night shift."),
         ("interpretation", "Shared credential without MFA cannot be attributed; treat as untrusted."),
         ("suggestion", "Disable the shared account and issue named accounts with MFA."),
     ]},
    {"title": "Backup restore test overdue", "status": "open",
     "severity": "medium", "commander": "", "age_hours": 200,
     "events": [
         ("observed", "No restore test has been recorded for the backup service."),
         ("evidence", "The last recovery test field is empty and backups are not immutable."),
         ("suggestion", "Run a test restore of erp01 to an isolated host and record the result."),
     ]},
]

ENVS["c"]["indicators"] = [
    {"value": "vendor-remote.example", "kind": "domain", "confidence": "low",
     "source": "Vendor support channel log", "days": 30},
    {"value": "payroll lure", "kind": "campaign", "confidence": "medium",
     "source": "Manufacturing ISAC bulletin", "days": 60},
]


def prepare_estate(env_id: str) -> dict:
    """Attach collector metadata + software inventory, mirroring seed._prepared_assets."""
    spec = ENVS[env_id]
    now = time.time()
    rows = []
    for source in spec["assets"]:
        row = dict(source)
        evidence = json.loads(row["evidence_json"])
        evidence["collector"] = {
            "source": "seed-fixture",
            "version": "1.1.0",
            "collected_at": now,
            "hostname": row.get("hostname", ""),
        }
        if row["id"] in spec.get("software", {}):
            evidence["software"] = spec["software"][row["id"]]
        row["evidence_json"] = json.dumps(evidence)
        rows.append(row)
    return {"assets": rows, "services": spec["services"],
            "relationships": spec["relationships"],
            "backup_records": spec["backup_records"],
            "incidents": spec["incidents"], "indicators": spec["indicators"]}
