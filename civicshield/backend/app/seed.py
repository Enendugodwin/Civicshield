"""Deterministic seed: 13 assets, 3 services, incidents and evidence fixtures.

The data represents a small municipal water utility (about 18,400 residents)
with an edge router, firewall, core/plant switches, servers, workstations and a
single external billing dependency.
"""
from __future__ import annotations

import json
import time

from app.database import Base, SessionLocal, engine
from app.models.models import (
    Asset,
    AssetRelationship,
    AssessmentResult,
    AssessmentRun,
    BackupRecord,
    Finding,
    Incident,
    IncidentEvent,
    IncidentFindingLink,
    RiskAssessment,
    Service,
    ThreatIndicator,
)

ASSETS = [
    {"id": 1, "name": "Admin Workstation", "kind": "workstation", "hostname": "adm-ws01", "owner": "", "os_name": "Windows 10", "environment": "office", "zone": "office", "criticality": "critical", "criticality_reason": "Holds admin credentials for billing service", "status": "operational", "evidence_json": json.dumps({"owner": "", "os": {"name": "Windows 10", "supported": False}, "identity": {"privileged_accounts": [{"name": "admin", "mfa": False, "last_login": "2026-05-12T09:15:00Z", "max_idle_days": 90}], "admin_count": 6, "max_admins": 3, "shared_admin_accounts": ["administrator"], "least_privilege_enforced": False}, "endpoint": {"edr_installed": False, "logging_enabled": True, "monitoring_coverage": 0.5, "baseline_verified": False}, "criticality": "critical", "backup": {"backups_required": True, "backup_target": "", "recovery_procedure": ""}})},
    {"id": 2, "name": "Operations Workstation", "kind": "workstation", "hostname": "ops-ws01", "owner": "ops-team", "os_name": "Windows 11", "environment": "operations", "zone": "plant", "criticality": "high", "criticality_reason": "Monitors treatment plant", "status": "operational", "evidence_json": json.dumps({"owner": "ops-team", "os": {"name": "Windows 11", "supported": True}, "endpoint": {"edr_installed": True, "logging_enabled": True, "monitoring_coverage": 0.9, "baseline_verified": True}, "criticality": "high", "backup": {"backups_required": True, "backup_target": "backup-server", "recovery_procedure": "Reimage from gold image"}})},
    {"id": 3, "name": "Identity Server", "kind": "directory", "hostname": "idp01", "owner": "it-team", "os_name": "Ubuntu 22.04", "environment": "core", "zone": "core", "criticality": "critical", "criticality_reason": "Authenticates all operators", "status": "operational", "evidence_json": json.dumps({"owner": "it-team", "os": {"name": "Ubuntu 22.04", "supported": True}, "identity": {"privileged_accounts": [{"name": "root", "mfa": True, "last_login": "2026-10-01T00:00:00Z", "max_idle_days": 90}], "admin_count": 2, "max_admins": 3, "least_privilege_enforced": True}, "endpoint": {"edr_installed": True, "logging_enabled": True, "monitoring_coverage": 0.95, "baseline_verified": True}, "criticality": "critical", "backup": {"backups_required": True, "backup_target": "backup-server", "recovery_procedure": "Restore the identity database from immutable backup and re-validate operator logins"}})},
    {"id": 4, "name": "Application Server", "kind": "server", "hostname": "app01", "owner": "it-team", "os_name": "Ubuntu 20.04", "environment": "core", "zone": "core", "criticality": "high", "criticality_reason": "Hosts billing app", "status": "operational", "evidence_json": json.dumps({"owner": "it-team", "os": {"name": "Ubuntu 20.04", "supported": True}, "patch": {"last_applied": "2026-08-18T02:10:00Z", "max_age_days": 30}, "network": {"remote_admin_exposed": True, "zone": "wan"}, "firewall": {"ingress": "0.0.0.0/0"}, "services": {"unnecessary": ["telnet"]}, "endpoint": {"edr_installed": True, "logging_enabled": False, "monitoring_coverage": 0.4, "baseline_verified": False}, "criticality": "high", "backup": {"backups_required": True, "backup_target": "backup-server", "recovery_procedure": "Redeploy from image"}})},
    {"id": 5, "name": "Database Server", "kind": "database", "hostname": "db01", "owner": "it-team", "os_name": "Ubuntu 22.04", "environment": "core", "zone": "core", "criticality": "critical", "criticality_reason": "Stores billing + operations data", "status": "operational", "evidence_json": json.dumps({"owner": "it-team", "os": {"name": "Ubuntu 22.04", "supported": True}, "patch": {"last_applied": "2026-10-20T00:00:00Z", "max_age_days": 30}, "endpoint": {"edr_installed": True, "logging_enabled": True, "monitoring_coverage": 0.9, "baseline_verified": True}, "criticality": "critical", "backup": {"last_success": "2026-10-10T01:30:00Z", "max_age_days": 7, "immutable_backup": False, "last_recovery_test": None, "max_test_age_days": 90, "backups_required": True, "backup_target": "backup-server", "recovery_procedure": "Restore from backup-server"}})},
    {"id": 6, "name": "Gateway Firewall", "kind": "firewall", "hostname": "gw01", "owner": "net-team", "os_name": "PAN-OS 11.0.0", "environment": "edge", "zone": "edge", "criticality": "critical", "criticality_reason": "Single ingress point", "status": "operational", "evidence_json": json.dumps({"owner": "net-team", "os": {"name": "PAN-OS 11.0.0", "supported": True}, "network": {"remote_admin_exposed": False, "zone": "edge"}, "firewall": {"ingress": "restricted"}, "criticality": "critical", "backup": {"backups_required": True, "backup_target": "backup-server", "recovery_procedure": "Restore firewall config"}})},
    {"id": 7, "name": "Backup Server", "kind": "backup", "hostname": "bkp01", "owner": "it-team", "os_name": "Ubuntu 22.04", "environment": "core", "zone": "core", "criticality": "high", "criticality_reason": "All restores depend on it", "status": "operational", "evidence_json": json.dumps({"owner": "it-team", "endpoint": {"edr_installed": False, "logging_enabled": True, "monitoring_coverage": 0.6, "baseline_verified": True}, "criticality": "high", "backup": {"last_success": "2026-10-25T00:00:00Z", "max_age_days": 7, "immutable_backup": True, "last_recovery_test": "2026-05-05T00:00:00Z", "max_test_age_days": 90, "backups_required": False, "backup_target": "", "recovery_procedure": "Rebuild from offsite copy"}})},
    {"id": 8, "name": "Water Monitoring WS", "kind": "workstation", "hostname": "wmon01", "owner": "ops-team", "os_name": "Windows 11", "environment": "operations", "zone": "plant", "criticality": "high", "criticality_reason": "Reads plant sensors", "status": "operational", "evidence_json": json.dumps({"owner": "ops-team", "os": {"name": "Windows 11", "supported": True}, "endpoint": {"edr_installed": True, "logging_enabled": True, "monitoring_coverage": 0.85, "baseline_verified": True}, "criticality": "high", "backup": {"backups_required": False, "backup_target": "", "recovery_procedure": ""}})},
    {"id": 9, "name": "Logging Server", "kind": "monitoring", "hostname": "log01", "owner": "", "os_name": "Ubuntu 22.04", "environment": "core", "zone": "core", "criticality": "moderate", "criticality_reason": "Central log aggregation", "status": "degraded", "evidence_json": json.dumps({"owner": "", "endpoint": {"edr_installed": True, "logging_enabled": True, "monitoring_coverage": 0.3, "baseline_verified": False}, "criticality": "moderate", "backup": {"backups_required": True, "backup_target": "backup-server", "recovery_procedure": ""}})},
    {"id": 10, "name": "Cloud Billing SaaS", "kind": "external", "hostname": "billing.vendor.example", "owner": "finance", "os_name": "n/a", "environment": "external", "zone": "external", "criticality": "moderate", "criticality_reason": "Offsite billing dependency", "status": "operational", "evidence_json": json.dumps({"owner": "finance", "criticality": "moderate", "backup": {"backups_required": False, "backup_target": "", "recovery_procedure": "Vendor SLA"}})},
    {"id": 11, "name": "Core Network Switch", "kind": "switch", "hostname": "sw-core01", "owner": "net-team", "os_name": "Cisco IOS 15.2", "environment": "core", "zone": "core", "criticality": "critical", "criticality_reason": "Carries all core, office and plant network traffic", "status": "operational", "evidence_json": json.dumps({"owner": "net-team", "os": {"name": "Cisco IOS 15.2", "supported": False}, "network": {"remote_admin_exposed": False, "zone": "core"}, "firewall": {"ingress": "restricted"}, "services": {"unnecessary": []}, "criticality": "critical", "backup": {"backups_required": True, "backup_target": "backup-server", "recovery_procedure": "Restore startup configuration from backup-server and validate uplinks"}})},
    {"id": 12, "name": "Edge Router", "kind": "router", "hostname": "rtr-edge01", "owner": "net-team", "os_name": "RouterOS 7.11", "environment": "edge", "zone": "edge", "criticality": "critical", "criticality_reason": "Only network path to the ISP", "status": "operational", "evidence_json": json.dumps({"owner": "net-team", "os": {"name": "RouterOS 7.11", "supported": True}, "network": {"remote_admin_exposed": False, "zone": "edge"}, "firewall": {"ingress": "restricted"}, "services": {"unnecessary": []}, "criticality": "critical", "backup": {"backups_required": True, "backup_target": "backup-server", "recovery_procedure": "Restore exported router configuration and re-establish the ISP link"}})},
    {"id": 13, "name": "Plant Distribution Switch", "kind": "switch", "hostname": "sw-plant01", "owner": "ops-team", "os_name": "Cisco IOS 15.2", "environment": "operations", "zone": "plant", "criticality": "high", "criticality_reason": "Connects plant sensors, monitoring and operator workstations", "status": "operational", "evidence_json": json.dumps({"owner": "ops-team", "os": {"name": "Cisco IOS 15.2", "supported": False}, "network": {"remote_admin_exposed": False, "zone": "plant"}, "firewall": {"ingress": "restricted"}, "services": {"unnecessary": []}, "criticality": "high", "backup": {"backups_required": True, "backup_target": "backup-server", "recovery_procedure": "Restore startup configuration from backup-server"}})},
]

# Declared software inventories used by the vulnerability matcher. These are
# synthetic fixtures for the demo, deliberately containing a mix of vulnerable
# and already-fixed versions so detection has a reproducible result.
SOFTWARE = {
    1: [{"name": "Windows 10", "version": "10.0.19044", "ecosystem": "windows"}],
    2: [{"name": "Windows 11", "version": "10.0.22631", "ecosystem": "windows"}],
    3: [
        {"name": "openssh-server", "version": "8.9p1-3ubuntu0.3", "ecosystem": "deb"},
        {"name": "glibc", "version": "2.35-0ubuntu3.8", "ecosystem": "deb"},
        {"name": "openssl", "version": "3.0.2-0ubuntu1.15", "ecosystem": "deb"},
        {"name": "curl", "version": "7.81.0-1ubuntu1.14", "ecosystem": "deb"},
    ],
    4: [
        {"name": "openssh-server", "version": "8.2p1-4ubuntu0.5", "ecosystem": "deb"},
        {"name": "openssl", "version": "1.1.1f-1ubuntu2.20", "ecosystem": "deb"},
        {"name": "log4j-core", "version": "2.14.1", "ecosystem": "maven",
         "package": "org.apache.logging.log4j:log4j-core"},
        {"name": "apache2", "version": "2.4.49-4ubuntu1", "ecosystem": "deb"},
    ],
    5: [
        {"name": "openssh-server", "version": "8.9p1-3ubuntu0.4", "ecosystem": "deb"},
        {"name": "glibc", "version": "2.35-0ubuntu3.8", "ecosystem": "deb"},
        {"name": "curl", "version": "7.81.0-1ubuntu1.14", "ecosystem": "deb"},
        {"name": "postgresql-14", "version": "14.5-0ubuntu0.22.04.1", "ecosystem": "deb"},
    ],
    6: [{"name": "pan-os", "version": "11.0.0", "ecosystem": "firmware"}],
    7: [
        {"name": "openssh-server", "version": "9.0p1-1ubuntu0.1", "ecosystem": "deb"},
        {"name": "glibc", "version": "2.35-0ubuntu3.8", "ecosystem": "deb"},
        {"name": "openssl", "version": "3.0.2-0ubuntu1.15", "ecosystem": "deb"},
    ],
    8: [{"name": "Windows 11", "version": "10.0.22631", "ecosystem": "windows"}],
    9: [
        {"name": "openssh-server", "version": "8.9p1-3ubuntu0.1", "ecosystem": "deb"},
        {"name": "glibc", "version": "2.35-0ubuntu3.8", "ecosystem": "deb"},
        {"name": "curl", "version": "7.81.0-1ubuntu1.14", "ecosystem": "deb"},
    ],
    11: [{"name": "cisco-ios", "version": "15.2", "ecosystem": "firmware"}],
    12: [{"name": "routeros", "version": "7.11", "ecosystem": "firmware"}],
    13: [{"name": "cisco-ios", "version": "15.2", "ecosystem": "firmware"}],
}


INCIDENTS = [
    {
        "title": "Invoice-themed phishing reported by finance",
        "status": "investigating",
        "severity": "medium",
        "commander": "IT Duty Officer",
        "age_hours": 3,
        "events": [
            ("observed", "Finance forwarded an invoice email from a lookalike billing domain; no attachment was opened."),
            ("evidence", "Sender domain was registered four days ago and failed SPF and DKIM checks."),
            ("interpretation", "Consistent with business email compromise reconnaissance; no credential entry was reported."),
            ("suggestion", "Block the sender domain at the mail gateway and reset the recipient's active sessions."),
            ("decision", "Email gateway block approved by the IT duty officer."),
        ],
    },
    {
        "title": "Unexpected privileged login on app01",
        "status": "contained",
        "severity": "high",
        "commander": "IT Operations Lead",
        "age_hours": 26,
        "events": [
            ("observed", "A privileged login to app01 originated from the office VLAN outside the maintenance window."),
            ("evidence", "Authentication logs show a valid administrator account; MFA status is unknown in the collected evidence."),
            ("interpretation", "Possible credential misuse; administrator error cannot yet be excluded."),
            ("suggestion", "Rotate the administrator credential and review commands executed during the session."),
            ("decision", "Containment approved: credential rotated and the session terminated."),
        ],
    },
    {
        "title": "Database backup window missed twice",
        "status": "open",
        "severity": "high",
        "commander": "",
        "age_hours": 52,
        "events": [
            ("observed", "The db01 nightly backup failed on two consecutive runs."),
            ("evidence", "The backup server reports insufficient free space on the repository volume."),
            ("suggestion", "Free repository space, rerun the backup and verify a restore before closing."),
        ],
    },
]

THREAT_INDICATORS = [
    {"value": "billing-verify.example", "kind": "domain", "confidence": "high",
     "source": "CommunityShield member report (verified, privacy-preserving)", "days": 60},
    {"value": "invoice-portal.example", "kind": "domain", "confidence": "medium",
     "source": "Municipal email gateway observation", "days": 30},
    {"value": "invoice-themed credential phishing", "kind": "campaign", "confidence": "medium",
     "source": "Regional water-sector information exchange", "days": 90},
]


def _prepared_assets() -> list[dict]:
    """Attach collector metadata + software inventory without mutating ASSETS."""
    now = time.time()
    rows = []
    for source in ASSETS:
        row = dict(source)
        evidence = json.loads(row["evidence_json"])
        evidence["collector"] = {
            "source": "seed-fixture",
            "version": "1.1.0",
            "collected_at": now,
            "hostname": row.get("hostname", ""),
        }
        if row["id"] in SOFTWARE:
            evidence["software"] = SOFTWARE[row["id"]]
        # Ubuntu 20.04 left standard support in May 2025; the fixture should
        # reflect that instead of claiming it is still supported.
        if (evidence.get("os") or {}).get("name") == "Ubuntu 20.04":
            evidence["os"]["supported"] = False
        row["evidence_json"] = json.dumps(evidence)
        rows.append(row)
    return rows


SERVICES = [
    {"id": 1, "name": "Safe Water Delivery", "zone": "central", "population_served": 18400, "rto_minutes": 240, "recovery_procedure": "Restore app01 then db01 then gw01; validate pressure telemetry before reopening supply"},
    {"id": 2, "name": "Billing Service", "zone": "office", "population_served": 18400, "rto_minutes": 480, "recovery_procedure": ""},
    {"id": 3, "name": "Plant Monitoring", "zone": "plant", "population_served": 18400, "rto_minutes": 120, "recovery_procedure": "Restart wmon01 sensor feed and verify plant telemetry in the operations console"},
]

RELATIONSHIPS = [
    {"source_type": "asset", "source_id": 4, "target_type": "asset", "target_id": 5, "rel": "depends_on"},
    {"source_type": "asset", "source_id": 4, "target_type": "asset", "target_id": 6, "rel": "depends_on"},
    {"source_type": "asset", "source_id": 5, "target_type": "asset", "target_id": 7, "rel": "backed_by"},
    {"source_type": "asset", "source_id": 1, "target_type": "asset", "target_id": 3, "rel": "authenticates_via"},
    {"source_type": "asset", "source_id": 2, "target_type": "asset", "target_id": 3, "rel": "authenticates_via"},
    {"source_type": "asset", "source_id": 4, "target_type": "service", "target_id": 2, "rel": "supplies"},
    {"source_type": "asset", "source_id": 5, "target_type": "service", "target_id": 2, "rel": "supplies"},
    {"source_type": "asset", "source_id": 6, "target_type": "service", "target_id": 1, "rel": "supplies"},
    {"source_type": "asset", "source_id": 3, "target_type": "service", "target_id": 1, "rel": "supplies"},
    {"source_type": "asset", "source_id": 2, "target_type": "service", "target_id": 3, "rel": "supplies"},
    {"source_type": "asset", "source_id": 8, "target_type": "service", "target_id": 3, "rel": "supplies"},
    # Network topology: router -> firewall -> core switch -> plant switch.
    {"source_type": "asset", "source_id": 12, "target_type": "asset", "target_id": 6, "rel": "depends_on"},
    {"source_type": "asset", "source_id": 11, "target_type": "asset", "target_id": 12, "rel": "depends_on"},
    {"source_type": "asset", "source_id": 13, "target_type": "asset", "target_id": 11, "rel": "depends_on"},
    {"source_type": "asset", "source_id": 3, "target_type": "asset", "target_id": 11, "rel": "depends_on"},
    {"source_type": "asset", "source_id": 4, "target_type": "asset", "target_id": 11, "rel": "depends_on"},
    {"source_type": "asset", "source_id": 5, "target_type": "asset", "target_id": 11, "rel": "depends_on"},
    {"source_type": "asset", "source_id": 7, "target_type": "asset", "target_id": 11, "rel": "depends_on"},
    {"source_type": "asset", "source_id": 9, "target_type": "asset", "target_id": 11, "rel": "depends_on"},
    {"source_type": "asset", "source_id": 2, "target_type": "asset", "target_id": 13, "rel": "depends_on"},
    {"source_type": "asset", "source_id": 8, "target_type": "asset", "target_id": 13, "rel": "depends_on"},
    {"source_type": "asset", "source_id": 11, "target_type": "service", "target_id": 1, "rel": "supplies"},
    {"source_type": "asset", "source_id": 12, "target_type": "service", "target_id": 1, "rel": "supplies"},
]


# Network devices are seeded as first-class assets so the Infrastructure Map
# shows the path from the ISP edge into the plant, not just servers.
NETWORK_HOSTNAMES = ("sw-core01", "rtr-edge01", "sw-plant01")

NETWORK_TOPOLOGY = [
    ("rtr-edge01", "gw01", "depends_on"),
    ("sw-core01", "rtr-edge01", "depends_on"),
    ("sw-plant01", "sw-core01", "depends_on"),
    ("idp01", "sw-core01", "depends_on"),
    ("app01", "sw-core01", "depends_on"),
    ("db01", "sw-core01", "depends_on"),
    ("bkp01", "sw-core01", "depends_on"),
    ("log01", "sw-core01", "depends_on"),
    ("ops-ws01", "sw-plant01", "depends_on"),
    ("wmon01", "sw-plant01", "depends_on"),
    ("sw-core01", "service:1", "supplies"),
    ("rtr-edge01", "service:1", "supplies"),
]


def ensure_network_assets() -> dict:
    """Idempotently add switches/router + topology to an existing demo DB.

    Fresh installs get these from seed(); this helper upgrades a database that
    was seeded before the network devices existed without deleting any records.
    """
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    created = 0
    links = 0
    try:
        prepared = {row["hostname"]: row for row in _prepared_assets()}
        by_host = {a.hostname: a for a in db.query(Asset).all() if a.hostname}
        for hostname in NETWORK_HOSTNAMES:
            if hostname in by_host or hostname not in prepared:
                continue
            data = dict(prepared[hostname])
            data.pop("id", None)  # let SQLite assign the next free id
            row = Asset(**data)
            db.add(row)
            db.flush()
            by_host[hostname] = row
            created += 1
        for source_host, target, rel in NETWORK_TOPOLOGY:
            source = by_host.get(source_host)
            if not source:
                continue
            if target.startswith("service:"):
                target_type, target_id = "service", int(target.split(":", 1)[1])
            else:
                target_asset = by_host.get(target)
                if not target_asset:
                    continue
                target_type, target_id = "asset", target_asset.id
            exists = (db.query(AssetRelationship)
                      .filter(AssetRelationship.source_type == "asset",
                              AssetRelationship.source_id == source.id,
                              AssetRelationship.target_type == target_type,
                              AssetRelationship.target_id == target_id,
                              AssetRelationship.rel == rel)
                      .first())
            if exists:
                continue
            db.add(AssetRelationship(source_type="asset", source_id=source.id,
                                     target_type=target_type, target_id=target_id, rel=rel))
            links += 1
        db.commit()
        return {"assets_created": created, "links_created": links,
                "network_assets": {h: by_host[h].id for h in NETWORK_HOSTNAMES if h in by_host}}
    finally:
        db.close()


def ensure_demo_evidence() -> dict:
    """Add software inventories + collector metadata to an existing demo DB.

    Existing evidence is preserved; only missing keys are merged. This keeps
    the detection demo usable without resetting incidents, audit history or
    operator changes.
    """
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    updated = 0
    now = time.time()
    try:
        for asset in db.query(Asset).all():
            try:
                evidence = json.loads(asset.evidence_json or "{}")
            except json.JSONDecodeError:
                evidence = {}
            changed = False
            if asset.id in SOFTWARE and "software" not in evidence:
                evidence["software"] = SOFTWARE[asset.id]
                changed = True
            if "collector" not in evidence:
                evidence["collector"] = {
                    "source": "seed-fixture",
                    "version": "1.1.0",
                    "collected_at": now,
                    "hostname": asset.hostname or "",
                }
                changed = True
            if (evidence.get("os") or {}).get("name") == "Ubuntu 20.04" \
                    and evidence["os"].get("supported") is not False:
                evidence["os"]["supported"] = False
                changed = True
            if changed:
                asset.evidence_json = json.dumps(evidence)
                updated += 1
        db.commit()
        return {"assets_updated": updated}
    finally:
        db.close()


def ensure_realistic_data() -> dict:
    """Upgrade the older demo fixture to the current, realistic estate.

    Removes obvious test artifacts (incident titles like "t", "smoke",
    "probe" and the google.com indicator), seeds realistic incidents and
    community indicators, updates the utility population and refreshes a few
    stale fixture dates that predate the current demo period.
    """
    import json as _json

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    removed_incidents = removed_indicators = added_incidents = added_indicators = 0
    try:
        test_titles = {"t", "smoke", "probe", "suspected intrusion"}
        for inc in list(db.query(Incident).all()):
            if inc.title.strip().lower() not in test_titles:
                continue
            db.query(IncidentEvent).filter(IncidentEvent.incident_id == inc.id).delete()
            db.query(IncidentFindingLink).filter(IncidentFindingLink.incident_id == inc.id).delete()
            db.delete(inc)
            removed_incidents += 1

        for ind in list(db.query(ThreatIndicator).all()):
            if ind.value.strip().lower() in {"www.google.com", "google.com", "example.com"}:
                db.delete(ind)
                removed_indicators += 1

        existing_titles = {i.title for i in db.query(Incident).all()}
        now = time.time()
        for spec in INCIDENTS:
            if spec["title"] in existing_titles:
                continue
            created = now - spec.get("age_hours", 1) * 3600
            inc = Incident(title=spec["title"], status=spec["status"],
                           severity=spec["severity"], commander=spec["commander"],
                           created_at=created)
            db.add(inc)
            db.flush()
            for i, (kind, detail) in enumerate(spec["events"]):
                db.add(IncidentEvent(incident_id=inc.id, kind=kind, detail=detail,
                                     ts=created + (i + 1) * 90))
            added_incidents += 1

        existing_values = {i.value for i in db.query(ThreatIndicator).all()}
        for item in THREAT_INDICATORS:
            if item["value"] in existing_values:
                continue
            db.add(ThreatIndicator(value=item["value"], kind=item["kind"],
                                   confidence=item["confidence"], source=item["source"],
                                   expires_at=now + item["days"] * 86400))
            added_indicators += 1

        # The original fixture used 88,000 for every service; a single small
        # municipal utility serves the same population across its services.
        for svc in db.query(Service).all():
            if svc.population_served == 88000:
                svc.population_served = 18400
            spec = next((s for s in SERVICES if s["id"] == svc.id), None)
            if spec:
                svc.recovery_procedure = spec["recovery_procedure"]

        prepared = {row["hostname"]: row for row in _prepared_assets()}
        replacements = {
            "adm-ws01": [("identity", "privileged_accounts", 0, "last_login",
                          "2024-01-01T00:00:00Z", "2026-05-12T09:15:00Z")],
            "app01": [("patch", None, None, "last_applied",
                       "2024-06-01T00:00:00Z", "2026-08-18T02:10:00Z")],
            "db01": [("backup", None, None, "last_success",
                      "2024-01-01T00:00:00Z", "2026-10-10T01:30:00Z")],
            "bkp01": [("backup", None, None, "last_recovery_test",
                       "2024-02-01T00:00:00Z", "2026-05-05T00:00:00Z")],
        }
        for asset in db.query(Asset).all():
            host = asset.hostname or ""
            try:
                evidence = _json.loads(asset.evidence_json or "{}")
            except _json.JSONDecodeError:
                continue
            changed = False
            if host == "gw01":
                if (evidence.get("os") or {}).get("name") == "PAN-OS 11":
                    evidence["os"]["name"] = "PAN-OS 11.0.0"
                    changed = True
                if asset.os_name == "PAN-OS 11":
                    asset.os_name = "PAN-OS 11.0.0"
            if host == "billing.saas":
                asset.hostname = "billing.vendor.example"
                evidence.setdefault("collector", {})["hostname"] = asset.hostname
                changed = True
            for section, subsection, index, key, old, new in replacements.get(host, []):
                container = evidence.get(section)
                if subsection:
                    if not isinstance(container, dict):
                        continue
                    container = container.get(subsection)
                if not isinstance(container, dict) and not isinstance(container, list):
                    continue
                if isinstance(container, list) and index is not None:
                    if index < len(container) and container[index].get(key) == old:
                        container[index][key] = new
                        changed = True
                elif isinstance(container, dict) and container.get(key) == old:
                    container[key] = new
                    changed = True
            if changed:
                asset.evidence_json = _json.dumps(evidence)
        for br in db.query(BackupRecord).all():
            if br.asset_id == "5" and br.last_success == "2024-01-01T00:00:00Z":
                br.last_success = "2026-10-10T01:30:00Z"

        db.commit()
        return {"removed_incidents": removed_incidents, "added_incidents": added_incidents,
                "removed_indicators": removed_indicators, "added_indicators": added_indicators}
    finally:
        db.close()


def seed() -> dict:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        for t in (BackupRecord, IncidentFindingLink, IncidentEvent, Incident,
                  ThreatIndicator, AssetRelationship, Service, Asset,
                  AssessmentResult, AssessmentRun, Finding, RiskAssessment):
            db.query(t).delete()
        for row in _prepared_assets():
            db.add(Asset(**row))
        for row in SERVICES:
            db.add(Service(**row))
        for row in RELATIONSHIPS:
            db.add(AssetRelationship(**row))
        db.add(BackupRecord(asset_id="5", last_success="2026-10-10T01:30:00Z", immutable_backup=0))
        db.add(BackupRecord(asset_id="7", last_success="2026-10-25T00:00:00Z", immutable_backup=1))
        now = time.time()
        for spec in INCIDENTS:
            created = now - spec.get("age_hours", 1) * 3600
            inc = Incident(title=spec["title"], status=spec["status"],
                           severity=spec["severity"], commander=spec["commander"],
                           created_at=created)
            db.add(inc)
            db.flush()
            for i, (kind, detail) in enumerate(spec["events"]):
                db.add(IncidentEvent(incident_id=inc.id, kind=kind, detail=detail,
                                     ts=created + (i + 1) * 90))
        for item in THREAT_INDICATORS:
            db.add(ThreatIndicator(value=item["value"], kind=item["kind"],
                                   confidence=item["confidence"], source=item["source"],
                                   expires_at=now + item["days"] * 86400))
        db.commit()
        return {"assets": len(ASSETS), "services": len(SERVICES),
                "relationships": len(RELATIONSHIPS), "incidents": len(INCIDENTS),
                "threat_indicators": len(THREAT_INDICATORS)}
    finally:
        db.close()


if __name__ == "__main__":
    print(seed())
