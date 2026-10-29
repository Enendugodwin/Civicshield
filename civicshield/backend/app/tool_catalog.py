"""Defensive tooling catalog: gap -> tool categories with open-source and
commercial examples.

The mapping is curated general knowledge, not an endorsement and not a
purchase order: every entry says what to evaluate for the buyer's own
environment. Deterministic functions below derive which entries apply from
live asset evidence, so recommendations always trace to an observed gap.
"""
from __future__ import annotations

# gap key -> recommendation. "applies" names the evidence check in code.
TOOL_CATALOG: list[dict] = [
    {"gap": "unsupported_os",
     "category": "OS lifecycle / patch management",
     "why": "Unsupported operating systems no longer receive security fixes; "
            "every unpatched CVE after end-of-life is permanently exploitable.",
     "open_source": ["WSUS / Windows Update for Business", "Landscape (Ubuntu, free tier)",
                     "Ansible OS upgrade playbooks"],
     "commercial": ["Microsoft Intune / Autopatch", "Canonical Ubuntu Pro",
                    "Cisco Smart Licensing + TAC support"],
     "note": "Verify the exact end-of-life date with the vendor; migrate or isolate first."},
    {"gap": "missing_edr",
     "category": "Endpoint detection and response (EDR)",
     "why": "No EDR means intrusions on the endpoint go unrecorded; the estate "
            "has assets with EDR explicitly absent.",
     "open_source": ["Wazuh", "OSSEC", "ClamAV (antimalware only)"],
     "commercial": ["CrowdStrike Falcon", "SentinelOne", "Microsoft Defender for Endpoint"],
     "note": "Start with highest-criticality assets lacking EDR."},
    {"gap": "low_monitoring",
     "category": "Centralized logging / SIEM",
     "why": "Coverage below 0.8 (or logging disabled) leaves blind spots the "
            "detection analyst cannot see.",
     "open_source": ["Wazuh", "Graylog", "ELK Stack", "Zeek"],
     "commercial": ["Splunk", "Microsoft Sentinel", "IBM QRadar"],
     "note": "Forward authentication and firewall logs first; they answer most questions."},
    {"gap": "no_backup",
     "category": "Backup and recovery",
     "why": "Assets requiring backups with no recorded target cannot be restored.",
     "open_source": ["Veeam Agent (free)", "BorgBackup", "Restic"],
     "commercial": ["Veeam Backup & Replication", "Acronis Cyber Protect"],
     "note": "Require periodic restore tests, not just successful jobs."},
    {"gap": "mutable_backup",
     "category": "Immutable backup storage",
     "why": "Mutable backups can be encrypted by ransomware along with primaries.",
     "open_source": ["MinIO with object locking", "Restic + append-only repos"],
     "commercial": ["Veeam hardened repository", "AWS S3 Object Lock / Azure immutable vaults"],
     "note": "Immutability must cover the full retention window."},
    {"gap": "external_exposure",
     "category": "Web application firewall / reverse proxy",
     "why": "Direct external-to-critical paths should pass through inspection "
            "and filtering, not reach the asset raw.",
     "open_source": ["ModSecurity + Nginx/HAProxy", "OPNsense / pfSense", "CrowdSec"],
     "commercial": ["Cloudflare WAF", "Palo Alto Prisma Access", "Zscaler Private Access"],
     "note": "Terminate external access at the proxy; deny direct routes."},
    {"gap": "missing_mfa",
     "category": "Multi-factor authentication / SSO",
     "why": "Privileged accounts without MFA fall to password theft alone.",
     "open_source": ["Keycloak", "Authentik", "privacyIDEA"],
     "commercial": ["Microsoft Entra ID", "Okta", "Duo"],
     "note": "Enforce phishing-resistant MFA for administrators first."},
    {"gap": "shared_admin",
     "category": "Privileged access management (PAM)",
     "why": "Shared administrator accounts destroy accountability and rotate poorly.",
     "open_source": ["Teleport Community", "Keycloak + per-user accounts"],
     "commercial": ["CyberArk", "Delinea Secret Server", "BeyondTrust"],
     "note": "One named account per administrator; vault the break-glass."},
    {"gap": "remote_admin",
     "category": "Secure remote access / jump host",
     "why": "Remote administration exposed beyond the boundary invites brute force.",
     "open_source": ["WireGuard bastion", "Teleport Community", "Apache Guacamole"],
     "commercial": ["Zscaler Private Access", "Palo Alto Prisma Access", "CyberArk PSM"],
     "note": "No direct remote admin from untrusted networks."},
    {"gap": "unnecessary_services",
     "category": "Attack-surface reduction (hardening)",
     "why": "Unneeded services (e.g. telnet) are ready-made footholds.",
     "open_source": ["OpenSCAP / CIS-CAT Lite", "Ansible hardening roles"],
     "commercial": ["Tenable Nessus", "Qualys VMDR", "Rapid7 InsightVM"],
     "note": "Rescan after removal; track exceptions with expiry dates."},
    {"gap": "data_exfiltration",
     "category": "Data loss prevention (DLP) / egress filtering",
     "why": "Databases and file stores reachable from workstations can leak "
            "without egress inspection.",
     "open_source": ["Squid + ICAP/ClamAV", "MyDLP Community", "Zeek file extraction"],
     "commercial": ["Symantec DLP", "Microsoft Purview DLP", "Zscaler Internet Access"],
     "note": "Start with egress allow-listing for database hosts, then content rules."},
    {"gap": "network_ids",
     "category": "Network intrusion detection (NIDS)",
     "why": "Lateral-movement assumptions (connects_to hops) need network evidence "
            "to confirm or refute.",
     "open_source": ["Suricata", "Snort", "Zeek"],
     "commercial": ["Darktrace", "ExtraHop", "Palo Alto Threat Prevention"],
     "note": "Span core switch uplinks first; tune to the estate's protocols."},
]


def _ev_get(ev: dict, *path, default=None):
    cur = ev
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
    return cur if cur is not None else default


def gaps_for_evidence(ev: dict, os_supported: bool | None,
                      zone: str = "", kind: str = "") -> list[str]:
    """Deterministic gap keys for one asset's evidence. No inventing."""
    gaps: list[str] = []
    if os_supported is False:
        gaps.append("unsupported_os")
    ep = _ev_get(ev, "endpoint", default={}) or {}
    if ep.get("edr_installed") is False:
        gaps.append("missing_edr")
    try:
        cov = float(ep.get("monitoring_coverage")) if ep.get("monitoring_coverage") is not None else None
    except (TypeError, ValueError):
        cov = None
    if ep.get("logging_enabled") is False or (cov is not None and cov < 0.8):
        gaps.append("low_monitoring")
    bk = _ev_get(ev, "backup", default={}) or {}
    if bk.get("backups_required") and not bk.get("backup_target"):
        gaps.append("no_backup")
    if bk.get("backups_required") and bk.get("backup_target") and not bk.get("immutable_backup"):
        gaps.append("mutable_backup")
    ident = _ev_get(ev, "identity", default={}) or {}
    priv = ident.get("privileged_accounts") or []
    if any(isinstance(p, dict) and not p.get("mfa") for p in priv):
        gaps.append("missing_mfa")
    if ident.get("shared_admin_accounts"):
        gaps.append("shared_admin")
    net = _ev_get(ev, "network", default={}) or {}
    if net.get("remote_admin_exposed"):
        gaps.append("remote_admin")
    if str(zone).lower() == "external" or str(kind).lower() == "external":
        gaps.append("external_exposure")
    svcs = _ev_get(ev, "services", default={}) or {}
    if svcs.get("unnecessary"):
        gaps.append("unnecessary_services")
    return gaps


def recommend(gap_keys: list[str], limit: int = 4) -> list[dict]:
    """Catalog entries for gap keys, in catalog order, bounded."""
    wanted = list(dict.fromkeys(gap_keys))
    out = [dict(e) for e in TOOL_CATALOG if e["gap"] in wanted]
    return out[:max(1, limit)]


def describe() -> list[dict]:
    return [dict(e) for e in TOOL_CATALOG]
