"""Deterministic fallback: rule-aware templated guidance.

Never fabricates a model call: model_used is always "fallback" and the
limitations text says plainly that no model was consulted. The guidance below
is drawn from the baseline-guard rule catalog (rule name, description, fix
hint), so Generate still produces finding-specific recommendations when the
live model is unreachable.
"""
from __future__ import annotations

from .schemas2 import FindingContext, RemediationPlanPayload


# rule_id -> focused remediation guidance. Keys mirror baseline_guard rule ids.
_RULE_GUIDANCE: dict[str, dict] = {
    "BG-ASSET-001": {
        "corrective_action": (
            "Assign an accountable owner to the asset in the asset record, "
            "then confirm the owner accepts operational responsibility."
        ),
        "verification_steps": [
            "Re-run the assessment rule",
            "Confirm the asset record shows a named owner",
        ],
        "required_approvals": ["Asset owner", "Operations lead"],
    },
    "BG-ASSET-002": {
        "corrective_action": (
            "Upgrade the asset to a supported OS release, or isolate it behind "
            "compensating controls until the upgrade window."
        ),
        "verification_steps": [
            "Re-run the assessment rule",
            "Confirm os.supported evidence is true for the running release",
        ],
    },
    "BG-ASSET-003": {
        "corrective_action": (
            "Apply outstanding security patches to the asset, oldest critical "
            "first, then record the patch completion timestamp."
        ),
        "verification_steps": [
            "Re-run the assessment rule",
            "Confirm patch_last_applied is within policy max age",
        ],
    },
    "BG-ASSET-004": {
        "corrective_action": (
            "Restrict remote administration (RDP/SSH/WinRM) to the management "
            "network or VPN only; close internet/WAN exposure at the firewall."
        ),
        "verification_steps": [
            "Re-run the assessment rule",
            "Probe the admin ports from outside to confirm they are closed",
        ],
        "service_disruption": (
            "Brief admin-access interruption while firewall rules change; "
            "schedule a window and keep console access."
        ),
    },
    "BG-ASSET-005": {
        "corrective_action": (
            "Replace the overly broad ingress rule with least-privilege rules: "
            "named sources, required ports only, deny-by-default otherwise."
        ),
        "verification_steps": [
            "Re-run the assessment rule",
            "Review the effective firewall policy for 0.0.0.0/0 remnants",
        ],
    },
    "BG-ASSET-006": {
        "corrective_action": (
            "Disable each unnecessary service on the asset and remove its "
            "startup entry so it cannot return after reboot."
        ),
        "verification_steps": [
            "Re-run the assessment rule",
            "List running services and confirm the unnecessary ones are gone",
        ],
    },
    "BG-ID-001": {
        "corrective_action": (
            "Enforce MFA on every privileged account named in the evidence; "
            "block interactive login for accounts that cannot enroll."
        ),
        "verification_steps": [
            "Re-run the assessment rule",
            "Confirm MFA evidence is true for each privileged account",
        ],
        "required_approvals": ["Identity owner", "Security lead"],
    },
    "BG-ID-002": {
        "corrective_action": (
            "Remove admin grants until the admin count is at or below the "
            "max_admins threshold, starting with dormant accounts."
        ),
        "verification_steps": [
            "Re-run the assessment rule",
            "Recount admins against the max_admins threshold",
        ],
        "required_approvals": ["Identity owner"],
    },
    "BG-ID-003": {
        "corrective_action": (
            "Replace each shared/generic admin account with named individual "
            "accounts and rotate any exposed credentials."
        ),
        "verification_steps": [
            "Re-run the assessment rule",
            "Confirm no shared admin accounts remain in evidence",
        ],
    },
    "BG-ID-004": {
        "corrective_action": (
            "Disable or rotate privileged accounts idle beyond max_idle_days, "
            "after confirming with the account owners."
        ),
        "verification_steps": [
            "Re-run the assessment rule",
            "Confirm every privileged login is within max_idle_days",
        ],
    },
    "BG-ID-005": {
        "corrective_action": (
            "Document least-privilege enforcement for the asset: role "
            "definitions, review cadence, and approval records."
        ),
        "verification_steps": [
            "Re-run the assessment rule",
            "Confirm least_privilege_enforced evidence is recorded",
        ],
    },
    "BG-ENDP-001": {
        "corrective_action": (
            "Install the standard endpoint protection agent on the asset and "
            "verify it reports healthy to the console."
        ),
        "verification_steps": [
            "Re-run the assessment rule",
            "Confirm edr_installed evidence is true and the agent checks in",
        ],
    },
    "BG-ENDP-002": {
        "corrective_action": (
            "Enable host logging and forward it to the central log server; "
            "confirm events arrive before closing."
        ),
        "verification_steps": [
            "Re-run the assessment rule",
            "Confirm logging_enabled evidence and recent events centrally",
        ],
    },
    "BG-ENDP-003": {
        "corrective_action": (
            "Extend monitoring coverage on the asset to at least the 0.8 "
            "policy threshold: deploy missing sensors or fix broken ones."
        ),
        "verification_steps": [
            "Re-run the assessment rule",
            "Confirm monitoring_coverage evidence meets the threshold",
        ],
    },
    "BG-ENDP-004": {
        "corrective_action": (
            "Verify the asset against the documented security baseline and "
            "record the verification result with date and verifier."
        ),
        "verification_steps": [
            "Re-run the assessment rule",
            "Confirm baseline_verified evidence is recorded",
        ],
    },
    "BG-BKP-001": {
        "corrective_action": (
            "Run a fresh backup of the asset now and investigate why the last "
            "success aged past the policy window."
        ),
        "verification_steps": [
            "Re-run the assessment rule",
            "Confirm last_success is within max_age_days",
        ],
    },
    "BG-BKP-002": {
        "corrective_action": (
            "Configure an immutable or offline backup copy so ransomware or "
            "operator error cannot destroy every copy at once."
        ),
        "verification_steps": [
            "Re-run the assessment rule",
            "Confirm immutable_backup evidence is true",
        ],
    },
    "BG-BKP-003": {
        "corrective_action": (
            "Execute a recovery test (restore to an isolated target), then "
            "record the test date and outcome."
        ),
        "verification_steps": [
            "Re-run the assessment rule",
            "Confirm last_recovery_test is within max_test_age_days",
        ],
    },
    "BG-BKP-004": {
        "corrective_action": (
            "Record the asset's backup dependency: backup target name and "
            "whether backups are required for this asset."
        ),
        "verification_steps": [
            "Re-run the assessment rule",
            "Confirm backup_target is recorded and reachable",
        ],
    },
    "BG-BKP-005": {
        "corrective_action": (
            "Document the recovery procedure for the critical service: restore "
            "source, responsible team, and expected recovery time."
        ),
        "verification_steps": [
            "Re-run the assessment rule",
            "Confirm a recovery_procedure is documented for the service",
        ],
    },
}

_DEFAULT_GUIDANCE: dict = {
    "corrective_action": (
        "Follow the documented hardening baseline for this check, then "
        "re-run the assessment."
    ),
    "verification_steps": ["Re-run the assessment rule", "Confirm finding is PASS"],
}


def fallback_plan(ctx: FindingContext) -> RemediationPlanPayload:
    asset = ctx.asset_hostname or ctx.asset_id or "the affected asset"
    guide = _RULE_GUIDANCE.get(ctx.rule_id, _DEFAULT_GUIDANCE)
    title = ctx.title or ctx.rule_id
    return RemediationPlanPayload(
        finding_id=ctx.finding_id,
        plain_language=(
            f"Finding '{title}' ({ctx.rule_id}, severity {ctx.severity}) "
            f"affects {asset}. The corrective action and verification steps "
            "below address this specific rule. "
            "This is templated offline guidance, not an AI review."
        ),
        technical_explanation=(
            f"Rule {ctx.rule_id} produced this finding from the recorded "
            f"evidence ({len(ctx.evidence)} item(s)). Apply the corrective "
            "action in a maintenance window, then run the verification steps."
        ),
        evidence=list(ctx.evidence),
        consequences=(
            f"If unresolved, the weakness on {asset} may degrade "
            f"{ctx.service_impact or 'dependent essential services'}."
        ),
        corrective_action=guide["corrective_action"],
        prerequisites=["Maintenance window", "Configuration backup"],
        required_approvals=list(guide.get("required_approvals", ["Asset owner"])),
        service_disruption=guide.get(
            "service_disruption",
            "Possible brief disruption; schedule a window.",
        ),
        rollback="Restore the pre-change configuration backup.",
        verification_steps=list(guide["verification_steps"]),
        limitations="Offline template: requires human review; no model was consulted.",
        requires_human_review=True,
        simulated=False,
        model_used="fallback",
    )
