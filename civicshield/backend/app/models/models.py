"""Full CivicShield SQLAlchemy models (SQLite default, Postgres-compatible)."""
from __future__ import annotations

import time

from sqlalchemy import Column, Float, ForeignKey, Integer, String, Text

from app.database import Base


def _ts() -> float:
    return time.time()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="viewer")  # admin | operator | viewer
    created_at = Column(Float, default=_ts)


class Organization(Base):
    __tablename__ = "organizations"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    created_at = Column(Float, default=_ts)


class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    kind = Column(String, nullable=False)
    hostname = Column(String, default="")
    owner = Column(String, default="")
    os_name = Column(String, default="")
    environment = Column(String, default="production")
    zone = Column(String, nullable=False, default="central")
    criticality = Column(String, default="low")
    criticality_reason = Column(Text, default="")
    status = Column(String, default="operational")
    retired = Column(Integer, default=0)
    evidence_json = Column(Text, default="{}")
    created_at = Column(Float, default=_ts)
    updated_at = Column(Float, default=_ts)


class Service(Base):
    __tablename__ = "services"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    zone = Column(String, nullable=False, default="central")
    population_served = Column(Integer, default=0)
    rto_minutes = Column(Integer, default=240)
    recovery_procedure = Column(Text, default="")
    created_at = Column(Float, default=_ts)


class AssetRelationship(Base):
    __tablename__ = "relationships"
    id = Column(Integer, primary_key=True, index=True)
    source_type = Column(String, nullable=False)
    source_id = Column(Integer, nullable=False)
    target_type = Column(String, nullable=False)
    target_id = Column(Integer, nullable=False)
    rel = Column(String, nullable=False)
    source_note = Column(String, default="verified")
    confidence = Column(String, default="high")
    # Phase 1 provenance: how this edge is known. observed|configured|inferred|simulated|imported|manual
    provenance = Column(String, default="manual")
    evidence_ref = Column(Text, default="")
    created_at = Column(Float, default=_ts)
    updated_at = Column(Float, default=_ts)


class ArchImportBatch(Base):
    """Staged architecture import: preview first, commit explicitly, never partial."""
    __tablename__ = "arch_import_batches"
    id = Column(Integer, primary_key=True)
    filename = Column(String, default="")
    format = Column(String, default="")  # csv|json|mermaid
    status = Column(String, default="preview")  # preview|committed|discarded
    node_count = Column(Integer, default=0)
    edge_count = Column(Integer, default=0)
    warnings_json = Column(Text, default="[]")
    payload_json = Column(Text, default="{}")
    actor = Column(String, default="")
    created_at = Column(Float, default=_ts)


# Back-compat alias: old code imports Relationship.
Relationship = AssetRelationship


class SecurityRule(Base):
    __tablename__ = "security_rules"
    id = Column(Integer, primary_key=True)
    rule_id = Column(String, unique=True, nullable=False)
    version = Column(String, default="1.0.0")
    name = Column(String, default="")
    category = Column(String, default="")
    severity = Column(String, default="medium")


class AssessmentRun(Base):
    __tablename__ = "assessment_runs"
    id = Column(Integer, primary_key=True)
    started_at = Column(Float, default=_ts)
    rule_version = Column(String, default="1.0.0")
    scope = Column(String, default="all")  # all | asset:<id>
    status = Column(String, default="complete")


class AssessmentResult(Base):
    __tablename__ = "assessment_results"
    id = Column(Integer, primary_key=True)
    run_id = Column(Integer, ForeignKey("assessment_runs.id"))
    rule_id = Column(String, default="")
    asset_id = Column(String, default="")
    outcome = Column(String, default="UNKNOWN")
    severity = Column(String, default="medium")
    evidence_ref = Column(Text, default="")


class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True)
    run_id = Column(Integer, default=0)
    rule_id = Column(String, default="")
    asset_id = Column(String, default="")
    severity = Column(String, default="medium")
    status = Column(String, default="confirmed")
    detail = Column(Text, default="")
    workflow = Column(String, default="open")
    assignee = Column(String, default="")
    resolution_reason = Column(Text, default="")


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"
    id = Column(Integer, primary_key=True)
    finding_id = Column(String, default="")
    score = Column(Float, default=0.0)
    priority = Column(String, default="Informational")
    factors_json = Column(Text, default="{}")
    created_at = Column(Float, default=_ts)


class RemediationPlan(Base):
    __tablename__ = "remediation_plans"
    id = Column(Integer, primary_key=True)
    finding_id = Column(String, default="")
    payload_json = Column(Text, default="{}")
    status = Column(String, default="proposed")
    simulated = Column(Integer, default=0)


class RemediationApproval(Base):
    __tablename__ = "remediation_approvals"
    id = Column(Integer, primary_key=True)
    plan_id = Column(String, default="")
    actor = Column(String, default="")
    decision = Column(String, default="")
    created_at = Column(Float, default=_ts)


class VerificationResult(Base):
    __tablename__ = "verification_results"
    id = Column(Integer, primary_key=True)
    plan_id = Column(String, default="")
    passed = Column(Integer, default=0)
    evidence = Column(Text, default="")
    created_at = Column(Float, default=_ts)


class RecoveryScenario(Base):
    __tablename__ = "recovery_scenarios"
    id = Column(Integer, primary_key=True)
    scenario_id = Column(String, unique=True)
    name = Column(String, default="")
    failed_asset = Column(String, default="")


class RecoveryRun(Base):
    __tablename__ = "recovery_runs"
    id = Column(Integer, primary_key=True)
    scenario_id = Column(String, default="")
    result_json = Column(Text, default="{}")
    created_at = Column(Float, default=_ts)


class RecoveryStep(Base):
    __tablename__ = "recovery_steps"
    id = Column(Integer, primary_key=True)
    run_id = Column(Integer, default=0)
    step_id = Column(String, default="")
    asset = Column(String, default="")
    status = Column(String, default="pending")


class BackupRecord(Base):
    __tablename__ = "backup_records"
    id = Column(Integer, primary_key=True)
    asset_id = Column(String, default="")
    last_success = Column(String, default="")
    immutable_backup = Column(Integer, default=0)


class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True)
    title = Column(String, default="")
    status = Column(String, default="open")
    severity = Column(String, default="medium")
    commander = Column(String, default="")
    created_at = Column(Float, default=_ts)


class IncidentEvent(Base):
    __tablename__ = "incident_events"
    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, default=0)
    ts = Column(Float, default=_ts)
    kind = Column(String, default="observed")
    detail = Column(Text, default="")


class IncidentFindingLink(Base):
    __tablename__ = "incident_finding_links"
    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, default=0)
    finding_id = Column(Integer, default=0)
    created_at = Column(Float, default=_ts)


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    id = Column(Integer, primary_key=True)
    value = Column(String, unique=True)
    kind = Column(String, default="domain")
    confidence = Column(String, default="medium")
    source = Column(String, default="")
    expires_at = Column(Float, default=0.0)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id = Column(Integer, primary_key=True)
    ts = Column(Float, default=_ts)
    actor = Column(String, default="")
    action = Column(String, default="")
    detail = Column(Text, default="")
    # Phase 6 hash chain (tamper-evidence). Filled automatically on insert
    # for every writer via a mapper listener; legacy rows are backfilled once.
    prev_hash = Column(String, default="")
    entry_hash = Column(String, default="")


class AppSetting(Base):
    """Phase 6 governance + protector configuration as key/value rows."""
    __tablename__ = "app_settings"
    key = Column(String, primary_key=True)
    value_json = Column(Text, default='""')
    updated_by = Column(String, default="")
    updated_at = Column(Float, default=_ts)


class DetectionRule(Base):
    """Phase 6 detection draft: a data-defined control evaluated with the
    deterministic engine. Lifecycle: draft -> active -> retired (terminal)."""
    __tablename__ = "detection_rules"
    id = Column(Integer, primary_key=True)
    rule_id = Column(String, unique=True, nullable=False)  # DR-XXXX
    version = Column(String, default="1.0.0")
    name = Column(String, default="")
    description = Column(Text, default="")
    category = Column(String, default="custom")
    severity = Column(String, default="medium")
    predicate_json = Column(Text, default="{}")
    status = Column(String, default="draft")  # draft|active|retired
    author = Column(String, default="")
    activated_by = Column(String, default="")
    test_json = Column(Text, default="{}")
    created_at = Column(Float, default=_ts)
    updated_at = Column(Float, default=_ts)


class ProtectionRun(Base):
    """Phase 6 continuous protector: one scheduled/event/manual reassessment."""
    __tablename__ = "protection_runs"
    id = Column(Integer, primary_key=True)
    trigger = Column(String, default="manual")  # scheduled|event|manual
    status = Column(String, default="complete")  # running|complete|failed
    findings_opened = Column(Integer, default=0)
    findings_reopened = Column(Integer, default=0)
    findings_resolved = Column(Integer, default=0)
    detail_json = Column(Text, default="{}")
    actor = Column(String, default="")
    started_at = Column(Float, default=_ts)
    finished_at = Column(Float, default=0.0)


class ProtectionNotification(Base):
    """Phase 6 posture-change notice. Ack is operator-explicit, never automatic."""
    __tablename__ = "protection_notifications"
    id = Column(Integer, primary_key=True)
    kind = Column(String, default="")  # finding_opened|finding_reopened|finding_resolved|run_failed|evidence_stale
    title = Column(Text, default="")
    detail = Column(Text, default="")
    finding_id = Column(Integer, default=0)
    run_id = Column(Integer, default=0)
    ack = Column(Integer, default=0)
    created_at = Column(Float, default=_ts)


class AgentRun(Base):
    """One orchestrated investigation: kind + plan + merged outcome."""
    __tablename__ = "agent_runs"
    id = Column(Integer, primary_key=True)
    kind = Column(String, default="")
    ref = Column(String, default="")
    actor = Column(String, default="")
    status = Column(String, default="running")  # running|complete|partial|cancelled
    plan_json = Column(Text, default="[]")
    summary_json = Column(Text, default="{}")
    created_at = Column(Float, default=_ts)
    updated_at = Column(Float, default=_ts)


class AgentTask(Base):
    """One specialist execution inside an investigation."""
    __tablename__ = "agent_tasks"
    id = Column(Integer, primary_key=True)
    run_id = Column(Integer, default=0)
    agent_id = Column(String, default="")
    batch = Column(Integer, default=1)
    status = Column(String, default="pending")  # pending|running|done|failed|cancelled
    attempts = Column(Integer, default=0)
    elapsed_ms = Column(Integer, default=0)
    result_json = Column(Text, default="{}")
    error = Column(Text, default="")
    created_at = Column(Float, default=_ts)
    updated_at = Column(Float, default=_ts)


class ArchProposal(Base):
    """An architecture change proposal: edits staged, never live until applied."""
    __tablename__ = "arch_proposals"
    id = Column(Integer, primary_key=True)
    title = Column(String, default="")
    status = Column(String, default="draft")  # draft|simulated|approved|applied|rejected
    actor = Column(String, default="")
    rationale = Column(Text, default="")
    created_at = Column(Float, default=_ts)
    updated_at = Column(Float, default=_ts)


class ArchProposalChange(Base):
    """One graph edit inside a proposal: remove_edge | add_edge | update_asset."""
    __tablename__ = "arch_proposal_changes"
    id = Column(Integer, primary_key=True)
    proposal_id = Column(Integer, default=0)
    op = Column(String, default="")
    payload_json = Column(Text, default="{}")
    created_at = Column(Float, default=_ts)


class ArchSimRun(Base):
    """One before/after simulation of a proposal with verification outcomes."""
    __tablename__ = "arch_sim_runs"
    id = Column(Integer, primary_key=True)
    proposal_id = Column(Integer, default=0)
    request_json = Column(Text, default="{}")
    result_json = Column(Text, default="{}")
    created_at = Column(Float, default=_ts)


class Conversation(Base):
    """Assistant chat thread. user_id is the demo role string (admin/operator/viewer)."""
    __tablename__ = "ai_conversations"
    id = Column(Integer, primary_key=True)
    user_id = Column(String, default="")
    title = Column(String, default="New conversation")
    summary = Column(Text, default="")
    created_at = Column(Float, default=_ts)
    updated_at = Column(Float, default=_ts)


class ChatMessage(Base):
    __tablename__ = "ai_messages"
    id = Column(Integer, primary_key=True)
    conversation_id = Column(Integer, default=0)
    role = Column(String, default="user")  # user|assistant|tool
    content = Column(Text, default="")
    meta_json = Column(Text, default="{}")
    created_at = Column(Float, default=_ts)


class AITask(Base):
    """Assistant-proposed action awaiting approval and execution."""
    __tablename__ = "ai_tasks"
    id = Column(Integer, primary_key=True)
    conversation_id = Column(Integer, default=0)
    requested_by = Column(String, default="")
    task_type = Column(String, default="")
    target_json = Column(Text, default="{}")
    status = Column(String, default="pending_approval")
    requires_approval = Column(Integer, default=1)
    approved_by = Column(String, default="")
    result_json = Column(Text, default="{}")
    error_summary = Column(Text, default="")
    correlation_id = Column(String, default="")
    created_at = Column(Float, default=_ts)
    started_at = Column(Float, default=0.0)
    completed_at = Column(Float, default=0.0)
