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
