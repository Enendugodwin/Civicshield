"""Pydantic schemas for structured AI remediation responses."""
from __future__ import annotations

from pydantic import BaseModel, Field


class RemediationPlanPayload(BaseModel):
    finding_id: str = Field(min_length=1)
    plain_language: str = Field(min_length=1)
    technical_explanation: str = Field(min_length=1)
    evidence: list[str] = Field(default_factory=list)
    consequences: str = Field(min_length=1)
    corrective_action: str = Field(min_length=1)
    prerequisites: list[str] = Field(default_factory=list)
    required_approvals: list[str] = Field(default_factory=list)
    service_disruption: str = Field(default="Unknown; assess before acting.")
    rollback: str = Field(min_length=1)
    verification_steps: list[str] = Field(min_length=1)
    limitations: str = Field(default="")
    requires_human_review: bool = Field(default=True)
    simulated: bool = Field(default=False)
    model_used: str = Field(default="fallback")


class FindingContext(BaseModel):
    finding_id: str = Field(min_length=1)
    rule_id: str = Field(default="UNKNOWN")
    title: str = Field(default="")
    severity: str = Field(default="unknown")
    asset_id: str = Field(default="")
    asset_hostname: str = Field(default="")
    evidence: list[str] = Field(default_factory=list)
    service_impact: str = Field(default="")
