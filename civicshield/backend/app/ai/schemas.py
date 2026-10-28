"""Consolidated AI schemas (canonical import path).

schemas2.py is kept for backward compatibility; import from here.
"""
from .schemas2 import FindingContext, RemediationPlanPayload

__all__ = ["FindingContext", "RemediationPlanPayload"]
