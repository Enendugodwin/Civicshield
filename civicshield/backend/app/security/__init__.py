"""Shared server-side authorization helpers.

Single source of truth for demo role checks. Roles are ordered
viewer < operator < admin. The role inputs are demo-grade (client-supplied
headers); production must replace them with authenticated identity.
"""
from __future__ import annotations

from fastapi import HTTPException


def role_of(authorization: str | None = None, x_role: str | None = None) -> str:
    if x_role in ("admin", "operator", "viewer"):
        return x_role
    if authorization and "admin" in authorization:
        return "admin"
    if authorization and "operator" in authorization:
        return "operator"
    return "viewer"


def require_role(minimum: str, role: str) -> None:
    order = {"viewer": 0, "operator": 1, "admin": 2}
    if order.get(role, 0) < order[minimum]:
        raise HTTPException(403, "insufficient role")
