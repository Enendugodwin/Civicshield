"""Phase 6 detection drafts: operator-authored deterministic controls.

A draft is data, not code: a small predicate over collected asset evidence
evaluated with the same PASS/FAIL/UNKNOWN semantics as the built-in engine.
Lifecycle is draft -> active -> retired (retired is terminal). Activation and
retirement need the operator role; activation additionally honors the
dual-control governance policy. Only active rules run inside detection runs;
test previews never write findings.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import governance
from app.database import get_db
from app.models.models import Asset, AuditEvent, DetectionRule
from app.security import require_role

router = APIRouter(prefix="/api/detection/rules", tags=["detection-rules"])

RULE_ID_RE = re.compile(r"^DR-[A-Z0-9-]{1,24}$")
PATH_RE = re.compile(r"^[A-Za-z0-9_.]{1,128}$")
SEVERITIES = {"critical", "high", "medium", "low", "info"}
CATEGORIES = {"asset", "identity", "endpoint", "backup", "custom"}
KINDS = {"evidence_missing", "evidence_equals", "evidence_in",
         "evidence_gt", "evidence_lt", "evidence_contains"}


def _get(evidence: Dict[str, Any], path: str) -> Any:
    cur: Any = evidence
    for key in path.split("."):
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def _evidence_of(asset: Asset) -> Dict[str, Any]:
    try:
        value = json.loads(asset.evidence_json or "{}")
        return value if isinstance(value, dict) else {}
    except (ValueError, TypeError, AttributeError):
        return {}


def validate_predicate(pred: Any) -> Dict[str, Any]:
    if not isinstance(pred, dict):
        raise HTTPException(422, "predicate must be an object")
    kind = pred.get("kind")
    path = pred.get("path")
    if kind not in KINDS:
        raise HTTPException(422, f"unknown predicate kind (one of {sorted(KINDS)})")
    if not isinstance(path, str) or not PATH_RE.match(path):
        raise HTTPException(422, "predicate.path must be a dotted evidence path")
    if kind == "evidence_in":
        values = pred.get("values")
        if not isinstance(values, list) or not values:
            raise HTTPException(422, "evidence_in needs a non-empty values list")
    elif kind != "evidence_missing" and "value" not in pred:
        raise HTTPException(422, f"{kind} needs a value")
    if kind in ("evidence_gt", "evidence_lt") and "value" in pred:
        try:
            float(pred["value"])
        except (TypeError, ValueError):
            raise HTTPException(422, f"{kind} needs a numeric value")
    return {"kind": kind, "path": path,
            **({"value": pred["value"]} if "value" in pred else {}),
            **({"values": list(pred["values"])} if kind == "evidence_in" else {})}


def evaluate(pred: Dict[str, Any], evidence: Dict[str, Any]) -> Optional[bool]:
    """True=fail present, False=no fail, None=insufficient evidence."""
    kind, path = pred["kind"], pred["path"]
    val = _get(evidence, path)
    if kind == "evidence_missing":
        return True if val is None or val in ("", [], {}) else False
    if val is None or val == "":
        return None
    if kind == "evidence_equals":
        return bool(val == pred["value"])
    if kind == "evidence_in":
        return bool(val in pred["values"])
    if kind == "evidence_contains":
        return str(pred["value"]).lower() in str(val).lower()
    try:
        num, bound = float(val), float(pred["value"])
    except (TypeError, ValueError):
        return None
    if kind == "evidence_gt":
        return num > bound
    return num < bound


def rule_to_dict(r: DetectionRule) -> Dict[str, Any]:
    try:
        predicate = json.loads(r.predicate_json or "{}")
    except ValueError:
        predicate = {}
    try:
        last_test = json.loads(r.test_json or "{}")
    except ValueError:
        last_test = {}
    return {
        "id": r.id, "rule_id": r.rule_id, "version": r.version, "name": r.name,
        "description": r.description, "category": r.category, "severity": r.severity,
        "predicate": predicate, "status": r.status, "author": r.author,
        "activated_by": r.activated_by, "last_test": last_test,
        "created_at": r.created_at, "updated_at": r.updated_at,
    }


def preview(db: Session, pred: Dict[str, Any]) -> Dict[str, Any]:
    """Dry-run a predicate over the estate. No writes, ever."""
    assets = db.query(Asset).filter(Asset.retired == 0).order_by(Asset.id).all()
    fails: List[Dict[str, Any]] = []
    passes = unknowns = 0
    for a in assets:
        verdict = evaluate(pred, _evidence_of(a))
        if verdict is True:
            fails.append({"asset_id": a.id, "hostname": a.hostname or "",
                          "name": a.name or "", "label": governance.asset_label(a)})
        elif verdict is False:
            passes += 1
        else:
            unknowns += 1
    return {"assets": len(assets), "fail_count": len(fails), "pass_count": passes,
            "unknown_count": unknowns, "fails": fails[:50],
            "truncated": len(fails) > 50,
            "note": ("UNKNOWN means the evidence path is absent: the rule cannot "
                     "judge those assets, it does not clear them.")}


def active_rules(db: Session) -> List[Tuple[DetectionRule, Dict[str, Any]]]:
    rows = db.query(DetectionRule).filter(DetectionRule.status == "active").all()
    out = []
    for r in rows:
        try:
            out.append((r, json.loads(r.predicate_json or "{}")))
        except ValueError:
            continue
    return out


class RuleIn(BaseModel):
    rule_id: str = Field(min_length=4, max_length=28)
    name: str = Field(min_length=3, max_length=120)
    description: str = Field(default="", max_length=2000)
    category: str = "custom"
    severity: str = "medium"
    predicate: Dict[str, Any] = Field(default_factory=dict)


class RulePatchIn(BaseModel):
    name: str | None = None
    description: str | None = None
    category: str | None = None
    severity: str | None = None
    predicate: Dict[str, Any] | None = None


def _get_rule(db: Session, rid: int) -> DetectionRule:
    r = db.query(DetectionRule).filter(DetectionRule.id == rid).first()
    if not r:
        raise HTTPException(404, "detection rule not found")
    return r


@router.get("", response_model=None)
def list_rules(db: Session = Depends(get_db)):
    return {"rules": [rule_to_dict(r) for r in
                      db.query(DetectionRule).order_by(DetectionRule.id).all()]}


@router.post("", status_code=201, response_model=None)
def create_rule(body: RuleIn, db: Session = Depends(get_db),
                authorization: str | None = Header(default=None),
                x_role: str | None = Header(default=None),
                x_user: str | None = Header(default=None)):
    from app.security import role_of
    require_role("operator", role_of(authorization, x_role))
    rid = body.rule_id.strip().upper()
    if not RULE_ID_RE.match(rid):
        raise HTTPException(422, "rule_id must look like DR-EXAMPLE-01")
    if db.query(DetectionRule).filter(DetectionRule.rule_id == rid).first():
        raise HTTPException(409, "rule_id already exists")
    if body.category not in CATEGORIES:
        raise HTTPException(422, f"category must be one of {sorted(CATEGORIES)}")
    if body.severity not in SEVERITIES:
        raise HTTPException(422, f"severity must be one of {sorted(SEVERITIES)}")
    pred = validate_predicate(body.predicate)
    actor = governance.actor_of(authorization, x_role, x_user)
    r = DetectionRule(rule_id=rid, name=body.name.strip(), description=body.description,
                      category=body.category, severity=body.severity,
                      predicate_json=json.dumps(pred), status="draft", author=actor,
                      created_at=time.time(), updated_at=time.time())
    db.add(r)
    db.commit()
    db.refresh(r)
    db.add(AuditEvent(actor=actor, action="detection_rule_created",
                      detail=f"rule={rid} name={r.name}"))
    db.commit()
    return rule_to_dict(r)


@router.get("/{rid}", response_model=None)
def get_rule(rid: int, db: Session = Depends(get_db)):
    return rule_to_dict(_get_rule(db, rid))


@router.patch("/{rid}", response_model=None)
def patch_rule(rid: int, body: RulePatchIn, db: Session = Depends(get_db),
               authorization: str | None = Header(default=None),
               x_role: str | None = Header(default=None),
               x_user: str | None = Header(default=None)):
    from app.security import role_of
    require_role("operator", role_of(authorization, x_role))
    r = _get_rule(db, rid)
    if r.status != "draft":
        raise HTTPException(409, f"only drafts can be edited (status={r.status})")
    if body.name is not None:
        r.name = body.name.strip()
    if body.description is not None:
        r.description = body.description
    if body.category is not None:
        if body.category not in CATEGORIES:
            raise HTTPException(422, f"category must be one of {sorted(CATEGORIES)}")
        r.category = body.category
    if body.severity is not None:
        if body.severity not in SEVERITIES:
            raise HTTPException(422, f"severity must be one of {sorted(SEVERITIES)}")
        r.severity = body.severity
    if body.predicate is not None:
        r.predicate_json = json.dumps(validate_predicate(body.predicate))
    r.updated_at = time.time()
    db.commit()
    db.add(AuditEvent(actor=governance.actor_of(authorization, x_role, x_user),
                      action="detection_rule_edited", detail=f"rule={r.rule_id}"))
    db.commit()
    return rule_to_dict(r)


@router.post("/{rid}/test", response_model=None)
def test_rule(rid: int, db: Session = Depends(get_db),
              authorization: str | None = Header(default=None),
              x_role: str | None = Header(default=None),
              x_user: str | None = Header(default=None)):
    """Preview what a draft would flag. Stores the preview, writes no findings."""
    from app.security import role_of
    require_role("operator", role_of(authorization, x_role))
    r = _get_rule(db, rid)
    try:
        pred = json.loads(r.predicate_json or "{}")
        validate_predicate(pred)
    except HTTPException as e:
        raise HTTPException(422, f"stored predicate invalid: {e.detail}")
    result = preview(db, pred)
    r.test_json = json.dumps({**result, "fails": result["fails"][:10],
                              "tested_at": time.time()})
    r.updated_at = time.time()
    db.commit()
    db.add(AuditEvent(actor=governance.actor_of(authorization, x_role, x_user),
                      action="detection_rule_tested",
                      detail=f"rule={r.rule_id} fail={result['fail_count']}"))
    db.commit()
    return result


@router.post("/{rid}/activate", response_model=None)
def activate_rule(rid: int, db: Session = Depends(get_db),
                  authorization: str | None = Header(default=None),
                  x_role: str | None = Header(default=None),
                  x_user: str | None = Header(default=None)):
    from app.security import role_of
    require_role("operator", role_of(authorization, x_role))
    r = _get_rule(db, rid)
    if r.status != "draft":
        raise HTTPException(409, f"only drafts can be activated (status={r.status})")
    actor = governance.actor_of(authorization, x_role, x_user)
    governance.check_dual_control(db, r.author, actor, f"rule {r.rule_id}")
    r.status = "active"
    r.activated_by = actor
    r.updated_at = time.time()
    db.commit()
    db.add(AuditEvent(actor=actor, action="detection_rule_activated",
                      detail=f"rule={r.rule_id}"))
    db.commit()
    return rule_to_dict(r)


@router.post("/{rid}/retire", response_model=None)
def retire_rule(rid: int, db: Session = Depends(get_db),
                authorization: str | None = Header(default=None),
                x_role: str | None = Header(default=None),
                x_user: str | None = Header(default=None)):
    from app.security import role_of
    require_role("operator", role_of(authorization, x_role))
    r = _get_rule(db, rid)
    if r.status == "retired":
        raise HTTPException(409, "rule already retired")
    actor = governance.actor_of(authorization, x_role, x_user)
    was = r.status
    r.status = "retired"
    r.updated_at = time.time()
    db.commit()
    db.add(AuditEvent(actor=actor, action="detection_rule_retired",
                      detail=f"rule={r.rule_id} was={was}"))
    db.commit()
    return rule_to_dict(r)
