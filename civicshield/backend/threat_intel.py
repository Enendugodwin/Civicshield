"""Phase 4: Threat indicator model with dedup/expiry (stdlib only)."""
from __future__ import annotations
import hashlib, json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional


VALID_TYPES = {"domain", "url", "hash", "campaign"}


def _norm(t: str, v: str) -> str:
    v = (v or "").strip()
    if t in ("domain", "campaign"):
        v = v.lower()
    return v


def fingerprint(i_type: str, value: str) -> str:
    return hashlib.sha256(f"{i_type}|{_norm(i_type, value)}".encode()).hexdigest()[:32]


@dataclass
class Indicator:
    id: str
    i_type: str
    value: str
    confidence: int  # 0-100
    source: str = ""
    first_seen: str = ""
    last_seen: str = ""
    expires: str = ""  # ISO date; empty = no expiry
    recommendation: str = ""
    fp: str = ""
    superseded_by: str = ""
    corrected: bool = False


class IntelStore:
    def __init__(self):
        self.by_fp: Dict[str, Indicator] = {}
        self._n = 0

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def add(self, i_type: str, value: str, confidence: int, source: str = "",
            expires: str = "", recommendation: str = "") -> tuple[Indicator, bool]:
        if i_type not in VALID_TYPES:
            raise ValueError(f"unknown type {i_type}")
        if not _norm(i_type, value):
            raise ValueError("empty value")
        if not (0 <= confidence <= 100):
            raise ValueError("confidence 0-100")
        fp = fingerprint(i_type, value)
        if fp in self.by_fp:
            ind = self.by_fp[fp]
            ind.last_seen = self._now()
            ind.confidence = max(ind.confidence, confidence)
            return ind, False  # duplicate
        self._n += 1
        ind = Indicator(id=f"IND-{self._n:04d}", i_type=i_type,
                        value=_norm(i_type, value), confidence=confidence,
                        source=source, first_seen=self._now(), last_seen=self._now(),
                        expires=expires, recommendation=recommendation, fp=fp)
        self.by_fp[fp] = ind
        return ind, True

    def correct(self, fp: str, recommendation: str, superseded_by: str = ""):
        ind = self.by_fp[fp]
        ind.recommendation = recommendation
        ind.superseded_by = superseded_by
        ind.corrected = True

    def is_expired(self, ind: Indicator, now: Optional[str] = None) -> bool:
        if not ind.expires:
            return False
        return (now or self._now()) > ind.expires

    def active(self) -> List[Indicator]:
        return [i for i in self.by_fp.values() if not self.is_expired(i)]

    def to_json(self) -> str:
        return json.dumps([asdict(i) for i in self.by_fp.values()], indent=2)
