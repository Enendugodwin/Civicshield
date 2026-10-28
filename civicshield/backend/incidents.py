"""Phase 4: Incident workspace + Threat intel model + auth roles + reports (stdlib only)."""
from __future__ import annotations
import csv, io, json, hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional


# ---------- Incidents ----------
@dataclass
class Event:
    ts: str  # ISO timestamp, observed
    kind: str  # observed|interpretation|suggestion
    text: str
    actor: str = ""


@dataclass
class Incident:
    id: str
    title: str
    status: str = "open"  # open|contained|resolved
    assets: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    events: List[Event] = field(default_factory=list)
    decisions: List[dict] = field(default_factory=list)


class IncidentStore:
    def __init__(self):
        self._items: Dict[str, Incident] = {}
        self._n = 0

    def create(self, title, assets=None, services=None) -> Incident:
        self._n += 1
        inc = Incident(id=f"INC-{self._n:04d}", title=title,
                       assets=assets or [], services=services or [])
        self._items[inc.id] = inc
        return inc

    def get(self, id: str) -> Incident:
        if id not in self._items:
            raise KeyError(id)
        return self._items[id]

    def add_event(self, id: str, kind: str, text: str, actor: str = "",
                  ts: Optional[str] = None) -> Event:
        if kind not in ("observed", "interpretation", "suggestion"):
            raise ValueError("kind must be observed|interpretation|suggestion")
        ev = Event(ts=ts or datetime.now(timezone.utc).isoformat(),
                   kind=kind, text=text, actor=actor)
        self.get(id).events.append(ev)
        return ev

    def link_finding(self, id: str, finding_id: str):
        self.get(id).findings.append(finding_id)

    def record_decision(self, id: str, action: str, approved_by: str, note: str = ""):
        self.get(id).decisions.append({"action": action, "approved_by": approved_by, "note": note})

    CONTAINMENT = [
        "Confirm scope from observed events only; do not invent timestamps.",
        "Preserve logs for affected assets before any disruptive action.",
        "Isolate only with explicit human approval; never auto-isolate on AI advice.",
        "Verify backups are intact and offline before restoration.",
    ]

    def report(self, id: str) -> dict:
        inc = self.get(id)
        return {"incident": asdict(inc), "containment_steps": list(self.CONTAINMENT)}

    def report_json(self, id: str) -> str:
        return json.dumps(self.report(id), indent=2, default=str)
