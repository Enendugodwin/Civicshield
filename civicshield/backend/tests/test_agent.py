"""The read-only collector agent produces evidence the engine can consume."""
from __future__ import annotations

import importlib.util
from pathlib import Path

AGENT = Path(__file__).resolve().parents[1] / "agent" / "civicshield_agent.py"


def _load():
    spec = importlib.util.spec_from_file_location("civicshield_agent", AGENT)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def test_agent_collects_structured_evidence_without_scanning():
    agent = _load()
    ev = agent.collect_evidence(quick=True, exposure="internal", hostname="test-host")
    assert ev["collector"]["source"] == "civicshield-agent"
    assert ev["collector"]["hostname"] == "test-host"
    assert ev["hostname"] == "test-host"
    assert ev["os"]["name"]
    assert ev["network"]["remote_admin_exposed"] is False
    # Quick mode must not enumerate the full software inventory.
    assert "software" not in ev


def test_agent_helpers_are_evidence_based():
    agent = _load()
    assert agent._supported_os("Windows 10", "10.0.19044") is False
    assert agent._supported_os("Ubuntu 22.04", "22.04") is True
    assert agent._supported_os("Ubuntu 20.04", "20.04") is False
    assert agent._supported_os("Something Else", "1") is None
    assert agent._unnecessary_services([{"port": 23}, {"port": 22}]) == ["telnet"]
    assert agent._unnecessary_services([]) == []
