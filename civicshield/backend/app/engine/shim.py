"""Engine package re-exports (shim for root-level stdlib engines)."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]

def _load(name: str):
    path = _ROOT / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"civicshield_{name}", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[f"civicshield_{name}"] = mod
    spec.loader.exec_module(mod)
    return mod

baseline_guard = _load("baseline_guard")
impact_engine = _load("impact_engine")

__all__ = ["baseline_guard", "impact_engine"]
