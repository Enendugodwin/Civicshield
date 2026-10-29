"""Deterministic routing: request kind -> ordered agent plan.

No model call decides who runs. Each plan is a list of steps with an
explicit batch number (execution order) and depends_on agent ids within the
run. Batches execute in order; steps in one batch are independent of each
other. The orchestrator validates every plan against the registry.
"""
from __future__ import annotations

from app.agents import registry

# kind -> [(agent_id, batch, [depends_on])]
PLANS: dict[str, list[tuple[str, int, list[str]]]] = {
    "architecture_upload": [("architecture", 1, []), ("advisor", 2, ["architecture"])],
    "critical_vulnerability": [("exposure", 1, []), ("architecture", 1, []),
                               ("advisor", 2, ["exposure", "architecture"])],
    "identity_activity": [("identity", 1, []), ("incident", 2, ["identity"])],
    "recovery_readiness": [("architecture", 1, []), ("recovery", 2, ["architecture"])],
    "incident": [("incident", 1, []), ("architecture", 1, []),
                 ("exposure", 2, ["incident"])],
    "threat_advisory": [("threat", 1, []), ("exposure", 2, ["threat"])],
    "finding": [("exposure", 1, []), ("remediation", 2, ["exposure"])],
    "full_assessment": [("architecture", 1, []), ("exposure", 1, []),
                        ("identity", 1, []), ("cloud", 1, []),
                        ("network", 1, []), ("threat", 1, []),
                        ("detection", 2, ["architecture", "exposure"]),
                        ("incident", 2, ["identity"]),
                        ("recovery", 2, ["architecture"]),
                        ("advisor", 3, ["architecture", "exposure", "detection"]),
                        ("remediation", 3, ["exposure"]),
                        ("governance", 3, ["exposure"])],
}

REQUEST_KINDS = sorted(PLANS)


def plan(kind: str) -> list[dict]:
    """Return validated steps [{agent_id, batch, depends_on}] for a kind."""
    if kind not in PLANS:
        raise KeyError(f"unknown investigation kind '{kind}'")
    steps = [{"agent_id": a, "batch": b, "depends_on": list(d)}
             for a, b, d in PLANS[kind]]
    ids = {s["agent_id"] for s in steps}
    for s in steps:
        registry.get(s["agent_id"])  # unknown agent -> KeyError
        for dep in s["depends_on"]:
            if dep not in ids:
                raise ValueError(f"plan '{kind}': {s['agent_id']} depends on "
                                 f"unplanned agent '{dep}'")
            dep_batch = next(x["batch"] for x in steps if x["agent_id"] == dep)
            if dep_batch >= s["batch"]:
                raise ValueError(f"plan '{kind}': {s['agent_id']} (batch "
                                 f"{s['batch']}) cannot depend on batch {dep_batch}")
    return steps
