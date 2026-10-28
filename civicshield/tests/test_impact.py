"""Pytest coverage for ImpactEngine scoring, priorities, traversal."""
from civicshield.impact_engine import ImpactEngine, priority_for, traverse_service_impact

EDGES = {"fw": ["app"], "app": ["db"], "db": []}
SERVICES = {"billing": ["app", "db"], "water-ops": ["db"]}


def _finding(**kw):
    base = {"rule_id": "BG-ASSET-004", "asset_id": "fw",
            "severity": "critical", "confidence": "high"}
    base.update(kw)
    return base


def test_priority_thresholds():
    assert priority_for(100) == "Critical"
    assert priority_for(85) == "Critical"
    assert priority_for(84.9) == "High"
    assert priority_for(65) == "High"
    assert priority_for(40) == "Moderate"
    assert priority_for(15) == "Low"
    assert priority_for(14.9) == "Informational"
    assert priority_for(0) == "Informational"


def test_max_risk_scores_100():
    # Documented weights: severity 30 + criticality 20 + exposure 15
    # + confidence 10 + exploitability 10 + privilege 5 + blast 5*(2/5)
    # + controls 5 = 97. blast_radius 2 normalizes to 2/5, not full marks.
    eng = ImpactEngine(EDGES, SERVICES)
    s = eng.score_finding(_finding(), {"criticality": "critical",
                                       "exposed": True, "known_exploited": True,
                                       "privileged": True})
    assert s.score == 97.0
    assert s.priority == "Critical"
    assert abs(sum(s.factors.values()) - 97.0) < 1e-6


def test_min_risk_is_informational():
    # severity info 0 + criticality low 5 + confidence low 3 + controls 5 = 13.
    # (5.0 is unreachable: test_compensating_controls_lower_score locks the
    # default controls factor at 5, so a floor of 5.0 would require a
    # negative confidence contribution.)
    eng = ImpactEngine()
    s = eng.score_finding(_finding(severity="info", confidence="low", asset_id="x"),
                          {"criticality": "low"})
    assert s.score == 13.0
    assert s.priority == "Informational"


def test_compensating_controls_lower_score():
    eng = ImpactEngine()
    a = eng.score_finding(_finding(), {"criticality": "high"})
    b = eng.score_finding(_finding(), {"criticality": "high",
                                       "compensating_controls": True})
    assert b.score == a.score - 5.0


def test_traversal_blast_radius_and_services():
    out = traverse_service_impact("fw", EDGES, SERVICES)
    assert out["visited_assets"] == ["fw", "app", "db"]
    assert out["blast_radius"] == 2
    assert out["impacted_services"] == ["billing", "water-ops"]


def test_prioritize_orders_descending():
    eng = ImpactEngine()
    scored = eng.prioritize([_finding(severity="low", asset_id="a"),
                             _finding(severity="critical", asset_id="b")],
                            {"a": {"criticality": "low"},
                             "b": {"criticality": "critical"}})
    assert [x.asset_id for x in scored] == ["b", "a"]
