"""Phase 4: agent registry + deterministic orchestration."""
from fastapi.testclient import TestClient

from app.agents import registry, router
from app.main import app
from app.seed import seed

client = TestClient(app)
OP = {"X-Role": "operator"}
VIEWER = {"X-Role": "viewer"}

KNOWN_TOOLS = {"environment_overview", "search_assets", "asset_details",
               "list_findings", "list_incidents", "incident_details",
               "recovery_status", "threats_summary", "create_incident",
               "propose_plan", "assign_task", "run_assessment", "run_recovery"}


# Synthesis is pinned to the deterministic template so the suite does not
# depend on the live model (was ~60s of network calls). The live synthesis
# path is covered by manual backend probes, not by these tests.
def _deterministic_synthesis(monkeypatch):
    from app.ai import muse_spark_adapter
    monkeypatch.setattr(
        muse_spark_adapter, "complete_text",
        lambda *a, **k: muse_spark_adapter.TextResult(ok=False, error="pinned"))


def setup_function(_):
    seed()


def test_registry_declares_thirteen_bounded_agents():
    agents = registry.describe()
    assert len(agents) == 13
    ids = [a["id"] for a in agents]
    assert len(set(ids)) == 13 and "orchestrator" in ids
    for a in agents:
        assert a["name"] and a["purpose"] and a["capabilities"]
        assert a["input_schema"] and a["output_schema"] and a["budget"]
        for t in a["tools"]:
            assert t["tool"] in KNOWN_TOOLS, (a["id"], t)
            assert t["access"] in ("read", "write")
    bound = [a for a in agents if a["id"] != "orchestrator"]
    assert all(not any(t["access"] == "write" for t in a["tools"]) for a in bound), \
        "specialists must be read-only; writes stay behind chat approval"


def test_router_plans_are_valid_and_ordered():
    for kind in router.REQUEST_KINDS:
        steps = router.plan(kind)
        assert steps
        batches = [s["batch"] for s in steps]
        assert batches == sorted(batches) and min(batches) == 1
    full = router.plan("full_assessment")
    assert {s["batch"] for s in full} == {1, 2, 3} and len(full) == 12
    arch = router.plan("architecture_upload")
    assert [s["agent_id"] for s in arch] == ["architecture", "advisor"]
    try:
        router.plan("nope")
    except KeyError:
        pass
    else:
        raise AssertionError("unknown kind must raise")


def test_full_investigation_completes_with_merged_summary(monkeypatch):
    _deterministic_synthesis(monkeypatch)
    r = client.post("/api/agents/investigations",
                    json={"kind": "full_assessment"}, headers=OP)
    assert r.status_code == 201, r.text
    run = r.json()
    assert run["status"] == "complete", run["status"]
    assert len(run["tasks"]) == 12
    assert all(t["status"] == "done" for t in run["tasks"])
    assert all(t["attempts"] == 1 and t["elapsed_ms"] >= 0 for t in run["tasks"])
    summary = run["summary"]
    assert summary["done"] == 12 and summary["failed"] == 0
    assert summary["executive"]["text"] and summary["executive"]["model_used"]
    assert summary["recommendations"]  # deduped, non-empty on seed
    texts = [x["text"] for x in summary["recommendations"]]
    assert len(texts) == len(set(t.lower() for t in texts))
    detail = client.get(f"/api/agents/investigations/{run['id']}").json()
    assert detail["id"] == run["id"] and len(detail["tasks"]) == 12
    assert client.get("/api/agents/investigations").json()[0]["id"] == run["id"]


def test_specialist_failure_is_isolated(monkeypatch):
    _deterministic_synthesis(monkeypatch)
    from app.agents import specialists
    real = specialists.HANDLERS["cloud"]
    monkeypatch.setitem(specialists.HANDLERS, "cloud",
                        lambda db, ctx: (_ for _ in ()).throw(RuntimeError("boom")))
    try:
        run = client.post("/api/agents/investigations",
                          json={"kind": "full_assessment"}, headers=OP).json()
    finally:
        monkeypatch.setitem(specialists.HANDLERS, "cloud", real)
    assert run["status"] == "partial"
    by_agent = {t["agent_id"]: t for t in run["tasks"]}
    assert by_agent["cloud"]["status"] == "failed"
    assert by_agent["cloud"]["attempts"] == 2
    assert "boom" in by_agent["cloud"]["error"]
    assert sum(1 for t in run["tasks"] if t["status"] == "done") == 11
    assert run["summary"]["failed"] == 1


def test_guards_and_cancel(monkeypatch):
    _deterministic_synthesis(monkeypatch)
    assert client.post("/api/agents/investigations",
                       json={"kind": "full_assessment"},
                       headers=VIEWER).status_code == 403
    assert client.post("/api/agents/investigations",
                       json={"kind": "nope"}, headers=OP).status_code == 422
    assert client.get("/api/agents/investigations/99999").status_code == 404
    run = client.post("/api/agents/investigations",
                      json={"kind": "finding", "ref": "53"}, headers=OP).json()
    assert run["status"] == "complete" and len(run["tasks"]) == 2
    assert client.post(f"/api/agents/investigations/{run['id']}/cancel",
                       headers=OP).status_code == 409
    assert client.get("/api/agents").json()["agents"][0]["id"] == "orchestrator"
