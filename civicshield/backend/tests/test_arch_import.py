"""Phase 1: architecture import + normalization (reommendations.md/Newfeats.md)."""
from fastapi.testclient import TestClient

from app.main import app
from app.seed import seed

client = TestClient(app)
OP = {"X-Role": "operator"}
VIEWER = {"X-Role": "viewer"}

CSV = """name,kind,hostname,zone,owner,criticality,depends_on
Web Frontend,server,web01,dmz,web-team,high,Gateway Firewall
Gateway Firewall,fw,gw01,edge,net-team,critical,
Cache,unknown-kind,cache01,unknown-zone,,,
"""

JSON_DOC = {
    "nodes": [{"id": "a", "name": "App Server", "kind": "server", "zone": "core"},
              {"id": "b", "name": "Identity Server", "kind": "idp", "zone": "core"}],
    "edges": [{"source": "a", "target": "b", "rel": "authenticates_via"},
              {"source": "a", "target": "b", "rel": "authenticates_via"}],
}

MERMAID = """graph TD
    web[Web Frontend] -->|depends_on| gw[Gateway Firewall]
    gw --> idp[Identity Server]
"""


def setup_function(_):
    seed()


def _import(filename, content, headers=OP):
    r = client.post("/api/architecture/import",
                    json={"filename": filename, "content": content}, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()


def test_csv_preview_normalizes_and_warns():
    b = _import("estate.csv", CSV)
    assert b["status"] == "preview" and b["format"] == "csv"
    assert b["node_count"] == 3 and b["edge_count"] == 1
    assert any("unknown" in w for w in b["warnings"]), b["warnings"]
    detail = client.get(f"/api/architecture/imports/{b['id']}", headers=OP).json()
    kinds = {n["name"]: n["kind"] for n in detail["nodes"]}
    assert kinds["Gateway Firewall"] == "firewall"  # fw alias
    assert kinds["Cache"] == "other"  # unknown default
    assert detail["nodes"][2]["zone"] == "central"
    assert detail["edges"][0]["rel"] == "depends_on"


def test_json_dedupes_and_aliases():
    b = _import("estate.json", __import__("json").dumps(JSON_DOC))
    assert b["edge_count"] == 1  # duplicate edge collapsed
    detail = client.get(f"/api/architecture/imports/{b['id']}", headers=OP).json()
    by_name = {n["name"]: n for n in detail["nodes"]}
    assert by_name["Identity Server"]["kind"] == "identity"  # idp alias


def test_mermaid_best_effort_and_rejects_garbage():
    b = _import("estate.mmd", MERMAID)
    assert b["format"] == "mermaid" and b["node_count"] == 3 and b["edge_count"] == 2
    bad = client.post("/api/architecture/import",
                      json={"filename": "x.txt", "content": "hello"}, headers=OP)
    assert bad.status_code == 422
    empty = client.post("/api/architecture/import",
                        json={"filename": "x.csv", "content": ""}, headers=OP)
    assert empty.status_code == 422
    big = client.post("/api/architecture/import",
                      json={"filename": "x.csv", "content": "z" * 1000001}, headers=OP)
    assert big.status_code == 422
    assert client.post("/api/architecture/import",
                       json={"filename": "x.csv", "content": CSV},
                       headers=VIEWER).status_code == 403


def test_commit_reuses_and_stays_idempotent():
    b = _import("estate.json", __import__("json").dumps(JSON_DOC))
    first = client.post(f"/api/architecture/imports/{b['id']}/commit", headers=OP).json()
    assert first["created_assets"] >= 1 and first["created_edges"] >= 1
    status = client.get(f"/api/architecture/imports/{b['id']}", headers=OP).json()
    assert status["status"] == "committed"
    again = client.post(f"/api/architecture/imports/{b['id']}/commit", headers=OP)
    assert again.status_code == 409
    g = client.get("/api/architecture/graph").json()
    imported = [e for e in g["edges"] if e.get("provenance") == "imported"]
    assert imported and all(e["confidence"] for e in imported)
    no = client.post("/api/architecture/imports/99999/commit", headers=OP)
    assert no.status_code == 404


CSV_ALIAS = """name,type,hostname,zone,criticality,os_name,connects_to
Edge Switch,switch,sw-edge-09,central,medium,Cisco IOS 15.2,
Field Camera,camera,cam-field-02,plant,low,,Edge Switch
"""


def test_csv_type_alias_connects_to_and_os_name():
    b = _import("estate.csv", CSV_ALIAS)
    assert b["node_count"] == 2 and b["edge_count"] == 1, b
    detail = client.get(f"/api/architecture/imports/{b['id']}", headers=OP).json()
    by_name = {n["name"]: n for n in detail["nodes"]}
    assert by_name["Edge Switch"]["kind"] == "switch"  # type alias
    assert by_name["Edge Switch"]["os_name"] == "Cisco IOS 15.2"
    assert detail["edges"][0]["rel"] == "connects_to"
    res = client.post(f"/api/architecture/imports/{b['id']}/commit", headers=OP).json()
    assert res["created_edges"] == 1 and res["skipped_edges"] == 0, res
    g = client.get("/api/architecture/graph").json()
    imported = [e for e in g["edges"]
                if e.get("provenance") == "imported" and e.get("rel") == "connects_to"]
    assert len(imported) == 1


def test_discard_flow():
    b = _import("estate.csv", CSV)
    d = client.post(f"/api/architecture/imports/{b['id']}/discard", headers=OP).json()
    assert d["status"] == "discarded"
    assert client.post(f"/api/architecture/imports/{b['id']}/discard",
                       headers=OP).status_code == 409
    assert client.post(f"/api/architecture/imports/{b['id']}/commit",
                       headers=OP).status_code == 409
