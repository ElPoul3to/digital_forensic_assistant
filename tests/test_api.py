from fastapi.testclient import TestClient

from dfa.api.app import app


def test_health_and_routes():
    c = TestClient(app)
    assert c.get("/health").json() == {"status": "ok"}
    paths = {r.path for r in app.routes}
    assert {"/chat", "/ingest", "/cases", "/cases/{case_id}/stats"} <= paths
    assert c.post("/ingest", json={"case_id": "x", "paths": ["/nonexistent/file"]}).status_code == 400
