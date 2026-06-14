import httpx

from promptwatch.server.collector import build_collector
from promptwatch.server.dashboard import _app as build_dashboard
from promptwatch.server.server_store import ServerStore


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def _enroll(settings):
    col = build_collector()
    token = ServerStore(settings).rotate_enroll_token()
    async with _client(col) as c:
        r = await c.post("/api/v1/enroll", json={"enroll_token": token, "device_name": "dev1", "os": "Linux"})
        assert r.status_code == 200
        return col, r.json()["agent_key"]


async def test_enroll_auth_and_ingest(settings):
    col, key = await _enroll(settings)
    async with _client(col) as c:
        assert (await c.post("/api/v1/enroll", json={"enroll_token": "bad", "device_name": "x"})).status_code == 401
        assert (await c.post("/api/v1/sessions", json={"prompt": "hi"})).status_code == 401
        r = await c.post("/api/v1/sessions", headers={"X-Agent-Key": key},
                         json={"prompt": "api_key=sk-ant-abcd1234efgh5678ijkl9012", "response": "ok", "device_name": "dev1"})
        assert r.status_code == 200


async def test_revoked_key_rejected(settings):
    col, key = await _enroll(settings)
    ServerStore(settings).revoke_agent(ServerStore(settings).verify_agent_key(key))
    async with _client(col) as c:
        assert (await c.post("/api/v1/sessions", headers={"X-Agent-Key": key},
                             json={"prompt": "x"})).status_code == 401


async def test_dashboard_requires_token(settings):
    async with _client(build_dashboard()) as c:
        assert (await c.get("/api/stats")).status_code == 401
        assert (await c.get("/healthz")).status_code == 200
        assert (await c.get("/api/stats", headers={"X-Dashboard-Token": "test-token"})).status_code == 200


async def test_admin_compliance_and_audit(settings):
    col, key = await _enroll(settings)
    async with _client(col) as c:
        await c.post("/api/v1/sessions", headers={"X-Agent-Key": key},
                     json={"prompt": "ssn 123-45-6789, SELECT * FROM prod database",
                           "response": "ok", "device_name": "dev1"})
    H = {"X-Dashboard-Token": "test-token"}
    async with _client(build_dashboard()) as c:
        assert (await c.get("/api/compliance")).status_code == 401  # gated
        comp = (await c.get("/api/compliance", headers=H)).json()
        assert comp["flagged"] >= 1 and comp["by_category"]
        assert (await c.get("/admin", headers=H)).status_code == 200
        agents = (await c.get("/api/admin/agents", headers=H)).json()
        assert agents and agents[0]["status"] == "active"
        aid = agents[0]["agent_id"]
        assert (await c.post(f"/api/admin/agents/{aid}/revoke", headers=H)).json()["ok"]
        audit = (await c.get("/api/admin/audit", headers=H)).json()
        assert audit["verified"] is True
        assert "agent.revoke" in [e["action"] for e in audit["entries"]]
