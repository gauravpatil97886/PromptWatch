import httpx

from promptward.common import compliance
from promptward.common.storage import Store
from promptward.server.collector import build_collector
from promptward.server.server_store import ServerStore


def test_pii_redaction_masks_but_keeps_card_last4():
    out, n = compliance.redact("ssn 123-45-6789, card 4111 1111 1111 1111, a@b.com")
    assert n >= 3
    assert "123-45-6789" not in out and "a@b.com" not in out
    assert "1111" in out  # card last-4 preserved
    assert "4111 1111 1111 1111" not in out


def test_store_delete_by_subject(settings):
    s = Store(settings)
    s.save(source="cli", prompt="x", response="y", sys_user="alice", device_name="d1")
    s.save(source="cli", prompt="x", response="y", sys_user="bob", device_name="d2")
    assert s.delete_by_subject(sys_user="alice") == 1
    assert s.stats()["total_interactions"] == 1
    assert s.delete_by_subject() == 0  # no-op without a subject


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def test_collector_redacts_pii_server_side(settings):
    col = build_collector()
    token = ServerStore(settings).rotate_enroll_token()
    async with _client(col) as c:
        key = (await c.post("/api/v1/enroll", json={"enroll_token": token, "device_name": "dev1"})).json()["agent_key"]
        # Agent ships RAW (simulating an old/forged agent); collector must redact.
        await c.post("/api/v1/sessions", headers={"X-Agent-Key": key},
                     json={"prompt": "ssn 123-45-6789", "response": "ok", "device_name": "dev1"})
        # rotate own key
        r = await c.post("/api/v1/rotate", headers={"X-Agent-Key": key})
        assert r.json()["agent_key"] and r.json()["agent_key"] != key
    rows = Store(settings).list_recent(5)
    assert "123-45-6789" not in rows[0]["prompt"]  # PII masked at rest
    assert rows[0]["alert_level"] == 3  # SSN flagged HIGH


async def test_admin_rotate_and_erase(settings):
    from promptward.server.dashboard import _app as build_dashboard
    col = build_collector()
    token = ServerStore(settings).rotate_enroll_token()
    async with _client(col) as c:
        await c.post("/api/v1/enroll", json={"enroll_token": token, "device_name": "dev1"})
    H = {"X-Dashboard-Token": "test-token"}
    async with _client(build_dashboard()) as c:
        agents = (await c.get("/api/admin/agents", headers=H)).json()
        aid = agents[0]["agent_id"]
        rot = (await c.post(f"/api/admin/agents/{aid}/rotate", headers=H)).json()
        assert rot["ok"] and rot["agent_key"]
        er = (await c.post("/api/admin/erase", headers=H, json={"device_name": "dev1"})).json()
        assert er["ok"]
