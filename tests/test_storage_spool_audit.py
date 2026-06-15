import asyncio

from promptward.agent import spool
from promptward.common.storage import Store
from promptward.server.audit import AuditLog


def test_store_save_prune_stats(settings):
    s = Store(settings)
    s.save(source="proxy", prompt="hi", response="ok", device_name="d1",
           alert_level=3, alert_reason="x", agent_id="a1")
    st = s.stats()
    assert st["total_interactions"] == 1 and st["alerts_high"] == 1 and st["total_devices"] == 1
    assert s.prune(3650) == 0  # recent row kept


def test_spool_enqueue_and_drain():
    spool.enqueue({"device_name": "d1", "n": 1})
    assert len(spool.pending()) == 1

    async def run():
        sent = await spool.drain(lambda p: _ok(p))
        assert sent == 1 and spool.pending() == []

    async def _ok(p):
        assert p["device_name"] == "d1"
        return True

    asyncio.run(run())


def test_spool_stops_on_failure():
    spool.enqueue({"n": 1})
    spool.enqueue({"n": 2})

    async def run():
        sent = await spool.drain(lambda p: _fail())
        assert sent == 0 and len(spool.pending()) == 2  # nothing lost on failure

    async def _fail():
        return False

    asyncio.run(run())


def test_audit_chain_and_tamper(settings):
    a = AuditLog(settings)
    a.record("admin", "login")
    a.record("admin", "settings.update", "retention_days", "0->90")
    assert a.verify() == (True, None)
    # tamper with a historical row
    import sqlite3
    con = sqlite3.connect(settings.db_path)
    con.execute("UPDATE audit_log SET detail='evil' WHERE action='settings.update'")
    con.commit()
    ok, broken = a.verify()
    assert ok is False and broken is not None
