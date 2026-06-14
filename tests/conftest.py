"""Shared fixtures: every test runs against an isolated temp DB + spool."""

import pytest


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("PW_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("PW_KEY_FILE", str(tmp_path / ".secret.key"))
    monkeypatch.setenv("PW_ENCRYPT_LOGS", "false")
    monkeypatch.setenv("PW_DASHBOARD_TOKEN", "test-token")
    # Redirect agent-side on-disk paths that are resolved at import time.
    import promptwatch.agent.spool as spool
    import promptwatch.agent.identity as identity
    monkeypatch.setattr(spool, "SPOOL_DIR", tmp_path / "spool")
    monkeypatch.setattr(identity, "AGENT_FILE", tmp_path / "agent.json")
    yield


@pytest.fixture
def settings():
    from promptwatch.common.config import get_settings
    return get_settings()
