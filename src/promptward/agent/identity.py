"""
Agent identity + central-server credentials.

Resolution order (env wins, then the enrollment file written by `pw enroll`):
    PW_SERVER     / agent.json:server     — collector base URL
    PW_AGENT_KEY  / agent.json:agent_key  — per-agent API key (no shared default)
    PW_AGENT_ID   / agent.json:agent_id   — server-assigned agent id

There is intentionally NO default agent key. Without an explicit key the agent
refuses to transmit (fail-open: it simply keeps logging locally).
"""

import json
import os

from ..common.config import DATA_DIR

AGENT_FILE = DATA_DIR / "agent.json"


def _file_cfg() -> dict:
    try:
        return json.loads(AGENT_FILE.read_text())
    except Exception:
        return {}


def server_url() -> str:
    # PW_BACKEND_URL kept as a backwards-compatible alias for PW_SERVER.
    url = os.getenv("PW_SERVER") or os.getenv("PW_BACKEND_URL") or _file_cfg().get("server", "")
    return url.rstrip("/")


def require_secure(url: str) -> None:
    """
    Guard credential-bearing requests. When PW_REQUIRE_HTTPS is on, refuse to send
    the enroll token / agent key over plain HTTP (loopback is exempt for local dev).
    """
    from ..common.config import get_settings

    if not get_settings().require_https:
        return
    u = url.lower()
    if u.startswith("https://"):
        return
    if u.startswith(("http://127.0.0.1", "http://localhost", "http://[::1]")):
        return
    raise ValueError(
        f"Refusing to send credentials to non-HTTPS collector: {url}. "
        "Use https:// or set PW_REQUIRE_HTTPS=false for trusted local networks."
    )


def agent_key() -> str:
    return os.getenv("PW_AGENT_KEY") or _file_cfg().get("agent_key", "")


def agent_id() -> str:
    return os.getenv("PW_AGENT_ID") or _file_cfg().get("agent_id", "")
