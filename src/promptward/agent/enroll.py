"""
Enroll this machine's agent with a central Promptward collector.

`pw enroll --server https://pw.corp --token <ORG_ENROLL_TOKEN>` exchanges
the org enroll token for a per-agent key and writes it to `~/.promptward/agent.json`
(mode 0600). Idempotent: re-running re-enrolls and overwrites the file.
"""

import json
from typing import Optional

import httpx

from ..common.config import get_machine_meta
from .identity import AGENT_FILE, require_secure


def enroll(server: str, token: str, device_name: Optional[str] = None) -> dict:
    """Call the collector's enroll endpoint and persist the returned credentials."""
    server = server.rstrip("/")
    require_secure(server)  # refuse to send the enroll token over plain HTTP
    meta = get_machine_meta()
    device = device_name or meta["hostname"]

    resp = httpx.post(
        f"{server}/api/v1/enroll",
        json={
            "enroll_token": token,
            "device_name": device,
            "hostname": meta["hostname"],
            "os": meta["os"],
            "arch": meta["arch"],
            "sys_user": meta["sys_user"],
        },
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()  # expects {"agent_id": ..., "agent_key": ...}

    AGENT_FILE.parent.mkdir(parents=True, exist_ok=True)
    AGENT_FILE.write_text(
        json.dumps(
            {
                "server": server,
                "agent_id": data["agent_id"],
                "agent_key": data["agent_key"],
                "device_name": device,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    AGENT_FILE.chmod(0o600)
    return {"agent_id": data["agent_id"], "device_name": device, "server": server}
