"""
Ship session events to the central Promptward collector (optional, fail-open).

Live sends that fail are written to the on-disk spool and replayed by
`drain_loop` (started from the forwarder lifespan). The agent forwards to
Anthropic independently of this module, so a collector outage never affects a
user's Claude call — it only delays log delivery.
"""

import asyncio
import logging
from typing import Optional

import httpx

from . import spool
from .identity import agent_key, agent_id, require_secure, server_url

logger = logging.getLogger("pw.shipper")

_warned_no_key = False
_DRAIN_INTERVAL = 30  # seconds between spool replay attempts


def _payload(**kw) -> dict:
    kw["agent_id"] = agent_id()
    return kw


async def _post(url: str, key: str, payload: dict) -> bool:
    """POST one event. Returns True on a 2xx, False on any failure."""
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.post(
                f"{url}/api/v1/sessions",
                json=payload,
                headers={"X-Agent-Key": key},
            )
            return r.status_code < 300
    except Exception as exc:
        logger.debug("collector post failed: %s", exc)
        return False


async def post_session(
    source: str,
    prompt: str,
    response: str,
    model: Optional[str] = None,
    tokens_in: Optional[int] = None,
    tokens_out: Optional[int] = None,
    device_name: Optional[str] = None,
    hostname: Optional[str] = None,
    sys_user: Optional[str] = None,
    os_info: Optional[str] = None,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    alert_level: int = 0,
    alert_reason: Optional[str] = None,
) -> None:
    global _warned_no_key
    url = server_url()
    if not url:
        return  # collector not configured — local SQLite only

    key = agent_key()
    if not key:
        # Refuse to transmit without an explicit per-agent key. Fail open:
        # local logging continues; we just don't ship unauthenticated.
        if not _warned_no_key:
            logger.warning(
                "Promptward server is configured but no agent key is set; not shipping "
                "events. Run `pw enroll` or set PW_AGENT_KEY."
            )
            _warned_no_key = True
        return

    try:
        require_secure(url)  # never send the agent key over plain HTTP
    except ValueError as exc:
        logger.warning("not shipping: %s", exc)
        return

    payload = _payload(
        source=source, prompt=prompt, response=response, model=model,
        tokens_in=tokens_in, tokens_out=tokens_out, device_name=device_name,
        hostname=hostname, sys_user=sys_user, os_info=os_info,
        client_ip=client_ip, user_agent=user_agent,
        alert_level=alert_level, alert_reason=alert_reason,
    )
    if not await _post(url, key, payload):
        spool.enqueue(payload)  # durable retry later


async def drain_loop() -> None:
    """Background task: periodically replay spooled events to the collector."""
    while True:
        await asyncio.sleep(_DRAIN_INTERVAL)
        url, key = server_url(), agent_key()
        if not url or not key:
            continue
        if spool.pending():
            sent = await spool.drain(lambda p: _post(url, key, p))
            if sent:
                logger.info("drained %d spooled event(s) to collector", sent)
