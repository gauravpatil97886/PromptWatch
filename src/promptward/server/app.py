"""
`pw server` — run the central collector + dashboard together (one process).

The collector (agent ingest, per-agent-key auth) and the dashboard (human UI,
token auth) listen on separate ports so their auth models never overlap. A
background task prunes per the retention policy.

For org-scale, run collector and dashboard as separate processes/containers and
point both at the same Postgres (`PW_DB_URL`); this combined runner is the
zero-config default.
"""

import asyncio
import logging

import uvicorn

from ..common.config import get_settings
from . import auth
from .collector import build_collector
from .dashboard import _app as build_dashboard
from .prune import prune_once

logger = logging.getLogger("pw.server")
_PRUNE_INTERVAL = 6 * 3600  # prune every 6 hours


async def _prune_loop() -> None:
    settings = get_settings()
    while True:
        await asyncio.sleep(_PRUNE_INTERVAL)
        if settings.retention_days > 0:
            removed = await asyncio.to_thread(prune_once)
            if removed:
                logger.info("retention prune removed %d interaction(s)", removed)


async def _serve(app, host: str, port: int) -> None:
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    await uvicorn.Server(config).serve()


def run() -> None:
    logging.basicConfig(level=logging.INFO)
    settings = get_settings()

    if not auth.is_loopback(settings.dashboard_host) and not settings.dashboard_token:
        raise SystemExit(
            "Refusing to expose the dashboard without a token. "
            "Set PW_DASHBOARD_TOKEN before starting the server."
        )

    print(f"  Collector → http://{settings.collector_host}:{settings.collector_port}  (agents)")
    print(f"  Dashboard → http://{settings.dashboard_host}:{settings.dashboard_port}  (team)")

    async def _main() -> None:
        await asyncio.gather(
            _serve(build_collector(), settings.collector_host, settings.collector_port),
            _serve(build_dashboard(), settings.dashboard_host, settings.dashboard_port),
            _prune_loop(),
        )

    asyncio.run(_main())
