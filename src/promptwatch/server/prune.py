"""
Retention pruning for the central store.

Run on a schedule (cron / systemd timer) or via `pw prune`. Honors
`PW_RETENTION_DAYS` (0 = keep forever). Phase 2 wires this into a background
task on the collector so org deployments self-trim.
"""

from typing import Optional

from ..common.config import get_settings
from ..common.storage import Store


def prune_once(retention_days: Optional[int] = None) -> int:
    """Delete interactions past the retention window. Returns rows removed.

    Resolution order: explicit arg → admin-saved DB setting → env/config.
    """
    settings = get_settings()
    if retention_days is None:
        from .server_store import ServerStore
        db_val = ServerStore(settings).get_setting("retention_days")
        retention_days = int(db_val) if db_val else settings.retention_days
    return Store(settings).prune(retention_days)
