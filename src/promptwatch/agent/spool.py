"""
On-disk spool for collector events — the durability half of fail-open.

When the collector is unreachable, events are written here (one JSON file each,
written atomically via tmp+rename) and replayed later by the drain loop. The
spool is bounded; once it exceeds `MAX_FILES` the oldest entries are dropped so a
long outage can never fill the disk.
"""

import itertools
import json
import logging
import os
import time
from pathlib import Path
from typing import Awaitable, Callable

from ..common.config import DATA_DIR

logger = logging.getLogger("pw.spool")

SPOOL_DIR = DATA_DIR / "spool"
MAX_FILES = 5000

_counter = itertools.count()


def _ensure() -> None:
    SPOOL_DIR.mkdir(parents=True, exist_ok=True)


def pending() -> list[Path]:
    return sorted(SPOOL_DIR.glob("*.json"))


def _enforce_bound() -> None:
    files = pending()
    if len(files) >= MAX_FILES:
        for f in files[: len(files) - MAX_FILES + 1]:
            try:
                f.unlink()
            except OSError:
                pass


def enqueue(payload: dict) -> None:
    """Persist one event. Best-effort; never raises into the caller."""
    try:
        _ensure()
        _enforce_bound()
        fid = f"{time.time_ns():020d}-{os.getpid()}-{next(_counter):06d}"
        tmp = SPOOL_DIR / f"{fid}.tmp"
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        tmp.rename(SPOOL_DIR / f"{fid}.json")
    except Exception as exc:  # pragma: no cover - disk edge cases
        logger.debug("spool enqueue failed: %s", exc)


async def drain(post_one: Callable[[dict], Awaitable[bool]]) -> int:
    """
    Replay spooled events in order via `post_one` (returns True on success).
    Stops at the first failure so ordering and retry are preserved. Returns the
    number of events successfully sent.
    """
    sent = 0
    for f in pending():
        try:
            payload = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            f.unlink(missing_ok=True)  # corrupt entry — drop it
            continue
        try:
            ok = await post_one(payload)
        except Exception:
            ok = False
        if not ok:
            break
        f.unlink(missing_ok=True)
        sent += 1
    return sent
