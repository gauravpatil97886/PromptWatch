"""
Append-only, hash-chained audit log (tamper-evident).

Each entry stores the hash of the previous entry, so any insertion, deletion, or
edit of historical rows breaks the chain and is detectable via `verify()`. Used
for governance evidence: admin/dashboard actions (login, settings change, key
revoke/rotate, report export) and, optionally, high-severity AI interactions.
"""

import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..common.config import Settings

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    target      TEXT,
    detail      TEXT,
    prev_hash   TEXT NOT NULL,
    entry_hash  TEXT NOT NULL
);
"""

_GENESIS = "0" * 64


def _digest(prev: str, ts: str, actor: str, action: str, target: str, detail: str) -> str:
    h = hashlib.sha256()
    h.update("\x1f".join([prev, ts, actor, action, target, detail]).encode("utf-8"))
    return h.hexdigest()


class AuditLog:
    def __init__(self, settings: Settings):
        self._db: Path = settings.db_path
        self._db.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._db) as con:
            con.executescript(_SCHEMA)

    def _last_hash(self, con: sqlite3.Connection) -> str:
        row = con.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else _GENESIS

    def record(self, actor: str, action: str, target: str = "", detail: str = "") -> str:
        """Append one tamper-evident entry. Returns its hash."""
        ts = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self._db) as con:
            prev = self._last_hash(con)
            entry = _digest(prev, ts, actor, action, target, detail)
            con.execute(
                "INSERT INTO audit_log(ts,actor,action,target,detail,prev_hash,entry_hash)"
                " VALUES (?,?,?,?,?,?,?)",
                (ts, actor, action, target, detail, prev, entry),
            )
        return entry

    def verify(self) -> tuple[bool, Optional[int]]:
        """Recompute the chain. Returns (ok, first_broken_id)."""
        with sqlite3.connect(self._db) as con:
            con.row_factory = sqlite3.Row
            rows = con.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
        prev = _GENESIS
        for r in rows:
            expected = _digest(prev, r["ts"], r["actor"], r["action"],
                               r["target"] or "", r["detail"] or "")
            if r["prev_hash"] != prev or r["entry_hash"] != expected:
                return False, r["id"]
            prev = r["entry_hash"]
        return True, None

    def list_recent(self, limit: int = 200) -> list[dict]:
        with sqlite3.connect(self._db) as con:
            con.row_factory = sqlite3.Row
            rows = con.execute(
                "SELECT id,ts,actor,action,target,detail FROM audit_log "
                "ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]
