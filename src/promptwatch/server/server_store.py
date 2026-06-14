"""
Server-side persistence: enrolled agents, the org enroll token, and the
notification queue. Shares the SQLite database file with the interactions store
(Phase 2 default). Postgres is a drop-in for org-scale deployments (Phase 2 stretch).

Agent keys and the enroll token are stored hashed (SHA-256); plaintext is shown
exactly once at creation.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..common.config import Settings
from . import auth

_SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id      TEXT PRIMARY KEY,
    key_hash      TEXT NOT NULL,
    device_name   TEXT,
    hostname      TEXT,
    os            TEXT,
    arch          TEXT,
    sys_user      TEXT,
    status        TEXT NOT NULL DEFAULT 'active',   -- active | revoked
    created_at    TEXT NOT NULL,
    last_seen     TEXT
);
CREATE TABLE IF NOT EXISTS org (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    enroll_hash   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notifications (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device        TEXT NOT NULL,
    title         TEXT,
    message       TEXT,
    severity      INTEGER DEFAULT 2,
    sent_by       TEXT,
    ts            TEXT NOT NULL,
    read          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_notif_device ON notifications(device, read);
CREATE TABLE IF NOT EXISTS settings (
    key           TEXT PRIMARY KEY,
    value         TEXT
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ServerStore:
    def __init__(self, settings: Settings):
        self._db: Path = settings.db_path
        self._db.parent.mkdir(parents=True, exist_ok=True)
        with self._con() as con:
            con.executescript(_SCHEMA)

    def _con(self) -> sqlite3.Connection:
        con = sqlite3.connect(self._db)
        con.row_factory = sqlite3.Row
        return con

    # ── org enroll token ────────────────────────────────────────────────────────
    def ensure_enroll_token(self) -> Optional[str]:
        """Create the enroll token if absent. Returns plaintext only on creation."""
        with self._con() as con:
            row = con.execute("SELECT enroll_hash FROM org WHERE id=1").fetchone()
            if row:
                return None
            token = auth.new_token("pw-enroll-")
            con.execute("INSERT INTO org(id, enroll_hash) VALUES (1, ?)", (auth.hash_key(token),))
            return token

    def rotate_enroll_token(self) -> str:
        token = auth.new_token("pw-enroll-")
        with self._con() as con:
            con.execute(
                "INSERT INTO org(id, enroll_hash) VALUES (1, ?) "
                "ON CONFLICT(id) DO UPDATE SET enroll_hash=excluded.enroll_hash",
                (auth.hash_key(token),),
            )
        return token

    def verify_enroll_token(self, token: str) -> bool:
        with self._con() as con:
            row = con.execute("SELECT enroll_hash FROM org WHERE id=1").fetchone()
        return bool(row) and auth.constant_eq(auth.hash_key(token), row["enroll_hash"])

    # ── agents ────────────────────────────────────────────────────────────────────
    def create_agent(self, device_name: str, meta: dict) -> tuple[str, str]:
        """Register an agent. Returns (agent_id, plaintext_key) — key shown once."""
        agent_id = auth.new_id()
        key = auth.new_token("cta_")
        with self._con() as con:
            con.execute(
                "INSERT INTO agents(agent_id,key_hash,device_name,hostname,os,arch,"
                "sys_user,status,created_at,last_seen) VALUES (?,?,?,?,?,?,?, 'active', ?, ?)",
                (agent_id, auth.hash_key(key), device_name, meta.get("hostname"),
                 meta.get("os"), meta.get("arch"), meta.get("sys_user"), _now(), _now()),
            )
        return agent_id, key

    def verify_agent_key(self, key: str) -> Optional[str]:
        """Return the agent_id for a valid, active key, else None."""
        if not key:
            return None
        kh = auth.hash_key(key)
        with self._con() as con:
            row = con.execute(
                "SELECT agent_id FROM agents WHERE key_hash=? AND status='active'", (kh,)
            ).fetchone()
        return row["agent_id"] if row else None

    def touch_agent(self, agent_id: str) -> None:
        with self._con() as con:
            con.execute("UPDATE agents SET last_seen=? WHERE agent_id=?", (_now(), agent_id))

    def get_agent(self, agent_id: str) -> Optional[dict]:
        with self._con() as con:
            row = con.execute(
                "SELECT agent_id,device_name,hostname,os,sys_user FROM agents WHERE agent_id=?",
                (agent_id,),
            ).fetchone()
        return dict(row) if row else None

    def rotate_agent_key(self, agent_id: str) -> Optional[str]:
        """Issue a fresh key for an existing agent. Returns plaintext once."""
        if not self.get_agent(agent_id):
            return None
        key = auth.new_token("cta_")
        with self._con() as con:
            con.execute("UPDATE agents SET key_hash=?, status='active' WHERE agent_id=?",
                        (auth.hash_key(key), agent_id))
        return key

    def revoke_agent(self, agent_id: str) -> None:
        with self._con() as con:
            con.execute("UPDATE agents SET status='revoked' WHERE agent_id=?", (agent_id,))

    def list_agents(self) -> list[dict]:
        with self._con() as con:
            rows = con.execute(
                "SELECT agent_id,device_name,hostname,os,arch,sys_user,status,"
                "created_at,last_seen FROM agents ORDER BY last_seen DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    # ── notifications ─────────────────────────────────────────────────────────────
    def add_notification(self, device: str, title: str, message: str,
                         severity: int = 2, sent_by: str = "Security Team") -> int:
        with self._con() as con:
            cur = con.execute(
                "INSERT INTO notifications(device,title,message,severity,sent_by,ts) "
                "VALUES (?,?,?,?,?,?)",
                (device, title, message, severity, sent_by, _now()),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def list_notifications(self, device: str, unread: bool = True) -> list[dict]:
        q = "SELECT * FROM notifications WHERE device=?"
        if unread:
            q += " AND read=0"
        q += " ORDER BY id DESC"
        with self._con() as con:
            rows = con.execute(q, (device,)).fetchall()
        return [dict(r) for r in rows]

    def ack_notification(self, notif_id: int) -> None:
        with self._con() as con:
            con.execute("UPDATE notifications SET read=1 WHERE id=?", (notif_id,))

    # ── settings (key/value, admin-configurable at runtime) ───────────────────────
    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self._con() as con:
            row = con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self._con() as con:
            con.execute(
                "INSERT INTO settings(key,value) VALUES (?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def all_settings(self) -> dict:
        with self._con() as con:
            rows = con.execute("SELECT key,value FROM settings").fetchall()
        return {r["key"]: r["value"] for r in rows}
