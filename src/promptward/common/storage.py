import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

from .config import Settings
from .crypto import Encryptor


_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS interactions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT    NOT NULL,
    source       TEXT    NOT NULL,
    model        TEXT,
    prompt       TEXT    NOT NULL,
    response     TEXT    NOT NULL,
    tokens_in    INTEGER,
    tokens_out   INTEGER,
    encrypted    INTEGER NOT NULL DEFAULT 0,
    -- device identity
    device_name  TEXT,
    hostname     TEXT,
    sys_user     TEXT,
    os_info      TEXT,
    client_ip    TEXT,
    user_agent   TEXT,
    -- security
    alert_level  INTEGER DEFAULT 0,
    alert_reason TEXT
);
"""

_MIGRATIONS = [
    "ALTER TABLE interactions ADD COLUMN device_name  TEXT",
    "ALTER TABLE interactions ADD COLUMN hostname     TEXT",
    "ALTER TABLE interactions ADD COLUMN sys_user     TEXT",
    "ALTER TABLE interactions ADD COLUMN os_info      TEXT",
    "ALTER TABLE interactions ADD COLUMN client_ip    TEXT",
    "ALTER TABLE interactions ADD COLUMN user_agent   TEXT",
    "ALTER TABLE interactions ADD COLUMN alert_level  INTEGER DEFAULT 0",
    "ALTER TABLE interactions ADD COLUMN alert_reason TEXT",
    # Central-collector columns (populated server-side; harmless on the agent).
    "ALTER TABLE interactions ADD COLUMN agent_id     TEXT",
    "ALTER TABLE interactions ADD COLUMN received_at  TEXT",
]

# Indexes keep dashboard queries fast as the table grows.
_INDEXES = [
    "CREATE INDEX IF NOT EXISTS ix_interactions_ts          ON interactions(ts)",
    "CREATE INDEX IF NOT EXISTS ix_interactions_device      ON interactions(device_name)",
    "CREATE INDEX IF NOT EXISTS ix_interactions_alert_level ON interactions(alert_level)",
]


class Store:
    def __init__(self, settings: Settings):
        self._db = settings.db_path
        self._db.parent.mkdir(parents=True, exist_ok=True)
        self._enc: Optional[Encryptor] = (
            Encryptor(settings.key_file) if settings.encrypt_logs else None
        )
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self._db) as con:
            con.execute("PRAGMA journal_mode=WAL")  # concurrent reads during writes
            con.execute(_CREATE_TABLE)
            for sql in _MIGRATIONS:
                try:
                    con.execute(sql)
                except sqlite3.OperationalError:
                    pass  # column already exists
            for sql in _INDEXES:
                con.execute(sql)

    def prune(self, retention_days: int) -> int:
        """Delete interactions older than retention_days. Returns rows removed."""
        if retention_days <= 0:
            return 0
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=retention_days)
        ).isoformat()
        with sqlite3.connect(self._db) as con:
            cur = con.execute("DELETE FROM interactions WHERE ts < ?", (cutoff,))
            return cur.rowcount

    def delete_by_subject(self, *, sys_user: Optional[str] = None,
                          device_name: Optional[str] = None) -> int:
        """Right-to-erasure: delete all interactions for a user or device. Returns rows removed."""
        if not sys_user and not device_name:
            return 0
        clauses, params = [], []
        if sys_user:
            clauses.append("sys_user = ?")
            params.append(sys_user)
        if device_name:
            clauses.append("device_name = ?")
            params.append(device_name)
        with sqlite3.connect(self._db) as con:
            cur = con.execute(
                f"DELETE FROM interactions WHERE {' OR '.join(clauses)}", params
            )
            return cur.rowcount

    def save(
        self,
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
        agent_id: Optional[str] = None,
        received_at: Optional[str] = None,
    ) -> int:
        encrypted = self._enc is not None
        p  = self._enc.encrypt(prompt)   if encrypted else prompt
        r  = self._enc.encrypt(response) if encrypted else response
        ts = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self._db) as con:
            cur = con.execute(
                "INSERT INTO interactions"
                "(ts,source,model,prompt,response,tokens_in,tokens_out,encrypted,"
                " device_name,hostname,sys_user,os_info,client_ip,user_agent,"
                " alert_level,alert_reason,agent_id,received_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ts, source, model, p, r, tokens_in, tokens_out, int(encrypted),
                 device_name, hostname, sys_user, os_info, client_ip, user_agent,
                 alert_level, alert_reason, agent_id, received_at),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def list_recent(self, limit: int = 300) -> list[dict]:
        with sqlite3.connect(self._db) as con:
            con.row_factory = sqlite3.Row
            rows = con.execute(
                "SELECT * FROM interactions ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._decode(dict(r)) for r in rows]

    def _decode(self, row: dict) -> dict:
        if row.get("encrypted") and self._enc:
            row["prompt"]   = self._enc.decrypt(row["prompt"])
            row["response"] = self._enc.decrypt(row["response"])
        return row

    def endpoints(self) -> list[dict]:
        """Per-device summary for the Endpoints view."""
        with sqlite3.connect(self._db) as con:
            con.row_factory = sqlite3.Row
            rows = con.execute("""
                SELECT
                    COALESCE(device_name, hostname, client_ip, 'unknown') AS device,
                    hostname,
                    sys_user,
                    os_info,
                    client_ip,
                    COUNT(*)                     AS sessions,
                    SUM(tokens_in)               AS tokens_in,
                    SUM(tokens_out)              AS tokens_out,
                    MAX(ts)                      AS last_seen,
                    MIN(ts)                      AS first_seen,
                    SUM(CASE WHEN alert_level>=3 THEN 1 ELSE 0 END) AS alerts_high,
                    SUM(CASE WHEN alert_level=2  THEN 1 ELSE 0 END) AS alerts_med,
                    SUM(CASE WHEN alert_level=1  THEN 1 ELSE 0 END) AS alerts_low
                FROM interactions
                GROUP BY COALESCE(device_name, hostname, client_ip, 'unknown')
                ORDER BY last_seen DESC
            """).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict:
        with sqlite3.connect(self._db) as con:
            total  = con.execute("SELECT COUNT(*) FROM interactions").fetchone()[0]
            tokens = con.execute(
                "SELECT SUM(tokens_in), SUM(tokens_out) FROM interactions"
            ).fetchone()
            alerts = con.execute(
                "SELECT alert_level, COUNT(*) FROM interactions"
                " WHERE alert_level > 0 GROUP BY alert_level"
            ).fetchall()
            devices = con.execute(
                "SELECT COUNT(DISTINCT COALESCE(device_name,hostname,client_ip)) FROM interactions"
            ).fetchone()[0]
        ac = {int(a[0]): int(a[1]) for a in alerts}
        return {
            "total_interactions": total,
            "total_tokens_in":    tokens[0] or 0,
            "total_tokens_out":   tokens[1] or 0,
            "alerts_low":         ac.get(1, 0),
            "alerts_medium":      ac.get(2, 0),
            "alerts_high":        ac.get(3, 0),
            "total_devices":      devices or 0,
        }
