"""SQLite-backed persistence for campaigns, deliveries, and tracking events."""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL DEFAULT '',
    department  TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS campaigns (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    template    TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'draft',
    started_at  TEXT,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS deliveries (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id  INTEGER NOT NULL REFERENCES campaigns(id),
    target_id    INTEGER NOT NULL REFERENCES targets(id),
    token        TEXT NOT NULL UNIQUE,
    sent_at      TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    delivery_id  INTEGER NOT NULL REFERENCES deliveries(id),
    type         TEXT NOT NULL,
    ip           TEXT,
    user_agent   TEXT,
    occurred_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_delivery ON events(delivery_id);
CREATE INDEX IF NOT EXISTS idx_deliveries_campaign ON deliveries(campaign_id);
"""

EVENT_TYPES = {"open", "click", "submit", "report"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        parent = Path(self.db_path).parent
        if str(parent) and not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        with self._lock, self._connect() as conn:
            cursor = conn.cursor()
            try:
                yield cursor
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    def add_target(self, email: str, name: str = "", department: str = "") -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO targets (email, name, department, created_at) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(email) DO UPDATE SET name=excluded.name, "
                "department=excluded.department",
                (email.strip().lower(), name, department, _now()),
            )
            cur.execute("SELECT id FROM targets WHERE email = ?", (email.strip().lower(),))
            return cur.fetchone()["id"]

    def get_targets(self, department: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._cursor() as cur:
            if department:
                cur.execute(
                    "SELECT * FROM targets WHERE department = ? ORDER BY email", (department,)
                )
            else:
                cur.execute("SELECT * FROM targets ORDER BY email")
            return [dict(row) for row in cur.fetchall()]

    def create_campaign(self, name: str, template: str) -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO campaigns (name, template, status, started_at) "
                "VALUES (?, ?, 'running', ?)",
                (name, template, _now()),
            )
            return cur.lastrowid

    def get_campaign(self, campaign_id: int) -> Optional[Dict[str, Any]]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_campaigns(self) -> List[Dict[str, Any]]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM campaigns ORDER BY id DESC")
            return [dict(row) for row in cur.fetchall()]

    def add_delivery(self, campaign_id: int, target_id: int, token: str) -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO deliveries (campaign_id, target_id, token) VALUES (?, ?, ?)",
                (campaign_id, target_id, token),
            )
            return cur.lastrowid

    def mark_delivered(self, delivery_id: int) -> None:
        with self._cursor() as cur:
            cur.execute("UPDATE deliveries SET sent_at = ? WHERE id = ?", (_now(), delivery_id))

    def record_event(
        self,
        delivery_id: int,
        event_type: str,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        if event_type not in EVENT_TYPES:
            raise ValueError(f"unknown event type: {event_type}")
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO events (delivery_id, type, ip, user_agent, occurred_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (delivery_id, event_type, ip, user_agent, _now()),
            )

    def get_delivery_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM deliveries WHERE token = ?", (token,))
            row = cur.fetchone()
            return dict(row) if row else None

    def campaign_stats(self, campaign_id: int) -> Dict[str, Any]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS delivered FROM deliveries WHERE campaign_id = ?",
                (campaign_id,),
            )
            delivered = cur.fetchone()["delivered"]

            cur.execute(
                """
                SELECT e.type, COUNT(DISTINCT d.id) AS unique_count
                FROM events e
                JOIN deliveries d ON d.id = e.delivery_id
                WHERE d.campaign_id = ?
                GROUP BY e.type
                """,
                (campaign_id,),
            )
            counts = {row["type"]: row["unique_count"] for row in cur.fetchall()}

            return {
                "campaign_id": campaign_id,
                "delivered": delivered,
                "opened": counts.get("open", 0),
                "clicked": counts.get("click", 0),
                "submitted": counts.get("submit", 0),
                "reported": counts.get("report", 0),
            }

    def department_breakdown(self, campaign_id: int) -> List[Dict[str, Any]]:
        with self._cursor() as cur:
            cur.execute(
                """
                SELECT t.department,
                       COUNT(DISTINCT d.id) AS delivered,
                       COUNT(DISTINCT CASE WHEN e.type = 'open' THEN d.id END) AS opened,
                       COUNT(DISTINCT CASE WHEN e.type = 'click' THEN d.id END) AS clicked,
                       COUNT(DISTINCT CASE WHEN e.type = 'submit' THEN d.id END) AS submitted,
                       COUNT(DISTINCT CASE WHEN e.type = 'report' THEN d.id END) AS reported
                FROM deliveries d
                JOIN targets t ON t.id = d.target_id
                LEFT JOIN events e ON e.delivery_id = d.id
                WHERE d.campaign_id = ?
                GROUP BY t.department
                ORDER BY t.department
                """,
                (campaign_id,),
            )
            return [dict(row) for row in cur.fetchall()]
