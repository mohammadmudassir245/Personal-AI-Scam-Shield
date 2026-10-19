"""SQLite-based analysis history store.

Stores only metadata — never the original message content.
Fields: id, timestamp, input_type, risk_score, risk_level, scam_type, techniques_count
"""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from app.config import DATABASE_PATH

_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DATABASE_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables if they don't exist."""
    with _lock, _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT    NOT NULL,
                input_type      TEXT    NOT NULL,
                risk_score      INTEGER NOT NULL,
                risk_level      TEXT    NOT NULL,
                risk_label      TEXT    NOT NULL,
                scam_type       TEXT    NOT NULL,
                techniques_count INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.commit()


def record_analysis(
    input_type: str,
    risk_score: int,
    risk_level: str,
    risk_label: str,
    scam_type: str,
    techniques_count: int,
) -> None:
    """Insert one metadata row. Never stores raw message content."""
    ts = datetime.now(timezone.utc).isoformat()
    with _lock, _connect() as conn:
        conn.execute(
            """
            INSERT INTO analysis_history
                (timestamp, input_type, risk_score, risk_level, risk_label, scam_type, techniques_count)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (ts, input_type, risk_score, risk_level, risk_label, scam_type, techniques_count),
        )
        conn.commit()


def get_recent(limit: int = 20) -> list[dict]:
    """Return the most recent analyses as plain dicts."""
    with _lock, _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, timestamp, input_type, risk_score, risk_level, risk_label,
                   scam_type, techniques_count
            FROM analysis_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]
