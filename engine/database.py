from __future__ import annotations

import sqlite3
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"
DB_PATH = DATA_DIR / "blue_team.db"


def get_connection():
    DATA_DIR.mkdir(exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_database():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        timestamp TEXT,
        source TEXT,
        rule TEXT,
        severity TEXT,
        score INTEGER,
        mitre TEXT,
        tactic TEXT,
        technique TEXT,
        message TEXT,
        ip TEXT,
        user TEXT,
        host TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        severity TEXT,
        score INTEGER,
        created TEXT
    )
    """)

    conn.commit()
    conn.close()
def save_alert(alert: dict):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    INSERT OR REPLACE INTO alerts (
        id,
        timestamp,
        source,
        rule,
        severity,
        score,
        mitre,
        tactic,
        technique,
        message,
        ip,
        user,
        host
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert.get("id"),
        alert.get("timestamp"),
        alert.get("source"),
        alert.get("rule"),
        alert.get("severity"),
        alert.get("score"),
        alert.get("mitre"),
        alert.get("tactic"),
        alert.get("technique"),
        alert.get("message"),
        alert.get("ip"),
        alert.get("user"),
        alert.get("host"),
    ))

    conn.commit()
    conn.close()
def save_alerts(alerts):
    for alert in alerts:
        save_alert(alert)

def load_alerts(limit: int = 500):
    conn = get_connection()
    conn.row_factory = sqlite3.Row

    cur = conn.cursor()

    cur.execute("""
        SELECT *
        FROM alerts
        ORDER BY score DESC, timestamp DESC
        LIMIT ?
    """, (limit,))

    rows = [dict(row) for row in cur.fetchall()]

    conn.close()

    return rows        