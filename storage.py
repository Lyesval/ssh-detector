"""SQLite persistence for normalized events, detections, and analyst cases."""
from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path


def initialize(database: str | Path) -> None:
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS ingestions (
                id INTEGER PRIMARY KEY,
                created_at TEXT NOT NULL,
                source_name TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                alert_count INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                ingestion_id INTEGER NOT NULL REFERENCES ingestions(id),
                ts TEXT NOT NULL,
                source TEXT NOT NULL,
                host TEXT NOT NULL,
                kind TEXT NOT NULL,
                user TEXT NOT NULL,
                ip TEXT NOT NULL,
                cmd TEXT NOT NULL,
                raw TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS events_ts_idx ON events(ts);
            CREATE INDEX IF NOT EXISTS events_host_user_idx ON events(host, user);
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY,
                ingestion_id INTEGER NOT NULL REFERENCES ingestions(id),
                ts TEXT NOT NULL,
                rule TEXT NOT NULL,
                severity TEXT NOT NULL,
                entity TEXT NOT NULL,
                message TEXT NOT NULL,
                host TEXT NOT NULL,
                evidence TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                notes TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS alerts_ts_idx ON alerts(ts);
            """
        )


def save_run(database: str | Path, source_name: str, events: list, alerts: list) -> list[dict]:
    initialize(database)
    created_at = datetime.now(timezone.utc).isoformat()
    with closing(sqlite3.connect(database)) as connection, connection:
        cursor = connection.execute(
            "INSERT INTO ingestions(created_at, source_name, event_count, alert_count) VALUES (?, ?, ?, ?)",
            (created_at, source_name, len(events), len(alerts)),
        )
        ingestion_id = cursor.lastrowid
        connection.executemany(
            """INSERT INTO events(ingestion_id, ts, source, host, kind, user, ip, cmd, raw)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [(ingestion_id, event.ts.isoformat(sep=" "), event.source, event.host, event.kind,
              event.user, event.ip, event.cmd, event.raw) for event in events],
        )
        saved_alerts = []
        for alert in alerts:
            values = alert if isinstance(alert, dict) else vars(alert)
            cursor = connection.execute(
                """INSERT INTO alerts(ingestion_id, ts, rule, severity, entity, message, host, evidence)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (ingestion_id, values["ts"], values["rule"], values["severity"], values["entity"],
                 values["message"], values["host"], values["evidence"]),
            )
            saved_alerts.append({**values, "id": cursor.lastrowid, "status": "open", "notes": ""})
    return saved_alerts


def search_events(database: str | Path, query: str = "", limit: int = 500) -> list[dict]:
    initialize(database)
    term = f"%{query}%"
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """SELECT id, ts, source, host, kind, user, ip, cmd, raw FROM events
               WHERE ? = '' OR host LIKE ? OR user LIKE ? OR ip LIKE ? OR kind LIKE ? OR raw LIKE ?
               ORDER BY ts DESC, id DESC LIMIT ?""",
            (query, term, term, term, term, term, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def list_alerts(database: str | Path, query: str = "", status: str = "", limit: int = 500) -> list[dict]:
    initialize(database)
    term = f"%{query}%"
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """SELECT id, ts, rule, severity, entity, message, host, evidence, status, notes
               FROM alerts WHERE (? = '' OR status = ?)
               AND (? = '' OR entity LIKE ? OR message LIKE ? OR rule LIKE ? OR evidence LIKE ?)
               ORDER BY ts DESC, id DESC LIMIT ?""",
            (status, status, query, term, term, term, term, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def update_case(database: str | Path, alert_id: int, status: str, notes: str) -> bool:
    if status not in {"open", "investigating", "resolved"}:
        raise ValueError("status must be open, investigating, or resolved")
    initialize(database)
    with closing(sqlite3.connect(database)) as connection, connection:
        cursor = connection.execute(
            "UPDATE alerts SET status = ?, notes = ? WHERE id = ?",
            (status, notes[:4000], alert_id),
        )
    return cursor.rowcount > 0


def delete_alert(database: str | Path, alert_id: int) -> bool:
    initialize(database)
    with closing(sqlite3.connect(database)) as connection, connection:
        cursor = connection.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
    return cursor.rowcount > 0


def delete_alert_type(database: str | Path, rule: str) -> int:
    initialize(database)
    with closing(sqlite3.connect(database)) as connection, connection:
        cursor = connection.execute("DELETE FROM alerts WHERE rule = ?", (rule,))
    return cursor.rowcount


def clear_storage(database: str | Path) -> dict[str, int]:
    initialize(database)
    with closing(sqlite3.connect(database)) as connection, connection:
        deleted_alerts = connection.execute("DELETE FROM alerts").rowcount
        deleted_events = connection.execute("DELETE FROM events").rowcount
        connection.execute("DELETE FROM ingestions")
    return {"events": deleted_events, "alerts": deleted_alerts}


def audit_report(database: str | Path, days: int = 30) -> dict:
    initialize(database)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).replace(tzinfo=None).isoformat(sep=" ")
    with closing(sqlite3.connect(database)) as connection, connection:
        event_total = connection.execute(
            "SELECT COUNT(*) FROM events WHERE ts >= ?", (cutoff,)
        ).fetchone()[0]
        alert_rows = connection.execute(
            "SELECT severity, rule, status, COUNT(*) FROM alerts WHERE ts >= ? GROUP BY severity, rule, status",
            (cutoff,),
        ).fetchall()
    by_severity, by_rule, by_status = {}, {}, {}
    alert_total = 0
    for severity, rule, status, count in alert_rows:
        alert_total += count
        by_severity[severity] = by_severity.get(severity, 0) + count
        by_rule[rule] = by_rule.get(rule, 0) + count
        by_status[status] = by_status.get(status, 0) + count
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period_days": days,
        "events": event_total,
        "alerts": alert_total,
        "alerts_by_severity": by_severity,
        "alerts_by_rule": by_rule,
        "alerts_by_status": by_status,
    }
