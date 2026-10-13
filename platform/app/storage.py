"""Almacenamiento en SQLite.

POR QUÉ SQLite al inicio: cero infraestructura, y aprendes el modelo de datos.
Está encapsulado en Store, así que migrar a Postgres/OpenSearch (Fase 3)
solo toca este archivo. Ver docs/adr/.

POR QUÉ consultas parametrizadas (?): NUNCA concatenar strings en SQL.
Los valores vienen de logs que controla el atacante -> inyección SQL.
"""
import json
import sqlite3
import threading
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    host TEXT, action TEXT, outcome TEXT, source_ip TEXT, user_name TEXT,
    doc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_lookup ON events(action, outcome, source_ip, ts);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    rule_id TEXT, severity TEXT, source_ip TEXT,
    doc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_lookup ON alerts(rule_id, source_ip, ts);
"""


class Store:
    def __init__(self, path: str):
        self.path = path
        # Evita condiciones de carrera entre "contar -> decidir -> insertar alerta".
        self.lock = threading.Lock()
        with self._conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ---- eventos ----
    def add_event(self, event) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO events (ts, host, action, outcome, source_ip, user_name, doc) VALUES (?,?,?,?,?,?,?)",
                (event.timestamp.timestamp(), event.host, event.action, event.outcome,
                 event.source_ip, event.user, json.dumps(event.to_ecs())),
            )

    def count_events(self, action: str, outcome: str, source_ip: str, since: float, until: float) -> int:
        with self._conn() as c:
            row = c.execute(
                "SELECT COUNT(*) AS n FROM events WHERE action=? AND outcome=? AND source_ip=? AND ts>=? AND ts<=?",
                (action, outcome, source_ip, since, until),
            ).fetchone()
            return row["n"]

    def list_events(self, limit: int = 50) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT doc FROM events ORDER BY ts DESC, id DESC LIMIT ?", (limit,)).fetchall()
            return [json.loads(r["doc"]) for r in rows]

    # ---- alertas ----
    def add_alert(self, alert) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO alerts (ts, rule_id, severity, source_ip, doc) VALUES (?,?,?,?,?)",
                (alert.ts, alert.rule_id, alert.severity, alert.source_ip, json.dumps(alert.to_dict())),
            )

    def last_alert_ts(self, rule_id: str, source_ip: str) -> float | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT MAX(ts) AS t FROM alerts WHERE rule_id=? AND source_ip=?", (rule_id, source_ip)
            ).fetchone()
            return row["t"]

    def list_alerts(self, limit: int = 50) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT doc FROM alerts ORDER BY ts DESC, id DESC LIMIT ?", (limit,)).fetchall()
            return [json.loads(r["doc"]) for r in rows]
