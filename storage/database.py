"""
Database layer for Argus.
Uses SQLite with WAL mode for concurrent reads + single writer.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


DB_PATH = Path(__file__).resolve().parent / "argus.db"
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None


def _connect() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(
            str(DB_PATH),
            check_same_thread=False,
            isolation_level=None,
            timeout=30,
        )
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode = WAL")
        _conn.execute("PRAGMA synchronous = NORMAL")
        _conn.execute("PRAGMA foreign_keys = ON")
        _conn.execute("PRAGMA cache_size = -64000")  # 64MB cache
    return _conn


def initialize() -> None:
    """Create tables from schema.sql."""
    conn = _connect()
    with _lock, open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())


@contextmanager
def cursor():
    """Thread-safe cursor context."""
    conn = _connect()
    with _lock:
        cur = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()


# ==========================================
# Metrics
# ==========================================

def insert_metric(metric: dict[str, Any]) -> int:
    with cursor() as cur:
        cur.execute(
            """
            INSERT INTO metrics (
                cpu_percent, memory_percent, memory_used_gb, memory_total_gb,
                disk_percent, disk_free_gb, process_count, thread_count,
                network_sent_mb, network_recv_mb, network_connections,
                cpu_delta, memory_delta, process_spawn_rate,
                top_process_cpu_ratio, disk_io_read_rate, disk_io_write_rate,
                context_switches_per_sec, hour_of_day, day_of_week,
                is_anomaly, anomaly_score, ai_explanation
            ) VALUES (
                :cpu_percent, :memory_percent, :memory_used_gb, :memory_total_gb,
                :disk_percent, :disk_free_gb, :process_count, :thread_count,
                :network_sent_mb, :network_recv_mb, :network_connections,
                :cpu_delta, :memory_delta, :process_spawn_rate,
                :top_process_cpu_ratio, :disk_io_read_rate, :disk_io_write_rate,
                :context_switches_per_sec, :hour_of_day, :day_of_week,
                :is_anomaly, :anomaly_score, :ai_explanation
            )
            """,
            {**{k: 0 for k in [
                "cpu_delta", "memory_delta", "process_spawn_rate",
                "top_process_cpu_ratio", "disk_io_read_rate",
                "disk_io_write_rate", "context_switches_per_sec",
                "network_sent_mb", "network_recv_mb", "network_connections",
                "is_anomaly", "anomaly_score",
            ]}, "ai_explanation": None, **metric},
        )
        return cur.lastrowid


def get_recent_metrics(limit: int = 100) -> list[dict]:
    with cursor() as cur:
        cur.execute("SELECT * FROM metrics ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [dict(row) for row in cur.fetchall()]


def get_metrics_since(hours: int = 1) -> list[dict]:
    since = datetime.utcnow() - timedelta(hours=hours)
    with cursor() as cur:
        cur.execute(
            "SELECT * FROM metrics WHERE timestamp >= ? ORDER BY timestamp ASC",
            (since,),
        )
        return [dict(row) for row in cur.fetchall()]


def get_latest_metric() -> dict | None:
    with cursor() as cur:
        cur.execute("SELECT * FROM metrics ORDER BY timestamp DESC LIMIT 1")
        row = cur.fetchone()
        return dict(row) if row else None


def count_metrics() -> int:
    with cursor() as cur:
        cur.execute("SELECT COUNT(*) as c FROM metrics")
        return cur.fetchone()["c"]


# ==========================================
# Events
# ==========================================

def insert_event(
    level: str,
    category: str,
    message: str,
    source: str,
    metadata: dict | None = None,
) -> int:
    with cursor() as cur:
        cur.execute(
            "INSERT INTO events (level, category, message, source, metadata) VALUES (?, ?, ?, ?, ?)",
            (level, category, message, source,
             json.dumps(metadata) if metadata else None),
        )
        return cur.lastrowid


def get_recent_events(limit: int = 50, level: str | None = None) -> list[dict]:
    with cursor() as cur:
        if level:
            cur.execute(
                "SELECT * FROM events WHERE level = ? ORDER BY timestamp DESC LIMIT ?",
                (level, limit),
            )
        else:
            cur.execute(
                "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
        return [dict(row) for row in cur.fetchall()]


# ==========================================
# Actions
# ==========================================

def insert_action(
    action_type: str,
    target: str | None,
    trigger: str,
    success: bool,
    details: str | None = None,
) -> int:
    with cursor() as cur:
        cur.execute(
            "INSERT INTO actions (action_type, target, trigger, success, details) VALUES (?, ?, ?, ?, ?)",
            (action_type, target, trigger, int(success), details),
        )
        return cur.lastrowid


def get_recent_actions(limit: int = 20) -> list[dict]:
    with cursor() as cur:
        cur.execute("SELECT * FROM actions ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [dict(row) for row in cur.fetchall()]


def last_action_time(action_type: str, target: str | None) -> datetime | None:
    """For cooldown checks."""
    with cursor() as cur:
        if target:
            cur.execute(
                "SELECT timestamp FROM actions WHERE action_type = ? AND target = ? ORDER BY timestamp DESC LIMIT 1",
                (action_type, target),
            )
        else:
            cur.execute(
                "SELECT timestamp FROM actions WHERE action_type = ? ORDER BY timestamp DESC LIMIT 1",
                (action_type,),
            )
        row = cur.fetchone()
        if row:
            return datetime.fromisoformat(row["timestamp"])
        return None


# ==========================================
# Attacks
# ==========================================

def insert_attack_start(attack_type: str, parameters: dict, pid: int) -> int:
    with cursor() as cur:
        cur.execute(
            "INSERT INTO attacks (attack_type, parameters, pid) VALUES (?, ?, ?)",
            (attack_type, json.dumps(parameters), pid),
        )
        return cur.lastrowid


def update_attack_stop(
    attack_id: int,
    duration: int,
    stopped_by: str,
    detected: bool = False,
    latency: float | None = None,
) -> None:
    with cursor() as cur:
        cur.execute(
            """
            UPDATE attacks SET
                duration_seconds = ?,
                stopped_by = ?,
                detected_by_defender = ?,
                detection_latency_seconds = ?
            WHERE id = ?
            """,
            (duration, stopped_by, int(detected), latency, attack_id),
        )


def get_attack_history(limit: int = 50) -> list[dict]:
    with cursor() as cur:
        cur.execute("SELECT * FROM attacks ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [dict(row) for row in cur.fetchall()]


# ==========================================
# Custom Rules
# ==========================================

def list_custom_rules(enabled_only: bool = False) -> list[dict]:
    with cursor() as cur:
        if enabled_only:
            cur.execute("SELECT * FROM custom_rules WHERE enabled = 1")
        else:
            cur.execute("SELECT * FROM custom_rules ORDER BY id")
        return [dict(row) for row in cur.fetchall()]


def add_custom_rule(rule: dict) -> int:
    with cursor() as cur:
        cur.execute(
            """
            INSERT INTO custom_rules
                (name, metric, operator, threshold, duration_seconds, action, severity, enabled)
            VALUES (:name, :metric, :operator, :threshold, :duration_seconds, :action, :severity, :enabled)
            """,
            {"severity": "warning", "enabled": 1, "duration_seconds": 0, **rule},
        )
        return cur.lastrowid


def delete_custom_rule(rule_id: int) -> None:
    with cursor() as cur:
        cur.execute("DELETE FROM custom_rules WHERE id = ?", (rule_id,))


# ==========================================
# Feedback (for AI retraining)
# ==========================================

def insert_feedback(metric_id: int, feedback_type: str, note: str | None = None) -> int:
    with cursor() as cur:
        cur.execute(
            "INSERT INTO feedback (metric_id, feedback_type, note) VALUES (?, ?, ?)",
            (metric_id, feedback_type, note),
        )
        return cur.lastrowid


def count_unused_feedback() -> int:
    with cursor() as cur:
        cur.execute("SELECT COUNT(*) as c FROM feedback WHERE applied_to_training = 0")
        return cur.fetchone()["c"]


# ==========================================
# Security: Process Genealogy
# ==========================================

def insert_genealogy(record: dict) -> int:
    with cursor() as cur:
        cur.execute(
            """
            INSERT INTO process_genealogy
                (pid, parent_pid, process_name, parent_name, cmdline, is_suspicious, suspicious_reason)
            VALUES (:pid, :parent_pid, :process_name, :parent_name, :cmdline, :is_suspicious, :suspicious_reason)
            """,
            {"is_suspicious": 0, "suspicious_reason": None, "cmdline": "", **record},
        )
        return cur.lastrowid


def get_suspicious_processes(limit: int = 50) -> list[dict]:
    with cursor() as cur:
        cur.execute(
            "SELECT * FROM process_genealogy WHERE is_suspicious = 1 ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        return [dict(row) for row in cur.fetchall()]


# ==========================================
# Security: Network connections
# ==========================================

def insert_network_connection(record: dict) -> int:
    with cursor() as cur:
        cur.execute(
            """
            INSERT INTO network_connections
                (pid, process_name, local_address, local_port, remote_address, remote_port, status, is_suspicious, suspicious_reason)
            VALUES (:pid, :process_name, :local_address, :local_port, :remote_address, :remote_port, :status, :is_suspicious, :suspicious_reason)
            """,
            {"is_suspicious": 0, "suspicious_reason": None, **record},
        )
        return cur.lastrowid


# ==========================================
# Retention / cleanup
# ==========================================

def cleanup_old_data(retention_days: int = 30) -> None:
    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    with cursor() as cur:
        for table in ("metrics", "events", "actions", "process_genealogy", "network_connections"):
            cur.execute(f"DELETE FROM {table} WHERE timestamp < ?", (cutoff,))
