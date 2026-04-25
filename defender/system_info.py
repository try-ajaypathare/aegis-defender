"""
System info provider — SIMULATION MODE.

Returns fake 'healthy server' processes and connections so the dashboard
looks like a production server dashboard, not the user's laptop.

Simulated attack impacts are mixed in so attacks are visible.
"""
from __future__ import annotations

import platform
import random
import time
from datetime import datetime
from typing import Any

import psutil

from shared.simulation import engine as sim_engine
from shared.windows_helper import get_boot_time, get_hostname, is_admin


# ----- Static server identity (looks like production) -----
FAKE_HOSTNAME = "argus-edge-01"
FAKE_OS = "Linux 6.5.0 (simulated)"
FAKE_PLATFORM = "Linux-6.5.0-42-generic-x86_64"


def get_system_info() -> dict[str, Any]:
    """Real hardware facts + simulated identity."""
    vm = psutil.virtual_memory()
    try:
        disk = psutil.disk_usage("C:\\" if _is_windows() else "/")
    except Exception:
        disk = psutil.disk_usage("/")

    # Fake uptime — show server "up" for N hours
    uptime_secs = int(time.time() - _fake_boot_ref())
    h = uptime_secs // 3600
    m = (uptime_secs % 3600) // 60
    s = uptime_secs % 60

    return {
        "hostname": FAKE_HOSTNAME,
        "platform": FAKE_PLATFORM,
        "os": "Linux (simulated)",
        "os_version": "6.5.0-42-generic",
        "architecture": "x86_64",
        "python_version": platform.python_version(),
        "is_admin": True,
        "cpu_count_physical": psutil.cpu_count(logical=False) or 4,
        "cpu_count_logical": psutil.cpu_count(logical=True) or 8,
        "cpu_freq_mhz": 2800,
        "memory_total_gb": round(vm.total / (1024 ** 3), 2),
        "swap_total_gb": 8.0,
        "swap_used_percent": 2.5,
        "disk_total_gb": round(disk.total / (1024 ** 3), 2),
        "boot_time": datetime.fromtimestamp(_fake_boot_ref()).isoformat(),
        "uptime_seconds": uptime_secs,
        "uptime_human": f"{h}h {m}m {s}s",
    }


# Cached reference so uptime looks stable across calls
_FAKE_BOOT: float | None = None


def _fake_boot_ref() -> float:
    """Fake boot time — pretends server has been up for a few hours."""
    global _FAKE_BOOT
    if _FAKE_BOOT is None:
        _FAKE_BOOT = time.time() - random.randint(3600 * 4, 3600 * 24 * 3)  # 4h to 3d ago
    return _FAKE_BOOT


# ----- Fake processes for a "clean production server" -----

_BASELINE_PROCESSES = [
    # System
    ("systemd",           0.3, 0.2,  5,   "root"),
    ("kthreadd",          0.0, 0.0,  1,   "root"),
    ("init",              0.1, 0.1,  1,   "root"),
    ("kworker",           0.5, 0.1,  1,   "root"),
    # Server stack
    ("nginx",             2.1, 1.5,  8,   "www-data"),
    ("nginx: worker",     3.2, 1.6,  4,   "www-data"),
    ("postgres",          1.8, 8.3,  16,  "postgres"),
    ("postgres: writer",  0.9, 2.1,  2,   "postgres"),
    ("redis-server",      1.3, 2.2,  4,   "redis"),
    ("node",              2.6, 5.1,  12,  "nodeuser"),
    ("python3",           3.2, 4.1,  8,   "appuser"),
    ("gunicorn",          2.8, 3.5,  6,   "appuser"),
    # Monitoring / infra
    ("argus-daemon",      0.8, 1.0,  3,   "argus"),
    ("prometheus",        1.1, 2.4,  8,   "monitoring"),
    ("node_exporter",     0.3, 0.5,  4,   "monitoring"),
    ("journald",          0.4, 0.6,  3,   "root"),
    ("ssh",               0.1, 0.3,  2,   "sshd"),
    ("cron",              0.0, 0.1,  1,   "root"),
]


def get_top_processes(n: int = 10) -> list[dict[str, Any]]:
    """Return 'healthy server' top processes + any active attack simulations."""
    pid_counter = 100
    results: list[dict[str, Any]] = []

    for name, cpu, mem, threads, user in _BASELINE_PROCESSES:
        # Small jitter to look alive
        cpu_j = max(0.0, cpu + (random.random() - 0.5) * 0.5)
        mem_j = max(0.0, mem + (random.random() - 0.5) * 0.2)
        results.append({
            "pid": pid_counter,
            "name": name,
            "cpu_percent": round(cpu_j, 1),
            "memory_percent": round(mem_j, 2),
            "memory_mb": round(mem_j * 80, 1),  # assume ~8GB total
            "num_threads": threads,
            "user": user,
            "status": "sleeping" if cpu_j < 1 else "running",
            "is_simulated": False,
        })
        pid_counter += random.randint(10, 80)

    # Add simulated attack processes
    for fake in sim_engine.as_fake_processes():
        results.append(fake)

    results.sort(key=lambda x: x["cpu_percent"], reverse=True)
    return results[:n]


# ----- Fake network connections -----

_BASELINE_CONNECTIONS = [
    ("nginx",       "0.0.0.0:80",       "203.0.113.14:54221",  "ESTABLISHED"),
    ("nginx",       "0.0.0.0:80",       "198.51.100.42:49812", "ESTABLISHED"),
    ("nginx",       "0.0.0.0:443",      "203.0.113.88:51223",  "ESTABLISHED"),
    ("postgres",    "127.0.0.1:5432",   "127.0.0.1:34556",     "ESTABLISHED"),
    ("redis-server","127.0.0.1:6379",   "127.0.0.1:41201",     "ESTABLISHED"),
    ("sshd",        "0.0.0.0:22",       "198.51.100.22:55332", "ESTABLISHED"),
    ("prometheus",  "0.0.0.0:9090",     "10.0.0.5:44120",      "ESTABLISHED"),
    ("node",        "0.0.0.0:3000",     "203.0.113.201:33021", "ESTABLISHED"),
]


def get_network_connections(limit: int = 15) -> list[dict[str, Any]]:
    results = []
    pid_counter = 100
    for process, local, remote, status in _BASELINE_CONNECTIONS:
        results.append({
            "pid": pid_counter,
            "process": process,
            "local": local,
            "remote": remote,
            "status": status,
            "family": "IPv4",
        })
        pid_counter += random.randint(10, 80)

    return results[:limit]


# ----- Detection stats (uses real DB data) -----

def get_detection_stats() -> dict[str, Any]:
    from storage import database as db

    with db.cursor() as cur:
        cur.execute("""
            SELECT level, COUNT(*) as c FROM events
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY level
        """)
        events_24h = {row["level"]: row["c"] for row in cur.fetchall()}

        cur.execute("""
            SELECT action_type, COUNT(*) as c FROM actions
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY action_type
        """)
        actions_24h = {row["action_type"]: row["c"] for row in cur.fetchall()}

        cur.execute("""
            SELECT COUNT(*) as total,
                   SUM(CASE WHEN detected_by_defender = 1 THEN 1 ELSE 0 END) as detected,
                   AVG(detection_latency_seconds) as avg_latency
            FROM attacks
            WHERE timestamp >= datetime('now', '-24 hours')
        """)
        row = cur.fetchone()
        attack_stats = {
            "total_attacks": row["total"] or 0,
            "detected": row["detected"] or 0,
            "avg_detection_latency_sec": round(row["avg_latency"] or 0, 2),
        }

        cur.execute("""
            SELECT COUNT(*) as c FROM process_genealogy
            WHERE is_suspicious = 1 AND timestamp >= datetime('now', '-24 hours')
        """)
        suspicious_procs = cur.fetchone()["c"] or 0

        cur.execute("""
            SELECT AVG(cpu_percent) as cpu, AVG(memory_percent) as mem,
                   MAX(cpu_percent) as cpu_peak, MAX(memory_percent) as mem_peak
            FROM metrics
            WHERE timestamp >= datetime('now', '-1 hour')
        """)
        row = cur.fetchone()

    return {
        "events_24h": events_24h,
        "actions_24h": actions_24h,
        "attack_stats": attack_stats,
        "suspicious_processes_24h": suspicious_procs,
        "performance_1h": {
            "avg_cpu": round(row["cpu"] or 0, 1),
            "avg_memory": round(row["mem"] or 0, 1),
            "peak_cpu": round(row["cpu_peak"] or 0, 1),
            "peak_memory": round(row["mem_peak"] or 0, 1),
        },
    }


def _is_windows() -> bool:
    return platform.system() == "Windows"
