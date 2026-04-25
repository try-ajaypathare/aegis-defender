"""
Metrics collector — FULL SIMULATION MODE.

Generates healthy-server baseline metrics (not user's real PC values) and
overlays active attack simulation impact. Real system is never stressed.

Only *static* info (total RAM, CPU count, disk size) is read from psutil;
everything else is synthesized.
"""
from __future__ import annotations

import time
from collections import deque
from datetime import datetime
from typing import Any

import psutil

from shared.config_loader import get_config
from shared.event_bus import Topics, bus
from shared.fake_baseline import FakeBaseline
from shared.logger import get_logger
from shared.simulation import engine as sim_engine
from storage import database as db

log = get_logger("monitor")


class Monitor:
    """Synthesizes baseline + overlays simulation, publishes to event bus."""

    def __init__(self) -> None:
        cfg = get_config()
        self.interval = cfg.monitoring.interval_seconds
        self.warmup = cfg.monitoring.warmup_samples
        self._running = False
        self._warmup_done = False
        self._warmup_count = 0

        self.fake = FakeBaseline()

        # Static system info (only thing we read from real system)
        self._total_ram_gb: float = psutil.virtual_memory().total / (1024 ** 3)
        try:
            self._total_disk_gb: float = psutil.disk_usage("C:\\" if _is_windows() else "/").total / (1024 ** 3)
        except Exception:
            self._total_disk_gb = 250.0

        self._prev_cpu: float = 0.0
        self._prev_memory_percent: float = 0.0
        self._process_history: deque = deque(maxlen=12)

    # ---------- Collection ----------

    def collect(self) -> dict[str, Any]:
        """Fake baseline + live simulation overlay."""
        base = self.fake.current()
        sim = sim_engine.totals()

        # CPU: cap at 100%
        cpu = min(100.0, base["cpu_percent"] + sim.get("cpu_percent", 0))

        # Memory: fake baseline % + simulated MB translated to %
        sim_mem_pct = (sim.get("memory_mb", 0) / 1024) / self._total_ram_gb * 100
        memory_pct = min(100.0, base["memory_percent"] + sim_mem_pct)
        memory_used_gb = self._total_ram_gb * memory_pct / 100

        # Disk: fake baseline % + simulated space translated to %
        sim_disk_pct = (sim.get("disk_space_mb", 0) / 1024) / self._total_disk_gb * 100
        disk_pct = min(100.0, base["disk_percent"] + sim_disk_pct)
        disk_free_gb = self._total_disk_gb * (100 - disk_pct) / 100

        # Counts
        proc_count = int(base["process_count"] + sim.get("process_count", 0))
        thread_count = int(base["thread_count"] + sim.get("thread_count", 0))
        conn_count = int(base["network_connections"] + sim.get("network_connections", 0))

        # Rates
        net_sent = base["network_sent_mb"] + sim.get("network_sent_mb", 0)
        net_recv = base["network_recv_mb"] + sim.get("network_recv_mb", 0)
        disk_read = base["disk_read_rate_mb"] + sim.get("disk_read_mb", 0)
        disk_write = base["disk_write_rate_mb"] + sim.get("disk_write_mb", 0)

        # Deltas
        cpu_delta = round(cpu - self._prev_cpu, 2)
        mem_delta = round(memory_pct - self._prev_memory_percent, 2)

        # Process spawn rate
        self._process_history.append(proc_count)
        if len(self._process_history) >= 2:
            spawn_rate = max(0, self._process_history[-1] - self._process_history[0])
            spawn_rate = spawn_rate * (60.0 / (len(self._process_history) * self.interval))
        else:
            spawn_rate = 0.0

        # Top process CPU (if sim has CPU)
        sim_cpu = sim.get("cpu_percent", 0)
        top_ratio = sim_cpu / 100.0 if sim_cpu > 0 else (base["cpu_percent"] / 300)

        now = datetime.now()

        metric = {
            "cpu_percent": round(cpu, 2),
            "memory_percent": round(memory_pct, 2),
            "memory_used_gb": round(memory_used_gb, 2),
            "memory_total_gb": round(self._total_ram_gb, 2),
            "disk_percent": round(disk_pct, 2),
            "disk_free_gb": round(disk_free_gb, 2),
            "process_count": proc_count,
            "thread_count": thread_count,
            "network_sent_mb": round(net_sent, 3),
            "network_recv_mb": round(net_recv, 3),
            "network_connections": conn_count,
            "cpu_delta": cpu_delta,
            "memory_delta": mem_delta,
            "process_spawn_rate": round(spawn_rate, 2),
            "top_process_cpu_ratio": round(top_ratio, 3),
            "disk_io_read_rate": round(disk_read, 3),
            "disk_io_write_rate": round(disk_write, 3),
            "context_switches_per_sec": round(base["context_switches"], 1),
            "hour_of_day": now.hour,
            "day_of_week": now.weekday(),
            "simulation_active": sim_engine.has_any(),
            "simulation_count": len(sim_engine.active_list()),
        }

        self._prev_cpu = cpu
        self._prev_memory_percent = memory_pct

        return metric

    def get_top_processes(self, n: int = 5, safety_list: list[str] | None = None) -> list[dict]:
        """Fake baseline processes + simulated attack processes."""
        # Synthetic "normal" processes that show up in every server
        baseline_processes = [
            {"pid": 1,   "name": "systemd",          "cpu_percent": 0.1, "memory_percent": 0.2, "is_simulated": False},
            {"pid": 4,   "name": "System",           "cpu_percent": 0.0, "memory_percent": 0.1, "is_simulated": False},
            {"pid": 200, "name": "nginx.exe",        "cpu_percent": 2.1, "memory_percent": 1.5, "is_simulated": False},
            {"pid": 312, "name": "redis-server.exe", "cpu_percent": 1.3, "memory_percent": 2.2, "is_simulated": False},
            {"pid": 455, "name": "python.exe",       "cpu_percent": 3.2, "memory_percent": 4.1, "is_simulated": False},
            {"pid": 500, "name": "postgres.exe",     "cpu_percent": 1.8, "memory_percent": 8.3, "is_simulated": False},
            {"pid": 601, "name": "node.exe",         "cpu_percent": 2.6, "memory_percent": 5.1, "is_simulated": False},
            {"pid": 755, "name": "argus-daemon",     "cpu_percent": 0.8, "memory_percent": 1.0, "is_simulated": False},
        ]
        result = list(baseline_processes)
        # Add simulated attack processes
        for fake in sim_engine.as_fake_processes():
            result.append(fake)
        result.sort(key=lambda x: x["cpu_percent"], reverse=True)
        return result[:n]

    # ---------- Loop ----------

    def start(self) -> None:
        log.info(f"Monitor starting (interval={self.interval}s) — FULL SIMULATION MODE (fake baseline)")
        self._running = True

        while self._running:
            try:
                metric = self.collect()

                if not self._warmup_done:
                    self._warmup_count += 1
                    if self._warmup_count >= self.warmup:
                        self._warmup_done = True
                        log.info("Warmup complete")
                else:
                    metric_id = db.insert_metric(metric)
                    metric["id"] = metric_id
                    bus.publish(Topics.METRIC_COLLECTED, metric)

            except Exception as e:  # noqa: BLE001
                log.error(f"Monitor error: {e}")

            time.sleep(self.interval)

    def stop(self) -> None:
        log.info("Monitor stopping")
        self._running = False


def _is_windows() -> bool:
    import platform
    return platform.system() == "Windows"
