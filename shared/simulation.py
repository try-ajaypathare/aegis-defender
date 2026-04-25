"""
Simulation Engine — tracks fake attack impact per attack ID.

CRITICAL SAFETY: In simulation mode, attacks DO NOT consume real system resources.
They only REGISTER their claimed impact here. The monitor adds this on top of
real baseline metrics, creating the illusion of attack without any real harm.

The defender's "kill_process" action translates to "unregister simulation"
so the attack effectively "dies" without any process actually being terminated.
"""
from __future__ import annotations

import random
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SimulatedImpact:
    """What an attack claims to be doing to the system."""
    attack_id: str
    attack_name: str
    # Simulated process identity (shown in top-processes, defender kills this)
    fake_pid: int = 0
    fake_process_name: str = ""

    # Impact on system metrics
    cpu_percent: float = 0.0          # additional CPU % on top of baseline
    memory_mb: float = 0.0            # additional MB of RAM
    disk_write_mb: float = 0.0        # disk I/O write rate (MB/s)
    disk_read_mb: float = 0.0         # disk I/O read rate (MB/s)
    disk_space_mb: float = 0.0        # disk space consumed (MB)
    process_count: int = 0            # additional process count
    thread_count: int = 0             # additional thread count
    network_connections: int = 0      # additional network connections
    network_sent_mb: float = 0.0      # network send rate (MB/s)
    network_recv_mb: float = 0.0      # network recv rate (MB/s)

    # Ramp-up: some attacks grow over time (slow_creep, memory_leak)
    ramp_start_time: float = 0.0
    ramp_duration: float = 0.0       # 0 = instant, > 0 = gradual ramp-up
    ramp_peak_multiplier: float = 1.0

    # Metadata
    created_at: float = field(default_factory=time.time)


class SimulationEngine:
    """Global registry of active attack impacts."""

    def __init__(self) -> None:
        self._active: dict[str, SimulatedImpact] = {}
        self._lock = threading.Lock()
        self._next_fake_pid = 100_000

    # -------- Registration --------

    def register(self, impact: SimulatedImpact) -> None:
        with self._lock:
            if not impact.fake_pid:
                impact.fake_pid = self._next_fake_pid
                self._next_fake_pid += 1
            if not impact.fake_process_name:
                impact.fake_process_name = f"sim_{impact.attack_name}.exe"
            self._active[impact.attack_id] = impact

    def unregister(self, attack_id: str) -> bool:
        """Remove an attack's simulated impact. Returns True if existed."""
        with self._lock:
            return self._active.pop(attack_id, None) is not None

    def kill_by_name(self, name: str) -> str | None:
        """Defender action: remove impact by fake process name. Returns attack_id killed."""
        with self._lock:
            for aid, impact in list(self._active.items()):
                if impact.fake_process_name == name:
                    del self._active[aid]
                    return aid
        return None

    def kill_by_pid(self, pid: int) -> str | None:
        with self._lock:
            for aid, impact in list(self._active.items()):
                if impact.fake_pid == pid:
                    del self._active[aid]
                    return aid
        return None

    def kill_top_cpu(self) -> SimulatedImpact | None:
        """Defender action: kill the simulated process using most CPU."""
        with self._lock:
            if not self._active:
                return None
            # Find the one with highest current CPU claim
            top = max(self._active.values(), key=lambda i: self._current_value(i, "cpu_percent"))
            if top.cpu_percent <= 0:
                return None
            del self._active[top.attack_id]
            return top

    def kill_top_memory(self) -> SimulatedImpact | None:
        with self._lock:
            if not self._active:
                return None
            top = max(self._active.values(), key=lambda i: self._current_value(i, "memory_mb"))
            if top.memory_mb <= 0:
                return None
            del self._active[top.attack_id]
            return top

    # -------- Ramp-up helpers --------

    def _current_value(self, impact: SimulatedImpact, attr: str) -> float:
        """Return current effective value of impact attribute, respecting ramp-up."""
        target = getattr(impact, attr, 0)
        if not target or impact.ramp_duration <= 0:
            return target
        elapsed = time.time() - impact.ramp_start_time
        if elapsed <= 0:
            return 0.0
        ratio = min(1.0, elapsed / impact.ramp_duration) * impact.ramp_peak_multiplier
        return target * ratio

    # -------- Aggregation --------

    def totals(self) -> dict[str, float]:
        """Sum all active impacts into total fake load."""
        totals = defaultdict(float)
        with self._lock:
            for imp in self._active.values():
                for attr in (
                    "cpu_percent", "memory_mb", "disk_write_mb", "disk_read_mb",
                    "disk_space_mb", "process_count", "thread_count",
                    "network_connections", "network_sent_mb", "network_recv_mb",
                ):
                    totals[attr] += self._current_value(imp, attr)
        return dict(totals)

    def active_list(self) -> list[SimulatedImpact]:
        with self._lock:
            return list(self._active.values())

    def has_any(self) -> bool:
        with self._lock:
            return bool(self._active)

    def clear(self) -> None:
        with self._lock:
            self._active.clear()

    # -------- Simulated top processes (for defender's top-proc view) --------

    def as_fake_processes(self) -> list[dict[str, Any]]:
        """Return simulated impacts as process-like entries."""
        out = []
        with self._lock:
            for imp in self._active.values():
                cpu = self._current_value(imp, "cpu_percent")
                mem_mb = self._current_value(imp, "memory_mb")
                out.append({
                    "pid": imp.fake_pid,
                    "name": imp.fake_process_name,
                    "cpu_percent": round(cpu, 1),
                    "memory_mb": round(mem_mb, 1),
                    "memory_percent": 0,  # will be computed by caller
                    "num_threads": max(1, int(self._current_value(imp, "thread_count"))),
                    "user": "ARGUS\\sim",
                    "status": "running",
                    "is_simulated": True,
                })
        return out


# Global singleton
engine = SimulationEngine()
