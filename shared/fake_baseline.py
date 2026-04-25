"""
Fake baseline generator — produces realistic "healthy server" metrics
for the simulation dashboard.

Instead of reading real psutil values (which reflect the user's actual PC load),
we generate plausible low-utilization metrics with small jitter so the dashboard
looks like a fresh production server being monitored.

Real system info (total RAM, disk size, CPU count) is still read via psutil
because those are static facts.
"""
from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass


@dataclass
class BaselineTargets:
    """Target values for a healthy simulated server."""
    cpu_percent: float = 12.0
    memory_percent: float = 32.0
    disk_percent: float = 45.0
    process_count: int = 120
    thread_count: int = 820
    network_connections: int = 28
    network_sent_mb: float = 0.08
    network_recv_mb: float = 0.15
    disk_read_rate_mb: float = 0.4
    disk_write_rate_mb: float = 0.3
    context_switches: float = 5200.0


class FakeBaseline:
    """
    Generates a smoothly-varying baseline around healthy server targets.

    Uses sinusoidal oscillation + small random jitter to look natural.
    """

    def __init__(self, targets: BaselineTargets | None = None) -> None:
        self.t = targets or BaselineTargets()
        self._start = time.time()
        self._seed = random.random() * 1000

        # Per-metric oscillation phase (so metrics don't move in lockstep)
        self._phases = {
            "cpu": random.random() * math.tau,
            "memory": random.random() * math.tau,
            "disk": 0,  # disk is nearly constant
            "processes": random.random() * math.tau,
            "threads": random.random() * math.tau,
            "network_connections": random.random() * math.tau,
            "network_sent": random.random() * math.tau,
            "network_recv": random.random() * math.tau,
            "disk_read": random.random() * math.tau,
            "disk_write": random.random() * math.tau,
        }

    def _wave(self, key: str, amplitude: float, period_sec: float = 45) -> float:
        """Smooth sine wave + random jitter."""
        phase = self._phases.get(key, 0)
        elapsed = time.time() - self._start
        sine = math.sin(phase + (elapsed * math.tau / period_sec))
        jitter = (random.random() - 0.5) * 0.3  # ±0.15
        return (sine + jitter) * amplitude

    def current(self) -> dict[str, float]:
        t = self.t
        return {
            # Percentages — oscillate slightly around target
            "cpu_percent":    max(0.1, t.cpu_percent    + self._wave("cpu", 4, 28)),
            "memory_percent": max(0.1, t.memory_percent + self._wave("memory", 2, 60)),
            "disk_percent":   max(0.1, t.disk_percent   + self._wave("disk", 0.05, 600)),
            # Integer counts
            "process_count":  max(10, int(t.process_count + self._wave("processes", 5, 35))),
            "thread_count":   max(50, int(t.thread_count  + self._wave("threads", 30, 40))),
            "network_connections": max(1, int(t.network_connections + self._wave("network_connections", 4, 50))),
            # Network rates (MB/s)
            "network_sent_mb": max(0.0, t.network_sent_mb + self._wave("network_sent", 0.04, 15)),
            "network_recv_mb": max(0.0, t.network_recv_mb + self._wave("network_recv", 0.08, 15)),
            # Disk I/O rates
            "disk_read_rate_mb":  max(0.0, t.disk_read_rate_mb  + self._wave("disk_read", 0.2, 20)),
            "disk_write_rate_mb": max(0.0, t.disk_write_rate_mb + self._wave("disk_write", 0.15, 20)),
            # Context switches
            "context_switches": max(0, int(t.context_switches + self._wave("cpu", 400, 30))),
        }
