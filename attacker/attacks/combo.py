"""Combo — SIMULATED. All cards jump dramatically."""
from __future__ import annotations

import time

import psutil

from attacker.base_attack import BaseAttack


class ComboAttack(BaseAttack):
    name = "combo"
    category = "performance"
    description = "[SIM] Hits CPU + RAM + Disk + Processes + Network simultaneously"

    def _run(self) -> None:
        intensity = self.params.get("intensity", "medium")

        try:
            total_ram = psutil.virtual_memory().total / (1024 * 1024)
            total_disk = psutil.disk_usage("C:\\").total / (1024 * 1024)
        except Exception:
            total_ram = 8192
            total_disk = 250_000

        cfg = {
            "low":    {"cpu": 40, "ram_pct": 0.08, "disk_pct": 0.03, "procs": 60,  "conns": 150},
            "medium": {"cpu": 70, "ram_pct": 0.15, "disk_pct": 0.06, "procs": 150, "conns": 400},
            "high":   {"cpu": 92, "ram_pct": 0.22, "disk_pct": 0.09, "procs": 300, "conns": 900},
        }
        c = cfg.get(intensity, cfg["medium"])

        self.register_impact(
            cpu_percent=c["cpu"],
            memory_mb=int(total_ram * c["ram_pct"]),
            disk_space_mb=int(total_disk * c["disk_pct"]),
            disk_write_mb=80,
            process_count=c["procs"],
            thread_count=c["procs"] * 3,
            network_connections=c["conns"],
            network_sent_mb=4,
            network_recv_mb=8,
            ramp_start_time=time.time(),
            ramp_duration=5,
        )

        while self.is_running and self._check_safety():
            time.sleep(0.5)
