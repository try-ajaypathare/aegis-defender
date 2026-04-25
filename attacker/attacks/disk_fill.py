"""Disk Fill — SIMULATED. Disk card visibly rises."""
from __future__ import annotations

import time

import psutil

from attacker.base_attack import BaseAttack


class DiskFill(BaseAttack):
    name = "disk_fill"
    category = "performance"
    description = "[SIM] Simulated disk fill — disk card jumps visibly, no real files"

    def _run(self) -> None:
        # Express as % of disk to fill (so user sees dramatic change).
        # Default aims to push disk close to 100%.
        try:
            disk_total_mb = psutil.disk_usage("C:\\").total / (1024 * 1024)
        except Exception:
            disk_total_mb = 250_000  # fallback: 250 GB

        # Param: size_mb OR fill_pct (both supported)
        requested_mb = int(self.params.get("size_mb", 0))
        fill_pct = float(self.params.get("fill_pct", 0))

        if fill_pct > 0:
            size_mb = int(disk_total_mb * fill_pct / 100)
        elif requested_mb > 0:
            # Scale user's MB request up by 40× so tiny numbers still visible
            size_mb = requested_mb * 40
        else:
            # Default: fill 8% of disk (visible spike)
            size_mb = int(disk_total_mb * 0.08)

        # Clamp so card doesn't overflow (keep some headroom)
        max_sim_mb = int(disk_total_mb * 0.12)
        size_mb = min(size_mb, max_sim_mb)

        self.register_impact(
            cpu_percent=15,
            memory_mb=60,
            disk_space_mb=size_mb,
            disk_write_mb=max(50, size_mb / max(5, self.max_duration)),
            thread_count=3,
            ramp_start_time=time.time(),
            ramp_duration=min(6, self.max_duration / 2),
        )

        while self.is_running and self._check_safety():
            time.sleep(0.5)
