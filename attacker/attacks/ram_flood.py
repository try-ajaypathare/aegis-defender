"""RAM Flood — SIMULATED. Memory card visibly jumps."""
from __future__ import annotations

import time

import psutil

from attacker.base_attack import BaseAttack


class RAMFlood(BaseAttack):
    name = "ram_flood"
    category = "performance"
    description = "[SIM] Simulated RAM allocation — memory card visibly spikes"

    def _run(self) -> None:
        try:
            total_mb = psutil.virtual_memory().total / (1024 * 1024)
        except Exception:
            total_mb = 8192

        # Default: fill to ~95% via simulation (accounts for baseline)
        # User can override via size_mb or fill_pct
        requested_mb = int(self.params.get("size_mb", 0))
        fill_pct = float(self.params.get("fill_pct", 0))

        if fill_pct > 0:
            size_mb = int(total_mb * fill_pct / 100)
        elif requested_mb > 0:
            size_mb = requested_mb
        else:
            size_mb = int(total_mb * 0.20)  # 20% of total RAM

        size_mb = min(size_mb, self.cfg.attacks.max_ram_mb, int(total_mb * 0.25))

        self.register_impact(
            cpu_percent=8,
            memory_mb=size_mb,
            thread_count=4,
            ramp_start_time=time.time(),
            ramp_duration=min(6, self.max_duration / 3),
        )

        while self.is_running and self._check_safety():
            time.sleep(0.5)
