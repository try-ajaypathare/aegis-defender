"""Swap Thrash — SIMULATED."""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack


class SwapThrash(BaseAttack):
    name = "swap_thrash"
    category = "io"
    description = "[SIM] Simulated swap thrashing — memory + I/O metrics rise"

    def _run(self) -> None:
        size_mb = min(int(self.params.get("size_mb", 1500)),
                      self.cfg.attacks.max_ram_mb)
        self.register_impact(
            cpu_percent=30,
            memory_mb=size_mb,
            disk_read_mb=25,
            disk_write_mb=25,
            ramp_start_time=time.time(),
            ramp_duration=6,
        )
        while self.is_running and self._check_safety():
            time.sleep(0.5)
