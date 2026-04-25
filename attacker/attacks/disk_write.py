"""Disk Write Storm — SIMULATED."""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack


class DiskWriteStorm(BaseAttack):
    name = "disk_write"
    category = "io"
    description = "[SIM] Simulated disk write storm — I/O metrics rise, no real writes"

    def _run(self) -> None:
        self.register_impact(
            cpu_percent=12,
            memory_mb=40,
            disk_write_mb=60,
        )
        while self.is_running and self._check_safety():
            time.sleep(0.5)
