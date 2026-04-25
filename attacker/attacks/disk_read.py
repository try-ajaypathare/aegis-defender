"""Disk Read Storm — SIMULATED."""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack


class DiskReadStorm(BaseAttack):
    name = "disk_read"
    category = "io"
    description = "[SIM] Simulated disk read storm — I/O metrics rise, no real reads"

    def _run(self) -> None:
        self.register_impact(
            cpu_percent=12,
            memory_mb=30,
            disk_read_mb=50,  # 50 MB/sec simulated read
        )

        while self.is_running and self._check_safety():
            time.sleep(0.5)
