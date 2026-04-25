"""Log Flood — SIMULATED."""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack


class LogFlood(BaseAttack):
    name = "log_flood"
    category = "advanced"
    description = "[SIM] Simulated log flood — disk write rate rises, no real files"

    def _run(self) -> None:
        self.register_impact(
            cpu_percent=15,
            memory_mb=20,
            disk_write_mb=30,
            disk_space_mb=100,
        )
        while self.is_running and self._check_safety():
            time.sleep(0.5)
