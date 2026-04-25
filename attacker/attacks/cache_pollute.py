"""Cache Pollute — SIMULATED."""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack


class CachePollute(BaseAttack):
    name = "cache_pollute"
    category = "resource_exhaustion"
    description = "[SIM] Simulated OS cache pollution — disk read rate rises, no real reads"

    def _run(self) -> None:
        self.register_impact(
            cpu_percent=10,
            memory_mb=200,
            disk_read_mb=20,
        )

        while self.is_running and self._check_safety():
            time.sleep(0.5)
