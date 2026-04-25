"""Thread Flood — SIMULATED. No real threads created."""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack


class ThreadFlood(BaseAttack):
    name = "thread_flood"
    category = "resource_exhaustion"
    description = "[SIM] Simulated thread explosion — thread counter rises, no real threads"

    def _run(self) -> None:
        count = min(int(self.params.get("count", 200)),
                    self.cfg.attacks.max_threads)

        self.register_impact(
            cpu_percent=15,
            memory_mb=count * 1.5,
            thread_count=count,
            ramp_start_time=time.time(),
            ramp_duration=4,
        )

        while self.is_running and self._check_safety():
            time.sleep(0.5)
