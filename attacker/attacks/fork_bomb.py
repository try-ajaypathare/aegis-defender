"""Fork Bomb — SIMULATED. Process card visibly jumps."""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack


class ForkBomb(BaseAttack):
    name = "fork_bomb"
    category = "resource_exhaustion"
    description = "[SIM] Simulated process flood — Processes card jumps visibly"

    def _run(self) -> None:
        # Boost count × 5 for visible impact (baseline is ~280, need big delta)
        requested = int(self.params.get("count", 20))
        count = min(requested * 5, 500)

        # Keep memory impact low so defender uses PROCESS rule, not memory kill
        self.register_impact(
            cpu_percent=20,
            memory_mb=count * 1,  # tiny — ~250MB for 250 processes
            process_count=count,
            thread_count=count * 2,
            ramp_start_time=time.time(),
            ramp_duration=2,
        )

        while self.is_running and self._check_safety():
            time.sleep(0.5)
