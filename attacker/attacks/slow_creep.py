"""Slow Creep — SIMULATED. Gradually rising CPU designed to evade threshold rules."""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack


class SlowCreep(BaseAttack):
    name = "slow_creep"
    category = "ai_test"
    description = "[SIM] Simulated gradual CPU rise — evades static thresholds"

    def _run(self) -> None:
        duration = min(int(self.params.get("duration", 180)), self.max_duration)

        self.register_impact(
            cpu_percent=80,  # peak target
            memory_mb=50,
            thread_count=2,
            ramp_start_time=time.time(),
            ramp_duration=duration * 0.9,  # ramp over 90% of duration
        )

        while self.is_running and self._check_safety():
            time.sleep(0.5)
