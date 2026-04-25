"""Memory Leak — SIMULATED. Slow memory growth pattern."""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack


class MemoryLeak(BaseAttack):
    name = "memory_leak"
    category = "ai_test"
    description = "[SIM] Simulated memory leak — gradual memory growth"

    def _run(self) -> None:
        rate_mb = max(1, int(self.params.get("leak_rate_mb_per_sec", 10)))
        duration = min(int(self.params.get("duration", 60)), self.max_duration)
        # Total accumulated over duration (capped at safe limit)
        total_mb = min(rate_mb * duration, self.cfg.attacks.max_ram_mb)

        self.register_impact(
            cpu_percent=3,
            memory_mb=total_mb,
            thread_count=1,
            ramp_start_time=time.time(),
            ramp_duration=duration,  # linear ramp over full duration
        )

        while self.is_running and self._check_safety():
            time.sleep(0.5)
