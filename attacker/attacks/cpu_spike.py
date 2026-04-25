"""CPU Spike — SIMULATED. No real CPU is burned."""
from __future__ import annotations

import os
import time

from attacker.base_attack import BaseAttack


class CPUSpike(BaseAttack):
    name = "cpu_spike"
    category = "performance"
    description = "[SIM] Simulated CPU spike — makes metric cards show high CPU, no real burn"

    def _run(self) -> None:
        cores = min(int(self.params.get("cores", 2)),
                    os.cpu_count() or 4,
                    self.cfg.attacks.max_cpu_cores)
        # Each core contributes ~25% simulated CPU
        cpu_impact = min(95, cores * 23)

        self.register_impact(
            cpu_percent=cpu_impact,
            memory_mb=50,      # small overhead for worker
            thread_count=cores * 2,
        )

        while self.is_running and self._check_safety():
            time.sleep(0.5)
