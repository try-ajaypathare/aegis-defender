"""Zombie Process — SIMULATED."""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack


class ZombieProcess(BaseAttack):
    name = "zombie_process"
    category = "advanced"
    description = "[SIM] Simulated zombie processes — process counter rises"

    def _run(self) -> None:
        count = min(int(self.params.get("count", 10)), 30)
        self.register_impact(
            cpu_percent=5,
            memory_mb=count * 4,
            process_count=count,
        )
        while self.is_running and self._check_safety():
            time.sleep(0.5)
