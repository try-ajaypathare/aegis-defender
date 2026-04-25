"""Scheduled Task Sim — SIMULATED. No real task created in scheduler."""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack


class ScheduledTaskSim(BaseAttack):
    name = "scheduled_task_sim"
    category = "security_threat"
    description = "[SIM] Simulated persistence via scheduled task — no real task created"

    def _run(self) -> None:
        impact = self.register_impact(
            cpu_percent=2,
            memory_mb=15,
            process_count=1,
        )
        impact.fake_process_name = "schtasks_sim.exe"

        while self.is_running and self._check_safety():
            time.sleep(0.5)
