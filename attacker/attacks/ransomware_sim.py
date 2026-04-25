"""Ransomware Simulation — SIMULATED. Rapid file I/O pattern."""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack


class RansomwareSim(BaseAttack):
    name = "ransomware_sim"
    category = "security_threat"
    description = "[SIM] Simulated ransomware I/O pattern — no real files touched"

    def _run(self) -> None:
        impact = self.register_impact(
            cpu_percent=45,
            memory_mb=200,
            disk_read_mb=40,
            disk_write_mb=40,
            thread_count=4,
        )
        impact.fake_process_name = "encrypt_sim.exe"

        while self.is_running and self._check_safety():
            time.sleep(0.5)
