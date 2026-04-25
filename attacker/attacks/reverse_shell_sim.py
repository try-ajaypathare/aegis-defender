"""Reverse Shell Simulation — SIMULATED. No real network connection made."""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack


class ReverseShellSim(BaseAttack):
    name = "reverse_shell_sim"
    category = "security_threat"
    description = "[SIM] Simulated reverse-shell traffic pattern — no real connection"

    def _run(self) -> None:
        port = int(self.params.get("port", 4444))
        impact = self.register_impact(
            cpu_percent=4,
            memory_mb=30,
            network_sent_mb=0.05,
            network_recv_mb=0.05,
            network_connections=1,
            thread_count=2,
        )
        impact.fake_process_name = f"revshell_sim_port{port}.exe"

        while self.is_running and self._check_safety():
            time.sleep(0.5)
