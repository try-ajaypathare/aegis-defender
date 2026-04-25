"""Cryptomining Simulation — SIMULATED. Realistic XMRig-like CPU pattern."""
from __future__ import annotations

import os
import time

from attacker.base_attack import BaseAttack


class CryptominingSim(BaseAttack):
    name = "cryptomining_sim"
    category = "security_threat"
    description = "[SIM] Simulated crypto mining (sustained high CPU pattern)"

    def _run(self) -> None:
        cores = min(int(self.params.get("cores", 2)),
                    os.cpu_count() or 4,
                    self.cfg.attacks.max_cpu_cores)
        cpu_impact = min(90, cores * 22)

        impact = self.register_impact(
            cpu_percent=cpu_impact,
            memory_mb=120,
            thread_count=cores,
            network_sent_mb=0.5,  # pool communication
            network_recv_mb=0.1,
        )
        # Custom fake name — defender should flag this
        impact.fake_process_name = "xmrig_sim.exe"

        while self.is_running and self._check_safety():
            time.sleep(0.5)
