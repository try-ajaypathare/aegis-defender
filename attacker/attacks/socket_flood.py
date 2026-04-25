"""Socket Flood — SIMULATED. No real sockets opened."""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack


class SocketFlood(BaseAttack):
    name = "socket_flood"
    category = "resource_exhaustion"
    description = "[SIM] Simulated socket flood — connection counter rises, no real sockets"

    def _run(self) -> None:
        count = min(int(self.params.get("count", 200)),
                    self.cfg.attacks.max_sockets)

        self.register_impact(
            cpu_percent=8,
            memory_mb=count * 0.3,
            network_connections=count,
            ramp_start_time=time.time(),
            ramp_duration=3,
        )

        while self.is_running and self._check_safety():
            time.sleep(0.5)
