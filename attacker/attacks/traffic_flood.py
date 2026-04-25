"""Traffic Flood — SIMULATED. Network card visibly jumps."""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack


class TrafficFlood(BaseAttack):
    name = "traffic_flood"
    category = "performance"
    description = "[SIM] Simulated HTTP flood — Network card spikes, no real requests"

    def _run(self) -> None:
        rps = int(self.params.get("requests_per_second", 500))
        # Scale connections proportional to RPS (tied together)
        connections = min(1500, rps)
        sent_mb = rps * 0.004
        recv_mb = rps * 0.008

        self.register_impact(
            cpu_percent=18,
            memory_mb=80,
            network_sent_mb=sent_mb,
            network_recv_mb=recv_mb,
            network_connections=connections,
            thread_count=10,
            ramp_start_time=time.time(),
            ramp_duration=3,
        )

        while self.is_running and self._check_safety():
            time.sleep(0.5)
