"""DNS Flood — SIMULATED. No real DNS queries."""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack


class DNSFlood(BaseAttack):
    name = "dns_flood"
    category = "security_threat"
    description = "[SIM] Simulated DNS query flood — network metrics rise, no real queries"

    def _run(self) -> None:
        qps = int(self.params.get("queries_per_second", 50))
        self.register_impact(
            cpu_percent=8,
            memory_mb=25,
            network_sent_mb=qps * 0.0001,
            network_recv_mb=qps * 0.0002,
            network_connections=min(50, qps),
        )
        while self.is_running and self._check_safety():
            time.sleep(0.5)
