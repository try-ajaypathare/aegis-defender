"""
DNS blackhole attack — flips DNS link to "down" so the dashboard shows
DNS resolution failures.
"""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack
from shared.event_bus import Topics, bus
from shared.logger import get_logger
from shared.state import network_state
from shared.state.network_state import DEGRADED, DOWN


log = get_logger("attack.dns_blackhole")


class DNSBlackhole(BaseAttack):
    name = "dns_blackhole"
    category = "network"
    description = "Simulate DNS resolution failure — public DNS unreachable / poisoned."

    DEFAULTS = {
        "mode": "down",        # "down" | "degraded"
        "duration": 60,
    }

    def _run(self) -> None:
        mode = self.params.get("mode", self.DEFAULTS["mode"])
        duration = int(self.params.get("duration", self.DEFAULTS["duration"]))

        status = DOWN if mode == "down" else DEGRADED
        ok = network_state.inject_link_failure("dns", status=status, reason="dns_blackhole_sim", duration_s=duration)
        if not ok:
            self.stop(stopped_by="link_not_registered")
            return

        bus.publish("event", {
            "category": "network",
            "level": "CRITICAL" if mode == "down" else "WARNING",
            "message": f"DNS resolution failing — link state {status}",
            "source": self.name,
            "link": "dns",
        })
        log.info(f"[SIM] DNS link → {status} for {duration}s")

        while self.is_running and self._check_safety():
            time.sleep(0.5)
