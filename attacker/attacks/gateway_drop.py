"""
Gateway drop attack — flips internet/gateway link to "down".
"""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack
from shared.event_bus import Topics, bus
from shared.logger import get_logger
from shared.state import network_state
from shared.state.network_state import DEGRADED, DOWN


log = get_logger("attack.gateway_drop")


class GatewayDrop(BaseAttack):
    name = "gateway_drop"
    category = "network"
    description = "Simulate internet uplink / gateway failure."

    DEFAULTS = {
        "target": "internet",      # "internet" | "gateway"
        "mode": "down",            # "down" | "degraded"
        "duration": 60,
    }

    def _run(self) -> None:
        target = self.params.get("target", self.DEFAULTS["target"])
        mode = self.params.get("mode", self.DEFAULTS["mode"])
        duration = int(self.params.get("duration", self.DEFAULTS["duration"]))

        if target not in ("internet", "gateway"):
            log.warning(f"Invalid target '{target}'")
            self.stop(stopped_by="invalid_target")
            return

        status = DOWN if mode == "down" else DEGRADED
        ok = network_state.inject_link_failure(target, status=status, reason=f"sim:{self.name}", duration_s=duration)
        if not ok:
            self.stop(stopped_by="link_not_registered")
            return

        bus.publish("event", {
            "category": "network",
            "level": "CRITICAL" if mode == "down" else "WARNING",
            "message": f"Network link '{target}' → {status}",
            "source": self.name,
            "link": target,
        })
        log.info(f"[SIM] Link {target} → {status} for {duration}s")

        while self.is_running and self._check_safety():
            time.sleep(0.5)
