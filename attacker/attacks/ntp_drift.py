"""
NTP drift attack — injects clock drift to trigger time-sync alerts.
"""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack
from shared.event_bus import Topics, bus
from shared.logger import get_logger
from shared.state import infra_state


log = get_logger("attack.ntp_drift")


class NTPDrift(BaseAttack):
    name = "ntp_drift"
    category = "infra"
    description = "Inject NTP clock drift — beyond the configured threshold."

    DEFAULTS = {
        "drift_seconds": 12.5,
        "duration": 90,
    }

    def _run(self) -> None:
        drift = float(self.params.get("drift_seconds", self.DEFAULTS["drift_seconds"]))

        infra_state.inject_ntp_drift(drift)
        bus.publish("event", {
            "category": "infra",
            "level": "WARNING",
            "message": f"NTP clock drift {drift:.2f}s injected",
            "source": self.name,
        })
        log.info(f"[SIM] NTP drift {drift}s injected")

        while self.is_running and self._check_safety():
            time.sleep(1)
