"""
Hardware warning attack — surfaces a SMART/fan/temp issue.
"""
from __future__ import annotations

import random
import time

from attacker.base_attack import BaseAttack
from shared.event_bus import Topics, bus
from shared.logger import get_logger
from shared.state import infra_state


log = get_logger("attack.hardware_warning")


WARNINGS = [
    "SMART: 5 pending sectors on /dev/sda",
    "SMART: reallocated sectors increasing",
    "Fan RPM dropped below threshold (300 RPM)",
    "CPU temp 92°C — sustained for 4 minutes",
    "Memory ECC errors detected on DIMM 2",
    "PSU voltage variance: 11.2V on 12V rail",
]


class HardwareWarning(BaseAttack):
    name = "hardware_warning"
    category = "infra"
    description = "Surface a hardware health warning (SMART/fan/temp/PSU)."

    DEFAULTS = {
        "message": None,
        "duration": 120,
    }

    def _run(self) -> None:
        msg = self.params.get("message") or random.choice(WARNINGS)
        infra_state.inject_hardware_warning(msg)

        bus.publish("event", {
            "category": "infra",
            "level": "WARNING",
            "message": f"Hardware warning: {msg}",
            "source": self.name,
        })
        log.info(f"[SIM] Hardware warning: {msg}")

        while self.is_running and self._check_safety():
            time.sleep(1)
