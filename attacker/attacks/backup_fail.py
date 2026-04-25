"""
Backup failure attack — marks the last backup attempt as failed.
"""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack
from shared.event_bus import Topics, bus
from shared.logger import get_logger
from shared.state import infra_state


log = get_logger("attack.backup_fail")


REASONS = [
    "Disk write error: device full",
    "Network timeout to backup server",
    "Backup destination unreachable: 503",
    "Permission denied: cannot read /var/data",
    "Snapshot creation failed: VSS error 0x8004230C",
]


class BackupFail(BaseAttack):
    name = "backup_fail"
    category = "infra"
    description = "Mark last backup as failed. Triggers infra-audit alert."

    DEFAULTS = {
        "duration": 90,
        "reason": None,
    }

    def _run(self) -> None:
        import random
        reason = self.params.get("reason") or random.choice(REASONS)

        infra_state.trigger_backup_failure(error=reason)
        bus.publish("event", {
            "category": "infra",
            "level": "CRITICAL",
            "message": f"Backup failed: {reason}",
            "source": self.name,
        })
        log.info(f"[SIM] Backup failure injected: {reason}")

        while self.is_running and self._check_safety():
            time.sleep(1)
