"""File Handle Exhaust — SIMULATED."""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack


class FileHandleExhaust(BaseAttack):
    name = "file_handle"
    category = "resource_exhaustion"
    description = "[SIM] Simulated file handle exhaustion — no real files opened"

    def _run(self) -> None:
        count = min(int(self.params.get("count", 300)),
                    self.cfg.attacks.max_file_handles)

        self.register_impact(
            cpu_percent=5,
            memory_mb=count * 0.5,
            thread_count=1,
        )

        while self.is_running and self._check_safety():
            time.sleep(0.5)
