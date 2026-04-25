"""PowerShell Obfuscation — SIMULATED. No real PowerShell spawned."""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack


class PowerShellObfuscation(BaseAttack):
    name = "powershell_obfuscation"
    category = "security_threat"
    description = "[SIM] Simulated PowerShell obfuscation — process counter rises, no real PS"

    def _run(self) -> None:
        count = min(int(self.params.get("count", 3)), 10)
        impact = self.register_impact(
            cpu_percent=count * 8,
            memory_mb=count * 60,
            process_count=count,
            thread_count=count * 4,
        )
        impact.fake_process_name = "powershell_enc_sim.exe"

        while self.is_running and self._check_safety():
            time.sleep(0.5)
