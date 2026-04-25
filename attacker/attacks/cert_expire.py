"""
Cert expire attack — fast-forwards a monitored SSL cert's expiry to make it
appear nearly-expired. Pure metadata simulation.
"""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack
from shared.event_bus import Topics, bus
from shared.logger import get_logger
from shared.state import cert_state


log = get_logger("attack.cert_expire")


class CertExpire(BaseAttack):
    name = "cert_expire"
    category = "security"
    description = "Fast-forward SSL cert expiry — simulate forgotten cert renewal."

    DEFAULTS = {
        "domain": "api.example.com",
        "target_days_remaining": 3,    # how close to expiry to push it
        "duration": 180,
    }

    def _run(self) -> None:
        domain = self.params.get("domain", self.DEFAULTS["domain"])
        target_days = float(self.params.get("target_days_remaining", self.DEFAULTS["target_days_remaining"]))

        cert = cert_state.get(domain)
        if not cert:
            log.warning(f"Unknown cert domain '{domain}'")
            self.stop(stopped_by="invalid_target")
            return

        ok = cert_state.fast_forward_expiry(domain, target_days_remaining=target_days)
        if not ok:
            self.stop(stopped_by="overlay_failed")
            return

        bus.publish("event", {
            "category": "security",
            "level": "WARNING" if target_days > 7 else "CRITICAL",
            "message": f"SSL cert {domain} now expires in {target_days} days",
            "source": self.name,
            "domain": domain,
        })
        log.info(f"[SIM] Cert {domain} fast-forwarded to {target_days}d")

        # Hold the overlay for the duration
        while self.is_running and self._check_safety():
            time.sleep(1)
