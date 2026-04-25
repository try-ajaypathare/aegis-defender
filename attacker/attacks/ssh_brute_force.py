"""
SSH brute force attack — generates synthetic failed-login events from
malicious IPs into auth_state. No real SSH server is touched.

Patterns:
  - "single_ip"  : one persistent attacker hammering many usernames
  - "distributed": multiple IPs each trying a few passwords
"""
from __future__ import annotations

import random
import time

from attacker.base_attack import BaseAttack
from shared.event_bus import Topics, bus
from shared.logger import get_logger
from shared.state import auth_state
from shared.state.auth_state import AuthEvent, RESULT_FAIL_PASSWORD, RESULT_FAIL_USER, RESULT_SUCCESS


log = get_logger("attack.ssh_brute_force")


# Fake malicious IP pool with country tags
MALICIOUS_IPS = [
    ("203.0.113.45", "RU"), ("198.51.100.222", "CN"), ("45.155.205.66", "BR"),
    ("185.220.101.34", "DE"), ("89.248.165.55", "NL"), ("167.99.234.12", "US"),
    ("94.156.65.231", "BG"), ("152.32.169.88", "VN"), ("139.59.190.55", "IN"),
]

USERNAMES = ["admin", "root", "ubuntu", "user", "postgres", "mysql", "deploy", "test", "git"]


class SSHBruteForce(BaseAttack):
    name = "ssh_brute_force"
    category = "security"
    description = "Synthetic SSH brute force — generates failed login events from malicious IPs into auth log."

    DEFAULTS = {
        "pattern": "single_ip",      # "single_ip" | "distributed"
        "duration": 90,
        "attempts_per_second": 3,
        "success_rate": 0.0,         # 0 = pure failure flood
    }

    def _pick_attacker(self, pattern: str) -> tuple[str, str]:
        return random.choice(MALICIOUS_IPS)

    def _run(self) -> None:
        pattern = self.params.get("pattern", self.DEFAULTS["pattern"])
        rate = float(self.params.get("attempts_per_second", self.DEFAULTS["attempts_per_second"]))
        success_rate = float(self.params.get("success_rate", self.DEFAULTS["success_rate"]))

        # Lock to one attacker IP if single mode
        if pattern == "single_ip":
            single = random.choice(MALICIOUS_IPS)
        else:
            single = None

        bus.publish("event", {
            "category": "security",
            "level": "WARNING",
            "message": f"SSH brute force started ({pattern}, {rate}/s)",
            "source": self.name,
            "pattern": pattern,
        })
        log.info(f"[SIM] SSH brute force pattern={pattern} rate={rate}/s")

        interval = 1.0 / max(0.1, rate)
        while self.is_running and self._check_safety():
            ip, country = single if single else random.choice(MALICIOUS_IPS)

            # Firewall realism: if defender has blocked this IP, packets never
            # reach the auth log. Skip recording → auth_failures count tapers
            # off as old events expire from the rolling window. This is what
            # makes AUTO mode visibly "solve" the brute force.
            threats = auth_state.all_threats()
            blocked = any(t["ip"] == ip and t.get("blocked") for t in threats)
            if blocked:
                # In single_ip mode, attack is fully contained — exit early
                if single:
                    log.info(f"[SIM] Brute force IP {ip} blocked by defender — attack contained")
                    break
                # In distributed mode, just skip this round, try a different IP next
                time.sleep(interval)
                continue

            user = random.choice(USERNAMES)
            is_success = random.random() < success_rate
            if is_success:
                result = RESULT_SUCCESS
            else:
                # Mostly password failures; occasional user-not-found
                result = RESULT_FAIL_PASSWORD if random.random() > 0.2 else RESULT_FAIL_USER

            auth_state.record_event(AuthEvent(
                timestamp=time.time(),
                source_ip=ip,
                username=user,
                service="ssh",
                result=result,
                country=country,
            ))
            time.sleep(interval)
