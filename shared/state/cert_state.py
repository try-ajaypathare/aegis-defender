"""
Certificate state — simulated SSL certs with expiry tracking.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class CertRecord:
    domain: str
    issuer: str
    subject: str
    valid_from: float           # epoch
    valid_until: float          # epoch
    serial: str
    rotation_count: int = 0

    # Sim overlay (for fast-forward attack)
    sim_expiry_override: Optional[float] = None

    def effective_expiry(self) -> float:
        return self.sim_expiry_override if self.sim_expiry_override is not None else self.valid_until

    def days_to_expiry(self) -> float:
        return (self.effective_expiry() - time.time()) / 86400

    def is_expired(self) -> bool:
        return self.days_to_expiry() <= 0

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "issuer": self.issuer,
            "subject": self.subject,
            "valid_from": self.valid_from,
            "valid_until": self.effective_expiry(),
            "days_to_expiry": round(self.days_to_expiry(), 1),
            "is_expired": self.is_expired(),
            "rotation_count": self.rotation_count,
            "serial": self.serial,
            "is_simulated": self.sim_expiry_override is not None,
        }


class CertState:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._certs: dict[str, CertRecord] = {}

    def register_from_config(self, domains: list[str]) -> None:
        """Auto-create healthy cert records for monitored domains."""
        import random
        with self._lock:
            now = time.time()
            for domain in domains:
                if domain in self._certs:
                    continue
                # Generate plausible cert metadata
                days_remaining = random.randint(60, 365)
                self._certs[domain] = CertRecord(
                    domain=domain,
                    issuer="Let's Encrypt Authority X3",
                    subject=f"CN={domain}",
                    valid_from=now - (180 * 86400),
                    valid_until=now + (days_remaining * 86400),
                    serial=f"03:AB:{random.randint(10,99):02d}:{random.randint(10,99):02d}:CD",
                )

    def all(self) -> list[CertRecord]:
        with self._lock:
            return list(self._certs.values())

    def all_dict(self) -> list[dict]:
        with self._lock:
            return [c.to_dict() for c in self._certs.values()]

    def get(self, domain: str) -> Optional[CertRecord]:
        with self._lock:
            return self._certs.get(domain)

    def warning_certs(self, warning_days: float = 30) -> list[CertRecord]:
        with self._lock:
            return [c for c in self._certs.values() if c.days_to_expiry() <= warning_days]

    def fast_forward_expiry(self, domain: str, target_days_remaining: float = 5) -> bool:
        """Attacker simulation — pretend cert is about to expire."""
        with self._lock:
            cert = self._certs.get(domain)
            if not cert:
                return False
            cert.sim_expiry_override = time.time() + (target_days_remaining * 86400)
            return True

    def rotate(self, domain: str, new_validity_days: int = 90) -> bool:
        """Defender action — issue a fresh cert."""
        with self._lock:
            cert = self._certs.get(domain)
            if not cert:
                return False
            now = time.time()
            cert.valid_from = now
            cert.valid_until = now + (new_validity_days * 86400)
            cert.sim_expiry_override = None
            cert.rotation_count += 1
            cert.serial = f"03:AB:{int(now) % 100:02d}:NEW"
            return True

    def clear_overlays(self) -> int:
        n = 0
        with self._lock:
            for cert in self._certs.values():
                if cert.sim_expiry_override is not None:
                    cert.sim_expiry_override = None
                    n += 1
        return n


# Singleton
cert_state = CertState()
