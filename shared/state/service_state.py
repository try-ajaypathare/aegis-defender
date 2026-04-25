"""
Service state — hybrid real-probe + simulation overlay.

Real probes update real_status, real_latency_ms.
Attacker simulations call inject_crash / inject_latency / clear_overlay.
Effective status = overlay if active, else real probe.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional


# Status values
STATUS_UP = "up"
STATUS_DOWN = "down"
STATUS_DEGRADED = "degraded"
STATUS_UNKNOWN = "unknown"


@dataclass
class ServiceRecord:
    id: str
    name: str
    type: str                                      # "http" | "tcp"
    host: Optional[str] = None
    port: int = 0
    probe_url: Optional[str] = None
    simulated_only: bool = False

    # REAL probe results
    real_status: str = STATUS_UNKNOWN
    real_latency_ms: float = 0.0
    real_last_probe_ts: float = 0.0
    real_error: Optional[str] = None

    # SIM overlay (set by attacker)
    sim_status: Optional[str] = None               # if not None, overrides real
    sim_latency_extra_ms: float = 0.0              # added on top of real latency
    sim_reason: Optional[str] = None               # e.g., "process_crash", "deadlock"
    sim_started_at: Optional[float] = None
    sim_until: Optional[float] = None              # epoch; None = manual clear

    # Post-heal grace: after a restart, hold status=UP for N seconds even if
    # real probes fail (transient post-restart probe failures are normal in
    # real life; in our demo XAMPP may not be running at all).
    grace_until: float = 0.0

    # Stats
    consecutive_failures: int = 0
    uptime_started_at: float = field(default_factory=time.time)
    last_status_change_ts: float = 0.0
    restart_count: int = 0

    def effective_status(self) -> str:
        """Return what dashboards should display — sim takes precedence."""
        if self.sim_status is not None:
            # Auto-clear if expired
            if self.sim_until is not None and time.time() > self.sim_until:
                self.sim_status = None
                self.sim_reason = None
                self.sim_started_at = None
                self.sim_until = None
                return self.real_status
            return self.sim_status
        # Post-heal grace window: hold UP through transient probe failures
        if self.grace_until and time.time() < self.grace_until:
            return STATUS_UP
        return self.real_status

    def effective_latency_ms(self) -> float:
        return self.real_latency_ms + self.sim_latency_extra_ms

    def uptime_seconds(self) -> float:
        if self.effective_status() == STATUS_UP:
            return time.time() - self.uptime_started_at
        return 0.0

    def is_simulated(self) -> bool:
        return self.sim_status is not None or self.sim_latency_extra_ms > 0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "host": self.host,
            "port": self.port,
            "status": self.effective_status(),
            "real_status": self.real_status,
            "latency_ms": round(self.effective_latency_ms(), 1),
            "real_latency_ms": round(self.real_latency_ms, 1),
            "uptime_seconds": int(self.uptime_seconds()),
            "consecutive_failures": self.consecutive_failures,
            "restart_count": self.restart_count,
            "last_probe_ts": self.real_last_probe_ts,
            "real_error": self.real_error,
            "is_simulated": self.is_simulated(),
            "sim_reason": self.sim_reason,
            "simulated_only": self.simulated_only,
        }


class ServiceState:
    """Global registry of monitored services."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._services: dict[str, ServiceRecord] = {}

    # --- Registry ---

    def register(self, rec: ServiceRecord) -> None:
        with self._lock:
            self._services[rec.id] = rec

    def register_from_config(self, monitored_list) -> None:
        """Register services from config.services.monitored list."""
        with self._lock:
            for svc in monitored_list:
                if svc.id not in self._services:
                    self._services[svc.id] = ServiceRecord(
                        id=svc.id,
                        name=svc.name,
                        type=svc.type,
                        host=svc.host or "127.0.0.1",
                        port=svc.port,
                        probe_url=svc.probe_url,
                        simulated_only=svc.simulated_only,
                    )

    def get(self, sid: str) -> Optional[ServiceRecord]:
        with self._lock:
            return self._services.get(sid)

    def all(self) -> list[ServiceRecord]:
        with self._lock:
            return list(self._services.values())

    def all_dict(self) -> list[dict]:
        with self._lock:
            return [s.to_dict() for s in self._services.values()]

    # --- Real probe updates ---

    def update_probe(
        self, sid: str, status: str, latency_ms: float, error: Optional[str] = None
    ) -> None:
        """Called by service_health check after each real probe."""
        with self._lock:
            rec = self._services.get(sid)
            if not rec:
                return

            now = time.time()
            old_eff = rec.effective_status()

            rec.real_status = status
            rec.real_latency_ms = latency_ms
            rec.real_last_probe_ts = now
            rec.real_error = error

            if status == STATUS_UP:
                rec.consecutive_failures = 0
            else:
                rec.consecutive_failures += 1

            new_eff = rec.effective_status()
            if old_eff != new_eff:
                rec.last_status_change_ts = now
                if new_eff == STATUS_UP:
                    rec.uptime_started_at = now

    # --- Simulation injections (called by attacker) ---

    def inject_crash(self, sid: str, reason: str = "process_crash", duration_s: Optional[float] = None) -> bool:
        with self._lock:
            rec = self._services.get(sid)
            if not rec:
                return False
            now = time.time()
            rec.sim_status = STATUS_DOWN
            rec.sim_reason = reason
            rec.sim_started_at = now
            rec.sim_until = (now + duration_s) if duration_s else None
            rec.last_status_change_ts = now
            return True

    def inject_degraded(self, sid: str, reason: str = "high_load", duration_s: Optional[float] = None) -> bool:
        with self._lock:
            rec = self._services.get(sid)
            if not rec:
                return False
            now = time.time()
            rec.sim_status = STATUS_DEGRADED
            rec.sim_reason = reason
            rec.sim_started_at = now
            rec.sim_until = (now + duration_s) if duration_s else None
            rec.last_status_change_ts = now
            return True

    def inject_latency(self, sid: str, extra_ms: float, duration_s: Optional[float] = None) -> bool:
        with self._lock:
            rec = self._services.get(sid)
            if not rec:
                return False
            now = time.time()
            rec.sim_latency_extra_ms = extra_ms
            rec.sim_reason = f"latency_inject (+{int(extra_ms)}ms)"
            rec.sim_started_at = now
            rec.sim_until = (now + duration_s) if duration_s else None
            return True

    def clear_overlay(self, sid: str, grace_seconds: float = 30) -> bool:
        """
        Clear simulation overlay — used by 'restart_service' action.

        Also forces real_status=UP and applies a `grace_seconds` window during
        which effective_status() returns UP regardless of real-probe failures.
        This prevents the rendered tile from immediately flipping back to DOWN
        when the underlying real service (XAMPP Apache/MySQL) is not running.
        """
        with self._lock:
            rec = self._services.get(sid)
            if not rec:
                return False
            now = time.time()
            rec.sim_status = None
            rec.sim_latency_extra_ms = 0.0
            rec.sim_reason = None
            rec.sim_started_at = None
            rec.sim_until = None
            # Force healthy state + grace window
            rec.real_status = STATUS_UP
            rec.real_error = None
            rec.consecutive_failures = 0
            rec.grace_until = now + grace_seconds
            rec.restart_count += 1
            rec.uptime_started_at = now
            rec.last_status_change_ts = now
            return True

    def clear_all_overlays(self) -> int:
        """Demo reset — clear all sim overlays."""
        n = 0
        with self._lock:
            for rec in self._services.values():
                if rec.is_simulated():
                    rec.sim_status = None
                    rec.sim_latency_extra_ms = 0.0
                    rec.sim_reason = None
                    rec.sim_started_at = None
                    rec.sim_until = None
                    n += 1
        return n


# Singleton
service_state = ServiceState()
