"""
Infrastructure audit — backup, NTP, OS updates, hardware.

Checks current state, emits events on degradation. Most state is
simulated/seeded; real probes (where possible) update baselines.
"""
from __future__ import annotations

import threading
import time

from shared.config_loader import get_config
from shared.event_bus import bus
from shared.logger import get_logger
from shared.state import infra_state


log = get_logger("checks.infra")


class InfraAuditCheck:
    def __init__(self) -> None:
        self.cfg = get_config()
        self._stop = threading.Event()
        self._last_emit: dict[str, float] = {}

    def _emit_throttled(self, key: str, payload: dict, throttle_s: int = 60) -> None:
        now = time.time()
        if now - self._last_emit.get(key, 0) >= throttle_s:
            bus.publish("event", payload)
            self._last_emit[key] = now

    def _check_backup(self) -> None:
        if infra_state.backup.last_status == "failed":
            self._emit_throttled("backup_failed", {
                "category": "infra",
                "level": "CRITICAL",
                "message": f"Backup failed: {infra_state.backup.last_error or 'unknown error'}",
                "source": "infra_audit",
            })
        elif infra_state.backup.is_overdue():
            self._emit_throttled("backup_overdue", {
                "category": "infra",
                "level": "WARNING",
                "message": f"Backup overdue — last success {round(infra_state.backup.hours_since_last_success(), 1)}h ago",
                "source": "infra_audit",
            })

    def _check_ntp(self) -> None:
        if infra_state.ntp.is_drifted():
            self._emit_throttled("ntp_drift", {
                "category": "infra",
                "level": "WARNING",
                "message": f"NTP drift {infra_state.ntp.effective_drift():.2f}s exceeds threshold",
                "source": "infra_audit",
            })

    def _check_hardware(self) -> None:
        if infra_state.hardware.has_warning():
            self._emit_throttled("hw_warning", {
                "category": "infra",
                "level": "WARNING",
                "message": f"Hardware warning: {infra_state.hardware.sim_warning or 'SMART status not OK'}",
                "source": "infra_audit",
            })

    def start(self) -> None:
        if not self.cfg.infra_health.enabled:
            log.info("Infra audit disabled in config")
            return

        infra_state.initialize_baseline(self.cfg)
        log.info(f"Infra audit started — {self.cfg.infra_health.audit_interval_seconds}s interval")

        while not self._stop.is_set():
            try:
                self._check_backup()
                self._check_ntp()
                self._check_hardware()
            except Exception as e:
                log.error(f"Infra audit error: {e}")
            self._stop.wait(self.cfg.infra_health.audit_interval_seconds)

    def stop(self) -> None:
        self._stop.set()
