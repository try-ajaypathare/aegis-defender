"""
Infrastructure state — backup, NTP, OS updates, hardware health.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class BackupState:
    last_attempt_ts: float = 0.0
    last_success_ts: float = 0.0
    last_status: str = "ok"           # "ok" | "failed" | "running"
    last_error: Optional[str] = None
    consecutive_failures: int = 0
    expected_interval_hours: int = 24

    def hours_since_last_success(self) -> float:
        if self.last_success_ts == 0:
            return 999
        return (time.time() - self.last_success_ts) / 3600

    def is_overdue(self) -> bool:
        return self.hours_since_last_success() > (self.expected_interval_hours * 1.5)

    def to_dict(self) -> dict:
        return {
            "last_attempt_ts": self.last_attempt_ts,
            "last_success_ts": self.last_success_ts,
            "last_status": self.last_status,
            "last_error": self.last_error,
            "consecutive_failures": self.consecutive_failures,
            "hours_since_last_success": round(self.hours_since_last_success(), 1),
            "is_overdue": self.is_overdue(),
            "expected_interval_hours": self.expected_interval_hours,
        }


@dataclass
class NTPState:
    drift_seconds: float = 0.0
    last_sync_ts: float = 0.0
    server: str = "time.windows.com"
    sim_drift_override: Optional[float] = None
    max_drift_seconds: float = 5.0

    def effective_drift(self) -> float:
        return self.sim_drift_override if self.sim_drift_override is not None else self.drift_seconds

    def is_drifted(self) -> bool:
        return abs(self.effective_drift()) > self.max_drift_seconds

    def to_dict(self) -> dict:
        return {
            "drift_seconds": round(self.effective_drift(), 3),
            "real_drift_seconds": round(self.drift_seconds, 3),
            "last_sync_ts": self.last_sync_ts,
            "server": self.server,
            "is_drifted": self.is_drifted(),
            "is_simulated": self.sim_drift_override is not None,
            "max_drift_seconds": self.max_drift_seconds,
        }


@dataclass
class OSUpdatesState:
    pending_count: int = 0
    security_count: int = 0
    last_check_ts: float = 0.0

    def to_dict(self) -> dict:
        return {
            "pending_count": self.pending_count,
            "security_count": self.security_count,
            "last_check_ts": self.last_check_ts,
        }


@dataclass
class HardwareHealth:
    smart_status: str = "ok"            # "ok" | "warning" | "fail"
    fan_rpm: int = 1850
    cpu_temp_c: float = 52.0
    sim_warning: Optional[str] = None

    def has_warning(self) -> bool:
        return self.sim_warning is not None or self.smart_status != "ok"

    def to_dict(self) -> dict:
        return {
            "smart_status": self.smart_status,
            "fan_rpm": self.fan_rpm,
            "cpu_temp_c": self.cpu_temp_c,
            "sim_warning": self.sim_warning,
            "has_warning": self.has_warning(),
        }


class InfraState:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.backup = BackupState()
        self.ntp = NTPState()
        self.os_updates = OSUpdatesState()
        self.hardware = HardwareHealth()

    def initialize_baseline(self, cfg) -> None:
        """Seed reasonable healthy baseline from config."""
        with self._lock:
            now = time.time()
            self.backup.last_success_ts = now - 3600   # 1h ago
            self.backup.last_attempt_ts = now - 3600
            self.backup.expected_interval_hours = cfg.infra_health.backup.expected_interval_hours
            self.ntp.last_sync_ts = now - 300
            self.ntp.drift_seconds = 0.012
            self.ntp.max_drift_seconds = cfg.infra_health.ntp.max_drift_seconds
            self.os_updates.pending_count = 3
            self.os_updates.security_count = 1
            self.os_updates.last_check_ts = now

    # --- Backup ---

    def trigger_backup_failure(self, error: str = "Disk write error") -> None:
        with self._lock:
            self.backup.last_attempt_ts = time.time()
            self.backup.last_status = "failed"
            self.backup.last_error = error
            self.backup.consecutive_failures += 1

    def retry_backup_action(self) -> bool:
        with self._lock:
            now = time.time()
            self.backup.last_attempt_ts = now
            self.backup.last_success_ts = now
            self.backup.last_status = "ok"
            self.backup.last_error = None
            self.backup.consecutive_failures = 0
            return True

    # --- NTP ---

    def inject_ntp_drift(self, drift_s: float) -> None:
        with self._lock:
            self.ntp.sim_drift_override = drift_s

    def sync_ntp_action(self) -> bool:
        with self._lock:
            self.ntp.drift_seconds = 0.001
            self.ntp.sim_drift_override = None
            self.ntp.last_sync_ts = time.time()
            return True

    # --- Hardware warning ---

    def inject_hardware_warning(self, msg: str = "SMART: pending sectors") -> None:
        with self._lock:
            self.hardware.sim_warning = msg

    def clear_hardware_warning(self) -> None:
        with self._lock:
            self.hardware.sim_warning = None

    # --- Snapshot ---

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "backup": self.backup.to_dict(),
                "ntp": self.ntp.to_dict(),
                "os_updates": self.os_updates.to_dict(),
                "hardware": self.hardware.to_dict(),
            }

    def clear_overlays(self) -> int:
        n = 0
        with self._lock:
            if self.ntp.sim_drift_override is not None:
                self.ntp.sim_drift_override = None
                n += 1
            if self.hardware.sim_warning is not None:
                self.hardware.sim_warning = None
                n += 1
        return n


# Singleton
infra_state = InfraState()
