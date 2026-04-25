"""
Auth state — simulated SSH/HTTP authentication log.

Holds a rolling buffer of auth events. Used by:
- Attacker: inject_failed_login() floods the log
- Security audit check: scans for brute force patterns
- UI: live auth feed
"""
from __future__ import annotations

import collections
import threading
import time
from dataclasses import dataclass
from typing import Optional


# Auth result types
RESULT_SUCCESS = "success"
RESULT_FAIL_PASSWORD = "fail_password"
RESULT_FAIL_USER = "fail_user"
RESULT_FAIL_OTHER = "fail_other"


@dataclass
class AuthEvent:
    timestamp: float
    source_ip: str
    username: str
    service: str            # "ssh" | "http" | "ftp"
    result: str             # success/fail_*
    user_agent: Optional[str] = None
    country: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "ts": self.timestamp,
            "ts_human": time.strftime("%H:%M:%S", time.localtime(self.timestamp)),
            "source_ip": self.source_ip,
            "username": self.username,
            "service": self.service,
            "result": self.result,
            "user_agent": self.user_agent,
            "country": self.country,
            "is_failure": self.result.startswith("fail"),
        }


@dataclass
class IPThreat:
    ip: str
    threat_score: int       # 0-100
    failures_recent: int
    first_seen: float
    last_seen: float
    blocked_until: Optional[float] = None
    country: Optional[str] = None
    reason: Optional[str] = None

    def is_blocked(self) -> bool:
        return self.blocked_until is not None and time.time() < self.blocked_until

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "threat_score": self.threat_score,
            "failures_recent": self.failures_recent,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "blocked": self.is_blocked(),
            "blocked_until": self.blocked_until,
            "country": self.country,
            "reason": self.reason,
        }


class AuthState:
    """Rolling auth log + IP threat tracking."""

    MAX_EVENTS = 500

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._events: collections.deque[AuthEvent] = collections.deque(maxlen=self.MAX_EVENTS)
        self._ip_threats: dict[str, IPThreat] = {}

    def record_event(self, ev: AuthEvent) -> None:
        with self._lock:
            self._events.append(ev)
            if ev.result.startswith("fail"):
                threat = self._ip_threats.get(ev.source_ip)
                if not threat:
                    threat = IPThreat(
                        ip=ev.source_ip,
                        threat_score=10,
                        failures_recent=0,
                        first_seen=ev.timestamp,
                        last_seen=ev.timestamp,
                        country=ev.country,
                    )
                    self._ip_threats[ev.source_ip] = threat
                threat.last_seen = ev.timestamp
                threat.failures_recent += 1
                threat.threat_score = min(100, 10 + threat.failures_recent * 8)

    def recent_events(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return [e.to_dict() for e in list(self._events)[-limit:]]

    def failed_in_window(self, window_seconds: float = 300) -> list[AuthEvent]:
        cutoff = time.time() - window_seconds
        with self._lock:
            return [e for e in self._events if e.timestamp >= cutoff and e.result.startswith("fail")]

    def failed_by_ip(self, window_seconds: float = 300) -> dict[str, int]:
        result: dict[str, int] = {}
        for e in self.failed_in_window(window_seconds):
            result[e.source_ip] = result.get(e.source_ip, 0) + 1
        return result

    def all_threats(self) -> list[dict]:
        with self._lock:
            return [t.to_dict() for t in self._ip_threats.values()]

    def block_ip(self, ip: str, duration_s: float, reason: str = "brute_force") -> bool:
        with self._lock:
            threat = self._ip_threats.get(ip)
            if not threat:
                threat = IPThreat(
                    ip=ip, threat_score=80, failures_recent=0,
                    first_seen=time.time(), last_seen=time.time(),
                )
                self._ip_threats[ip] = threat
            threat.blocked_until = time.time() + duration_s
            threat.reason = reason
            threat.threat_score = max(threat.threat_score, 80)
            return True

    def unblock_ip(self, ip: str) -> bool:
        with self._lock:
            threat = self._ip_threats.get(ip)
            if threat:
                threat.blocked_until = None
                return True
            return False

    def clear_all(self) -> None:
        with self._lock:
            self._events.clear()
            self._ip_threats.clear()

    def stats(self) -> dict:
        with self._lock:
            now = time.time()
            blocked_set = {ip for ip, t in self._ip_threats.items() if t.is_blocked()}
            failed_5m = sum(1 for e in self._events if now - e.timestamp < 300 and e.result.startswith("fail"))
            # active = failures from non-blocked IPs (effectively, the live threat)
            active_failed_5m = sum(1 for e in self._events
                                    if now - e.timestamp < 300
                                    and e.result.startswith("fail")
                                    and e.source_ip not in blocked_set)
            success_5m = sum(1 for e in self._events if now - e.timestamp < 300 and e.result == RESULT_SUCCESS)
            return {
                "total_events": len(self._events),
                "failed_5m": failed_5m,
                "active_failed_5m": active_failed_5m,
                "success_5m": success_5m,
                "unique_ips": len(self._ip_threats),
                "blocked_ips": len(blocked_set),
            }


# Singleton
auth_state = AuthState()
