"""
Network state — gateway/DNS/firewall + port audit.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional


# Health values
HEALTHY = "healthy"
DEGRADED = "degraded"
DOWN = "down"


@dataclass
class NetworkLink:
    name: str               # "internet" | "gateway" | "dns" | "firewall"
    target: str             # IP / hostname
    real_status: str = HEALTHY
    real_latency_ms: float = 0.0
    real_last_probe_ts: float = 0.0

    # Sim overlay
    sim_status: Optional[str] = None
    sim_reason: Optional[str] = None
    sim_until: Optional[float] = None

    def effective_status(self) -> str:
        if self.sim_status is not None:
            if self.sim_until is not None and time.time() > self.sim_until:
                self.sim_status = None
                self.sim_reason = None
                self.sim_until = None
                return self.real_status
            return self.sim_status
        return self.real_status

    def is_simulated(self) -> bool:
        return self.sim_status is not None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "target": self.target,
            "status": self.effective_status(),
            "real_status": self.real_status,
            "latency_ms": round(self.real_latency_ms, 1),
            "is_simulated": self.is_simulated(),
            "sim_reason": self.sim_reason,
            "last_probe_ts": self.real_last_probe_ts,
        }


@dataclass
class PortRecord:
    port: int
    protocol: str = "tcp"
    expected: bool = False      # in expected_open_ports config?
    forbidden: bool = False     # in forbidden_ports config?
    real_open: bool = False
    sim_open: Optional[bool] = None
    process: Optional[str] = None
    last_check_ts: float = 0.0

    def effective_open(self) -> bool:
        return self.sim_open if self.sim_open is not None else self.real_open

    def severity(self) -> str:
        """Risk level for this port's current state."""
        if self.forbidden and self.effective_open():
            return "critical"
        if not self.expected and self.effective_open():
            return "warning"
        if self.expected and not self.effective_open():
            return "warning"
        return "ok"

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "expected": self.expected,
            "forbidden": self.forbidden,
            "open": self.effective_open(),
            "real_open": self.real_open,
            "is_simulated": self.sim_open is not None,
            "process": self.process,
            "severity": self.severity(),
            "last_check_ts": self.last_check_ts,
        }


class NetworkState:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._links: dict[str, NetworkLink] = {}
        self._ports: dict[int, PortRecord] = {}

    # --- Network links ---

    def register_link(self, name: str, target: str) -> None:
        with self._lock:
            if name not in self._links:
                self._links[name] = NetworkLink(name=name, target=target)

    def update_link_probe(self, name: str, status: str, latency_ms: float = 0) -> None:
        with self._lock:
            link = self._links.get(name)
            if link:
                link.real_status = status
                link.real_latency_ms = latency_ms
                link.real_last_probe_ts = time.time()

    def inject_link_failure(self, name: str, status: str = DOWN, reason: str = "simulated", duration_s: Optional[float] = None) -> bool:
        with self._lock:
            link = self._links.get(name)
            if not link:
                return False
            link.sim_status = status
            link.sim_reason = reason
            link.sim_until = (time.time() + duration_s) if duration_s else None
            return True

    def clear_link_overlay(self, name: str) -> bool:
        with self._lock:
            link = self._links.get(name)
            if link and link.sim_status is not None:
                link.sim_status = None
                link.sim_reason = None
                link.sim_until = None
                return True
            return False

    def all_links(self) -> list[dict]:
        with self._lock:
            return [l.to_dict() for l in self._links.values()]

    # --- Ports ---

    def register_ports(self, expected: list[int], forbidden: list[int]) -> None:
        with self._lock:
            for p in expected:
                if p not in self._ports:
                    self._ports[p] = PortRecord(port=p, expected=True, real_open=True)
            for p in forbidden:
                if p not in self._ports:
                    self._ports[p] = PortRecord(port=p, forbidden=True, real_open=False)

    def all_ports(self) -> list[dict]:
        with self._lock:
            return sorted([p.to_dict() for p in self._ports.values()], key=lambda x: x["port"])

    def inject_port_open(self, port: int, process: str = "unknown") -> bool:
        """Attacker — leak a forbidden port."""
        with self._lock:
            rec = self._ports.get(port)
            if not rec:
                rec = PortRecord(port=port, forbidden=True)
                self._ports[port] = rec
            rec.sim_open = True
            rec.process = process
            return True

    def inject_port_close(self, port: int) -> bool:
        """Attacker — close an expected port (e.g., crash that listens)."""
        with self._lock:
            rec = self._ports.get(port)
            if not rec:
                return False
            rec.sim_open = False
            return True

    def close_port_action(self, port: int) -> bool:
        """Defender action — close a forbidden open port."""
        with self._lock:
            rec = self._ports.get(port)
            if not rec:
                return False
            rec.sim_open = False
            rec.real_open = False
            return True

    def clear_overlays(self) -> int:
        n = 0
        with self._lock:
            for link in self._links.values():
                if link.sim_status is not None:
                    link.sim_status = None
                    link.sim_reason = None
                    link.sim_until = None
                    n += 1
            for port in self._ports.values():
                if port.sim_open is not None:
                    port.sim_open = None
                    n += 1
        return n


# Singleton
network_state = NetworkState()
