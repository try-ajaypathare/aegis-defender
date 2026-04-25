"""
Network probe — pings gateway/internet/DNS, updates network_state.
"""
from __future__ import annotations

import socket
import subprocess
import threading
import time

from shared.config_loader import get_config
from shared.event_bus import bus
from shared.logger import get_logger
from shared.state import network_state
from shared.state.network_state import HEALTHY, DEGRADED, DOWN


log = get_logger("checks.network")


class NetworkProbeCheck:
    def __init__(self) -> None:
        self.cfg = get_config()
        self._stop = threading.Event()
        self._last_status: dict[str, str] = {}

    def _ping(self, host: str, timeout_s: float = 2.0) -> tuple[bool, float]:
        """Cross-platform ping; returns (ok, latency_ms)."""
        import platform
        param = "-n" if platform.system().lower() == "windows" else "-c"
        try:
            start = time.perf_counter()
            r = subprocess.run(
                ["ping", param, "1", "-w", str(int(timeout_s * 1000)), host],
                capture_output=True, timeout=timeout_s + 1, text=True,
            )
            elapsed = (time.perf_counter() - start) * 1000
            ok = r.returncode == 0
            return ok, elapsed
        except Exception:
            return False, 0.0

    def _resolve_dns(self, hostname: str, timeout_s: float = 2.0) -> bool:
        try:
            socket.setdefaulttimeout(timeout_s)
            socket.gethostbyname(hostname)
            return True
        except Exception:
            return False
        finally:
            socket.setdefaulttimeout(None)

    def _check_internet(self) -> None:
        ok_any = False
        latency_total = 0.0
        for target in self.cfg.network_health.internet_targets:
            ok, lat = self._ping(target)
            if ok:
                ok_any = True
                latency_total += lat
        avg = (latency_total / max(1, len(self.cfg.network_health.internet_targets))) if ok_any else 0
        status = HEALTHY if ok_any else DOWN
        network_state.update_link_probe("internet", status, avg)

    def _check_gateway(self) -> None:
        ok, lat = self._ping(self.cfg.network_health.gateway_ip)
        network_state.update_link_probe("gateway", HEALTHY if ok else DOWN, lat)

    def _check_dns(self) -> None:
        ok_count = 0
        for domain in self.cfg.network_health.dns_test_domains:
            if self._resolve_dns(domain):
                ok_count += 1
        if ok_count == 0:
            status = DOWN
        elif ok_count < len(self.cfg.network_health.dns_test_domains):
            status = DEGRADED
        else:
            status = HEALTHY
        network_state.update_link_probe("dns", status, 0)

    def _emit_status_changes(self) -> None:
        for link in network_state.all_links():
            name = link["name"]
            new_status = link["status"]
            old_status = self._last_status.get(name)
            if old_status is not None and old_status != new_status:
                level = "CRITICAL" if new_status == DOWN else ("WARNING" if new_status == DEGRADED else "INFO")
                bus.publish("event", {
                    "category": "network",
                    "level": level,
                    "message": f"Network link '{name}' → {new_status}",
                    "source": "network_probe",
                    "link": name,
                    "old_status": old_status,
                    "new_status": new_status,
                })
            self._last_status[name] = new_status

    def start(self) -> None:
        if not self.cfg.network_health.enabled:
            log.info("Network probe disabled in config")
            return

        # Register links
        network_state.register_link("internet", self.cfg.network_health.internet_targets[0])
        network_state.register_link("gateway", self.cfg.network_health.gateway_ip)
        network_state.register_link("dns", self.cfg.network_health.dns_test_domains[0])

        log.info(f"Network probe started — {self.cfg.network_health.probe_interval_seconds}s interval")

        while not self._stop.is_set():
            try:
                self._check_internet()
                self._check_gateway()
                self._check_dns()
                self._emit_status_changes()
            except Exception as e:
                log.error(f"Network probe error: {e}")
            self._stop.wait(self.cfg.network_health.probe_interval_seconds)

    def stop(self) -> None:
        self._stop.set()
