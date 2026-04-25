"""
Service health prober — runs periodically, hits configured services
via HTTP/TCP, updates ServiceState, publishes status_change events.

Probes are best-effort and never raise; failures get recorded as DOWN.
For services marked simulated_only, real probe is skipped and the service
shows whatever the simulation overlay says (or UP by default).
"""
from __future__ import annotations

import socket
import threading
import time
from typing import Optional

import requests

from shared.config_loader import get_config, MonitoredService
from shared.event_bus import bus
from shared.logger import get_logger
from shared.state import service_state
from shared.state.service_state import STATUS_UP, STATUS_DOWN, STATUS_DEGRADED


log = get_logger("checks.service")


class ServiceHealthCheck:
    """Periodic prober for configured services."""

    def __init__(self) -> None:
        self.cfg = get_config()
        self._stop = threading.Event()
        self._last_eff_status: dict[str, str] = {}

    # ---- probes ----

    def _probe_http(self, svc: MonitoredService) -> tuple[str, float, Optional[str]]:
        url = svc.probe_url or f"http://{svc.host or '127.0.0.1'}:{svc.port}/"
        start = time.perf_counter()
        try:
            r = requests.get(url, timeout=svc.timeout_seconds, allow_redirects=False)
            elapsed_ms = (time.perf_counter() - start) * 1000
            if 200 <= r.status_code < 400:
                # Latency-based degradation
                if elapsed_ms > self.cfg.thresholds.service_latency_ms.critical:
                    return STATUS_DEGRADED, elapsed_ms, f"high_latency_{int(elapsed_ms)}ms"
                return STATUS_UP, elapsed_ms, None
            return STATUS_DOWN, elapsed_ms, f"http_{r.status_code}"
        except requests.exceptions.ConnectTimeout:
            return STATUS_DOWN, svc.timeout_seconds * 1000, "connect_timeout"
        except requests.exceptions.ConnectionError:
            return STATUS_DOWN, 0.0, "connection_refused"
        except requests.exceptions.ReadTimeout:
            return STATUS_DOWN, svc.timeout_seconds * 1000, "read_timeout"
        except Exception as e:
            return STATUS_DOWN, 0.0, f"error: {type(e).__name__}"

    def _probe_tcp(self, svc: MonitoredService) -> tuple[str, float, Optional[str]]:
        host = svc.host or "127.0.0.1"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(svc.timeout_seconds)
        start = time.perf_counter()
        try:
            sock.connect((host, svc.port))
            elapsed_ms = (time.perf_counter() - start) * 1000
            sock.close()
            return STATUS_UP, elapsed_ms, None
        except socket.timeout:
            return STATUS_DOWN, svc.timeout_seconds * 1000, "tcp_timeout"
        except ConnectionRefusedError:
            return STATUS_DOWN, 0.0, "connection_refused"
        except OSError as e:
            return STATUS_DOWN, 0.0, f"os_error: {e}"
        except Exception as e:
            return STATUS_DOWN, 0.0, f"error: {type(e).__name__}"
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _probe_one(self, svc: MonitoredService) -> None:
        if svc.simulated_only:
            # Synthetic baseline — pretend service is healthy with random tiny latency
            import random
            service_state.update_probe(svc.id, STATUS_UP, random.uniform(2, 25), None)
            return

        if svc.type == "http":
            status, latency_ms, err = self._probe_http(svc)
        elif svc.type == "tcp":
            status, latency_ms, err = self._probe_tcp(svc)
        else:
            log.warning(f"Unknown probe type '{svc.type}' for {svc.id}")
            return

        service_state.update_probe(svc.id, status, latency_ms, err)

        # Publish status change event
        rec = service_state.get(svc.id)
        if not rec:
            return
        new_eff = rec.effective_status()
        old_eff = self._last_eff_status.get(svc.id)
        if old_eff is not None and old_eff != new_eff:
            severity = "critical" if new_eff == STATUS_DOWN else ("warning" if new_eff == STATUS_DEGRADED else "info")
            bus.publish("event", {
                "category": "service",
                "level": severity.upper(),
                "message": f"{svc.name} → {new_eff}" + (f" ({err})" if err else ""),
                "source": "service_health",
                "service_id": svc.id,
                "old_status": old_eff,
                "new_status": new_eff,
            })
        self._last_eff_status[svc.id] = new_eff

    # ---- thread loop ----

    def start(self) -> None:
        if not self.cfg.services.enabled:
            log.info("Service health check disabled in config")
            return

        # Register configured services
        service_state.register_from_config(self.cfg.services.monitored)

        log.info(f"Service health check started — {len(self.cfg.services.monitored)} services, "
                 f"{self.cfg.services.probe_interval_seconds}s interval")

        # First pass immediately, then loop
        for svc in self.cfg.services.monitored:
            try:
                self._probe_one(svc)
            except Exception as e:
                log.error(f"Probe error {svc.id}: {e}")

        while not self._stop.is_set():
            self._stop.wait(self.cfg.services.probe_interval_seconds)
            if self._stop.is_set():
                break
            for svc in self.cfg.services.monitored:
                try:
                    self._probe_one(svc)
                except Exception as e:
                    log.error(f"Probe error {svc.id}: {e}")

    def stop(self) -> None:
        self._stop.set()
