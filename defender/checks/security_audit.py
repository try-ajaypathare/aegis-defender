"""
Security audit — periodic scan of auth log, certs, ports.

For Phase 1 this is a minimal stub that registers state from config and
performs basic threshold checks. Full brute-force pattern detection
arrives in Phase 2.
"""
from __future__ import annotations

import threading
import time

from shared.config_loader import get_config
from shared.event_bus import bus
from shared.logger import get_logger
from shared.state import auth_state, cert_state, network_state


log = get_logger("checks.security")


class SecurityAuditCheck:
    def __init__(self) -> None:
        self.cfg = get_config()
        self._stop = threading.Event()
        self._cert_warn_state: dict[str, str] = {}   # domain -> last warning level

    def _check_brute_force(self) -> None:
        """Scan auth log for IPs with too many failures."""
        threshold = self.cfg.security_audit.ssh_brute_force.block_threshold_failures
        window = self.cfg.security_audit.ssh_brute_force.track_window_minutes * 60
        failed_by_ip = auth_state.failed_by_ip(window)
        for ip, count in failed_by_ip.items():
            if count >= threshold:
                threat = next((t for t in auth_state.all_threats() if t["ip"] == ip), None)
                if threat and not threat.get("blocked"):
                    bus.publish("event", {
                        "category": "security",
                        "level": "WARNING",
                        "message": f"Brute force detected: {ip} — {count} failures in last {window//60}m",
                        "source": "security_audit",
                        "ip": ip,
                        "failures": count,
                    })

    def _check_certs(self) -> None:
        warn_days = self.cfg.thresholds.cert_days_to_expiry.warning
        crit_days = self.cfg.thresholds.cert_days_to_expiry.critical
        for cert in cert_state.all():
            days = cert.days_to_expiry()
            level = "ok"
            if days <= crit_days:
                level = "critical"
            elif days <= warn_days:
                level = "warning"
            prev = self._cert_warn_state.get(cert.domain, "ok")
            if level != prev and level != "ok":
                bus.publish("event", {
                    "category": "security",
                    "level": level.upper(),
                    "message": f"SSL cert {cert.domain} expires in {round(days, 1)} days",
                    "source": "security_audit",
                    "domain": cert.domain,
                    "days_to_expiry": round(days, 2),
                })
            self._cert_warn_state[cert.domain] = level

    def _check_ports(self) -> None:
        for port in network_state.all_ports():
            if port["severity"] == "critical":
                bus.publish("event", {
                    "category": "security",
                    "level": "CRITICAL",
                    "message": f"Forbidden port {port['port']} is OPEN ({port.get('process') or 'unknown'})",
                    "source": "security_audit",
                    "port": port["port"],
                })

    def start(self) -> None:
        if not self.cfg.security_audit.enabled:
            log.info("Security audit disabled in config")
            return

        # Register state
        cert_state.register_from_config(self.cfg.security_audit.cert_check.monitored_domains)
        network_state.register_ports(
            self.cfg.security_audit.port_audit.expected_open_ports,
            self.cfg.security_audit.port_audit.forbidden_ports,
        )
        log.info(f"Security audit started — {self.cfg.security_audit.audit_interval_seconds}s interval")

        while not self._stop.is_set():
            try:
                self._check_brute_force()
                self._check_certs()
                self._check_ports()
            except Exception as e:
                log.error(f"Security audit error: {e}")
            self._stop.wait(self.cfg.security_audit.audit_interval_seconds)

    def stop(self) -> None:
        self._stop.set()
