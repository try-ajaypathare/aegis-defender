"""
Network watcher.
Detects suspicious outbound connections (crypto-mining, C2).
"""
from __future__ import annotations

import ipaddress
import time
from typing import Any

import psutil

from shared.config_loader import get_config
from shared.event_bus import Topics, bus
from shared.logger import get_logger
from storage import database as db

log = get_logger("network-watcher")


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


class NetworkWatcher:
    def __init__(self) -> None:
        self.cfg = get_config()
        self.suspicious_ports = set(self.cfg.security.suspicious_ports)
        self.seen_connections: set[tuple] = set()
        self._running = False
        self._interval = 10

    def scan(self) -> list[dict]:
        found: list[dict] = []
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            log.debug("net_connections needs admin — skipping")
            return []

        for conn in connections:
            if not conn.raddr:
                continue  # only outbound

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port

            if _is_loopback(remote_ip):
                continue

            key = (conn.pid, remote_ip, remote_port)
            if key in self.seen_connections:
                continue
            self.seen_connections.add(key)

            proc_name = ""
            if conn.pid:
                try:
                    proc_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            is_suspicious, reason = self._evaluate(remote_ip, remote_port, proc_name)

            record: dict[str, Any] = {
                "pid": conn.pid,
                "process_name": proc_name,
                "local_address": conn.laddr.ip if conn.laddr else None,
                "local_port": conn.laddr.port if conn.laddr else None,
                "remote_address": remote_ip,
                "remote_port": remote_port,
                "status": conn.status,
                "is_suspicious": int(is_suspicious),
                "suspicious_reason": reason,
            }

            db.insert_network_connection(record)

            if is_suspicious:
                db.insert_event(
                    level="SECURITY",
                    category="network",
                    message=f"Suspicious connection: {proc_name} → {remote_ip}:{remote_port} ({reason})",
                    source="watcher",
                    metadata=record,
                )
                bus.publish(Topics.NETWORK_ALERT, record)
                log.warning(f"🌐 {proc_name} → {remote_ip}:{remote_port} — {reason}")
                found.append(record)

        # Keep seen set bounded
        if len(self.seen_connections) > 10000:
            self.seen_connections.clear()

        return found

    def _evaluate(
        self,
        remote_ip: str,
        remote_port: int,
        proc_name: str,
    ) -> tuple[bool, str | None]:
        if remote_port in self.suspicious_ports:
            return True, f"Port {remote_port} associated with mining/C2"

        # Uncommon high ports from non-browser processes
        if remote_port > 30000 and proc_name.lower() not in (
            "chrome.exe", "firefox.exe", "msedge.exe", "brave.exe",
            "opera.exe", "safari.exe", "vivaldi.exe",
        ):
            return True, f"High port {remote_port} from non-browser ({proc_name})"

        return False, None

    def start(self) -> None:
        if not self.cfg.security.network_watcher:
            log.info("Network watcher disabled")
            return
        log.info("Network watcher starting")
        self._running = True
        while self._running:
            try:
                self.scan()
            except Exception as e:  # noqa: BLE001
                log.error(f"Scan error: {e}")
            time.sleep(self._interval)

    def stop(self) -> None:
        self._running = False
