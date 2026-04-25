"""
USB device monitor — tracks drive plug/unplug.
"""
from __future__ import annotations

import time

from shared.config_loader import get_config
from shared.event_bus import Topics, bus
from shared.logger import get_logger
from shared.windows_helper import IS_WINDOWS, list_drives
from storage import database as db

log = get_logger("usb-monitor")


class USBMonitor:
    def __init__(self) -> None:
        self.cfg = get_config()
        self._known_drives: set[str] = set()
        self._running = False
        self._interval = 5

    def scan(self) -> None:
        current = set(list_drives())
        added = current - self._known_drives
        removed = self._known_drives - current

        for drive in added:
            db._connect()  # ensure DB is open
            with db.cursor() as cur:
                cur.execute(
                    "INSERT INTO usb_events (event_type, drive_letter) VALUES (?, ?)",
                    ("connected", drive),
                )
            bus.publish(Topics.USB_EVENT, {"type": "connected", "drive": drive})
            log.info(f"🔌 USB/Drive connected: {drive}")

        for drive in removed:
            with db.cursor() as cur:
                cur.execute(
                    "INSERT INTO usb_events (event_type, drive_letter) VALUES (?, ?)",
                    ("disconnected", drive),
                )
            bus.publish(Topics.USB_EVENT, {"type": "disconnected", "drive": drive})
            log.info(f"🔌 USB/Drive disconnected: {drive}")

        self._known_drives = current

    def start(self) -> None:
        if not self.cfg.security.usb_monitor or not IS_WINDOWS:
            log.info("USB monitor disabled or non-Windows")
            return
        self._known_drives = set(list_drives())
        self._running = True
        log.info("USB monitor started")
        while self._running:
            try:
                self.scan()
            except Exception as e:  # noqa: BLE001
                log.error(f"USB scan error: {e}")
            time.sleep(self._interval)

    def stop(self) -> None:
        self._running = False
