"""
Registry watcher — tracks Windows Run keys for persistence detection.
"""
from __future__ import annotations

import time

from shared.config_loader import get_config
from shared.event_bus import Topics, bus
from shared.logger import get_logger
from shared.windows_helper import IS_WINDOWS, list_startup_programs
from storage import database as db

log = get_logger("registry-watcher")


class RegistryWatcher:
    def __init__(self) -> None:
        self.cfg = get_config()
        self._baseline: dict[str, dict] = {}
        self._running = False
        self._interval = 60  # check every minute

    def _snapshot_key(self, entries: list[dict]) -> dict[str, dict]:
        return {f"{e['hive']}\\{e['key']}\\{e['name']}": e for e in entries}

    def build_baseline(self) -> None:
        if not IS_WINDOWS:
            log.info("Registry watcher requires Windows")
            return
        entries = list_startup_programs()
        self._baseline = self._snapshot_key(entries)
        log.info(f"Registry baseline: {len(self._baseline)} startup entries")

    def check(self) -> list[dict]:
        if not IS_WINDOWS:
            return []

        current = self._snapshot_key(list_startup_programs())
        changes: list[dict] = []

        # New entries
        for key, entry in current.items():
            if key not in self._baseline:
                changes.append({
                    "registry_key": f"{entry['hive']}\\{entry['key']}",
                    "value_name": entry["name"],
                    "value_data": entry["value"],
                    "change_type": "added",
                })
            elif self._baseline[key]["value"] != entry["value"]:
                changes.append({
                    "registry_key": f"{entry['hive']}\\{entry['key']}",
                    "value_name": entry["name"],
                    "value_data": entry["value"],
                    "change_type": "modified",
                })

        # Removed entries
        for key, entry in self._baseline.items():
            if key not in current:
                changes.append({
                    "registry_key": f"{entry['hive']}\\{entry['key']}",
                    "value_name": entry["name"],
                    "value_data": entry["value"],
                    "change_type": "removed",
                })

        for c in changes:
            db.insert_event(
                level="SECURITY",
                category="registry",
                message=f"Registry {c['change_type']}: {c['value_name']} = {c['value_data']}",
                source="watcher",
                metadata=c,
            )
            bus.publish(Topics.SECURITY_ALERT, c)
            log.warning(f"🔑 Registry {c['change_type']}: {c['value_name']}")

        self._baseline = current
        return changes

    def start(self) -> None:
        if not self.cfg.security.registry_watcher or not IS_WINDOWS:
            log.info("Registry watcher disabled or non-Windows")
            return

        self.build_baseline()
        self._running = True
        while self._running:
            time.sleep(self._interval)
            try:
                self.check()
            except Exception as e:  # noqa: BLE001
                log.error(f"Registry check error: {e}")

    def stop(self) -> None:
        self._running = False
