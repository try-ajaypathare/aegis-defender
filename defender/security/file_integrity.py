"""
File integrity monitor.
Tracks SHA256 hashes of files in watched folders. Flags changes.
"""
from __future__ import annotations

import hashlib
import time
from datetime import datetime
from pathlib import Path

from shared.config_loader import get_config
from shared.event_bus import Topics, bus
from shared.logger import get_logger
from storage import database as db

log = get_logger("file-integrity")


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


class FileIntegrityMonitor:
    def __init__(self) -> None:
        self.cfg = get_config()
        self.folders = self.cfg.security.watched_folders
        self._baseline: dict[str, dict] = {}  # path -> {hash, size, mtime}
        self._running = False
        self._interval = 300  # 5 min

    def build_baseline(self) -> None:
        log.info(f"Building file integrity baseline for {len(self.folders)} folders")
        count = 0
        for folder in self.folders:
            folder_path = Path(folder)
            if not folder_path.exists():
                continue
            for item in folder_path.rglob("*"):
                try:
                    if item.is_file():
                        h = sha256_of(item)
                        if h:
                            self._baseline[str(item)] = {
                                "hash": h,
                                "size": item.stat().st_size,
                                "mtime": item.stat().st_mtime,
                            }
                            count += 1
                except (PermissionError, OSError):
                    continue
        log.info(f"Baseline built: {count} files tracked")

    def check(self) -> list[dict]:
        changes: list[dict] = []
        for path_str, baseline in self._baseline.items():
            path = Path(path_str)
            if not path.exists():
                changes.append({
                    "path": path_str,
                    "change": "deleted",
                    "severity": "critical",
                })
                continue

            try:
                current_size = path.stat().st_size
                current_mtime = path.stat().st_mtime
                if current_size != baseline["size"] or current_mtime != baseline["mtime"]:
                    new_hash = sha256_of(path)
                    if new_hash and new_hash != baseline["hash"]:
                        changes.append({
                            "path": path_str,
                            "change": "modified",
                            "old_hash": baseline["hash"],
                            "new_hash": new_hash,
                            "severity": "critical",
                        })
                        baseline["hash"] = new_hash
                        baseline["size"] = current_size
                        baseline["mtime"] = current_mtime
            except (PermissionError, OSError):
                continue

        for c in changes:
            db.insert_event(
                level="SECURITY",
                category="file_integrity",
                message=f"File {c['change']}: {c['path']}",
                source="watcher",
                metadata=c,
            )
            bus.publish(Topics.SECURITY_ALERT, c)
            log.warning(f"🗂️ File {c['change']}: {c['path']}")

        return changes

    def start(self) -> None:
        if not self.cfg.security.file_integrity:
            log.info("File integrity monitor disabled")
            return
        if not self.folders:
            log.info("No watched folders configured")
            return

        self.build_baseline()
        self._running = True
        log.info(f"File integrity monitor running (check every {self._interval}s)")

        while self._running:
            time.sleep(self._interval)
            try:
                self.check()
            except Exception as e:  # noqa: BLE001
                log.error(f"Integrity check error: {e}")

    def stop(self) -> None:
        self._running = False
