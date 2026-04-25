"""
Process genealogy watcher.
Tracks parent-child process relationships; flags suspicious chains.

Detects classic attack patterns like:
  explorer.exe → cmd.exe → powershell.exe  (LOLBin chain)
  winword.exe → cmd.exe                    (macro execution)
  excel.exe → powershell.exe               (macro → PS)
"""
from __future__ import annotations

import time
from typing import Any

import psutil

from shared.config_loader import get_config
from shared.event_bus import Topics, bus
from shared.logger import get_logger
from storage import database as db

log = get_logger("proc-genealogy")


SUSPICIOUS_PATH_HINTS = [
    r"\\temp\\", r"\\tmp\\", r"\\downloads\\",
    r"\\appdata\\local\\temp\\",
    r"\\users\\public\\",
]


def _is_high_entropy_name(name: str) -> bool:
    """
    Detect random-looking filenames like '8f3k2p9xq7r1m4n6.exe'.
    Conservative: only flags names that look truly random.
    """
    base = name.rsplit(".", 1)[0]
    if len(base) < 12:
        return False

    # Separators (hyphen, underscore, dot) → real product names, not random
    if any(sep in base for sep in ("-", "_", ".")):
        return False

    # CamelCase transitions → legitimate service naming
    transitions = sum(1 for i in range(1, len(base))
                      if base[i-1].islower() and base[i].isupper())
    if transitions >= 1:
        return False

    # Count digits — random names have heavy digit mixing (>30%)
    digits = sum(1 for c in base if c.isdigit())
    digit_ratio = digits / len(base)
    if digit_ratio < 0.3:
        return False

    # Count vowels — random names have almost none (<15%)
    vowels = sum(1 for c in base.lower() if c in "aeiou")
    alphas = sum(1 for c in base if c.isalpha())
    if alphas > 0 and (vowels / alphas) > 0.2:
        return False

    return True


class ProcessGenealogyWatcher:
    def __init__(self) -> None:
        self.cfg = get_config()
        self.known_pids: set[int] = set()
        self.suspicious_chains = [
            tuple(c) for c in self.cfg.security.suspicious_chains
        ]
        self._running = False
        self._interval = 5
        self._warmup = True  # First scan just populates known_pids

    def scan(self) -> list[dict]:
        """Scan for new processes. Returns list of new records."""
        current_pids: set[int] = set()
        new_records: list[dict] = []

        # First pass: just snapshot existing processes; don't flag anything
        if self._warmup:
            for p in psutil.process_iter(["pid"]):
                try:
                    current_pids.add(p.info["pid"])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            self.known_pids = current_pids
            self._warmup = False
            log.info(f"Genealogy warmup: {len(self.known_pids)} existing processes snapshotted")
            return []

        for p in psutil.process_iter(["pid", "name", "ppid", "cmdline", "exe"]):
            try:
                pid = p.info["pid"]
                current_pids.add(pid)
                if pid in self.known_pids:
                    continue

                parent_name = ""
                try:
                    parent = psutil.Process(p.info["ppid"]) if p.info["ppid"] else None
                    parent_name = parent.name() if parent else ""
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                cmdline = " ".join(p.info.get("cmdline") or [])
                exe_path = p.info.get("exe") or ""
                name = p.info.get("name") or ""

                is_suspicious, reason = self._evaluate(
                    name=name,
                    parent_name=parent_name,
                    exe_path=exe_path,
                    cmdline=cmdline,
                )

                record = {
                    "pid": pid,
                    "parent_pid": p.info.get("ppid"),
                    "process_name": name,
                    "parent_name": parent_name,
                    "cmdline": cmdline[:500],
                    "is_suspicious": int(is_suspicious),
                    "suspicious_reason": reason,
                }

                db.insert_genealogy(record)
                new_records.append(record)

                if is_suspicious:
                    db.insert_event(
                        level="SECURITY",
                        category="security",
                        message=f"Suspicious process: {name} (parent: {parent_name}) — {reason}",
                        source="watcher",
                        metadata={"pid": pid, "parent_pid": p.info.get("ppid")},
                    )
                    bus.publish(Topics.PROCESS_SUSPICIOUS, record)
                    log.warning(f"⚠️ Suspicious: {parent_name} → {name} :: {reason}")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        self.known_pids = current_pids
        return new_records

    def _evaluate(
        self,
        name: str,
        parent_name: str,
        exe_path: str,
        cmdline: str,
    ) -> tuple[bool, str | None]:
        """Return (is_suspicious, reason)."""
        name_lower = name.lower()
        parent_lower = parent_name.lower()
        path_lower = exe_path.lower()
        cmd_lower = cmdline.lower()

        # Chain check
        for chain in self.suspicious_chains:
            if len(chain) >= 2:
                if (parent_lower == chain[-2].lower()
                        and name_lower == chain[-1].lower()):
                    return True, f"Chain: {' → '.join(chain)}"

        # Executable running from suspicious path
        for hint in SUSPICIOUS_PATH_HINTS:
            if hint in path_lower:
                return True, f"Executable running from {hint.strip(chr(92))}"

        # High entropy filename
        if _is_high_entropy_name(name):
            return True, "High-entropy filename (possible malware)"

        # PowerShell with encoded command
        if name_lower in ("powershell.exe", "pwsh.exe"):
            if "-enc" in cmd_lower or "-encodedcommand" in cmd_lower:
                return True, "PowerShell with encoded command"
            if "downloadstring" in cmd_lower or "invoke-webrequest" in cmd_lower:
                return True, "PowerShell downloading remote content"
            if "-nop" in cmd_lower and "-w hidden" in cmd_lower:
                return True, "PowerShell hidden execution"

        # cmd launched by office apps
        if name_lower in ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"):
            if parent_lower in ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"):
                return True, f"Office app ({parent_name}) spawned {name}"

        # Known LOLBins with suspicious args
        if name_lower == "rundll32.exe" and ("javascript:" in cmd_lower or "url.dll" in cmd_lower):
            return True, "rundll32 with suspicious args"

        if name_lower == "regsvr32.exe" and ("/i:http" in cmd_lower or "scrobj.dll" in cmd_lower):
            return True, "regsvr32 remote script (Squiblydoo)"

        return False, None

    def start(self) -> None:
        if not self.cfg.security.process_genealogy:
            log.info("Process genealogy disabled in config")
            return
        log.info("Process genealogy watcher starting")
        self._running = True
        while self._running:
            try:
                self.scan()
            except Exception as e:  # noqa: BLE001
                log.error(f"Scan error: {e}")
            time.sleep(self._interval)

    def stop(self) -> None:
        self._running = False
