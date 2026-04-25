"""
Windows-specific helpers. No-ops on other platforms.
"""
from __future__ import annotations

import platform
import subprocess
from typing import Any

IS_WINDOWS = platform.system() == "Windows"


def is_admin() -> bool:
    if not IS_WINDOWS:
        import os
        return os.geteuid() == 0  # type: ignore[attr-defined]
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def get_boot_time() -> float:
    import psutil
    return psutil.boot_time()


def get_hostname() -> str:
    import socket
    return socket.gethostname()


def get_cpu_count() -> int:
    import psutil
    return psutil.cpu_count(logical=True) or 1


def list_startup_programs() -> list[dict[str, Any]]:
    """Read HKLM/HKCU Run keys for persistence detection."""
    if not IS_WINDOWS:
        return []
    try:
        import winreg  # type: ignore
    except ImportError:
        return []

    entries: list[dict[str, Any]] = []
    locations = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ]

    for hive, path in locations:
        try:
            with winreg.OpenKey(hive, path) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        entries.append({
                            "hive": "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU",
                            "key": path,
                            "name": name,
                            "value": str(value),
                        })
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            continue
        except Exception:
            continue

    return entries


def list_drives() -> list[str]:
    """Return list of drive letters currently mounted."""
    if not IS_WINDOWS:
        return []
    import psutil
    return [p.device for p in psutil.disk_partitions(all=False)]


def check_signature(file_path: str) -> bool:
    """Best-effort: check if executable is signed (uses PowerShell)."""
    if not IS_WINDOWS:
        return True
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-AuthenticodeSignature -FilePath '{file_path}').Status"],
            capture_output=True, text=True, timeout=5,
        )
        return "Valid" in result.stdout
    except Exception:
        return False
