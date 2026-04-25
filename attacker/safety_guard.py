"""
Safety guard — global kill switch and active-attack registry.
"""
from __future__ import annotations

import threading
from typing import Any

from shared.config_loader import get_config
from shared.logger import get_logger
from shared.notifier import notify

log = get_logger("safety-guard")


class SafetyGuard:
    def __init__(self) -> None:
        self.cfg = get_config()
        self._active: dict[str, Any] = {}
        self._lock = threading.Lock()
        self._hotkey_listener = None

    # ---------- Registry ----------

    def register(self, attack) -> None:
        with self._lock:
            self._active[attack.id] = attack

    def unregister(self, attack_id: str) -> None:
        with self._lock:
            self._active.pop(attack_id, None)

    def get(self, attack_id: str):
        return self._active.get(attack_id)

    def list_active(self) -> list[dict]:
        with self._lock:
            return [a.status() for a in self._active.values() if a.is_running]

    # ---------- Kill switch ----------

    def stop_all(self, reason: str = "kill_switch") -> int:
        count = 0
        with self._lock:
            attacks = list(self._active.values())
        for a in attacks:
            try:
                if a.is_running:
                    a.stop(stopped_by=reason)
                    count += 1
            except Exception as e:  # noqa: BLE001
                log.error(f"Failed to stop {a.name}: {e}")
        with self._lock:
            self._active.clear()

        if count > 0:
            notify(
                "Argus: Kill Switch",
                f"Stopped {count} active attack(s)",
                level="warning",
            )
            log.warning(f"🛑 KILL SWITCH — stopped {count} attacks")
        return count

    # ---------- Hotkey ----------

    def start_hotkey_listener(self) -> None:
        """Register global hotkey (Ctrl+Shift+Q by default)."""
        try:
            from pynput import keyboard  # type: ignore
        except ImportError:
            log.info("pynput not installed — hotkey disabled")
            return

        combo_str = self.cfg.attacks.kill_switch_hotkey
        # Parse "ctrl+shift+q"
        parts = combo_str.lower().split("+")
        key_map = {
            "ctrl": keyboard.Key.ctrl,
            "shift": keyboard.Key.shift,
            "alt": keyboard.Key.alt,
            "cmd": keyboard.Key.cmd,
        }
        target_keys = set()
        for p in parts:
            if p in key_map:
                target_keys.add(key_map[p])
            else:
                target_keys.add(keyboard.KeyCode.from_char(p))

        pressed: set = set()

        def on_press(key):
            pressed.add(key)
            if target_keys.issubset(pressed):
                self.stop_all("hotkey")

        def on_release(key):
            pressed.discard(key)

        listener = keyboard.Listener(on_press=on_press, on_release=on_release, daemon=True)
        listener.start()
        self._hotkey_listener = listener
        log.info(f"Hotkey listener started ({combo_str})")


# Global singleton
guard = SafetyGuard()
