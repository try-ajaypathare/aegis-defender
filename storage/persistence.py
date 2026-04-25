"""
Lightweight JSON-based persistence for runtime state.
Survives restarts: defense mode, trust list, custom rules.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

STATE_FILE = Path(__file__).resolve().parent / "runtime_state.json"
_lock = threading.Lock()


def load() -> dict[str, Any]:
    if not STATE_FILE.exists():
        return {}
    try:
        with _lock, open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def save(data: dict[str, Any]) -> None:
    try:
        with _lock, open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def update(key: str, value: Any) -> None:
    """Read-modify-write a single key."""
    state = load()
    state[key] = value
    save(state)


def get(key: str, default: Any = None) -> Any:
    return load().get(key, default)
