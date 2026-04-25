"""
Defense Mode — toggle between rule-based, AI-driven, and hybrid response.

Three modes:
  AUTO   : Pure rule engine. Deterministic, fast, free. No LLM calls.
  AI     : LLM picks every action. Smart but slow + costs API quota.
  HYBRID : Rule engine decides + LLM verifies/escalates uncertain cases. (default)
"""
from __future__ import annotations

import threading
import time
from enum import Enum


class DefenseMode(str, Enum):
    AUTO = "auto"      # rules only, no LLM at all
    AI = "ai"          # LLM picks every action
    HYBRID = "hybrid"  # rules + LLM verify + auto-investigate


MODE_DESCRIPTIONS = {
    DefenseMode.AUTO:
        "Rule-based only. Risk score → action. Fast, predictable, no API cost.",
    DefenseMode.AI:
        "AI picks every action. LLM analyzes each threat and chooses response.",
    DefenseMode.HYBRID:
        "Rules decide + AI verifies + auto-investigation. Best for production.",
}


class DefenseModeState:
    """Thread-safe global mode state with disk persistence."""

    def __init__(self) -> None:
        # Restore from disk if available
        from storage import persistence
        saved = persistence.get("defense_mode", "hybrid")
        try:
            self._mode = DefenseMode(saved)
        except ValueError:
            self._mode = DefenseMode.HYBRID
        self._lock = threading.Lock()
        self._changed_at: float = time.time()
        self._change_count: int = 0

    @property
    def mode(self) -> DefenseMode:
        with self._lock:
            return self._mode

    def set(self, mode: str | DefenseMode) -> DefenseMode:
        if isinstance(mode, str):
            mode = DefenseMode(mode.lower())
        with self._lock:
            self._mode = mode
            self._changed_at = time.time()
            self._change_count += 1
        # Persist
        from storage import persistence
        persistence.update("defense_mode", mode.value)
        return mode

    def is_auto(self) -> bool:
        return self.mode == DefenseMode.AUTO

    def is_ai(self) -> bool:
        return self.mode == DefenseMode.AI

    def is_hybrid(self) -> bool:
        return self.mode == DefenseMode.HYBRID

    def llm_enabled(self) -> bool:
        """LLM advisor/verify/investigate are allowed."""
        return self.mode in (DefenseMode.AI, DefenseMode.HYBRID)

    def state_dict(self) -> dict:
        with self._lock:
            return {
                "mode": self._mode.value,
                "description": MODE_DESCRIPTIONS[self._mode],
                "changed_at": self._changed_at,
                "change_count": self._change_count,
                "available_modes": [
                    {"value": m.value, "description": MODE_DESCRIPTIONS[m]}
                    for m in DefenseMode
                ],
            }


# Global singleton
state = DefenseModeState()
