"""
Base class for all attacks — SIMULATION MODE ONLY.

Attacks DO NOT consume real system resources. They register their claimed
impact with the SimulationEngine; the monitor adds it to real baseline metrics
to create the illusion of system stress for testing defender logic.

Real hardware is never harmed.
"""
from __future__ import annotations

import os
import threading
import time
import uuid
from typing import Any

from shared.config_loader import get_config
from shared.event_bus import Topics, bus
from shared.logger import get_logger
from shared.simulation import SimulatedImpact, engine as sim_engine
from storage import database as db

log = get_logger("attack")


class BaseAttack:
    """Parent class. Pure simulation — no real resource use."""

    name: str = "base"
    category: str = "generic"
    description: str = ""

    def __init__(self, params: dict | None = None) -> None:
        self.params = params or {}
        self.cfg = get_config()
        self.id = str(uuid.uuid4())
        self.is_running = False
        self.start_time: float | None = None
        self.thread: threading.Thread | None = None
        self._db_id: int | None = None
        self._impact: SimulatedImpact | None = None

        requested = int(self.params.get("duration", 60))
        self.max_duration = min(requested, self.cfg.attacks.max_duration_seconds)

    # ---------- Lifecycle ----------

    def start(self) -> bool:
        if self.is_running:
            return False

        self.is_running = True
        self.start_time = time.time()

        self._db_id = db.insert_attack_start(
            attack_type=self.name,
            parameters=self.params,
            pid=os.getpid(),
        )

        self.thread = threading.Thread(target=self._guarded_run, daemon=True)
        self.thread.start()

        bus.publish(Topics.ATTACK_STARTED, {
            "id": self.id,
            "db_id": self._db_id,
            "name": self.name,
            "category": self.category,
            "params": self.params,
            "start_time": self.start_time,
            "simulated": True,
        })
        log.info(f"[SIM] Attack started: {self.name} ({self.params})")
        return True

    def stop(self, stopped_by: str = "user") -> None:
        if not self.is_running:
            return
        self.is_running = False

        duration = int(time.time() - (self.start_time or time.time()))

        # Remove simulation impact
        if self._impact:
            sim_engine.unregister(self.id)

        try:
            self.cleanup()
        except Exception as e:  # noqa: BLE001
            log.error(f"Cleanup failed for {self.name}: {e}")

        if self._db_id is not None:
            db.update_attack_stop(self._db_id, duration, stopped_by)

        bus.publish(Topics.ATTACK_STOPPED, {
            "id": self.id,
            "name": self.name,
            "duration": duration,
            "stopped_by": stopped_by,
        })
        log.info(f"[SIM] Attack stopped: {self.name} (reason={stopped_by}, {duration}s)")

    # ---------- Simulation helpers ----------

    def register_impact(self, **kwargs: Any) -> SimulatedImpact:
        """Register this attack's simulated impact. kwargs match SimulatedImpact fields."""
        impact = SimulatedImpact(
            attack_id=self.id,
            attack_name=self.name,
            **kwargs,
        )
        sim_engine.register(impact)
        self._impact = impact
        return impact

    def update_impact(self, **kwargs: Any) -> None:
        """Update ongoing impact (e.g., for ramp-up changes)."""
        if not self._impact:
            return
        for k, v in kwargs.items():
            if hasattr(self._impact, k):
                setattr(self._impact, k, v)

    # ---------- Override in subclasses ----------

    def _run(self) -> None:
        """
        Override in subclasses. Typically:
          1. self.register_impact(cpu_percent=X, memory_mb=Y, ...)
          2. while self.is_running and self._check_safety(): time.sleep(0.5)
        """
        raise NotImplementedError

    def cleanup(self) -> None:
        """Override if attack needs custom cleanup. Simulation is auto-cleaned."""
        pass

    # ---------- Internals ----------

    def _guarded_run(self) -> None:
        try:
            self._run()
        except Exception as e:  # noqa: BLE001
            log.error(f"Attack {self.name} crashed: {e}")
            self.stop(stopped_by="error")

    def _check_safety(self) -> bool:
        if self.start_time is None:
            return True
        if time.time() - self.start_time > self.max_duration:
            self.stop(stopped_by="timeout")
            return False
        return self.is_running

    def status(self) -> dict[str, Any]:
        duration = int(time.time() - self.start_time) if self.start_time else 0
        return {
            "id": self.id,
            "db_id": self._db_id,
            "name": self.name,
            "category": self.category,
            "is_running": self.is_running,
            "duration": duration,
            "max_duration": self.max_duration,
            "params": self.params,
            "simulated": True,
        }
