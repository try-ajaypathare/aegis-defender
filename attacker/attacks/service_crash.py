"""
Service crash attack — flips a configured service into 'down' or 'degraded'
state via simulation overlay. Real services (XAMPP Apache/MySQL) are NEVER
actually stopped.
"""
from __future__ import annotations

import time

from attacker.base_attack import BaseAttack
from shared.event_bus import Topics, bus
from shared.logger import get_logger
from shared.state import service_state


log = get_logger("attack.service_crash")


class ServiceCrashAttack(BaseAttack):
    name = "service_crash"
    category = "service"
    description = "Crash a monitored service (Apache/MySQL/Redis/App). Pure simulation overlay — actual service untouched."

    DEFAULTS = {
        "service_id": "apache",        # which service to crash
        "mode": "crash",               # "crash" | "degrade" | "latency"
        "duration": 120,
        "extra_latency_ms": 800,       # only for mode=latency
    }

    def _run(self) -> None:
        sid = self.params.get("service_id", self.DEFAULTS["service_id"])
        mode = self.params.get("mode", self.DEFAULTS["mode"])
        duration = int(self.params.get("duration", self.DEFAULTS["duration"]))
        extra_ms = float(self.params.get("extra_latency_ms", self.DEFAULTS["extra_latency_ms"]))

        rec = service_state.get(sid)
        if not rec:
            log.warning(f"Unknown service_id '{sid}' — attack aborted")
            self.stop(stopped_by="invalid_target")
            return

        # Apply simulation overlay
        if mode == "crash":
            ok = service_state.inject_crash(sid, reason=f"sim:{self.name}", duration_s=duration)
            human = f"{rec.name} CRASHED"
        elif mode == "degrade":
            ok = service_state.inject_degraded(sid, reason=f"sim:{self.name}", duration_s=duration)
            human = f"{rec.name} DEGRADED"
        elif mode == "latency":
            ok = service_state.inject_latency(sid, extra_ms=extra_ms, duration_s=duration)
            human = f"{rec.name} latency +{int(extra_ms)}ms"
        else:
            log.warning(f"Unknown mode '{mode}'")
            self.stop(stopped_by="invalid_mode")
            return

        if not ok:
            self.stop(stopped_by="overlay_failed")
            return

        bus.publish("event", {
            "category": "service",
            "level": "CRITICAL" if mode == "crash" else "WARNING",
            "message": f"Service incident: {human}",
            "source": self.name,
            "service_id": sid,
            "mode": mode,
        })
        log.info(f"[SIM] {human} ({sid}) for {duration}s")

        # Spin until duration or stop
        while self.is_running and self._check_safety():
            # If overlay self-cleared (sim_until passed), stop attack
            r = service_state.get(sid)
            if r and not r.is_simulated():
                log.info(f"[SIM] Service {sid} overlay auto-cleared")
                break
            time.sleep(0.5)

    def cleanup(self) -> None:
        sid = self.params.get("service_id", self.DEFAULTS["service_id"])
        # Don't auto-clear here — defender's restart_service action does that
        # when AI/rules decides. Just log for transparency.
        log.info(f"Service crash attack ended for {sid} (overlay may persist if duration not elapsed)")
