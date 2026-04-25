"""
Rules engine — BASELINE-AWARE + DELTA-BASED.

Instead of firing on absolute thresholds (which trigger constantly when a
system baseline is already high), this engine:

1. Learns a baseline over the first BASELINE_SAMPLES metrics.
2. Fires warnings/critical when metrics deviate from baseline by N percentage
   points (delta triggers), OR when a simulated attack is active and metrics
   exceed attack-response thresholds.
3. Stays quiet during normal steady-state operation.

This makes the defender react to actual CHANGES (attacks) rather than
baseline noise.
"""
from __future__ import annotations

import statistics
import time
from collections import deque
from typing import Any

from shared.config_loader import get_config
from shared.logger import get_logger
from shared.simulation import engine as sim_engine
from storage import database as db

log = get_logger("rules")


BASELINE_SAMPLES = 10  # learn over first 10 samples (~20 seconds at 2s interval)
BASELINE_UPDATE_INTERVAL = 60  # refresh baseline every 60s of steady state


class RulesEngine:
    """Evaluates metrics vs baseline + absolute ceilings."""

    def __init__(self) -> None:
        self.cfg = get_config()

        # Baseline tracking
        self._samples: dict[str, deque] = {
            "cpu": deque(maxlen=30),
            "memory": deque(maxlen=30),
            "disk": deque(maxlen=30),
            "processes": deque(maxlen=30),
            "network_connections": deque(maxlen=30),
        }
        self.baseline: dict[str, float] = {}
        self._last_baseline_refresh = 0.0
        self._baseline_ready = False

        # Track breach duration
        self._breach_since: dict[str, float] = {}

        # Custom rules
        self._custom_rules: list[dict] = db.list_custom_rules(enabled_only=True)
        self._last_reload = time.time()

    def reload(self) -> None:
        self._custom_rules = db.list_custom_rules(enabled_only=True)
        self._last_reload = time.time()

    # ---------- Baseline management ----------

    def _update_baseline(self, metric: dict) -> None:
        """Keep rolling sample of non-attack metrics for baseline."""
        # Don't contaminate baseline during simulated attack
        if metric.get("simulation_active"):
            return

        self._samples["cpu"].append(metric.get("cpu_percent", 0))
        self._samples["memory"].append(metric.get("memory_percent", 0))
        self._samples["disk"].append(metric.get("disk_percent", 0))
        self._samples["processes"].append(metric.get("process_count", 0))
        self._samples["network_connections"].append(metric.get("network_connections", 0))

        # Compute baseline once we have enough samples
        if not self._baseline_ready and len(self._samples["cpu"]) >= BASELINE_SAMPLES:
            self._compute_baseline()
            self._baseline_ready = True
            log.info(f"Baseline learned: {self.baseline}")
        elif self._baseline_ready and time.time() - self._last_baseline_refresh > BASELINE_UPDATE_INTERVAL:
            self._compute_baseline()

    def _compute_baseline(self) -> None:
        """Use median (robust to outliers) of recent samples."""
        for key, q in self._samples.items():
            if len(q) >= 3:
                self.baseline[key] = statistics.median(q)
        self._last_baseline_refresh = time.time()

    # ---------- Main evaluation ----------

    def evaluate(self, metric: dict[str, Any]) -> list[dict]:
        if time.time() - self._last_reload > 30:
            self.reload()

        # Update baseline with this sample
        self._update_baseline(metric)

        # If baseline not ready yet, don't fire any rules
        if not self._baseline_ready:
            return []

        sim_active = metric.get("simulation_active", False)
        actions: list[dict] = []

        # ---- CPU ----
        actions.extend(self._check(
            metric, "cpu", "cpu_percent",
            absolute_warn=92,          # only if CPU > 92% (unusual for any system)
            absolute_crit=96,          # only if CPU > 96%
            delta_warn=15,             # OR baseline + 15%
            delta_crit=25,             # OR baseline + 25%
            sustained=self.cfg.thresholds.cpu.sustained_seconds,
            critical_action="kill_top_cpu",
            sim_active=sim_active,
        ))

        # ---- Memory ----
        actions.extend(self._check(
            metric, "memory", "memory_percent",
            absolute_warn=93,
            absolute_crit=96,
            delta_warn=8,
            delta_crit=15,
            sustained=self.cfg.thresholds.memory.sustained_seconds,
            critical_action="kill_top_memory",
            sim_active=sim_active,
        ))

        # ---- Disk ----
        actions.extend(self._check(
            metric, "disk", "disk_percent",
            absolute_warn=95,
            absolute_crit=98,
            delta_warn=3,              # disk changes slowly, even small delta matters
            delta_crit=5,
            sustained=self.cfg.thresholds.disk.sustained_seconds,
            critical_action="clear_temp",
            sim_active=sim_active,
        ))

        # ---- Processes ----
        actions.extend(self._check_int(
            metric, "processes", "process_count",
            absolute_warn=500,
            absolute_crit=700,
            delta_warn=30,
            delta_crit=80,
            critical_action="alert_only",
            sim_active=sim_active,
        ))

        # ---- Network connections ----
        actions.extend(self._check_int(
            metric, "network_connections", "network_connections",
            absolute_warn=400,
            absolute_crit=800,
            delta_warn=80,
            delta_crit=200,
            critical_action="alert_only",
            sim_active=sim_active,
        ))

        # Custom rules (absolute only, applied as-is)
        for rule in self._custom_rules:
            value = metric.get(f"{rule['metric']}_percent") or metric.get(rule["metric"])
            if value is None:
                continue
            if self._op_match(value, rule["operator"], rule["threshold"]):
                actions.append({
                    "action": rule["action"],
                    "reason": f"Custom rule '{rule['name']}': {rule['metric']} {rule['operator']} {rule['threshold']}",
                    "severity": rule.get("severity", "warning"),
                    "category": "custom",
                    "source": "rules",
                })

        return actions

    # ---------- Generic check (percentage metrics) ----------

    def _check(
        self,
        metric: dict,
        key: str,
        metric_key: str,
        absolute_warn: float,
        absolute_crit: float,
        delta_warn: float,
        delta_crit: float,
        sustained: int,
        critical_action: str,
        sim_active: bool,
    ) -> list[dict]:
        """
        Fire if EITHER absolute ceiling exceeded OR delta-from-baseline exceeded.
        During simulated attack, be more reactive (lower effective threshold).
        """
        value = metric.get(metric_key, 0)
        baseline = self.baseline.get(key, value)
        delta = value - baseline

        # Effective thresholds — slightly more reactive if simulated attack is
        # running, but never below a safe floor so normal fluctuations don't fire.
        abs_warn = max(70, absolute_warn - (3 if sim_active else 0))
        abs_crit = max(85, absolute_crit - (3 if sim_active else 0))
        d_warn = max(5, delta_warn - (2 if sim_active else 0))
        d_crit = max(10, delta_crit - (3 if sim_active else 0))

        out: list[dict] = []
        now = time.time()
        crit_key = f"{key}_crit"
        warn_key = f"{key}_warn"

        # Critical = delta OR absolute over critical
        if delta >= d_crit or value >= abs_crit:
            start = self._breach_since.setdefault(crit_key, now)
            if now - start >= sustained:
                out.append({
                    "action": critical_action,
                    "reason": (
                        f"{key.upper()} critical: {value:.1f}% "
                        f"(baseline {baseline:.1f}%, Δ +{delta:.1f})"
                        + (" during simulated attack" if sim_active else "")
                    ),
                    "severity": "critical",
                    "category": key,
                    "source": "rules",
                })
            self._breach_since.pop(warn_key, None)
            return out

        # Warning
        if delta >= d_warn or value >= abs_warn:
            start = self._breach_since.setdefault(warn_key, now)
            if now - start >= sustained:
                out.append({
                    "action": "alert_only",
                    "reason": f"{key.upper()} warning: {value:.1f}% (baseline {baseline:.1f}%, Δ +{delta:.1f})",
                    "severity": "warning",
                    "category": key,
                    "source": "rules",
                })
            self._breach_since.pop(crit_key, None)
        else:
            self._breach_since.pop(crit_key, None)
            self._breach_since.pop(warn_key, None)
        return out

    def _check_int(
        self,
        metric: dict,
        key: str,
        metric_key: str,
        absolute_warn: int,
        absolute_crit: int,
        delta_warn: int,
        delta_crit: int,
        critical_action: str,
        sim_active: bool,
    ) -> list[dict]:
        """Integer-valued version (process count, connection count)."""
        value = metric.get(metric_key, 0)
        baseline = self.baseline.get(key, value)
        delta = value - baseline

        out: list[dict] = []
        if delta >= delta_crit or value >= absolute_crit:
            out.append({
                "action": critical_action,
                "reason": f"{key} critical: {int(value)} (baseline {int(baseline)}, Δ +{int(delta)})",
                "severity": "critical",
                "category": key,
                "source": "rules",
            })
        elif delta >= delta_warn or value >= absolute_warn:
            out.append({
                "action": "alert_only",
                "reason": f"{key} warning: {int(value)} (baseline {int(baseline)}, Δ +{int(delta)})",
                "severity": "warning",
                "category": key,
                "source": "rules",
            })
        return out

    # ---------- Public helpers ----------

    def snapshot(self) -> dict[str, Any]:
        """For UI: expose current baseline state."""
        return {
            "ready": self._baseline_ready,
            "baseline": self.baseline.copy(),
            "samples_collected": len(self._samples["cpu"]),
            "samples_required": BASELINE_SAMPLES,
        }

    @staticmethod
    def _op_match(value: float, op: str, threshold: float) -> bool:
        return {
            ">": value > threshold,
            "<": value < threshold,
            ">=": value >= threshold,
            "<=": value <= threshold,
            "==": value == threshold,
        }.get(op, False)
