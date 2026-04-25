"""
Defender orchestrator with intelligent multi-tier response.

Flow:
  Monitor → metric → rules detect threat → DecisionEngine assesses risk →
  picks graduated action → executor applies (simulated) → AI verifies →
  if repeated, escalates next time.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from ai import advisor as ai_advisor
from ai.investigator import run_investigation
from ai.live_solver import solve_now as ai_solve_now
from ai.predictor import Predictor
from attacker.safety_guard import guard
from defender.decision_engine import (
    Action,
    engine as decision_engine,
    offenders,
    threat_from_aegis_event,
    threat_from_attack,
    threat_from_metric,
)
from defender.defense_mode import DefenseMode, state as mode_state
from defender.executor import Executor
from defender.rules_engine import RulesEngine
from shared.config_loader import get_config
from shared.event_bus import Topics, bus
from shared.logger import get_logger
from storage import database as db

log = get_logger("orchestrator")


class DefenderOrchestrator:
    def __init__(self) -> None:
        self.cfg = get_config()
        self.rules = RulesEngine()
        self.ai = Predictor()
        self.executor = Executor()
        self._loop: asyncio.AbstractEventLoop | None = None
        # Investigation throttling
        self._investigation_in_progress = False
        self._last_investigation_at: float = 0
        self._investigation_cooldown = 25  # seconds
        # Live solver throttling — only one solver running, cooldown between
        self._solver_in_progress = False
        self._last_solve_at: float = 0
        self._solver_cooldown = 12  # seconds

    @property
    def predictor(self) -> Predictor:
        return self.ai

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def register_with_bus(self) -> None:
        bus.subscribe(Topics.METRIC_COLLECTED, self.handle_metric)
        # Aegis: also subscribe to category events emitted by checks/attacks
        bus.subscribe("event", self.handle_aegis_event)
        # Throttle map: source_id -> last_action_ts. Prevents action spam from
        # repeated events about the same incident.
        self._aegis_action_throttle: dict[str, float] = {}
        self._aegis_throttle_seconds = 8

    def handle_aegis_event(self, event: dict[str, Any]) -> None:
        """
        Process category events (service/security/network/infra) from checks/attacks.
        Branches by defense mode (AUTO/HYBRID/AI), runs decision flow, executes action.
        """
        try:
            category = event.get("category", "")
            if category not in ("service", "security", "network", "infra"):
                return  # not for us — legacy categories ignored

            level = event.get("level", "INFO").upper()
            if level == "INFO":
                return  # only react to WARNING/CRITICAL

            threat = threat_from_aegis_event(event)
            if threat is None:
                return

            # De-duplicate: same source within throttle window → skip
            throttle_key = f"{threat.source_type}:{threat.source_id}:{threat.threat_type}"
            now = time.time()
            last = self._aegis_action_throttle.get(throttle_key, 0)
            if now - last < self._aegis_throttle_seconds:
                return
            self._aegis_action_throttle[throttle_key] = now

            current_mode = mode_state.mode

            # AI mode: pure LLM decision via live solver (when not throttled)
            if current_mode == DefenseMode.AI:
                if not self._solver_in_progress and (now - self._last_solve_at > self._solver_cooldown):
                    self._kick_off_live_solver(
                        f"AI mode: detected {category} incident — {event.get('message', '')[:80]}"
                    )
                else:
                    # Cooldown: fall through to engine-based action so something happens
                    pass

            # AUTO + HYBRID + (AI-cooldown): use DecisionEngine
            decision = decision_engine.decide(threat)

            db.insert_event(
                level="ACTION" if decision.action.value not in ("none", "log_only") else "INFO",
                category=threat.source_type,
                message=(
                    f"[{current_mode.value.upper()}] {category} incident "
                    f"→ {decision.action.value} (target: {threat.source_name})"
                ),
                source=f"orchestrator:{current_mode.value}",
                metadata=decision.to_dict(),
            )
            bus.publish("defender.decision", decision.to_dict())

            # HYBRID extras: AI verify after action (similar to metric flow)
            if current_mode == DefenseMode.HYBRID:
                self._maybe_auto_investigate(decision, threat)

            # Execute (AUTO + HYBRID always; AI as fallback when solver cooling down)
            if self.cfg.actions.auto_kill_enabled and decision.action.value not in ("none",):
                result = self.executor.execute_decision(decision)
                # AI verify in HYBRID mode for non-trivial actions
                if (current_mode == DefenseMode.HYBRID
                        and self.cfg.actions.ai_verify_after_action
                        and decision.action.value not in ("none", "log_only", "alert")):
                    self._schedule_aegis_verification(threat, decision, result)

        except Exception as e:  # noqa: BLE001
            log.error(f"Aegis event handler error: {e}", exc_info=True)

    def _schedule_aegis_verification(self, threat, decision, action_result) -> None:
        """Lightweight verify: did the state actually heal after the action?"""
        if not self._loop:
            return

        async def _verify() -> None:
            await asyncio.sleep(2)
            try:
                # Quick state check based on category
                from shared.state import service_state, auth_state, cert_state, network_state, infra_state
                healed = False
                detail = ""
                if threat.source_type == "service":
                    rec = service_state.get(threat.metadata.get("service_id", threat.source_id))
                    healed = rec is not None and rec.effective_status() == "up"
                    detail = f"service status = {rec.effective_status() if rec else 'unknown'}"
                elif threat.source_type == "ip":
                    threats = auth_state.all_threats()
                    target = next((t for t in threats if t["ip"] == threat.source_id), None)
                    healed = target is not None and target.get("blocked", False)
                    detail = f"ip blocked = {bool(target and target.get('blocked'))}"
                elif threat.source_type == "cert":
                    cert = cert_state.get(threat.metadata.get("domain", threat.source_id))
                    healed = cert is not None and cert.days_to_expiry() > 60
                    detail = f"cert days = {cert.days_to_expiry() if cert else 'unknown'}"
                elif threat.source_type == "port":
                    ports = network_state.all_ports()
                    target = next((p for p in ports if p["port"] == int(threat.source_id)), None)
                    healed = target is not None and not target["open"]
                    detail = f"port closed = {bool(target and not target['open'])}"
                else:
                    healed = True
                    detail = "verified"
                bus.publish("ai.verify", {
                    "decision": decision.to_dict(),
                    "outcome": "healed" if healed else "not_healed",
                    "detail": detail,
                })
                db.insert_event(
                    level="INFO" if healed else "WARN",
                    category="ai_verify",
                    message=f"Verify after {decision.action.value}: {detail}",
                    source="aegis_verify",
                )
            except Exception as e:  # noqa: BLE001
                log.debug(f"Aegis verify error: {e}")

        try:
            asyncio.run_coroutine_threadsafe(_verify(), self._loop)
        except Exception as e:  # noqa: BLE001
            log.debug(f"Aegis verify schedule failed: {e}")

    def handle_metric(self, metric: dict[str, Any]) -> None:
        try:
            # 1. ML anomaly detection
            ai_result = self.ai.predict(metric)
            if ai_result.get("ready"):
                self._update_metric_ai(metric["id"], ai_result)
                metric["is_anomaly"] = int(ai_result.get("is_anomaly", False))
                metric["anomaly_score"] = ai_result.get("score", 0)
                if ai_result.get("is_anomaly"):
                    db.insert_event(
                        level="WARN", category="ai",
                        message=f"Anomaly score {ai_result['score']:.2f}: {ai_result.get('explanation_text','')}",
                        source="ml",
                    )

            # 2. Rule evaluation
            rule_actions = self.rules.evaluate(metric)
            if not rule_actions:
                return

            # 3. Per rule-trigger: build threat context + decide
            active_attacks = guard.list_active()
            current_mode = mode_state.mode
            for rule_action in rule_actions:
                threat = self._build_threat_from_rule(rule_action, metric, active_attacks)
                if not threat:
                    continue

                # Branch by defense mode
                if current_mode == DefenseMode.AI:
                    # Pure AI: run the demo-grade live solver (visible step-by-step)
                    # Falls back to single-shot if a solver is already running
                    if not self._solver_in_progress and (time.time() - self._last_solve_at > self._solver_cooldown):
                        self._kick_off_live_solver(
                            f"AI mode: detected {threat.threat_type} on {threat.source_name}"
                        )
                    else:
                        # Cooldown active — use single-shot path
                        self._handle_threat_ai_mode(threat, metric)
                else:
                    # AUTO and HYBRID both use DecisionEngine for primary action.
                    # Difference: HYBRID also runs AI verify + auto-investigate.
                    decision = decision_engine.decide(threat)
                    db.insert_event(
                        level="ACTION" if decision.action.value not in ("none", "log_only") else "WARN",
                        category=threat.source_type,
                        message=(
                            f"[{current_mode.value.upper()}] Risk {decision.risk_score:.0f}/100 "
                            f"→ {decision.action.value} (target: {threat.source_name})"
                        ),
                        source=f"decision_engine:{current_mode.value}",
                        metadata=decision.to_dict(),
                    )
                    bus.publish("defender.decision", decision.to_dict())

                    # HYBRID-only extras: investigation + AI verify
                    if current_mode == DefenseMode.HYBRID:
                        self._maybe_auto_investigate(decision, threat)

                    # Execute (both AUTO and HYBRID)
                    if self.cfg.actions.auto_kill_enabled:
                        result = self.executor.execute_decision(decision)

                        # AI verify only in HYBRID
                        if (current_mode == DefenseMode.HYBRID
                                and self.cfg.actions.ai_verify_after_action
                                and decision.action.value not in ("none", "log_only", "alert")):
                            self._schedule_verification(metric, decision, result)

        except Exception as e:  # noqa: BLE001
            log.error(f"Orchestrator error: {e}")

    # ==========================================================
    # Build threats from various sources
    # ==========================================================

    def _build_threat_from_rule(
        self,
        rule_action: dict,
        metric: dict,
        active_attacks: list[dict],
    ) -> Any:
        """Construct ThreatContext from a rule trigger."""
        category = rule_action.get("category", "unknown")
        severity = rule_action.get("severity", "medium")

        # If a simulated attack is active, link the threat to it
        # (so the executor can act on the right simulated process)
        if active_attacks:
            primary = active_attacks[0]  # most recent
            return threat_from_attack(primary, severity=severity, confidence=0.9)

        # Otherwise treat as a generic metric breach
        baseline_map = {
            "cpu": metric.get("baseline_cpu", 0),
            "memory": metric.get("baseline_memory", 0),
            "disk": metric.get("baseline_disk", 0),
            "processes": metric.get("baseline_processes", 0),
            "network_connections": metric.get("baseline_network_connections", 0),
        }
        value_map = {
            "cpu": metric.get("cpu_percent", 0),
            "memory": metric.get("memory_percent", 0),
            "disk": metric.get("disk_percent", 0),
            "processes": metric.get("process_count", 0),
            "network_connections": metric.get("network_connections", 0),
        }

        return threat_from_metric(
            metric_key=category,
            value=value_map.get(category, 0),
            baseline=baseline_map.get(category, 0) or value_map.get(category, 0) * 0.6,
            severity=severity,
            threat_type=f"{category}_anomaly",
            confidence=0.8,
        )

    # ==========================================================
    # Live Solver kick-off (used in AI mode for demo flow)
    # ==========================================================

    def _kick_off_live_solver(self, trigger: str) -> None:
        """Spawn a live solver session in the background. UI streams it live."""
        if not self._loop:
            return
        if self._solver_in_progress:
            return
        self._solver_in_progress = True
        self._last_solve_at = time.time()

        async def _run() -> None:
            try:
                await ai_solve_now(trigger)
            except Exception as e:  # noqa: BLE001
                log.error(f"Live solver crashed: {e}")
            finally:
                self._solver_in_progress = False

        try:
            asyncio.run_coroutine_threadsafe(_run(), self._loop)
        except Exception as e:  # noqa: BLE001
            log.error(f"Failed to schedule solver: {e}")
            self._solver_in_progress = False

    # ==========================================================
    # AI MODE — single-shot fallback (when solver cooldown active)
    # ==========================================================

    def _handle_threat_ai_mode(self, threat, metric: dict) -> None:
        """In pure AI mode, the LLM picks the action directly."""
        if not self._loop:
            return

        async def _go() -> None:
            try:
                # Build threat dict for LLM
                threat_dict = {
                    "source_type": threat.source_type,
                    "source_name": threat.source_name,
                    "threat_type": threat.threat_type,
                    "severity": threat.severity,
                    "confidence": threat.confidence,
                    "is_trusted": threat.is_trusted,
                    "repeat_count": threat.repeat_count,
                    "metric_value": threat.metric_value,
                    "metric_baseline": threat.metric_baseline,
                }
                ai_choice = await ai_advisor.ai_pick_action(threat_dict, metric)

                ai_action_str = ai_choice.get("action", "alert_only")
                ai_severity = ai_choice.get("severity", "medium")
                ai_reason = ai_choice.get("reason", "AI decision")
                ai_confidence = float(ai_choice.get("confidence", 0.5))

                # Map AI action string → engine Action enum (validate)
                try:
                    chosen = Action(ai_action_str)
                except ValueError:
                    log.warning(f"AI returned invalid action {ai_action_str!r}, defaulting to alert")
                    chosen = Action.ALERT

                # Risk score: derive from BOTH AI severity AND tier of chosen action,
                # not just confidence. A clear threat with high tier should show high risk.
                from defender.decision_engine import (
                    ACTION_TIER, Decision as DecObj,
                )
                severity_weights = {"info": 10, "low": 25, "medium": 50, "high": 75, "critical": 92}
                base_score = severity_weights.get(ai_severity, 50)
                # Blend with action tier (higher tier = more action urgency)
                tier_score = ACTION_TIER.get(chosen, 0) * 18  # 0..72
                risk_score = max(base_score, tier_score) * (0.7 + 0.3 * ai_confidence)
                risk_score = min(100, max(5, risk_score))

                decision = DecObj(
                    action=chosen,
                    risk_score=risk_score,
                    reasoning=[
                        f"[AI MODE] LLM analyzed threat",
                        f"AI severity assessment: {ai_severity}",
                        f"AI confidence: {ai_confidence:.2f}",
                        f"Action tier: {ACTION_TIER.get(chosen, 0)}",
                        ai_reason,
                    ],
                    rejected_alternatives=[
                        (Action(alt["action"]), alt.get("rejected_because", ""))
                        for alt in (ai_choice.get("alternatives_considered") or [])
                        if "action" in alt and alt.get("action") in {a.value for a in Action}
                    ] if isinstance(ai_choice.get("alternatives_considered"), list) else [],
                    threat=threat,
                    expected_outcome="LLM-recommended outcome",
                )

                # Log + broadcast
                db.insert_event(
                    level="ACTION" if chosen.value not in ("none", "log_only", "alert") else "WARN",
                    category=threat.source_type,
                    message=f"[AI MODE] {chosen.value} — {ai_reason[:80]}",
                    source=f"llm:{ai_choice.get('provider', '?')}",
                    metadata={
                        "decision": decision.to_dict(),
                        "ai_choice": ai_choice,
                    },
                )
                bus.publish("defender.decision", decision.to_dict())

                # Execute
                if self.cfg.actions.auto_kill_enabled:
                    self.executor.execute_decision(decision)

            except Exception as e:  # noqa: BLE001
                log.error(f"AI mode handling failed: {e}")
                # Fallback: log + alert
                db.insert_event(
                    level="WARN", category="ai_mode_error",
                    message=f"AI mode failed: {e}", source="orchestrator",
                )

        try:
            asyncio.run_coroutine_threadsafe(_go(), self._loop)
        except Exception as e:  # noqa: BLE001
            log.error(f"Failed to schedule AI handler: {e}")

    # ==========================================================
    # AI Investigation auto-trigger
    # ==========================================================

    def _maybe_auto_investigate(self, decision, threat) -> None:
        """
        Trigger an AI investigation if the situation is unusual.
        Conditions:
          - Risk score in uncertain band (40-60) → AI tie-breaker
          - Source has 5+ recent violations → escalation review
          - Same source already blocked but repeating → policy review
        """
        if self._investigation_in_progress:
            return
        if time.time() - self._last_investigation_at < self._investigation_cooldown:
            return
        if not self._loop:
            return

        # Determine if we should investigate
        score = decision.risk_score
        offender = offenders.get(threat.source_type, threat.source_id)
        repeat_count = offender.recent_count(300) if offender else 0

        trigger_reason = None
        if 40 <= score <= 60:
            trigger_reason = (
                f"Risk score {score:.0f} is in the uncertain band (40-60). "
                f"Need deeper analysis on {threat.source_type}={threat.source_name}."
            )
        elif repeat_count >= 5:
            trigger_reason = (
                f"Source {threat.source_id} has {repeat_count} violations in 5 min. "
                f"Repeat-offender pattern requires escalation review."
            )

        if not trigger_reason:
            return

        # Mark in-progress so we don't fire again
        self._investigation_in_progress = True
        self._last_investigation_at = time.time()

        async def _run() -> None:
            try:
                context = {
                    "trigger_score": score,
                    "trigger_action": decision.action.value,
                    "source_type": threat.source_type,
                    "source_id": threat.source_id,
                    "source_name": threat.source_name,
                    "threat_type": threat.threat_type,
                    "severity": threat.severity,
                    "repeat_count": repeat_count,
                    "decision_reasoning": decision.reasoning,
                }
                await run_investigation(trigger_reason, context, max_steps=4)
            except Exception as e:  # noqa: BLE001
                log.error(f"Auto-investigation failed: {e}")
            finally:
                self._investigation_in_progress = False

        try:
            asyncio.run_coroutine_threadsafe(_run(), self._loop)
        except Exception as e:  # noqa: BLE001
            log.error(f"Failed to schedule investigation: {e}")
            self._investigation_in_progress = False

    # ==========================================================
    # AI verification (post-action)
    # ==========================================================

    def _schedule_verification(self, before_metric: dict, decision, result: dict) -> None:
        if not self._loop:
            return

        async def _verify() -> None:
            await asyncio.sleep(6)
            try:
                latest = db.get_latest_metric() or {}
                verdict = await ai_advisor.verify_solved(before_metric, latest, decision.action.value)
                text = (
                    f"[AI-Verify] action={decision.action.value} "
                    f"solved={verdict.get('solved')} conf={verdict.get('confidence',0):.2f} "
                    f"— {verdict.get('summary','')}"
                )
                db.insert_event(
                    level="AI", category="ai_verify",
                    message=text,
                    source="llm:" + verdict.get("provider", "?"),
                    metadata=verdict,
                )
                bus.publish("ai.verify", verdict)
            except Exception as e:  # noqa: BLE001
                log.debug(f"Verify failed: {e}")

        try:
            asyncio.run_coroutine_threadsafe(_verify(), self._loop)
        except Exception:
            pass

    # ==========================================================
    # Helpers
    # ==========================================================

    def _update_metric_ai(self, metric_id: int, ai_result: dict) -> None:
        try:
            with db.cursor() as cur:
                cur.execute(
                    "UPDATE metrics SET is_anomaly = ?, anomaly_score = ?, ai_explanation = ? WHERE id = ?",
                    (
                        int(ai_result.get("is_anomaly", False)),
                        ai_result.get("score", 0),
                        json.dumps(ai_result.get("explanation", [])) if ai_result.get("explanation") else None,
                        metric_id,
                    ),
                )
        except Exception:
            pass


def auto_retrain_loop(predictor: Predictor, interval_hours: int = 72) -> None:
    from ai import trainer
    cfg = get_config()
    interval = interval_hours * 3600
    while True:
        time.sleep(interval)
        try:
            count = db.count_metrics()
            if count >= cfg.ai.min_samples_for_training:
                log.info(f"Auto-retraining AI ({count} samples)")
                trainer.train_all()
                predictor.reload()
        except Exception as e:
            log.error(f"Auto-retrain error: {e}")
