"""
Action Executor — SIMULATION MODE.

Carries out decisions from the DecisionEngine. All actions are SIMULATED:
- Throttle: reduce simulated impact (not real cgroups)
- Block IP: tracked in offender registry
- Kill: unregister from simulation engine
- Quarantine: mark file as "quarantined" in metadata

No real processes, files, or network connections are touched.
"""
from __future__ import annotations

import os
import time
from datetime import datetime
from typing import Any

from attacker.safety_guard import guard
from defender.decision_engine import Action, Decision, offenders, trust
from shared.config_loader import get_config
from shared.event_bus import Topics, bus
from shared.logger import get_logger
from shared.notifier import notify
from shared.simulation import engine as sim_engine
from storage import database as db

log = get_logger("executor")


class Executor:
    """Simulated action executor — no real harm."""

    def __init__(self) -> None:
        self.cfg = get_config()
        self.protected_pids: set[int] = {os.getpid()}

    # =================================================================
    # Main dispatch — accepts a Decision object from DecisionEngine
    # =================================================================

    def execute_decision(self, decision: Decision) -> dict[str, Any]:
        """Execute the action chosen by the DecisionEngine."""
        action = decision.action
        threat = decision.threat

        handlers = {
            Action.NONE: self._noop,
            Action.LOG_ONLY: self._log_only,
            Action.ALERT: self._alert,
            Action.INCREASE_MONITORING: self._increase_monitoring,
            Action.THROTTLE_CPU: self._throttle_cpu,
            Action.THROTTLE_NETWORK: self._throttle_network,
            Action.RATE_LIMIT_SOURCE: self._rate_limit_source,
            Action.REQUIRE_CHALLENGE: self._require_challenge,
            Action.SANDBOX_PROCESS: self._sandbox_process,
            Action.BLOCK_NETWORK: self._block_network,
            Action.QUARANTINE_FILES: self._quarantine_files,
            Action.SUSPEND_PROCESS: self._suspend_process,
            Action.BLOCK_IP_TEMPORARY: self._block_ip_temporary,
            Action.KILL_PROCESS: self._kill_process,
            Action.KILL_AND_CAPTURE: self._kill_and_capture,
            Action.BLOCK_IP_PERMANENT: self._block_ip_permanent,
            Action.CLEAR_TEMP: self._clear_temp,
            Action.ROLLBACK_CHANGES: self._rollback_changes,
            Action.NOTIFY_SOC: self._notify_soc,
        }
        handler = handlers.get(action, self._noop)

        try:
            result = handler(decision)
            self._log_action(decision, result)
            bus.publish(Topics.ACTION_EXECUTED, {
                "decision": decision.to_dict(),
                "result": result,
            })
            return result
        except Exception as e:  # noqa: BLE001
            log.error(f"Executor error on {action.value}: {e}")
            return {"success": False, "error": str(e)}

    # =================================================================
    # Backward-compat — old code still calls execute(dict)
    # =================================================================

    def execute(self, decision_dict: dict[str, Any]) -> dict[str, Any]:
        """Legacy interface — minimal handlers for backwards compatibility."""
        action = decision_dict.get("action", "alert_only")
        if action == "alert_only":
            db.insert_action("alert", None, decision_dict.get("source", "rules"), True,
                             decision_dict.get("reason", ""))
            notify("Argus Alert", decision_dict.get("reason", ""), level="warning")
            return {"success": True}
        # Map old-style to new
        return {"success": False, "reason": "use execute_decision instead"}

    # =================================================================
    # Tier 0: Observe
    # =================================================================

    def _noop(self, d: Decision) -> dict:
        return {"success": True, "action": "none", "message": "no action needed"}

    def _log_only(self, d: Decision) -> dict:
        return {"success": True, "action": "log_only", "message": "Logged for audit trail"}

    def _alert(self, d: Decision) -> dict:
        msg = f"[{d.threat.severity.upper()}] {d.threat.threat_type} from {d.threat.source_name}"
        notify("Argus Alert", msg, level="warning")
        return {"success": True, "action": "alert", "message": msg}

    def _increase_monitoring(self, d: Decision) -> dict:
        return {
            "success": True, "action": "increase_monitoring",
            "message": f"Monitoring frequency doubled for {d.threat.source_name}",
        }

    # =================================================================
    # Tier 1: Limit
    # =================================================================

    def _throttle_cpu(self, d: Decision) -> dict:
        """Reduce simulated CPU claim by 50%."""
        att = self._find_sim_by_source(d)
        if att:
            new_cpu = att.cpu_percent * 0.5
            sim_engine.unregister(att.attack_id)
            att.cpu_percent = new_cpu
            sim_engine.register(att)
            return {
                "success": True, "action": "throttle_cpu",
                "message": f"CPU usage of sim_{d.threat.threat_type} throttled to {new_cpu:.0f}%",
                "throttled_to": new_cpu,
            }
        return {"success": False, "reason": "no matching simulation"}

    def _throttle_network(self, d: Decision) -> dict:
        att = self._find_sim_by_source(d)
        if att:
            att.network_sent_mb *= 0.3
            att.network_recv_mb *= 0.3
            return {"success": True, "action": "throttle_network",
                    "message": "Network bandwidth limited to 30%"}
        return {"success": False}

    def _rate_limit_source(self, d: Decision) -> dict:
        """Apply rate limit to a request source IP."""
        offenders.block_for(d.threat.source_type, d.threat.source_id, seconds=10)
        return {
            "success": True, "action": "rate_limit_source",
            "message": f"Rate limit applied to {d.threat.source_id} for 10s (max 5 req/min)",
        }

    def _require_challenge(self, d: Decision) -> dict:
        return {
            "success": True, "action": "require_challenge",
            "message": f"CAPTCHA challenge required for {d.threat.source_id}",
        }

    # =================================================================
    # Tier 2: Contain
    # =================================================================

    def _sandbox_process(self, d: Decision) -> dict:
        att = self._find_sim_by_source(d)
        if att:
            # Reduce impact dramatically and mark sandboxed
            att.cpu_percent *= 0.2
            att.memory_mb *= 0.5
            att.network_connections = 0
            return {
                "success": True, "action": "sandbox_process",
                "message": f"{d.threat.source_name} sandboxed — capabilities restricted",
            }
        return {"success": False}

    def _block_network(self, d: Decision) -> dict:
        att = self._find_sim_by_source(d)
        if att:
            att.network_sent_mb = 0
            att.network_recv_mb = 0
            att.network_connections = 0
            return {"success": True, "action": "block_network",
                    "message": f"All network access cut for {d.threat.source_name}"}
        return {"success": False}

    def _quarantine_files(self, d: Decision) -> dict:
        return {
            "success": True, "action": "quarantine_files",
            "message": f"Files associated with {d.threat.source_name} quarantined",
            "quarantined_count": 12,  # simulated count
        }

    # =================================================================
    # Tier 3: Suspend
    # =================================================================

    def _suspend_process(self, d: Decision) -> dict:
        """SIGSTOP-equivalent — freeze simulated process AND stop the attack."""
        att = self._find_sim_by_source(d)
        if att:
            # Mark suspended visually (impact gone) AND stop the attack object
            sim_engine.unregister(att.attack_id)
            self._stop_attack_object(att.attack_id, "defender_suspended")
            return {
                "success": True, "action": "suspend_process",
                "message": f"{d.threat.source_name} SUSPENDED (frozen for forensics)",
            }
        return {"success": False}

    def _block_ip_temporary(self, d: Decision) -> dict:
        offenders.block_for(d.threat.source_type, d.threat.source_id, seconds=300)
        return {
            "success": True, "action": "block_ip_temporary",
            "message": f"IP {d.threat.source_id} blocked for 5 minutes",
        }

    # =================================================================
    # Tier 4: Terminate
    # =================================================================

    def _kill_process(self, d: Decision) -> dict:
        att = self._find_sim_by_source(d)
        if att:
            sim_engine.unregister(att.attack_id)
            self._stop_attack_object(att.attack_id, "defender_killed")
            return {
                "success": True, "action": "kill_process",
                "message": f"Terminated simulated {att.fake_process_name} (fake PID {att.fake_pid})",
                "pid": att.fake_pid,
            }
        top = sim_engine.kill_top_cpu()
        if top:
            self._stop_attack_object(top.attack_id, "defender_killed")
            return {"success": True, "action": "kill_process",
                    "message": f"Terminated top-CPU sim {top.fake_process_name}",
                    "pid": top.fake_pid}
        return {"success": False, "reason": "no simulation to kill"}

    def _kill_and_capture(self, d: Decision) -> dict:
        result = self._kill_process(d)
        if result.get("success"):
            result["message"] += " + memory dump captured for forensics"
            result["forensic_artifact"] = f"/forensics/sim-dump-{int(time.time())}.dmp"
        return result

    def _block_ip_permanent(self, d: Decision) -> dict:
        offenders.block_for(d.threat.source_type, d.threat.source_id, seconds=86400)  # 24h
        return {
            "success": True, "action": "block_ip_permanent",
            "message": f"IP {d.threat.source_id} BLOCKED indefinitely (firewall rule added)",
        }

    # =================================================================
    # Tier 5: Recover
    # =================================================================

    def _clear_temp(self, d: Decision) -> dict:
        return {
            "success": True, "action": "clear_temp",
            "message": "Cleared 240 MB of cached temp files (simulated)",
            "freed_mb": 240,
        }

    def _rollback_changes(self, d: Decision) -> dict:
        return {
            "success": True, "action": "rollback_changes",
            "message": "Restored 87 files from snapshot (simulated ransomware recovery)",
            "files_restored": 87,
        }

    def _notify_soc(self, d: Decision) -> dict:
        return {
            "success": True, "action": "notify_soc",
            "message": f"SOC team notified with full incident report",
        }

    # =================================================================
    # Helpers
    # =================================================================

    def _find_sim_by_source(self, d: Decision):
        """Find the SimulatedImpact matching the threat's source."""
        for imp in sim_engine.active_list():
            if imp.attack_id == d.threat.source_id:
                return imp
            if d.threat.source_name and imp.fake_process_name == d.threat.source_name:
                return imp
            # Match by attack name (cpu_spike threat → impact with attack_name=cpu_spike)
            if imp.attack_name == d.threat.threat_type:
                return imp
        return None

    def _stop_attack_object(self, attack_id: str, reason: str) -> None:
        """
        Find the actual attack instance by id and call stop().
        This is what makes the attack THREAD exit and broadcasts ATTACK_STOPPED
        so the timeline UI sees the resolution.
        """
        try:
            attack = guard.get(attack_id)
            if attack and attack.is_running:
                attack.stop(stopped_by=reason)
                guard.unregister(attack_id)
        except Exception as e:  # noqa: BLE001
            log.debug(f"Could not stop attack object {attack_id}: {e}")

    def _log_action(self, decision: Decision, result: dict) -> None:
        action = decision.action.value
        target = decision.threat.source_name or decision.threat.source_id
        success = bool(result.get("success"))
        details = result.get("message", "")
        db.insert_action(action, target, "decision_engine", success, details)
        log.warning(f"[ACTION] {action} → {target} :: {details}")
