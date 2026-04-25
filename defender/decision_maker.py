"""
Decision maker — hybrid Rules + AI logic.
"""
from __future__ import annotations

from typing import Any

from shared.logger import get_logger

log = get_logger("decision")


class DecisionMaker:
    """
    Hybrid decision:
      rule + ai_anomaly    → execute (high confidence)
      rule + ai_normal     → downgrade to alert (possible false positive)
      no rule + ai_anomaly → alert only (new pattern)
      no rule + ai_normal  → no action
    """

    def decide(
        self,
        metric: dict[str, Any],
        rules_output: list[dict],
        ai_output: dict,
    ) -> list[dict]:
        rule_fired = bool(rules_output)
        is_anomaly = bool(ai_output.get("is_anomaly"))
        confidence = ai_output.get("confidence", "low")
        ai_active = ai_output.get("ready", False)

        decisions: list[dict] = []

        # Case 1: rule + AI anomaly (or AI disabled)
        if rule_fired and (is_anomaly or not ai_active):
            for action in rules_output:
                decisions.append({
                    **action,
                    "confidence": "high" if is_anomaly else "medium",
                    "executed_by": "hybrid" if is_anomaly else "rules",
                    "ai_score": ai_output.get("score", 0),
                })

        # Case 2: rule fired but AI says normal — downgrade critical actions
        elif rule_fired and ai_active and not is_anomaly and confidence != "low":
            for action in rules_output:
                d = {**action, "ai_score": ai_output.get("score", 0)}
                if action["severity"] == "critical":
                    d["action"] = "alert_only"
                    d["executed_by"] = "rules_downgraded"
                    d["reason"] = f"[DOWNGRADED] {action['reason']} — AI says normal"
                else:
                    d["executed_by"] = "rules"
                decisions.append(d)

        # Case 3: no rule but AI anomaly
        elif not rule_fired and is_anomaly and confidence != "low":
            decisions.append({
                "action": "alert_only",
                "reason": f"AI anomaly detected (score={ai_output.get('score', 0):.2f})",
                "severity": "warning",
                "executed_by": "ai",
                "source": "ai",
                "category": "ai_novel",
                "ai_score": ai_output.get("score", 0),
            })

        return decisions
