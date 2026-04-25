"""
AI Investigator — multi-step agent loop for complex security situations.

When standard rule-based responses aren't enough (uncertain risk, repeat offender,
novel pattern), the AI runs an iterative investigation:

  1. Get initial context (current state, history, related events)
  2. AI plans next step → picks a TOOL + arguments
  3. Tool executes → returns observation data
  4. AI sees result → plans next step OR concludes
  5. Loop until AI marks "done" or max_steps reached
  6. Final report with recommendation

Each step is published to the event bus → streamed to UI in real time.

This demonstrates AGENTIC AI: the model isn't just answering one question,
it's investigating step-by-step like a security analyst would.
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

from ai.json_extract import extract_json
from ai.llm_client import client as llm
from defender.decision_engine import offenders
from shared.event_bus import bus
from shared.logger import get_logger
from shared.simulation import engine as sim_engine
from storage import database as db

log = get_logger("ai-investigator")


# ============================================================
# Tools the agent can use
# ============================================================

class InvestigatorTools:
    """Tools the AI can invoke during investigation."""

    @staticmethod
    def inspect_metric(name: str = "cpu", window_seconds: int = 60) -> dict:
        """Fetch metric history for analysis."""
        try:
            with db.cursor() as cur:
                cur.execute(
                    "SELECT cpu_percent, memory_percent, disk_percent, "
                    "process_count, network_connections, timestamp "
                    "FROM metrics WHERE timestamp >= datetime('now', ?) "
                    "ORDER BY timestamp DESC LIMIT 30",
                    (f'-{window_seconds} seconds',)
                )
                rows = [dict(r) for r in cur.fetchall()]
        except Exception as e:
            return {"error": str(e)}
        if not rows:
            return {"data_points": 0, "summary": "no recent data"}
        key = name + "_percent" if name in ("cpu", "memory", "disk") else name
        if key in ("process_count", "network_connections"):
            values = [r[key] for r in rows if r.get(key) is not None]
        else:
            values = [r.get(key, 0) for r in rows]
        if not values:
            return {"data_points": 0}
        return {
            "metric": key,
            "data_points": len(rows),
            "current": values[0],
            "min": min(values),
            "max": max(values),
            "avg": round(sum(values) / len(values), 2),
            "trend": "rising" if values[0] > values[-1] + 5 else "falling" if values[0] < values[-1] - 5 else "stable",
            "samples": values[:10],
        }

    @staticmethod
    def inspect_offender(source_id: str) -> dict:
        """Get violation history for a source."""
        for source_type in ("request", "process", "metric"):
            rec = offenders.get(source_type, source_id)
            if rec:
                return {
                    "found": True,
                    "source_type": rec.source_type,
                    "source_name": rec.source_name,
                    "violations_total": len(rec.violations),
                    "violations_recent_5m": rec.recent_count(300),
                    "threat_types": list(rec.threat_types),
                    "actions_taken": [a.value for a in rec.actions_taken[-10:]],
                    "is_blocked": rec.blocked_until > time.time(),
                    "first_seen_seconds_ago": int(time.time() - rec.first_seen),
                    "last_seen_seconds_ago": int(time.time() - rec.last_seen),
                }
        return {"found": False, "reason": f"no record for source {source_id}"}

    @staticmethod
    def inspect_attack_history(limit: int = 5) -> list[dict]:
        """Recent attack history."""
        attacks = db.get_attack_history(limit=limit)
        return [{
            "type": a["attack_type"],
            "timestamp": a["timestamp"],
            "duration": a.get("duration_seconds", 0),
            "stopped_by": a.get("stopped_by"),
            "detected": bool(a.get("detected_by_defender")),
        } for a in attacks]

    @staticmethod
    def inspect_active_simulations() -> list[dict]:
        """What attacks are currently active in the system."""
        return [{
            "name": imp.attack_name,
            "fake_pid": imp.fake_pid,
            "fake_process": imp.fake_process_name,
            "claimed_cpu": imp.cpu_percent,
            "claimed_memory_mb": imp.memory_mb,
            "running_seconds": int(time.time() - imp.created_at),
        } for imp in sim_engine.active_list()]

    @staticmethod
    def inspect_recent_events(limit: int = 10, level: str | None = None) -> list[dict]:
        """Recent system events."""
        events = db.get_recent_events(limit=limit, level=level)
        return [{
            "ts": e["timestamp"],
            "level": e["level"],
            "category": e["category"],
            "message": e["message"][:120],
        } for e in events]

    @staticmethod
    def wait_and_observe(seconds: int = 3) -> dict:
        """Wait, then snapshot current metric."""
        time.sleep(min(seconds, 8))
        m = db.get_latest_metric() or {}
        return {
            "waited_seconds": seconds,
            "snapshot": {
                "cpu": m.get("cpu_percent", 0),
                "memory": m.get("memory_percent", 0),
                "disk": m.get("disk_percent", 0),
                "active_sims": m.get("simulation_count", 0),
            },
        }

    @staticmethod
    def try_throttle_simulation(simulation_name: str) -> dict:
        """Throttle a simulated attack and observe."""
        for imp in sim_engine.active_list():
            if simulation_name.lower() in imp.attack_name.lower() or simulation_name.lower() in imp.fake_process_name.lower():
                old_cpu = imp.cpu_percent
                imp.cpu_percent *= 0.5
                imp.network_sent_mb *= 0.3
                return {
                    "applied": True,
                    "target": imp.fake_process_name,
                    "cpu_before": old_cpu,
                    "cpu_after": imp.cpu_percent,
                }
        return {"applied": False, "reason": f"no simulation matches '{simulation_name}'"}

    @staticmethod
    def try_terminate_simulation(simulation_name: str) -> dict:
        """Terminate a simulated attack."""
        for imp in sim_engine.active_list():
            if simulation_name.lower() in imp.attack_name.lower() or simulation_name.lower() in imp.fake_process_name.lower():
                target = imp.fake_process_name
                sim_engine.unregister(imp.attack_id)
                return {"terminated": True, "target": target}
        return {"terminated": False, "reason": f"no simulation matches '{simulation_name}'"}


# ============================================================
# Investigation orchestrator
# ============================================================

@dataclass
class InvestigationStep:
    step_num: int
    thought: str
    tool: str
    tool_args: dict
    observation: dict
    elapsed_ms: int = 0
    timestamp: float = field(default_factory=time.time)


@dataclass
class Investigation:
    id: str
    trigger_reason: str
    initial_context: dict
    steps: list[InvestigationStep] = field(default_factory=list)
    final_recommendation: str = ""
    final_action: str = ""
    confidence: float = 0.0
    status: str = "running"  # running | done | failed | limit_reached
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    max_steps: int = 4

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "trigger_reason": self.trigger_reason,
            "initial_context": self.initial_context,
            "steps": [asdict(s) for s in self.steps],
            "final_recommendation": self.final_recommendation,
            "final_action": self.final_action,
            "confidence": self.confidence,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_seconds": round((self.finished_at or time.time()) - self.started_at, 1),
            "step_count": len(self.steps),
        }


SYSTEM_PROMPT = """You are Argus, a senior SOC analyst doing a brief investigation.
You have TOOLS to inspect data and take actions.

OUTPUT FORMAT: ONLY a single valid JSON object. No markdown, no prose.

Schema while investigating:
{
  "thought": "1 short sentence",
  "tool": "<tool name>",
  "tool_args": {...},
  "expected_signal": "what would change your assessment"
}

To END (preferred — be aggressive about ending):
{
  "thought": "what you learned",
  "tool": "finalize",
  "tool_args": {
    "recommendation": "1-2 sentence plain-English summary",
    "action": "alert_only|throttle|sandbox|suspend|terminate|block_ip",
    "confidence": 0.85
  }
}

CRITICAL TIMING RULES:
- Run AT MOST 2 inspection steps before finalizing
- After step 1: if metrics look normal, finalize immediately with action="alert_only"
- After step 2: ALWAYS finalize, don't request more inspections
- Step 3 should be a finalize, never another inspection"""


TOOL_DESCRIPTIONS = """Available tools:
- inspect_metric(name, window_seconds): see metric history. names: cpu, memory, disk, process_count, network_connections
- inspect_offender(source_id): violation history of a source (IP or attack id)
- inspect_attack_history(limit): recent attacks observed
- inspect_active_simulations(): currently running simulated attacks
- inspect_recent_events(limit, level): recent log events. level optional: INFO, WARN, ACTION, AI, SECURITY
- wait_and_observe(seconds): pause N seconds and re-check metrics
- try_throttle_simulation(simulation_name): apply throttle, return effect
- try_terminate_simulation(simulation_name): kill simulation
- finalize: end investigation with recommendation"""


def _format_history(steps: list[InvestigationStep]) -> str:
    if not steps:
        return "(no prior steps)"
    parts = []
    for s in steps:
        parts.append(
            f"Step {s.step_num}: thought={s.thought!r} | "
            f"tool={s.tool}({json.dumps(s.tool_args)}) | "
            f"observation={json.dumps(s.observation)[:300]}"
        )
    return "\n".join(parts)


async def _ai_plan_step(inv: Investigation) -> dict:
    """Ask the LLM to plan the next step."""
    prompt = (
        f"INVESTIGATION TRIGGER: {inv.trigger_reason}\n\n"
        f"INITIAL CONTEXT:\n{json.dumps(inv.initial_context, indent=2, default=str)}\n\n"
        f"{TOOL_DESCRIPTIONS}\n\n"
        f"PRIOR STEPS:\n{_format_history(inv.steps)}\n\n"
        f"Decide the NEXT step. Return JSON only."
    )

    res = await llm.ask(
        prompt=prompt,
        system=SYSTEM_PROMPT,
        topic=None,
        max_tokens=400,
        use_cache=False,
    )

    text = res.get("text", "")
    parsed = extract_json(text)
    if parsed and "tool" in parsed:
        return parsed

    # Last-resort fallback: log raw response for debugging, default to finalize
    log.warning(f"AI plan_step parse failed. Raw response (first 200 chars): {text[:200]!r}")
    return {
        "thought": "Could not parse AI plan; ending investigation safely.",
        "tool": "finalize",
        "tool_args": {
            "recommendation": (
                f"AI returned non-JSON response. Raw preview: {text[:120]!r}. "
                f"Recommend rerunning or checking LLM provider."
            ),
            "action": "alert_only",
            "confidence": 0.3,
        },
    }


async def _execute_tool(tool: str, args: dict) -> dict:
    """Run the chosen tool."""
    tools_map = {
        "inspect_metric":            InvestigatorTools.inspect_metric,
        "inspect_offender":          InvestigatorTools.inspect_offender,
        "inspect_attack_history":    InvestigatorTools.inspect_attack_history,
        "inspect_active_simulations":InvestigatorTools.inspect_active_simulations,
        "inspect_recent_events":     InvestigatorTools.inspect_recent_events,
        "wait_and_observe":          InvestigatorTools.wait_and_observe,
        "try_throttle_simulation":   InvestigatorTools.try_throttle_simulation,
        "try_terminate_simulation":  InvestigatorTools.try_terminate_simulation,
    }
    fn = tools_map.get(tool)
    if not fn:
        return {"error": f"unknown tool '{tool}'"}
    try:
        # Run sync tool in executor (don't block event loop)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: fn(**(args or {})))
    except TypeError as e:
        return {"error": f"tool args invalid: {e}"}
    except Exception as e:  # noqa: BLE001
        return {"error": f"tool failed: {e}"}


async def run_investigation(
    trigger_reason: str,
    initial_context: dict,
    max_steps: int = 3,
) -> Investigation:
    """
    Run a multi-step AI investigation. Each step is broadcast to bus → WS → UI.
    """
    inv = Investigation(
        id=str(uuid.uuid4())[:12],
        trigger_reason=trigger_reason,
        initial_context=initial_context,
        max_steps=max_steps,
    )
    bus.publish("investigation.started", inv.to_dict())
    log.info(f"[Investigation {inv.id}] STARTED: {trigger_reason}")

    for step_num in range(1, max_steps + 1):
        step_start = time.time()

        plan = await _ai_plan_step(inv)
        tool = plan.get("tool", "finalize")

        # Force finalize at the last allowed step (never reach limit_reached)
        if step_num >= max_steps and tool != "finalize":
            tool = "finalize"
            plan["tool"] = "finalize"
            plan["tool_args"] = {
                "recommendation": plan.get("thought", "Investigation auto-finalized at step limit"),
                "action": "alert_only",
                "confidence": 0.5,
            }

        # If finalize, end here
        if tool == "finalize":
            args = plan.get("tool_args", {})
            inv.final_recommendation = args.get("recommendation", "")
            inv.final_action = args.get("action", "alert_only")
            inv.confidence = float(args.get("confidence", 0.5))
            inv.status = "done"

            step = InvestigationStep(
                step_num=step_num,
                thought=plan.get("thought", ""),
                tool="finalize",
                tool_args=args,
                observation={"final": True},
                elapsed_ms=int((time.time() - step_start) * 1000),
            )
            inv.steps.append(step)
            bus.publish("investigation.step", {"investigation_id": inv.id, "step": asdict(step)})
            break

        # Execute tool
        tool_args = plan.get("tool_args", {})
        observation = await _execute_tool(tool, tool_args)

        step = InvestigationStep(
            step_num=step_num,
            thought=plan.get("thought", ""),
            tool=tool,
            tool_args=tool_args,
            observation=observation,
            elapsed_ms=int((time.time() - step_start) * 1000),
        )
        inv.steps.append(step)
        bus.publish("investigation.step", {"investigation_id": inv.id, "step": asdict(step)})
        log.info(f"[Investigation {inv.id}] step {step_num}: {tool} → {str(observation)[:100]}")

    # If we hit max_steps without finalize
    if inv.status == "running":
        inv.status = "limit_reached"
        inv.final_recommendation = "Investigation reached step limit without conclusion. Recommend human review."
        inv.final_action = "alert_only"
        inv.confidence = 0.4

    inv.finished_at = time.time()

    # Persist + broadcast final
    db.insert_event(
        level="AI",
        category="investigation",
        message=f"[Investigation] {inv.status} in {len(inv.steps)} step(s) → {inv.final_action} "
                f"(conf {inv.confidence:.2f}): {inv.final_recommendation[:200]}",
        source="llm:investigator",
        metadata=inv.to_dict(),
    )
    bus.publish("investigation.finished", inv.to_dict())
    log.info(f"[Investigation {inv.id}] FINISHED: {inv.final_action} (conf {inv.confidence:.2f})")
    return inv
