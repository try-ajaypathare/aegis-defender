"""
AI Live Solver — demo-grade step-by-step problem solving.

When a problem is detected (or user manually triggers), the AI runs through:

  1. DETECT   — scan + identify the problem
  2. ANALYZE  — gather context, classify threat
  3. DECIDE   — LLM picks action with reasoning
  4. EXECUTE  — apply the action via simulation
  5. VERIFY   — observe result, confirm fix
  6. REPORT   — final summary

Each stage publishes start + complete events so the UI streams them live
with realistic pacing. Designed for *visible* demos.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from ai import advisor as ai_advisor
from ai.json_extract import extract_json
from ai.llm_client import client as llm
from defender.decision_engine import (
    ACTION_TIER, Action, Decision, threat_from_attack,
)
from shared.event_bus import bus
from shared.logger import get_logger
from shared.simulation import engine as sim_engine
from storage import database as db

log = get_logger("ai-solver")


STAGES = ["detect", "analyze", "decide", "execute", "verify", "report"]
STAGE_TITLES = {
    "detect":  "Scanning the server",
    "analyze": "Analyzing the threat",
    "decide":  "Deciding the response",
    "execute": "Executing the action",
    "verify":  "Verifying the result",
    "report":  "Final report",
}


@dataclass
class SolveSession:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    trigger: str = ""
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    steps: list[dict] = field(default_factory=list)
    success: bool = False
    summary: str = ""


def _publish(session_id: str, payload: dict) -> None:
    bus.publish("ai.solve.event", {**payload, "session_id": session_id})


async def _stage(session: SolveSession, stage: str, body: str, **extra: Any) -> dict:
    step = {
        "stage": stage,
        "title": STAGE_TITLES[stage],
        "body": body,
        "status": "active",
        "started_at": time.time(),
        **extra,
    }
    session.steps.append(step)
    _publish(session.id, {"event": "step_start", "step_index": len(session.steps) - 1, "step": step})
    return step


def _complete_stage(session: SolveSession, body: str | None = None, **extra: Any) -> None:
    if not session.steps:
        return
    step = session.steps[-1]
    step["status"] = "done"
    step["finished_at"] = time.time()
    step["elapsed_ms"] = int((step["finished_at"] - step["started_at"]) * 1000)
    if body is not None:
        step["body"] = body
    step.update(extra)
    _publish(session.id, {"event": "step_done", "step_index": len(session.steps) - 1, "step": step})


# ============================================================
# Stage implementations
# ============================================================

async def _stage_detect(session: SolveSession) -> dict:
    """Find the most concerning issue right now."""
    await _stage(session, "detect", "Scanning metrics, simulations, and recent events…")
    await asyncio.sleep(0.7)

    metric = db.get_latest_metric() or {}
    sims = sim_engine.active_list()

    cpu = metric.get("cpu_percent", 0)
    mem = metric.get("memory_percent", 0)
    disk = metric.get("disk_percent", 0)

    if sims:
        # Pick the most-impactful sim
        worst = max(sims, key=lambda s: s.cpu_percent + (s.memory_mb / 100))
        problem = {
            "type": "active_attack",
            "attack_id": worst.attack_id,
            "attack_name": worst.attack_name,
            "fake_process": worst.fake_process_name,
            "fake_pid": worst.fake_pid,
            "claimed_cpu": worst.cpu_percent,
            "claimed_memory_mb": worst.memory_mb,
            "running_seconds": int(time.time() - worst.created_at),
            "current_cpu": cpu, "current_memory": mem, "current_disk": disk,
        }
        body = (
            f"Detected active attack: {worst.attack_name} "
            f"({worst.fake_process_name}, fake PID {worst.fake_pid}). "
            f"Currently consuming ~{worst.cpu_percent:.0f}% CPU, "
            f"{worst.memory_mb:.0f} MB RAM. Running for {problem['running_seconds']}s."
        )
    elif cpu > 85 or mem > 90 or disk > 95:
        problem = {
            "type": "metric_anomaly", "cpu": cpu, "memory": mem, "disk": disk,
        }
        body = f"No active attack found, but metrics are elevated: CPU {cpu:.0f}%, MEM {mem:.0f}%, Disk {disk:.0f}%."
    else:
        problem = {
            "type": "no_problem", "cpu": cpu, "memory": mem, "disk": disk,
        }
        body = (
            f"System looks healthy — CPU {cpu:.0f}%, MEM {mem:.0f}%, Disk {disk:.0f}%. "
            f"Nothing critical to solve right now."
        )

    _complete_stage(session, body=body, problem=problem)
    return problem


async def _stage_analyze(session: SolveSession, problem: dict) -> dict:
    """Use LLM to classify and contextualize the problem."""
    if problem["type"] == "no_problem":
        await _stage(session, "analyze", "Skipping deep analysis — no active threat.")
        await asyncio.sleep(0.3)
        _complete_stage(session, body="System normal. No further analysis needed.")
        return {"severity": "info", "summary": "system normal"}

    await _stage(session, "analyze", "Asking the LLM to classify the threat…")

    prompt = (
        f"You are a SOC analyst. A problem was detected on the server. "
        f"Classify it in 2-3 short sentences for a status panel.\n\n"
        f"PROBLEM: {problem}\n\n"
        f"Return JSON only:\n"
        f'{{"severity": "info|low|medium|high|critical", '
        f'"summary": "<2-3 sentence plain English>", '
        f'"threat_class": "<short category>"}}'
    )
    res = await llm.ask(
        prompt,
        system="You analyze security telemetry. Reply with strict JSON only — no markdown, no extra text. Keep it terse.",
        topic=None, max_tokens=160, use_cache=False,
    )
    parsed = extract_json(res["text"]) or {
        "severity": "high",
        "summary": f"Auto-classified as {problem.get('attack_name') or 'anomaly'}.",
        "threat_class": problem.get("attack_name", "unknown"),
    }
    _complete_stage(
        session,
        body=parsed.get("summary", ""),
        severity=parsed.get("severity"),
        threat_class=parsed.get("threat_class"),
        provider=res.get("provider"),
        latency_ms=res.get("latency_ms", 0),
    )
    return parsed


async def _stage_decide(session: SolveSession, problem: dict, analysis: dict) -> dict:
    """LLM picks the action."""
    if problem["type"] == "no_problem":
        await _stage(session, "decide", "No action needed.")
        await asyncio.sleep(0.3)
        _complete_stage(session, body="No remediation required.")
        return {"action": None, "reason": "no problem"}

    await _stage(session, "decide", "Asking the LLM to pick the appropriate response…")

    threat_dict = {
        "threat_type": problem.get("attack_name") or "anomaly",
        "severity": analysis.get("severity", "high"),
        "source_type": "process",
        "source_name": problem.get("fake_process") or "anomaly",
        "is_trusted": False,
        "repeat_count": 0,
        "metric_value": problem.get("claimed_cpu") or problem.get("cpu", 0),
        "metric_baseline": 12,  # reasonable baseline
    }
    metric = db.get_latest_metric() or {}
    decision = await ai_advisor.ai_pick_action(threat_dict, metric)

    body = (
        f"Action: {decision.get('action')} — {decision.get('reason', '')}"
    )
    _complete_stage(
        session,
        body=body,
        action=decision.get("action"),
        confidence=decision.get("confidence"),
        reason=decision.get("reason"),
        provider=decision.get("provider"),
        latency_ms=decision.get("latency_ms", 0),
    )
    return decision


async def _stage_execute(session: SolveSession, problem: dict, decision: dict) -> dict:
    """Apply the action."""
    if not decision.get("action") or problem["type"] == "no_problem":
        await _stage(session, "execute", "Skipping execution.")
        await asyncio.sleep(0.2)
        _complete_stage(session, body="Nothing to execute.")
        return {"applied": False}

    action_str = decision["action"]
    await _stage(session, "execute", f"Applying {action_str}…")
    await asyncio.sleep(0.5)

    # Build a Decision and use the executor (so it ties into the simulation engine + offender tracker)
    try:
        chosen = Action(action_str)
    except ValueError:
        chosen = Action.SUSPEND_PROCESS  # safe fallback

    # Build threat from problem (so executor can locate the simulation)
    if problem["type"] == "active_attack":
        attack_dict = {
            "id": problem["attack_id"],
            "name": problem["attack_name"],
            "category": "performance",
        }
        threat = threat_from_attack(attack_dict, severity="high", confidence=0.9)
    else:
        # generic; executor will fall back to top sim
        threat = threat_from_attack(
            {"id": "unknown", "name": "anomaly", "category": "performance"},
            severity="high", confidence=0.7,
        )

    dec = Decision(
        action=chosen,
        risk_score=80.0,
        reasoning=[f"AI Live Solver chose {chosen.value}"],
        rejected_alternatives=[],
        threat=threat,
        expected_outcome="threat resolved",
    )

    # Use the executor
    from defender.executor import Executor
    result = Executor().execute_decision(dec)

    body = result.get("message", f"Applied {action_str}.")
    _complete_stage(session, body=body, applied=bool(result.get("success")), result=result)
    return result


async def _stage_verify(session: SolveSession, problem: dict, exec_result: dict) -> dict:
    """Wait + check the metrics actually improved."""
    if problem["type"] == "no_problem" or not exec_result.get("applied", True):
        await _stage(session, "verify", "Skipping verification (nothing was changed).")
        await asyncio.sleep(0.3)
        _complete_stage(session, body="No verification needed.")
        return {"solved": True}

    await _stage(session, "verify", "Waiting 3 seconds for the system to settle…")
    await asyncio.sleep(3)

    after = db.get_latest_metric() or {}
    cpu_before = problem.get("current_cpu") or problem.get("cpu", 0)
    cpu_after = after.get("cpu_percent", 0)
    mem_before = problem.get("current_memory") or problem.get("memory", 0)
    mem_after = after.get("memory_percent", 0)
    sims_remaining = len(sim_engine.active_list())

    # Solved if metrics dropped significantly OR no active sims remain
    solved = (
        sims_remaining == 0
        or (cpu_after < cpu_before - 20)
        or (mem_after < mem_before - 8)
    )

    body = (
        f"CPU: {cpu_before:.1f}% → {cpu_after:.1f}%   "
        f"MEM: {mem_before:.1f}% → {mem_after:.1f}%   "
        f"Active sims: {sims_remaining}"
    )
    _complete_stage(
        session,
        body=body,
        solved=solved,
        cpu_before=cpu_before, cpu_after=cpu_after,
        mem_before=mem_before, mem_after=mem_after,
        sims_remaining=sims_remaining,
    )
    return {"solved": solved, "cpu_before": cpu_before, "cpu_after": cpu_after}


async def _stage_report(session: SolveSession, problem: dict, analysis: dict,
                        decision: dict, verify: dict) -> str:
    """Final LLM-generated report."""
    if problem["type"] == "no_problem":
        await _stage(session, "report", "Compiling report…")
        await asyncio.sleep(0.4)
        msg = "System is healthy. No action was needed."
        _complete_stage(session, body=msg)
        return msg

    await _stage(session, "report", "Writing the final report…")

    prompt = (
        f"Write a concise security incident report (3-4 sentences). Plain English, no markdown.\n\n"
        f"PROBLEM: {problem.get('attack_name') or problem['type']} on {problem.get('fake_process', 'system')}\n"
        f"SEVERITY: {analysis.get('severity', '?')}\n"
        f"ACTION TAKEN: {decision.get('action', '?')}\n"
        f"REASON: {decision.get('reason', '')}\n"
        f"OUTCOME: {'resolved' if verify.get('solved') else 'still active — requires human review'}\n"
        f"  CPU before: {verify.get('cpu_before', 0):.0f}%, after: {verify.get('cpu_after', 0):.0f}%"
    )
    res = await llm.ask(
        prompt,
        system="You write 2-3 sentence security incident summaries. No markdown, no headings. Be concise.",
        topic=None, max_tokens=140, use_cache=False,
    )
    msg = (res.get("text") or "").strip() or "Report could not be generated."

    _complete_stage(session, body=msg, provider=res.get("provider"), latency_ms=res.get("latency_ms", 0))
    session.success = bool(verify.get("solved"))
    session.summary = msg
    return msg


# ============================================================
# Public entry point
# ============================================================

async def solve_now(trigger: str = "Manual trigger") -> SolveSession:
    """Run the full demo-style solve sequence."""
    session = SolveSession(trigger=trigger)
    bus.publish("ai.solve.event", {
        "event": "session_start",
        "session_id": session.id,
        "trigger": trigger,
        "started_at": session.started_at,
    })
    log.info(f"[Solver {session.id}] START — {trigger}")

    try:
        problem = await _stage_detect(session)
        analysis = await _stage_analyze(session, problem)
        decision = await _stage_decide(session, problem, analysis)
        exec_result = await _stage_execute(session, problem, decision)
        verify = await _stage_verify(session, problem, exec_result)
        await _stage_report(session, problem, analysis, decision, verify)
    except Exception as e:  # noqa: BLE001
        log.error(f"[Solver {session.id}] failed: {e}")
        session.summary = f"Solver crashed: {e}"

    session.finished_at = time.time()
    bus.publish("ai.solve.event", {
        "event": "session_done",
        "session_id": session.id,
        "success": session.success,
        "summary": session.summary,
        "finished_at": session.finished_at,
        "elapsed_seconds": round(session.finished_at - session.started_at, 1),
    })

    db.insert_event(
        level="AI", category="ai_solve",
        message=f"[AI Solve] {'OK' if session.success else 'partial'} in "
                f"{round(session.finished_at - session.started_at, 1)}s — {session.summary[:200]}",
        source="llm:solver",
    )
    log.info(f"[Solver {session.id}] DONE — success={session.success}")
    return session
