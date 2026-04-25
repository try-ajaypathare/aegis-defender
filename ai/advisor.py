"""
AI Advisor — uses LLM to explain, diagnose, and verify.

Key functions:
- explain_server(): human-friendly status summary
- analyze_threat(metrics, active_attacks): recommend action
- verify_solved(before, after, action): check if remediation worked
- handle_fake_request(req): simulated WAF — AI decides response

All functions use the llm_client with caching + rate limits.
"""
from __future__ import annotations

import json
from typing import Any

from ai.json_extract import extract_json
from ai.llm_client import client as llm


SYSTEM_PROMPTS = {
    "explain": (
        "You are Argus, a concise security operations AI. Given system metrics, "
        "explain in 2-3 short sentences what the system is doing right now. "
        "Be direct, use plain English. No markdown, no headers."
    ),
    "analyze": (
        "You are Argus, a security decision engine. Given system metrics + active simulated attacks, "
        "return a JSON object with: {\"action\": <one of: kill_top_cpu, kill_top_memory, clear_temp, alert_only, none>, "
        "\"severity\": <low|medium|high|critical>, \"reason\": <short 1-sentence why>, "
        "\"confidence\": <0.0-1.0>}. Return ONLY JSON, no markdown."
    ),
    "verify": (
        "You are Argus verification. Compare before/after metrics + what action was taken. "
        "Return JSON: {\"solved\": <true|false>, \"confidence\": <0.0-1.0>, \"summary\": <1-sentence>}. "
        "Return ONLY JSON, no markdown."
    ),
    "request": (
        "You are Argus WAF AI. Given a simulated HTTP request, decide if it's malicious. "
        "Return JSON: {\"verdict\": <allow|block|challenge>, \"threat_type\": <string>, "
        "\"confidence\": <0.0-1.0>, \"reason\": <short sentence>, "
        "\"action\": <one of: log_only, alert, block_ip, simulate_kill>}. Return ONLY JSON, no markdown."
    ),
}


def _extract_json(text: str) -> dict[str, Any] | None:
    """Robust JSON extraction (handles fences, prose, nested objects)."""
    return extract_json(text)


async def explain_server(metrics: dict[str, Any], active_attacks: list[dict[str, Any]]) -> dict[str, Any]:
    """Plain-English status summary."""
    prompt = (
        f"Current metrics:\n"
        f"  CPU: {metrics.get('cpu_percent', 0):.1f}%\n"
        f"  Memory: {metrics.get('memory_percent', 0):.1f}% ({metrics.get('memory_used_gb', 0):.1f}GB)\n"
        f"  Disk: {metrics.get('disk_percent', 0):.1f}%\n"
        f"  Processes: {metrics.get('process_count', 0)}\n"
        f"  Network connections: {metrics.get('network_connections', 0)}\n"
        f"  AI anomaly score: {metrics.get('anomaly_score', 0):.2f}\n"
        f"Active simulated attacks: {len(active_attacks)}"
        + (f" ({', '.join(a.get('name', '?') for a in active_attacks)})" if active_attacks else "")
        + "\nExplain briefly."
    )
    res = await llm.ask(prompt, system=SYSTEM_PROMPTS["explain"], topic="explain", max_tokens=256)
    return {
        "text": res["text"],
        "provider": res["provider"],
        "cached": res["cached"],
        "latency_ms": res["latency_ms"],
    }


async def analyze_threat(metrics: dict[str, Any], active_attacks: list[dict[str, Any]]) -> dict[str, Any]:
    """AI-recommended action as structured JSON."""
    prompt = (
        f"Metrics: {json.dumps({k: metrics.get(k) for k in ('cpu_percent', 'memory_percent', 'disk_percent', 'process_count', 'anomaly_score')})}\n"
        f"Active attacks: {[{'name': a.get('name'), 'category': a.get('category'), 'duration': a.get('duration')} for a in active_attacks]}\n"
        f"What should the defender do?"
    )
    res = await llm.ask(prompt, system=SYSTEM_PROMPTS["analyze"], topic="analyze", max_tokens=256)
    parsed = _extract_json(res["text"]) or {
        "action": "alert_only",
        "severity": "low",
        "reason": "AI response could not be parsed, defaulting to alert",
        "confidence": 0.3,
    }
    return {**parsed, "provider": res["provider"], "cached": res["cached"], "latency_ms": res["latency_ms"]}


async def verify_solved(
    before: dict[str, Any],
    after: dict[str, Any],
    action: str,
) -> dict[str, Any]:
    """Ask AI if problem is actually solved."""
    prompt = (
        f"Action taken: {action}\n"
        f"BEFORE metrics: CPU={before.get('cpu_percent')}%, MEM={before.get('memory_percent')}%, "
        f"anomaly={before.get('anomaly_score', 0):.2f}\n"
        f"AFTER metrics:  CPU={after.get('cpu_percent')}%, MEM={after.get('memory_percent')}%, "
        f"anomaly={after.get('anomaly_score', 0):.2f}\n"
        f"Is the problem solved?"
    )
    res = await llm.ask(prompt, system=SYSTEM_PROMPTS["verify"], topic="verify", max_tokens=256)
    parsed = _extract_json(res["text"]) or {
        "solved": False,
        "confidence": 0.3,
        "summary": "AI response could not be parsed",
    }
    return {**parsed, "provider": res["provider"], "cached": res["cached"], "latency_ms": res["latency_ms"]}


async def handle_fake_request(request: dict[str, Any]) -> dict[str, Any]:
    """
    WAF AI: decide verdict for a simulated HTTP request.
    request = {method, path, source_ip, user_agent, payload_snippet, headers, ...}
    """
    prompt = (
        f"Incoming simulated request:\n"
        f"  Method: {request.get('method')}\n"
        f"  Path: {request.get('path')}\n"
        f"  Source IP: {request.get('source_ip')}\n"
        f"  User-Agent: {request.get('user_agent', '-')[:80]}\n"
        f"  Payload: {str(request.get('payload', ''))[:200]}\n"
        f"  Source pattern: {request.get('pattern', 'unknown')}\n"
        f"Decide the response."
    )
    # No topic-rate-limiting for WAF — each unique request should be analyzed.
    # Cache still prevents duplicate-prompt calls.
    res = await llm.ask(prompt, system=SYSTEM_PROMPTS["request"], topic=None,
                         max_tokens=256, use_cache=True)
    parsed = _extract_json(res["text"]) or {
        "verdict": "allow",
        "threat_type": "unknown",
        "confidence": 0.3,
        "reason": "AI parse error, defaulting to allow with logging",
        "action": "log_only",
    }
    return {**parsed, "provider": res["provider"], "cached": res["cached"], "latency_ms": res["latency_ms"]}


async def ai_pick_action(threat: dict, current_metric: dict) -> dict[str, Any]:
    """
    Pure AI mode: LLM picks the action directly (no rule engine).
    Returns: {action, severity, confidence, reason, alternatives_considered}
    """
    system = """You are Argus security AI on an active production server. You decide the response action for a CONFIRMED threat.

CRITICAL: Respond with ONLY a single JSON object. No markdown, no prose.

Available actions (pick exactly one):
  Tier 0 (observe):   alert, log_only, increase_monitoring
  Tier 1 (limit):     throttle_cpu, throttle_network, rate_limit_source
  Tier 2 (contain):   sandbox_process, block_network, quarantine_files
  Tier 3 (suspend):   suspend_process, block_ip_temporary
  Tier 4 (terminate): kill_process, kill_and_capture, block_ip_permanent

Schema:
{
  "action": "<exact name from above>",
  "severity": "info|low|medium|high|critical",
  "confidence": 0.85,
  "reason": "1-2 sentence justification",
  "alternatives_considered": [
    {"action": "<other action>", "rejected_because": "<why>"}
  ]
}

DECISION RULES — FOLLOW STRICTLY:
1. If `is_trusted=true`: use Tier 0 only (log_only or alert).
2. If source_name starts with `sim_` or contains known malware names (xmrig, encrypt_sim, revshell): treat as CONFIRMED malicious — pick Tier 3 or Tier 4.
3. If CPU >95% AND threat is process-based: minimum Tier 2 (sandbox or stronger). DO NOT use alert_only.
4. If memory >90% AND threat is process-based: minimum Tier 2.
5. If repeat_count >= 3: escalate one tier above what you'd otherwise pick.
6. If severity is "critical": pick Tier 3 or Tier 4 unless source is trusted.
7. NEVER pick `alert_only` or `log_only` for an active simulated attack — those don't stop the attack.
8. NEVER pick `increase_monitoring` for an attack already at >85% CPU.

When in doubt for an active attack, prefer SUSPEND_PROCESS (Tier 3) — it stops the threat without losing forensics."""

    is_active_sim = bool(threat.get("source_name", "").startswith("sim_") or threat.get("source_name", "").startswith("xmrig") or "encrypt_sim" in threat.get("source_name", ""))

    prompt = (
        f"THREAT:\n"
        f"  type: {threat.get('threat_type')}\n"
        f"  severity hint: {threat.get('severity')}\n"
        f"  source: {threat.get('source_type')}={threat.get('source_name')}\n"
        f"  is_trusted: {threat.get('is_trusted')}\n"
        f"  repeat_count: {threat.get('repeat_count', 0)}\n"
        f"  metric_value: {threat.get('metric_value')}\n"
        f"  metric_baseline: {threat.get('metric_baseline')}\n"
        f"  is_active_simulation: {is_active_sim}\n\n"
        f"CURRENT SYSTEM:\n"
        f"  CPU: {current_metric.get('cpu_percent', 0):.1f}%\n"
        f"  Memory: {current_metric.get('memory_percent', 0):.1f}%\n"
        f"  Disk: {current_metric.get('disk_percent', 0):.1f}%\n"
        f"  Anomaly: {current_metric.get('anomaly_score', 0):.2f}\n\n"
        + (
            "CONTEXT: This is a CONFIRMED active malicious simulation. "
            "Do NOT use alert_only or increase_monitoring. Pick Tier 2+.\n\n"
            if is_active_sim else ""
        ) +
        f"Pick the action that will actually STOP this threat."
    )

    res = await llm.ask(prompt, system=system, topic=None, max_tokens=200, use_cache=False)
    parsed = _extract_json(res["text"]) or {
        "action": "suspend_process",  # safer default than alert
        "severity": threat.get("severity", "high"),
        "confidence": 0.5,
        "reason": "AI parse failed; defaulting to suspend (Tier 3) for safety",
        "alternatives_considered": [],
    }

    # Hard guard: if AI picked too-soft action for clear active threat, escalate
    weak_actions = {"alert", "log_only", "increase_monitoring"}
    if is_active_sim and parsed.get("action") in weak_actions and not threat.get("is_trusted"):
        parsed["action"] = "suspend_process"
        parsed["reason"] = (
            f"AI initially chose {parsed.get('action')!r} for an active malicious "
            f"simulation; engine guardrail escalated to suspend_process."
        )

    parsed["provider"] = res.get("provider")
    parsed["latency_ms"] = res.get("latency_ms", 0)
    return parsed


async def chat(user_message: str, context: str = "") -> dict[str, Any]:
    """Free-form chat about the server / defender / attacks."""
    system = (
        "You are Argus, a friendly security assistant for a simulated defender dashboard. "
        "Answer concisely in 2-4 sentences. Focus on the user's specific question."
    )
    prompt = f"Context: {context}\n\nUser: {user_message}" if context else user_message
    res = await llm.ask(prompt, system=system, topic=None, max_tokens=512, use_cache=False)
    return res
