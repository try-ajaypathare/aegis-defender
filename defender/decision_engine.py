"""
Decision Engine — multi-tier intelligent defender response.

Key principles:
  1. **Graduated response**: don't kill on first sign of trouble. Escalate from
     observe → throttle → contain → suspend → terminate based on risk score.
  2. **Risk score**: continuous 0-100 score combining severity, confidence,
     reputation, repeat-offender history, and time-of-day context.
  3. **Action catalog**: 14 distinct response actions (not just "kill").
  4. **Repeat-offender tracking**: same source repeating attacks gets escalating
     response automatically (so 1st alert → 2nd throttle → 3rd block).
  5. **Trust system**: whitelisted processes/IPs get more lenient treatment.
  6. **Reasoning chain**: every decision logs WHY (factors that influenced
     score, alternatives considered, rejected options).
"""
from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any


# ============================================================
# Action catalog (all simulated — no real harm)
# ============================================================

class Action(str, Enum):
    """All possible defender response actions, ordered by severity."""
    # Tier 0: Observe
    NONE = "none"
    LOG_ONLY = "log_only"
    ALERT = "alert"
    INCREASE_MONITORING = "increase_monitoring"

    # Tier 1: Limit (preserve forensics, don't terminate)
    THROTTLE_CPU = "throttle_cpu"
    THROTTLE_NETWORK = "throttle_network"
    RATE_LIMIT_SOURCE = "rate_limit_source"
    REQUIRE_CHALLENGE = "require_challenge"   # CAPTCHA-style for WAF

    # Tier 2: Contain (isolate, prevent spread)
    SANDBOX_PROCESS = "sandbox_process"
    BLOCK_NETWORK = "block_network"
    QUARANTINE_FILES = "quarantine_files"

    # Tier 3: Suspend (preserve for analysis)
    SUSPEND_PROCESS = "suspend_process"
    BLOCK_IP_TEMPORARY = "block_ip_temporary"

    # Tier 4: Terminate (last resort)
    KILL_PROCESS = "kill_process"
    KILL_AND_CAPTURE = "kill_and_capture"  # kill + memory dump
    BLOCK_IP_PERMANENT = "block_ip_permanent"

    # Tier 5: Recover
    CLEAR_TEMP = "clear_temp"
    ROLLBACK_CHANGES = "rollback_changes"   # ransomware
    NOTIFY_SOC = "notify_soc"


ACTION_TIER = {
    Action.NONE: 0, Action.LOG_ONLY: 0, Action.ALERT: 0, Action.INCREASE_MONITORING: 0,
    Action.THROTTLE_CPU: 1, Action.THROTTLE_NETWORK: 1, Action.RATE_LIMIT_SOURCE: 1, Action.REQUIRE_CHALLENGE: 1,
    Action.SANDBOX_PROCESS: 2, Action.BLOCK_NETWORK: 2, Action.QUARANTINE_FILES: 2,
    Action.SUSPEND_PROCESS: 3, Action.BLOCK_IP_TEMPORARY: 3,
    Action.KILL_PROCESS: 4, Action.KILL_AND_CAPTURE: 4, Action.BLOCK_IP_PERMANENT: 4,
    Action.CLEAR_TEMP: 0, Action.ROLLBACK_CHANGES: 4, Action.NOTIFY_SOC: 0,
}


# ============================================================
# Threat context
# ============================================================

@dataclass
class ThreatContext:
    """Everything we know about a potential threat at decision time."""

    # Source identification
    source_type: str             # "process", "request", "metric"
    source_id: str               # PID, IP, metric_name
    source_name: str = ""        # process name, request path

    # Threat classification
    threat_type: str = "unknown"  # cpu_attack, sql_injection, ransomware, etc.
    severity: str = "low"         # info, low, medium, high, critical
    confidence: float = 0.5       # 0.0 - 1.0

    # Reputation factors
    is_trusted: bool = False
    is_signed: bool = False       # binary signature trust
    repeat_count: int = 0         # how many violations from this source

    # Context factors
    is_business_hours: bool = True
    is_admin_context: bool = False
    metric_value: float = 0
    metric_baseline: float = 0
    metric_delta: float = 0

    # AI input (optional)
    ai_verdict: dict | None = None

    # Free-form metadata
    metadata: dict = field(default_factory=dict)


@dataclass
class Decision:
    """Output of the decision engine."""
    action: Action
    risk_score: float       # 0-100
    reasoning: list[str]    # ordered list of reasoning steps
    rejected_alternatives: list[tuple[Action, str]]  # (action, why_rejected)
    threat: ThreatContext
    timestamp: float = field(default_factory=time.time)

    # Optional follow-up
    escalation_window_seconds: int = 30  # if same source repeats, escalate
    expected_outcome: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "tier": ACTION_TIER[self.action],
            "risk_score": round(self.risk_score, 1),
            "reasoning": self.reasoning,
            "rejected_alternatives": [
                {"action": a.value, "reason": r} for a, r in self.rejected_alternatives
            ],
            "source_type": self.threat.source_type,
            "source_id": self.threat.source_id,
            "source_name": self.threat.source_name,
            "threat_type": self.threat.threat_type,
            "severity": self.threat.severity,
            "confidence": self.threat.confidence,
            "expected_outcome": self.expected_outcome,
            "timestamp": self.timestamp,
        }


# ============================================================
# Repeat-offender + trust tracking
# ============================================================

@dataclass
class OffenderRecord:
    source_id: str
    source_type: str
    source_name: str
    violations: list[float] = field(default_factory=list)  # timestamps
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    threat_types: set = field(default_factory=set)
    actions_taken: list[Action] = field(default_factory=list)
    blocked_until: float = 0   # epoch — 0 = not blocked

    def add_violation(self, threat_type: str, action: Action) -> None:
        now = time.time()
        self.violations.append(now)
        self.last_seen = now
        self.threat_types.add(threat_type)
        self.actions_taken.append(action)

    def recent_count(self, window_seconds: int = 300) -> int:
        cutoff = time.time() - window_seconds
        return sum(1 for t in self.violations if t > cutoff)


class OffenderTracker:
    """Tracks who has violated, how often, and what response was applied."""

    def __init__(self) -> None:
        self._records: dict[str, OffenderRecord] = {}

    def key(self, source_type: str, source_id: str) -> str:
        return f"{source_type}:{source_id}"

    def record(self, threat: ThreatContext, action: Action) -> OffenderRecord:
        k = self.key(threat.source_type, threat.source_id)
        rec = self._records.get(k)
        if not rec:
            rec = OffenderRecord(
                source_id=threat.source_id,
                source_type=threat.source_type,
                source_name=threat.source_name,
            )
            self._records[k] = rec
        rec.add_violation(threat.threat_type, action)
        return rec

    def get(self, source_type: str, source_id: str) -> OffenderRecord | None:
        return self._records.get(self.key(source_type, source_id))

    def repeat_count(self, source_type: str, source_id: str) -> int:
        rec = self.get(source_type, source_id)
        return rec.recent_count() if rec else 0

    def is_blocked(self, source_type: str, source_id: str) -> bool:
        rec = self.get(source_type, source_id)
        return bool(rec and rec.blocked_until > time.time())

    def block_for(self, source_type: str, source_id: str, seconds: int) -> None:
        rec = self.get(source_type, source_id)
        if rec:
            rec.blocked_until = time.time() + seconds

    def top_offenders(self, n: int = 10) -> list[OffenderRecord]:
        return sorted(self._records.values(), key=lambda r: len(r.violations), reverse=True)[:n]

    def cleanup_old(self, max_age_hours: int = 24) -> None:
        cutoff = time.time() - max_age_hours * 3600
        for k in list(self._records):
            if self._records[k].last_seen < cutoff:
                del self._records[k]


class TrustSystem:
    """Manages trusted processes and internal IP ranges. Persists to disk."""

    DEFAULT_PROCESSES = {
        "systemd", "init", "kthreadd", "kworker", "ssh", "sshd",
        "argus-daemon", "argus", "prometheus", "node_exporter", "journald",
    }
    DEFAULT_IP_PREFIXES = [
        "127.", "10.",
        "192.168.",
        "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
    ]

    def __init__(self) -> None:
        from storage import persistence
        # Restore extra trusted processes that user added previously
        saved_extra = persistence.get("trusted_processes_extra", [])
        self.trusted_process_names: set = set(self.DEFAULT_PROCESSES) | set(saved_extra)
        saved_ips = persistence.get("trusted_ip_prefixes_extra", [])
        self.trusted_ip_prefixes: list = list(self.DEFAULT_IP_PREFIXES) + list(saved_ips)

    def is_trusted_process(self, name: str) -> bool:
        return name.lower() in {p.lower() for p in self.trusted_process_names}

    def is_trusted_ip(self, ip: str) -> bool:
        return any(ip.startswith(p) for p in self.trusted_ip_prefixes)

    def add_trusted_process(self, name: str) -> None:
        self.trusted_process_names.add(name)
        from storage import persistence
        extra = sorted(self.trusted_process_names - self.DEFAULT_PROCESSES)
        persistence.update("trusted_processes_extra", extra)

    def remove_trusted_process(self, name: str) -> bool:
        """Returns True if removed; default-protected names cannot be removed."""
        if name in self.DEFAULT_PROCESSES:
            return False
        if name in self.trusted_process_names:
            self.trusted_process_names.discard(name)
            from storage import persistence
            extra = sorted(self.trusted_process_names - self.DEFAULT_PROCESSES)
            persistence.update("trusted_processes_extra", extra)
            return True
        return False


# Global instances
offenders = OffenderTracker()
trust = TrustSystem()


# ============================================================
# Decision Engine
# ============================================================

class DecisionEngine:
    """Smart, multi-tier defender decision logic."""

    SEVERITY_WEIGHTS = {"info": 5, "low": 15, "medium": 35, "high": 65, "critical": 90}

    def decide(self, threat: ThreatContext) -> Decision:
        """
        Main entry point — given a threat context, decide what to do.

        Steps:
         1. Compute risk score (deterministic)
         2. Look up any prior history (repeat offender escalation)
         3. Pick action based on score + threat type + reputation
         4. Build reasoning chain
        """
        # ---- 1. Risk score ----
        score = self._compute_risk_score(threat)

        # ---- 2. Repeat offender ----
        prior = offenders.get(threat.source_type, threat.source_id)
        if prior:
            threat.repeat_count = prior.recent_count(window_seconds=300)
            score = self._apply_escalation(score, prior)

        # ---- 3. Pick action ----
        action, rejected, reasoning, expected = self._select_action(score, threat, prior)

        # Build full reasoning trail
        full_reasoning = self._build_reasoning(score, threat, prior, reasoning)

        decision = Decision(
            action=action,
            risk_score=score,
            reasoning=full_reasoning,
            rejected_alternatives=rejected,
            threat=threat,
            expected_outcome=expected,
        )

        # ---- 4. Record for future escalation ----
        if action != Action.NONE:
            offenders.record(threat, action)

        return decision

    # -------- Risk scoring --------

    def _compute_risk_score(self, threat: ThreatContext) -> float:
        score = self.SEVERITY_WEIGHTS.get(threat.severity, 15)
        # Confidence multiplier
        score *= max(0.3, threat.confidence)

        # Trust reduction
        if threat.is_trusted:
            score *= 0.25
        if threat.is_signed:
            score *= 0.7

        # Time-of-day boost (out-of-hours = more suspicious)
        if not threat.is_business_hours:
            score *= 1.15

        # Metric delta amplification (big jumps from baseline = scarier)
        if threat.metric_delta and threat.metric_baseline:
            delta_ratio = threat.metric_delta / max(1, threat.metric_baseline)
            score *= 1 + min(0.3, delta_ratio)

        return min(100, max(0, score))

    def _apply_escalation(self, score: float, prior: OffenderRecord) -> float:
        """Same source repeating violations → boost score."""
        recent = prior.recent_count(window_seconds=300)
        # +10 score per repeat (caps the climb)
        boost = min(30, recent * 8)
        return min(100, score + boost)

    # -------- Action selection --------

    def _select_action(
        self,
        score: float,
        threat: ThreatContext,
        prior: OffenderRecord | None,
    ) -> tuple[Action, list[tuple[Action, str]], list[str], str]:
        """
        Pick action based on risk score + threat type.
        Returns (action, [(rejected_action, why_rejected), ...], extra_reasoning, expected_outcome).
        """
        rejected: list[tuple[Action, str]] = []
        reasoning: list[str] = []

        # --- Trusted source: never escalate beyond alert ---
        if threat.is_trusted:
            rejected.append((Action.KILL_PROCESS, "source is trusted"))
            rejected.append((Action.SUSPEND_PROCESS, "source is trusted"))
            return Action.LOG_ONLY, rejected, ["Source trusted — log for audit only"], "no impact"

        # --- Score-based tier selection ---
        # Tier 0: Observe (0-30)
        if score < 30:
            action = Action.ALERT if score >= 15 else Action.LOG_ONLY
            return action, rejected, [
                f"Risk score {score:.0f} below intervention threshold",
                "First time observing — alert and watch",
            ], "monitored, no resource impact"

        # Tier 1: Throttle/Limit (30-50)
        if score < 50:
            action = self._tier_1_action(threat)
            rejected.append((Action.KILL_PROCESS, "premature — try non-destructive first"))
            rejected.append((Action.SUSPEND_PROCESS, "preserve forensics, just limit"))
            return action, rejected, [
                f"Risk {score:.0f} → graduated response (limit, not terminate)",
                f"Chose {action.value} to preserve evidence + business continuity",
            ], "resource use capped, behavior observable"

        # Tier 2: Contain (50-70)
        if score < 70:
            action = self._tier_2_action(threat)
            rejected.append((Action.LOG_ONLY, "score too high to ignore"))
            rejected.append((Action.KILL_PROCESS, "isolation preferred over termination"))
            return action, rejected, [
                f"Risk {score:.0f} → contain to prevent lateral spread",
                f"{action.value} preserves the threat for analysis while stopping damage",
            ], "threat isolated, system protected"

        # Tier 3: Suspend / Block (70-85)
        if score < 85:
            action = self._tier_3_action(threat)
            rejected.append((Action.THROTTLE_CPU, f"score {score:.0f} too high for soft response"))
            rejected.append((Action.KILL_PROCESS, "suspend first to enable forensics"))
            return action, rejected, [
                f"Risk {score:.0f} → must stop activity now",
                f"{action.value} freezes the threat without destroying evidence",
            ], "threat halted, available for investigation"

        # Tier 4: Terminate (85-100)
        action = self._tier_4_action(threat)
        rejected.append((Action.SUSPEND_PROCESS, f"score {score:.0f} requires immediate termination"))
        rejected.append((Action.THROTTLE_CPU, "incompatible with critical threat"))
        return action, rejected, [
            f"Risk {score:.0f} → critical, immediate termination",
            f"{action.value} chosen — capture forensics on the way out",
        ], "threat eliminated"

    # -------- Per-tier action picking based on threat type --------

    def _tier_1_action(self, threat: ThreatContext) -> Action:
        if threat.source_type == "request":
            return Action.RATE_LIMIT_SOURCE
        if "cpu" in threat.threat_type.lower():
            return Action.THROTTLE_CPU
        if "network" in threat.threat_type.lower() or "ddos" in threat.threat_type.lower():
            return Action.THROTTLE_NETWORK
        return Action.INCREASE_MONITORING

    def _tier_2_action(self, threat: ThreatContext) -> Action:
        if threat.source_type == "request":
            return Action.REQUIRE_CHALLENGE
        if "ransomware" in threat.threat_type.lower():
            return Action.QUARANTINE_FILES
        if "network" in threat.threat_type.lower() or "exfil" in threat.threat_type.lower():
            return Action.BLOCK_NETWORK
        return Action.SANDBOX_PROCESS

    def _tier_3_action(self, threat: ThreatContext) -> Action:
        if threat.source_type == "request":
            return Action.BLOCK_IP_TEMPORARY
        return Action.SUSPEND_PROCESS

    def _tier_4_action(self, threat: ThreatContext) -> Action:
        if threat.source_type == "request":
            return Action.BLOCK_IP_PERMANENT
        if "ransomware" in threat.threat_type.lower():
            return Action.ROLLBACK_CHANGES
        # Critical threats get forensic capture
        if threat.severity == "critical":
            return Action.KILL_AND_CAPTURE
        return Action.KILL_PROCESS

    # -------- Reasoning chain --------

    def _build_reasoning(
        self,
        score: float,
        threat: ThreatContext,
        prior: OffenderRecord | None,
        extra: list[str],
    ) -> list[str]:
        reasons = []
        # Severity factor
        sev_weight = self.SEVERITY_WEIGHTS.get(threat.severity, 0)
        reasons.append(
            f"Severity {threat.severity!r} contributes {sev_weight} base points"
        )
        # Confidence
        reasons.append(
            f"Confidence {threat.confidence:.2f} → multiplier × {max(0.3, threat.confidence):.2f}"
        )
        # Trust
        if threat.is_trusted:
            reasons.append("Source TRUSTED → score reduced 75%")
        elif threat.is_signed:
            reasons.append("Source SIGNED → score reduced 30%")
        # Repeat
        if prior and threat.repeat_count > 0:
            reasons.append(
                f"REPEAT OFFENDER: {threat.repeat_count} violation(s) in last 5 min "
                f"→ +{min(30, threat.repeat_count*8)} score boost"
            )
        # Time
        if not threat.is_business_hours:
            reasons.append("Outside business hours → +15% suspicion multiplier")
        # Final score
        reasons.append(f"=> Final risk score: {score:.0f}/100")
        # Extra contextual
        reasons.extend(extra)
        return reasons


# Global engine
engine = DecisionEngine()


# ============================================================
# Convenience builders
# ============================================================

def threat_from_metric(
    metric_key: str,
    value: float,
    baseline: float,
    severity: str,
    threat_type: str,
    confidence: float = 0.85,
) -> ThreatContext:
    """Build threat from a metric breach (e.g. CPU spike)."""
    delta = value - baseline
    is_business = 8 <= datetime.now().hour <= 19
    return ThreatContext(
        source_type="metric",
        source_id=metric_key,
        source_name=metric_key.upper(),
        threat_type=threat_type,
        severity=severity,
        confidence=confidence,
        is_business_hours=is_business,
        metric_value=value,
        metric_baseline=baseline,
        metric_delta=delta,
    )


def threat_from_attack(attack: dict, severity: str = "high", confidence: float = 0.9) -> ThreatContext:
    """Build threat from an active simulated attack."""
    name = attack.get("name", "unknown")
    is_business = 8 <= datetime.now().hour <= 19
    return ThreatContext(
        source_type="process",
        source_id=str(attack.get("id", "")),
        source_name=f"sim_{name}.exe",
        threat_type=name,
        severity=severity,
        confidence=confidence,
        is_business_hours=is_business,
        is_trusted=trust.is_trusted_process(name),
        metadata={"attack_id": attack.get("id"), "category": attack.get("category")},
    )


def threat_from_request(request: dict, ai_verdict: dict | None = None) -> ThreatContext:
    """Build threat from a simulated WAF request."""
    src_ip = request.get("source_ip", "")
    pattern = request.get("pattern", "unknown")
    sev_map = {
        "credential_stuffing": "high",
        "sql_injection": "critical",
        "path_traversal": "high",
        "xss": "high",
        "recon_scanner": "medium",
        "ddos_volumetric": "high",
        "api_scraping": "medium",
        "normal_browse": "info",
        "normal_api": "info",
    }
    severity = sev_map.get(pattern, "low")

    confidence = 0.85
    if ai_verdict and "confidence" in ai_verdict:
        confidence = float(ai_verdict["confidence"])

    is_business = 8 <= datetime.now().hour <= 19

    return ThreatContext(
        source_type="request",
        source_id=src_ip,
        source_name=f"{request.get('method', '?')} {request.get('path', '')[:40]}",
        threat_type=pattern,
        severity=severity,
        confidence=confidence,
        is_business_hours=is_business,
        is_trusted=trust.is_trusted_ip(src_ip),
        ai_verdict=ai_verdict,
        metadata={"request": request, "ai": ai_verdict},
    )
