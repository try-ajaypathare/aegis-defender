"""
Defender FastAPI application.
Serves dashboard UI + REST/WebSocket endpoints.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from fastapi import Body, Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from ai import advisor as ai_advisor
from ai import trainer
from ai.investigator import run_investigation
from ai.live_solver import solve_now as ai_solve_now
from ai.llm_client import client as llm
from ai.predictor import Predictor
from attacker import fake_requests
from attacker.safety_guard import guard
from defender import system_info
from defender.decision_engine import (
    ACTION_TIER,
    engine as decision_engine,
    offenders,
    threat_from_request,
    trust,
)
from defender.defense_mode import DefenseMode, state as mode_state
from defender.executor import Executor
from shared.auth import verify_token
from shared.config_loader import get_config
from shared.event_bus import Topics, bus
from shared.logger import get_logger
from storage import database as db

log = get_logger("defender-api")


UI_DIR = Path(__file__).resolve().parent.parent / "ui"


class ConnectionManager:
    """Thread-safe WebSocket connection manager.

    Critical: the event bus subscribers run in worker threads (monitor, watchers),
    which have no running asyncio loop. We capture the server's loop at startup
    and use run_coroutine_threadsafe to schedule broadcasts safely.
    """

    def __init__(self) -> None:
        self.active: list[WebSocket] = []
        self.loop: asyncio.AbstractEventLoop | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, payload: dict) -> None:
        dead = []
        for ws in list(self.active):
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    def schedule_broadcast(self, payload: dict) -> None:
        """Safe to call from any thread."""
        if self.loop and self.loop.is_running():
            try:
                asyncio.run_coroutine_threadsafe(self.broadcast(payload), self.loop)
            except Exception as e:  # noqa: BLE001
                log.debug(f"schedule_broadcast failed: {e}")


def create_app(predictor: Predictor | None = None, orchestrator = None) -> FastAPI:
    app = FastAPI(title="Argus Defender", version="1.0.0")

    # CORS — allow attacker dashboard (port 8001) to read defender metrics
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:8001", "http://localhost:8001"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    if UI_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(UI_DIR)), name="static")

    ws_manager = ConnectionManager()

    @app.on_event("startup")
    async def _startup() -> None:
        loop = asyncio.get_running_loop()
        ws_manager.set_loop(loop)
        if orchestrator is not None:
            orchestrator.set_loop(loop)
        log.info("WebSocket + AI orchestrator loop attached")

    # Wire event bus → WebSocket (thread-safe)
    bus.subscribe(Topics.METRIC_COLLECTED,
                  lambda d: ws_manager.schedule_broadcast({"type": "metric", "data": d}))
    bus.subscribe(Topics.ACTION_EXECUTED,
                  lambda d: ws_manager.schedule_broadcast({"type": "action", "data": d}))
    bus.subscribe(Topics.SECURITY_ALERT,
                  lambda d: ws_manager.schedule_broadcast({"type": "security", "data": d}))
    bus.subscribe(Topics.PROCESS_SUSPICIOUS,
                  lambda d: ws_manager.schedule_broadcast({"type": "suspicious_process", "data": d}))
    bus.subscribe(Topics.NETWORK_ALERT,
                  lambda d: ws_manager.schedule_broadcast({"type": "network_alert", "data": d}))
    bus.subscribe(Topics.USB_EVENT,
                  lambda d: ws_manager.schedule_broadcast({"type": "usb", "data": d}))
    bus.subscribe(Topics.ATTACK_STARTED,
                  lambda d: ws_manager.schedule_broadcast({"type": "attack_started", "data": d}))
    bus.subscribe(Topics.ATTACK_STOPPED,
                  lambda d: ws_manager.schedule_broadcast({"type": "attack_stopped", "data": d}))
    bus.subscribe("ai.advice",
                  lambda d: ws_manager.schedule_broadcast({"type": "ai_advice", "data": d}))
    bus.subscribe("ai.verify",
                  lambda d: ws_manager.schedule_broadcast({"type": "ai_verify", "data": d}))
    bus.subscribe("fake_request.processed",
                  lambda d: ws_manager.schedule_broadcast({"type": "fake_request", "data": d}))
    bus.subscribe("defender.decision",
                  lambda d: ws_manager.schedule_broadcast({"type": "defender_decision", "data": d}))
    bus.subscribe("investigation.started",
                  lambda d: ws_manager.schedule_broadcast({"type": "investigation_started", "data": d}))
    bus.subscribe("investigation.step",
                  lambda d: ws_manager.schedule_broadcast({"type": "investigation_step", "data": d}))
    bus.subscribe("investigation.finished",
                  lambda d: ws_manager.schedule_broadcast({"type": "investigation_finished", "data": d}))
    bus.subscribe("defense_mode.changed",
                  lambda d: ws_manager.schedule_broadcast({"type": "defense_mode", "data": d}))
    bus.subscribe("ai.solve.event",
                  lambda d: ws_manager.schedule_broadcast({"type": "ai_solve", "data": d}))

    # ---------- Routes ----------

    @app.get("/")
    async def root():
        index = UI_DIR / "defender.html"
        if index.exists():
            return FileResponse(index)
        return {"name": "Argus Defender", "status": "UI not found"}

    @app.get("/api/metrics/current", dependencies=[Depends(verify_token)])
    async def current_metric():
        m = db.get_latest_metric() or {}
        # Overlay live simulation state (not persisted in DB)
        from shared.simulation import engine as sim_engine
        m["simulation_active"] = sim_engine.has_any()
        m["simulation_count"] = len(sim_engine.active_list())
        return m

    @app.get("/api/metrics/history", dependencies=[Depends(verify_token)])
    async def history(hours: float = 1):
        return db.get_metrics_since(hours=int(max(1, hours)))

    @app.get("/api/events", dependencies=[Depends(verify_token)])
    async def events(limit: int = 50, level: str | None = None):
        return db.get_recent_events(limit=limit, level=level)

    @app.get("/api/actions", dependencies=[Depends(verify_token)])
    async def actions(limit: int = 20):
        return db.get_recent_actions(limit=limit)

    @app.get("/api/stats/summary", dependencies=[Depends(verify_token)])
    async def summary():
        latest = db.get_latest_metric() or {}
        total_metrics = db.count_metrics()
        return {
            "current": latest,
            "samples_collected": total_metrics,
            "ai_ready": predictor.ready if predictor else False,
            "ai_engine": get_config().ai.engine,
            "ws_clients": len(ws_manager.active),
        }

    @app.get("/api/ai/status", dependencies=[Depends(verify_token)])
    async def ai_status():
        return {
            "ready": predictor.ready if predictor else False,
            "engine": get_config().ai.engine,
            "samples_available": db.count_metrics(),
            "min_samples_required": get_config().ai.min_samples_for_training,
        }

    @app.post("/api/ai/retrain", dependencies=[Depends(verify_token)])
    async def retrain():
        result = trainer.train_all()
        if predictor:
            predictor.reload()
        return result

    @app.get("/api/rules", dependencies=[Depends(verify_token)])
    async def list_rules():
        return db.list_custom_rules(enabled_only=False)

    @app.post("/api/rules", dependencies=[Depends(verify_token)])
    async def add_rule(rule: dict = Body(...)):
        required = {"name", "metric", "operator", "threshold", "action"}
        if not required.issubset(rule):
            raise HTTPException(400, f"Missing required: {required - set(rule)}")
        rule_id = db.add_custom_rule(rule)
        return {"id": rule_id}

    @app.delete("/api/rules/{rule_id}", dependencies=[Depends(verify_token)])
    async def delete_rule(rule_id: int):
        db.delete_custom_rule(rule_id)
        return {"success": True}

    @app.post("/api/feedback", dependencies=[Depends(verify_token)])
    async def feedback(payload: dict = Body(...)):
        metric_id = payload.get("metric_id")
        fb_type = payload.get("type", "false_positive")
        note = payload.get("note")
        if not metric_id:
            raise HTTPException(400, "metric_id required")
        fid = db.insert_feedback(metric_id, fb_type, note)
        return {"id": fid}

    @app.get("/api/security/suspicious_processes", dependencies=[Depends(verify_token)])
    async def suspicious():
        return db.get_suspicious_processes(limit=50)

    # ---------- New info-rich endpoints ----------

    @app.get("/api/system/info", dependencies=[Depends(verify_token)])
    async def system_info_ep():
        return system_info.get_system_info()

    @app.get("/api/system/top_processes", dependencies=[Depends(verify_token)])
    async def top_processes(n: int = 10):
        return system_info.get_top_processes(n=n)

    @app.get("/api/system/network_connections", dependencies=[Depends(verify_token)])
    async def network_conns(limit: int = 15):
        return system_info.get_network_connections(limit=limit)

    @app.get("/api/stats/detection", dependencies=[Depends(verify_token)])
    async def detection_stats():
        return system_info.get_detection_stats()

    @app.get("/api/stats/baseline", dependencies=[Depends(verify_token)])
    async def baseline_snapshot():
        if orchestrator is None:
            return {"ready": False}
        return orchestrator.rules.snapshot()

    # ========================================================================
    # Aegis state endpoints (services / security / network / infra)
    # ========================================================================

    @app.get("/api/services", dependencies=[Depends(verify_token)])
    async def services_list():
        from shared.state import service_state
        return {"services": service_state.all_dict()}

    @app.post("/api/services/{service_id}/restart", dependencies=[Depends(verify_token)])
    async def restart_service_ep(service_id: str):
        from shared.state import service_state
        ok = service_state.clear_overlay(service_id)
        if not ok:
            raise HTTPException(404, f"Unknown service: {service_id}")
        rec = service_state.get(service_id)
        bus.publish("event", {
            "category": "service",
            "level": "INFO",
            "message": f"Service {rec.name if rec else service_id} restart requested",
            "source": "manual",
        })
        return {"success": True, "service": rec.to_dict() if rec else None}

    @app.get("/api/security/auth_events", dependencies=[Depends(verify_token)])
    async def auth_events_ep(limit: int = 50):
        from shared.state import auth_state
        return {
            "events": auth_state.recent_events(limit),
            "stats": auth_state.stats(),
            "threats": auth_state.all_threats(),
        }

    @app.post("/api/security/block_ip", dependencies=[Depends(verify_token)])
    async def block_ip_ep(payload: dict = Body(...)):
        from shared.state import auth_state
        ip = payload.get("ip")
        duration = float(payload.get("duration_minutes", 15)) * 60
        if not ip:
            raise HTTPException(400, "ip required")
        auth_state.block_ip(ip, duration_s=duration, reason="manual_block")
        bus.publish("event", {
            "category": "security",
            "level": "INFO",
            "message": f"IP {ip} blocked for {int(duration//60)}m",
            "source": "manual",
        })
        return {"success": True, "ip": ip}

    @app.get("/api/security/certs", dependencies=[Depends(verify_token)])
    async def certs_ep():
        from shared.state import cert_state
        return {"certs": cert_state.all_dict()}

    @app.post("/api/security/certs/{domain}/rotate", dependencies=[Depends(verify_token)])
    async def rotate_cert_ep(domain: str):
        from shared.state import cert_state
        ok = cert_state.rotate(domain)
        if not ok:
            raise HTTPException(404, f"Unknown cert domain: {domain}")
        return {"success": True, "cert": cert_state.get(domain).to_dict()}

    @app.get("/api/security/ports", dependencies=[Depends(verify_token)])
    async def ports_ep():
        from shared.state import network_state
        return {"ports": network_state.all_ports()}

    @app.post("/api/security/ports/{port}/close", dependencies=[Depends(verify_token)])
    async def close_port_ep(port: int):
        from shared.state import network_state
        ok = network_state.close_port_action(port)
        if not ok:
            raise HTTPException(404, f"Unknown port: {port}")
        return {"success": True, "port": port}

    @app.get("/api/network", dependencies=[Depends(verify_token)])
    async def network_ep():
        from shared.state import network_state
        return {"links": network_state.all_links()}

    @app.get("/api/infra", dependencies=[Depends(verify_token)])
    async def infra_ep():
        from shared.state import infra_state
        return infra_state.snapshot()

    @app.post("/api/infra/backup/retry", dependencies=[Depends(verify_token)])
    async def retry_backup_ep():
        from shared.state import infra_state
        infra_state.retry_backup_action()
        return {"success": True, "backup": infra_state.backup.to_dict()}

    @app.post("/api/infra/ntp/sync", dependencies=[Depends(verify_token)])
    async def sync_ntp_ep():
        from shared.state import infra_state
        infra_state.sync_ntp_action()
        return {"success": True, "ntp": infra_state.ntp.to_dict()}

    # ========================================================================
    # AI endpoints
    # ========================================================================

    @app.get("/api/ai/llm/status", dependencies=[Depends(verify_token)])
    async def llm_status():
        return {
            "available": llm.available,
            "providers": llm.providers(),
            "usage": llm.usage_stats(),
        }

    @app.get("/api/ai/usage", dependencies=[Depends(verify_token)])
    async def llm_usage():
        return llm.usage_stats()

    @app.post("/api/ai/explain", dependencies=[Depends(verify_token)])
    async def ai_explain():
        metric = db.get_latest_metric() or {}
        active = guard.list_active()
        result = await ai_advisor.explain_server(metric, active)
        return result

    @app.post("/api/ai/analyze", dependencies=[Depends(verify_token)])
    async def ai_analyze():
        metric = db.get_latest_metric() or {}
        active = guard.list_active()
        result = await ai_advisor.analyze_threat(metric, active)
        return result

    @app.post("/api/ai/chat", dependencies=[Depends(verify_token)])
    async def ai_chat(payload: dict = Body(...)):
        message = payload.get("message", "").strip()
        if not message:
            raise HTTPException(400, "message required")
        # Build context
        metric = db.get_latest_metric() or {}
        active = guard.list_active()
        ctx = (
            f"CPU={metric.get('cpu_percent', 0)}% "
            f"MEM={metric.get('memory_percent', 0)}% "
            f"Disk={metric.get('disk_percent', 0)}% "
            f"Active_attacks={len(active)}"
        )
        return await ai_advisor.chat(message, context=ctx)

    # ========================================================================
    # Fake request (WAF simulation) endpoints
    # ========================================================================

    @app.get("/api/waf/patterns", dependencies=[Depends(verify_token)])
    async def waf_patterns():
        return {"patterns": fake_requests.pattern_names()}

    waf_executor = Executor()

    @app.post("/api/waf/send", dependencies=[Depends(verify_token)])
    async def waf_send(payload: dict = Body(default={})):
        """
        Generate fake request(s) → AI verdict → DecisionEngine → graduated action.
        Same source repeating? → automatic escalation.
        """
        pattern = payload.get("pattern")
        count = min(10, max(1, int(payload.get("count", 1))))
        reqs = fake_requests.generate(pattern=pattern, count=count)

        results = []
        for req in reqs:
            req_dict = req.to_dict()

            # 1. Get AI verdict (free advice)
            ai_verdict = await ai_advisor.handle_fake_request(req_dict)

            # 2. Build threat context
            threat = threat_from_request(req_dict, ai_verdict=ai_verdict)

            # 3. DecisionEngine picks graduated action
            decision = decision_engine.decide(threat)

            # 4. Execute (simulated)
            exec_result = waf_executor.execute_decision(decision)

            # 5. Log + broadcast
            level = "SECURITY" if decision.action.value not in ("none", "log_only", "alert") else "INFO"
            db.insert_event(
                level=level, category="waf",
                message=(
                    f"[WAF] {req.method} {req.path[:55]} from {req.source_ip} "
                    f"→ score {decision.risk_score:.0f} → {decision.action.value}"
                ),
                source="decision_engine",
                metadata={"request": req_dict, "ai": ai_verdict, "decision": decision.to_dict(), "result": exec_result},
            )
            payload_out = {
                "request": req_dict,
                "ai_verdict": ai_verdict,
                "decision": decision.to_dict(),
                "result": exec_result,
            }
            bus.publish("fake_request.processed", payload_out)
            bus.publish("defender.decision", decision.to_dict())
            results.append(payload_out)

        return {"processed": len(results), "results": results}

    # ========================================================================
    # New: Offender tracking + decision insights endpoints
    # ========================================================================

    @app.get("/api/defender/offenders", dependencies=[Depends(verify_token)])
    async def list_offenders(limit: int = 20):
        """Top repeat offenders (sources that triggered multiple actions)."""
        records = offenders.top_offenders(n=limit)
        out = []
        for r in records:
            out.append({
                "source_id": r.source_id,
                "source_type": r.source_type,
                "source_name": r.source_name,
                "violations_total": len(r.violations),
                "violations_recent_5m": r.recent_count(300),
                "threat_types": list(r.threat_types),
                "actions_taken": [a.value for a in r.actions_taken],
                "first_seen": r.first_seen,
                "last_seen": r.last_seen,
                "is_blocked": r.blocked_until > __import__("time").time(),
                "blocked_until": r.blocked_until,
            })
        return {"count": len(out), "offenders": out}

    @app.get("/api/defender/action_catalog", dependencies=[Depends(verify_token)])
    async def action_catalog():
        """All actions defender knows about + their tier."""
        from defender.decision_engine import Action
        catalog = []
        descriptions = {
            "none": "Take no action",
            "log_only": "Record event for audit trail",
            "alert": "Send alert notification",
            "increase_monitoring": "Increase monitoring frequency for source",
            "throttle_cpu": "Limit CPU usage to 50%",
            "throttle_network": "Limit network bandwidth to 30%",
            "rate_limit_source": "Rate-limit source IP for 10s",
            "require_challenge": "Require CAPTCHA challenge",
            "sandbox_process": "Run process in restricted sandbox",
            "block_network": "Cut all network access",
            "quarantine_files": "Move associated files to quarantine",
            "suspend_process": "Freeze process (preserves for forensics)",
            "block_ip_temporary": "Block IP for 5 minutes",
            "kill_process": "Terminate process",
            "kill_and_capture": "Kill + capture memory dump",
            "block_ip_permanent": "Block IP indefinitely",
            "clear_temp": "Clear temp files",
            "rollback_changes": "Restore files from snapshot",
            "notify_soc": "Notify SOC team",
        }
        for a in Action:
            catalog.append({
                "action": a.value,
                "tier": ACTION_TIER[a],
                "description": descriptions.get(a.value, ""),
            })
        return {"actions": sorted(catalog, key=lambda x: (x["tier"], x["action"]))}

    @app.get("/api/defender/trust", dependencies=[Depends(verify_token)])
    async def trust_status():
        return {
            "trusted_processes": sorted(trust.trusted_process_names),
            "trusted_ip_prefixes": trust.trusted_ip_prefixes,
        }

    @app.post("/api/defender/trust/process", dependencies=[Depends(verify_token)])
    async def trust_add_process(payload: dict = Body(...)):
        name = payload.get("name", "").strip()
        if not name:
            raise HTTPException(400, "name required")
        trust.add_trusted_process(name)
        return {"success": True, "trusted_processes": sorted(trust.trusted_process_names)}

    # ========================================================================
    # Defense Mode toggle (AUTO / AI / HYBRID)
    # ========================================================================

    @app.get("/api/defender/mode", dependencies=[Depends(verify_token)])
    async def get_mode():
        return mode_state.state_dict()

    @app.post("/api/defender/demo_reset", dependencies=[Depends(verify_token)])
    async def demo_reset():
        """
        Clear runtime demo state for a fresh demonstration:
          - stop all active attacks + simulations
          - reset offender tracker
          - reset baseline learning
          - clear events/actions older than 5 minutes (keep recent for context)
        Does NOT change defense mode or trust list (those persist).
        """
        from shared.simulation import engine as _sim
        # Stop attacks + sims
        guard.stop_all("demo_reset")
        _sim.clear()

        # Reset offenders
        offenders._records.clear()

        # Reset rules/baseline (next sample restarts learning)
        if orchestrator is not None:
            orchestrator.rules._samples = {k: __import__('collections').deque(maxlen=30) for k in orchestrator.rules._samples}
            orchestrator.rules.baseline.clear()
            orchestrator.rules._baseline_ready = False
            orchestrator.rules._breach_since.clear()

        # Clear DB events/actions older than 5 min so demo starts clean
        with db.cursor() as cur:
            cur.execute("DELETE FROM events WHERE timestamp < datetime('now', '-5 minutes')")
            cur.execute("DELETE FROM actions WHERE timestamp < datetime('now', '-5 minutes')")
            cur.execute("DELETE FROM attacks WHERE timestamp < datetime('now', '-5 minutes')")

        bus.publish("demo.reset", {"timestamp": __import__('time').time()})
        return {"success": True, "message": "Demo state cleared. Baseline learning restarted."}

    @app.post("/api/defender/mode", dependencies=[Depends(verify_token)])
    async def set_mode(payload: dict = Body(...)):
        new_mode = (payload.get("mode") or "").lower().strip()
        if new_mode not in [m.value for m in DefenseMode]:
            raise HTTPException(400, f"mode must be one of: {[m.value for m in DefenseMode]}")
        old = mode_state.mode.value
        mode_state.set(new_mode)
        db.insert_event(
            level="INFO", category="config",
            message=f"Defense mode changed: {old} → {new_mode}",
            source="user",
        )
        bus.publish("defense_mode.changed", mode_state.state_dict())
        return mode_state.state_dict()

    # ========================================================================
    # AI Investigation — multi-step agent loop
    # ========================================================================

    @app.post("/api/ai/investigate", dependencies=[Depends(verify_token)])
    async def ai_investigate(payload: dict = Body(default={})):
        """
        Trigger an AI agent investigation.

        Body: { trigger_reason, context, max_steps }
        - trigger_reason: short string explaining why
        - context: dict with relevant data (auto-built if empty)
        - max_steps: 2-6, default 4

        Each step streams via WebSocket. Returns final report when done.
        """
        trigger = payload.get("trigger_reason", "User-triggered investigation")
        max_steps = max(2, min(6, int(payload.get("max_steps", 4))))

        # Auto-build context from current state
        latest = db.get_latest_metric() or {}
        active_attacks = guard.list_active()
        recent_events = db.get_recent_events(limit=5)
        top_offs = offenders.top_offenders(n=3)

        context = payload.get("context") or {
            "current_metrics": {
                "cpu": latest.get("cpu_percent", 0),
                "memory": latest.get("memory_percent", 0),
                "disk": latest.get("disk_percent", 0),
                "anomaly_score": latest.get("anomaly_score", 0),
            },
            "active_attacks": [{"name": a.get("name"), "duration": a.get("duration")} for a in active_attacks],
            "recent_event_summary": [e.get("message", "")[:80] for e in recent_events[:3]],
            "top_offenders": [{
                "source_id": o.source_id,
                "violations": len(o.violations),
                "threat_types": list(o.threat_types),
            } for o in top_offs],
        }

        inv = await run_investigation(trigger, context, max_steps=max_steps)
        return inv.to_dict()

    @app.post("/api/ai/solve", dependencies=[Depends(verify_token)])
    async def ai_solve(payload: dict = Body(default={})):
        """
        Run the AI Live Solver — step-by-step demo of:
        DETECT → ANALYZE → DECIDE → EXECUTE → VERIFY → REPORT.
        Each stage streams over WebSocket as it executes.
        Returns the full session at the end.
        """
        trigger = payload.get("trigger", "User clicked Solve with AI")
        session = await ai_solve_now(trigger)
        return {
            "session_id": session.id,
            "trigger": session.trigger,
            "started_at": session.started_at,
            "finished_at": session.finished_at,
            "success": session.success,
            "summary": session.summary,
            "steps": session.steps,
        }

    @app.get("/api/ai/investigations", dependencies=[Depends(verify_token)])
    async def list_investigations(limit: int = 20):
        """List recent investigations from the event log."""
        with db.cursor() as cur:
            cur.execute(
                "SELECT id, timestamp, message, metadata FROM events "
                "WHERE category = 'investigation' ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            rows = [dict(r) for r in cur.fetchall()]
        out = []
        for r in rows:
            try:
                meta = json.loads(r["metadata"]) if r.get("metadata") else {}
            except Exception:
                meta = {}
            out.append({
                "timestamp": r["timestamp"],
                "summary": r["message"],
                "investigation_id": meta.get("id"),
                "status": meta.get("status"),
                "final_action": meta.get("final_action"),
                "confidence": meta.get("confidence"),
                "step_count": meta.get("step_count"),
            })
        return {"count": len(out), "investigations": out}

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket):
        try:
            await ws_manager.connect(ws)
        except Exception:
            return

        # Push current state on connect
        latest = db.get_latest_metric()
        if latest:
            try:
                await ws.send_json({"type": "metric", "data": latest})
            except Exception:
                ws_manager.disconnect(ws)
                return

        try:
            while True:
                # Client may or may not send messages; any exception = disconnect
                await ws.receive_text()
        except (WebSocketDisconnect, RuntimeError, Exception):
            ws_manager.disconnect(ws)

    return app
