"""
Attacker FastAPI application.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from attacker.attacks import REGISTRY, get_attack_list
from attacker.safety_guard import guard
from shared.auth import verify_token
from shared.logger import get_logger
from storage import database as db

log = get_logger("attacker-api")


UI_DIR = Path(__file__).resolve().parent.parent / "ui"


def create_app() -> FastAPI:
    app = FastAPI(title="Argus Attacker", version="1.0.0")

    if UI_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(UI_DIR)), name="static")

    @app.get("/")
    async def root():
        index = UI_DIR / "attacker.html"
        if index.exists():
            return FileResponse(index)
        return {"name": "Argus Attacker"}

    @app.get("/api/attacks/list", dependencies=[Depends(verify_token)])
    async def list_attacks():
        return get_attack_list()

    @app.get("/api/attacks/active", dependencies=[Depends(verify_token)])
    async def active():
        return guard.list_active()

    @app.post("/api/attacks/{attack_type}/start", dependencies=[Depends(verify_token)])
    async def start_attack(attack_type: str, params: dict = Body(default={})):
        cls = REGISTRY.get(attack_type)
        if not cls:
            raise HTTPException(404, f"Unknown attack: {attack_type}")
        try:
            attack = cls(params or {})
            guard.register(attack)
            started = attack.start()
            if not started:
                guard.unregister(attack.id)
                raise HTTPException(500, "Attack failed to start (already running?)")
            return {
                "id": attack.id,
                "db_id": attack._db_id,
                "name": attack.name,
                "category": attack.category,
                "status": "running",
                "params": params,
            }
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            log.error(f"start_attack {attack_type} crashed: {e}", exc_info=True)
            raise HTTPException(500, f"Error: {e}")

    @app.post("/api/attacks/{attack_id}/stop", dependencies=[Depends(verify_token)])
    async def stop_attack(attack_id: str):
        attack = guard.get(attack_id)
        if not attack:
            raise HTTPException(404, "No such active attack")
        attack.stop(stopped_by="user")
        guard.unregister(attack_id)
        return {"success": True}

    @app.post("/api/attacks/stop_all", dependencies=[Depends(verify_token)])
    async def stop_all():
        count = guard.stop_all(reason="user_kill_switch")
        return {"stopped": count}

    @app.get("/api/attacks/history", dependencies=[Depends(verify_token)])
    async def history(limit: int = 50):
        return db.get_attack_history(limit=limit)

    return app
