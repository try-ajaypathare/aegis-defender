"""
Simple token-based auth for dashboards.
Disabled by default; enable via config.
"""
from __future__ import annotations

from fastapi import Header, HTTPException, status

from shared.config_loader import get_config


async def verify_token(x_auth_token: str | None = Header(default=None)) -> None:
    cfg = get_config()
    if not cfg.dashboards.auth_enabled:
        return
    if x_auth_token != cfg.dashboards.auth_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing auth token",
        )
