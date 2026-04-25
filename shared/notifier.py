"""
Notification dispatcher — Windows toast + optional Telegram/Discord/Email.
"""
from __future__ import annotations

import platform
import smtplib
import threading
from email.mime.text import MIMEText
from typing import Literal

from shared.logger import get_logger

log = get_logger("notifier")

_toast_available = False
if platform.system() == "Windows":
    try:
        from win10toast import ToastNotifier  # type: ignore
        _toaster = ToastNotifier()
        _toast_available = True
    except Exception:
        _toast_available = False


Level = Literal["info", "warning", "critical"]


def windows_toast(title: str, message: str, level: Level = "info") -> None:
    if not _toast_available:
        return

    def _show() -> None:
        try:
            duration = {"info": 3, "warning": 5, "critical": 10}[level]
            _toaster.show_toast(title, message, duration=duration, threaded=False)
        except Exception as e:  # noqa: BLE001
            log.debug(f"Toast failed: {e}")

    threading.Thread(target=_show, daemon=True).start()


def send_telegram(token: str, chat_id: str, message: str) -> bool:
    if not token or not chat_id:
        return False
    try:
        import requests
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": message, "parse_mode": "Markdown"},
            timeout=5,
        )
        return r.status_code == 200
    except Exception as e:  # noqa: BLE001
        log.warning(f"Telegram send failed: {e}")
        return False


def send_discord(webhook_url: str, message: str, level: Level = "info") -> bool:
    if not webhook_url:
        return False
    try:
        import requests
        color_map = {"info": 3447003, "warning": 16776960, "critical": 15158332}
        payload = {
            "embeds": [{
                "title": f"Argus Alert ({level.upper()})",
                "description": message,
                "color": color_map.get(level, 3447003),
            }]
        }
        r = requests.post(webhook_url, json=payload, timeout=5)
        return r.status_code in (200, 204)
    except Exception as e:  # noqa: BLE001
        log.warning(f"Discord send failed: {e}")
        return False


def send_email(
    host: str,
    port: int,
    username: str,
    password: str,
    recipients: list[str],
    subject: str,
    body: str,
) -> bool:
    if not (host and username and password and recipients):
        return False
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = username
        msg["To"] = ", ".join(recipients)

        with smtplib.SMTP(host, port, timeout=10) as server:
            server.starttls()
            server.login(username, password)
            server.sendmail(username, recipients, msg.as_string())
        return True
    except Exception as e:  # noqa: BLE001
        log.warning(f"Email send failed: {e}")
        return False


def notify(
    title: str,
    message: str,
    level: Level = "info",
    channels: list[str] | None = None,
) -> None:
    """High-level notify. Reads config for channel settings."""
    from shared.config_loader import get_config

    cfg = get_config()
    channels = channels or ["toast"]

    if "toast" in channels and cfg.notifications.windows_toast:
        windows_toast(title, message, level)

    if "telegram" in channels and cfg.notifications.telegram.enabled:
        send_telegram(
            cfg.notifications.telegram.bot_token,
            cfg.notifications.telegram.chat_id,
            f"*{title}*\n{message}",
        )

    if "discord" in channels and cfg.notifications.discord.enabled:
        send_discord(cfg.notifications.discord.webhook_url, message, level)

    if "email" in channels and cfg.notifications.email.enabled:
        send_email(
            cfg.notifications.email.smtp_host,
            cfg.notifications.email.smtp_port,
            cfg.notifications.email.username,
            cfg.notifications.email.password,
            cfg.notifications.email.recipients,
            subject=f"[Argus] {title}",
            body=message,
        )
