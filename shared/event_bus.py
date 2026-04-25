"""
Simple in-process pub/sub event bus.
Decouples monitor → rules → AI → dashboard.
"""
from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any, Callable, Coroutine


class EventBus:
    """Async-first event bus. Sync subscribers also supported."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Callable]] = defaultdict(list)
        self._async_subscribers: dict[str, list[Callable]] = defaultdict(list)

    def subscribe(self, topic: str, callback: Callable[[Any], None]) -> None:
        """Register sync callback."""
        self._subscribers[topic].append(callback)

    def subscribe_async(
        self, topic: str, callback: Callable[[Any], Coroutine]
    ) -> None:
        """Register async callback."""
        self._async_subscribers[topic].append(callback)

    def publish(self, topic: str, data: Any) -> None:
        """Fire sync subscribers synchronously, async ones via loop."""
        for cb in self._subscribers.get(topic, []):
            try:
                cb(data)
            except Exception as e:  # noqa: BLE001
                print(f"[EventBus] sync error on {topic}: {e}")

        async_subs = self._async_subscribers.get(topic, [])
        if async_subs:
            try:
                loop = asyncio.get_running_loop()
                for cb in async_subs:
                    loop.create_task(self._safe_async(topic, cb, data))
            except RuntimeError:
                # No running loop — skip async subs
                pass

    async def _safe_async(self, topic: str, cb: Callable, data: Any) -> None:
        try:
            await cb(data)
        except Exception as e:  # noqa: BLE001
            print(f"[EventBus] async error on {topic}: {e}")

    def unsubscribe_all(self, topic: str) -> None:
        self._subscribers.pop(topic, None)
        self._async_subscribers.pop(topic, None)


# Global singleton
bus = EventBus()


# Standard topic names
class Topics:
    METRIC_COLLECTED = "metric.collected"
    RULE_FIRED = "rule.fired"
    AI_ANOMALY = "ai.anomaly"
    ACTION_EXECUTED = "action.executed"
    ATTACK_STARTED = "attack.started"
    ATTACK_STOPPED = "attack.stopped"
    SECURITY_ALERT = "security.alert"
    USB_EVENT = "usb.event"
    NETWORK_ALERT = "network.alert"
    PROCESS_SUSPICIOUS = "process.suspicious"
