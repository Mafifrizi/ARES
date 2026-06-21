"""
ares.strategy.notifier — Operator notification hooks for autonomous engagements.

Collects and dispatches notifications during strategy engine rounds.
Pluggable via webhook callback or WebSocket forwarding.

Extracted from strategy/__init__.py for maintainability.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Callable

from ares.core.logger import get_logger

logger = get_logger("ares.strategy.notifier")


class OperatorNotifier:
    """Collects operator notifications — pluggable via webhook or WebSocket."""

    def __init__(self, notify_fn: Callable | None = None) -> None:
        self._fn       = notify_fn
        self.messages: list[dict] = []

    async def send(self, event_type: str, data: dict) -> None:
        msg = {"event": event_type, "ts": time.time(), **data}
        self.messages.append(msg)
        if self._fn:
            try:
                if asyncio.iscoroutinefunction(self._fn):
                    await self._fn(msg)
                else:
                    self._fn(msg)
            except Exception as exc:
                logger.warning("notifier_error", error=str(exc)[:80])
