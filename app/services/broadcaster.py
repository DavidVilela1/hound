"""Fan-out of processed events to WebSocket subscribers.

The processing thread calls :meth:`EventBroadcaster.publish` (thread-safe);
delivery happens on the asyncio event loop. Every subscriber has a bounded
queue: a slow client loses its oldest messages instead of growing memory or
slowing down anyone else.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

logger = logging.getLogger(__name__)

Message = dict[str, Any]


class EventBroadcaster:
    def __init__(self, client_queue_size: int = 500) -> None:
        self._client_queue_size = client_queue_size
        self._subscribers: set[asyncio.Queue[Message]] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()
        self._dropped = 0

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        with self._lock:
            self._loop = loop

    def unbind(self) -> None:
        with self._lock:
            self._loop = None

    def publish(self, messages: list[Message]) -> None:
        """Schedule delivery of ``messages`` from any thread (no-op without a loop)."""
        if not messages:
            return
        with self._lock:
            loop = self._loop
        if loop is None or loop.is_closed():
            return
        try:
            loop.call_soon_threadsafe(self._fanout, messages)
        except RuntimeError:  # loop closed between the check and the call
            pass

    def _fanout(self, messages: list[Message]) -> None:
        for subscriber in list(self._subscribers):
            for message in messages:
                if subscriber.full():
                    try:
                        subscriber.get_nowait()
                    except asyncio.QueueEmpty:  # pragma: no cover - race-free on one loop
                        pass
                    self._dropped += 1
                subscriber.put_nowait(message)

    @asynccontextmanager
    async def subscribe(self) -> AsyncIterator[asyncio.Queue[Message]]:
        queue: asyncio.Queue[Message] = asyncio.Queue(maxsize=self._client_queue_size)
        self._subscribers.add(queue)
        logger.debug("WebSocket subscriber added", extra={"subscribers": len(self._subscribers)})
        try:
            yield queue
        finally:
            self._subscribers.discard(queue)
            logger.debug("WebSocket subscriber removed", extra={"subscribers": len(self._subscribers)})

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    @property
    def dropped(self) -> int:
        return self._dropped
