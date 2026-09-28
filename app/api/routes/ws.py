"""Real-time event stream over WebSocket.

Message format (JSON text frames)::

    {"type": "hello", "data": {"version": "1.0.0"}}
    {"type": "event", "data": <EventOut>}
    {"type": "heartbeat", "data": {"time": "..."}}

Browsers always send an ``Origin`` header with WebSocket handshakes, and the
same-origin policy does not protect WebSockets, so the origin is checked
against the Host allow-list to stop other websites from reading the feed.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import UTC, datetime
from urllib.parse import urlsplit

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app import __version__
from app.core.config import Settings

logger = logging.getLogger(__name__)
router = APIRouter()

HEARTBEAT_SECONDS = 15.0
POLICY_VIOLATION = 1008


def origin_allowed(origin: str | None, settings: Settings) -> bool:
    """Allow non-browser clients (no Origin) and same-host browser origins only."""
    if origin is None:
        return True
    hostname = urlsplit(origin).hostname
    return hostname is not None and hostname in settings.allowed_host_list


async def _wait_for_close(websocket: WebSocket) -> None:
    """Consume client frames until the connection closes (clients do not need to send)."""
    with contextlib.suppress(WebSocketDisconnect, RuntimeError):
        while True:
            message = await websocket.receive()
            if message.get("type") == "websocket.disconnect":
                return


@router.websocket("/ws/events")
async def events_stream(websocket: WebSocket) -> None:
    settings: Settings = websocket.app.state.settings
    runtime = websocket.app.state.runtime
    if not origin_allowed(websocket.headers.get("origin"), settings):
        logger.warning("Rejected WebSocket from disallowed origin")
        await websocket.close(code=POLICY_VIOLATION)
        return
    await websocket.accept()
    closed = asyncio.create_task(_wait_for_close(websocket))
    try:
        async with runtime.broadcaster.subscribe() as queue:
            await websocket.send_json({"type": "hello", "data": {"version": __version__}})
            while not closed.done():
                getter = asyncio.ensure_future(queue.get())
                done, _ = await asyncio.wait(
                    {getter, closed}, timeout=HEARTBEAT_SECONDS, return_when=asyncio.FIRST_COMPLETED
                )
                if getter in done:
                    await websocket.send_json(getter.result())
                    continue
                getter.cancel()
                if getter.done() and not getter.cancelled():  # completed right after the timeout
                    await websocket.send_json(getter.result())
                    continue
                if closed in done:
                    break
                await websocket.send_json({"type": "heartbeat", "data": {"time": datetime.now(UTC).isoformat()}})
    except (WebSocketDisconnect, RuntimeError, ConnectionError):
        logger.debug("WebSocket client disconnected")
    finally:
        closed.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await closed
