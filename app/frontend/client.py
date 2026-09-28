"""Clients the dashboard uses to talk to the Hound API.

The frontend never touches SQLite: it reads REST endpoints with
:class:`HoundApiClient` and receives live events through
:class:`LiveEventStream` (WebSocket). Both can point at a server in another
process via ``HOUND_API_URL``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

import httpx
from websockets.asyncio.client import connect
from websockets.exceptions import WebSocketException

logger = logging.getLogger(__name__)

JSON = dict[str, Any]
EventCallback = Callable[[JSON], None]


class ApiError(RuntimeError):
    """The API could not be reached or returned an error."""


class HoundApiClient:
    def __init__(self, base_url: str, *, timeout: float = 5.0, client: httpx.AsyncClient | None = None) -> None:
        # trust_env=False: never route calls to the local API through an HTTP proxy.
        self._client = client or httpx.AsyncClient(base_url=base_url, timeout=timeout, trust_env=False)

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> JSON:
        clean = {k: v for k, v in (params or {}).items() if v is not None}
        try:
            response = await self._client.get(path, params=clean)
        except httpx.HTTPError as exc:
            raise ApiError(f"Cannot reach the Hound API ({type(exc).__name__})") from exc
        if response.status_code == 404:
            raise ApiError("Not found")
        if response.status_code >= 400:
            raise ApiError(f"API error {response.status_code}")
        try:
            data = response.json()
        except ValueError as exc:
            raise ApiError("API returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise ApiError("Unexpected API response")
        return data

    async def health(self) -> JSON:
        return await self._get("/health")

    async def stats(self) -> JSON:
        return await self._get("/api/stats")

    async def events(self, **params: Any) -> JSON:
        return await self._get("/api/events", params)

    async def event(self, event_id: int) -> JSON:
        return await self._get(f"/api/events/{int(event_id)}")

    async def devices(self, **params: Any) -> JSON:
        return await self._get("/api/devices", params)

    async def device(self, source_ip: str) -> JSON:
        return await self._get(f"/api/devices/{quote(source_ip, safe=':.')}")

    async def countries(self, *, include_local: bool = False) -> JSON:
        return await self._get("/api/stats/countries", {"include_local": str(include_local).lower()})

    async def aclose(self) -> None:
        await self._client.aclose()


class LiveEventStream:
    """Maintains one WebSocket connection and fans events out to local callbacks.

    Reconnects with exponential backoff. Callbacks must be cheap and must not
    raise; they are invoked on the event loop for every ``event`` message.
    """

    def __init__(self, url: str, *, max_backoff: float = 15.0) -> None:
        self._url = url
        self._max_backoff = max_backoff
        self._subscribers: dict[int, EventCallback] = {}
        self._next_id = 0
        self._task: asyncio.Task[None] | None = None
        self.connected = False

    def subscribe(self, callback: EventCallback) -> Callable[[], None]:
        token = self._next_id
        self._next_id += 1
        self._subscribers[token] = callback

        def unsubscribe() -> None:
            self._subscribers.pop(token, None)

        return unsubscribe

    async def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run(), name="hound-live-stream")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        self.connected = False

    def dispatch(self, message: JSON) -> None:
        if message.get("type") != "event" or not isinstance(message.get("data"), dict):
            return
        for callback in list(self._subscribers.values()):
            try:
                callback(message["data"])
            except Exception:
                logger.exception("Live event subscriber failed")

    async def _run(self) -> None:
        backoff = 0.5
        while True:
            try:
                async with connect(self._url, proxy=None, open_timeout=5, max_size=2**20) as websocket:
                    self.connected = True
                    backoff = 0.5
                    logger.info("Dashboard connected to live event stream")
                    async for raw in websocket:
                        try:
                            message = json.loads(raw)
                        except (TypeError, ValueError):
                            logger.warning("Ignoring malformed live message")
                            continue
                        if isinstance(message, dict):
                            self.dispatch(message)
            except asyncio.CancelledError:
                raise
            except (OSError, WebSocketException, TimeoutError) as exc:
                logger.debug("Live stream unavailable; retrying", extra={"error": type(exc).__name__})
            finally:
                self.connected = False
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, self._max_backoff)
