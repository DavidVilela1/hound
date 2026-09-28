"""Forward normalised events from a (privileged) capture daemon to the Hound API.

Uses only the standard library (``urllib``) so the privileged process carries
as little code as possible. Events are batched, the in-memory backlog is
bounded, and delivery failures back off exponentially instead of spinning.
"""

from __future__ import annotations

import json
import logging
import socket
import threading
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.core.security import TOKEN_HEADER
from app.ingestion.queue import EventQueue
from app.models.events import NetworkEvent, PacketType

logger = logging.getLogger(__name__)

INGEST_PATH = "/api/ingest"
MAX_BACKOFF_SECONDS = 30.0


class ForwarderError(RuntimeError):
    pass


class SelfTrafficFilter:
    """Recognise the daemon's own connections to the Hound API.

    Without this, capturing on the interface that carries the forwarding
    traffic (e.g. loopback) would create a feedback loop: each POST opens a
    TCP connection, whose SYN is captured and forwarded, and so on.
    """

    def __init__(self, api_url: str) -> None:
        parts = urlsplit(api_url)
        self._port = parts.port or (443 if parts.scheme == "https" else 80)
        self._ips: frozenset[str] = frozenset()
        if parts.hostname:
            try:
                infos = socket.getaddrinfo(parts.hostname, self._port, proto=socket.IPPROTO_TCP)
                self._ips = frozenset(str(info[4][0]).split("%", 1)[0] for info in infos)
            except OSError:
                logger.warning(
                    "Could not resolve API host; self-traffic filter disabled", extra={"host": parts.hostname}
                )

    def excludes(self, event: NetworkEvent) -> bool:
        return (
            event.packet_type is PacketType.TCP_SYN
            and event.destination_port == self._port
            and event.destination_ip in self._ips
        )


@dataclass(slots=True)
class ForwarderStats:
    sent: int = 0
    dropped: int = 0
    failures: int = 0


Transport = Callable[[str, bytes, dict[str, str], float], int]
"""``(url, body, headers, timeout) -> HTTP status``; injectable for tests."""


# Talks to the local Hound API only, so proxy settings from the environment (or Windows'
# system proxy) must never apply: a proxy would swallow or reject localhost traffic.
DIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def urllib_transport(url: str, body: bytes, headers: dict[str, str], timeout: float) -> int:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with DIRECT_OPENER.open(request, timeout=timeout) as response:  # scheme validated in __init__
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)


class HttpEventForwarder:
    def __init__(
        self,
        queue: EventQueue,
        *,
        api_url: str,
        token: str,
        batch_size: int = 200,
        flush_interval: float = 0.5,
        timeout: float = 5.0,
        max_retries_per_batch: int = 5,
        transport: Transport = urllib_transport,
    ) -> None:
        parts = urlsplit(api_url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ForwarderError(f"api_url must be an http(s) URL, got {api_url!r}")
        self._url = api_url.rstrip("/") + INGEST_PATH
        self._token = token
        self._queue = queue
        self._batch_size = min(batch_size, 1000)
        self._flush_interval = flush_interval
        self._timeout = timeout
        self._max_retries = max_retries_per_batch
        self._transport = transport
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.stats = ForwarderStats()

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="hound-forwarder", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._timeout + 2)
            self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            batch = self._queue.get_batch(self._batch_size, self._flush_interval)
            if batch:
                self.deliver(batch)
        # Best-effort final flush.
        remaining = self._queue.get_batch(self._batch_size, 0.01)
        if remaining:
            self.deliver(remaining, retries=1)

    def deliver(self, batch: list[NetworkEvent], retries: int | None = None) -> bool:
        """Send one batch with bounded retries. Returns ``True`` on success."""
        body = json.dumps({"events": [event.model_dump(mode="json") for event in batch]}).encode("utf-8")
        headers = {"Content-Type": "application/json", TOKEN_HEADER: self._token}
        backoff = 1.0
        attempts = retries if retries is not None else self._max_retries
        for attempt in range(1, attempts + 1):
            try:
                status = self._transport(self._url, body, headers, self._timeout)
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                status, detail = 0, str(exc)
            else:
                detail = f"HTTP {status}"
            if 200 <= status < 300:
                self.stats.sent += len(batch)
                return True
            self.stats.failures += 1
            if status in (401, 403):
                logger.error(
                    "API rejected the ingest token; check HOUND_INGEST_TOKEN / token file", extra={"status": status}
                )
                break
            if status == 422:
                logger.error("API rejected the event batch as invalid", extra={"size": len(batch)})
                break
            logger.warning(
                "Event delivery failed; retrying",
                extra={"attempt": attempt, "detail": detail, "backoff_s": backoff},
            )
            if self._stop.wait(backoff):
                break
            backoff = min(backoff * 2, MAX_BACKOFF_SECONDS)
        self.stats.dropped += len(batch)
        logger.error("Dropped event batch after failed delivery", extra={"size": len(batch)})
        return False
