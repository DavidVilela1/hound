"""Stand-alone capture daemon (``python run.py capture``).

This is the only component that needs packet-capture privileges. It captures,
parses and forwards normalised events to a Hound server running as an
ordinary user. It contains no database, API or UI code.
"""

from __future__ import annotations

import logging
import signal
import threading
import time
import urllib.error
from types import FrameType

from app.core.config import Settings
from app.ingestion.capture import CaptureError, PacketCaptureService
from app.ingestion.forwarder import DIRECT_OPENER, HttpEventForwarder, SelfTrafficFilter
from app.ingestion.queue import EventQueue
from app.models.events import NetworkEvent

logger = logging.getLogger(__name__)

STATS_INTERVAL_SECONDS = 60.0
STATUS_POLL_SECONDS = 2.0


def _api_reachable(api_url: str, timeout: float = 3.0) -> bool:
    try:
        with DIRECT_OPENER.open(api_url.rstrip("/") + "/health", timeout=timeout) as resp:
            return 200 <= resp.status < 600
    except urllib.error.HTTPError:
        return True  # the server answered, even if degraded
    except (urllib.error.URLError, OSError, TimeoutError):
        return False


class CaptureDaemon:
    def __init__(self, settings: Settings, *, interface: str | None, api_url: str, token: str) -> None:
        self._settings = settings
        self._queue = EventQueue(settings.queue_max_size)
        self._self_traffic = SelfTrafficFilter(api_url)
        self._capture = PacketCaptureService(interface, settings.bpf_filter, self._sink)
        self._forwarder = HttpEventForwarder(
            self._queue,
            api_url=api_url,
            token=token,
            batch_size=settings.batch_size,
            flush_interval=settings.flush_interval_seconds,
            reporter=self._report,
        )
        self._api_url = api_url
        self._stop = threading.Event()

    def _sink(self, event: NetworkEvent) -> bool:
        if self._self_traffic.excludes(event):
            return False  # our own forwarding connection, not network activity
        return self._queue.offer(event)

    def _report(self) -> dict[str, object]:
        """Cumulative counters sent to the server with each batch (``DaemonReport``)."""
        status = self._capture.status()
        q = self._queue.stats()
        f = self._forwarder.stats
        return {
            "interface": status.interface,
            "packets_parsed": status.packets_parsed,
            "packets_malformed": status.packets_malformed,
            "queue_dropped": q.dropped,
            "capture_restarts": status.restarts,
            "capture_downtime_seconds": status.downtime_seconds,
            "queue_high_water": q.high_water,
            "queue_capacity": q.capacity,
            "events_forwarded": f.sent,
            "events_forward_dropped": f.dropped,
            "forward_failures": f.failures,
        }

    def stop(self) -> None:
        """Ask :meth:`run` to finish (thread-safe; used by signal handlers and embedders)."""
        self._stop.set()

    def _handle_signal(self, signum: int, _frame: FrameType | None) -> None:
        logger.info("Shutdown requested", extra={"signal": signum})
        self.stop()

    def run(self) -> int:
        """Run until interrupted. Returns a process exit code."""
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, self._handle_signal)
            except (ValueError, OSError):  # not in main thread / unsupported on platform
                pass
        if not _api_reachable(self._api_url):
            logger.warning(
                "Hound API not reachable yet; events will be buffered and retried",
                extra={"api_url": self._api_url},
            )
        self._forwarder.start()
        try:
            self._capture.start()
        except CaptureError as exc:
            logger.error("Capture could not start: %s", exc)
            self._forwarder.stop()
            return 2
        exit_code = 0
        last_stats = time.monotonic()
        try:
            while not self._stop.wait(STATUS_POLL_SECONDS):
                status = self._capture.status()
                if status.state == "error":  # "restarting" is not an error: capture recovers by itself
                    logger.error("Capture failed: %s", status.error)
                    exit_code = 3
                    break
                if time.monotonic() - last_stats >= STATS_INTERVAL_SECONDS:
                    last_stats = time.monotonic()
                    q = self._queue.stats()
                    logger.info(
                        "Capture statistics",
                        extra={
                            "parsed": status.packets_parsed,
                            "malformed": status.packets_malformed,
                            "queued": q.size,
                            "queue_drops": q.dropped,
                            "forwarded": self._forwarder.stats.sent,
                            "forward_drops": self._forwarder.stats.dropped,
                            "capture_restarts": status.restarts,
                            "capture_downtime_seconds": status.downtime_seconds,
                        },
                    )
        finally:
            self._capture.stop()
            self._forwarder.stop()
        return exit_code
