"""The processing worker: queue → enrich → score → persist → publish.

Runs on one dedicated thread, so the risk engine's per-device state and the
SQLite writer are never touched concurrently. Events arrive already validated
(:class:`NetworkEvent` is a Pydantic model constructed by every source).
"""

from __future__ import annotations

import logging
import math
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from app.database.engine import DatabaseError
from app.enrichment.service import EnrichmentService
from app.ingestion.queue import EventQueue
from app.models.events import NetworkEvent
from app.models.processed import ProcessedEvent
from app.models.schemas import EventOut
from app.risk.engine import RiskEngine
from app.services.store import EventStore

logger = logging.getLogger(__name__)

Publisher = Callable[[list[dict[str, Any]]], None]

LATENCY_SAMPLES = 1000
"""Batch durations kept for percentiles (the most recent ones; bounded memory)."""


@dataclass(slots=True)
class ProcessingStats:
    processed: int = 0
    failed: int = 0
    responses_observed: int = 0
    last_event_at: datetime | None = None
    last_error: str | None = None
    batches: int = 0


@dataclass(frozen=True, slots=True)
class LatencySummary:
    """Wall-clock time per batch (enrich + score + store + publish), in milliseconds."""

    samples: int
    p50_ms: float | None
    p95_ms: float | None
    max_ms: float | None


def summarize_latency(durations_ms: Sequence[float]) -> LatencySummary:
    """Nearest-rank percentiles; ``None`` values when there are no samples."""
    if not durations_ms:
        return LatencySummary(0, None, None, None)
    ordered = sorted(durations_ms)

    def rank(p: float) -> float:
        index = min(len(ordered), max(1, math.ceil(p / 100 * len(ordered)))) - 1
        return round(ordered[index], 3)

    return LatencySummary(len(ordered), rank(50), rank(95), round(ordered[-1], 3))


class ProcessingService:
    def __init__(
        self,
        queue: EventQueue,
        enrichment: EnrichmentService,
        risk_engine: RiskEngine,
        store: EventStore,
        *,
        publisher: Publisher | None = None,
        batch_size: int = 200,
        flush_interval: float = 0.5,
    ) -> None:
        self._queue = queue
        self._enrichment = enrichment
        self._risk = risk_engine
        self._store = store
        self._publisher = publisher
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._stats = ProcessingStats()
        self._latencies_ms: deque[float] = deque(maxlen=LATENCY_SAMPLES)

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="hound-processing", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _run(self) -> None:
        logger.info("Processing worker started")
        while not self._stop.is_set():
            batch = self._queue.get_batch(self._batch_size, self._flush_interval)
            if batch:
                self.process_batch(batch)
        # Drain what is already queued so a clean shutdown loses nothing.
        while batch := self._queue.get_batch(self._batch_size, 0):
            self.process_batch(batch)
        logger.info("Processing worker stopped")

    # ------------------------------------------------------------------ processing
    def process_batch(self, events: Sequence[NetworkEvent]) -> list[EventOut]:
        """Process a batch synchronously (also used directly by tests)."""
        started = time.perf_counter()
        try:
            return self._process_batch(events)
        finally:
            if events:
                elapsed_ms = (time.perf_counter() - started) * 1000
                with self._lock:
                    self._stats.batches += 1
                    self._latencies_ms.append(elapsed_ms)

    def _process_batch(self, events: Sequence[NetworkEvent]) -> list[EventOut]:
        processed: list[ProcessedEvent] = []
        for event in events:
            try:
                item = self._process_one(event)
            except Exception:
                self._bump(failed=1)
                logger.exception("Failed to process event")
                continue
            if item is not None:
                processed.append(item)
        if not processed:
            return []
        try:
            stored = self._store.save(processed)
        except (SQLAlchemyError, DatabaseError, OSError) as exc:
            self._bump(failed=len(processed), error=f"Database write failed: {type(exc).__name__}")
            logger.error("Database write failed; batch dropped", extra={"size": len(processed), "error": str(exc)})
            return []
        latest = max(item.event.timestamp for item in processed)
        with self._lock:
            self._stats.processed += len(stored)
            self._stats.last_error = None
            if self._stats.last_event_at is None or latest > self._stats.last_event_at:
                self._stats.last_event_at = latest
        if self._publisher is not None and stored:
            try:
                self._publisher([{"type": "event", "data": event.model_dump(mode="json")} for event in stored])
            except Exception:
                logger.exception("Failed to publish events to subscribers")
        return stored

    def _process_one(self, event: NetworkEvent) -> ProcessedEvent | None:
        if event.is_response:
            # Responses are not stored; they update the DNS cache and NXDOMAIN counters.
            self._enrichment.observe_dns_response(event)
            self._risk.observe(event)
            self._bump(responses=1)
            return None
        enrichment = self._enrichment.enrich(event)
        risk = self._risk.assess(event, enrichment)
        logger.debug(
            "Event scored",
            extra={"type": event.packet_type.value, "score": risk.score, "level": risk.level.value},
        )
        return ProcessedEvent(event=event, enrichment=enrichment, risk=risk)

    def _bump(self, *, failed: int = 0, responses: int = 0, error: str | None = None) -> None:
        with self._lock:
            self._stats.failed += failed
            self._stats.responses_observed += responses
            if error:
                self._stats.last_error = error

    def stats(self) -> ProcessingStats:
        with self._lock:
            s = self._stats
            return ProcessingStats(
                s.processed, s.failed, s.responses_observed, s.last_event_at, s.last_error, s.batches
            )

    def latency(self) -> LatencySummary:
        with self._lock:
            samples = list(self._latencies_ms)
        return summarize_latency(samples)
