"""Persistence of processed events (events + device aggregates in one transaction)."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Protocol

from app.database.engine import Database
from app.database.repositories import DeviceRepository, EventRepository
from app.models.processed import ProcessedEvent
from app.models.schemas import EventOut
from app.services.mappers import event_to_schema

logger = logging.getLogger(__name__)

PRUNE_EVERY_SECONDS = 300.0
"""Retention also runs on a timer, so an idle server still drops events past the age limit."""


class EventStore(Protocol):
    def save(self, items: Sequence[ProcessedEvent]) -> list[EventOut]: ...


class SqlEventStore:
    """Writes batches atomically; applies retention (count and optional age) separately.

    Retention runs from :meth:`prune_if_due`, which the processing worker calls between
    batches and while idle — never inside :meth:`save`, so a failed prune can no longer
    make an already stored batch look lost.
    """

    def __init__(
        self,
        database: Database,
        *,
        device_risk_window: timedelta,
        retention_max_events: int,
        retention_days: int | None = None,
        prune_every_batches: int = 50,
        prune_every_seconds: float = PRUNE_EVERY_SECONDS,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._db = database
        self._risk_window = device_risk_window
        self._retention = retention_max_events
        self._max_age = timedelta(days=retention_days) if retention_days else None
        self._prune_every = max(1, prune_every_batches)
        self._prune_seconds = prune_every_seconds
        self._clock = clock
        self._batches_since_prune = 0
        self._last_prune: float | None = None  # monotonic; None = never (prune on first call)
        self.pruned_total = 0
        """Events deleted by retention since start (deliberate, not loss)."""
        self.pruned_devices_total = 0
        """Devices deleted because retention removed their last stored event."""

    def save(self, items: Sequence[ProcessedEvent]) -> list[EventOut]:
        if not items:
            return []
        with self._db.session() as session:
            records = EventRepository(session).add_many(items)
            DeviceRepository(session).apply_events(items, risk_window=self._risk_window)
            stored = [event_to_schema(record) for record in records]
        self._batches_since_prune += 1
        return stored

    def prune_if_due(self) -> int:
        """Prune after every ``prune_every_batches`` batches, or ``prune_every_seconds`` of time."""
        now = time.monotonic()
        due = (
            self._last_prune is None
            or self._batches_since_prune >= self._prune_every
            or now - self._last_prune >= self._prune_seconds
        )
        return self.prune() if due else 0

    def prune(self) -> int:
        self._last_prune = time.monotonic()
        self._batches_since_prune = 0
        older_than = self._clock() - self._max_age if self._max_age else None
        with self._db.session() as session:
            result = EventRepository(session).prune(self._retention, older_than)
            DeviceRepository(session).forget(result)
        self.pruned_total += result.events
        self.pruned_devices_total += result.devices_removed
        if result.events:
            logger.info(
                "Retention applied",
                extra={
                    "removed_events": result.events,
                    "removed_devices": result.devices_removed,
                    "limit": self._retention,
                    "max_age_days": self._max_age.days if self._max_age else None,
                },
            )
        return result.events
