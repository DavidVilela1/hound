"""Persistence of processed events (events + device aggregates in one transaction)."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import timedelta
from typing import Protocol

from app.database.engine import Database
from app.database.repositories import DeviceRepository, EventRepository
from app.models.processed import ProcessedEvent
from app.models.schemas import EventOut
from app.services.mappers import event_to_schema

logger = logging.getLogger(__name__)


class EventStore(Protocol):
    def save(self, items: Sequence[ProcessedEvent]) -> list[EventOut]: ...


class SqlEventStore:
    """Writes batches atomically and periodically enforces the retention limit."""

    def __init__(
        self,
        database: Database,
        *,
        device_risk_window: timedelta,
        retention_max_events: int,
        prune_every_batches: int = 50,
    ) -> None:
        self._db = database
        self._risk_window = device_risk_window
        self._retention = retention_max_events
        self._prune_every = max(1, prune_every_batches)
        self._batches = 0
        self.pruned_total = 0
        """Events deleted by the retention limit since start (deliberate, not loss)."""

    def save(self, items: Sequence[ProcessedEvent]) -> list[EventOut]:
        if not items:
            return []
        with self._db.session() as session:
            records = EventRepository(session).add_many(items)
            DeviceRepository(session).apply_events(items, risk_window=self._risk_window)
            stored = [event_to_schema(record) for record in records]
        self._batches += 1
        if self._batches % self._prune_every == 0:
            self.prune()
        return stored

    def prune(self) -> int:
        with self._db.session() as session:
            removed = EventRepository(session).prune(self._retention)
        self.pruned_total += removed
        if removed:
            logger.info("Retention limit applied", extra={"removed_events": removed, "limit": self._retention})
        return removed
