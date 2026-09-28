"""Bounded, thread-safe hand-off between event sources and consumers.

Producers (the Scapy callback, the demo generator, the ingest API) call
:meth:`EventQueue.offer`, which never blocks: if the queue is full the event is
dropped and counted, so a slow consumer can never stall packet capture or grow
memory without bound.
"""

from __future__ import annotations

import queue
import threading
from dataclasses import dataclass

from app.models.events import NetworkEvent


@dataclass(frozen=True, slots=True)
class QueueStats:
    size: int
    capacity: int
    received: int
    dropped: int
    high_water: int = 0
    """Largest size the queue has reached; close to ``capacity`` means drops are near."""


class EventQueue:
    def __init__(self, max_size: int = 10_000) -> None:
        if max_size < 1:
            raise ValueError("max_size must be positive")
        self._queue: queue.Queue[NetworkEvent] = queue.Queue(maxsize=max_size)
        self._capacity = max_size
        self._lock = threading.Lock()
        self._received = 0
        self._dropped = 0
        self._high_water = 0

    def offer(self, event: NetworkEvent) -> bool:
        """Enqueue without blocking. Returns ``False`` (and counts a drop) when full."""
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            with self._lock:
                self._dropped += 1
            return False
        size = self._queue.qsize()
        with self._lock:
            self._received += 1
            if size > self._high_water:
                self._high_water = size
        return True

    def get_batch(self, max_items: int, timeout: float) -> list[NetworkEvent]:
        """Wait up to ``timeout`` seconds for the first event, then drain up to ``max_items``."""
        batch: list[NetworkEvent] = []
        try:
            batch.append(self._queue.get(timeout=timeout))
        except queue.Empty:
            return batch
        while len(batch) < max_items:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return batch

    def stats(self) -> QueueStats:
        with self._lock:
            return QueueStats(self._queue.qsize(), self._capacity, self._received, self._dropped, self._high_water)

    def __len__(self) -> int:
        return self._queue.qsize()
