"""Event-source abstraction shared by real capture and demo mode.

Nothing here imports Scapy, so the API can run without loading it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol

from app.models.events import NetworkEvent

SourceStateName = Literal["idle", "starting", "running", "restarting", "stopped", "error"]

EventSink = Callable[[NetworkEvent], bool]
"""Callable that accepts an event without blocking; returns ``False`` if it was dropped."""


@dataclass(frozen=True, slots=True)
class SourceStatus:
    name: str
    state: SourceStateName
    error: str | None = None
    interface: str | None = None
    packets_parsed: int = 0
    packets_ignored: int = 0
    packets_malformed: int = 0
    restarts: int = 0
    """Times the source recovered, or tried to, after failing while running."""
    downtime_seconds: float = 0.0
    """Time spent not capturing between such a failure and recovery (includes an ongoing outage)."""


class EventSource(Protocol):
    """Something that produces :class:`NetworkEvent` objects into a sink on its own thread."""

    name: str

    def start(self) -> None:
        """Start producing events. Raises on unrecoverable start-up failure."""
        ...

    def stop(self) -> None:
        """Stop producing events and release resources (idempotent)."""
        ...

    def status(self) -> SourceStatus: ...
