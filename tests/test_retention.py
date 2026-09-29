"""Retention (17c, ADR-028): count and age limits, device rows kept equal to what is stored."""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError

from app.core.config import Settings
from app.database.repositories import DeviceRepository, EventRepository
from app.database.tables import DeviceRecord, EventRecord
from app.models.events import NetworkEvent, PacketType
from app.services import processing as processing_module
from app.services.runtime import HoundRuntime
from app.services.store import SqlEventStore
from tests.conftest import EventFactory

LAPTOP = "192.168.1.10"
PHONE = "192.168.1.20"
TV = "192.168.1.30"
NOW = datetime.now(UTC).replace(microsecond=0)


@pytest.fixture
def runtime(settings: Settings) -> Iterator[HoundRuntime]:
    runtime = HoundRuntime(settings)
    runtime.database.initialize()
    yield runtime
    runtime.database.dispose()


def at(make_event: EventFactory, source: str, days_ago: float, **extra: Any) -> NetworkEvent:
    return make_event(source_ip=source, timestamp=NOW - timedelta(days=days_ago), **extra)


def store(runtime: HoundRuntime, retention_days: int | None = None, max_events: int = 250_000) -> SqlEventStore:
    return SqlEventStore(
        runtime.database,
        device_risk_window=timedelta(minutes=60),
        retention_max_events=max_events,
        retention_days=retention_days,
        clock=lambda: NOW,
    )


def devices(runtime: HoundRuntime) -> dict[str, DeviceRecord]:
    with runtime.database.session() as session:
        rows = session.scalars(select(DeviceRecord)).all()
        session.expunge_all()
    return {row.source_ip: row for row in rows}


def stored_counts(runtime: HoundRuntime) -> dict[str, tuple[int, int, int, int, int]]:
    """Per device, recomputed from the events table: total, DNS, SYN, suspicious, dangerous."""
    with runtime.database.session() as session:
        rows = session.execute(
            select(EventRecord.source_ip, EventRecord.packet_type, EventRecord.risk_level, func.count()).group_by(
                EventRecord.source_ip, EventRecord.packet_type, EventRecord.risk_level
            )
        ).all()
    counts: dict[str, list[int]] = {}
    for ip, packet_type, level, n in rows:
        c = counts.setdefault(ip, [0, 0, 0, 0, 0])
        c[0] += n
        c[1] += n if packet_type == PacketType.DNS_QUERY.value else 0
        c[2] += n if packet_type == PacketType.TCP_SYN.value else 0
        c[3] += n if level == "suspicious" else 0
        c[4] += n if level == "dangerous" else 0
    return {ip: tuple(c) for ip, c in counts.items()}  # type: ignore[misc]


def device_counts(runtime: HoundRuntime) -> dict[str, tuple[int, int, int, int, int]]:
    return {
        ip: (
            d.event_count,
            d.dns_query_count,
            d.connection_attempt_count,
            d.suspicious_event_count,
            d.dangerous_event_count,
        )
        for ip, d in devices(runtime).items()
    }


def mixed_history(make_event: EventFactory) -> list[NetworkEvent]:
    """Three devices over ten days: lookups, connection attempts, safe and dangerous events."""
    events = []
    for day in range(10, 0, -1):
        events.append(at(make_event, LAPTOP, day, domain=f"day{day}.example"))
        events.append(at(make_event, LAPTOP, day - 0.5, packet_type=PacketType.TCP_SYN))
        events.append(at(make_event, PHONE, day - 0.2, domain="bad.example"))  # blocklisted → dangerous
    events.append(at(make_event, TV, 9, domain="tv.example"))  # a device only seen long ago
    return events


# ------------------------------------------------------------------------------ setting
@pytest.mark.parametrize(("raw", "expected"), [("", None), ("30", 30), (None, None)])
def test_retention_days_setting(raw: str | None, expected: int | None) -> None:
    assert Settings(_env_file=None, retention_days=raw).retention_days == expected  # type: ignore[call-arg, arg-type]


@pytest.mark.parametrize("raw", ["0", "-1", "3651", "a week"])
def test_invalid_retention_days_are_refused(raw: str) -> None:
    with pytest.raises(ValidationError, match="retention_days"):
        Settings(_env_file=None, retention_days=raw)  # type: ignore[call-arg, arg-type]


# ------------------------------------------------------------------------------ age limit
def test_events_older_than_the_age_limit_are_deleted(runtime: HoundRuntime, make_event: EventFactory) -> None:
    runtime.processor.process_batch(mixed_history(make_event))
    removed = store(runtime, retention_days=7).prune()
    with runtime.database.session() as session:
        oldest = session.scalar(select(func.min(EventRecord.timestamp)))
    assert oldest is not None and oldest >= NOW - timedelta(days=7)
    assert removed == 3 * 3 + 1  # three kinds of event from days 10, 9 and 8, plus the TV's only event
    assert TV not in devices(runtime)  # its only event is gone, so is the device
    assert device_counts(runtime) == stored_counts(runtime)


def test_no_age_limit_by_default(runtime: HoundRuntime, make_event: EventFactory) -> None:
    runtime.processor.process_batch(mixed_history(make_event))
    assert store(runtime).prune() == 0
    assert set(devices(runtime)) == {LAPTOP, PHONE, TV}


# ------------------------------------------------------------------------------ count limit
@pytest.mark.parametrize("keep", [1, 5, 17, 30])
def test_device_counters_always_equal_the_stored_events(
    runtime: HoundRuntime, make_event: EventFactory, keep: int
) -> None:
    runtime.processor.process_batch(mixed_history(make_event))
    before = devices(runtime)
    store(runtime, max_events=keep).prune()
    assert device_counts(runtime) == stored_counts(runtime)
    for ip, device in devices(runtime).items():  # first/last sighting are history, not recomputed
        assert (device.first_seen, device.last_seen) == (before[ip].first_seen, before[ip].last_seen)


def test_age_and_count_limits_together(runtime: HoundRuntime, make_event: EventFactory) -> None:
    runtime.processor.process_batch(mixed_history(make_event))
    # The count limit keeps the 4 newest rows by id (day 1's three events and the TV's,
    # which was stored last); the age limit then removes the TV's 9-day-old event.
    assert store(runtime, retention_days=5, max_events=4).prune() == 28
    with runtime.database.session() as session:
        assert EventRepository(session).count() == 3
    assert device_counts(runtime) == stored_counts(runtime)


def test_a_forgotten_device_that_returns_starts_afresh(runtime: HoundRuntime, make_event: EventFactory) -> None:
    runtime.processor.process_batch([at(make_event, TV, 30, domain="tv.example")])
    store(runtime, retention_days=7).prune()
    assert devices(runtime) == {}
    runtime.processor.process_batch([at(make_event, TV, 0, domain="tv.example")])
    tv = devices(runtime)[TV]
    assert tv.event_count == 1 and tv.first_seen == NOW


def test_counters_never_go_negative(runtime: HoundRuntime, make_event: EventFactory) -> None:
    """A database from an older build may have counters that disagree with its events."""
    runtime.processor.process_batch([at(make_event, LAPTOP, 3), at(make_event, LAPTOP, 0)])
    with runtime.database.session() as session:
        session.scalar(select(DeviceRecord)).event_count = 0  # type: ignore[union-attr]
    store(runtime, retention_days=1).prune()
    assert devices(runtime)[LAPTOP].event_count == 0


# ------------------------------------------------------------------------------ scheduling
def test_prune_runs_first_then_by_batches_or_time(runtime: HoundRuntime, make_event: EventFactory) -> None:
    s = store(runtime, max_events=1_000_000)
    s._prune_every = 3
    calls: list[float] = []
    real = s.prune

    def counting() -> int:
        calls.append(time.monotonic())
        return real()

    s.prune = counting  # type: ignore[method-assign]
    s.prune_if_due()
    assert len(calls) == 1  # at start: a server restarted after a week drops old events at once
    s.prune_if_due()
    assert len(calls) == 1  # nothing new, interval not reached
    for n in range(3):
        s.save([runtime.processor._process_one(make_event(seconds=n))])  # type: ignore[list-item]
    s.prune_if_due()
    assert len(calls) == 2  # after enough batches
    s._prune_seconds = 0
    s.prune_if_due()
    assert len(calls) == 3  # after enough time


def test_an_idle_server_still_applies_the_age_limit(settings: Settings, make_event: EventFactory) -> None:
    runtime = HoundRuntime(settings.model_copy(update={"retention_days": 7}))
    runtime.database.initialize()
    runtime.processor.process_batch([at(make_event, TV, 30, domain="tv.example")])
    runtime.start()  # idle mode: no event will arrive
    try:
        deadline = time.monotonic() + 5
        while devices(runtime) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert devices(runtime) == {}
        metrics = runtime.metrics().storage
        assert (metrics.retention_days, metrics.retention_pruned_events, metrics.retention_pruned_devices) == (7, 1, 1)
    finally:
        runtime.stop()


# ------------------------------------------------------------------------------ failures
def test_a_failed_prune_never_marks_a_stored_batch_as_lost(
    runtime: HoundRuntime, make_event: EventFactory, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Regression: pruning ran inside save(), so a prune error after the commit counted the
    already stored batch as failed ("batch dropped") and skipped publishing it."""

    def locked(self: EventRepository, *args: Any) -> Any:
        raise OperationalError("DELETE", {}, Exception("database is locked"))

    monkeypatch.setattr(EventRepository, "prune", locked)
    published: list[Any] = []
    runtime.processor._publisher = published.extend
    with caplog.at_level(logging.ERROR, logger=processing_module.__name__):
        for n in range(60):
            runtime.processor.process_batch([make_event(seconds=n)])
            runtime.processor.housekeep()
    stats = runtime.processor.stats()
    assert (stats.processed, stats.failed) == (60, 0)
    assert len(published) == 60
    assert runtime.metrics().loss.total_events_lost == 0
    assert "Maintenance (retention) failed" in caplog.text
    with runtime.database.session() as session:
        assert EventRepository(session).count() == 60


def test_prune_is_one_transaction(
    runtime: HoundRuntime, make_event: EventFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If updating the devices fails, the deleted events come back too (counters stay true)."""
    runtime.processor.process_batch(mixed_history(make_event))
    before = (stored_counts(runtime), device_counts(runtime))

    def broken(self: DeviceRepository, result: Any) -> int:
        raise OperationalError("UPDATE", {}, Exception("disk I/O error"))

    monkeypatch.setattr(DeviceRepository, "forget", broken)
    with pytest.raises(OperationalError):
        store(runtime, retention_days=3).prune()
    assert (stored_counts(runtime), device_counts(runtime)) == before
