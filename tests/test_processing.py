"""End-to-end processing pipeline (queue → enrichment → risk → SQLite → publisher)."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from sqlalchemy.exc import OperationalError

from app.core.config import Settings
from app.database.repositories import EventFilter
from app.ingestion.queue import EventQueue
from app.models.events import PacketType
from app.services.broadcaster import EventBroadcaster
from app.services.runtime import HoundRuntime
from tests.conftest import EventFactory


def test_event_queue_is_bounded(make_event: EventFactory) -> None:
    queue = EventQueue(max_size=2)
    assert queue.offer(make_event()) and queue.offer(make_event())
    assert not queue.offer(make_event())
    stats = queue.stats()
    assert (stats.size, stats.received, stats.dropped) == (2, 2, 1)
    assert len(queue.get_batch(10, 0.01)) == 2
    assert queue.get_batch(10, 0.01) == []


def test_process_batch_persists_and_publishes(settings: Settings, make_event: EventFactory) -> None:
    runtime = HoundRuntime(settings)
    runtime.database.initialize()
    published: list[dict[str, Any]] = []
    runtime.processor._publisher = published.extend  # capture instead of WebSocket fan-out
    response = make_event(
        packet_type=PacketType.DNS_RESPONSE,
        source_ip="192.168.1.1",
        destination_ip="192.168.1.10",
        domain="cdn.bad.example",
        dns_answers=("93.184.216.34",),
        dns_rcode=0,
    )
    stored = runtime.processor.process_batch(
        [make_event(domain="cdn.bad.example"), response, make_event(packet_type=PacketType.TCP_SYN, seconds=1)]
    )
    assert len(stored) == 2  # the DNS response updates state but is not stored
    query, syn = stored
    assert query.risk_level == "dangerous" and query.blocklist_match == "bad.example"
    assert syn.domain == "cdn.bad.example" and syn.domain_source == "dns_cache" and syn.country == "US"
    assert [m["data"]["id"] for m in published] == [query.id, syn.id]
    assert runtime.devices.get_device("192.168.1.10") is not None
    stats = runtime.processor.stats()
    assert stats.processed == 2 and stats.responses_observed == 1 and stats.failed == 0
    runtime.database.dispose()


def test_worker_thread_drains_queue(settings: Settings, make_event: EventFactory) -> None:
    runtime = HoundRuntime(settings)
    runtime.start()
    try:
        for i in range(25):
            assert runtime.queue.offer(make_event(seconds=i, domain=f"s{i}.example"))
        deadline = time.monotonic() + 5
        while runtime.processor.stats().processed < 25 and time.monotonic() < deadline:
            time.sleep(0.02)
        assert runtime.events.list_events(EventFilter(), limit=100, offset=0).total == 25
        status = runtime.pipeline_status()
        assert status.mode == "idle" and status.source_state == "idle" and status.events_processed == 25
    finally:
        runtime.stop()


def test_database_failure_is_counted_not_fatal(settings: Settings, make_event: EventFactory) -> None:
    runtime = HoundRuntime(settings)
    runtime.database.initialize()

    class FailingStore:
        def save(self, items: Any) -> list[Any]:
            raise OperationalError("INSERT", {}, Exception("database is locked"))

    runtime.processor._store = FailingStore()
    assert runtime.processor.process_batch([make_event()]) == []
    stats = runtime.processor.stats()
    assert stats.failed == 1 and stats.last_error and "Database" in stats.last_error
    assert runtime.pipeline_status().source_error is not None
    runtime.database.dispose()


def test_broadcaster_fanout_and_bounded_queues() -> None:
    async def scenario() -> tuple[int, int, int]:
        broadcaster = EventBroadcaster(client_queue_size=3)
        broadcaster.publish([{"type": "event"}])  # no loop bound yet: silently ignored
        broadcaster.bind_loop(asyncio.get_running_loop())
        async with broadcaster.subscribe() as fast, broadcaster.subscribe() as slow:
            broadcaster.publish([{"type": "event", "n": i} for i in range(5)])
            await asyncio.sleep(0.01)
            received = [fast.get_nowait()["n"] for _ in range(fast.qsize())]
            assert received == [2, 3, 4]  # oldest dropped, newest kept
            count = broadcaster.subscriber_count
            size = slow.qsize()
        return count, size, broadcaster.subscriber_count

    assert asyncio.run(scenario()) == (2, 3, 0)
