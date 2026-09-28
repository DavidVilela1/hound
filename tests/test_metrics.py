"""``GET /api/metrics``: every loss point is counted, attributed to its stage, and summed."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from app.api.app import create_app
from app.core.config import Settings
from app.core.security import TOKEN_HEADER
from app.ingestion.forwarder import HttpEventForwarder
from app.ingestion.queue import EventQueue
from app.services.processing import summarize_latency
from app.services.runtime import HoundRuntime
from tests.conftest import EventFactory

DAEMON_REPORT = {
    "interface": "Wi-Fi",
    "packets_parsed": 120,
    "packets_malformed": 2,
    "queue_dropped": 5,
    "queue_high_water": 90,
    "queue_capacity": 10_000,
    "events_forwarded": 100,
    "events_forward_dropped": 7,
    "forward_failures": 3,
}


@pytest.fixture
def runtime(settings: Settings) -> HoundRuntime:
    return HoundRuntime(settings)


@pytest.fixture
def client(settings: Settings, runtime: HoundRuntime) -> Iterator[TestClient]:
    with TestClient(create_app(settings, runtime)) as test_client:
        yield test_client


def ingest(client: TestClient, runtime: HoundRuntime, body: Any, **kwargs: Any) -> int:
    headers = {TOKEN_HEADER: runtime.ingest_token or ""} | kwargs.pop("headers", {})
    if isinstance(body, bytes):
        return client.post("/api/ingest", content=body, headers=headers).status_code
    return client.post("/api/ingest", json=body, headers=headers).status_code


# ------------------------------------------------------------------------------ building blocks
def test_latency_percentiles_nearest_rank() -> None:
    empty = summarize_latency([])
    assert (empty.samples, empty.p50_ms, empty.p95_ms, empty.max_ms) == (0, None, None, None)
    hundred = summarize_latency([float(n) for n in range(100, 0, -1)])  # unsorted input
    assert (hundred.p50_ms, hundred.p95_ms, hundred.max_ms) == (50.0, 95.0, 100.0)
    assert summarize_latency([7.0]).p95_ms == 7.0


def test_queue_high_water_mark(make_event: EventFactory) -> None:
    queue = EventQueue(max_size=4)
    for second in range(3):
        queue.offer(make_event(seconds=second))
    queue.get_batch(10, 0)
    queue.offer(make_event(seconds=9))
    assert queue.stats().high_water == 3  # the peak, not the current size
    for second in range(10):
        queue.offer(make_event(seconds=second))
    stats = queue.stats()
    assert stats.high_water == stats.capacity == 4 and stats.dropped == 7


def test_processing_counts_batches_and_latency(runtime: HoundRuntime, make_event: EventFactory) -> None:
    runtime.database.initialize()
    runtime.processor.process_batch([make_event(), make_event(seconds=1)])
    runtime.processor.process_batch([make_event(seconds=2)])
    runtime.processor.process_batch([])  # nothing to do: not a batch
    assert runtime.processor.stats().batches == 2
    latency = runtime.processor.latency()
    assert latency.samples == 2 and latency.p50_ms is not None and latency.max_ms is not None
    assert 0 < latency.p50_ms <= latency.max_ms
    runtime.database.dispose()


def test_forwarder_attaches_fresh_counters_to_every_attempt(make_event: EventFactory) -> None:
    bodies: list[bytes] = []
    statuses = [503, 202]
    calls = iter(range(100))

    def transport(url: str, body: bytes, headers: dict[str, str], timeout: float) -> int:
        bodies.append(body)
        return statuses.pop(0)

    forwarder = HttpEventForwarder(
        EventQueue(),
        api_url="http://127.0.0.1:8000",
        token="t" * 32,
        transport=transport,
        reporter=lambda: {"forward_failures": next(calls)},
    )
    forwarder._stop.wait = lambda timeout=None: False  # type: ignore[method-assign]  # no back-off sleep
    assert forwarder.deliver([make_event()])
    reports = [json.loads(body)["daemon"]["forward_failures"] for body in bodies]
    assert reports == [0, 1]  # re-read on the retry, not frozen at the first attempt

    bodies.clear()
    statuses.append(202)
    plain = HttpEventForwarder(EventQueue(), api_url="http://127.0.0.1:8000", token="t" * 32, transport=transport)
    assert plain.deliver([make_event()])
    assert "daemon" not in json.loads(bodies[0])  # no reporter: request unchanged


# ------------------------------------------------------------------------------ the endpoint
def test_fresh_server_reports_zero_loss(client: TestClient) -> None:
    body = client.get("/api/metrics").json()
    assert body["loss"] == {
        "total_events_lost": 0,
        "daemon_queue_full": None,
        "daemon_delivery_failed": None,
        "server_queue_full": 0,
        "processing_failed": 0,
        "daemon_reported": False,
    }
    assert body["daemon"] is None
    assert body["storage"]["database_bytes"] > 0 and body["storage"]["retention_limit"] > 0
    assert body["uptime_seconds"] >= 0
    assert body["processing"]["batch_latency"]["samples"] == 0


def test_ingest_outcomes_are_counted(client: TestClient, runtime: HoundRuntime, make_event: EventFactory) -> None:
    event = make_event().model_dump(mode="json")
    assert ingest(client, runtime, {"events": [event]}, headers={TOKEN_HEADER: "wrong" * 8}) == 401
    assert ingest(client, runtime, b"{not json") == 422
    assert ingest(client, runtime, {"events": [event], "daemon": {"queue_dropped": -1}}) == 422
    assert ingest(client, runtime, {"events": [event], "daemon": {"unknown_counter": 1}}) == 422
    assert ingest(client, runtime, b"x" * (3 * 1024 * 1024)) == 413
    assert ingest(client, runtime, {"events": [event, make_event(seconds=1).model_dump(mode="json")]}) == 202

    counts = client.get("/api/metrics").json()["ingest"]
    assert counts == {
        "requests_accepted": 1,
        "requests_unauthorized": 1,
        "requests_invalid": 3,
        "requests_too_large": 1,
        "events_accepted": 2,
        "events_dropped": 0,
    }


def test_daemon_report_is_exposed_and_counted_as_loss(
    client: TestClient, runtime: HoundRuntime, make_event: EventFactory
) -> None:
    assert ingest(client, runtime, {"events": [make_event().model_dump(mode="json")], "daemon": DAEMON_REPORT}) == 202
    body = client.get("/api/metrics").json()
    daemon = body["daemon"]
    assert {k: daemon[k] for k in DAEMON_REPORT} == DAEMON_REPORT and daemon["received_at"]
    assert body["loss"]["daemon_reported"] is True
    assert body["loss"]["daemon_queue_full"] == 5 and body["loss"]["daemon_delivery_failed"] == 7
    assert body["loss"]["total_events_lost"] == 12


def test_server_side_losses_are_attributed(settings: Settings, make_event: EventFactory) -> None:
    runtime = HoundRuntime(settings.model_copy(update={"queue_max_size": 100}))
    runtime.database.initialize()
    for second in range(103):  # worker not started: the queue fills up
        runtime.queue.offer(make_event(seconds=second))

    class FailingStore:
        pruned_total = 0

        def save(self, items: Any) -> list[Any]:
            raise OperationalError("INSERT", {}, Exception("database is locked"))

    runtime.processor._store = FailingStore()
    runtime.processor.process_batch([make_event(), make_event(seconds=1)])
    loss = runtime.metrics().loss
    assert (loss.server_queue_full, loss.processing_failed, loss.total_events_lost) == (3, 2, 5)
    assert loss.daemon_queue_full is None and not loss.daemon_reported
    metrics = runtime.metrics()
    assert metrics.queue.high_water == metrics.queue.capacity == 100
    runtime.database.dispose()


def test_websocket_drops_and_retention_are_reported_but_not_loss(settings: Settings, make_event: EventFactory) -> None:
    runtime = HoundRuntime(settings.model_copy(update={"ws_client_queue_size": 2}))
    runtime.database.initialize()

    async def slow_viewer() -> None:
        runtime.broadcaster.bind_loop(asyncio.get_running_loop())
        async with runtime.broadcaster.subscribe():
            runtime.broadcaster.publish([{"type": "event", "n": n} for n in range(5)])
            await asyncio.sleep(0.01)

    asyncio.run(slow_viewer())
    runtime.store._retention = 1  # keep only the newest event
    runtime.processor.process_batch([make_event(seconds=s) for s in range(3)])
    runtime.store.prune()
    metrics = runtime.metrics()
    assert metrics.websocket.messages_dropped == 3
    assert metrics.storage.retention_pruned_events == 2
    assert metrics.loss.total_events_lost == 0  # neither is data loss
    runtime.database.dispose()


def test_metrics_contain_no_addresses_or_domains(
    client: TestClient, runtime: HoundRuntime, make_event: EventFactory
) -> None:
    runtime.processor.process_batch([make_event(domain="private-browsing.example", source_ip="192.168.1.77")])
    text = client.get("/api/metrics").text
    assert "private-browsing" not in text and "192.168.1.77" not in text


def test_metrics_documented_in_openapi(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    assert "/api/metrics" in schema["paths"]
    assert "daemon" in schema["components"]["schemas"]["IngestRequest"]["properties"]
