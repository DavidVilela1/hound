"""Frontend helpers and the API client contract (the dashboard only uses these)."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from app.api.app import create_app
from app.core.config import Settings
from app.frontend.client import ApiError, HoundApiClient, LiveEventStream
from app.frontend.formatting import country_rows, device_row, event_row, fmt_endpoint, passes_min_level, top_reason
from app.services.runtime import HoundRuntime
from tests.conftest import EventFactory

SAMPLE_EVENT: dict[str, Any] = {
    "id": 5,
    "timestamp": "2026-01-15T12:00:00Z",
    "source_ip": "192.168.1.10",
    "destination_ip": "2606:4700::1",
    "destination_port": 443,
    "protocol": "TCP",
    "packet_type": "tcp_syn",
    "domain": "example.com",
    "domain_source": "dns_cache",
    "country_name": "United States",
    "risk_level": "suspicious",
    "risk_score": 30,
    "risk_reasons": [
        {"code": "A", "points": 5, "description": "small"},
        {"code": "B", "points": 25, "description": "big"},
    ],
}


def test_event_row_formatting() -> None:
    row = event_row(SAMPLE_EVENT)
    assert row["destination"] == "[2606:4700::1]:443"
    assert row["domain"] == "example.com (via DNS)"
    assert row["protocol"] == "TCP · TCP SYN"
    assert row["reason"] == "big"
    assert row["risk_level"] == "suspicious" and row["risk_score"] == 30
    assert len(row["time"]) == 8


def test_small_helpers() -> None:
    assert fmt_endpoint(None, None) == "—"
    assert fmt_endpoint("10.0.0.1", None) == "10.0.0.1"
    assert top_reason({"risk_reasons": []}) == "—"
    assert passes_min_level("dangerous", "suspicious")
    assert not passes_min_level("safe", "suspicious")
    assert device_row({"source_ip": "1.2.3.4", "event_count": 3})["events"] == 3
    rows = country_rows(
        {"countries": [{"country": "PT", "country_name": "Portugal", "events": 2, "percentage": 66.666}]}
    )
    assert rows[0]["percentage"] == "66.7%"


def test_api_client_against_real_app(settings: Settings, make_event: EventFactory) -> None:
    runtime = HoundRuntime(settings)
    app = create_app(settings, runtime)

    async def scenario() -> None:
        runtime.start(asyncio.get_running_loop())
        try:
            runtime.processor.process_batch([make_event(domain="client.example")])
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
                api = HoundApiClient("http://testserver", client=http)
                assert (await api.health())["status"] == "ok"
                assert (await api.stats())["total_events"] == 1
                events = await api.events(limit=5, min_risk_level=None)
                assert events["items"][0]["domain"] == "client.example"
                assert (await api.event(events["items"][0]["id"]))["id"] == events["items"][0]["id"]
                assert (await api.device("192.168.1.10"))["event_count"] == 1
                assert (await api.devices())["total"] == 1
                assert (await api.countries(include_local=True))["total_events"] == 1
                try:
                    await api.event(999)
                except ApiError as exc:
                    assert "Not found" in str(exc)
                else:
                    raise AssertionError("expected ApiError")
        finally:
            runtime.stop()

    asyncio.run(scenario())


def test_api_client_reports_unreachable_server() -> None:
    async def scenario() -> None:
        api = HoundApiClient("http://127.0.0.1:9", timeout=0.5)
        try:
            await api.stats()
        except ApiError as exc:
            assert "Cannot reach" in str(exc)
        else:
            raise AssertionError("expected ApiError")
        finally:
            await api.aclose()

    asyncio.run(scenario())


def test_live_stream_dispatch_and_unsubscribe() -> None:
    stream = LiveEventStream("ws://127.0.0.1:9/ws/events")
    seen: list[int] = []
    unsubscribe = stream.subscribe(lambda e: seen.append(e["id"]))
    stream.subscribe(lambda e: 1 / 0)  # a failing subscriber must not affect others
    stream.dispatch({"type": "event", "data": {"id": 1}})
    stream.dispatch({"type": "heartbeat", "data": {}})
    stream.dispatch({"type": "event", "data": "not-a-dict"})
    unsubscribe()
    stream.dispatch({"type": "event", "data": {"id": 2}})
    assert seen == [1]
