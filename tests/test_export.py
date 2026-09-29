"""Export of events and devices (17b, ADR-027): same data as the API, streamed, spreadsheet-safe."""

from __future__ import annotations

import csv
import io
import itertools
import json
import logging
import re
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from app.api.app import create_app
from app.core.config import Settings
from app.database.repositories import EventFilter, EventRepository
from app.models.events import PacketType
from app.services import export as export_module
from app.services.export import (
    DEVICE_COLUMNS,
    EVENT_COLUMNS,
    ExportService,
    csv_cell,
    csv_stream,
)
from app.services.runtime import HoundRuntime
from tests.conftest import EventFactory

LAPTOP = "192.168.1.10"
PHONE = "192.168.1.20"


@pytest.fixture
def runtime(settings: Settings) -> Iterator[HoundRuntime]:
    runtime = HoundRuntime(settings)
    runtime.database.initialize()
    yield runtime
    runtime.database.dispose()


@pytest.fixture
def client(settings: Settings, runtime: HoundRuntime) -> Iterator[TestClient]:
    with TestClient(create_app(settings, runtime), base_url="http://127.0.0.1") as test_client:
        yield test_client


def store_sample(runtime: HoundRuntime, make_event: EventFactory) -> None:
    runtime.processor.process_batch(
        [
            make_event(source_ip=LAPTOP, domain="example.com", seconds=0),
            make_event(source_ip=LAPTOP, domain="bad.example", seconds=1),  # blocklisted → dangerous
            make_event(packet_type=PacketType.TCP_SYN, source_ip=PHONE, seconds=2),
            make_event(source_ip=PHONE, domain="k8x7q2z9w4v1.xyz", seconds=3),
        ]
    )


def read_csv(text: str) -> list[dict[str, str]]:
    assert text.startswith("\ufeff")  # byte-order mark, so Excel reads UTF-8
    return list(csv.DictReader(io.StringIO(text.removeprefix("\ufeff"), newline="")))


# ------------------------------------------------------------------------------ formula safety
@pytest.mark.parametrize(
    "value",
    ["=1+1", "+1", "-1", "@SUM(A1)", "\t=1", "\r=1", "=cmd|' /C calc'!A0", '  =HYPERLINK("http://x")', "\n@x"],
)
def test_formula_like_text_is_neutralised(value: str) -> None:
    assert csv_cell(value) == "'" + value


@pytest.mark.parametrize("value", ["example.com", "192.168.1.10", "2001:db8::1", "a=b", "", "Wi-Fi"])
def test_ordinary_text_is_unchanged(value: str) -> None:
    assert csv_cell(value) == value


def test_numbers_and_empty_values() -> None:
    assert csv_cell(-5) == -5  # numbers are not text a spreadsheet would evaluate
    assert csv_cell(None) == ""


def test_hostile_interface_name_cannot_become_a_formula(
    runtime: HoundRuntime, client: TestClient, make_event: EventFactory
) -> None:
    """Ingest input is untrusted (any token holder, or a crafted interface name)."""
    runtime.processor.process_batch([make_event(interface="=cmd|' /C calc'!A0")])
    [row] = read_csv(client.get("/api/export/events").text)
    assert row["interface"] == "'=cmd|' /C calc'!A0"


# ------------------------------------------------------------------------------ events
def test_events_csv_matches_the_api(runtime: HoundRuntime, client: TestClient, make_event: EventFactory) -> None:
    store_sample(runtime, make_event)
    response = client.get("/api/export/events")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/csv; charset=utf-8"
    assert re.fullmatch(
        r'attachment; filename="hound-events-\d{8}-\d{6}\.csv"', response.headers["content-disposition"]
    )
    assert response.headers["cache-control"] == "no-store"
    assert "\r\n" in response.text  # RFC 4180 line ends

    rows = read_csv(response.text)
    assert list(rows[0]) == EVENT_COLUMNS
    api = client.get("/api/events", params={"limit": 50}).json()["items"]
    assert [int(r["id"]) for r in rows] == sorted(e["id"] for e in api)  # all of them, oldest first
    by_id = {e["id"]: e for e in api}
    for row in rows:
        event = by_id[int(row["id"])]
        for column in EVENT_COLUMNS[:17]:
            expected = event[column]
            assert row[column] == ("" if expected is None else str(expected)), column
        assert row["risk_reason_codes"] == ";".join(r["code"] for r in event["risk_reasons"])
    dangerous = next(r for r in rows if r["domain"] == "bad.example")
    assert "BLOCKLISTED_DOMAIN" in dangerous["risk_reason_codes"].split(";")
    assert "(+" in dangerous["risk_reasons"]


def test_events_json_matches_the_api(runtime: HoundRuntime, client: TestClient, make_event: EventFactory) -> None:
    store_sample(runtime, make_event)
    response = client.get("/api/export/events", params={"format": "json"})
    assert response.headers["content-type"] == "application/json"
    assert response.headers["content-disposition"].endswith('.json"')
    exported = response.json()
    api = client.get("/api/events", params={"limit": 50}).json()["items"]
    assert exported == sorted(api, key=lambda e: e["id"])


@pytest.mark.parametrize(
    "params",
    [
        {"min_risk_level": "suspicious"},
        {"source_ip": PHONE},
        {"domain": "EXAMPLE"},
        {"packet_type": "tcp_syn"},
        {"since": "2026-01-15T12:00:02Z"},
    ],
)
def test_filters_are_the_same_as_the_list_endpoint(
    runtime: HoundRuntime, client: TestClient, make_event: EventFactory, params: dict[str, str]
) -> None:
    store_sample(runtime, make_event)
    exported = client.get("/api/export/events", params={"format": "json", **params}).json()
    listed = client.get("/api/events", params={"limit": 50, **params}).json()["items"]
    assert exported and sorted(e["id"] for e in exported) == sorted(e["id"] for e in listed)


@pytest.mark.parametrize(
    "params",
    [
        {"format": "xml"},
        {"source_ip": "not-an-ip"},
        {"since": "2026-02-01T00:00:00Z", "until": "2026-01-01T00:00:00Z"},
        {"min_risk_level": "catastrophic"},
    ],
)
def test_invalid_requests_are_refused(client: TestClient, params: dict[str, str]) -> None:
    assert client.get("/api/export/events", params=params).status_code == 422


def test_empty_database(client: TestClient) -> None:
    assert read_csv(client.get("/api/export/events").text) == []
    assert client.get("/api/export/events").text == "\ufeff" + ",".join(EVENT_COLUMNS) + "\r\n"
    assert client.get("/api/export/events", params={"format": "json"}).json() == []
    assert client.get("/api/export/devices", params={"format": "json"}).json() == []


def test_list_endpoint_parameters_are_unchanged(client: TestClient) -> None:
    """The filters moved into a shared dependency; the public contract of /api/events must not change."""
    parameters = client.get("/openapi.json").json()["paths"]["/api/events"]["get"]["parameters"]
    assert sorted(p["name"] for p in parameters) == sorted(
        ["limit", "offset", "source_ip", "destination_ip", "domain", "risk_level", "min_risk_level"]
        + ["packet_type", "protocol", "country", "since", "until"]
    )


# ------------------------------------------------------------------------------ devices
def test_devices_csv_and_json(runtime: HoundRuntime, client: TestClient, make_event: EventFactory) -> None:
    store_sample(runtime, make_event)
    rows = read_csv(client.get("/api/export/devices").text)
    assert list(rows[0]) == DEVICE_COLUMNS
    assert [r["source_ip"] for r in rows] == [LAPTOP, PHONE]  # order Hound first saw them
    laptop = rows[0]
    assert (laptop["event_count"], laptop["dns_query_count"], laptop["risk_level"]) == ("2", "2", "dangerous")
    assert "BLOCKLISTED_DOMAIN" in laptop["observation_codes"].split(";")
    assert "(last seen 2026-01-15T12:00:01Z)" in laptop["observations"]

    exported = client.get("/api/export/devices", params={"format": "json"}).json()
    api = client.get("/api/devices", params={"sort": "first_seen"}).json()["items"]
    assert exported == api
    only = client.get("/api/export/devices", params={"format": "json", "risk_level": "dangerous"}).json()
    assert [d["source_ip"] for d in only] == [LAPTOP]


# ------------------------------------------------------------------------------ streaming
def test_every_page_is_read_including_an_exact_multiple(runtime: HoundRuntime, make_event: EventFactory) -> None:
    runtime.processor.process_batch([make_event(domain=f"h{n}.example", seconds=n) for n in range(9)])
    for page_size in (3, 4, 100):
        items = list(ExportService(runtime.database, page_size=page_size).events(EventFilter()))
        assert [e.domain for e in items] == [f"h{n}.example" for n in range(9)], page_size


def test_export_is_a_snapshot_of_when_it_started(runtime: HoundRuntime, make_event: EventFactory) -> None:
    runtime.processor.process_batch([make_event(domain=f"old{n}.example", seconds=n) for n in range(5)])
    items = ExportService(runtime.database, page_size=2).events(EventFilter())
    first = next(items)
    runtime.processor.process_batch([make_event(domain=f"new{n}.example", seconds=100 + n) for n in range(5)])
    rest = list(items)
    assert [e.domain for e in [first, *rest]] == [f"old{n}.example" for n in range(5)]


def test_pages_are_fetched_lazily(
    runtime: HoundRuntime, make_event: EventFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime.processor.process_batch([make_event(domain=f"h{n}.example", seconds=n) for n in range(10)])
    calls: list[int] = []
    original = EventRepository.export_page

    def counting(self: EventRepository, *args: Any, **kwargs: Any) -> Any:
        calls.append(kwargs["after_id"])
        return original(self, *args, **kwargs)

    monkeypatch.setattr(EventRepository, "export_page", counting)
    items = ExportService(runtime.database, page_size=3).events(EventFilter())
    assert calls == []  # nothing read yet (only the snapshot bound)
    list(itertools.islice(items, 4))
    assert len(calls) == 2  # two pages of three, not the whole table


def test_csv_is_written_in_chunks_without_reading_everything() -> None:
    def rows() -> Iterator[list[Any]]:
        for n in range(4):
            yield [n, f"row{n}"]
        raise AssertionError("read past the second chunk: the writer is not streaming")

    chunks = csv_stream(["n", "text"], rows(), flush_every=2)
    first = next(chunks)
    assert first == "\ufeffn,text\r\n0,row0\r\n1,row1\r\n"
    assert next(chunks) == "2,row2\r\n3,row3\r\n"


def test_database_down_before_streaming_is_a_503(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def down(self: EventRepository) -> int:
        raise OperationalError("SELECT", {}, Exception("database is locked"))

    monkeypatch.setattr(EventRepository, "max_id", down)
    response = client.get("/api/export/events")
    assert response.status_code == 503 and response.json() == {"detail": "Database unavailable"}


def test_database_error_mid_export_is_logged(
    runtime: HoundRuntime, make_event: EventFactory, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    runtime.processor.process_batch([make_event(domain=f"h{n}.example", seconds=n) for n in range(5)])
    original = EventRepository.export_page

    def fails_on_second_page(self: EventRepository, *args: Any, **kwargs: Any) -> Any:
        if kwargs["after_id"]:
            raise OperationalError("SELECT", {}, Exception("disk I/O error"))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(EventRepository, "export_page", fails_on_second_page)
    items = ExportService(runtime.database, page_size=2).events(EventFilter())
    with caplog.at_level(logging.ERROR, logger=export_module.__name__), pytest.raises(OperationalError):
        list(items)
    assert "Export interrupted by a database error" in caplog.text


def test_interrupted_json_is_not_valid_json(runtime: HoundRuntime, make_event: EventFactory) -> None:
    """A cut-off JSON download fails to parse instead of looking like a shorter, complete list."""
    runtime.processor.process_batch([make_event(domain=f"h{n}.example", seconds=n) for n in range(3)])
    items = ExportService(runtime.database).events(EventFilter())
    chunks = list(export_module.json_stream(items, flush_every=2))
    assert len(chunks) == 2
    assert [e["domain"] for e in json.loads("".join(chunks))] == ["h0.example", "h1.example", "h2.example"]
    with pytest.raises(json.JSONDecodeError):
        json.loads(chunks[0])  # two complete items, but no closing bracket


def test_json_is_written_in_chunks_without_reading_everything(runtime: HoundRuntime, make_event: EventFactory) -> None:
    runtime.processor.process_batch([make_event(domain=f"h{n}.example", seconds=n) for n in range(2)])
    stored = list(ExportService(runtime.database).events(EventFilter()))

    def items() -> Iterator[Any]:
        yield from stored
        raise AssertionError("read past the first chunk: the writer is not streaming")

    first = next(export_module.json_stream(items(), flush_every=2))
    assert first.startswith("[\n{") and first.count("h0.example") == 1
