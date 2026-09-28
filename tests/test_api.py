"""HTTP/WebSocket API tests (FastAPI TestClient; no network, no privileges)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.api.app import create_app
from app.core.config import Settings
from app.core.security import TOKEN_HEADER
from app.models.events import PacketType
from app.services.runtime import HoundRuntime
from tests.conftest import EventFactory


@pytest.fixture
def runtime(settings: Settings) -> HoundRuntime:
    return HoundRuntime(settings)


@pytest.fixture
def client(settings: Settings, runtime: HoundRuntime) -> Iterator[TestClient]:
    with TestClient(create_app(settings, runtime)) as test_client:
        yield test_client


@pytest.fixture
def seeded(client: TestClient, runtime: HoundRuntime, make_event: EventFactory) -> TestClient:
    runtime.processor.process_batch(
        [
            make_event(domain="www.example.com", seconds=0),
            make_event(domain="c2.bad.example", seconds=1, source_ip="192.168.1.23"),
            make_event(packet_type=PacketType.TCP_SYN, destination_port=3389, seconds=2),
            make_event(packet_type=PacketType.TCP_SYN, destination_ip="185.15.56.10", seconds=3),
        ]
    )
    return client


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok" and body["database"] == "ok"
    assert body["pipeline"]["mode"] == "idle" and body["pipeline"]["remote_ingest_enabled"] is True
    assert response.headers["x-content-type-options"] == "nosniff"


def test_events_list_and_detail(seeded: TestClient) -> None:
    body = seeded.get("/api/events").json()
    assert body["total"] == 4 and body["limit"] == 50 and body["offset"] == 0
    first = body["items"][0]
    assert first["packet_type"] == "tcp_syn" and first["country"] == "NL" and first["country_name"] == "Netherlands"
    detail = seeded.get(f"/api/events/{first['id']}").json()
    assert detail == first


def test_events_filters(seeded: TestClient) -> None:
    get = lambda **p: seeded.get("/api/events", params=p).json()["total"]  # noqa: E731
    assert get(risk_level="dangerous") == 1
    assert get(min_risk_level="suspicious") == 2
    assert get(source_ip="192.168.1.23") == 1
    assert get(domain="EXAMPLE.com") == 1
    assert get(packet_type="tcp_syn") == 2
    assert get(protocol="TCP") == 2
    assert get(country="nl") == 1
    assert get(limit=1, offset=3) == 4
    assert len(seeded.get("/api/events", params={"limit": 1, "offset": 3}).json()["items"]) == 1


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 100000},
        {"limit": 600},  # above HOUND_MAX_PAGE_SIZE (500)
        {"offset": -1},
        {"risk_level": "catastrophic"},
        {"source_ip": "not-an-ip"},
        {"country": "U$"},
        {"since": "2026-01-02T00:00:00", "until": "2026-01-01T00:00:00"},
    ],
)
def test_events_validation(client: TestClient, params: dict[str, object]) -> None:
    assert client.get("/api/events", params=params).status_code == 422


def test_event_not_found_and_bad_id(client: TestClient) -> None:
    assert client.get("/api/events/12345").status_code == 404
    assert client.get("/api/events/0").status_code == 422
    assert client.get("/api/events/abc").status_code == 422


def test_devices(seeded: TestClient) -> None:
    body = seeded.get("/api/devices").json()
    assert body["total"] == 2
    top = body["items"][0]
    assert top["source_ip"] == "192.168.1.23" and top["risk_level"] == "dangerous"
    assert top["observations"][0]["code"] == "BLOCKLISTED_DOMAIN"
    assert seeded.get("/api/devices", params={"risk_level": "safe"}).json()["total"] == 0
    assert seeded.get("/api/devices/192.168.1.10").json()["event_count"] == 3
    assert seeded.get("/api/devices/10.9.9.9").status_code == 404
    assert seeded.get("/api/devices/nonsense").status_code == 422
    assert seeded.get("/api/devices", params={"sort": "bogus"}).status_code == 422


def test_stats(seeded: TestClient) -> None:
    body = seeded.get("/api/stats").json()
    assert body["total_events"] == 4 and body["devices"] == 2
    assert body["dangerous_events"] == 1 and body["suspicious_events"] == 1
    assert body["events_by_risk"] == {"safe": 2, "suspicious": 1, "dangerous": 1}
    assert body["dns_queries"] == 2 and body["connection_attempts"] == 2
    assert body["blocklist_hits"] == 1
    assert body["pipeline"]["events_processed"] == 4


def test_country_stats(seeded: TestClient) -> None:
    body = seeded.get("/api/stats/countries").json()
    assert body["basis"] == "events" and body["simulated"] is True
    assert body["total_events"] == 2  # LAN destinations excluded by default
    assert {c["country"] for c in body["countries"]} == {"US", "NL"}
    assert sum(c["percentage"] for c in body["countries"]) == pytest.approx(100.0)
    with_local = seeded.get("/api/stats/countries", params={"include_local": True}).json()
    assert with_local["total_events"] == 4
    assert seeded.get("/api/stats/countries", params={"since_minutes": 0}).status_code == 422


def test_ingest_requires_token(client: TestClient, runtime: HoundRuntime, make_event: EventFactory) -> None:
    payload = {"events": [make_event().model_dump(mode="json")]}
    assert client.post("/api/ingest", json=payload).status_code == 401
    assert (
        client.post("/api/ingest", json=payload, headers={TOKEN_HEADER: "wrong-token-value-xxxxxxxxxxx"}).status_code
        == 401
    )
    ok = client.post("/api/ingest", json=payload, headers={TOKEN_HEADER: runtime.ingest_token or ""})
    assert ok.status_code == 202 and ok.json() == {"accepted": 1, "dropped": 0}


def test_ingest_validation(client: TestClient, runtime: HoundRuntime, make_event: EventFactory) -> None:
    headers = {TOKEN_HEADER: runtime.ingest_token or ""}
    bad_ip = make_event().model_dump(mode="json") | {"source_ip": "999.1.1.1"}
    assert client.post("/api/ingest", json={"events": [bad_ip]}, headers=headers).status_code == 422
    assert client.post("/api/ingest", json={"events": []}, headers=headers).status_code == 422
    assert client.post("/api/ingest", content=b"{not json", headers=headers).status_code == 422
    huge = b"x" * (3 * 1024 * 1024)
    assert client.post("/api/ingest", content=huge, headers=headers).status_code == 413


def test_websocket_streams_new_events(client: TestClient, runtime: HoundRuntime, make_event: EventFactory) -> None:
    with client.websocket_connect("/ws/events") as ws:
        assert ws.receive_json()["type"] == "hello"
        runtime.queue.offer(make_event(domain="live.example"))
        message = ws.receive_json()
        assert message["type"] == "event" and message["data"]["domain"] == "live.example"


def test_websocket_rejects_foreign_origin(client: TestClient) -> None:
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/events", headers={"origin": "https://evil.example"}) as ws:
            ws.receive_json()


def test_host_header_allow_list(client: TestClient) -> None:
    assert client.get("/health", headers={"host": "attacker.example"}).status_code == 400


def test_openapi_docs_available(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    for path in (
        "/health",
        "/api/events",
        "/api/events/{event_id}",
        "/api/devices",
        "/api/stats",
        "/api/stats/countries",
        "/api/ingest",
    ):
        assert path in schema["paths"]
    assert "IngestRequest" in schema["components"]["schemas"]
    assert client.get("/docs").status_code == 200
    assert client.get("/redoc").status_code == 200
