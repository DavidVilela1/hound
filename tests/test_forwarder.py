"""Capture-daemon forwarding with an injected transport (no sockets)."""

from __future__ import annotations

import json

import pytest

from app.core.security import TOKEN_HEADER
from app.ingestion.forwarder import ForwarderError, HttpEventForwarder
from app.ingestion.queue import EventQueue
from tests.conftest import EventFactory


class Recorder:
    def __init__(self, statuses: list[int]) -> None:
        self.statuses = statuses
        self.calls: list[tuple[str, dict, dict]] = []

    def __call__(self, url: str, body: bytes, headers: dict[str, str], timeout: float) -> int:
        self.calls.append((url, json.loads(body), headers))
        return self.statuses.pop(0) if self.statuses else 202


def forwarder(transport: Recorder) -> HttpEventForwarder:
    fwd = HttpEventForwarder(EventQueue(), api_url="http://127.0.0.1:8000/", token="t" * 32, transport=transport)
    fwd._stop.wait = lambda timeout=None: False  # type: ignore[method-assign]  # skip real back-off sleeps
    return fwd


def test_successful_delivery(make_event: EventFactory) -> None:
    transport = Recorder([202])
    fwd = forwarder(transport)
    assert fwd.deliver([make_event(), make_event(seconds=1)])
    url, body, headers = transport.calls[0]
    assert url == "http://127.0.0.1:8000/api/ingest"
    assert headers[TOKEN_HEADER] == "t" * 32
    assert len(body["events"]) == 2 and body["events"][0]["domain"] == "example.com"
    assert fwd.stats.sent == 2


def test_retries_then_succeeds(make_event: EventFactory) -> None:
    transport = Recorder([503, 0, 202])
    fwd = forwarder(transport)
    assert fwd.deliver([make_event()])
    assert len(transport.calls) == 3 and fwd.stats.failures == 2


def test_auth_failure_is_not_retried(make_event: EventFactory) -> None:
    transport = Recorder([401])
    fwd = forwarder(transport)
    assert not fwd.deliver([make_event()])
    assert len(transport.calls) == 1 and fwd.stats.dropped == 1


def test_gives_up_after_bounded_retries(make_event: EventFactory) -> None:
    transport = Recorder([500] * 10)
    fwd = forwarder(transport)
    assert not fwd.deliver([make_event()])
    assert len(transport.calls) == 5


def test_rejects_non_http_urls() -> None:
    with pytest.raises(ForwarderError):
        HttpEventForwarder(EventQueue(), api_url="file:///etc/passwd", token="x" * 32)


def test_self_traffic_filter(make_event: EventFactory) -> None:
    from app.ingestion.forwarder import SelfTrafficFilter
    from app.models.events import PacketType

    guard = SelfTrafficFilter("http://127.0.0.1:8000")
    own = make_event(packet_type=PacketType.TCP_SYN, destination_ip="127.0.0.1", destination_port=8000)
    other_port = make_event(packet_type=PacketType.TCP_SYN, destination_ip="127.0.0.1", destination_port=8001)
    assert guard.excludes(own)
    assert not guard.excludes(other_port)
    assert not guard.excludes(make_event())
