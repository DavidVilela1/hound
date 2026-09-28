"""Event normalisation and validation (the contract every source must satisfy)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.models.events import NetworkEvent, PacketType, TransportProtocol
from app.models.risk import RiskAssessment, RiskLevel, RiskReason

BASE = {
    "timestamp": datetime(2026, 1, 1, 12, 0, 0),
    "source_ip": " 192.168.1.10 ",
    "destination_ip": "2001:0DB8:0000::0001",
    "protocol": "UDP",
    "packet_type": "dns_query",
    "domain": "WWW.Example.COM.",
    "source_port": 5353,
    "destination_port": 53,
}


def test_normalisation() -> None:
    event = NetworkEvent(**BASE)
    assert event.timestamp.tzinfo is UTC  # naive → UTC
    assert event.destination_ip == "2001:db8::1"
    assert event.domain == "www.example.com"
    assert event.protocol is TransportProtocol.UDP and event.packet_type is PacketType.DNS_QUERY
    assert not event.is_response


def test_timezone_conversion() -> None:
    lisbon_summer = timezone(timedelta(hours=1))
    event = NetworkEvent(**(BASE | {"timestamp": datetime(2026, 7, 1, 13, 0, tzinfo=lisbon_summer)}))
    assert event.timestamp == datetime(2026, 7, 1, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    "override",
    [
        {"source_ip": "300.1.1.1"},
        {"destination_ip": "example.com"},
        {"source_port": 70000},
        {"destination_port": -1},
        {"protocol": "ICMP"},
        {"packet_type": "http"},
        {"domain": "bad domain.example"},
        {"dns_query_type": "a; drop"},
        {"dns_answers": ("1.2.3.4", "nope")},
        {"unexpected_field": 1},
    ],
)
def test_invalid_events_rejected(override: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        NetworkEvent(**(BASE | override))


def test_events_are_immutable() -> None:
    event = NetworkEvent(**BASE)
    with pytest.raises(ValidationError):
        event.domain = "other.example"  # type: ignore[misc]


def test_json_round_trip() -> None:
    event = NetworkEvent(**(BASE | {"packet_type": "dns_response", "dns_rcode": 0, "dns_answers": ("93.184.216.34",)}))
    assert NetworkEvent.model_validate_json(event.model_dump_json()) == event
    assert event.is_response


def test_risk_value_objects() -> None:
    assessment = RiskAssessment(
        score=30,
        level=RiskLevel.SUSPICIOUS,
        reasons=(RiskReason("A", 5, "small"), RiskReason("B", 25, "big")),
    )
    assert assessment.summary == "big"
    assert RiskAssessment(0, RiskLevel.SAFE).summary is None
    assert RiskLevel.DANGEROUS.label == "🔴 DANGEROUS" and RiskLevel.SAFE.rank == 0
