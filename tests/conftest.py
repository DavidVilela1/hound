"""Shared fixtures. Nothing here needs root privileges or real network traffic."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from app.core.config import Settings
from app.database.engine import Database
from app.models.events import NetworkEvent, PacketType, TransportProtocol

BASE_TIME = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def blocklist_file(tmp_path: Path) -> Path:
    path = tmp_path / "blocklist.txt"
    path.write_text("# test list\nbad.example\n*.tracker.test\n0.0.0.0 hosts-style.example\n", encoding="utf-8")
    return path


@pytest.fixture
def geo_file(tmp_path: Path) -> Path:
    path = tmp_path / "geo.csv"
    path.write_text("# cidr,country\n93.184.216.0/24,US\n185.15.56.0/22,NL\n2a00:1450::/32,DE\n", encoding="utf-8")
    return path


@pytest.fixture
def settings(tmp_path: Path, blocklist_file: Path, geo_file: Path) -> Settings:
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        database_url=f"sqlite:///{tmp_path / 'hound-test.db'}",
        blocklist_path=blocklist_file,
        geo_ranges_path=geo_file,
        ingest_token_path=tmp_path / ".ingest_token",
        allowed_hosts="testserver,127.0.0.1,localhost",
        flush_interval_seconds=0.05,
        demo_seed=42,
    )


@pytest.fixture
def database(settings: Settings) -> Iterator[Database]:
    db = Database(settings.resolved_database_url)
    db.initialize()
    yield db
    db.dispose()


EventFactory = Callable[..., NetworkEvent]


@pytest.fixture
def make_event() -> EventFactory:
    """Build valid events with sensible defaults; override any field by keyword."""

    def factory(**overrides: Any) -> NetworkEvent:
        offset = overrides.pop("seconds", 0)
        packet_type = overrides.get("packet_type", PacketType.DNS_QUERY)
        defaults: dict[str, Any] = {
            "timestamp": BASE_TIME + timedelta(seconds=offset),
            "source_ip": "192.168.1.10",
            "source_port": 40000,
            "destination_ip": "192.168.1.1" if packet_type is PacketType.DNS_QUERY else "93.184.216.34",
            "destination_port": 53 if packet_type is PacketType.DNS_QUERY else 443,
            "protocol": TransportProtocol.UDP if packet_type is not PacketType.TCP_SYN else TransportProtocol.TCP,
            "packet_type": packet_type,
            "domain": "example.com" if packet_type is PacketType.DNS_QUERY else None,
            "interface": "test0",
            "dns_query_type": "A" if packet_type is PacketType.DNS_QUERY else None,
        }
        defaults.update(overrides)
        return NetworkEvent(**defaults)

    return factory
