"""Database initialisation, insertion, querying, filtering and persistence."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from sqlalchemy import inspect, text

from app.database.engine import Database
from app.database.repositories import DeviceRepository, EventFilter, EventRepository
from app.models.events import NetworkEvent, PacketType
from app.models.processed import Enrichment, ProcessedEvent
from app.models.risk import RiskAssessment, RiskLevel, RiskReason
from tests.conftest import BASE_TIME, EventFactory

WINDOW = timedelta(minutes=60)


def processed(
    event: NetworkEvent, score: int = 0, country: str | None = "US", reasons: tuple[RiskReason, ...] = ()
) -> ProcessedEvent:
    level = RiskLevel.DANGEROUS if score >= 70 else RiskLevel.SUSPICIOUS if score >= 25 else RiskLevel.SAFE
    return ProcessedEvent(
        event=event,
        enrichment=Enrichment(
            country=country, domain=event.domain, domain_source=None, blocklist_match=None, destination_is_public=True
        ),
        risk=RiskAssessment(score=score, level=level, reasons=reasons),
    )


def save(db: Database, items: list[ProcessedEvent]) -> None:
    with db.session() as session:
        EventRepository(session).add_many(items)
        DeviceRepository(session).apply_events(items, risk_window=WINDOW)


def sample_events(make_event: EventFactory) -> list[ProcessedEvent]:
    """10 DNS queries alternating between two devices + 1 SYN."""
    items = []
    for i in range(10):
        score = 80 if i == 7 else 30 if i in (3, 5) else 0
        items.append(
            processed(
                make_event(
                    domain=f"site{i}.example", seconds=i, source_ip="192.168.1.20" if i % 2 == 0 else "192.168.1.10"
                ),
                score=score,
                country="NL" if i < 3 else "US",
            )
        )
    items.append(processed(make_event(packet_type=PacketType.TCP_SYN, seconds=20), 0, country=None))
    return items


def test_initialisation_creates_schema_and_indexes(tmp_path: Path) -> None:
    db = Database(f"sqlite:///{tmp_path / 'nested' / 'dir' / 'h.db'}")
    db.initialize()
    inspector = inspect(db.engine)
    assert {"events", "devices"} <= set(inspector.get_table_names())
    index_names = {ix["name"] for ix in inspector.get_indexes("events")}
    assert {"ix_events_timestamp", "ix_events_source_ip_timestamp", "ix_events_risk_level_timestamp"} <= index_names
    with db.engine.connect() as conn:
        assert conn.execute(text("PRAGMA journal_mode")).scalar() == "wal"
    assert db.ping()
    db.initialize()  # idempotent
    db.dispose()


def test_in_memory_database_works_across_threads() -> None:
    import threading

    db = Database("sqlite:///:memory:")
    db.initialize()
    result: list[bool] = []
    thread = threading.Thread(target=lambda: result.append(db.ping()))
    thread.start()
    thread.join()
    assert result == [True]


def test_insert_and_get(database: Database, make_event: EventFactory) -> None:
    reason = RiskReason("BLOCKLISTED_DOMAIN", 70, "Domain bad.example matches blocklist")
    save(database, [processed(make_event(domain="bad.example"), 70, reasons=(reason,))])
    with database.session() as s:
        record = EventRepository(s).get(1)
        assert record is not None
        assert record.domain == "bad.example"
        assert record.risk_level == "dangerous"
        assert record.risk_reasons == [reason.as_dict()]
        assert record.timestamp == BASE_TIME  # timezone-aware round trip
        assert EventRepository(s).get(999) is None


def test_listing_order_and_pagination(database: Database, make_event: EventFactory) -> None:
    save(database, sample_events(make_event))
    with database.session() as s:
        repo = EventRepository(s)
        page1, total = repo.list_page(EventFilter(), limit=4, offset=0)
        page2, _ = repo.list_page(EventFilter(), limit=4, offset=4)
        assert total == 11 and len(page1) == 4 and len(page2) == 4
        assert page1[0].packet_type == "tcp_syn"  # newest first
        timestamps = [r.timestamp for r in page1 + page2]
        assert timestamps == sorted(timestamps, reverse=True)
        assert not {r.id for r in page1} & {r.id for r in page2}


def test_filters(database: Database, make_event: EventFactory) -> None:
    save(database, sample_events(make_event))
    with database.session() as s:
        repo = EventRepository(s)
        assert repo.count(EventFilter(source_ip="192.168.1.20")) == 5
        assert repo.count(EventFilter(risk_level=RiskLevel.SUSPICIOUS)) == 2
        assert repo.count(EventFilter(min_risk_level=RiskLevel.SUSPICIOUS)) == 3
        assert repo.count(EventFilter(packet_type=PacketType.TCP_SYN)) == 1
        assert repo.count(EventFilter(protocol="TCP")) == 1
        assert repo.count(EventFilter(country="NL")) == 3
        assert repo.count(EventFilter(domain_contains="site1")) == 1
        assert repo.count(EventFilter(domain_contains="%")) == 0  # LIKE wildcards are escaped
        assert repo.count(EventFilter(since=BASE_TIME + timedelta(seconds=5))) == 6
        assert repo.count(EventFilter(until=BASE_TIME + timedelta(seconds=1))) == 2
        assert repo.count_by_risk_level() == {"safe": 8, "suspicious": 2, "dangerous": 1}
        assert repo.count_by_packet_type() == {"dns_query": 10, "tcp_syn": 1}


def test_country_distribution(database: Database, make_event: EventFactory) -> None:
    items = sample_events(make_event) + [processed(make_event(seconds=30), country="LAN")]
    save(database, items)
    with database.session() as s:
        repo = EventRepository(s)
        assert repo.country_distribution(include_local=False) == [("US", 7), ("NL", 3), ("UNKNOWN", 1)]
        assert ("LAN", 1) in repo.country_distribution(include_local=True)


def test_device_aggregation(database: Database, make_event: EventFactory) -> None:
    save(database, sample_events(make_event))
    with database.session() as s:
        repo = DeviceRepository(s)
        assert repo.count() == 2
        device = repo.get("192.168.1.10")
        assert device is not None
        assert device.event_count == 6  # 5 queries + 1 SYN
        assert device.dns_query_count == 5 and device.connection_attempt_count == 1
        assert device.suspicious_event_count == 2 and device.dangerous_event_count == 1
        assert device.risk_score == 80 and device.risk_level == "dangerous"
        assert device.first_seen == BASE_TIME + timedelta(seconds=1)
        assert device.last_seen == BASE_TIME + timedelta(seconds=20)
        rows, total = repo.list_page(risk_level=None, sort="risk", limit=10, offset=0)
        assert total == 2 and rows[0].source_ip == "192.168.1.10"
        rows, total = repo.list_page(risk_level=RiskLevel.SAFE, sort="events", limit=10, offset=0)
        assert total == 1 and rows[0].source_ip == "192.168.1.20"


def test_device_risk_window_expiry_and_observations(database: Database, make_event: EventFactory) -> None:
    reason = RiskReason("SUSPICIOUS_PORT", 25, "Connection attempt to port 3389")
    save(database, [processed(make_event(), 80, reasons=(reason,))])
    save(database, [processed(make_event(seconds=10), 0)])  # within window: peak kept
    with database.session() as s:
        device = DeviceRepository(s).get("192.168.1.10")
        assert device is not None and device.risk_score == 80
    save(database, [processed(make_event(seconds=4000), 0)])  # window (60 min) expired: reset
    with database.session() as s:
        device = DeviceRepository(s).get("192.168.1.10")
        assert device is not None
        assert device.risk_score == 0 and device.risk_level == "safe"
        assert device.observations[0]["code"] == "SUSPICIOUS_PORT"


def test_persistence_across_reopen(tmp_path: Path, make_event: EventFactory) -> None:
    url = f"sqlite:///{tmp_path / 'persist.db'}"
    first = Database(url)
    first.initialize()
    save(first, sample_events(make_event))
    first.dispose()
    second = Database(url)
    second.initialize()
    with second.session() as s:
        assert EventRepository(s).count() == 11
        assert DeviceRepository(s).count() == 2
    second.dispose()


def test_prune_keeps_newest(database: Database, make_event: EventFactory) -> None:
    save(database, sample_events(make_event))
    with database.session() as s:
        assert EventRepository(s).prune(4).events == 7
    with database.session() as s:
        rows, total = EventRepository(s).list_page(EventFilter(), limit=10, offset=0)
        assert total == 4 and min(r.id for r in rows) == 8
        assert EventRepository(s).prune(100).events == 0
