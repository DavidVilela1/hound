"""Read-side services used by the API routes (routes stay thin)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from app.database.engine import Database
from app.database.repositories import DeviceRepository, DeviceSort, EventFilter, EventRepository
from app.enrichment.geo import country_name
from app.models.events import PacketType
from app.models.risk import RiskLevel
from app.models.schemas import (
    CountryStat,
    CountryStatsOut,
    DeviceOut,
    DevicePage,
    EventOut,
    EventPage,
    PipelineStatus,
    RiskLevelCounts,
    StatsOut,
)
from app.services.mappers import device_to_schema, event_to_schema

COUNTRY_BASIS_DESCRIPTION = (
    "Share of stored events (DNS queries and TCP connection attempts) by the country of the "
    "event's destination IP address. DNS responses and SYN-ACKs are not counted."
)


class EventQueryService:
    def __init__(self, database: Database, *, geo_simulated: bool) -> None:
        self._db = database
        self._geo_simulated = geo_simulated

    def list_events(self, flt: EventFilter, *, limit: int, offset: int) -> EventPage:
        with self._db.session() as session:
            records, total = EventRepository(session).list_page(flt, limit=limit, offset=offset)
            items = [event_to_schema(r) for r in records]
        return EventPage(items=items, total=total, limit=limit, offset=offset)

    def get_event(self, event_id: int) -> EventOut | None:
        with self._db.session() as session:
            record = EventRepository(session).get(event_id)
            return event_to_schema(record) if record else None

    def country_stats(self, *, include_local: bool, since_minutes: int | None = None) -> CountryStatsOut:
        since = datetime.now(UTC) - timedelta(minutes=since_minutes) if since_minutes else None
        with self._db.session() as session:
            rows = EventRepository(session).country_distribution(include_local=include_local, since=since)
        total = sum(count for _, count in rows)
        countries = [
            CountryStat(
                country=code,
                country_name=country_name(code),
                events=count,
                percentage=round(100.0 * count / total, 2) if total else 0.0,
            )
            for code, count in rows
        ]
        return CountryStatsOut(
            description=COUNTRY_BASIS_DESCRIPTION,
            include_local=include_local,
            total_events=total,
            simulated=self._geo_simulated,
            countries=countries,
        )


class DeviceQueryService:
    def __init__(self, database: Database) -> None:
        self._db = database

    def list_devices(self, *, risk_level: RiskLevel | None, sort: DeviceSort, limit: int, offset: int) -> DevicePage:
        with self._db.session() as session:
            records, total = DeviceRepository(session).list_page(
                risk_level=risk_level, sort=sort, limit=limit, offset=offset
            )
            items = [device_to_schema(r) for r in records]
        return DevicePage(items=items, total=total, limit=limit, offset=offset)

    def get_device(self, source_ip: str) -> DeviceOut | None:
        with self._db.session() as session:
            record = DeviceRepository(session).get(source_ip)
            return device_to_schema(record) if record else None


class StatsService:
    def __init__(self, database: Database, pipeline_status: Callable[[], PipelineStatus]) -> None:
        self._db = database
        self._pipeline_status = pipeline_status

    def stats(self) -> StatsOut:
        now = datetime.now(UTC)
        with self._db.session() as session:
            events = EventRepository(session)
            by_risk = events.count_by_risk_level()
            by_type = events.count_by_packet_type()
            total = sum(by_risk.values())
            last_minute = events.count(EventFilter(since=now - timedelta(minutes=1)))
            blocklist_hits = events.count_blocklist_hits()
            devices = DeviceRepository(session).count()
        counts = RiskLevelCounts(
            safe=by_risk.get(RiskLevel.SAFE.value, 0),
            suspicious=by_risk.get(RiskLevel.SUSPICIOUS.value, 0),
            dangerous=by_risk.get(RiskLevel.DANGEROUS.value, 0),
        )
        return StatsOut(
            total_events=total,
            devices=devices,
            events_by_risk=counts,
            suspicious_events=counts.suspicious,
            dangerous_events=counts.dangerous,
            events_last_minute=last_minute,
            dns_queries=by_type.get(PacketType.DNS_QUERY.value, 0),
            connection_attempts=by_type.get(PacketType.TCP_SYN.value, 0),
            blocklist_hits=blocklist_hits,
            generated_at=now,
            pipeline=self._pipeline_status(),
        )
