"""Repositories: the only place that builds SQL queries.

All queries are constructed with SQLAlchemy expressions and bound
parameters; user input is never interpolated into SQL text.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from sqlalchemy import Select, delete, func, select
from sqlalchemy.orm import Session

from app.database.tables import DeviceRecord, EventRecord
from app.models.events import PacketType
from app.models.processed import ProcessedEvent
from app.models.risk import RiskLevel

LOCAL_COUNTRY = "LAN"
UNKNOWN_COUNTRY = "UNKNOWN"
MAX_DEVICE_OBSERVATIONS = 10


@dataclass(frozen=True, slots=True)
class EventFilter:
    """Optional filters for event queries; ``None`` means "no constraint"."""

    source_ip: str | None = None
    destination_ip: str | None = None
    domain_contains: str | None = None
    risk_level: RiskLevel | None = None
    min_risk_level: RiskLevel | None = None
    packet_type: PacketType | None = None
    protocol: str | None = None
    country: str | None = None
    since: datetime | None = None
    until: datetime | None = None


DeviceSort = Literal["risk", "last_seen", "events", "first_seen"]


class EventRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    # ------------------------------------------------------------------ writes
    def add_many(self, items: Sequence[ProcessedEvent]) -> list[EventRecord]:
        records = [self._to_record(item) for item in items]
        self._session.add_all(records)
        self._session.flush()  # assigns primary keys
        return records

    @staticmethod
    def _to_record(item: ProcessedEvent) -> EventRecord:
        event, enrichment, risk = item.event, item.enrichment, item.risk
        return EventRecord(
            timestamp=event.timestamp,
            source_ip=event.source_ip,
            source_port=event.source_port,
            destination_ip=event.destination_ip,
            destination_port=event.destination_port,
            protocol=event.protocol.value,
            packet_type=event.packet_type.value,
            domain=enrichment.domain,
            domain_source=enrichment.domain_source.value if enrichment.domain_source else None,
            interface=event.interface,
            dns_query_type=event.dns_query_type,
            country=enrichment.country,
            risk_score=risk.score,
            risk_level=risk.level.value,
            risk_reasons=[reason.as_dict() for reason in risk.reasons],
            blocklist_match=enrichment.blocklist_match,
        )

    def prune(self, max_events: int) -> int:
        """Delete the oldest events so that at most ``max_events`` remain."""
        cutoff = self._session.scalar(
            select(EventRecord.id).order_by(EventRecord.id.desc()).offset(max_events).limit(1)
        )
        if cutoff is None:
            return 0
        result = self._session.execute(delete(EventRecord).where(EventRecord.id <= cutoff))
        return int(result.rowcount or 0)  # type: ignore[attr-defined]

    # ------------------------------------------------------------------ reads
    def get(self, event_id: int) -> EventRecord | None:
        return self._session.get(EventRecord, event_id)

    def list_page(self, flt: EventFilter, *, limit: int, offset: int) -> tuple[list[EventRecord], int]:
        base = self._apply_filter(select(EventRecord), flt)
        total = self._session.scalar(select(func.count()).select_from(base.subquery())) or 0
        rows = self._session.scalars(
            base.order_by(EventRecord.timestamp.desc(), EventRecord.id.desc()).limit(limit).offset(offset)
        ).all()
        return list(rows), int(total)

    def count(self, flt: EventFilter | None = None) -> int:
        query = self._apply_filter(select(func.count(EventRecord.id)), flt or EventFilter())
        return int(self._session.scalar(query) or 0)

    def count_by_risk_level(self) -> dict[str, int]:
        rows = self._session.execute(
            select(EventRecord.risk_level, func.count(EventRecord.id)).group_by(EventRecord.risk_level)
        ).all()
        return {level: int(count) for level, count in rows}

    def count_by_packet_type(self) -> dict[str, int]:
        rows = self._session.execute(
            select(EventRecord.packet_type, func.count(EventRecord.id)).group_by(EventRecord.packet_type)
        ).all()
        return {ptype: int(count) for ptype, count in rows}

    def count_blocklist_hits(self) -> int:
        query = select(func.count(EventRecord.id)).where(EventRecord.blocklist_match.is_not(None))
        return int(self._session.scalar(query) or 0)

    def country_distribution(self, *, include_local: bool, since: datetime | None = None) -> list[tuple[str, int]]:
        country = func.coalesce(EventRecord.country, UNKNOWN_COUNTRY)
        query = select(country, func.count(EventRecord.id)).group_by(country)
        if not include_local:
            query = query.where(func.coalesce(EventRecord.country, UNKNOWN_COUNTRY) != LOCAL_COUNTRY)
        if since is not None:
            query = query.where(EventRecord.timestamp >= since)
        rows = self._session.execute(query.order_by(func.count(EventRecord.id).desc())).all()
        return [(str(code), int(count)) for code, count in rows]

    @staticmethod
    def _apply_filter(query: Select, flt: EventFilter) -> Select:  # type: ignore[type-arg]
        if flt.source_ip:
            query = query.where(EventRecord.source_ip == flt.source_ip)
        if flt.destination_ip:
            query = query.where(EventRecord.destination_ip == flt.destination_ip)
        if flt.domain_contains:
            query = query.where(EventRecord.domain.contains(flt.domain_contains, autoescape=True))
        if flt.risk_level:
            query = query.where(EventRecord.risk_level == RiskLevel(flt.risk_level).value)
        if flt.min_risk_level:
            minimum = RiskLevel(flt.min_risk_level)
            allowed = [lvl.value for lvl in RiskLevel if lvl.rank >= minimum.rank]
            query = query.where(EventRecord.risk_level.in_(allowed))
        if flt.packet_type:
            query = query.where(EventRecord.packet_type == PacketType(flt.packet_type).value)
        if flt.protocol:
            query = query.where(EventRecord.protocol == flt.protocol)
        if flt.country:
            query = query.where(EventRecord.country == flt.country)
        if flt.since:
            query = query.where(EventRecord.timestamp >= flt.since)
        if flt.until:
            query = query.where(EventRecord.timestamp <= flt.until)
        return query


class DeviceRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def apply_events(self, items: Sequence[ProcessedEvent], *, risk_window: timedelta) -> None:
        """Update (or create) device aggregates for a batch of processed events.

        A device's ``risk_score`` is the highest event score seen within
        ``risk_window``; once the window expires, the next event resets it.
        """
        grouped: dict[str, list[ProcessedEvent]] = {}
        for item in items:
            grouped.setdefault(item.event.source_ip, []).append(item)
        if not grouped:
            return
        existing = {
            device.source_ip: device
            for device in self._session.scalars(select(DeviceRecord).where(DeviceRecord.source_ip.in_(list(grouped))))
        }
        for ip, device_items in grouped.items():
            device = existing.get(ip) or self._new_device(ip, device_items[0])
            observations = [o for o in (device.observations or []) if isinstance(o, dict)]
            for item in device_items:
                self._apply_one(device, item, risk_window, observations)
            # Assign a new list so SQLAlchemy detects the JSON change.
            device.observations = observations[-MAX_DEVICE_OBSERVATIONS:]

    def _new_device(self, ip: str, first: ProcessedEvent) -> DeviceRecord:
        device = DeviceRecord(
            source_ip=ip,
            first_seen=first.event.timestamp,
            last_seen=first.event.timestamp,
            event_count=0,
            dns_query_count=0,
            connection_attempt_count=0,
            suspicious_event_count=0,
            dangerous_event_count=0,
            risk_score=0,
            risk_level=RiskLevel.SAFE.value,
            risk_updated_at=None,
            observations=[],
        )
        self._session.add(device)
        return device

    @staticmethod
    def _apply_one(
        device: DeviceRecord,
        item: ProcessedEvent,
        risk_window: timedelta,
        observations: list[dict[str, str]],
    ) -> None:
        ts = item.event.timestamp
        device.first_seen = min(device.first_seen, ts)
        device.last_seen = max(device.last_seen, ts)
        device.event_count += 1
        if item.event.packet_type is PacketType.DNS_QUERY:
            device.dns_query_count += 1
        elif item.event.packet_type is PacketType.TCP_SYN:
            device.connection_attempt_count += 1
        if item.risk.level is RiskLevel.SUSPICIOUS:
            device.suspicious_event_count += 1
        elif item.risk.level is RiskLevel.DANGEROUS:
            device.dangerous_event_count += 1

        expired = device.risk_updated_at is None or ts - device.risk_updated_at > risk_window
        if expired or item.risk.score >= device.risk_score:
            device.risk_score = item.risk.score
            device.risk_level = item.risk.level.value
            device.risk_updated_at = ts

        # One observation per signal code, keeping the most recent description.
        for reason in item.risk.reasons:
            observations[:] = [o for o in observations if o.get("code") != reason.code]
            observations.append({"code": reason.code, "description": reason.description, "last_seen": ts.isoformat()})

    def get(self, source_ip: str) -> DeviceRecord | None:
        return self._session.scalar(select(DeviceRecord).where(DeviceRecord.source_ip == source_ip))

    def list_page(
        self,
        *,
        risk_level: RiskLevel | None,
        sort: DeviceSort,
        limit: int,
        offset: int,
    ) -> tuple[list[DeviceRecord], int]:
        query = select(DeviceRecord)
        if risk_level is not None:
            query = query.where(DeviceRecord.risk_level == RiskLevel(risk_level).value)
        total = self._session.scalar(select(func.count()).select_from(query.subquery())) or 0
        order = {
            "risk": (DeviceRecord.risk_score.desc(), DeviceRecord.last_seen.desc()),
            "last_seen": (DeviceRecord.last_seen.desc(),),
            "events": (DeviceRecord.event_count.desc(),),
            "first_seen": (DeviceRecord.first_seen.asc(),),
        }[sort]
        rows = self._session.scalars(query.order_by(*order, DeviceRecord.id).limit(limit).offset(offset)).all()
        return list(rows), int(total)

    def count(self) -> int:
        return int(self._session.scalar(select(func.count(DeviceRecord.id))) or 0)
