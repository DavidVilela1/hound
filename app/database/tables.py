"""SQLAlchemy ORM schema. Tables are created automatically on startup."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Index, Integer, String, TypeDecorator
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class UTCDateTime(TypeDecorator[datetime]):
    """Store datetimes as naive UTC and always return timezone-aware UTC values.

    SQLite has no native timezone support, so normalising at the boundary keeps
    comparisons and ordering correct.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: Any, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC)


class Base(DeclarativeBase):
    pass


class EventRecord(Base):
    """One persisted DNS query or TCP connection attempt."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False)
    packet_type: Mapped[str] = mapped_column(String(16), nullable=False)
    domain: Mapped[str | None] = mapped_column(String(253))
    domain_source: Mapped[str | None] = mapped_column(String(16))
    interface: Mapped[str | None] = mapped_column(String(64))
    dns_query_type: Mapped[str | None] = mapped_column(String(16))
    country: Mapped[str | None] = mapped_column(String(16))
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_reasons: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    blocklist_match: Mapped[str | None] = mapped_column(String(253))

    __table_args__ = (
        Index("ix_events_timestamp", "timestamp"),
        Index("ix_events_source_ip_timestamp", "source_ip", "timestamp"),
        Index("ix_events_risk_level_timestamp", "risk_level", "timestamp"),
        Index("ix_events_destination_ip", "destination_ip"),
        Index("ix_events_domain", "domain"),
        Index("ix_events_country", "country"),
        Index("ix_events_packet_type", "packet_type"),
    )


class DeviceRecord(Base):
    """Aggregated state for one source IP."""

    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, unique=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    dns_query_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    connection_attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    suspicious_event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    dangerous_event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="safe")
    risk_updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    observations: Mapped[list[dict[str, str]]] = mapped_column(JSON, nullable=False, default=list)

    __table_args__ = (
        Index("ix_devices_risk_score", "risk_score"),
        Index("ix_devices_last_seen", "last_seen"),
    )
