"""Normalised network-event model shared by every layer.

The ingestion layer converts raw packets into :class:`NetworkEvent` objects;
raw Scapy packets never leave :mod:`app.ingestion`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.netutils import normalize_domain, normalize_ip


class PacketType(StrEnum):
    """What kind of observation an event represents."""

    DNS_QUERY = "dns_query"
    DNS_RESPONSE = "dns_response"
    TCP_SYN = "tcp_syn"


class TransportProtocol(StrEnum):
    UDP = "UDP"
    TCP = "TCP"


class DomainSource(StrEnum):
    """Where an event's domain came from."""

    DNS_QUERY = "dns_query"  # the domain was in the packet itself
    DNS_CACHE = "dns_cache"  # inferred from a previously observed DNS answer


class NetworkEvent(BaseModel):
    """A validated, normalised observation emitted by an event source.

    ``id`` is assigned by the database when the event is persisted and is
    therefore not part of this model (see :class:`app.models.schemas.EventOut`).
    ``dns_rcode`` and ``dns_answers`` are only meaningful for DNS responses,
    which feed enrichment/risk state but are not persisted as events.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    timestamp: datetime
    source_ip: str
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_ip: str
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: TransportProtocol
    packet_type: PacketType
    domain: str | None = Field(default=None, max_length=253)
    interface: str | None = Field(default=None, max_length=64)
    dns_query_type: str | None = Field(default=None, max_length=16, pattern=r"^[A-Z0-9]+$")
    dns_rcode: int | None = Field(default=None, ge=0, le=4095)
    dns_answers: tuple[str, ...] = Field(default=(), max_length=32)

    @field_validator("timestamp")
    @classmethod
    def _utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def _valid_ip(cls, value: str) -> str:
        return normalize_ip(value)

    @field_validator("domain")
    @classmethod
    def _valid_domain(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = normalize_domain(value)
        if normalized is None:
            raise ValueError("invalid domain name")
        return normalized

    @field_validator("dns_answers")
    @classmethod
    def _valid_answers(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(normalize_ip(ip) for ip in value)

    @property
    def is_response(self) -> bool:
        return self.packet_type is PacketType.DNS_RESPONSE
