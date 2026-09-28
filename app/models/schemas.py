"""Public data contracts (Pydantic) shared by the services, the API and its clients."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.models.events import DomainSource, NetworkEvent, PacketType, TransportProtocol
from app.models.risk import RiskLevel

MAX_INGEST_BATCH = 1000


class RiskReasonOut(BaseModel):
    code: str = Field(..., examples=["BLOCKLISTED_DOMAIN"])
    points: int = Field(..., ge=0, le=100)
    description: str


class EventOut(BaseModel):
    """A persisted, enriched and scored network event."""

    model_config = ConfigDict(json_schema_extra={"description": "Persisted network event"})

    id: int = Field(..., ge=1)
    timestamp: datetime
    source_ip: str = Field(..., description="Device that initiated the query/connection attempt.")
    source_port: int | None
    destination_ip: str
    destination_port: int | None
    protocol: TransportProtocol
    packet_type: PacketType
    domain: str | None = Field(default=None, description="Queried domain, or domain inferred from DNS answers.")
    domain_source: DomainSource | None
    interface: str | None
    dns_query_type: str | None
    country: str | None = Field(default=None, description="Destination country code (simulated by default).")
    country_name: str | None
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    risk_reasons: list[RiskReasonOut]
    blocklist_match: str | None


class EventPage(BaseModel):
    items: list[EventOut]
    total: int = Field(..., ge=0, description="Total number of events matching the filters.")
    limit: int
    offset: int


class DeviceObservation(BaseModel):
    """Most recent occurrence of one risk indicator for a device."""

    code: str
    description: str
    last_seen: datetime


class DeviceOut(BaseModel):
    """Aggregated view of one source IP observed on the network."""

    source_ip: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    dns_query_count: int
    connection_attempt_count: int
    suspicious_event_count: int
    dangerous_event_count: int
    risk_score: int = Field(..., ge=0, le=100, description="Highest event score within the device risk window.")
    risk_level: RiskLevel
    risk_updated_at: datetime | None
    observations: list[DeviceObservation] = Field(
        default_factory=list, description="Recent distinct risk indicators (one per signal code)."
    )


class DevicePage(BaseModel):
    items: list[DeviceOut]
    total: int
    limit: int
    offset: int


class RiskLevelCounts(BaseModel):
    safe: int = 0
    suspicious: int = 0
    dangerous: int = 0


SourceState = Literal["idle", "starting", "running", "stopped", "error"]
RunModeName = Literal["idle", "demo", "capture"]


class PipelineStatus(BaseModel):
    """Live state of the ingestion → processing pipeline."""

    mode: RunModeName
    source: str | None = Field(default=None, description="Active in-process event source, if any.")
    source_state: SourceState
    source_error: str | None = None
    interface: str | None = None
    packets_parsed: int = Field(default=0, description="Packets turned into events by the in-process source.")
    packets_malformed: int = Field(default=0, description="Malformed packets skipped by the in-process source.")
    queue_size: int
    queue_capacity: int
    events_received: int
    events_dropped: int
    events_processed: int
    events_failed: int
    last_event_at: datetime | None
    websocket_subscribers: int
    remote_ingest_enabled: bool
    started_at: datetime | None


class StatsOut(BaseModel):
    total_events: int
    devices: int
    events_by_risk: RiskLevelCounts
    suspicious_events: int
    dangerous_events: int
    events_last_minute: int
    dns_queries: int
    connection_attempts: int
    blocklist_hits: int
    generated_at: datetime
    pipeline: PipelineStatus


class CountryStat(BaseModel):
    country: str = Field(..., description="Country code, 'LAN' for local addresses or 'UNKNOWN'.")
    country_name: str
    events: int
    percentage: float = Field(..., ge=0, le=100)


class CountryStatsOut(BaseModel):
    basis: Literal["events"] = "events"
    description: str
    include_local: bool
    total_events: int
    simulated: bool = Field(..., description="True when the default simulated geolocator is in use.")
    countries: list[CountryStat]


class HealthOut(BaseModel):
    status: Literal["ok", "degraded"]
    version: str
    time: datetime
    database: Literal["ok", "error"]
    pipeline: PipelineStatus


class IngestRequest(BaseModel):
    """Batch of normalised events forwarded by a capture daemon."""

    model_config = ConfigDict(extra="forbid")

    events: list[NetworkEvent] = Field(..., min_length=1, max_length=MAX_INGEST_BATCH)


class IngestResponse(BaseModel):
    accepted: int
    dropped: int
