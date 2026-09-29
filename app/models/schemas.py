"""Public data contracts (Pydantic) shared by the services, the API and its clients."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

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


Counter = Annotated[int, Field(ge=0, le=10**15)]


class DaemonReport(BaseModel):
    """Cumulative counters of a capture daemon since it started, sent with each batch.

    Values are as of the moment that batch was sent, so ``events_forwarded`` does not yet
    include the batch carrying the report.
    """

    model_config = ConfigDict(extra="forbid")

    interface: str | None = Field(default=None, max_length=256)
    packets_parsed: Counter = 0
    packets_malformed: Counter = 0
    queue_dropped: Counter = Field(default=0, description="Events lost because the daemon's queue was full.")
    queue_high_water: Counter = 0
    queue_capacity: Counter = 0
    events_forwarded: Counter = 0
    events_forward_dropped: Counter = Field(
        default=0, description="Events in batches the daemon gave up delivering (API down, rejected)."
    )
    forward_failures: Counter = Field(default=0, description="Failed delivery attempts, including retries.")


class IngestRequest(BaseModel):
    """Batch of normalised events forwarded by a capture daemon."""

    model_config = ConfigDict(extra="forbid")

    events: list[NetworkEvent] = Field(..., min_length=1, max_length=MAX_INGEST_BATCH)
    daemon: DaemonReport | None = Field(default=None, description="The sending daemon's own counters (optional).")


class IngestResponse(BaseModel):
    accepted: int
    dropped: int


class ReloadOut(BaseModel):
    """What ``POST /api/admin/reload`` loaded and applied."""

    reloaded_at: datetime
    blocklist_entries: int
    allowlist_domains: int
    allowlist_devices: int
    risk_values_from_file: int = Field(description="Settings in the risk file that differ from the defaults.")
    risk_overridden_by_environment: list[str] = Field(description="Risk settings pinned by HOUND_RISK_* values.")
    behaviour_windows_reset: bool = Field(
        description="True when the behaviour window length changed, so per-device windows restarted."
    )


# ---------------------------------------------------------------------------- metrics
class LossMetrics(BaseModel):
    """Events lost per stage. ``None`` = that stage is not visible (no daemon report yet)."""

    total_events_lost: int = Field(description="Sum of the visible stages below.")
    daemon_queue_full: int | None
    daemon_delivery_failed: int | None
    server_queue_full: int
    processing_failed: int = Field(description="Enrichment/scoring errors and failed database writes.")
    daemon_reported: bool = Field(description="False until a capture daemon has sent counters.")


class CaptureMetrics(BaseModel):
    """The in-process event source (demo or all-in-one capture), if any."""

    source: str | None
    packets_parsed: int
    packets_malformed: int


class DaemonMetrics(DaemonReport):
    received_at: datetime = Field(description="When the latest report arrived (with an event batch).")


class IngestMetrics(BaseModel):
    requests_accepted: int
    requests_unauthorized: int
    requests_invalid: int
    requests_too_large: int
    events_accepted: int
    events_dropped: int = Field(description="Events refused because the server queue was full.")


class QueueMetrics(BaseModel):
    size: int
    capacity: int
    high_water: int
    received: int
    dropped: int


class LatencyMetrics(BaseModel):
    samples: int
    p50_ms: float | None
    p95_ms: float | None
    max_ms: float | None


class ProcessingMetrics(BaseModel):
    batches: int
    processed: int
    failed: int
    responses_observed: int = Field(description="DNS responses used for correlation (not stored).")
    batch_latency: LatencyMetrics = Field(description="Most recent batches (up to 1000).")


class WebSocketMetrics(BaseModel):
    subscribers: int
    messages_dropped: int = Field(description="Dropped for slow viewers only; stored events are unaffected.")


class StorageMetrics(BaseModel):
    database_bytes: int | None
    wal_bytes: int | None
    retention_limit: int
    retention_days: int | None = Field(default=None, description="Age limit for events, if set.")
    retention_pruned_events: int = Field(description="Events deleted by the count or age limit (by design, not loss).")
    retention_pruned_devices: int = Field(
        default=0, description="Devices deleted because retention removed their last stored event."
    )


class MetricsOut(BaseModel):
    """Pipeline counters for answering "did we lose anything, and where?"."""

    generated_at: datetime
    uptime_seconds: float | None
    loss: LossMetrics
    capture: CaptureMetrics
    daemon: DaemonMetrics | None
    ingest: IngestMetrics
    queue: QueueMetrics
    processing: ProcessingMetrics
    websocket: WebSocketMetrics
    storage: StorageMetrics


# ------------------------------------------------------------------------------ coverage (ADR-026)
CoverageEvidence = Literal["demo", "not_enough_traffic", "no_local_ipv4", "one_device", "several_devices"]


class CoverageObserved(BaseModel):
    """What the stored traffic of the last ``window_hours`` shows: addresses that *started*
    something (a DNS lookup or a connection attempt). DNS answers are not stored."""

    window_hours: int
    lookups_and_connections: int = Field(..., description="DNS lookups + TCP connection attempts in the window.")
    observed_minutes: int = Field(..., description="Minutes between the first and last of them.")
    ipv4_devices: int = Field(..., description="Local IPv4 addresses that looked up names or started connections.")
    ipv6_addresses: int = Field(..., description="IPv6 addresses doing so (one device often uses several).")
    public_ipv4_sources: int = Field(..., description="Public IPv4 addresses doing so (seen e.g. on a WAN side).")
    busiest_ipv4_devices: list[str] = Field(..., description="Up to five local IPv4 addresses, busiest first.")


class CoverageOut(BaseModel):
    """What the configured deployment position can and cannot see, checked against the traffic."""

    position: Literal["auto", "this_computer", "gateway", "mirror", "dns_server"]
    position_set: bool = Field(..., description="False when HOUND_DEPLOYMENT_POSITION is not set (auto).")
    label: str
    summary: str
    sees: list[str]
    misses: list[str] = Field(..., description="Blind spots of this position, then those of every position.")
    observed: CoverageObserved
    evidence: CoverageEvidence
    assessment: str
    assessment_level: Literal["info", "ok", "warning"]
    generated_at: datetime
