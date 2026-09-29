"""Composition root: builds and wires every component of a Hound server process.

Dependency direction::

    ingestion (sources) ──▶ EventQueue ──▶ ProcessingService ──▶ SqlEventStore ──▶ SQLite
                                                   │
                                                   └──▶ EventBroadcaster ──▶ WebSocket clients
    API routes ──▶ query services ──▶ repositories ──▶ SQLite
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections import defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Literal

from app.core.config import Settings
from app.core.security import load_or_create_ingest_token
from app.database.engine import Database
from app.enrichment.allowlist import Allowlist
from app.enrichment.blocklist import Blocklist
from app.enrichment.dns_cache import ResolutionCache
from app.enrichment.geo import build_geolocator, load_ranges
from app.enrichment.service import EnrichmentService
from app.ingestion.queue import EventQueue
from app.ingestion.sources import EventSource
from app.models.events import NetworkEvent
from app.models.schemas import (
    CaptureMetrics,
    DaemonMetrics,
    DaemonReport,
    IngestMetrics,
    LatencyMetrics,
    LossMetrics,
    MetricsOut,
    PipelineStatus,
    ProcessingMetrics,
    QueueMetrics,
    ReloadOut,
    StorageMetrics,
    WebSocketMetrics,
)
from app.risk.config import RiskConfig, explicit_environment, file_value_count, load_risk_file
from app.risk.engine import RiskEngine
from app.services.broadcaster import EventBroadcaster
from app.services.processing import ProcessingService
from app.services.queries import DeviceQueryService, EventQueryService, StatsService
from app.services.store import SqlEventStore

logger = logging.getLogger(__name__)


class RunMode(StrEnum):
    IDLE = "idle"  # API/UI only; events arrive from a capture daemon via /api/ingest
    DEMO = "demo"  # synthetic traffic generated in-process
    CAPTURE = "capture"  # in-process packet capture (whole process needs privileges)


IngestRejection = Literal["unauthorized", "invalid", "too_large"]


class HoundRuntime:
    """Owns the lifecycle of the pipeline and exposes services to the API."""

    def __init__(
        self,
        settings: Settings,
        mode: RunMode = RunMode.IDLE,
        *,
        interface: str | None = None,
        database: Database | None = None,
    ) -> None:
        self.settings = settings
        self.mode = mode
        self.interface = interface or settings.network_interface
        self.database = database or Database(settings.resolved_database_url)
        self.queue = EventQueue(settings.queue_max_size)
        self.broadcaster = EventBroadcaster(settings.ws_client_queue_size)

        self.blocklist = Blocklist.from_file(settings.resolve_path(settings.blocklist_path))
        geolocator = build_geolocator(settings.geo_mode, settings.resolve_path(settings.geo_ranges_path))
        self.enrichment = EnrichmentService(
            self.blocklist,
            geolocator,
            ResolutionCache(settings.dns_cache_size, timedelta(seconds=settings.dns_cache_ttl_seconds)),
            Allowlist.from_file(settings.resolve_path(settings.allowlist_path)),
        )
        self.risk_engine = RiskEngine(RiskConfig.from_settings(settings))
        self.store = SqlEventStore(
            self.database,
            device_risk_window=timedelta(minutes=settings.device_risk_window_minutes),
            retention_max_events=settings.retention_max_events,
        )
        self.processor = ProcessingService(
            self.queue,
            self.enrichment,
            self.risk_engine,
            self.store,
            publisher=self.broadcaster.publish,
            batch_size=settings.batch_size,
            flush_interval=settings.flush_interval_seconds,
        )
        self.events = EventQueryService(self.database, geo_simulated=settings.geo_mode == "simulated")
        self.devices = DeviceQueryService(self.database)
        self.stats = StatsService(self.database, self.pipeline_status)

        self.ingest_token: str | None = None
        self._ingest_lock = threading.Lock()
        self._ingest_counts: dict[str, int] = dict.fromkeys(
            ("accepted", "unauthorized", "invalid", "too_large", "events_accepted", "events_dropped"), 0
        )
        self._daemon_report: DaemonMetrics | None = None
        self._source: EventSource | None = None
        self._source_error: str | None = None
        self._started_at: datetime | None = None

    # ------------------------------------------------------------------ lifecycle
    def start(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        """Initialise storage and start the pipeline. Source failures are non-fatal."""
        self.database.initialize()
        self.ingest_token = load_or_create_ingest_token(self.settings)
        if loop is not None:
            self.broadcaster.bind_loop(loop)
        self.processor.start()
        self._started_at = datetime.now(UTC)
        try:
            self._source = self._build_source()
            if self._source is not None:
                self._source.start()
        except Exception as exc:
            self._source_error = str(exc)
            logger.error("Event source failed to start; API and dashboard keep running", extra={"error": str(exc)})
        logger.info("Hound runtime started", extra={"mode": self.mode.value})

    def stop(self) -> None:
        if self._source is not None:
            try:
                self._source.stop()
            except Exception:
                logger.exception("Error stopping event source")
        self.processor.stop()
        self.broadcaster.unbind()
        self.database.dispose()
        logger.info("Hound runtime stopped")

    def _build_source(self) -> EventSource | None:
        if self.mode is RunMode.DEMO:
            from app.ingestion.demo import DemoEventSource, DemoTrafficGenerator

            networks: dict[str, list] = defaultdict(list)  # type: ignore[type-arg]
            for network, code in load_ranges(self.settings.resolve_path(self.settings.geo_ranges_path)):
                networks[code].append(network)
            generator = DemoTrafficGenerator(
                seed=self.settings.demo_seed,
                blocklisted_domains=self.blocklist.domains,
                country_networks=networks,
            )
            return DemoEventSource(
                self.queue.offer, events_per_second=self.settings.demo_events_per_second, generator=generator
            )
        if self.mode is RunMode.CAPTURE:
            from app.ingestion.capture import PacketCaptureService

            return PacketCaptureService(self.interface, self.settings.bpf_filter, self.queue.offer)
        return None

    # ------------------------------------------------------------------ ingest / status
    def ingest(self, events: Sequence[NetworkEvent], report: DaemonReport | None = None) -> tuple[int, int]:
        """Queue externally supplied events (from a capture daemon). Returns (accepted, dropped)."""
        accepted = sum(1 for event in events if self.queue.offer(event))
        dropped = len(events) - accepted
        with self._ingest_lock:
            self._ingest_counts["accepted"] += 1
            self._ingest_counts["events_accepted"] += accepted
            self._ingest_counts["events_dropped"] += dropped
            if report is not None:
                self._daemon_report = DaemonMetrics(**report.model_dump(), received_at=datetime.now(UTC))
        return accepted, dropped

    def record_ingest_rejection(self, reason: IngestRejection) -> None:
        with self._ingest_lock:
            self._ingest_counts[reason] += 1

    def pipeline_status(self) -> PipelineStatus:
        q = self.queue.stats()
        p = self.processor.stats()
        source_status = self._source.status() if self._source is not None else None
        if source_status is not None:
            state, name, error = source_status.state, source_status.name, source_status.error
            interface = source_status.interface
        elif self._source_error:
            state, name, error, interface = "error", self.mode.value, self._source_error, self.interface
        else:
            state, name, error, interface = "idle", None, None, None
        if error is None and p.last_error:
            error = p.last_error
        return PipelineStatus(
            mode=self.mode.value,  # type: ignore[arg-type]
            source=name,
            source_state=state,
            source_error=error,
            interface=interface,
            packets_parsed=source_status.packets_parsed if source_status else 0,
            packets_malformed=source_status.packets_malformed if source_status else 0,
            queue_size=q.size,
            queue_capacity=q.capacity,
            events_received=q.received,
            events_dropped=q.dropped,
            events_processed=p.processed,
            events_failed=p.failed,
            last_event_at=p.last_event_at,
            websocket_subscribers=self.broadcaster.subscriber_count,
            remote_ingest_enabled=self.ingest_token is not None,
            started_at=self._started_at,
        )

    def reload_detection_config(self) -> ReloadOut:
        """Re-read the blocklist, allowlist and risk settings and apply them (16c, ADR-023).

        Everything is loaded and validated first; an invalid risk file raises
        :class:`RiskConfigError` and nothing changes. The swap happens between two batches,
        and the DNS answer cache and per-device behaviour windows are kept (the windows
        restart only when their length changes). Environment/.env values are not re-read.
        """
        settings = self.settings
        file_values = load_risk_file(settings.resolve_path(settings.risk_config_path))
        config = RiskConfig.from_settings(settings)
        blocklist = Blocklist.from_file(settings.resolve_path(settings.blocklist_path))
        allowlist = Allowlist.from_file(settings.resolve_path(settings.allowlist_path))
        windows_reset = False

        def apply() -> None:
            nonlocal windows_reset
            self.enrichment.update_lists(blocklist, allowlist)
            windows_reset = self.risk_engine.reconfigure(config)

        self.processor.reconfigure(apply)
        self.blocklist = blocklist
        result = ReloadOut(
            reloaded_at=datetime.now(UTC),
            blocklist_entries=len(blocklist),
            allowlist_domains=allowlist.domain_count,
            allowlist_devices=allowlist.device_count,
            risk_values_from_file=file_value_count(file_values),
            risk_overridden_by_environment=sorted(explicit_environment(settings)),
            behaviour_windows_reset=windows_reset,
        )
        logger.info("Detection settings reloaded", extra=result.model_dump(mode="json"))
        return result

    def metrics(self) -> MetricsOut:
        """Every loss point and the few performance numbers that drive decisions (ROADMAP §15)."""
        status = self.pipeline_status()
        q = self.queue.stats()
        p = self.processor.stats()
        latency = self.processor.latency()
        with self._ingest_lock:
            counts = dict(self._ingest_counts)
            daemon = self._daemon_report
        database_bytes, wal_bytes = self.database.file_sizes()
        now = datetime.now(UTC)
        daemon_queue = daemon.queue_dropped if daemon else None
        daemon_delivery = daemon.events_forward_dropped if daemon else None
        return MetricsOut(
            generated_at=now,
            uptime_seconds=round((now - self._started_at).total_seconds(), 1) if self._started_at else None,
            loss=LossMetrics(
                total_events_lost=(daemon_queue or 0) + (daemon_delivery or 0) + q.dropped + p.failed,
                daemon_queue_full=daemon_queue,
                daemon_delivery_failed=daemon_delivery,
                server_queue_full=q.dropped,
                processing_failed=p.failed,
                daemon_reported=daemon is not None,
            ),
            capture=CaptureMetrics(
                source=status.source, packets_parsed=status.packets_parsed, packets_malformed=status.packets_malformed
            ),
            daemon=daemon,
            ingest=IngestMetrics(
                requests_accepted=counts["accepted"],
                requests_unauthorized=counts["unauthorized"],
                requests_invalid=counts["invalid"],
                requests_too_large=counts["too_large"],
                events_accepted=counts["events_accepted"],
                events_dropped=counts["events_dropped"],
            ),
            queue=QueueMetrics(
                size=q.size, capacity=q.capacity, high_water=q.high_water, received=q.received, dropped=q.dropped
            ),
            processing=ProcessingMetrics(
                batches=p.batches,
                processed=p.processed,
                failed=p.failed,
                responses_observed=p.responses_observed,
                batch_latency=LatencyMetrics(
                    samples=latency.samples, p50_ms=latency.p50_ms, p95_ms=latency.p95_ms, max_ms=latency.max_ms
                ),
            ),
            websocket=WebSocketMetrics(
                subscribers=self.broadcaster.subscriber_count, messages_dropped=self.broadcaster.dropped
            ),
            storage=StorageMetrics(
                database_bytes=database_bytes,
                wal_bytes=wal_bytes,
                retention_limit=self.settings.retention_max_events,
                retention_pruned_events=self.store.pruned_total,
            ),
        )
