"""Internal value objects produced by the processing pipeline."""

from __future__ import annotations

from dataclasses import dataclass

from app.models.events import DomainSource, NetworkEvent
from app.models.risk import RiskAssessment


@dataclass(frozen=True, slots=True)
class Enrichment:
    """Metadata added to an event by :class:`app.enrichment.service.EnrichmentService`."""

    country: str | None
    domain: str | None
    domain_source: DomainSource | None
    blocklist_match: str | None
    destination_is_public: bool


@dataclass(frozen=True, slots=True)
class ProcessedEvent:
    """An event after enrichment and risk scoring, ready to persist."""

    event: NetworkEvent
    enrichment: Enrichment
    risk: RiskAssessment
