"""Convert ORM records into public schemas (keeps the API free of ORM details)."""

from __future__ import annotations

import logging
from typing import Any

from pydantic import ValidationError

from app.database.tables import DeviceRecord, EventRecord
from app.enrichment.geo import country_name
from app.models.schemas import DeviceObservation, DeviceOut, EventOut, RiskReasonOut

logger = logging.getLogger(__name__)


def _reasons(raw: Any) -> list[RiskReasonOut]:
    """Validate stored JSON reasons; corrupted entries are skipped, never executed."""
    if not isinstance(raw, list):
        return []
    reasons: list[RiskReasonOut] = []
    for item in raw:
        try:
            reasons.append(RiskReasonOut.model_validate(item))
        except ValidationError:
            logger.warning("Skipping malformed stored risk reason")
    return reasons


def event_to_schema(record: EventRecord) -> EventOut:
    return EventOut(
        id=record.id,
        timestamp=record.timestamp,
        source_ip=record.source_ip,
        source_port=record.source_port,
        destination_ip=record.destination_ip,
        destination_port=record.destination_port,
        protocol=record.protocol,  # type: ignore[arg-type]
        packet_type=record.packet_type,  # type: ignore[arg-type]
        domain=record.domain,
        domain_source=record.domain_source,  # type: ignore[arg-type]
        interface=record.interface,
        dns_query_type=record.dns_query_type,
        country=record.country,
        country_name=country_name(record.country) if record.country else None,
        risk_score=record.risk_score,
        risk_level=record.risk_level,  # type: ignore[arg-type]
        risk_reasons=_reasons(record.risk_reasons),
        blocklist_match=record.blocklist_match,
    )


def _observations(raw: Any) -> list[DeviceObservation]:
    if not isinstance(raw, list):
        return []
    result: list[DeviceObservation] = []
    for item in raw:
        try:
            result.append(DeviceObservation.model_validate(item))
        except ValidationError:
            logger.warning("Skipping malformed stored device observation")
    return result


def device_to_schema(record: DeviceRecord) -> DeviceOut:
    return DeviceOut(
        source_ip=record.source_ip,
        first_seen=record.first_seen,
        last_seen=record.last_seen,
        event_count=record.event_count,
        dns_query_count=record.dns_query_count,
        connection_attempt_count=record.connection_attempt_count,
        suspicious_event_count=record.suspicious_event_count,
        dangerous_event_count=record.dangerous_event_count,
        risk_score=record.risk_score,
        risk_level=record.risk_level,  # type: ignore[arg-type]
        risk_updated_at=record.risk_updated_at,
        observations=_observations(record.observations),
    )
