"""Event endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from app.api.deps import RuntimeDep, SettingsDep, check_page_size, validated_ip
from app.core.config import HARD_MAX_PAGE_SIZE
from app.database.repositories import EventFilter
from app.models.events import PacketType, TransportProtocol
from app.models.risk import RiskLevel
from app.models.schemas import EventOut, EventPage

router = APIRouter(prefix="/api/events", tags=["events"])


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def event_filter(
    source_ip: Annotated[str | None, Query(max_length=64, description="Exact device IP")] = None,
    destination_ip: Annotated[str | None, Query(max_length=64)] = None,
    domain: Annotated[str | None, Query(min_length=1, max_length=253, description="Case-insensitive substring")] = None,
    risk_level: Annotated[RiskLevel | None, Query(description="Exact risk level")] = None,
    min_risk_level: Annotated[RiskLevel | None, Query(description="This level or higher")] = None,
    packet_type: PacketType | None = None,
    protocol: TransportProtocol | None = None,
    country: Annotated[str | None, Query(pattern=r"^[A-Za-z]{2,8}$")] = None,
    since: Annotated[datetime | None, Query(description="ISO-8601; naive values are UTC")] = None,
    until: Annotated[datetime | None, Query(description="ISO-8601; naive values are UTC")] = None,
) -> EventFilter:
    """Event filters shared by the list and export endpoints (validated the same way)."""
    since_utc, until_utc = _utc(since), _utc(until)
    if since_utc and until_utc and since_utc > until_utc:
        raise HTTPException(status_code=422, detail="since must be earlier than until")
    return EventFilter(
        source_ip=validated_ip(source_ip, "source_ip"),
        destination_ip=validated_ip(destination_ip, "destination_ip"),
        domain_contains=domain.strip().lower() if domain else None,
        risk_level=risk_level,
        min_risk_level=min_risk_level,
        packet_type=packet_type,
        protocol=protocol.value if protocol else None,
        country=country.upper() if country else None,
        since=since_utc,
        until=until_utc,
    )


EventFilterDep = Annotated[EventFilter, Depends(event_filter)]


@router.get("", response_model=EventPage, summary="List events, newest first")
def list_events(
    runtime: RuntimeDep,
    settings: SettingsDep,
    flt: EventFilterDep,
    limit: Annotated[int, Query(ge=1, le=HARD_MAX_PAGE_SIZE, description="Page size")] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000_000)] = 0,
) -> EventPage:
    check_page_size(limit, settings)
    return runtime.events.list_events(flt, limit=limit, offset=offset)


@router.get(
    "/{event_id}",
    response_model=EventOut,
    summary="Get one event",
    responses={status.HTTP_404_NOT_FOUND: {"description": "Event not found"}},
)
def get_event(runtime: RuntimeDep, event_id: Annotated[int, Path(ge=1, le=2**63 - 1)]) -> EventOut:
    event = runtime.events.get_event(event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return event
