"""Aggregate statistics endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from app.api.deps import RuntimeDep
from app.models.schemas import CountryStatsOut, StatsOut

router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("", response_model=StatsOut, summary="Overview counters and pipeline status")
def get_stats(runtime: RuntimeDep) -> StatsOut:
    return runtime.stats.stats()


@router.get(
    "/countries",
    response_model=CountryStatsOut,
    summary="Event distribution by destination country",
    description=(
        "Percentages are computed over **events** (stored DNS queries and TCP connection attempts), "
        "grouped by the country of each event's destination IP. The default geolocator is simulated."
    ),
)
def get_country_stats(
    runtime: RuntimeDep,
    include_local: Annotated[bool, Query(description="Include events whose destination is on the LAN")] = False,
    since_minutes: Annotated[int | None, Query(ge=1, le=10_080, description="Only the last N minutes")] = None,
) -> CountryStatsOut:
    return runtime.events.country_stats(include_local=include_local, since_minutes=since_minutes)
