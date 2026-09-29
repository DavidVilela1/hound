"""Export endpoints: every matching event or device as a CSV or JSON download (17b, ADR-027)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

from app.api.deps import RuntimeDep
from app.api.routes.events import EventFilterDep
from app.models.risk import RiskLevel
from app.services.export import (
    DEVICE_COLUMNS,
    EVENT_COLUMNS,
    MEDIA_TYPES,
    ExportFormat,
    csv_stream,
    device_row,
    event_row,
    filename,
    json_stream,
)

router = APIRouter(prefix="/api/export", tags=["export"])

FormatQuery = Annotated[ExportFormat, Query(description="`csv` (opens in a spreadsheet) or `json` (a JSON array)")]
DOWNLOAD: dict[int | str, dict[str, Any]] = {
    200: {"description": "The file, streamed.", "content": {"text/csv": {}, "application/json": {}}}
}


def _download(body: Iterator[str], kind: str, fmt: ExportFormat) -> StreamingResponse:
    return StreamingResponse(
        body,
        media_type=MEDIA_TYPES[fmt],
        headers={
            "Content-Disposition": f'attachment; filename="{filename(kind, fmt, datetime.now(UTC))}"',
            "Cache-Control": "no-store",
        },
    )


@router.get(
    "/events",
    summary="Download events (CSV or JSON)",
    response_class=StreamingResponse,
    responses=DOWNLOAD,
    description=(
        "All events matching the same filters as `GET /api/events`, oldest first, without paging. "
        "Streamed in bounded memory; events stored after the download starts are not included. "
        "CSV: UTF-8 with a byte-order mark; cells that a spreadsheet would run as a formula start with `'`."
    ),
)
def export_events(runtime: RuntimeDep, flt: EventFilterDep, format: FormatQuery = "csv") -> StreamingResponse:
    items = runtime.export.events(flt)  # reads the snapshot bound now: a DB outage is a 503, not a broken file
    body = csv_stream(EVENT_COLUMNS, map(event_row, items)) if format == "csv" else json_stream(items)
    return _download(body, "events", format)


@router.get(
    "/devices",
    summary="Download devices (CSV or JSON)",
    response_class=StreamingResponse,
    responses=DOWNLOAD,
    description="Every device (optionally one risk level), in the order Hound first saw them.",
)
def export_devices(
    runtime: RuntimeDep, format: FormatQuery = "csv", risk_level: RiskLevel | None = None
) -> StreamingResponse:
    items = runtime.export.devices(risk_level)
    body = csv_stream(DEVICE_COLUMNS, map(device_row, items)) if format == "csv" else json_stream(items)
    return _download(body, "devices", format)
