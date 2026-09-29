"""Export stored events and devices as CSV or JSON, streamed in bounded memory (17b, ADR-027).

Rows are read in keyset pages (``id > last``, ``EXPORT_PAGE_SIZE`` at a time), each page in
its own short database session, and written out page by page — so memory stays flat
whatever the table size, no connection is held across the response, and the server keeps
writing while an export runs. The upper id is fixed when the export starts: events stored
meanwhile are not included, so the file is a consistent "as of" view (retention may still
remove the oldest rows before they are reached).

Both formats carry the same fields as the REST API (``EventOut`` / ``DeviceOut``). CSV cells
that a spreadsheet would treat as a formula (starting with ``=``, ``+``, ``-``, ``@``, tab or
carriage return, also after leading spaces) are prefixed with ``'``: captured traffic and
ingest input are untrusted, and a domain or interface name must never run in Excel.
"""

from __future__ import annotations

import csv
import io
import logging
from collections.abc import Callable, Iterable, Iterator
from datetime import datetime
from typing import Any, Literal

from sqlalchemy.exc import SQLAlchemyError

from app.database.engine import Database
from app.database.repositories import DeviceRepository, EventFilter, EventRepository
from app.models.risk import RiskLevel
from app.models.schemas import DeviceOut, EventOut
from app.services.mappers import device_to_schema, event_to_schema

logger = logging.getLogger(__name__)

ExportFormat = Literal["csv", "json"]
EXPORT_PAGE_SIZE = 1000
FORMULA_PREFIXES = frozenset("=+-@\t\r")
BOM = "\ufeff"  # lets Excel on Windows read the UTF-8 text correctly (e.g. localised interface names)
MEDIA_TYPES: dict[ExportFormat, str] = {"csv": "text/csv; charset=utf-8", "json": "application/json"}

EVENT_COLUMNS = [
    "id",
    "timestamp",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "protocol",
    "packet_type",
    "domain",
    "domain_source",
    "dns_query_type",
    "interface",
    "country",
    "country_name",
    "risk_score",
    "risk_level",
    "blocklist_match",
    "risk_reason_codes",
    "risk_reasons",
]
DEVICE_COLUMNS = [
    "source_ip",
    "first_seen",
    "last_seen",
    "event_count",
    "dns_query_count",
    "connection_attempt_count",
    "suspicious_event_count",
    "dangerous_event_count",
    "risk_score",
    "risk_level",
    "risk_updated_at",
    "observation_codes",
    "observations",
]


# ------------------------------------------------------------------------------ formatting
def csv_cell(value: Any) -> Any:
    """Neutralise spreadsheet formulas; ``None`` becomes an empty cell."""
    if value is None:
        return ""
    if isinstance(value, str) and value and (value[0] in FORMULA_PREFIXES or value.lstrip()[:1] in FORMULA_PREFIXES):
        return "'" + value
    return value


def event_row(event: EventOut) -> list[Any]:
    data = event.model_dump(mode="json")
    data["risk_reason_codes"] = ";".join(reason.code for reason in event.risk_reasons)
    data["risk_reasons"] = " | ".join(f"{reason.description} (+{reason.points})" for reason in event.risk_reasons)
    return [data[column] for column in EVENT_COLUMNS]


def device_row(device: DeviceOut) -> list[Any]:
    data = device.model_dump(mode="json")
    observations = data["observations"]
    data["observation_codes"] = ";".join(obs["code"] for obs in observations)
    data["observations"] = " | ".join(f"{obs['description']} (last seen {obs['last_seen']})" for obs in observations)
    return [data[column] for column in DEVICE_COLUMNS]


def csv_stream(columns: list[str], rows: Iterable[list[Any]], *, flush_every: int = EXPORT_PAGE_SIZE) -> Iterator[str]:
    """RFC 4180 CSV (``\\r\\n`` line ends) with a UTF-8 byte-order mark, in chunks."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    buffer.write(BOM)
    writer.writerow(columns)
    pending = 0
    for row in rows:
        writer.writerow([csv_cell(value) for value in row])
        pending += 1
        if pending >= flush_every:
            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate()
            pending = 0
    yield buffer.getvalue()


def json_stream(
    items: Iterable[EventOut] | Iterable[DeviceOut], *, flush_every: int = EXPORT_PAGE_SIZE
) -> Iterator[str]:
    """A JSON array, in chunks (an interrupted download is invalid JSON, not a short list).

    Items are grouped per chunk: one chunk per item made the download ~4x slower.
    """
    parts = ["["]
    separator, pending = "\n", 0
    for item in items:
        parts.append(separator + item.model_dump_json())
        separator, pending = ",\n", pending + 1
        if pending >= flush_every:
            yield "".join(parts)
            parts.clear()
            pending = 0
    parts.append("\n]\n")
    yield "".join(parts)


def filename(kind: str, fmt: ExportFormat, now: datetime) -> str:
    return f"hound-{kind}-{now:%Y%m%d-%H%M%S}.{fmt}"


# ------------------------------------------------------------------------------ reading
class ExportService:
    def __init__(self, database: Database, *, page_size: int = EXPORT_PAGE_SIZE) -> None:
        self._db = database
        self._page_size = page_size

    def events(self, flt: EventFilter) -> Iterator[EventOut]:
        """Fixes the snapshot now (so a database error surfaces before streaming starts)."""
        with self._db.session() as session:
            up_to = EventRepository(session).max_id()

        def page(after: int) -> list[tuple[int, EventOut]]:
            with self._db.session() as session:
                records = EventRepository(session).export_page(
                    flt, after_id=after, up_to_id=up_to, limit=self._page_size
                )
                return [(record.id, event_to_schema(record)) for record in records]

        return self._pages(page, "events")

    def devices(self, risk_level: RiskLevel | None) -> Iterator[DeviceOut]:
        with self._db.session() as session:
            up_to = DeviceRepository(session).max_id()

        def page(after: int) -> list[tuple[int, DeviceOut]]:
            with self._db.session() as session:
                records = DeviceRepository(session).export_page(
                    risk_level=risk_level, after_id=after, up_to_id=up_to, limit=self._page_size
                )
                return [(record.id, device_to_schema(record)) for record in records]

        return self._pages(page, "devices")

    def _pages(self, page: Callable[[int], list[tuple[int, Any]]], kind: str) -> Iterator[Any]:
        after, exported = 0, 0
        try:
            while True:
                rows = page(after)
                for _, item in rows:
                    yield item
                exported += len(rows)
                if len(rows) < self._page_size:
                    break
                after = rows[-1][0]
        except SQLAlchemyError:
            # Headers are already sent: the client sees a truncated download. Say so in the log.
            logger.error("Export interrupted by a database error", extra={"kind": kind, "rows_sent": exported})
            raise
        logger.info("Export finished", extra={"kind": kind, "rows": exported})
