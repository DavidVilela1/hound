"""Liveness/readiness endpoint."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Response, status

from app import __version__
from app.api.deps import RuntimeDep
from app.models.schemas import HealthOut

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    response_model=HealthOut,
    summary="Service health",
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": HealthOut, "description": "Database unavailable"}},
)
def health(runtime: RuntimeDep, response: Response) -> HealthOut:
    """``ok`` when the database and event source are healthy, ``degraded`` otherwise.

    Returns HTTP 503 only when the database is unreachable.
    """
    db_ok = runtime.database.ping()
    pipeline = runtime.pipeline_status()
    degraded = not db_ok or pipeline.source_state == "error" or not runtime.processor.running
    if not db_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return HealthOut(
        status="degraded" if degraded else "ok",
        version=__version__,
        time=datetime.now(UTC),
        database="ok" if db_ok else "error",
        pipeline=pipeline,
    )
