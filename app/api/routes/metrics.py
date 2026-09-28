"""Pipeline metrics: where events are lost, and how busy the pipeline is."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.deps import RuntimeDep
from app.models.schemas import MetricsOut

router = APIRouter(prefix="/api", tags=["metrics"])


@router.get(
    "/metrics",
    response_model=MetricsOut,
    summary="Loss and performance counters",
    description=(
        "Cumulative counters since the server started. `loss` sums the events lost at each stage; "
        "the capture daemon's own counters appear once it has delivered a batch (split mode). "
        "Contains no domains or addresses."
    ),
)
def get_metrics(runtime: RuntimeDep) -> MetricsOut:
    return runtime.metrics()
