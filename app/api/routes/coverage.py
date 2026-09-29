"""Deployment coverage: what Hound's position can and cannot see (ADR-026)."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.deps import RuntimeDep
from app.models.schemas import CoverageOut

router = APIRouter(prefix="/api", tags=["coverage"])


@router.get(
    "/coverage",
    response_model=CoverageOut,
    summary="What this deployment position can and cannot see",
    description=(
        "Describes the configured position (`HOUND_DEPLOYMENT_POSITION`) and its blind spots, and checks it "
        "against the last 24 h of traffic: how many devices looked up names or started connections. "
        "Recomputed at most every 30 seconds."
    ),
)
def get_coverage(runtime: RuntimeDep) -> CoverageOut:
    return runtime.coverage.coverage()
