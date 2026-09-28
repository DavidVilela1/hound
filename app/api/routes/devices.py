"""Device endpoints."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, status

from app.api.deps import RuntimeDep, SettingsDep, check_page_size, validated_ip
from app.core.config import HARD_MAX_PAGE_SIZE
from app.models.risk import RiskLevel
from app.models.schemas import DeviceOut, DevicePage

router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("", response_model=DevicePage, summary="List observed devices")
def list_devices(
    runtime: RuntimeDep,
    settings: SettingsDep,
    limit: Annotated[int, Query(ge=1, le=HARD_MAX_PAGE_SIZE)] = 100,
    offset: Annotated[int, Query(ge=0, le=100_000_000)] = 0,
    risk_level: RiskLevel | None = None,
    sort: Annotated[
        Literal["risk", "last_seen", "events", "first_seen"],
        Query(description="Sort order (risk = highest score first)"),
    ] = "risk",
) -> DevicePage:
    check_page_size(limit, settings)
    return runtime.devices.list_devices(risk_level=risk_level, sort=sort, limit=limit, offset=offset)


@router.get(
    "/{source_ip}",
    response_model=DeviceOut,
    summary="Get one device",
    responses={status.HTTP_404_NOT_FOUND: {"description": "Device not found"}},
)
def get_device(runtime: RuntimeDep, source_ip: str) -> DeviceOut:
    ip = validated_ip(source_ip, "source_ip")
    assert ip is not None
    device = runtime.devices.get_device(ip)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return device
