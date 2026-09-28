"""FastAPI dependencies: resolve services from application state (no globals)."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request

from app.core.config import Settings
from app.core.netutils import normalize_ip
from app.services.runtime import HoundRuntime


def get_runtime(request: Request) -> HoundRuntime:
    return request.app.state.runtime  # type: ignore[no-any-return]


def get_settings(request: Request) -> Settings:
    return request.app.state.settings  # type: ignore[no-any-return]


RuntimeDep = Annotated[HoundRuntime, Depends(get_runtime)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


def validated_ip(value: str | None, field: str) -> str | None:
    """Normalise an optional IP query/path parameter or raise HTTP 422."""
    if value is None:
        return None
    try:
        return normalize_ip(value)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"{field} is not a valid IP address") from None


def check_page_size(limit: int, settings: Settings) -> int:
    if limit > settings.max_page_size:
        raise HTTPException(
            status_code=422,
            detail=f"limit must be <= {settings.max_page_size}",
        )
    return limit
