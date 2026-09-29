"""Administrative actions. Token-protected like ingest: the custom header also means a web
page in the owner's browser cannot trigger them (cross-origin requests with custom headers
need a CORS preflight, which Hound never grants)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status

from app.api.deps import RuntimeDep
from app.core.security import TOKEN_HEADER, tokens_match
from app.models.schemas import ReloadOut
from app.risk.config import RiskConfigError

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.post(
    "/reload",
    response_model=ReloadOut,
    summary="Reload blocklist, allowlist and risk settings",
    description=(
        f"Requires the `{TOKEN_HEADER}` header. Re-reads `config/blocklist.txt`, `config/allowlist.txt` and "
        "`config/risk.toml` (or the configured paths) and applies them between two processing batches. "
        "All or nothing: if the risk settings are invalid, nothing changes and 400 explains why. "
        "Environment and `.env` values are not re-read (restart for those). Easiest: `python run.py reload`."
    ),
    openapi_extra={
        "parameters": [{"name": TOKEN_HEADER, "in": "header", "required": True, "schema": {"type": "string"}}]
    },
    responses={
        400: {"description": "Invalid settings; the previous settings stay in effect"},
        401: {"description": "Missing or invalid token"},
    },
)
def reload_detection_config(request: Request, runtime: RuntimeDep) -> ReloadOut:
    if not tokens_match(request.headers.get(TOKEN_HEADER), runtime.ingest_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing token")
    try:
        return runtime.reload_detection_config()
    except RiskConfigError as exc:
        raise HTTPException(status_code=400, detail=f"{exc}. The previous settings stay in effect.") from None
