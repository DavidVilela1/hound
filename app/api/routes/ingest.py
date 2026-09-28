"""Authenticated ingest endpoint used by the privileged capture daemon.

The token is checked **before** the body is read, and the body size is
capped, so unauthenticated clients cannot make the server buffer large
payloads.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import ValidationError

from app.api.deps import RuntimeDep
from app.core.security import TOKEN_HEADER, tokens_match
from app.models.schemas import IngestRequest, IngestResponse

router = APIRouter(prefix="/api", tags=["ingest"])

MAX_BODY_BYTES = 2 * 1024 * 1024


async def _read_limited_body(request: Request) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > MAX_BODY_BYTES):
        raise HTTPException(status_code=413, detail="Request body too large")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="Request body too large")
    return bytes(body)


@router.post(
    "/ingest",
    response_model=IngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit events from a capture daemon",
    description=f"Requires the `{TOKEN_HEADER}` header. Accepts up to 1000 normalised events per request.",
    openapi_extra={
        "requestBody": {
            "required": True,
            # The schema itself is registered in components by app.api.openapi.
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/IngestRequest"}}},
        },
        "parameters": [{"name": TOKEN_HEADER, "in": "header", "required": True, "schema": {"type": "string"}}],
    },
    responses={401: {"description": "Missing or invalid token"}, 413: {"description": "Body too large"}},
)
async def ingest_events(request: Request, runtime: RuntimeDep) -> IngestResponse:
    if not tokens_match(request.headers.get(TOKEN_HEADER), runtime.ingest_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing ingest token")
    body = await _read_limited_body(request)
    try:
        payload = IngestRequest.model_validate_json(body)
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=exc.errors(include_url=False, include_context=False, include_input=False),
        ) from None
    accepted, dropped = runtime.ingest(payload.events)
    return IngestResponse(accepted=accepted, dropped=dropped)
