"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import __version__
from app.api.openapi import install_openapi
from app.api.routes import admin, coverage, devices, events, export, health, ingest, metrics, stats, ws
from app.core.config import Settings
from app.database.engine import DatabaseError
from app.services.runtime import HoundRuntime

logger = logging.getLogger(__name__)

API_DESCRIPTION = """
Local API for **Hound**, a home-network monitor.

* Events are DNS queries and TCP connection attempts (SYN) observed on the network.
* Risk levels (`safe`, `suspicious`, `dangerous`) reflect *indicators associated with
  elevated risk*; they are not proof of compromise.
* Country data comes from the free DB-IP Lite database (IP Geolocation by DB-IP, CC BY 4.0);
  demo mode without it uses a **simulated** geolocator.
* Real-time events are available on the `/ws/events` WebSocket.
"""

OPENAPI_TAGS = [
    {"name": "health", "description": "Service health and pipeline status."},
    {"name": "events", "description": "Enriched and scored network events."},
    {"name": "devices", "description": "Per-device aggregates."},
    {"name": "stats", "description": "Overview counters and country distribution."},
    {"name": "export", "description": "Events and devices as CSV or JSON downloads."},
    {"name": "metrics", "description": "Loss and performance counters for each pipeline stage."},
    {"name": "coverage", "description": "What this deployment position can and cannot see."},
    {"name": "ingest", "description": "Authenticated endpoint used by the capture daemon."},
    {"name": "admin", "description": "Authenticated administrative actions (reload settings)."},
]

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


def create_app(settings: Settings, runtime: HoundRuntime | None = None, *, dashboard: bool = False) -> FastAPI:
    """Build the FastAPI app. The runtime is started/stopped by the app lifespan."""
    runtime = runtime or HoundRuntime(settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        try:
            runtime.start(asyncio.get_running_loop())
        except DatabaseError as exc:
            logger.error("Cannot start: %s", exc)
            raise
        try:
            yield
        finally:
            await asyncio.to_thread(runtime.stop)

    app = FastAPI(
        title="Hound API",
        version=__version__,
        description=API_DESCRIPTION,
        openapi_tags=OPENAPI_TAGS,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )
    app.state.settings = settings
    app.state.runtime = runtime

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_host_list)

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response

    @app.exception_handler(SQLAlchemyError)
    async def database_error(_request: Request, exc: SQLAlchemyError) -> JSONResponse:
        logger.error("Database error while serving request", extra={"error": type(exc).__name__})
        return JSONResponse(status_code=503, content={"detail": "Database unavailable"})

    for router in (
        health.router,
        events.router,
        devices.router,
        export.router,
        stats.router,
        metrics.router,
        coverage.router,
        ingest.router,
        admin.router,
        ws.router,
    ):
        app.include_router(router)
    install_openapi(app)

    if dashboard:
        from app.frontend.dashboard import mount_dashboard

        mount_dashboard(app, settings)
    else:

        @app.get("/", include_in_schema=False)
        def root() -> dict[str, str]:
            return {"name": "Hound API", "docs": "/docs", "health": "/health"}

    return app
