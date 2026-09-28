"""API routers. Routes are thin: validate input, call a service, return a schema."""

from app.api.routes import devices, events, health, ingest, stats, ws

__all__ = ["devices", "events", "health", "ingest", "stats", "ws"]
