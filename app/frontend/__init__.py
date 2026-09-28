"""NiceGUI dashboard. It talks to the backend only through the HTTP/WebSocket API.

``app.frontend.dashboard`` imports NiceGUI and is loaded lazily by the API
factory, so API-only deployments and tests do not import it.
"""
