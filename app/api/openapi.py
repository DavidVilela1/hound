"""OpenAPI customisation.

The ingest route parses its body manually (to authenticate before reading
it), so its request model is registered in the schema components here.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from app.models.schemas import IngestRequest


def install_openapi(app: FastAPI) -> None:
    def custom_openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
            tags=app.openapi_tags,
        )
        body_schema = IngestRequest.model_json_schema(ref_template="#/components/schemas/{model}")
        definitions = body_schema.pop("$defs", {})
        components = schema.setdefault("components", {}).setdefault("schemas", {})
        for name, definition in definitions.items():
            components.setdefault(name, definition)
        components["IngestRequest"] = body_schema
        app.openapi_schema = schema
        return schema

    app.openapi = custom_openapi  # type: ignore[method-assign]
