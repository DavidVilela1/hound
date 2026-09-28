"""Pure presentation helpers (no NiceGUI imports, unit-testable)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

RISK_RANK = {"safe": 0, "suspicious": 1, "dangerous": 2}
RISK_LABEL = {"safe": "🟢 SAFE", "suspicious": "🟡 SUSPICIOUS", "dangerous": "🔴 DANGEROUS"}
RISK_COLOR = {"safe": "positive", "suspicious": "warning", "dangerous": "negative"}
PACKET_LABEL = {"dns_query": "DNS query", "dns_response": "DNS response", "tcp_syn": "TCP SYN"}
EMPTY = "—"


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def fmt_time(value: str | None) -> str:
    """Local wall-clock time ``HH:MM:SS``."""
    ts = parse_ts(value)
    return ts.astimezone().strftime("%H:%M:%S") if ts else EMPTY


def fmt_datetime(value: str | None) -> str:
    ts = parse_ts(value)
    return ts.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z") if ts else EMPTY


def fmt_endpoint(ip: str | None, port: int | None) -> str:
    if not ip:
        return EMPTY
    host = f"[{ip}]" if ":" in ip else ip
    return f"{host}:{port}" if port is not None else host


def top_reason(event: dict[str, Any]) -> str:
    reasons = event.get("risk_reasons") or []
    if not reasons:
        return EMPTY
    best = max(reasons, key=lambda r: r.get("points", 0))
    return str(best.get("description", EMPTY))


def passes_min_level(level: str | None, minimum: str) -> bool:
    return RISK_RANK.get(level or "safe", 0) >= RISK_RANK.get(minimum, 0)


def event_row(event: dict[str, Any]) -> dict[str, Any]:
    """Flatten an ``EventOut`` JSON object into a table row."""
    domain = event.get("domain") or EMPTY
    if event.get("domain_source") == "dns_cache" and domain != EMPTY:
        domain = f"{domain} (via DNS)"
    return {
        "id": event.get("id"),
        "time": fmt_time(event.get("timestamp")),
        "device": event.get("source_ip") or EMPTY,
        "destination": fmt_endpoint(event.get("destination_ip"), event.get("destination_port")),
        "domain": domain,
        "protocol": f"{event.get('protocol', '?')} · {PACKET_LABEL.get(event.get('packet_type', ''), '?')}",
        "country": event.get("country_name") or EMPTY,
        "risk_level": event.get("risk_level") or "safe",
        "risk_score": event.get("risk_score", 0),
        "reason": top_reason(event),
    }


def device_row(device: dict[str, Any]) -> dict[str, Any]:
    return {
        "ip": device.get("source_ip"),
        "first_seen": fmt_datetime(device.get("first_seen")),
        "last_seen": fmt_datetime(device.get("last_seen")),
        "events": device.get("event_count", 0),
        "risk_score": device.get("risk_score", 0),
        "risk_level": device.get("risk_level") or "safe",
    }


def country_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "country": c.get("country_name") or c.get("country"),
            "code": c.get("country"),
            "events": c.get("events", 0),
            "percentage": f"{c.get('percentage', 0):.1f}%",
            "pct": c.get("percentage", 0),
        }
        for c in payload.get("countries", [])
    ]
