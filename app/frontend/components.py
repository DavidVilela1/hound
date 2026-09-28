"""Reusable NiceGUI building blocks for the dashboard."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from nicegui import ui

from app.frontend.formatting import EMPTY, PACKET_LABEL, RISK_COLOR, RISK_LABEL, fmt_datetime, fmt_endpoint

CSS = """
.hound-header { background: linear-gradient(90deg, #0f172a, #1e3a8a); }
.kpi-card { min-width: 140px; flex: 1 1 140px; }
.hound-info { background: #e0ecff; color: #0b3a82; }
body.body--dark .hound-info { background: #16325c; color: #dbe7ff; }
.kpi-value { font-size: 1.75rem; font-weight: 700; line-height: 1.1; font-variant-numeric: tabular-nums; }
.kpi-title { font-size: 0.75rem; text-transform: uppercase; letter-spacing: .04em; opacity: .7; }
.hound-table { width: 100%; }
.hound-table td { font-variant-numeric: tabular-nums; }
.hound-muted { opacity: .7; font-size: .8rem; }
.hound-kv { display: grid; grid-template-columns: max-content 1fr; gap: .25rem 1rem; }
.hound-kv .k { opacity: .65; }
"""

# Risk badge carries text + score, never colour alone.
RISK_SLOT = r"""
<q-td :props="props">
  <q-badge :color="{safe:'positive', suspicious:'warning', dangerous:'negative'}[props.value] || 'grey'"
           :text-color="props.value === 'suspicious' ? 'black' : 'white'"
           :label="(props.value || '').toUpperCase() + ' · ' + props.row.risk_score" />
</q-td>
"""

FEED_COLUMNS: list[dict[str, Any]] = [
    {"name": "time", "label": "Time", "field": "time", "align": "left"},
    {"name": "device", "label": "Device", "field": "device", "align": "left"},
    {"name": "destination", "label": "Destination", "field": "destination", "align": "left"},
    {
        "name": "domain",
        "label": "Domain",
        "field": "domain",
        "align": "left",
        "classes": "ellipsis",
        "style": "max-width: 280px",
    },
    {"name": "protocol", "label": "Protocol", "field": "protocol", "align": "left"},
    {"name": "country", "label": "Country", "field": "country", "align": "left"},
    {"name": "risk_level", "label": "Risk", "field": "risk_level", "align": "left"},
    {
        "name": "reason",
        "label": "Reason",
        "field": "reason",
        "align": "left",
        "classes": "ellipsis",
        "style": "max-width: 360px",
    },
]

DEVICE_COLUMNS: list[dict[str, Any]] = [
    {"name": "ip", "label": "IP", "field": "ip", "align": "left", "sortable": True},
    {"name": "first_seen", "label": "First seen", "field": "first_seen", "align": "left"},
    {"name": "last_seen", "label": "Last seen", "field": "last_seen", "align": "left"},
    {"name": "events", "label": "Events", "field": "events", "align": "right", "sortable": True},
    {"name": "risk_score", "label": "Risk score", "field": "risk_score", "align": "right", "sortable": True},
    {"name": "risk_level", "label": "Risk level", "field": "risk_level", "align": "left"},
]

COUNTRY_COLUMNS: list[dict[str, Any]] = [
    {"name": "country", "label": "Country", "field": "country", "align": "left"},
    {"name": "events", "label": "Events", "field": "events", "align": "right"},
    {"name": "percentage", "label": "Share of events", "field": "percentage", "align": "right"},
]

BAR_COLOR = "#2a78d6"  # single-series magnitude: one hue
AXIS_TEXT = "#8a8986"  # neutral mid-grey, legible on light and dark surfaces


def kpi_card(title: str, icon: str) -> ui.label:
    """A stat tile; returns the value label so callers can update it."""
    with ui.card().classes("kpi-card").props("flat bordered"):
        with ui.row().classes("items-center gap-2 no-wrap"):
            ui.icon(icon).classes("text-xl opacity-70")
            ui.label(title).classes("kpi-title ellipsis")
        value = ui.label("…").classes("kpi-value")
    return value


def risk_table(columns: list[dict[str, Any]], row_key: str, empty_text: str, rows_per_page: int = 25) -> ui.table:
    table = ui.table(columns=columns, rows=[], row_key=row_key, pagination=rows_per_page).classes("hound-table")
    table.props(f'flat bordered dense no-data-label="{empty_text}" wrap-cells=false')
    table.add_slot("body-cell-risk_level", RISK_SLOT)
    return table


def row_from_click(args: Any) -> dict[str, Any] | None:
    """Extract the row dict from a Quasar ``rowClick`` event payload."""
    candidates = args if isinstance(args, list) else [args]
    for item in candidates:
        if isinstance(item, dict) and ("id" in item or "ip" in item):
            return item
    return None


def country_chart_options(rows: list[dict[str, Any]]) -> dict[str, Any]:
    top = rows[:12][::-1]  # largest at the top of a horizontal bar chart
    return {
        "animation": False,
        "grid": {"left": 8, "right": 56, "top": 8, "bottom": 8, "containLabel": True},
        "tooltip": {"trigger": "item", "formatter": "{b}: {c}% of events"},
        "xAxis": {
            "type": "value",
            "axisLabel": {"formatter": "{value}%", "color": AXIS_TEXT},
            "splitLine": {"lineStyle": {"opacity": 0.25}},
        },
        "yAxis": {
            "type": "category",
            "data": [r["country"] for r in top],
            "axisLabel": {"color": AXIS_TEXT},
            "axisTick": {"show": False},
        },
        "series": [
            {
                "type": "bar",
                "name": "Share of events",
                "data": [round(float(r["pct"]), 1) for r in top],
                "barMaxWidth": 18,
                "itemStyle": {"color": BAR_COLOR, "borderRadius": [0, 4, 4, 0]},
                "label": {"show": True, "position": "right", "formatter": "{c}%", "color": AXIS_TEXT},
            }
        ],
    }


def event_details(container: ui.element, event: dict[str, Any]) -> None:
    """Render the full detail view of one event into ``container``."""
    level = event.get("risk_level", "safe")
    with container:
        with ui.row().classes("items-center gap-3"):
            ui.badge(RISK_LABEL.get(level, level), color=RISK_COLOR.get(level, "grey")).classes("text-sm")
            ui.label(f"Score {event.get('risk_score', 0)}/100").classes("font-medium")
            ui.label(f"Event #{event.get('id')}").classes("hound-muted")
        with ui.element("div").classes("hound-kv q-mt-md"):
            fields = [
                ("Time", fmt_datetime(event.get("timestamp"))),
                ("Type", PACKET_LABEL.get(event.get("packet_type", ""), EMPTY)),
                ("Protocol", event.get("protocol") or EMPTY),
                ("Source (device)", fmt_endpoint(event.get("source_ip"), event.get("source_port"))),
                ("Destination", fmt_endpoint(event.get("destination_ip"), event.get("destination_port"))),
                ("Domain", event.get("domain") or EMPTY),
                (
                    "Domain source",
                    {"dns_query": "DNS query", "dns_cache": "Earlier DNS answer"}.get(
                        event.get("domain_source") or "", EMPTY
                    ),
                ),
                ("DNS query type", event.get("dns_query_type") or EMPTY),
                ("Country (simulated)", event.get("country_name") or EMPTY),
                ("Blocklist match", event.get("blocklist_match") or EMPTY),
                ("Interface", event.get("interface") or EMPTY),
            ]
            for key, value in fields:
                ui.label(key).classes("k")
                ui.label(str(value)).classes("break-all")
        ui.label("Risk indicators").classes("text-subtitle2 q-mt-md")
        reasons = event.get("risk_reasons") or []
        if not reasons:
            ui.label("No risk indicators were identified for this event.").classes("hound-muted")
        for reason in reasons:
            with ui.row().classes("items-start no-wrap gap-2"):
                ui.badge(f"+{reason.get('points', 0)}", color="grey-7")
                with ui.column().classes("gap-0"):
                    ui.label(str(reason.get("description", "")))
                    ui.label(str(reason.get("code", ""))).classes("hound-muted")
        if reasons:
            ui.label(
                "Hound identified indicators associated with elevated risk. These are heuristics, "
                "not proof that a device is compromised."
            ).classes("hound-muted q-mt-sm")


async def guarded(action: Callable[[], Awaitable[None]], on_error: Callable[[str], None]) -> bool:
    """Run an async UI action, reporting failures instead of raising."""
    try:
        await action()
    except Exception as exc:  # UI must survive API outages
        on_error(str(exc))
        return False
    return True
