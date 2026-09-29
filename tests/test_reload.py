"""Reloading detection settings in a running server (``POST /api/admin/reload``, ``run.py reload``)."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app import cli
from app.api.app import create_app
from app.core.config import Settings
from app.core.security import TOKEN_HEADER
from app.models.events import PacketType
from app.services.runtime import HoundRuntime
from tests.conftest import EventFactory
from tests.test_daemon import LiveServer, free_port, start_server

DGA_LIKE = "x7k2qp9zv4m1bw.top"


@pytest.fixture
def runtime(settings: Settings) -> HoundRuntime:
    return HoundRuntime(settings)


@pytest.fixture
def client(settings: Settings, runtime: HoundRuntime) -> Iterator[TestClient]:
    with TestClient(create_app(settings, runtime)) as test_client:
        yield test_client


def reload(client: TestClient, runtime: HoundRuntime, token: str | None = None) -> Any:
    return client.post("/api/admin/reload", headers={TOKEN_HEADER: token or runtime.ingest_token or ""})


def level_of(runtime: HoundRuntime, event: Any) -> str:
    stored = runtime.processor.process_batch([event])
    return stored[0].risk_level if stored else "not stored"


# ------------------------------------------------------------------------------ access
def test_reload_requires_the_token(client: TestClient, runtime: HoundRuntime) -> None:
    config_before = runtime.risk_engine.config
    assert client.post("/api/admin/reload").status_code == 401
    assert reload(client, runtime, token="wrong-token-" * 3).status_code == 401
    assert client.get("/api/admin/reload").status_code == 405  # never a simple GET
    assert runtime.risk_engine.config is config_before


# ------------------------------------------------------------------------------ what gets applied
def test_blocklist_edit_applies_without_restart(
    client: TestClient, runtime: HoundRuntime, settings: Settings, make_event: EventFactory
) -> None:
    assert level_of(runtime, make_event(domain="newly-bad.example", seconds=1)) == "safe"
    with settings.blocklist_path.open("a", encoding="utf-8") as handle:
        handle.write("newly-bad.example\n")
    response = reload(client, runtime)
    assert response.status_code == 200
    body = response.json()
    assert body["blocklist_entries"] == 4 and body["behaviour_windows_reset"] is False
    assert level_of(runtime, make_event(domain="newly-bad.example", seconds=2)) == "dangerous"


def test_allowlist_and_risk_file_edits_apply(
    client: TestClient, runtime: HoundRuntime, settings: Settings, make_event: EventFactory
) -> None:
    assert level_of(runtime, make_event(domain=DGA_LIKE, seconds=1)) == "suspicious"
    settings.allowlist_path.write_text(f"{DGA_LIKE}\n192.168.1.5\n", encoding="utf-8")
    settings.risk_config_path.write_text("[levels]\nsuspicious = 40\n", encoding="utf-8")
    body = reload(client, runtime).json()
    assert (body["allowlist_domains"], body["allowlist_devices"], body["risk_values_from_file"]) == (1, 1, 1)
    assert runtime.risk_engine.config.suspicious_threshold == 40
    earlier = client.get("/api/events", params={"domain": DGA_LIKE}).json()["items"]
    assert [item["risk_level"] for item in earlier] == ["suspicious"]  # stored events are not rescored
    assert level_of(runtime, make_event(domain=DGA_LIKE, seconds=2)) == "safe"


def test_invalid_risk_file_changes_nothing(
    client: TestClient, runtime: HoundRuntime, settings: Settings, make_event: EventFactory
) -> None:
    config_before = runtime.risk_engine.config
    with settings.blocklist_path.open("a", encoding="utf-8") as handle:
        handle.write("would-be-bad.example\n")
    settings.risk_config_path.write_text("[weights]\nblocklisted = 70\n", encoding="utf-8")  # typo
    response = reload(client, runtime)
    assert response.status_code == 400
    assert "weights.blocklisted: unknown setting" in response.json()["detail"]
    assert "previous settings stay in effect" in response.json()["detail"]
    assert runtime.risk_engine.config is config_before
    assert level_of(runtime, make_event(domain="would-be-bad.example")) == "safe"  # blocklist not swapped either


# ------------------------------------------------------------------------------ state that must survive
def test_behaviour_windows_survive_unless_their_length_changes(
    client: TestClient, runtime: HoundRuntime, settings: Settings, make_event: EventFactory
) -> None:
    def syn(port: int) -> Any:
        return make_event(packet_type=PacketType.TCP_SYN, destination_port=port, seconds=port * 0.01)

    runtime.processor.process_batch([syn(port) for port in range(1000, 1010)])  # 10 distinct ports
    settings.risk_config_path.write_text("[weights]\nuncommon_port = 6\n", encoding="utf-8")
    assert reload(client, runtime).json()["behaviour_windows_reset"] is False
    stored = runtime.processor.process_batch([syn(port) for port in range(1010, 1015)])  # 15 in total
    assert "PORT_SCAN_PATTERN" in {r.code for r in stored[-1].risk_reasons}  # counting continued

    settings.risk_config_path.write_text("[behaviour]\nwindow_seconds = 120\n", encoding="utf-8")
    assert reload(client, runtime).json()["behaviour_windows_reset"] is True
    stored = runtime.processor.process_batch([syn(1020)])
    assert "PORT_SCAN_PATTERN" not in {r.code for r in stored[-1].risk_reasons}  # windows restarted


def test_dns_answer_cache_survives(client: TestClient, runtime: HoundRuntime, make_event: EventFactory) -> None:
    answer = make_event(
        packet_type=PacketType.DNS_RESPONSE,
        source_ip="192.168.1.1",
        destination_ip="192.168.1.10",
        domain="cdn.example.org",
        dns_answers=("93.184.216.99",),
        dns_rcode=0,
    )
    runtime.processor.process_batch([answer])
    assert reload(client, runtime).status_code == 200
    stored = runtime.processor.process_batch(
        [make_event(packet_type=PacketType.TCP_SYN, destination_ip="93.184.216.99", seconds=1)]
    )
    assert stored[0].domain == "cdn.example.org" and stored[0].domain_source == "dns_cache"


def test_swap_waits_for_the_batch_in_progress(runtime: HoundRuntime, make_event: EventFactory) -> None:
    order: list[str] = []
    real_save = runtime.store.save

    def slow_save(items: Any) -> Any:
        order.append("batch started")
        time.sleep(0.3)
        order.append("batch finished")
        return real_save(items)

    runtime.database.initialize()
    runtime.store.save = slow_save  # type: ignore[method-assign]
    worker = threading.Thread(target=runtime.processor.process_batch, args=([make_event()],))
    worker.start()
    time.sleep(0.05)  # the batch is now in progress
    runtime.processor.reconfigure(lambda: order.append("swap"))
    worker.join()
    assert order == ["batch started", "batch finished", "swap"]
    runtime.database.dispose()


# ------------------------------------------------------------------------------ the CLI
@pytest.fixture
def server(settings: Settings) -> Iterator[LiveServer]:
    live = start_server(settings, free_port())
    yield live
    live.stop()


def test_cli_reload_against_a_running_server(
    settings: Settings, server: LiveServer, capsys: pytest.CaptureFixture[str]
) -> None:
    args = ["reload", "--api-url", server.url]
    configured = settings.model_copy(update={"port": server.port})
    patch = pytest.MonkeyPatch()
    patch.setattr(cli, "load_settings", lambda **_: configured)
    patch.setattr(cli, "configure_logging", lambda *a, **k: None)
    try:
        assert cli.main(args) == 0
        assert "Reloaded: 3 blocklist entries" in capsys.readouterr().out

        settings.risk_config_path.write_text("[levels]\nsuspicious = 0\n", encoding="utf-8")
        assert cli.main(args) == 1  # refused: the previous settings stay
        assert "Reload refused (HTTP 400)" in capsys.readouterr().err

        patch.setattr(cli, "load_settings", lambda **_: configured.model_copy(update={"ingest_token": None}))
        settings.resolve_path(settings.ingest_token_path).write_text("x" * 40, encoding="utf-8")  # wrong token
        assert cli.main(args) == 2
        assert "HTTP 401" in capsys.readouterr().err
    finally:
        patch.undo()


def test_cli_reload_without_a_server(settings: Settings, monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    settings.resolve_path(settings.ingest_token_path).write_text("y" * 40, encoding="utf-8")
    monkeypatch.setattr(cli, "load_settings", lambda **_: settings)
    monkeypatch.setattr(cli, "configure_logging", lambda *a, **k: None)
    assert cli.main(["reload", "--api-url", f"http://127.0.0.1:{free_port()}"]) == 2
    assert "Is the server running?" in capsys.readouterr().err


def test_reload_is_documented(client: TestClient) -> None:
    assert "/api/admin/reload" in client.get("/openapi.json").json()["paths"]
