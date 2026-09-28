"""Capture daemon end to end, without privileges.

Split mode for real: a live uvicorn server (unprivileged Hound) and the ``CaptureDaemon``
(normally the privileged process) talking over localhost HTTP with the ingest token.
Only the Scapy sniffer is replaced: a fake capture feeds real serialised packets through
the real ``PacketParser`` into the daemon's sink, exactly as ``AsyncSniffer`` would.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import pytest
import uvicorn
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

import app.ingestion.daemon as daemon_mod
from app.api.app import create_app
from app.core.config import Settings
from app.core.security import load_or_create_ingest_token
from app.database.repositories import EventFilter
from app.ingestion.capture import CaptureError
from app.ingestion.daemon import CaptureDaemon
from app.ingestion.parser import PacketParser
from app.ingestion.sources import SourceStatus
from app.services.runtime import HoundRuntime
from tests.conftest import eth

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")  # websockets/uvicorn internals


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_until(condition: Callable[[], bool], timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return False


# --------------------------------------------------------------------------- live server


@dataclass
class LiveServer:
    url: str
    port: int
    runtime: HoundRuntime
    server: uvicorn.Server
    thread: threading.Thread

    def stored_events(self) -> int:
        return self.runtime.events.list_events(EventFilter(), limit=1, offset=0).total

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=15)


def start_server(settings: Settings, port: int) -> LiveServer:
    runtime = HoundRuntime(settings)
    config = uvicorn.Config(
        create_app(settings, runtime), host="127.0.0.1", port=port, log_config=None, access_log=False
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="test-uvicorn", daemon=True)
    thread.start()
    assert wait_until(lambda: server.started, 15), "test server did not start"
    return LiveServer(f"http://127.0.0.1:{port}", port, runtime, server, thread)


@pytest.fixture
def live_server(settings: Settings) -> Iterator[LiveServer]:
    server = start_server(settings, free_port())
    yield server
    server.stop()


# --------------------------------------------------------------------------- fake capture


def frames(api_port: int) -> list[bytes]:
    """Raw frames as a sniffer would deliver them (incl. the daemon's own API connection)."""
    return [
        bytes(
            eth()
            / IP(src="192.168.1.10", dst="192.168.1.1")
            / UDP(sport=50001, dport=53)
            / DNS(qd=DNSQR(qname="daemon-test.example.com"))
        ),
        bytes(
            eth()
            / IP(src="192.168.1.10", dst="192.168.1.1")
            / UDP(sport=50002, dport=53)
            / DNS(qd=DNSQR(qname="c2.bad.example"))
        ),
        bytes(eth() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=40000, dport=443, flags="S")),
        # The daemon's own POST to the API: must be filtered, never forwarded.
        bytes(eth() / IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=45000, dport=api_port, flags="S")),
    ]


EXPECTED_EVENTS = 3  # two DNS queries + one real SYN


class FakeCapture:
    """Stands in for ``PacketCaptureService``; configured per test via class attributes."""

    frames: list[bytes] = []
    fail_on_start: str | None = None
    fail_after_start: str | None = None
    instances: list[FakeCapture] = []

    def __init__(self, interface: str | None, bpf_filter: str, sink: Callable[..., bool], **_: Any) -> None:
        self.interface = interface or "fake0"
        self.bpf_filter = bpf_filter
        self.sink = sink
        self.parser = PacketParser(self.interface)
        self.state = "idle"
        self.error: str | None = None
        FakeCapture.instances.append(self)

    def start(self) -> None:
        if FakeCapture.fail_on_start:
            self.state, self.error = "error", FakeCapture.fail_on_start
            raise CaptureError(FakeCapture.fail_on_start)
        self.state = "running"
        for raw in FakeCapture.frames:
            packet = Ether(raw)
            packet.time = time.time()
            event = self.parser.parse(packet)
            if event is not None:
                self.sink(event)
        if FakeCapture.fail_after_start:
            self.state, self.error = "error", FakeCapture.fail_after_start

    def stop(self) -> None:
        if self.state != "error":
            self.state = "stopped"

    def status(self) -> SourceStatus:
        stats = self.parser.stats
        return SourceStatus(
            "capture",
            self.state,
            self.error,
            self.interface,
            stats.parsed,
            stats.ignored,
            stats.malformed,  # type: ignore[arg-type]
        )


@pytest.fixture(autouse=True)
def fake_capture(monkeypatch: pytest.MonkeyPatch) -> type[FakeCapture]:
    FakeCapture.frames, FakeCapture.instances = [], []
    FakeCapture.fail_on_start = FakeCapture.fail_after_start = None
    monkeypatch.setattr(daemon_mod, "PacketCaptureService", FakeCapture)
    monkeypatch.setattr(daemon_mod, "STATUS_POLL_SECONDS", 0.05)
    return FakeCapture


@dataclass
class DaemonRun:
    daemon: CaptureDaemon
    thread: threading.Thread
    result: list[int]

    def stop(self) -> int:
        self.daemon.stop()
        self.thread.join(timeout=15)
        assert not self.thread.is_alive(), "daemon did not stop"
        return self.result[0]


def run_daemon(settings: Settings, api_url: str, token: str) -> DaemonRun:
    daemon = CaptureDaemon(settings, interface="fake0", api_url=api_url, token=token)
    result: list[int] = []
    thread = threading.Thread(target=lambda: result.append(daemon.run()), name="test-daemon", daemon=True)
    thread.start()
    return DaemonRun(daemon, thread, result)


# --------------------------------------------------------------------------- tests


def test_split_mode_delivers_events_end_to_end(settings: Settings, live_server: LiveServer) -> None:
    FakeCapture.frames = frames(live_server.port)
    token = live_server.runtime.ingest_token
    assert token
    run = run_daemon(settings, live_server.url, token)
    assert wait_until(lambda: live_server.stored_events() >= EXPECTED_EVENTS), "events never reached the server"
    time.sleep(0.3)  # would expose a forwarded self-traffic event
    assert run.stop() == 0

    page = live_server.runtime.events.list_events(EventFilter(), limit=10, offset=0)
    assert page.total == EXPECTED_EVENTS
    domains = {e.domain for e in page.items}
    assert {"daemon-test.example.com", "c2.bad.example"} <= domains
    assert all(e.destination_port != live_server.port for e in page.items)  # own traffic filtered
    dangerous = [e for e in page.items if e.risk_level == "dangerous"]
    assert [e.domain for e in dangerous] == ["c2.bad.example"]  # server-side enrichment ran
    assert run.daemon._forwarder.stats.sent == EXPECTED_EVENTS
    assert FakeCapture.instances[0].state == "stopped"


def test_capture_start_failure_exits_2(settings: Settings, live_server: LiveServer) -> None:
    FakeCapture.fail_on_start = "Permission denied opening interface 'fake0'"
    run = run_daemon(settings, live_server.url, live_server.runtime.ingest_token or "")
    run.thread.join(timeout=15)
    assert run.result == [2]
    assert not run.daemon._forwarder._thread  # forwarder was stopped again


def test_capture_failure_while_running_exits_3(settings: Settings, live_server: LiveServer) -> None:
    FakeCapture.fail_after_start = "Network interface 'fake0' is not available."
    run = run_daemon(settings, live_server.url, live_server.runtime.ingest_token or "")
    run.thread.join(timeout=15)
    assert run.result == [3]


def test_api_down_at_start_then_recovers(settings: Settings, caplog: pytest.LogCaptureFixture) -> None:
    port = free_port()
    token = load_or_create_ingest_token(settings)  # the server will read the same token file
    FakeCapture.frames = frames(port)
    with caplog.at_level(logging.WARNING, logger="app.ingestion.daemon"):
        run = run_daemon(settings, f"http://127.0.0.1:{port}", token)
        assert wait_until(lambda: "not reachable yet" in caplog.text, 5)
    server = start_server(settings, port)  # comes up after the daemon has buffered events
    try:
        assert wait_until(lambda: server.stored_events() >= EXPECTED_EVENTS, 20), "buffered events were not retried"
        assert run.stop() == 0
    finally:
        server.stop()


PROXY_PROBE = r"""
import json, sys
from datetime import UTC, datetime
from app.ingestion import daemon, forwarder
url, token = sys.argv[1], sys.argv[2]
event = {"timestamp": datetime.now(UTC).isoformat(), "source_ip": "192.168.1.10", "source_port": 5000,
         "destination_ip": "192.168.1.1", "destination_port": 53, "protocol": "UDP",
         "packet_type": "dns_query", "domain": "proxy-probe.example.com"}
status = forwarder.urllib_transport(url + forwarder.INGEST_PATH, json.dumps({"events": [event]}).encode(),
                                   {"Content-Type": "application/json", "X-Hound-Token": token}, 5.0)
print(json.dumps({"reachable": daemon._api_reachable(url), "ingest_status": status}))
"""


def test_proxy_settings_are_ignored_for_the_local_api(settings: Settings, live_server: LiveServer) -> None:
    """A proxy in the environment (common on work laptops) must not capture localhost traffic.

    Runs in a fresh interpreter because the daemon's HTTP opener is created at import time,
    exactly when a real daemon process would read its proxy environment.
    """
    import json
    import os
    import subprocess
    import sys

    from app.core.config import PROJECT_ROOT

    env = {k: v for k, v in os.environ.items() if k.lower() not in {"no_proxy", "http_proxy", "https_proxy"}}
    env.update(HTTP_PROXY="http://127.0.0.1:9", HTTPS_PROXY="http://127.0.0.1:9")  # nothing listens there
    env["http_proxy"] = env["https_proxy"] = "http://127.0.0.1:9"
    result = subprocess.run(
        [sys.executable, "-c", PROXY_PROBE, live_server.url, live_server.runtime.ingest_token or ""],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    outcome = json.loads(result.stdout.strip().splitlines()[-1])
    assert outcome == {"reachable": True, "ingest_status": 202}, "daemon traffic went through the proxy"
    assert wait_until(lambda: live_server.stored_events() == 1)


def test_statistics_are_logged(
    settings: Settings, live_server: LiveServer, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(daemon_mod, "STATS_INTERVAL_SECONDS", 0.0)
    FakeCapture.frames = frames(live_server.port)
    with caplog.at_level(logging.INFO, logger="app.ingestion.daemon"):
        run = run_daemon(settings, live_server.url, live_server.runtime.ingest_token or "")
        assert wait_until(lambda: "Capture statistics" in caplog.text, 5)
        assert run.stop() == 0
    record = next(r for r in caplog.records if r.getMessage() == "Capture statistics")
    assert record.parsed == 4 and record.queue_drops == 0  # type: ignore[attr-defined]


def test_cli_capture_requires_a_token(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.cli as cli

    monkeypatch.setenv("HOUND_INGEST_TOKEN_PATH", str(settings.resolve_path(settings.ingest_token_path)))
    monkeypatch.delenv("HOUND_INGEST_TOKEN", raising=False)
    monkeypatch.setattr(cli, "configure_logging", lambda *a, **k: None)
    assert cli.main(["capture", "-i", "fake0"]) == 2  # no token file exists yet
