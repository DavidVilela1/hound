"""Capture-service behaviour with Scapy's sniffer replaced by fakes (no root needed)."""

from __future__ import annotations

import errno
import logging
import threading
from typing import Any

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from app.ingestion import capture as capture_mod
from app.ingestion.capture import CaptureError, InterfaceInfo, PacketCaptureService, describe_capture_error
from app.models.events import NetworkEvent
from tests.conftest import eth


@pytest.fixture(autouse=True)
def fake_interfaces(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        capture_mod, "list_interfaces", lambda: [InterfaceInfo("eth0", "Ethernet", "192.168.1.10", None)]
    )


class FakeSniffer:
    """Mimics scapy.sendrecv.AsyncSniffer."""

    fail_with: BaseException | None = None
    instances: list[FakeSniffer] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.exception: BaseException | None = None
        self.running = False
        self.thread: threading.Thread | None = None
        self._stop = threading.Event()
        FakeSniffer.instances.append(self)

    def start(self) -> None:
        def run() -> None:
            if FakeSniffer.fail_with is not None:
                self.exception = FakeSniffer.fail_with
                return
            self.running = True
            self.kwargs["started_callback"]()
            self._stop.wait()
            self.running = False

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def stop(self, join: bool = True) -> None:
        self._stop.set()
        if join and self.thread:
            self.thread.join()


@pytest.fixture
def fake_sniffer(monkeypatch: pytest.MonkeyPatch) -> type[FakeSniffer]:
    FakeSniffer.fail_with = None
    FakeSniffer.instances = []
    monkeypatch.setattr(capture_mod, "AsyncSniffer", FakeSniffer)
    return FakeSniffer


def test_capture_start_feed_and_stop(fake_sniffer: type[FakeSniffer]) -> None:
    received: list[NetworkEvent] = []
    service = PacketCaptureService("eth0", "udp port 53", lambda e: received.append(e) or True)
    service.start()
    assert service.status().state == "running"
    sniffer = fake_sniffer.instances[0]
    assert sniffer.kwargs["filter"] == "udp port 53" and sniffer.kwargs["store"] is False
    packet = Ether(
        bytes(
            eth()
            / IP(src="192.168.1.10", dst="192.168.1.1")
            / UDP(sport=1, dport=53)
            / DNS(qd=DNSQR(qname="a.example"))
        )
    )
    sniffer.kwargs["prn"](packet)  # what Scapy does for each captured packet
    sniffer.kwargs["prn"](Ether(b"\x00" * 20))  # garbage must not raise
    assert [e.domain for e in received] == ["a.example"]
    service.stop()
    assert service.status().state == "stopped"


def test_permission_denied_is_reported_clearly(fake_sniffer: type[FakeSniffer]) -> None:
    fake_sniffer.fail_with = PermissionError(errno.EPERM, "Operation not permitted")
    service = PacketCaptureService("eth0", "udp port 53", lambda e: True)
    with pytest.raises(CaptureError, match="Permission denied"):
        service.start()
    status = service.status()
    assert status.state == "error" and status.error and "privileges" in status.error


def test_unknown_interface(fake_sniffer: type[FakeSniffer]) -> None:
    service = PacketCaptureService("does-not-exist0", "udp port 53", lambda e: True)
    with pytest.raises(CaptureError, match="not found"):
        service.start()
    assert service.status().state == "error"


def test_interface_description_is_accepted(fake_sniffer: type[FakeSniffer]) -> None:
    service = PacketCaptureService("Ethernet", "udp port 53", lambda e: True)
    service.start()
    assert service.status().interface == "eth0"
    service.stop()


def test_missing_libpcap_falls_back_to_userspace_filter(fake_sniffer: type[FakeSniffer]) -> None:
    from app.core.config import DEFAULT_BPF_FILTER

    fake_sniffer.fail_with = ImportError("libpcap is not available. Cannot compile filter !")
    original_start = FakeSniffer.start

    def start_once_failing(self: FakeSniffer) -> None:
        if "filter" not in self.kwargs:
            FakeSniffer.fail_with = None  # the retry without a BPF filter succeeds
        original_start(self)

    FakeSniffer.start = start_once_failing  # type: ignore[method-assign]
    try:
        service = PacketCaptureService("eth0", DEFAULT_BPF_FILTER, lambda e: True)
        service.start()
        assert service.status().state == "running"
        assert "lfilter" in fake_sniffer.instances[-1].kwargs
        service.stop()
    finally:
        FakeSniffer.start = original_start  # type: ignore[method-assign]


def test_supervisor_detects_dead_sniffer_when_restarts_are_off(fake_sniffer: type[FakeSniffer]) -> None:
    service = PacketCaptureService("eth0", "udp port 53", lambda e: True, supervise_interval=0.05, restart=False)
    service.start()
    sniffer = fake_sniffer.instances[0]
    sniffer.exception = OSError(errno.ENODEV, "No such device")
    sniffer.stop()
    for _ in range(100):
        if service.status().state == "error":
            break
        threading.Event().wait(0.02)
    assert service.status().state == "error"
    assert "not available" in (service.status().error or "")
    service.stop()


# --------------------------------------------------------------------------- recovery (ADR-030)
def wait_for(condition: Any, timeout: float = 5.0) -> bool:
    deadline = threading.Event()
    for _ in range(int(timeout / 0.02)):
        if condition():
            return True
        deadline.wait(0.02)
    return bool(condition())


@pytest.fixture
def reloads(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls: list[int] = []
    monkeypatch.setattr(capture_mod, "_reload_interfaces", lambda: calls.append(1))
    return calls


def fast_service(**kwargs: Any) -> PacketCaptureService:
    return PacketCaptureService(
        "eth0", "udp port 53", lambda e: True, supervise_interval=0.02, restart_delay=0.05, **kwargs
    )


def kill(sniffer: FakeSniffer, exc: BaseException | None = None) -> None:
    """End the fake sniffer the way Scapy does: with an exception, or quietly (interface down)."""
    sniffer.exception = exc
    sniffer.stop()


def test_capture_restarts_after_the_interface_goes_down(fake_sniffer: type[FakeSniffer], reloads: list[int]) -> None:
    service = fast_service()
    service.start()
    kill(fake_sniffer.instances[0])  # Scapy's "Network is down": thread ends, no exception
    assert wait_for(lambda: len(fake_sniffer.instances) == 2 and service.status().state == "running")
    status = service.status()
    assert status.restarts == 1 and status.downtime_seconds >= 0 and status.error is None
    assert fake_sniffer.instances[1].kwargs["filter"] == "udp port 53"  # same capture as before
    assert reloads  # the interface list was re-read before relaunching
    kill(fake_sniffer.instances[1], OSError(errno.ENETDOWN, "Network is down"))
    assert wait_for(lambda: service.status().restarts == 2 and service.status().state == "running")
    service.stop()
    assert service.status().state == "stopped"


def test_restarting_is_visible_and_retries_until_the_interface_returns(
    fake_sniffer: type[FakeSniffer], reloads: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    present: list[InterfaceInfo] = []  # the adapter is gone (sleep, Wi-Fi off, unplugged)
    service = fast_service(restart_max_delay=0.1)
    service.start()
    monkeypatch.setattr(capture_mod, "list_interfaces", lambda: list(present))
    kill(fake_sniffer.instances[0])
    assert wait_for(lambda: service.status().state == "restarting")
    status = service.status()
    assert status.error and "went down or disappeared" in status.error and "automatically" in status.error
    assert wait_for(lambda: len(reloads) >= 3)  # keeps trying, with growing delays capped at the maximum
    assert len(fake_sniffer.instances) == 1  # nothing launched while the interface is missing
    assert service.status().downtime_seconds >= 0.1  # an ongoing outage is already counted
    present.append(InterfaceInfo("eth0", "Ethernet", "192.168.1.10", None))  # it is back
    assert wait_for(lambda: service.status().state == "running")
    assert len(fake_sniffer.instances) == 2 and service.status().restarts == 1
    service.stop()


def test_failed_restarts_back_off_up_to_the_maximum(
    fake_sniffer: type[FakeSniffer],
    reloads: list[int],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """1, 2, 4 … seconds then once a minute in real use; scaled down here."""
    service = fast_service(restart_max_delay=0.2)
    service.start()
    monkeypatch.setattr(capture_mod, "list_interfaces", lambda: [])
    with caplog.at_level(logging.WARNING, logger=capture_mod.__name__):
        kill(fake_sniffer.instances[0])
        assert wait_for(lambda: len(reloads) >= 4)
        service.stop()
    delays = [r.retry_in_seconds for r in caplog.records if hasattr(r, "retry_in_seconds")]  # type: ignore[attr-defined]
    assert delays[:4] == [0.1, 0.2, 0.2, 0.2]


def test_stop_while_restarting(
    fake_sniffer: type[FakeSniffer], reloads: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    service = fast_service(restart_max_delay=0.05)
    service.start()
    monkeypatch.setattr(capture_mod, "list_interfaces", lambda: [])
    kill(fake_sniffer.instances[0])
    assert wait_for(lambda: service.status().state == "restarting")
    threading.Event().wait(0.1)
    service.stop()  # returns promptly; the supervisor ends
    status = service.status()
    assert status.state == "stopped" and status.error is None
    assert status.restarts == 1 and status.downtime_seconds >= 0.1
    assert service._supervisor is None


def test_a_restart_keeps_the_user_space_filter(fake_sniffer: type[FakeSniffer], reloads: list[int]) -> None:
    from app.core.config import DEFAULT_BPF_FILTER

    fake_sniffer.fail_with = ImportError("libpcap is not available. Cannot compile filter !")
    original_start = FakeSniffer.start

    def start_without_bpf(self: FakeSniffer) -> None:
        if "filter" not in self.kwargs:
            FakeSniffer.fail_with = None
        original_start(self)

    FakeSniffer.start = start_without_bpf  # type: ignore[method-assign]
    try:
        service = PacketCaptureService(
            "eth0", DEFAULT_BPF_FILTER, lambda e: True, supervise_interval=0.02, restart_delay=0.05
        )
        service.start()
        kill(fake_sniffer.instances[-1])
        assert wait_for(lambda: service.status().restarts == 1 and service.status().state == "running")
        relaunched = fake_sniffer.instances[-1]
        assert "filter" not in relaunched.kwargs and "lfilter" in relaunched.kwargs
        service.stop()
    finally:
        FakeSniffer.start = original_start  # type: ignore[method-assign]


@pytest.mark.parametrize(
    "exc,fragment",
    [
        (PermissionError(errno.EACCES, "denied"), "Permission denied"),
        (OSError(errno.ENODEV, "No such device"), "not available"),
        (RuntimeError("Npcap is not installed"), "driver unavailable"),
        (RuntimeError("Failed to compile filter expression"), "Invalid BPF filter"),
        (ValueError("weird"), "Packet capture failed"),
    ],
)
def test_describe_capture_error(exc: BaseException, fragment: str) -> None:
    assert fragment in describe_capture_error(exc, "eth0")


def test_loopback_duplicates_are_dropped() -> None:
    from app.ingestion.capture import LoopbackDeduplicator, is_loopback_interface

    dedupe = LoopbackDeduplicator(window=0.2)
    assert not dedupe.is_duplicate(b"frame-1", 10.0)
    assert dedupe.is_duplicate(b"frame-1", 10.001)  # same frame, second direction
    assert not dedupe.is_duplicate(b"frame-2", 10.002)
    assert not dedupe.is_duplicate(b"frame-1", 11.0)  # outside the window: a new packet
    assert is_loopback_interface("lo") and is_loopback_interface("lo0")
    assert is_loopback_interface("Npcap Loopback Adapter")
    assert not is_loopback_interface("eth0") and not is_loopback_interface(None)


def test_windows_network_name_is_accepted(monkeypatch: pytest.MonkeyPatch, fake_sniffer: type[FakeSniffer]) -> None:
    npf = r"\Device\NPF_{3F2504E0-4F89-11D3-9A0C-0305E82C3301}"
    monkeypatch.setattr(
        capture_mod,
        "list_interfaces",
        lambda: [InterfaceInfo("Wi-Fi", "Intel(R) Wi-Fi 6 AX201 160MHz", "192.168.1.20", None, npf)],
    )
    for alias in ("Wi-Fi", "Intel(R) Wi-Fi 6 AX201 160MHz", npf):
        service = PacketCaptureService(alias, "udp port 53", lambda e: True)
        service.start()
        assert service.status().interface == "Wi-Fi"  # always resolved to Scapy's name
        service.stop()
