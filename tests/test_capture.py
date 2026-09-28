"""Capture-service behaviour with Scapy's sniffer replaced by fakes (no root needed)."""

from __future__ import annotations

import errno
import threading
from typing import Any

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from app.ingestion import capture as capture_mod
from app.ingestion.capture import CaptureError, InterfaceInfo, PacketCaptureService, describe_capture_error
from app.models.events import NetworkEvent


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
            Ether()
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


def test_supervisor_detects_dead_sniffer(fake_sniffer: type[FakeSniffer]) -> None:
    service = PacketCaptureService("eth0", "udp port 53", lambda e: True, supervise_interval=0.05)
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
