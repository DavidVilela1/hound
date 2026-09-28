"""Per-device sliding-window behaviour tracking (bounded memory).

All timing uses **event timestamps**, not the wall clock, so results are
deterministic and reproducible in tests and demo mode.
"""

from __future__ import annotations

from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass(frozen=True, slots=True)
class BehaviorSnapshot:
    """Counts for one device within the current window."""

    attempts_to_target: int = 0  # SYNs to the same destination ip:port
    ports_on_target_host: int = 0  # distinct destination ports on the same destination ip
    local_hosts_contacted: int = 0  # distinct local-network destination ips
    nxdomain_count: int = 0  # failed lookups (NXDOMAIN) received


@dataclass(slots=True)
class _Attempt:
    ts: datetime
    ip: str
    port: int | None
    local: bool


@dataclass(slots=True)
class _DeviceWindow:
    attempts: deque[_Attempt] = field(default_factory=deque)
    targets: Counter[tuple[str, int | None]] = field(default_factory=Counter)
    ports_per_host: dict[str, Counter[int | None]] = field(default_factory=dict)
    local_hosts: Counter[str] = field(default_factory=Counter)
    nxdomain: deque[datetime] = field(default_factory=deque)


class DeviceBehaviorTracker:
    """Tracks recent connection attempts and DNS failures per device.

    Memory is bounded by ``max_devices`` (least-recently-active devices are
    evicted) and ``max_entries_per_device``.
    """

    def __init__(
        self,
        window: timedelta,
        *,
        max_devices: int = 4096,
        max_entries_per_device: int = 4096,
    ) -> None:
        self._window = window
        self._max_devices = max_devices
        self._max_entries = max_entries_per_device
        self._devices: OrderedDict[str, _DeviceWindow] = OrderedDict()

    def _state(self, device: str) -> _DeviceWindow:
        state = self._devices.get(device)
        if state is None:
            state = _DeviceWindow()
            self._devices[device] = state
            while len(self._devices) > self._max_devices:
                self._devices.popitem(last=False)
        else:
            self._devices.move_to_end(device)
        return state

    def _evict_attempt(self, state: _DeviceWindow) -> None:
        old = state.attempts.popleft()
        key = (old.ip, old.port)
        state.targets[key] -= 1
        if state.targets[key] <= 0:
            del state.targets[key]
        ports = state.ports_per_host.get(old.ip)
        if ports is not None:
            ports[old.port] -= 1
            if ports[old.port] <= 0:
                del ports[old.port]
            if not ports:
                del state.ports_per_host[old.ip]
        if old.local:
            state.local_hosts[old.ip] -= 1
            if state.local_hosts[old.ip] <= 0:
                del state.local_hosts[old.ip]

    def _prune(self, state: _DeviceWindow, now: datetime) -> None:
        cutoff = now - self._window
        while state.attempts and state.attempts[0].ts < cutoff:
            self._evict_attempt(state)
        while state.nxdomain and state.nxdomain[0] < cutoff:
            state.nxdomain.popleft()

    def _snapshot(self, state: _DeviceWindow, ip: str | None = None, port: int | None = None) -> BehaviorSnapshot:
        return BehaviorSnapshot(
            attempts_to_target=state.targets.get((ip, port), 0) if ip else 0,
            ports_on_target_host=len(state.ports_per_host.get(ip, ())) if ip else 0,
            local_hosts_contacted=len(state.local_hosts),
            nxdomain_count=len(state.nxdomain),
        )

    def record_attempt(
        self, device: str, dst_ip: str, dst_port: int | None, ts: datetime, *, local: bool
    ) -> BehaviorSnapshot:
        """Record a TCP connection attempt and return the updated counts."""
        state = self._state(device)
        self._prune(state, ts)
        if len(state.attempts) >= self._max_entries:
            self._evict_attempt(state)
        state.attempts.append(_Attempt(ts, dst_ip, dst_port, local))
        state.targets[(dst_ip, dst_port)] += 1
        state.ports_per_host.setdefault(dst_ip, Counter())[dst_port] += 1
        if local:
            state.local_hosts[dst_ip] += 1
        return self._snapshot(state, dst_ip, dst_port)

    def record_nxdomain(self, device: str, ts: datetime) -> None:
        state = self._state(device)
        self._prune(state, ts)
        if len(state.nxdomain) >= self._max_entries:
            state.nxdomain.popleft()
        state.nxdomain.append(ts)

    def snapshot(self, device: str, ts: datetime) -> BehaviorSnapshot:
        state = self._devices.get(device)
        if state is None:
            return BehaviorSnapshot()
        self._prune(state, ts)
        return self._snapshot(state)

    @property
    def tracked_devices(self) -> int:
        return len(self._devices)
