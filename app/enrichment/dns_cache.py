"""Bounded IP → domain cache built from observed DNS answers.

Lets Hound label a TCP SYN to ``142.250.1.1`` with the domain the device
looked up moments earlier. Bounded (LRU) and time-limited (TTL) so it cannot
grow without limit.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from datetime import datetime, timedelta


class ResolutionCache:
    def __init__(self, max_entries: int = 10_000, ttl: timedelta = timedelta(hours=1)) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self._max = max_entries
        self._ttl = ttl
        self._data: OrderedDict[str, tuple[str, datetime]] = OrderedDict()
        self._lock = threading.Lock()

    def put(self, ip: str, domain: str, observed_at: datetime) -> None:
        with self._lock:
            self._data[ip] = (domain, observed_at + self._ttl)
            self._data.move_to_end(ip)
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    def get(self, ip: str, at: datetime) -> str | None:
        with self._lock:
            entry = self._data.get(ip)
            if entry is None:
                return None
            domain, expires = entry
            if at > expires:
                del self._data[ip]
                return None
            self._data.move_to_end(ip)
            return domain

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)
