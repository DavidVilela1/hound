"""A minimal MaxMind DB (.mmdb) writer, only for building test databases.

Writes the documented format (https://maxmind.github.io/MaxMind-DB/): an IPv6 search tree
with 24-bit records (IPv4 networks live under ``::/96``), a data section and the metadata
map. The files are read by the real ``maxminddb`` reader in the tests, so they exercise
exactly the code path a DB-IP download takes. Networks must not overlap.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

RECORD_BYTES = 3  # 24-bit records
METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"


def _size(type_bits: int, size: int, extended: int | None = None) -> bytes:
    head = type_bits << 5
    if size < 29:
        control, extra = head | size, b""
    elif size < 285:
        control, extra = head | 29, bytes([size - 29])
    elif size < 65821:
        control, extra = head | 30, (size - 285).to_bytes(2, "big")
    else:
        control, extra = head | 31, (size - 65821).to_bytes(3, "big")
    return bytes([control]) + (bytes([extended]) if extended is not None else b"") + extra


class U16(int):
    """Force an integer's MMDB type: libmaxminddb (the C reader) checks metadata types."""


class U32(int):
    pass


class U64(int):
    pass


def _uint(type_bits: int, value: int, extended: int | None = None) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
    return _size(type_bits, len(raw), extended) + raw


def encode(value: Any) -> bytes:
    if isinstance(value, U16):
        return _uint(5, value)
    if isinstance(value, U32):
        return _uint(6, value)
    if isinstance(value, U64):
        return _uint(0, value, extended=9 - 7)
    if isinstance(value, bool):
        return _size(0, int(value), extended=14 - 7)
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _size(2, len(raw)) + raw
    if isinstance(value, int):
        if value < 0:
            raise ValueError("negative integers are not needed here")
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
        if value < 2**16:
            return _size(5, len(raw)) + raw  # uint16
        if value < 2**32:
            return _size(6, len(raw)) + raw  # uint32
        return _size(0, len(raw), extended=9 - 7) + raw  # uint64
    if isinstance(value, dict):
        body = b"".join(encode(str(k)) + encode(v) for k, v in value.items())
        return _size(7, len(value)) + body
    if isinstance(value, list):
        return _size(0, len(value), extended=11 - 7) + b"".join(encode(v) for v in value)
    raise TypeError(f"cannot encode {type(value).__name__}")


class _Node:
    __slots__ = ("children", "number")

    def __init__(self) -> None:
        self.children: list[_Node | int | None] = [None, None]  # int = offset in the data section
        self.number = -1


def write_mmdb(
    path: Path,
    networks: dict[str, dict[str, Any]],
    *,
    database_type: str = "DBIP-Country-Lite",
    build_epoch: int = 1_788_000_000,
) -> Path:
    """Write ``{cidr: record}`` to ``path``; IPv4 networks are placed under ``::/96``."""
    data = bytearray()
    offsets: dict[int, int] = {}
    root = _Node()
    for cidr, record in networks.items():
        net = ipaddress.ip_network(cidr)
        # IPv4 a.b.c.d/n is ::a.b.c.d/(96+n) in an IPv6 tree.
        bits = int(net.network_address)
        length = net.prefixlen + (96 if net.version == 4 else 0)
        key = id(record)
        if key not in offsets:
            offsets[key] = len(data)
            data += encode(record)
        node = root
        for depth in range(length):
            bit = (bits >> (127 - depth)) & 1
            if depth == length - 1:
                node.children[bit] = offsets[key]
                break
            child = node.children[bit]
            if not isinstance(child, _Node):
                child = _Node()
                node.children[bit] = child
            node = child
    # Number the nodes breadth-first.
    order, queue = [], [root]
    while queue:
        node = queue.pop(0)
        node.number = len(order)
        order.append(node)
        queue.extend(c for c in node.children if isinstance(c, _Node))
    node_count = len(order)

    def record_value(child: _Node | int | None) -> int:
        if child is None:
            return node_count  # "no data"
        if isinstance(child, _Node):
            return child.number
        return node_count + 16 + child  # pointer into the data section

    tree = b"".join(
        record_value(n.children[0]).to_bytes(RECORD_BYTES, "big")
        + record_value(n.children[1]).to_bytes(RECORD_BYTES, "big")
        for n in order
    )
    metadata = {
        "node_count": U32(node_count),
        "record_size": U16(RECORD_BYTES * 8),
        "ip_version": U16(6),
        "database_type": database_type,
        "languages": ["en"],
        "binary_format_major_version": U16(2),
        "binary_format_minor_version": U16(0),
        "build_epoch": U64(build_epoch),
        "description": {"en": "Hound test database"},
    }
    path.write_bytes(tree + b"\x00" * 16 + bytes(data) + METADATA_MARKER + encode(metadata))
    return path


def country(code: str, name: str = "") -> dict[str, Any]:
    """A record shaped like DB-IP's / GeoLite2's country databases."""
    return {
        "continent": {"code": "EU"},
        "country": {"iso_code": code, "names": {"en": name or code}, "is_in_european_union": False},
    }


NETWORKS: dict[str, dict[str, Any]] = {
    "8.8.8.0/24": country("US", "United States"),
    "1.1.1.0/24": country("AU", "Australia"),
    "81.0.0.0/8": country("PT", "Portugal"),
    "2001:4860::/32": country("US", "United States"),
}


def dbip_file(directory: Path, month: str, networks: dict[str, Any] | None = None) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    return write_mmdb(directory / f"dbip-country-lite-{month}.mmdb", networks or NETWORKS)
