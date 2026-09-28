#!/usr/bin/env python3
"""Send a few harmless packets over loopback to verify real packet capture.

Start Hound capturing on the loopback interface first (``lo`` on Linux,
``lo0`` on macOS; Windows needs the Npcap loopback adapter), then run:

    python scripts/generate_test_traffic.py

It sends two DNS queries to 127.0.0.1:53 (one for a sample-blocklist domain)
and two TCP connection attempts to closed local ports. Nothing leaves the
machine and no response is expected.
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scapy.layers.dns import DNS, DNSQR  # noqa: E402

TARGET = "127.0.0.1"
DOMAINS = ("capture-test.example.com", "malware-c2.example")
PORTS = (9, 3389)


def main() -> int:
    for domain in DOMAINS:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(bytes(DNS(rd=1, qd=DNSQR(qname=domain))), (TARGET, 53))
        print(f"DNS query sent for {domain}")
    for port in PORTS:
        with socket.socket() as sock:
            sock.settimeout(1)
            try:
                sock.connect((TARGET, port))
            except OSError:
                pass
        print(f"TCP connection attempt sent to {TARGET}:{port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
