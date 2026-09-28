#!/usr/bin/env python3
"""End-to-end smoke test: start Hound in demo mode and verify the whole pipeline.

Checks: server starts → database initialises → demo events are generated →
events are persisted → REST API responds → dashboard page is served →
a new event arrives over the WebSocket.

Uses a temporary database and a free port, so it never touches data/.
Run from the project root:  python scripts/smoke_test.py
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 (local URL)
        return json.loads(resp.read())


def wait_for(url: str, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            get_json(url)
            return
        except OSError:
            time.sleep(0.3)
    raise SystemExit(f"FAIL: server did not answer {url} within {timeout}s")


async def receive_ws_event(url: str, timeout: float = 20) -> dict:
    from websockets.asyncio.client import connect

    async with connect(url, proxy=None) as ws:
        async with asyncio.timeout(timeout):
            async for raw in ws:
                message = json.loads(raw)
                if message.get("type") == "event":
                    return message["data"]
    raise SystemExit("FAIL: no event received over WebSocket")


def check(label: str, condition: bool) -> None:
    print(f"  {'PASS' if condition else 'FAIL'}  {label}")
    if not condition:
        raise SystemExit(1)


def main() -> int:
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory() as tmp:
        env = os.environ | {
            "HOUND_DATABASE_URL": f"sqlite:///{Path(tmp) / 'smoke.db'}",
            "HOUND_INGEST_TOKEN_PATH": str(Path(tmp) / "token"),
            "HOUND_DEMO_EVENTS_PER_SECOND": "20",
            "HOUND_LOG_LEVEL": "WARNING",
        }
        proc = subprocess.Popen([sys.executable, "run.py", "--demo", "--port", str(port)], cwd=ROOT, env=env)
        try:
            print(f"Hound smoke test on {base}")
            wait_for(f"{base}/health")
            health = get_json(f"{base}/health")
            check("server started and /health answers", health["status"] in ("ok", "degraded"))
            check("database initialised", health["database"] == "ok")
            check("demo source running", health["pipeline"]["source_state"] == "running")
            time.sleep(3)
            stats = get_json(f"{base}/api/stats")
            check(f"demo events persisted ({stats['total_events']} events)", stats["total_events"] > 0)
            check("devices aggregated", stats["devices"] > 0)
            events = get_json(f"{base}/api/events?limit=5")
            check("/api/events returns items", len(events["items"]) > 0)
            check("/api/events/{id} works", get_json(f"{base}/api/events/{events['items'][0]['id']}")["id"] > 0)
            check("/api/devices works", get_json(f"{base}/api/devices")["total"] > 0)
            check("/api/stats/countries works", "countries" in get_json(f"{base}/api/stats/countries"))
            with urllib.request.urlopen(f"{base}/", timeout=10) as resp:  # noqa: S310
                html = resp.read().decode()
            check("dashboard page served", resp.status == 200 and "Hound" in html)
            with urllib.request.urlopen(f"{base}/docs", timeout=5) as resp:  # noqa: S310
                check("OpenAPI docs served at /docs", resp.status == 200)
            event = asyncio.run(receive_ws_event(f"ws://127.0.0.1:{port}/ws/events"))
            check(f"real-time event over WebSocket (#{event['id']} {event['packet_type']})", event["id"] > 0)
            print("All smoke checks passed.")
            return 0
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
