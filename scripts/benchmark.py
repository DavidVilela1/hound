#!/usr/bin/env python3
"""Measure Hound's throughput and latency on this machine (ROADMAP §I).

Everything runs in-process on a temporary database — no network, no privileges,
nothing written to data/. Stages:

1. Scapy dissection and parsing of realistic frames from the demo traffic generator.
2. Processing (enrich + risk + SQLite commit) at batch sizes 1, 50 and 200.
3. Filling the database to --rows events, then timing the API endpoints the dashboard
   polls (in-process HTTP, including JSON serialisation).
4. Storage per event and peak memory.

The events are replayed from a pool of parsed demo packets with fresh timestamps, so a
large database fills quickly while keeping a realistic mix. Checks at the end compare
against the thresholds in ROADMAP §I; they are informational (exit code 0) because
timings on shared or busy machines vary.

    python scripts/benchmark.py                 # 50 000 rows, about a minute
    python scripts/benchmark.py --rows 250000   # the full retention cap (the §I baseline)
    python scripts/benchmark.py --json          # machine-readable result
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import sys
import tempfile
import time
import warnings
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

BUSY_HOME_EVENTS_PER_SECOND = 100  # a busy household: tens of DNS queries + SYNs per second
STATS_TRIGGER_MS = 200.0  # ROADMAP §I: above this, maintain counters incrementally
PROCESSING_SAMPLE = {1: 1_000, 50: 5_000, 200: 10_000}  # events timed per batch size


def peak_rss_mib() -> float | None:
    """Peak resident memory of this process, where the OS reports it."""
    try:
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            class Counters(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            # Declare the real signatures: without them ctypes passes the process handle as a
            # 32-bit int, which is not a valid HANDLE on 64-bit Windows and the call fails
            # (the first version always printed "n/a" there). Private DLL objects, so the global
            # ctypes.windll prototypes stay untouched.
            kernel32 = ctypes.WinDLL("kernel32")
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            kernel32.GetCurrentProcess.argtypes = []
            get_info = kernel32.K32GetProcessMemoryInfo  # kernel32 export since Windows 7
            get_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
            get_info.restype = wintypes.BOOL
            counters = Counters()
            counters.cb = ctypes.sizeof(counters)
            if not get_info(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
                return None
            return round(counters.PeakWorkingSetSize / 2**20, 1)
        import resource

        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(peak / 2**20 if sys.platform == "darwin" else peak / 2**10, 1)  # macOS: bytes, Linux: KiB
    except (ImportError, OSError, AttributeError):
        return None


def timed_ms(action: Callable[[], object], repeat: int) -> float:
    action()  # warm-up (caches, first-query planning)
    started = time.perf_counter()
    for _ in range(repeat):
        action()
    return round((time.perf_counter() - started) / repeat * 1000, 2)


def run(rows: int, packets: int, seed: int, repeat: int, samples: dict[int, int]) -> dict[str, Any]:
    logging.disable(logging.WARNING)
    warnings.filterwarnings("ignore")
    from fastapi.testclient import TestClient
    from scapy.layers.l2 import Ether

    from app import __version__
    from app.api.app import create_app
    from app.core.config import Settings
    from app.ingestion.demo import DemoTrafficGenerator
    from app.ingestion.parser import PacketParser
    from app.services.processing import summarize_latency
    from app.services.runtime import HoundRuntime

    result: dict[str, Any] = {
        "environment": {
            "hound": __version__,
            "python": platform.python_version(),
            "platform": platform.platform(),
            "cpus": os.cpu_count(),
            "rows": rows,
            "seed": seed,
        }
    }

    # 1. dissection + parsing --------------------------------------------------------------
    generator = DemoTrafficGenerator(seed=seed)
    raw: list[bytes] = []
    while len(raw) < packets:
        raw.extend(bytes(packet) for packet in generator.next_batch())
    raw = raw[:packets]
    started = time.perf_counter()
    dissected = [Ether(frame) for frame in raw]
    dissect_s = time.perf_counter() - started
    parser = PacketParser("bench0")
    started = time.perf_counter()
    pool = [event for packet in dissected if (event := parser.parse(packet)) is not None]
    parse_s = time.perf_counter() - started
    if not pool:
        raise SystemExit("the demo generator produced no parseable events")
    result["capture"] = {
        "packets": len(raw),
        "events_parsed": len(pool),
        "dissect_packets_per_s": round(len(raw) / dissect_s),
        "parse_packets_per_s": round(len(raw) / parse_s),
    }

    clock = datetime.now(UTC) - timedelta(days=2)

    def replay(count: int) -> list[Any]:
        """``count`` events from the pool with fresh, increasing timestamps."""
        nonlocal clock
        events = []
        for index in range(count):
            clock += timedelta(milliseconds=5)
            events.append(pool[index % len(pool)].model_copy(update={"timestamp": clock}))
        return events

    # ignore_cleanup_errors: Windows may still hold a SQLite handle for a moment after shutdown.
    with tempfile.TemporaryDirectory(prefix="hound-bench-", ignore_cleanup_errors=True) as tmp:
        settings = Settings(
            _env_file=None,  # type: ignore[call-arg]
            database_url=f"sqlite:///{Path(tmp, 'bench.db').as_posix()}",
            ingest_token_path=Path(tmp, ".ingest_token"),
            allowed_hosts="testserver",
            retention_max_events=max(rows * 2, 1_000),  # no pruning while filling
            enable_dashboard=False,
            # Use an installed DB-IP file if there is one (read-only), so lookups are measured
            # as in real use; never download anything from a benchmark.
            geoip_auto_update=False,
        )
        runtime = HoundRuntime(settings)
        result["environment"]["geolocation"] = runtime.geo_description()
        with TestClient(create_app(settings, runtime)) as client:
            # 2. processing at several batch sizes ---------------------------------------
            processing = []
            for batch_size, count in samples.items():
                events = replay(count)
                durations: list[float] = []
                started = time.perf_counter()
                for offset in range(0, len(events), batch_size):
                    batch_started = time.perf_counter()
                    runtime.processor.process_batch(events[offset : offset + batch_size])
                    durations.append((time.perf_counter() - batch_started) * 1000)
                elapsed = time.perf_counter() - started
                latency = summarize_latency(durations)
                processing.append(
                    {
                        "batch_size": batch_size,
                        "events": len(events),
                        "events_per_s": round(len(events) / elapsed),
                        "batch_p50_ms": latency.p50_ms,
                        "batch_p95_ms": latency.p95_ms,
                    }
                )
            result["processing"] = processing

            # 3. fill to --rows, then time the API ---------------------------------------
            stored = client.get("/api/stats").json()["total_events"]
            fill_started = time.perf_counter()
            filled = 0
            while stored < rows:
                before = runtime.processor.stats().processed
                runtime.processor.process_batch(replay(min(500, rows - stored)))
                gained = runtime.processor.stats().processed - before
                if gained == 0 and runtime.processor.stats().failed:
                    raise SystemExit("processing failed while filling the database")
                stored += gained
                filled += gained
            fill_s = time.perf_counter() - fill_started
            result["fill"] = {
                "rows": stored,
                "events_per_s": round(filled / fill_s) if filled and fill_s else None,
            }
            sample_domain = next((e.domain for e in pool if e.domain), "example")[:4]
            endpoints = {
                "/api/stats": "/api/stats",
                "/api/stats/countries": "/api/stats/countries",
                "/api/events?limit=50": "/api/events?limit=50",
                "/api/events?limit=50&domain=...": f"/api/events?limit=50&domain={sample_domain}",
                "/api/events?limit=50&min_risk_level=suspicious": "/api/events?limit=50&min_risk_level=suspicious",
                "/api/devices?sort=risk": "/api/devices?sort=risk&limit=100",
                "/api/metrics": "/api/metrics",
            }
            queries = {}
            for label, path in endpoints.items():

                def call(path: str = path) -> None:
                    response = client.get(path)
                    if response.status_code != 200:
                        raise SystemExit(f"{path} returned {response.status_code}")

                queries[label] = timed_ms(call, repeat)
            result["api_ms"] = queries
            # Fold the write-ahead log into the main file first, so bytes/event is not inflated
            # by WAL pages (this is the benchmark's own temporary database).
            with runtime.database.engine.connect() as connection:
                connection.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
            storage = client.get("/api/metrics").json()["storage"]
            database_bytes = (storage["database_bytes"] or 0) + (storage["wal_bytes"] or 0)

        result["storage"] = {
            "database_and_wal_bytes": database_bytes,
            "bytes_per_event": round(database_bytes / stored) if stored else None,
        }
    result["memory"] = {"peak_rss_mib": peak_rss_mib()}

    best = max(entry["events_per_s"] for entry in result["processing"])
    stats_ms = result["api_ms"]["/api/stats"]
    result["checks"] = [
        {
            "name": "processing headroom over a busy home network",
            "value": round(best / BUSY_HOME_EVENTS_PER_SECOND, 1),
            "unit": "x",
            "ok": best >= BUSY_HOME_EVENTS_PER_SECOND,
        },
        {
            "name": f"/api/stats below the {STATS_TRIGGER_MS:.0f} ms optimisation trigger",
            "value": stats_ms,
            "unit": "ms",
            "ok": stats_ms < STATS_TRIGGER_MS,
        },
    ]
    return result


def render(result: dict[str, Any]) -> str:
    env, capture = result["environment"], result["capture"]
    lines = [
        f"Hound {env['hound']} benchmark - Python {env['python']}, {env['platform']}, {env['cpus']} CPUs",
        f"Geolocation: {env['geolocation']}",
        "",
        f"Scapy dissection          {capture['dissect_packets_per_s']:>9,} packets/s  ({capture['packets']:,} frames)",
        f"Parsing to events         {capture['parse_packets_per_s']:>9,} packets/s",
    ]
    for entry in result["processing"]:
        lines.append(
            f"Processing, batch {entry['batch_size']:>3}     {entry['events_per_s']:>9,} events/s   "
            f"batch p50 {entry['batch_p50_ms']} ms, p95 {entry['batch_p95_ms']} ms"
        )
    fill = result["fill"]
    lines += ["", f"API latency at {fill['rows']:,} stored events (in-process, incl. JSON):"]
    for label, ms in result["api_ms"].items():
        lines.append(f"  {label:<48} {ms:>8.1f} ms")
    storage, memory = result["storage"], result["memory"]
    lines += [
        "",
        f"Storage                   {storage['bytes_per_event']} bytes/event "
        f"({storage['database_and_wal_bytes'] / 2**20:.1f} MiB incl. WAL)",
        f"Peak memory               {memory['peak_rss_mib'] or 'n/a'} MiB",
        "",
    ]
    for check in result["checks"]:
        lines.append(f"[{' OK ' if check['ok'] else 'NOTE'}] {check['name']}: {check['value']} {check['unit']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--rows", type=int, default=50_000, help="events stored before timing the API")
    parser.add_argument("--packets", type=int, default=5_000, help="demo frames dissected and parsed")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--repeat", type=int, default=10, help="calls per API endpoint")
    parser.add_argument("--quick", action="store_true", help="tiny sizes, for tests (numbers not meaningful)")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args(argv)
    samples = dict(PROCESSING_SAMPLE)
    if args.quick:
        args.rows, args.packets, args.repeat = 1_500, 400, 2
        samples = {1: 50, 50: 300, 200: 600}
    if args.rows < 1 or args.packets < 1 or args.repeat < 1:
        parser.error("--rows, --packets and --repeat must be positive")
    result = run(args.rows, args.packets, args.seed, args.repeat, samples)
    print(json.dumps(result, indent=2) if args.json else render(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
