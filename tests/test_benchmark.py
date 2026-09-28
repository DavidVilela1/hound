"""``scripts/benchmark.py`` keeps working (quick mode; the numbers themselves are not asserted)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "benchmark.py"


def run_script(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=ROOT, capture_output=True, text=True, timeout=180)


def listing(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.iterdir()) if folder.is_dir() else []


def test_quick_run_reports_every_stage_and_touches_no_project_data() -> None:
    data_before = listing(ROOT / "data")
    result = run_script("--quick", "--json")
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)

    assert report["environment"]["rows"] == 1_500
    assert report["capture"]["events_parsed"] > 0 and report["capture"]["dissect_packets_per_s"] > 0
    assert [entry["batch_size"] for entry in report["processing"]] == [1, 50, 200]
    assert all(entry["events_per_s"] > 0 and entry["batch_p95_ms"] > 0 for entry in report["processing"])
    assert report["fill"]["rows"] >= 1_500
    assert set(report["api_ms"]) >= {"/api/stats", "/api/stats/countries", "/api/events?limit=50", "/api/metrics"}
    assert all(ms > 0 for ms in report["api_ms"].values())
    assert report["storage"]["bytes_per_event"] > 0
    assert {check["name"] for check in report["checks"]} and all("ok" in c for c in report["checks"])
    assert listing(ROOT / "data") == data_before  # temporary database only


def test_text_report_and_argument_validation() -> None:
    text = run_script("--quick")
    assert text.returncode == 0, text.stderr
    assert "Processing, batch 200" in text.stdout and "/api/stats" in text.stdout
    assert text.stdout.isascii()  # prints on any console encoding

    bad = run_script("--rows", "0")
    assert bad.returncode == 2 and "must be positive" in bad.stderr
