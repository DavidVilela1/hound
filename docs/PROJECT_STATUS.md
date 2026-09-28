# Hound — Project Status

> Answers: *where are we, what works, what is missing, what blocks us, what is next.*
> Update this file at the end of every task. Plan: [`ROADMAP.md`](ROADMAP.md) ·
> Architecture: [`ARCHITECTURE.md`](ARCHITECTURE.md) · Decisions: [`DECISIONS.md`](DECISIONS.md)

```text
Last updated:      2026-09-28 (session 2: task 14.1 closed for Windows)
Current milestone: M6 — Production-quality local build   (M0–M5 reached, M2 on Linux only)
Current phase:     Phase 14 — Release hardening
Current task:      none in progress
Next task:         14.2 Schema versioning & migrations
Overall state:     Working system. Test suite and demo smoke test pass on Linux (Py 3.11 +
                   3.13) and on the owner's Windows laptop. Not yet exercised: live capture
                   on Windows, anything on macOS, the GitHub CI workflow itself.
```

## 1. Baseline assessment

```text
AREA            STATUS          NOTES
------------------------------------------------------------------------------------------
Architecture    VERIFIED        Layered modular monolith; module-import check clean; ADR-001..017
Ingestion       VERIFIED*       Parser/capture/daemon/demo; live capture on Linux lo only.
                                Accepts Windows NPF interface names. Daemon 0% automated coverage
Event model     VERIFIED        Frozen Pydantic NetworkEvent; used by all sources
Backend         VERIFIED        Worker thread, retention, error isolation, broadcaster
Database        NEEDS_REFACTOR  Works (WAL, indexes, retention) but has no schema versioning
Enrichment      VERIFIED        Blocklist (suffix matching), simulated geo, DNS correlation
Risk engine     VERIFIED*       13 deterministic signals; not yet tuned on real traffic
Frontend        FUNCTIONAL      All views work (manual Playwright check); 0% automated tests
Testing         FUNCTIONAL      209 tests, 79% line coverage; all pass on Linux (Py 3.11 + 3.13)
                                and Windows (owner); suite isolated from host routing (conftest)
Configuration   VERIFIED        HOUND_* env/.env/CLI, validated; .env.example parses
Security        FUNCTIONAL      Least privilege, loopback, Host/Origin checks, token ingest;
                                Windows token protection documented (S-6); data/ modes open (S-8)
Documentation   FUNCTIONAL      README Windows guidance corrected; not yet confirmed on Windows
Packaging       IN_PROGRESS     CI workflow + requirements-dev.txt added; no lock file, LICENSE,
                                CHANGELOG; version says 1.0.0 before any release
```
`*` = verified with the caveat in the notes.

## 2. Validation log

| Date | Check | Platform | Result |
|---|---|---|---|
| 2026-09-28 s2 | `python -m compileall -q app tests scripts run.py` | Linux, Py 3.11.15 | pass |
| 2026-09-28 s2 | `ruff check app tests scripts run.py`; `ruff format --check` | Py 3.11 / 3.13 | clean / 77 files formatted |
| 2026-09-28 s2 | `mypy --platform {linux,win32,darwin}` | mypy 1.20.2 (Py 3.11) and 2.3.1 (Py 3.13) | clean ×6 (first 2.3.1 run found 5 errors; fixed) |
| 2026-09-28 s2 | `pytest` | Py 3.11.15 / Py 3.13.7 (fresh venv from `requirements-dev.txt`) | 209 passed / 209 passed |
| 2026-09-28 s2 | `scripts/smoke_test.py` | Py 3.11 / Py 3.13 | 12/12 / 12/12 |
| 2026-09-28 s2 | `pip-audit -r requirements.txt` | Py 3.13 | no known vulnerabilities |
| 2026-09-28 s2 | `actionlint .github/workflows/ci.yml` (v1.7.12) | — | no issues |
| 2026-09-28 s2 | OpenAPI schema before vs after the `Field(default=…)` change | Py 3.11 | byte-identical |
| 2026-09-28 s2 | Dashboard via Playwright (live feed, event + device dialogs) | Linux Chromium | pass, no console/server errors |
| 2026-09-28 s1 | Live capture, split mode (server as `nobody`, daemon root, `lo`) | Linux | DNS + SYN captured; blocklist hit flagged |
| 2026-09-28 s1 | Live capture, all-in-one; unprivileged → clear error, server stays up | Linux | pass |
| 2026-09-28 s1 | Throughput/latency benchmark (ROADMAP §I) | Linux sandbox | ≈ 5 400 events/s; `/api/stats` 71 ms @ 250 k rows |
| 2026-09-28 s2 | `pytest` — **owner's Windows laptop** | Windows, owner's venv | **208 passed, 1 failed**: `test_ipv6_dns_query` — a bare `Ether()` made Scapy look up the IPv6 route, which resolved to the unknown "Microsoft KM-TEST Loopback Adapter". Test-only; app code never builds packets without explicit MACs |
| 2026-09-28 s2 | Reproduction on Linux with every route pointed at that adapter | Py 3.11 | 13 failed (all bare-`Ether()` tests), 196 passed — reproduced |
| 2026-09-28 s2 | After fix: explicit MACs in tests + session-wide routing guard in `tests/conftest.py` | Py 3.11 / 3.13 | 209 passed / 209 passed; a deliberate bare-`Ether()` probe test fails under the guard as intended |
| — | `.github/workflows/ci.yml` executed on GitHub | Windows / macOS / Linux | **not run** (no repository yet) |
| 2026-09-28 s2 | `pytest` + `python scripts/smoke_test.py` re-run — **owner's Windows laptop** | Windows, owner's venv | all green (owner report) |
| — | Live capture on Windows (needs Npcap + Administrator); anything on macOS | — | **not run** |

## 3. Completed
- Phases 0–13 of the original plan (ROADMAP §F).
- Fixes from live testing: capture-daemon feedback loop on loopback, duplicate frames on
  Linux `lo` (ADR-014).
- Planning baseline: `docs/ARCHITECTURE.md`, `docs/DECISIONS.md`, `docs/ROADMAP.md`, this file.
- **14.1 implementation (session 2):**
  - `.github/workflows/ci.yml`: Linux/Windows/macOS × Py 3.11/3.13 running compileall,
    ruff, mypy, pytest and the smoke test, plus a pip-audit job (ADR-017).
  - `requirements-dev.txt` (ruff, mypy, pip-audit); lint/type settings in `pyproject.toml`.
  - Windows path assertions in `tests/test_config.py` fixed.
  - `resolve_interface()` accepts Scapy's Windows `network_name` (`\Device\NPF_{…}`); new test.
  - `_is_privileged()` detects an elevated Administrator on Windows (always False before); new test.
  - README: §9 Windows interface naming corrected; §12 ingest-token protection on Windows;
    §15 dev tools and CI; §16 and §18 cloud-sync (OneDrive) warnings.
  - `scripts/smoke_test.py` tolerates Windows file-handle delays when cleaning up.
  - Compatibility with mypy 2.x: Pydantic fields use explicit `default=`; two small type fixes.
  - First Windows run (owner): the one failure was a test relying on host routing. All test
    packets now use explicit MACs (`tests.conftest.eth()`), and an autouse session fixture
    points every Scapy route lookup at a non-existent adapter, so the whole class of
    "works on my machine" packet tests now fails everywhere.

## 4. In progress
- Nothing. **14.1 is closed for Windows** (owner re-run: pytest and smoke test all green).
  Residual, tracked below: the CI workflow has never executed (no GitHub repository), so
  macOS is untested; live capture on Windows is untested.

## 5. Next (in order — only the first is "the next task")
1. **14.2 Schema versioning & migrations.** Record the schema version in
   `PRAGMA user_version` and run ordered migration steps at start-up. Existing databases
   are adopted as version 1, and the app refuses to start on a database newer than the
   code. Unblocked, and a prerequisite for every future schema change.
2. 14.3 Reproducible installs & release hygiene (lock file, LICENSE, CHANGELOG, version label).
3. 14.4 Automated coverage for the daemon and dashboard.
4. When the project is on GitHub: confirm the CI run (macOS coverage).

## 6. Blocked / needs owner input
| Item | Needed | Blocks |
|---|---|---|
| CI on GitHub | Push the project to a GitHub repository | macOS verification; automatic checks on every change |
| Windows live capture | Install Npcap, then `python run.py capture -i "Wi-Fi"` from an Administrator shell with the server running | M2 on Windows |
| License | Choose a license (e.g. MIT, Apache-2.0, GPL-3.0, or "all rights reserved") | 14.3 |
| Version label | Keep `1.0.0` or re-label `0.9.0` until M6 | 14.3 |
| Field trial | A monitoring position that sees household traffic (router, mirror port or DNS host) | M7 |

## 7. Technical debt

**Critical** (must be fixed before the thing it blocks)
- No schema versioning (ADR-015). *Why accepted:* first release, no user data.
  *Consequence:* any schema change breaks existing DBs. *Revisit:* 14.2 (next task).

**Important**
- CI workflow never executed and macOS never tested → first push to GitHub.
- Live capture never run on Windows (the owner's platform) → owner test with Npcap.
- `dashboard.py`/`components.py` and `daemon.py` have 0 % automated coverage → 14.4.
- No lock file. Runtime installs and dev tools resolve to the newest compatible
  versions; mypy 2.x already changed results once → 14.3.
- `data/` and the DB file use default permissions (browsing metadata) → 14.2 (S-8).

**Nice-to-have**
- A device's risk resets only after its window expires *and* it sends a new event, so a
  silent device keeps its last level. The UI caption doesn't explain this; revisit in 16.
- `devices` rows are never expired; counters are lifetime totals even after event
  retention prunes old events → 17.
- `/api/stats` uses `COUNT(*)` scans (71 ms at the 250 k cap) → only if metrics show need.
- The forwarder opens one TCP connection per batch (ADR-016); fine at the current cadence.
- `cli.py` 51 % and `logging_config.py` 40 % coverage.

**Future**
- Package named `app` (ADR-011) → rename before publishing a wheel (Phase 21).
- Risk-engine state is in memory and resets on restart (windows ≤ minutes; by design).

## 8. Known limitations (product)
- Country data is **simulated** (ADR-008).
- Only traffic visible to the capture interface is seen (switched/Wi-Fi networks).
- Default BPF catches IPv4 SYNs only; the IPv6 clause is documented, not default.
- Encrypted DNS (DoH/DoT/DoQ) hides domain names.
- Risk levels are heuristics, not malware detection; not yet tuned on real traffic.
- Devices are identified by IP address.
- Single process, single user, localhost only; no dashboard authentication.
- Live capture verified on Linux only.
- In a cloud-synced folder (OneDrive etc.) the database and ingest token are uploaded, and
  sync can lock SQLite; documented in the README with workarounds.

## 9. How to verify this file is still true
```bash
pip install -r requirements-dev.txt
python -m compileall -q app tests scripts run.py
ruff check app tests scripts run.py
mypy
pytest
python scripts/smoke_test.py
```
If any result differs from §2, update this file before starting new work.
