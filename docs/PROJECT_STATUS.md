# Hound — Project Status

> Answers: *where are we, what works, what is missing, what blocks us, what is next.*
> Update this file at the end of every task. Plan: [`ROADMAP.md`](ROADMAP.md) ·
> Architecture: [`ARCHITECTURE.md`](ARCHITECTURE.md) · Decisions: [`DECISIONS.md`](DECISIONS.md)

```text
Last updated:      2026-09-28 (session 5: task 14.4b dashboard tests)
Current milestone: M6 — Production-quality local build   (M0–M5 reached, M2 on Linux only)
Current phase:     Phase 14 — Release hardening (14.1 done for Windows, 14.2 and 14.4 done)
Current task:      none in progress
Next task:         14.3a Lock file + CHANGELOG (the unblocked half of 14.3)
Overall state:     Working system with a versioned, upgrade-safe database, an end-to-end
                   tested capture daemon and an automatically tested dashboard (92 % line
                   coverage). Linux: 245 tests pass (Py 3.11 + 3.13). Owner's Windows laptop:
                   last run 231 + 2 expected skips (before 14.4b). Not yet exercised: live
                   capture on Windows, macOS, CI.
```

## 1. Baseline assessment

```text
AREA            STATUS          NOTES
------------------------------------------------------------------------------------------
Architecture    VERIFIED        Layered modular monolith; module-import check clean; ADR-001..018
Ingestion       VERIFIED*       Parser/capture/daemon/demo; live capture on Linux lo only.
                                Daemon split mode tested end to end (96%); parser fuzzed
Event model     VERIFIED        Frozen Pydantic NetworkEvent; used by all sources
Backend         VERIFIED        Worker thread, retention, error isolation, broadcaster
Database        VERIFIED        WAL, indexes, retention; schema v1 in PRAGMA user_version with
                                ordered atomic migrations (ADR-018); owner-only files on POSIX
Enrichment      VERIFIED        Blocklist (suffix matching), simulated geo, DNS correlation
Risk engine     VERIFIED*       13 deterministic signals; not yet tuned on real traffic
Frontend        VERIFIED        12 page-level tests against the real API (dashboard.py 96 %,
                                components.py 91 %); visuals still checked manually
Testing         VERIFIED*       245 tests, 92% line coverage; all pass on Linux (Py 3.11 + 3.13);
                                Windows last confirmed at 231 (before 14.4b); CI never run
Configuration   VERIFIED        HOUND_* env/.env/CLI, validated; .env.example parses
Security        FUNCTIONAL      Least privilege, loopback, Host/Origin checks, token ingest;
                                S-3 fuzz, S-6 documented, S-8 done; daemon ignores proxies
Documentation   FUNCTIONAL      README covers upgrades/refusals; Windows guidance owner-checked
Packaging       IN_PROGRESS     CI workflow + requirements-dev.txt; no lock file, LICENSE,
                                CHANGELOG; version says 1.0.0 before any release
```
`*` = verified with the caveat in the notes.

## 2. Validation log

| Date | Check | Platform | Result |
|---|---|---|---|
| 2026-09-28 s5 | `ruff check`; `ruff format --check` | Py 3.11 | clean / 81 files formatted |
| 2026-09-28 s5 | `mypy --platform {linux,win32,darwin}` | mypy 1.20.2 and 2.3.1 | clean ×6 (59 files) |
| 2026-09-28 s5 | `pytest` | Py 3.11.15 / Py 3.13.7 | 245 passed / 245 passed (~18 s / ~19 s); coverage 92 % (`dashboard.py` 0 → 96 %, `components.py` 0 → 91 %) |
| 2026-09-28 s5 | `tests/test_dashboard.py` repeated 3× with `-W error::RuntimeWarning` | Py 3.11 | 12/12 each run (~9.7 s) |
| 2026-09-28 s5 | Mutation check: 9 deliberate dashboard breakages (error banner, feed cap, live filter, live order, pause, polling fallback, include-local, dialog replacement, spinner on error) | Py 3.11 | each caught; original restored (diff clean) |
| 2026-09-28 s5 | `scripts/smoke_test.py` | Py 3.11 | all checks passed |
| 2026-09-28 s4 | `python -m compileall`; `ruff check`; `ruff format --check` | Py 3.11 / 3.13 | pass / clean / 80 files formatted |
| 2026-09-28 s4 | `mypy --platform {linux,win32,darwin}` | mypy 1.20.2 and 2.3.1 | clean ×6 (59 files) |
| 2026-09-28 s4 | `pytest` | Py 3.11.15 / Py 3.13.7 | 233 passed / 233 passed; coverage 83 % (`daemon.py` 96 %, `forwarder.py` 93 %) |
| 2026-09-28 s4 | `tests/test_daemon.py` repeated 5× | Py 3.11 | 7/7 each run (~4.5 s); no flakiness seen |
| 2026-09-28 s4 | Proxy test before the fix (fresh process, `HTTP(S)_PROXY` = dead proxy, no `NO_PROXY`) | Py 3.11 | **failed** — daemon delivered nothing; after fix: pass |
| 2026-09-28 s4 | Mutation check: parser error handling / self-traffic filter / proxy bypass removed | Py 3.11 | each caught (the first in-process proxy test missed it → rewritten as subprocess test) |
| 2026-09-28 s4 | `scripts/smoke_test.py` | Py 3.11 / Py 3.13 | 12/12 / 12/12 |
| 2026-09-28 s3 | `python -m compileall -q app tests scripts run.py` | Linux, Py 3.11.15 | pass |
| 2026-09-28 s3 | `ruff check …`; `ruff format --check …` | Py 3.11 / 3.13 | clean / 79 files formatted |
| 2026-09-28 s3 | `mypy --platform {linux,win32,darwin}` | mypy 1.20.2 (Py 3.11) and 2.3.1 (Py 3.13) | clean ×6 (59 files) |
| 2026-09-28 s3 | `pytest` | Py 3.11.15 / Py 3.13.7 | 225 passed / 225 passed; coverage 80 %, `migrations.py` 100 % |
| 2026-09-28 s3 | Mutation check of `tests/test_migrations.py` (5 deliberate breakages: no rollback, no newer-DB check, no adoption check, ORM change without migration, no chmod) | Py 3.11 | each caught (1–3 tests fail); originals restored, 15/15 pass |
| 2026-09-28 s3 | **Real upgrade:** previous release (no versioning) ran demo mode → DB with 385 events, 6 devices, `user_version` 0, mode 644; new code started on it | Py 3.11 | adopted as v1; API shows 385 events / 6 devices; DB, WAL, SHM now 600 |
| 2026-09-28 s3 | Server start on a DB with `user_version` 5 | Py 3.11 | refused: 1 clear error line, exit code 2, file untouched (before the CLI pre-flight: ~60-line traceback, exit 3) |
| 2026-09-28 s3 | `scripts/smoke_test.py` | Py 3.11 / Py 3.13 | 12/12 / 12/12 |
| 2026-09-28 s3 | OpenAPI schema vs previous release | Py 3.11 | identical |
| 2026-09-28 s2 | `pytest` + smoke test — **owner's Windows laptop** (209 tests, before 14.2) | Windows | all green (owner report) |
| 2026-09-28 s2 | First Windows run: 208/209, failure = test depending on host routing; fixed + guarded | Windows / Linux | see ROADMAP 14.1 |
| 2026-09-28 s2 | `pip-audit -r requirements.txt`; `actionlint` on the CI workflow | Py 3.13 | no vulnerabilities; no issues |
| 2026-09-28 s1 | Live capture, split mode (server as `nobody`, daemon root, `lo`) | Linux | DNS + SYN captured; blocklist hit flagged |
| 2026-09-28 s1 | Throughput/latency benchmark (ROADMAP §I) | Linux sandbox | ≈ 5 400 events/s; `/api/stats` 71 ms @ 250 k rows |
| 2026-09-28 s3 | `pytest` with 14.2 — **owner's Windows laptop** | Windows | 223 passed, 2 skipped (the two POSIX file-mode tests; expected) |
| 2026-09-28 s3 | Smoke test with 14.2 on Windows | Windows | owner replied "good" after the request; output not shared |
| 2026-09-28 s4 | `pytest` with 14.4a — **owner's Windows laptop** | Windows | 231 passed, 2 skipped (POSIX file-mode tests; expected) in 12.7 s |
| — | 14.4b dashboard tests on Windows | — | **not run yet** (expected: 243 passed, 2 skipped) |
| — | `.github/workflows/ci.yml` on GitHub; live capture on Windows; anything on macOS | — | **not run** |

## 3. Completed
- Phases 0–13 of the original plan (ROADMAP §F).
- 14.1 Cross-platform verification & CI — done for Windows (session 2; details in ROADMAP).
- **14.2 Schema versioning & migrations (session 3):**
  - `app/database/migrations.py` (ADR-018): version in `PRAGMA user_version`; frozen v1
    baseline DDL; ordered steps, each atomic with its version bump (`BEGIN IMMEDIATE`,
    version read inside the transaction).
  - Pre-versioning databases adopted as v1 only on an exact structure match; newer or
    foreign databases refused without modification.
  - `Database.initialize()` uses the migration runner for SQLite (`create_all` remains only
    for untested non-SQLite URLs) and exposes `schema_version`.
  - S-8: new data directory `0700`; DB, `-wal`, `-shm` tightened to `0600` on POSIX.
  - CLI pre-flight: the database is checked before the web server starts, so refusals are
    a single clear error line with exit code 2.
  - `tests/test_migrations.py` (16 tests), including a drift guard: the migrated schema
    must equal the ORM models.
  - README: "Database and upgrades", two troubleshooting rows, file-permission note.
- **14.4a Capture daemon + parser fuzzing (session 4):**
  - `tests/test_daemon.py` (7 tests): split mode end to end without privileges — fake
    sniffer → real parser → `CaptureDaemon` → forwarder → live uvicorn server → pipeline →
    SQLite; self-traffic filtering; exit codes 2 and 3; API down then recovering;
    statistics logging; `capture` without a token; proxy settings.
  - **Bug fixed:** daemon → API HTTP honoured `HTTP(S)_PROXY`, so behind a proxy nothing
    was delivered. Now a proxy-free opener (ADR-016 revisited; README §11 notes it).
  - Parser fuzz test (S-3): 2 400 random/mutated/truncated frames, deterministic.
  - `CaptureDaemon.stop()` (public, thread-safe) for tests and future service wrappers.
- **14.4b Dashboard tests (session 5):**
  - `tests/test_dashboard.py` (12 tests) using NiceGUI's user simulation
    (`nicegui.testing.user_simulation`, part of NiceGUI — no new dependency, no browser,
    no sockets). The page talks to the **real** API in-process (`httpx.ASGITransport`),
    so the tests also guard the dashboard ↔ API contract.
  - Covered: rendering of KPIs/feed/devices/countries, live events batched into the feed
    (order, 200-row cap), risk filter for snapshot + live events, pause/resume,
    WebSocket-down polling fallback, event and device dialogs (incl. empty states),
    unreachable API (banner, "Offline", notifications, recovery), pipeline-state banners,
    include-local switch, and `mount_dashboard` (served page + once-per-process guard, in
    a subprocess because `ui.run_with` changes process-wide state).
  - `dashboard.py`: two `.mark()` handles on the clickable tables (no behaviour change).
  - No product bug found. Found and neutralised a test-only stall: on Python 3.11
    NiceGUI's outbox can swallow its teardown cancellation (an `asyncio.wait_for` race
    fixed in 3.12), costing 2 s per test; the harness lets the outbox go idle first.

## 4. In progress
- Nothing.

## 5. Next (in order — only the first is "the next task")
1. **14.3a Lock file + CHANGELOG.** Generate a pinned lock file for runtime + dev tools,
   use it in CI, and start `CHANGELOG.md` from the work already recorded here. Unblocked
   (LICENSE and the version label stay with the owner → 14.3b).
2. 14.3b LICENSE + version label, once the owner decides.
3. When the project is on GitHub: confirm the CI run (macOS coverage).

## 6. Blocked / needs owner input
| Item | Needed | Blocks |
|---|---|---|
| License | Choose a license (e.g. MIT, Apache-2.0, GPL-3.0, or "all rights reserved") | 14.3b |
| Version label | Keep `1.0.0` or re-label `0.9.0` until M6 | 14.3b |
| Windows re-run | `pytest` on the laptop with this build (expect 243 passed, 2 skipped) | confirming 14.4b on Windows |
| CI on GitHub | Push the project to a GitHub repository | macOS verification; automatic checks on every change |
| Windows live capture | Install Npcap, then `python run.py capture -i "Wi-Fi"` from an Administrator shell with the server running | M2 on Windows |
| Field trial | A monitoring position that sees household traffic (router, mirror port or DNS host) | M7 |

## 7. Technical debt

**Critical**
- None open. (Schema versioning — the previous critical item — was resolved by 14.2.)

**Important**
- CI workflow never executed and macOS never tested → first push to GitHub.
- Live capture never run on Windows (the owner's platform) → owner test with Npcap.
- No lock file. Runtime installs and dev tools resolve to the newest compatible
  versions; mypy 2.x already changed results once → 14.3a (next).

**Nice-to-have**
- A device's risk resets only after its window expires *and* it sends a new event, so a
  silent device keeps its last level. The UI caption doesn't explain this; revisit in 16.
- `devices` rows are never expired; counters are lifetime totals even after event
  retention prunes old events → 17.
- No backup command yet; the README advises copying `data/` before upgrades → 17.
- `/api/stats` uses `COUNT(*)` scans (71 ms at the 250 k cap) → only if metrics show need.
- The forwarder opens one TCP connection per batch (ADR-016); fine at the current cadence.
- `Database.initialize()` runs twice at server start (CLI pre-flight + lifespan); the second
  run is a no-op version check. Harmless; revisit only if start-up time matters.
- `cli.py` 74 % and `logging_config.py` 40 % coverage.
- The test suite now takes ~18 s (was ~10 s): dashboard tests ~9.7 s, daemon tests ~4.5 s.
  Acceptable; if it keeps growing, add an opt-in `slow` marker for the UI/daemon files.
- The dashboard tests call a few private methods (`_load_stats`, `_stats_tick`,
  `_render_pipeline`) to avoid waiting on 2–5 s UI timers. Cheap to maintain; if the page
  is refactored, prefer injectable intervals.
- The dashboard tests depend on `nicegui.testing.user_simulation` (NiceGUI ≥ 2.x API).
  A NiceGUI major upgrade may need harness changes; the lock file (14.3a) pins it.

**Future**
- Package named `app` (ADR-011) → rename before publishing a wheel (Phase 21).
- Risk-engine state is in memory and resets on restart (windows ≤ minutes; by design).
- Migrations are hand-written SQL; SQLite needs the table-rebuild pattern for most column
  changes (ADR-018).

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
- A database written by a newer Hound cannot be opened by an older one (by design; no
  downgrades).

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
