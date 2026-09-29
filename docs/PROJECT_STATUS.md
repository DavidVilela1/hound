# Hound — Project Status

> Answers: *where are we, what works, what is missing, what blocks us, what is next.*
> Update this file at the end of every task. Plan: [`ROADMAP.md`](ROADMAP.md) ·
> Architecture: [`ARCHITECTURE.md`](ARCHITECTURE.md) · Decisions: [`DECISIONS.md`](DECISIONS.md)

```text
Last updated:      2026-09-29 (session 13: task 17a backup + restore)
Current milestone: M6 — Production-quality local build   (M0–M5 reached; M2 on Linux + Windows)
Current phase:     Phase 16 — engineering part done (16a–16c); 16d field trial needs the
                   owner. Phase 17 (data lifecycle) starts meanwhile. Phase 14's last
                   items (licence, version label) wait on the owner
Current task:      none in progress
Next task:         17b export events and devices (CSV/JSON)
Overall state:     Working system with a versioned, upgrade-safe database, an end-to-end
                   tested capture daemon, an automatically tested dashboard, reproducible
                   hash-checked installs, a read-only `doctor` setup check and per-stage
                   loss metrics (`/api/metrics`), a reproducible benchmark and an
                   owner allowlist, a risk settings file, reload without restart and
                   backup/restore (94 % line coverage). Linux: 380 tests pass
                   (Py 3.11 + 3.13, from the lock). Owner: Windows 292 passed + 3 expected
                   skips (before 15b); CI green on Linux/Windows/macOS (before 15b); live
                   capture works on Windows (split mode, Npcap, "Wi-Fi").
```

## 1. Baseline assessment

```text
AREA            STATUS          NOTES
------------------------------------------------------------------------------------------
Architecture    VERIFIED        Layered modular monolith; module-import check clean; ADR-001..019
Ingestion       VERIFIED*       Parser/capture/daemon/demo; live capture on Linux (lo) and on
                                Windows (Wi-Fi, owner report).
                                Daemon split mode tested end to end (96%); parser fuzzed
Event model     VERIFIED        Frozen Pydantic NetworkEvent; used by all sources
Backend         VERIFIED        Worker thread, retention, error isolation, broadcaster
Database        VERIFIED        WAL, indexes, retention; schema v1 in PRAGMA user_version with
                                ordered atomic migrations (ADR-018); owner-only files on POSIX
Enrichment      VERIFIED        Blocklist (suffix matching), simulated geo, DNS correlation
Risk engine     VERIFIED*       13 deterministic signals; not yet tuned on real traffic
Frontend        VERIFIED        12 page-level tests against the real API (dashboard.py 96 %,
                                components.py 91 %); visuals still checked manually
Testing         VERIFIED*       380 tests, 94% line coverage; all pass on Linux (Py 3.11 + 3.13);
                                Windows 292 + 3 expected skips (owner); CI green (owner report)
Configuration   VERIFIED        HOUND_* env/.env/CLI, validated; .env.example parses
Security        FUNCTIONAL      Least privilege, loopback, Host/Origin checks, token ingest;
                                S-3 fuzz, S-6 documented, S-8 done; daemon ignores proxies
Documentation   FUNCTIONAL      README covers upgrades/refusals; Windows guidance owner-checked
Packaging       FUNCTIONAL      Hash-checked universal locks (ADR-019), CHANGELOG, CI installs
                                the lock; missing: LICENSE, version label (owner) → 14.3b
```
`*` = verified with the caveat in the notes.

## 2. Validation log

| Date | Check | Platform | Result |
|---|---|---|---|
| 2026-09-28 s7 | `pytest` with 15a — **owner's Windows laptop** | Windows | **1 failed**, 283 passed, 3 skipped: `test_database_path_with_spaces_and_special_characters` — "unable to open database file" |
| 2026-09-28 s7 | Diagnosis of that failure | Linux | real bug in `Settings.resolved_database_url` (existing since the first build): the path was put into the URL unencoded, so `%20` in a folder name was decoded to a space (Windows strips trailing spaces → cannot open; Linux silently used a *different* folder, so the Linux run passed) and `?` truncated the path |
| 2026-09-28 s7 | After the fix: `pytest` (dev env / 3.11 lock / 3.13 lock); ruff; mypy ×3 platforms; smoke | Linux | 299 / 299 / 299 passed; clean; smoke all passed |
| 2026-09-28 s7 | Old URL code against the new tests | Py 3.11 | exactly the `%20` and `?` cases fail (5 tests); fixed code: all pass |
| 2026-09-28 s7 | Real demo server started from a copy of the project in `…/Ambiente de Trabalho #1 %20 what?/hound` | Linux | database created in that folder's `data/`; 8 events served; `doctor`: running server found, schema v1 current, 0 problems |
| 2026-09-28 s7 | `pytest` (dev env / fresh lock venvs) | Py 3.11.15 / 3.11 lock / 3.13.7 lock | 287 / 287 / 287 passed; coverage 93 % (`doctor.py` 93 %) |
| 2026-09-28 s7 | `ruff check`, `ruff format --check`, `mypy` (+ `--platform win32/darwin`), compileall, smoke test | both lock venvs | clean ×all (61 source files, 85 formatted); smoke all passed |
| 2026-09-28 s7 | `python run.py doctor` before and while a real demo server ran (lock venv 3.13, temp data dir) | Linux | 0 problems; port check identified "Hound 1.0.0 is running"; database "schema v1, current"; token OK; `-i lo` found; token/DB bytes unchanged by the check |
| 2026-09-28 s7 | Read-only probe: plain `mode=ro` on a closed WAL database | SQLite (Py 3.11) | **created** `-wal` + `-shm` → switched to `immutable=1` when no WAL exists; verified nothing is created |
| 2026-09-28 s7 | Mutation check of `tests/test_doctor.py` (8 breakages: no immutable open, no Hound probe, adopt any legacy DB, no newer-schema check, no OneDrive marker, no token-permission check, exit code always 0, no version compare) | Py 3.11 | each caught; original restored |
| 2026-09-28 s7 | `doctor` wall time (warm) | Linux | 0.6–1.0 s |
| 2026-09-28 s6 | `uv pip compile … --only-binary :all:` against the locks for Windows x86-64, macOS x86-64 + arm64, Linux x86-64 × Py 3.11/3.12/3.13/3.14 | uv 0.8.17 | all 16 resolve: a wheel exists for every pin |
| 2026-09-28 s6 | Fresh venvs, `pip install -r requirements-dev.lock` (plain pip, hash mode), then compileall, ruff check + format, mypy, pytest, smoke test | Py 3.11.15 / Py 3.13.7 | `pip check` ok; all clean; 252 passed / 252 passed; smoke all passed |
| 2026-09-28 s6 | Fresh venv, `pip install -r requirements.lock` (runtime only, pip 24.0) then pytest + smoke | Py 3.11 | 252 passed; smoke all passed; ruff absent as intended |
| 2026-09-28 s6 | `pip-audit -r requirements{,-dev}.lock --require-hashes --disable-pip` | pip-audit 2.10.1 | no known vulnerabilities (both) |
| 2026-09-28 s6 | Mutation check of `tests/test_dependency_locks.py` (6 breakages: range raised, requirement added, dev pin drift, hashes removed, dev tool added, different generator flags) | Py 3.11 | each caught; files restored (cmp clean) |
| 2026-09-28 s6 | `actionlint` on the updated workflow | 1 file | no issues |
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
| 2026-09-28 s7 | `pytest` with 15a + URL fix — **owner's Windows laptop** | Windows | 292 passed, 3 skipped (POSIX file-mode tests; expected) |
| 2026-09-28 s7 | `python run.py doctor` — **owner's Windows laptop** (Py 3.13.7) | Windows | 0 problems, 2 warnings, both correct: Npcap not installed; data folder inside OneDrive. Packages match the lock; 48 interfaces, default "Wi-Fi"; DB schema v1 current; token OK; not Administrator (INFO) |
| 2026-09-28 s7 | **Live capture, split mode — owner's Windows laptop**: data moved out of OneDrive via `.env` (`C:\hound-data`), Npcap installed, server as normal user, `python run.py capture -i "Wi-Fi"` from an Administrator shell | Windows (Py 3.13.7) | owner: "working" (events appear in the dashboard). First attempt before starting the server: capture refused with the intended "No ingest token found … start the server first" message. Detailed counts not shared |
| 2026-09-29 s13 | `pytest` with the restore fix — **owner's Windows laptop** | Windows | 369 passed, 5 skipped (expected: 4 Linux-only folder-name cases are not generated on Windows; 5 POSIX file-mode skips). Output also showed "--- Logging error --- ValueError: I/O operation on closed file" |
| 2026-09-29 s13 | Diagnosis of the logging error | Linux | tests calling `cli.main` → `configure_logging()` replaced the root handlers with one bound to that test's captured stderr (`_io.FileIO name=8`), which pytest later closes; any later log line (e.g. a server thread shutting down) then fails. Reproduced deterministically by `tests/test_logging_isolation.py` (failed before the fix) |
| 2026-09-29 s13 | After an autouse conftest fixture that restores root/uvicorn/noisy-logger handlers, levels and propagation after every test | Linux | isolation tests 2/2; full suite 380 / 380 / 380 (dev, 3.11 lock, 3.13 lock), no "Logging error"; ruff/mypy clean. Windows re-run pending (expect 371 passed, 5 skipped) |
| 2026-09-29 s13 | `pytest` with 17a — **owner's Windows laptop** | Windows | **1 failed**, 367 passed, 5 skipped: `test_restore_brings_back_the_backup…` — `PermissionError [WinError 32]` moving the database |
| 2026-09-29 s13 | Diagnosis | Linux | (1) test bug: `count_events()` used `with sqlite3.connect()`, which commits but does not close → the file stayed open and Windows refused the move; (2) **real bug**: after the failed move, restore's rollback called `database.unlink()` on the *original* database — blocked on Windows only by the lock, on Linux it would delete the live database. Regression test written first: on Linux the database was indeed deleted (`exists()` False) |
| 2026-09-29 s13 | After the fix (rollback removes the file only once the original is aside and copying began; test connections closed with `contextlib.closing`) | Linux | backup tests 16/16; regression test passes; Py 3.13 `ResourceWarning` proxy for Windows file locks: old `count_events` → 8 unclosed connections, fixed → 0; full suite 378 / 378 / 378 (dev, 3.11 lock, 3.13 lock); ruff/mypy clean |
| 2026-09-29 s13 | `pytest` (dev env / fresh 3.11 lock / fresh 3.13 lock); ruff; mypy (linux/win32/darwin); compileall; smoke | Linux | 377 / 377 / 377 passed; clean; smoke all passed; `backup.py` 93 %, `inspect.py` 98 % |
| 2026-09-29 s13 | Mutation check (8: copy left in WAL mode, overwrite allowed, any backup restorable, no rollback, copy created world-readable, restored file not private, restore while running, failed copy left behind) | Py 3.11 | 7 caught at first; **"created world-readable" survived** (the final chmod hid it) → test now observes the mode mid-backup; then caught |
| 2026-09-29 s13 | **Real cycle on a demo server**: `backup` ×2 while writing; `restore` while running; stop; `restore`; start | Linux, lock venv 3.13 | backups with 151 / 262 events, integrity ok; restore while running refused (exit 2); after stop the DB had 302 events → restored to 151, previous kept as `hound.db.before-restore-…`; modes 600 (DB, backup) / 700 (backups dir); restarted server reports 151 events |
| 2026-09-29 s13 | SQLite `-wal`/`-shm` permissions check | Py 3.11 / SQLite | created with the DB file's mode (0600) → corrected a wrong statement in ARCHITECTURE §3.11a |
| 2026-09-29 s12 | `pytest` (dev env / fresh 3.11 lock / fresh 3.13 lock); ruff; mypy (linux/win32/darwin); compileall; smoke | Linux | 362 / 362 / 362 passed; clean; smoke all passed; `routes/admin.py` 100 % |
| 2026-09-29 s12 | Mutation check (6: swap without the batch lock, windows always reset, DNS cache dropped, no token check, not all-or-nothing, CLI hiding a refusal) — every run under `timeout` | Py 3.11 | each caught; originals restored |
| 2026-09-29 s12 | **Real demo server + real `python run.py reload`**: `[weights] blocklisted_domain = 0` written, reloaded, then a typo'd file | Linux, lock venv 3.13 | before: 18 blocklist hits, all DANGEROUS (70 pts); reload exit 0; events after: 9 hits with 0 pts (8 SAFE, 1 SUSPICIOUS from other signals); typo → "Reload refused (HTTP 400) … weights.blocklisted: unknown setting … previous settings stay in effect", exit 1, server still serving |
| 2026-09-28 s11 | `pytest` (dev env / fresh 3.11 lock / fresh 3.13 lock); ruff; mypy (linux/win32/darwin); compileall; smoke | Linux | 352 / 352 / 352 passed; clean; smoke all passed; `risk/config.py` 99 % |
| 2026-09-28 s11 | Drift guard (uncomment every value in `config/risk.toml`) while building | Py 3.11 | **caught 2 real problems**: a prose comment line looked like a setting (file would break when "uncommented"), and `[behaviour] nxdomain_burst` mapped to a non-existent field — both fixed |
| 2026-09-28 s11 | Mutation check (6: typos ignored, environment not winning, wrong key mapping, CLI traceback instead of exit 2, doctor skipping the file, `.env.example` pinning a value) | Py 3.11 | each caught. First attempt hung: with typos ignored, the CLI test started a real server → test now replaces `uvicorn.run` with a failing stub |
| 2026-09-28 s11 | **Demo mode, same seed: defaults vs `[weights] high_entropy_domain = 0, risky_tld = 0`** | Linux, lock venv 3.13 | entropy/TLD points on 7/2 events → 0/0; blocklist hits 2 → 2; dangerous 5 → 5; suspicious 23 → 22; "Risk settings file loaded values=2" logged |
| 2026-09-28 s11 | Invalid file (`suspicious = 90` > default dangerous 70): `run.py` and `run.py doctor` | Linux | server: one "Cannot start: … suspicious < dangerous" line, exit 2; doctor: `[FAIL] Risk settings`, 1 problem |
| 2026-09-28 s10 | `pytest` (dev env / fresh 3.11 lock / fresh 3.13 lock); ruff; mypy (linux/win32/darwin); compileall; smoke | Linux | 334 / 334 / 334 passed; clean; smoke all passed; coverage 94 % (`risk/engine.py` 100 %, `allowlist.py` 96 %) |
| 2026-09-28 s10 | Mutation check of `tests/test_allowlist.py` (7 breakages: device entry hides blocklist, policy not applied, silent suppression, bare TLD accepted, domain not matched, file not wired, no broad-range warning) | Py 3.11 | each caught; originals restored |
| 2026-09-28 s10 | **Demo mode, same seed, without vs. with allowlist `192.168.1.0/24`** (10 s at 40 events/s) | Linux, lock venv 3.13 | without: 28 flagged (26 without a blocklist hit); with: only the 2 blocklist hits flagged (still DANGEROUS), 69 events carry an `ALLOWLISTED` reason; "Allowlist loaded devices=1" logged |
| 2026-09-28 s9 | `python scripts/benchmark.py` (default 50 k rows / `--rows 250000`) | Linux, 2 vCPU, Py 3.11 | 21 s / 69 s; batch-200 ≈ 5 800–6 100 events/s; `/api/stats` 20 / 81 ms; 516 B/event; peak 163 MiB; both checks OK (details: ROADMAP §I) |
| 2026-09-28 s9 | `pytest` (dev env / fresh 3.11 lock / fresh 3.13 lock); ruff; mypy; compileall; smoke; `benchmark.py --quick` | Linux | 312 / 312 / 312 passed; clean; smoke all passed; quick benchmark OK in both lock venvs; no `hound-bench-*` temp folders left |
| 2026-09-28 s9 | First benchmark draft measured storage before a WAL checkpoint | Py 3.11 | 3 246 B/event (misleading: WAL pages) → checkpoint added before measuring |
| 2026-09-28 s8 | `pytest` (dev env / fresh 3.11 lock / fresh 3.13 lock) | Linux | 310 / 310 / 310 passed; coverage 94 % (`routes/metrics.py` 100 %, `runtime.py` 94 %) |
| 2026-09-28 s8 | ruff check + format, mypy (linux/win32/darwin), compileall, smoke test | both lock venvs | clean (62 source files, 87 formatted); smoke all passed |
| 2026-09-28 s8 | Mutation check (8 breakages: no high-water, 413 not counted, daemon report not stored, total ignores daemon, WS drops hidden, prune not counted, batches not counted, report frozen across retries) | Py 3.11 | each caught; originals restored (cmp clean) |
| 2026-09-28 s8 | `EventQueue.offer` micro-benchmark, before vs. after high-water tracking (200 k offers, 2 runs each) | Py 3.11 | ~0.32–0.42 M/s vs ~0.37–0.43 M/s: no measurable cost (pipeline itself ≈ 5 400 events/s) |
| 2026-09-28 s8 | **Real split mode**: server (idle mode) + real capture daemon on `lo` + `scripts/generate_test_traffic.py`, then `GET /api/metrics` | Linux, lock venv 3.13 | daemon report received (interface `lo`, 4 parsed, queue peak 2); server accepted/processed 4 in 2 batches (p50 11 ms, p95 40 ms); `total_events_lost` 0; daemon exit 0 |
| 2026-09-28 s7 | Dependency licence survey (installed runtime lock env, package metadata + Scapy SPDX headers) | Py 3.11 | all permissive or weak-copyleft (MIT, BSD, Apache-2.0, MPL-2.0, PSF) **except Scapy: GPL-2.0-only** (287 files incl. `scapy/__init__.py`; 83 files GPL-2.0-or-later). Note: Apache-2.0 packages (e.g. aiohttp, yarl, python-multipart) are, per the FSF, incompatible with GPLv2 — so the Scapy question exists independently of Hound's own licence. Hound ships source only; users install dependencies from PyPI |
| 2026-09-28 s7 | `.github/workflows/ci.yml` on GitHub (Linux/Windows/macOS × Py 3.11/3.13, audit, newest-deps job) | GitHub Actions | owner: "CI is working perfectly" — first macOS coverage. Run logs not shared |

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
- **14.3a Lock files + CHANGELOG (session 6):**
  - `requirements.lock` / `requirements-dev.lock`: universal (one file for all OSes,
    markers where needed), hash-checked, generated with `uv pip compile` (ADR-019). The dev
    lock is constrained by the runtime lock, so shared pins are identical.
  - CI: test matrix installs `requirements-dev.lock`; audit job audits both locks; new
    non-blocking job runs the newest versions the ranges allow.
  - `tests/test_dependency_locks.py` (7 tests): locks within ranges, every pin hashed,
    runtime pins identical in both locks, generation command recorded.
  - `CHANGELOG.md` (Unreleased + initial build), README install/update sections, ADR-019,
    ADR-017 revisited.
  - README: Windows venv command `py -3` instead of `py -3.11` (the owner's machine has no
    3.11; the old command failed).
  - Note: the lock resolves newer versions than the previous dev environment (e.g.
    uvicorn 0.46 → 0.54, pydantic-settings 2.14 → 2.15); validated in fresh environments.
- **15a `doctor` environment check (session 7):**
  - `python run.py doctor [-i IFACE]` → `app/services/doctor.py`: 10 read-only checks
    (Python, packages vs. `requirements.lock`, capture driver via Scapy's own
    Npcap/libpcap detection, privileges, interface, bind address, port — recognises a
    running Hound via `/health` —, cloud-synced data folder, database schema/adoption/
    upgrade/writability, ingest token incl. POSIX permissions). Each non-OK result names
    the fix; exit status 1 on any failure.
  - Read-only by construction and by test: the database is opened `immutable` when no WAL
    exists (plain read-only mode was found to create `-wal`/`-shm` files).
  - `is_privileged()` moved to `app/core/privileges.py` (CLI keeps `_is_privileged`).
  - `tests/test_doctor.py` (35 tests); README §11 "First: check your setup", command table,
    troubleshooting row; ARCHITECTURE §3.11a; CHANGELOG.
  - **Bug found by the owner's Windows run and fixed:** `Settings.resolved_database_url`
    built the SQLite URL from the raw path, so a project folder containing `%XX` or `?`
    pointed the database elsewhere (Linux) or failed to open it (Windows). SQLAlchemy now
    renders the URL (percent-encoded). My Linux test had passed only because it checked
    that a database worked, not *where* it was created; the tests now assert the location
    and cover awkward project folder names (12 new cases). README notes that explicit
    `HOUND_DATABASE_URL` paths with `%`, `?`, `#` must be encoded.

- **15b `/api/metrics` (session 8):**
  - `GET /api/metrics` (`app/api/routes/metrics.py`, `HoundRuntime.metrics()`): `loss`
    per stage (daemon queue, daemon delivery, server queue, processing) + total;
    `capture`, `daemon`, `ingest` (accepted / 401 / 422 / 413 + events), `queue` (incl.
    high-water), `processing` (batches, latency p50/p95/max over the last 1 000 batches),
    `websocket` (drops — not loss), `storage` (DB/WAL bytes, retention pruned — not loss).
  - New counters: `EventQueue` high-water mark; `ProcessingService` batches + latency
    window; `SqlEventStore.pruned_total`; ingest outcomes; `Database.file_sizes()`.
  - Split mode: the daemon's counters ride on each ingest POST (optional, strictly
    validated `daemon` field; refreshed on every retry) — ADR-020.
  - `tests/test_metrics.py` (11) + end-to-end daemon test extended; README §13 + §11,
    ARCHITECTURE §3.12/§5.5, ADR-020, CHANGELOG.

- **15c benchmark script (session 9):** `scripts/benchmark.py` — in-process, temporary
  database, no network/privileges: dissection, parsing, processing at batch 1/50/200
  (with batch latency via `summarize_latency`), fill to `--rows`, API latency of the
  dashboard's endpoints, bytes/event after a WAL checkpoint, peak memory (POSIX
  `resource`, Windows `GetProcessMemoryInfo`), two informational checks; `--json`,
  `--quick`. `tests/test_benchmark.py` (2, quick mode — so CI runs it on all three OSes).
  Reproduced the ROADMAP §I baseline (table updated). README §15 "Measuring
  performance". **Phase 15 complete.**

- **16a Allowlist (session 10):** `app/enrichment/allowlist.py` (domains via the
  blocklist's suffix matching; devices as IP/CIDR; bare labels rejected, ranges wider
  than /24 or /64 logged), `Enrichment.allowlisted_domain/device`, and
  `apply_allowlist()` in the risk engine (ADR-021): domain entries cover every indicator,
  device entries all but `BLOCKLISTED_DOMAIN`; covered indicators are removed from the
  score and listed in a 0-point `ALLOWLISTED` reason (no schema change). Setting
  `HOUND_ALLOWLIST_PATH` (default `config/allowlist.txt`, shipped with comments only →
  default behaviour unchanged). Test fixture uses an absent allowlist so the owner's
  entries never affect tests. `tests/test_allowlist.py` (22). README §8, ARCHITECTURE
  §3.5/§3.6, `.env.example`, CHANGELOG.
  *Deviation from the plan:* the plan said "cap the level at SAFE"; covered indicators
  are removed from the score instead, so score, level and device aggregates cannot
  disagree (ADR-021).

- **16b Risk settings file (session 11):** `config/risk.toml` (`HOUND_RISK_CONFIG_PATH`),
  `load_risk_file()` + `RiskConfig.from_settings()` in `app/risk/config.py` (ADR-022):
  sections levels/behaviour/domains/ports/dns/weights, strict (unknown keys and bad
  ranges rejected with the key named); precedence defaults < file < explicitly set
  `HOUND_RISK_*`/`HOUND_TRUSTED_DNS_SERVERS`; `RiskConfigError` → `serve` exits 2 before
  the web server starts; new `doctor` check (11 checks) that also lists environment
  overrides; `doctor` output no longer includes INFO log lines. `.env.example` now keeps
  the risk variables commented (a copied `.env` would otherwise silently override the
  file). Shipped file = every default, commented; drift-guard test. Test fixture uses an
  absent risk file. `tests/test_risk_config.py` (18). README §8, ARCHITECTURE §3.6,
  ADR-022, CHANGELOG.

- **16c Reload without restart (session 12):** `POST /api/admin/reload` (ingest token in
  `X-Hound-Token`; `app/api/routes/admin.py`) and `python run.py reload` (exit 0 applied,
  1 refused, 2 no token/unreachable/401). `HoundRuntime.reload_detection_config()` loads
  and validates blocklist, allowlist and risk settings first, then swaps them via
  `ProcessingService.reconfigure()` under the per-batch lock; `EnrichmentService
  .update_lists()` keeps the DNS answer cache, `RiskEngine.reconfigure()` keeps the
  behaviour tracker unless the window length changes (ADR-023). Shared helper
  `file_value_count()` (doctor + reload). `tests/test_reload.py` (10). README §8/§11/§13,
  shipped config comments, ARCHITECTURE §3.11, ADR-023, CHANGELOG.

- **17a Backup + restore (session 13):** `app/database/backup.py` (ADR-024):
  `python run.py backup [PATH]` (SQLite online backup API, safe while writing; owner-only
  from the first byte; single file; integrity-checked; never overwrites; default
  `data/backups/hound-<UTC time>.db`) and `python run.py restore BACKUP` (refuses while a
  Hound answers; validates integrity/version/structure; moves the current DB + WAL/SHM
  aside; rolls back on failure). `app/database/inspect.py` now holds the read-only
  helpers `doctor` used (`sqlite_path`, `open_read_only`, `inspect_database`), shared by
  doctor and restore; `doctor.probe_hound` made public. `tests/test_backup.py` (16).
  **Fixed after the owner's Windows run:** a failed move during restore made the rollback
  delete the *original* database (Linux would have lost it; Windows' lock prevented it);
  now only a partial copy is ever removed — regression test added. Also from that run:
  tests leaked the CLI's logging handler (bound to a closed capture stream) → autouse
  fixture in `tests/conftest.py` restores logging state after each test.
  README "Backups", command table, tree; ARCHITECTURE §3.7/§3.11a; ADR-024; CHANGELOG.

## 4. In progress
- Nothing.

## 5. Next (in order — only the first is "the next task")
1. **17b Export.** Events (filterable like `/api/events`) and devices as CSV and JSON,
   via API endpoints and/or `python run.py export`, streaming so large exports stay within
   bounded memory; CSV safe against formula injection (a domain starting with `=`, `+`,
   `-`, `@` must not execute in a spreadsheet). For the field-trial review. Unblocked.
2. 16d field trial + tuning (needs the owner's monitoring position).
3. 14.3b LICENSE + version label, once the owner decides.
4. Owner: if an older `.env` was copied from `.env.example`, remove its `HOUND_RISK_*`
   lines (or `python run.py doctor` shows them as overrides).
4. Owner: run `python scripts/benchmark.py` on the Windows laptop once, to record a
   baseline for the machine that will actually run Hound.

## 6. Blocked / needs owner input
| Item | Needed | Blocks |
|---|---|---|
| License | Owner leans to GPL-3.0 but deferred the decision (2026-09-28) after the dependency check below: Scapy core is **GPL-2.0-only**, which the FSF treats as incompatible with GPL-3.0 in a combined program; options considered: GPL-2.0-or-later, GPL-3.0-or-later, GPL-3.0-only. Not legal advice — worth a qualified opinion before publishing a release | 14.3b |
| Version label | Keep `1.0.0` or re-label `0.9.0` until M6 | 14.3b |
| Field trial | A monitoring position that sees household traffic (router, mirror port or DNS host) | M7 |

## 7. Technical debt

**Critical**
- None open. (Schema versioning — the previous critical item — was resolved by 14.2.)

**Important**
- Locked versions only move when someone re-locks; the audit job and the non-blocking
  newest-versions CI job are the signals (both inert until the project is on GitHub).

**Nice-to-have**
- A device's risk resets only after its window expires *and* it sends a new event, so a
  silent device keeps its last level. The UI caption doesn't explain this; revisit in 16.
- `devices` rows are never expired; counters are lifetime totals even after event
  retention prunes old events → 17.
- Backups accumulate in `data/backups/` (no rotation or pruning yet).
- `restore` detects a running server only on the configured port; a server started on
  another port is not detected (on Windows the file move then fails and is rolled back).
- `/api/stats` uses `COUNT(*)` scans (71 ms at the 250 k cap) → only if metrics show need.
- The forwarder opens one TCP connection per batch (ADR-016); fine at the current cadence.
- `Database.initialize()` runs twice at server start (CLI pre-flight + lifespan); the second
  run is a no-op version check. Harmless; revisit only if start-up time matters.
- `cli.py` 79 % and `logging_config.py` 40 % coverage; `privileges.py` 55 % on Linux (the
  Windows branch runs only on Windows).
- `doctor`'s database-writability check uses `os.access`, which ignores Windows ACL
  details; a false "writable" is possible there (the server then reports the real error).
- The test suite now takes ~21–24 s: dashboard ~9.7 s, daemon ~4.5 s, doctor ~3 s (2 s
  of it is the port-probe timeout against a silent listener).
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
- Allowlist and risk-settings changes apply with `python run.py reload`; `.env` changes
  still need a restart; entries match domains or source devices only —
  "any device → this destination" (e.g. SMB to the owner's NAS) is not expressible yet.
- Single process, single user, localhost only; no dashboard authentication.
- Live capture verified on Linux (loopback) and Windows (Wi-Fi, owner's report); macOS not
  yet. On Wi-Fi, only this computer's own traffic is visible (see README §9).
- In a cloud-synced folder (OneDrive etc.) the database and ingest token are uploaded, and
  sync can lock SQLite; documented in the README with workarounds.
- A database written by a newer Hound cannot be opened by an older one (by design; no
  downgrades).

## 9. How to verify this file is still true
```bash
pip install -r requirements-dev.lock
python -m compileall -q app tests scripts run.py
ruff check app tests scripts run.py
mypy
pytest
python scripts/smoke_test.py
```
If any result differs from §2, update this file before starting new work.
