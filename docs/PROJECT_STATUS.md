# Hound — Project Status

> Answers: *where are we, what works, what is missing, what blocks us, what is next.*
> Update this file at the end of every task. Plan: [`ROADMAP.md`](ROADMAP.md) ·
> Architecture: [`ARCHITECTURE.md`](ARCHITECTURE.md) · Decisions: [`DECISIONS.md`](DECISIONS.md)

```text
Last updated:      2026-09-30 (session 19: 16g capture restarts itself after interface failures)
Current milestone: M7 — Field-validated (M0–M6 reached; M2 on Linux + Windows)
Current phase:     Phase 16 — 16a–16c, 16e–16g done; 16d field trial next (owner, week
                   of 2026-10-05, laptop-only position; procedure in docs/FIELD_TRIAL.md).
                   Phase 17: 17a–17c done, 17d open
Current task:      none in progress
Next task:         17d periodic PRAGMA optimize (engineering); 16d is the owner's
Overall state:     Hound 1.0.0 (MIT) + unreleased 16e–16g, 17b, 17c: capture (split mode,
                   Linux + Windows) that restarts itself after interface outages,
                   enrichment with real countries (DB-IP Lite, automatic monthly
                   download), explainable risk with allowlist and a tunable, reloadable
                   risk file, API, live dashboard with coverage line and downloads,
                   CSV/JSON export, retention by count and age, metrics, doctor,
                   backup/restore, benchmark. Linux: 525 tests pass (Py 3.11 + 3.13, from
                   the lock). Not yet verified on the owner's machine: a real DB-IP
                   download, and capture recovery on Windows/Npcap after sleep.
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
Database        VERIFIED        WAL, indexes, retention by count + optional age (devices follow); schema v1 in PRAGMA user_version with
                                ordered atomic migrations (ADR-018); owner-only files on POSIX
Enrichment      VERIFIED*       Blocklist (suffix matching), DB-IP Lite countries (real file not
                                yet downloaded in any test environment), DNS correlation
Risk engine     VERIFIED*       13 deterministic signals; not yet tuned on real traffic
Frontend        VERIFIED        16 page-level tests against the real API (dashboard.py 96 %);
                                visuals checked manually (coverage line: screenshots s15)
Testing         VERIFIED*       525 tests, 94% line coverage; all pass on Linux (Py 3.11 + 3.13);
                                Windows 292 + 3 expected skips (owner); CI green (owner report)
Configuration   VERIFIED        HOUND_* env/.env/CLI, validated; .env.example parses
Security        FUNCTIONAL      Least privilege, loopback, Host/Origin checks, token ingest;
                                S-3 fuzz, S-6 documented, S-8 done; daemon ignores proxies
Documentation   FUNCTIONAL      README covers upgrades/refusals; Windows guidance owner-checked
Packaging       VERIFIED        Hash-checked universal locks (ADR-019), CHANGELOG [1.0.0], MIT
                                LICENSE with PEP 639 metadata (wheel builds), CI installs the lock
```
`*` = verified with the caveat in the notes.

## 2. Validation log

| Date | Check | Platform | Result |
|---|---|---|---|
| 2026-09-30 s19 | Baseline `pytest`; repo = last delivered zip | Linux, Py 3.11 | 519 passed |
| 2026-09-30 s19 | **Real Scapy on a veth interface** (root in the sandbox; `ip link` via iproute2) | Linux, Scapy 2.7 | link **down** or interface **deleted** → Scapy logs "Network is down", closes the socket and the sniffer thread ends with **no exception**; it does not resume when the link comes back |
| 2026-09-30 s19 | **Previous build** (daemon) on the same outage | Linux | "Packet capture stopped unexpectedly … capture thread exited unexpectedly" → daemon **exit 3** |
| 2026-09-30 s19 | New `PacketCaptureService` on the real veth: DNS before → link down 4 s → up → DNS; then interface deleted 5 s → re-created → DNS | Linux | state `restarting` with "went down or disappeared"; 2 failed attempts each ("Network is down"), then "Packet capture resumed"; all 3 queries captured; `restarts` 2, `downtime_seconds` 14.5 |
| 2026-09-30 s19 | **Real split mode**: server + `python run.py capture -i vh0` (separate processes), link down 6 s → up | Linux | daemon stayed up; events before and after stored (2); `/api/metrics` `daemon.capture_restarts` 1, `capture_downtime_seconds` 7.39, `total_events_lost` 0 |
| 2026-09-30 s19 | Mutation check (13: no restart, interfaces not re-read, filter mode lost, no backoff growth, no backoff cap, restarts not counted, ongoing outage not counted, stale error after stop, daemon exits while restarting, restarts not reported, dashboard hides restarting, quiet end treated as generic) — each under `timeout` | Py 3.11 | first pass: "no backoff growth" **survived** → backoff test added; then 13/13 caught |
| 2026-09-30 s19 | `tests/test_capture.py` + `tests/test_daemon.py` repeated 5× (timing-based tests) | lock venv 3.13 | 26/26 each run |
| 2026-09-30 s19 | `pytest` (dev env / fresh 3.11 lock / fresh 3.13 lock); ruff; mypy 2.3.1 ×3 platforms + 3.11 lock; compileall; smoke | Linux | 525 / 525 / 525 passed; clean; smoke all passed; 0 ResourceWarnings in `test_capture.py` |
| 2026-09-29 s18 | Data source facts (web): DB-IP Country Lite — CC BY 4.0, monthly, CSV + MMDB, `download.db-ip.com/free/dbip-country-lite-YYYY-MM.mmdb.gz`, ~717 k records; MaxMind GeoLite2 needs account + key and 30-day deletion | db-ip.com, dev.maxmind.com | owner chose DB-IP Lite with automatic download |
| 2026-09-29 s18 | `maxminddb` 3.2.0: licence, Python, wheels | PyPI | Apache-2.0, Python ≥ 3.10, wheels for win_amd64 and macOS arm64 (cp311, cp313) and Linux; locks regenerated — only `maxminddb` added; `pip-audit` on the runtime lock: no known vulnerabilities |
| 2026-09-29 s18 | Real download from the sandbox | Linux | **blocked** by the sandbox's egress policy (403 at the proxy) → not verified here; the server logged one warning, kept running with countries *Unknown*, left no partial file, and did not retry within the 6 h window |
| 2026-09-29 s18 | Test `.mmdb` writer (`tests/mmdb.py`) against the real reader | maxminddb C extension + pure Python (MODE_AUTO/MEMORY/FILE) | first version rejected by the C reader (metadata integer types) → typed metadata; then identical lookups in all modes |
| 2026-09-29 s18 | `tests/test_benchmark.py` in the full suite | Linux | **caught** the benchmark creating `data/geoip` in the project (its runtime started the updater with auto-download) → benchmark now never downloads (uses an installed database read-only, reports the source) |
| 2026-09-29 s18 | Mutation check (15: no unpacked-size cap, no download cap, truncation undetected, no sanity lookups, live falls back to simulated, no retry window, replaced reader not closed, reload ignores geo, no attribution in API, credit never shown, no staleness warning, any host allowed, old files kept, partial file kept) — each under `timeout` | Py 3.11 | 14/15 at first: the unpacked-size check survived because the final `flush()` check also caught the test bomb — but `flush()` inflates everything at once; test changed to stream in 8-byte chunks → 15/15 |
| 2026-09-29 s18 | **Real server** (idle, default settings): no database → one blocked download attempt; test database copied into `data/geoip`; `python run.py reload`; 4 events ingested | Linux | countries API `source=dbip`, month 2026-09, credit present, `simulated=false`; Portugal 2, United States 1, Unknown 1 (as in the test database); `geo status` and `doctor` "[ OK ] Geolocation DB-IP Lite 2026-09 (8.8.8.8 -> US)"; Chromium screenshot: Countries tab note + "IP Geolocation by DB-IP" link |
| 2026-09-29 s18 | Lookup speed, 100 k random IPv4 | Py 3.11 | `.mmdb` (C extension): ~93 k lookups/s vs simulated ~39 k/s — no pipeline impact (~5.5 k events/s) |
| 2026-09-29 s18 | `pytest` (dev env / fresh 3.11 lock / fresh 3.13 lock); ruff; mypy 2.3.1 ×3 platforms + 3.11 lock; compileall; smoke (demo, no database: simulated, nothing created in `data/`) | Linux | 519 / 519 / 519 passed; clean; smoke all passed; 0 ResourceWarnings in `test_geoip.py` |
| 2026-09-29 s17 | Baseline: `pytest`; no file newer than the last delivered zip | Linux, Py 3.11 | 459 passed |
| 2026-09-29 s17 | **Bug reproduced before the fix**: `EventRepository.prune` made to raise "database is locked", 50 single-event batches | Py 3.11 | all 50 stored, yet `failed=1`, "Database write failed; batch dropped" logged (pruning ran inside `save()` after the commit) → pruning moved to worker housekeeping; regression test passes |
| 2026-09-29 s17 | Test expectations for the age/count scenarios | Py 3.11 | two hand-computed expectations were wrong (a boundary event at exactly 7 days is kept; the count limit runs before the age limit) — corrected the tests, not the code, after re-deriving them |
| 2026-09-29 s17 | Mutation check (12: prune back inside save, housekeeping unguarded, age limit ignored, empty devices kept, DNS / dangerous counters not decremented, worker never housekeeps, no prune at start, events and devices in two transactions, no clamping, pruned devices not counted, tally ignores risk level) — each under `timeout` | Py 3.11 | 12/12 caught; originals restored |
| 2026-09-29 s17 | Prune cost on 250 k rows spanning 10 days, 30 devices | Py 3.11 | first 7-day prune: 75 001 rows in 464 ms; steady count prune of 999 rows: 28 ms; nothing to prune: 7 ms; afterwards Σ device `event_count` = stored rows (174 000) |
| 2026-09-29 s17 | **Real server**: events 10, 9, 1 and 0 days old ingested over HTTP; restart with `HOUND_RETENTION_DAYS=7` | Linux | on start "Retention applied removed_events=2 removed_devices=1"; devices: `.10` 1 event (was 2), `.20` 1, `.30` gone; `/api/metrics` `retention_days` 7, pruned 2 events / 1 device; no WARNING/ERROR |
| 2026-09-29 s17 | Real demo server at 200 events/s with `HOUND_RETENTION_MAX_EVENTS=1000`, `HOUND_RETENTION_DAYS=1` | Linux | processed 2 198 = stored 1 018 + pruned 1 180, loss 0; after stop, in SQLite: Σ device counts = 1 018 = stored events, 0 devices without events, 0 devices whose count differs from its events; 12 "Retention applied" lines, no WARNING/ERROR |
| 2026-09-29 s17 | `pytest` (dev env / fresh 3.11 lock / fresh 3.13 lock); ruff check + format; mypy 2.3.1 linux/win32/darwin + 3.11 lock; compileall; smoke | Linux | 479 / 479 / 479 passed; clean; clean ×4; smoke all passed; `store.py` 98 %, `repositories.py` 99 %, `processing.py` 95 %; Py 3.13 ResourceWarnings in the new tests: 0 |
| 2026-09-29 s16 | Baseline: `pytest`; ruff check + format (app tests scripts run.py); mypy | Linux, Py 3.11 | 419 passed; clean; clean |
| 2026-09-29 s16 | Export endpoints by hand (TestClient) | Py 3.11 | CSV with BOM + `Content-Disposition`; an ingest-supplied interface `=cmd\|' /C calc'!A0` was **accepted by ingest** and came out as `'=cmd…` (formula neutralised); `format=xml` and `since > until` → 422 |
| 2026-09-29 s16 | `/api/events` OpenAPI parameters after moving the filters into a shared dependency | Py 3.11 | same 12 parameters (now also a test) |
| 2026-09-29 s16 | Mutation check (16: no formula prefix, leading spaces unchecked, no BOM, no snapshot bound, filters ignored, stops after first page, keyset off by one, newest first, whole table read eagerly, CSV not chunked, JSON not chunked, JSON per item, JSON not closed, error not logged, dashboard link ignores filter, device risk filter ignored) — each under `timeout` | Py 3.11 | 16/16 caught. The "CSV not chunked" test first used an endless generator, so the mutant hung until `timeout` → rewritten to raise instead, now fails in 3 s |
| 2026-09-29 s16 | **Real server** (subprocess, dashboard off), events pre-filled, `httpx` streaming download; server `VmHWM` before/after | Linux, Py 3.11 | 25 k rows: CSV 5.6 MB 2.2 s, JSON 13.4 MB 9.0 s; 250 k rows: CSV 56.4 MB 21.6 s, JSON 134 MB **87.6 s** — peak RSS 77 → 83 MiB in every case (bounded). JSON was one chunk per item → batched per 1 000 → 250 k JSON 17.7 s (14.1 k rows/s), CSV 20.7 s (12.1 k rows/s), RSS still 83 MiB |
| 2026-09-29 s16 | **Real demo server** + `curl` + Chromium | Linux | `min_risk_level=suspicious` CSV: 72 rows, only suspicious/dangerous, ids ascending, headers `attachment; filename="hound-events-…csv"`, `no-store`; devices JSON 6 devices; dashboard: *Dangerous* filter then *Download CSV* in the browser → `hound-events-….csv` with 44 rows, all dangerous; 3 "Export finished" log lines, no WARNING/ERROR |
| 2026-09-29 s16 | `pytest` (dev env / fresh 3.11 lock / fresh 3.13 lock); ruff check + format; mypy linux/win32/darwin (mypy 2.3.1 from the lock) + 3.11 lock; compileall; smoke | Linux | 459 / 459 / 459 passed; clean; **mypy 2.3.1 found 2 errors the dev env's mypy 1.20 did not** (`responses=` dict type) → annotated; then clean ×4; smoke all passed; `export.py` 100 %, `routes/export.py` 100 %, `routes/events.py` 100 % |
| 2026-09-29 s16 | Py 3.13 `-W error::ResourceWarning` on the export + dashboard tests | lock venv 3.13 | 0 ResourceWarnings |
| 2026-09-29 s15 | Baseline before 16e: `pytest` | Linux, Py 3.11 | 380 passed (2 third-party deprecation warnings: websockets/uvicorn) |
| 2026-09-29 s15 | Default BPF vs. an IPv6 SYN (`tcpdump -r` on crafted frames) | libpcap 1.10.4 | IPv4 SYN and IPv6 DNS matched; **IPv6 SYN not matched** → the "IPv6 connection attempts" blind spot is stated only when the default filter is in use |
| 2026-09-29 s15 | Premise check while writing tests: are DNS answers stored (router counted as a device)? | Linux | **no** — answers only feed the DNS cache; the first draft's docstrings claimed otherwise and were corrected; the laptop test now guards the end-to-end behaviour |
| 2026-09-29 s15 | Coverage query at 250 k rows, all within 24 h | Linux, Py 3.11 | with a packet-type filter: 300–390 ms (index on `packet_type` + temp B-tree); without it: 84–107 ms (covering `(source_ip, timestamp)` index) → filter dropped (every stored event is a lookup or connection attempt) |
| 2026-09-29 s15 | Mutation check (12: IPv6 counted as devices, no 24 h window, no minimum span, public addresses counted, gateway single device not flagged, demo judged, custom filter ignored, no cache, dashboard never warns, dashboard reloads every tick, doctor check missing, spelling not normalised) — each run under `timeout` | Py 3.11 | 12/12 caught; originals restored (full suite green afterwards) |
| 2026-09-29 s15 | **Real server** (idle, `HOUND_DEPLOYMENT_POSITION=Gateway` in `.env`), events posted to `/api/ingest` with the token | Linux | empty: "not enough traffic"; 60 lookups by one device over 20 min → `one_device`/warning "…check that the capture runs on the LAN side"; +1 device → still cached (30 s), then `several_devices`/ok; `doctor`: "[ OK ] Deployment position  Router / gateway; does not see traffic between devices inside your network"; no WARNING/ERROR in the log |
| 2026-09-29 s15 | Real demo server (`this_computer`, then `gateway`) + Chromium screenshots | Linux | coverage `demo`/info ("the events are synthetic…"); coverage line under the banner and the *What Hound can't see* dialog render as intended |
| 2026-09-29 s15 | `pytest` (dev env / fresh 3.11 lock / fresh 3.13 lock); ruff check; ruff format (app tests scripts run.py); mypy linux/win32/darwin; compileall; smoke | Linux | 417 (before 2 extra branch tests) / 419 / 419 passed; clean; smoke all passed; `coverage.py` 100 %, `routes/coverage.py` 100 %, `dashboard.py` 96 % |
| 2026-09-29 s15 | Py 3.13 `-W error::ResourceWarning` (Windows file-lock proxy) | lock venv 3.13 | 419 passed; ~30 unclosed-connection warnings, all allocated in **`tests/test_migrations.py` helpers** (pre-existing, `with sqlite3.connect()` without close) — none from 16e code or tests → technical debt |
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
| 2026-09-29 s14 | **Owner decisions**: licence MIT, version label 1.0.0 | — | `LICENSE` added; `pyproject.toml` `license = "MIT"`, `license-files`, setuptools ≥ 77; `pip wheel .` built `hound-1.0.0` with `License-Expression: MIT` and `licenses/LICENSE`; CHANGELOG `[1.0.0] - 2026-09-29`; ADR-025 → **M6 reached** |
| 2026-09-29 s14 | `python run.py backup` — **owner's Windows laptop** | Windows | works (owner report) |
| 2026-09-29 s14 | `python scripts/benchmark.py` — **owner's Windows laptop** (16 CPUs, Py 3.13.7) | Windows | batch-200 5 565 events/s; `/api/stats` 32.5 ms at 50 k rows; 508 B/event; headroom 55.6×; peak memory "n/a" → **bug**: ctypes passed the process handle as a 32-bit int (no argtypes/restype) → fixed with declared signatures (`K32GetProcessMemoryInfo`); untested on Windows here, re-run pending |
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

- **14.3b Licence + version (session 14, owner decisions):** MIT + 1.0.0 → M6 reached
  (ADR-025). Also: Windows peak-memory measurement in `scripts/benchmark.py` fixed; owner's
  benchmark recorded as the laptop baseline (ROADMAP §I); deployment-position principle
  recorded (ADR-026, roadmap slice 16e).

- **16e Deployment positions (session 15, ADR-026):** `HOUND_DEPLOYMENT_POSITION`
  (`auto` default, `this_computer`, `gateway`, `mirror`, `dns_server`; spelling-tolerant).
  `app/services/coverage.py` holds the only copy of what each position sees and misses
  (plus the blind spots of every position) and checks it against the last 24 h: local
  IPv4 addresses that started a lookup or connection (IPv6 reported, never decisive;
  public sources counted separately), no verdict before 50 events over 15 min, demo never
  judged, mismatch = warning with the likely cause. Surfaces: `GET /api/coverage` (30 s
  cache), a dashboard coverage line (amber on mismatch) with a *What Hound can't see*
  dialog, a `doctor` line (12 checks now), README §9 *Where to run Hound*, `.env.example`.
  39 new tests (`tests/test_coverage.py` 36 incl. a drift guard against README and
  `.env.example`; 3 dashboard), mutation-checked.

- **17b Export (session 16, ADR-027):** `GET /api/export/events` (every `/api/events`
  filter, through one shared `event_filter` dependency) and `GET /api/export/devices`
  (`risk_level`), `format=csv|json`. `app/services/export.py`: keyset pages of 1 000 rows,
  each in its own session, up to an id fixed at request time (DB outage → 503 before
  streaming; later rows excluded); oldest first; CSV = RFC 4180, UTF-8 with BOM,
  formula-like cells prefixed with `'`; JSON = one array in 1 000-item chunks. Dashboard:
  *Download CSV / JSON* on the feed (follows the risk filter) and the Devices tab.
  40 new tests (`tests/test_export.py` 39, dashboard 1), mutation-checked; bounded
  memory measured on a real server.

- **17c Retention by age + device consistency (session 17, ADR-028):**
  `HOUND_RETENTION_DAYS` (1–3650, unset = off) besides the row limit. `EventRepository.prune`
  tallies deleted rows per device (`PruneResult`); `DeviceRepository.forget` subtracts them
  and deletes devices with no stored event left — one transaction. Retention runs from
  `SqlEventStore.prune_if_due()` via the worker's `housekeep()` (start, every 50 batches,
  every 5 min, also when idle), no longer inside `save()` — which fixed a pre-existing
  bug where a failed prune reported a stored batch as lost. Metrics:
  `storage.retention_days`, `retention_pruned_devices`. 20 new tests
  (`tests/test_retention.py`), mutation-checked.

- **16f Real geolocation (session 18, ADR-029, owner request):** DB-IP "IP to Country
  Lite" (`.mmdb`, CC BY 4.0) read with `maxminddb` (new dependency); downloaded
  automatically at start and monthly by `GeoIpUpdater` (HTTPS to download.db-ip.com only,
  size caps, validation, atomic install, hot swap under the batch lock);
  `python run.py geo status|update`; `reload` picks up new files; `HOUND_GEO_MODE=auto`
  (default): no invented countries in live use; countries API `source` + credit;
  dashboard credit link; `doctor` *Geolocation* check; all ISO country names;
  `.env.example` no longer pins `simulated`. 42 new tests (`tests/test_geoip.py` 41,
  dashboard 1), mutation-checked. Field-trial procedure written: `docs/FIELD_TRIAL.md`.

- **16g Capture restarts itself (session 19, ADR-030):** `PacketCaptureService` relaunches
  a sniffer that ends while running (interface down/gone — Scapy ends quietly), state
  `restarting`, interface list re-read each attempt, same filter mode, retry 1→60 s until
  stopped; `restarts`/`downtime_seconds` in `SourceStatus`, the daemon report
  (`capture_restarts`, `capture_downtime_seconds`) and `/api/metrics`; dashboard
  *Reconnecting*; the daemon exits only on start-up failures. 6 new tests (capture 5,
  daemon 1) plus a dashboard assertion; verified with real Scapy on a veth interface and
  a real server + daemon.

## 4. In progress
- Nothing.

## 5. Next (in order — only the first is "the next task")
1. **17d Periodic `PRAGMA optimize`** (engineering, unblocked): run it from the
   housekeeping hook (start + hourly) and measure `/api/stats`, coverage and export
   queries at 250 k rows before/after.
2. **Owner, before the trial:** install the new zip, `pip install -r requirements.lock`
   (new `maxminddb`), **remove `HOUND_GEO_MODE=simulated` from `.env`**, start the server
   once and check `python run.py geo status` — the first real DB-IP download. Then
   `pytest` (expect 516 passed, 5 skipped on Windows).
3. **16d field trial** (owner, week of 2026-10-05) — follow `docs/FIELD_TRIAL.md`.
4. Test debt: close the SQLite connections in `tests/test_migrations.py` helpers (§7).

## 6. Blocked / needs owner input
| Item | Needed | Blocks |
|---|---|---|
| First real DB-IP download | The owner's machine (the dev sandbox cannot reach download.db-ip.com) | confirming 16f end to end |
| Field trial | A monitoring position that sees household traffic (router, mirror port or DNS host); owner plans it for the week of 2026-10-05 | M7 |
| Benchmark re-run on Windows | `python scripts/benchmark.py` once more, to confirm the peak-memory fix (Windows-only code path, untested here) | nothing (informational) |

## 7. Technical debt

**Critical**
- None open. (Schema versioning — the previous critical item — was resolved by 14.2.)

**Important**
- Locked versions only move when someone re-locks; the audit job and the non-blocking
  newest-versions CI job are the signals (both inert until the project is on GitHub).

**Nice-to-have**
- A first age prune after enabling `HOUND_RETENTION_DAYS` on a large database holds the
  worker for up to ~0.5 s per 75 k rows (measured); the queue buffers meanwhile. Fine at
  current sizes; chunk the delete only if a field trial shows queue pressure.
- A device's risk resets only after its window expires *and* it sends a new event, so a
  silent device keeps its last level. The UI caption doesn't explain this; revisit in 16.
- Backups accumulate in `data/backups/` (no rotation or pruning yet).
- An export of 250 k rows occupies one API thread-pool worker for ~20 s; several at
  once would slow other requests. Fine for one local user; revisit only with evidence.
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
- `tests/test_migrations.py` helpers open SQLite with `with sqlite3.connect()` (commits,
  does not close): ~30 `ResourceWarning`s on Py 3.13. Same pattern that broke the backup
  test on Windows (s13); the Windows run passes today, but it should get `closing()`.
- The dashboard's *Devices* tile counts every address in the device table; the coverage
  check counts only local IPv4 addresses from the last 24 h. Both are correct for what
  they say, but the two numbers can differ; the coverage dialog states its own basis.
- The test suite now takes ~35–60 s here (525 tests): dashboard ~14 s, daemon ~4.5 s, doctor ~3 s (2 s
  of it is the port-probe timeout against a silent listener).
  Acceptable; if it keeps growing, add an opt-in `slow` marker for the UI/daemon files.
- The dashboard tests call a few private methods (`_load_stats`, `_stats_tick`,
  `_render_pipeline`, `_slow_tick`, `_load_coverage`) to avoid waiting on 2–60 s UI timers. Cheap to maintain; if the page
  is refactored, prefer injectable intervals.
- The dashboard tests depend on `nicegui.testing.user_simulation` (NiceGUI ≥ 2.x API).
  A NiceGUI major upgrade may need harness changes; the lock file (14.3a) pins it.

**Future**
- Package named `app` (ADR-011) → rename before publishing a wheel (Phase 21).
- Risk-engine state is in memory and resets on restart (windows ≤ minutes; by design).
- Migrations are hand-written SQL; SQLite needs the table-rebuild pattern for most column
  changes (ADR-018).

## 8. Known limitations (product)
- Countries are approximate: DB-IP Lite, country level (DB-IP states ~81 % accuracy);
  anycast/VPN/cloud addresses show where they are registered. *Unknown* until the first
  download succeeds; simulated only in demo mode.
- Capture recovery (ADR-030) is verified on Linux only; on Windows/Npcap, whether sleep
  ends the capture (and how it resumes) is observed first in the field trial. While
  the split-mode daemon is reconnecting the dashboard cannot show it (its reports ride
  on event batches); `/api/metrics` shows restarts and downtime once it resumes.
- Hound makes one outbound HTTPS request per month (download.db-ip.com) unless
  `HOUND_GEOIP_AUTO_UPDATE=false`.
- Only traffic visible to the capture interface is seen (switched/Wi-Fi networks); what
  each deployment position sees is now stated in the product (ADR-026). The coverage
  check is a heuristic: VMs, containers and inbound connections add addresses, and a
  router forwarding DNS hides devices from a DNS-server position.
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
- Exports: a CSV cut short by a database error mid-download looks complete (only the
  server log says "Export interrupted"; a cut JSON file fails to parse). Semicolon-locale
  Excel needs *Data → From Text/CSV* to split the comma-separated columns.

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
