# Hound — Project Status

> Answers: *where are we, what works, what is missing, what blocks us, what is next.*
> Update this file at the end of every task. Plan: [`ROADMAP.md`](ROADMAP.md) ·
> Architecture: [`ARCHITECTURE.md`](ARCHITECTURE.md) · Decisions: [`DECISIONS.md`](DECISIONS.md)

```text
Last updated:      2026-09-28 (session 3: task 14.2 schema versioning)
Current milestone: M6 — Production-quality local build   (M0–M5 reached, M2 on Linux only)
Current phase:     Phase 14 — Release hardening (14.1 done for Windows, 14.2 done)
Current task:      none in progress
Next task:         14.4 Automated coverage for the capture daemon and dashboard
Overall state:     Working system with a versioned, upgrade-safe database. Tests and the demo
                   smoke test pass on Linux (Py 3.11 + 3.13); owner's Windows laptop was green
                   before this session's change and has not been re-run since. Not yet
                   exercised: live capture on Windows, macOS, the GitHub CI workflow.
```

## 1. Baseline assessment

```text
AREA            STATUS          NOTES
------------------------------------------------------------------------------------------
Architecture    VERIFIED        Layered modular monolith; module-import check clean; ADR-001..018
Ingestion       VERIFIED*       Parser/capture/daemon/demo; live capture on Linux lo only.
                                Accepts Windows NPF interface names. Daemon 0% automated coverage
Event model     VERIFIED        Frozen Pydantic NetworkEvent; used by all sources
Backend         VERIFIED        Worker thread, retention, error isolation, broadcaster
Database        VERIFIED        WAL, indexes, retention; schema v1 in PRAGMA user_version with
                                ordered atomic migrations (ADR-018); owner-only files on POSIX
Enrichment      VERIFIED        Blocklist (suffix matching), simulated geo, DNS correlation
Risk engine     VERIFIED*       13 deterministic signals; not yet tuned on real traffic
Frontend        FUNCTIONAL      All views work (manual Playwright check); 0% automated tests
Testing         FUNCTIONAL      225 tests, 80% line coverage; all pass on Linux (Py 3.11 + 3.13);
                                Windows green at 209 tests (before 14.2); isolated from host routing
Configuration   VERIFIED        HOUND_* env/.env/CLI, validated; .env.example parses
Security        FUNCTIONAL      Least privilege, loopback, Host/Origin checks, token ingest;
                                S-6 (Windows token) documented; S-8 (DB file modes) done
Documentation   FUNCTIONAL      README covers upgrades/refusals; Windows guidance owner-checked
Packaging       IN_PROGRESS     CI workflow + requirements-dev.txt; no lock file, LICENSE,
                                CHANGELOG; version says 1.0.0 before any release
```
`*` = verified with the caveat in the notes.

## 2. Validation log

| Date | Check | Platform | Result |
|---|---|---|---|
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
| — | 14.2 code on Windows (pytest + smoke) | Windows | **not run yet** |
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

## 4. In progress
- Nothing.

## 5. Next (in order — only the first is "the next task")
1. **14.4 Automated coverage for the capture daemon and dashboard.** `daemon.py`,
   `dashboard.py` and `components.py` have 0 % automated coverage; also fold the smoke test
   into pytest (opt-in marker). Fully unblocked; moved ahead of 14.3 (see ROADMAP).
2. 14.3 Reproducible installs & release hygiene: lock file, CHANGELOG, plus LICENSE and
   version label once decided.
3. When the project is on GitHub: confirm the CI run (macOS coverage).

## 6. Blocked / needs owner input
| Item | Needed | Blocks |
|---|---|---|
| Windows re-run | `pytest` and `python scripts\smoke_test.py` with this update | confirming 14.2 on Windows |
| License | Choose a license (e.g. MIT, Apache-2.0, GPL-3.0, or "all rights reserved") | 14.3 |
| Version label | Keep `1.0.0` or re-label `0.9.0` until M6 | 14.3 |
| CI on GitHub | Push the project to a GitHub repository | macOS verification; automatic checks on every change |
| Windows live capture | Install Npcap, then `python run.py capture -i "Wi-Fi"` from an Administrator shell with the server running | M2 on Windows |
| Field trial | A monitoring position that sees household traffic (router, mirror port or DNS host) | M7 |

## 7. Technical debt

**Critical**
- None open. (Schema versioning — the previous critical item — was resolved by 14.2.)

**Important**
- CI workflow never executed and macOS never tested → first push to GitHub.
- Live capture never run on Windows (the owner's platform) → owner test with Npcap.
- `dashboard.py`/`components.py` and `daemon.py` have 0 % automated coverage → 14.4 (next).
- No lock file. Runtime installs and dev tools resolve to the newest compatible
  versions; mypy 2.x already changed results once → 14.3.

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
- `cli.py` 66 % and `logging_config.py` 40 % coverage.

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
