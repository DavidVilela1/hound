# Hound — Project Status

> Answers: *where are we, what works, what is missing, what blocks us, what is next.*
> Update this file at the end of every task. Plan: [`ROADMAP.md`](ROADMAP.md) ·
> Architecture: [`ARCHITECTURE.md`](ARCHITECTURE.md) · Decisions: [`DECISIONS.md`](DECISIONS.md)

```text
Last updated:      2026-09-28
Current milestone: M6 — Production-quality local build   (M0–M5 reached, M2 on Linux only)
Current phase:     Phase 14 — Release hardening
Current task:      none in progress
Next task:         14.1 Cross-platform verification & CI (Windows first)
Overall state:     Working system, verified on Linux. Not yet verified on Windows,
                   which is the owner's platform.
```

## 1. Baseline assessment (verified 2026-09-28)

```text
AREA            STATUS          NOTES
------------------------------------------------------------------------------------------
Architecture    VERIFIED        Layered modular monolith; module-import check clean; ADR-001..016
Ingestion       VERIFIED*       Parser/capture/daemon/demo; live capture on Linux lo only.
                                Daemon has 0% automated coverage (manually verified)
Event model     VERIFIED        Frozen Pydantic NetworkEvent; used by all sources
Backend         VERIFIED        Worker thread, retention, error isolation, broadcaster
Database        NEEDS_REFACTOR  Works (WAL, indexes, retention) but has no schema versioning
Enrichment      VERIFIED        Blocklist (suffix matching), simulated geo, DNS correlation
Risk engine     VERIFIED*       13 deterministic signals; not yet tuned on real traffic
Frontend        FUNCTIONAL      All views work (manual Playwright check); 0% automated tests
Testing         FUNCTIONAL      207 tests, 79% line coverage, Linux only; 2 assertions will
                                fail on Windows (path separators)
Configuration   VERIFIED        HOUND_* env/.env/CLI, validated; .env.example parses
Security        FUNCTIONAL      Least privilege, loopback, Host/Origin checks, token ingest;
                                Windows token-file permissions and data/ modes open (S-6, S-8)
Documentation   FUNCTIONAL      README complete; Windows interface-naming text is wrong (README §9)
Packaging       IN_PROGRESS     requirements ranges + pyproject; no lock file, CI, LICENSE,
                                CHANGELOG; version says 1.0.0 before any release
```
`*` = verified with the caveat in the notes.

## 2. Verification log

| Date | Check | Platform | Result |
|---|---|---|---|
| 2026-09-28 | `python -m compileall app tests scripts run.py` | Linux, Py 3.11.15 | pass |
| 2026-09-28 | `ruff check` (E,F,W,B,UP,I) / `mypy app` | Linux | clean / clean (58 files) |
| 2026-09-28 | `pytest` | Linux | 207 passed, 79 % line coverage |
| 2026-09-28 | `scripts/smoke_test.py` (demo → DB → API → dashboard → WS) | Linux | 12/12 |
| 2026-09-28 | Fresh venv from `requirements.txt` + pytest + smoke | Linux | pass (uvicorn 0.54 resolved) |
| 2026-09-28 | `pip-audit -r requirements.txt` | Linux | no known vulnerabilities |
| 2026-09-28 | Live capture, split mode (server as `nobody`, daemon root, `lo`) | Linux | DNS + SYN captured; blocklist hit flagged |
| 2026-09-28 | Live capture, all-in-one; unprivileged → clear error, server stays up | Linux | pass |
| 2026-09-28 | Dashboard via Playwright (live updates, dialogs, filters, dark, 390 px) | Linux Chromium | pass, no console errors |
| 2026-09-28 | Throughput/latency benchmark (see ROADMAP §I) | Linux sandbox | ≈ 5 400 events/s processing; `/api/stats` 71 ms @ 250 k rows |
| — | Anything on **Windows** or **macOS** | — | **not run** |

## 3. Completed
- Phases 0–13 of the original plan (see ROADMAP §F): capture, parsing, queue,
  processing, enrichment, risk engine, SQLite, REST API, WebSocket, dashboard, demo
  mode, capture daemon with token ingest, CLI, README, 207 tests, smoke test.
- Fixes found during live testing: capture-daemon feedback loop on loopback; duplicate
  frames on Linux `lo` (ADR-014).
- Planning baseline: `docs/ARCHITECTURE.md`, `docs/DECISIONS.md`, `docs/ROADMAP.md`, this file.

## 4. In progress
- Nothing. (Phase 14 has not started.)

## 5. Next (in order — only the first is "the next task")
1. **14.1 Cross-platform verification & CI** — CI matrix (Linux/Windows/macOS ×
   Py 3.11/3.13) with ruff, mypy, pytest, smoke test, pip-audit; fix the Windows path
   assertions in `tests/test_config.py`; accept `\Device\NPF_{…}` names; correct README §9;
   document Windows token-file protection.
2. 14.2 Schema versioning & migrations.
3. 14.3 Reproducible installs & release hygiene.
4. 14.4 Automated coverage for daemon and dashboard.

## 6. Blocked / needs owner input
| Item | Needed | Blocks |
|---|---|---|
| CI | A GitHub repository for the project (or: owner runs `pytest` on Windows and shares output) | full acceptance of 14.1 |
| License | Choose a license (e.g. MIT, Apache-2.0, GPL-3.0, or "all rights reserved") | 14.3 |
| Version label | Keep `1.0.0` or re-label `0.9.0` until M6 | 14.3 |
| Field trial | A monitoring position that sees household traffic (router, mirror port or DNS host) | M7 |

## 7. Technical debt

**Critical** (must be fixed before the thing it blocks)
- No schema versioning (ADR-015). *Why accepted:* first release, no user data. *Consequence:*
  any schema change breaks existing DBs. *Revisit:* 14.2, before any schema change.
- Unverified on Windows; 2 test assertions expected to fail there. *Revisit:* 14.1.

**Important**
- `dashboard.py`/`components.py` and `daemon.py` have 0 % automated coverage → 14.4.
- No lock file; installs resolve newest compatible versions → 14.3.
- README §9 Windows interface-naming statement is incorrect → 14.1.
- Ingest token file relies on POSIX `0600`; on Windows only profile ACLs protect it → 14.1 (S-6).
- `data/` and the DB file use default permissions (browsing metadata) → 14.2 (S-8).

**Nice-to-have**
- Device risk only resets when the device sends a new event after its window expires
  (a silent device keeps its last level). The UI caption does not explain this; revisit in 16.
- `devices` rows are never expired; counters are lifetime totals even after event
  retention prunes old events → 17.
- `/api/stats` uses `COUNT(*)` scans (71 ms at the 250 k cap) → only if metrics show need.
- Forwarder opens one TCP connection per batch (no keep-alive) (ADR-016) — fine at
  current cadence.
- `cli.py` 52 % and `logging_config.py` 40 % coverage.

**Future**
- Package named `app` (ADR-011) → rename before publishing a wheel (Phase 21).
- Risk-engine state is in memory and resets on restart (windows ≤ minutes; by design).

## 8. Known limitations (product)
- Country data is **simulated** (ADR-008).
- Only traffic visible to the capture interface is seen (switched/Wi-Fi networks).
- Default BPF catches IPv4 SYNs only; IPv6 clause documented, not default.
- Encrypted DNS (DoH/DoT/DoQ) hides domain names.
- Risk levels are heuristics, not malware detection; not yet tuned on real traffic.
- Devices are identified by IP address.
- Single process, single user, localhost only; no dashboard authentication.
- Live capture verified on Linux only.

## 9. How to verify this file is still true
```bash
python -m compileall -q app tests scripts run.py
ruff check app tests scripts run.py && mypy app --ignore-missing-imports
pytest
python scripts/smoke_test.py
```
If any result differs from §2, update this file before starting new work.
