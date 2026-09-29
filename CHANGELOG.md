# Changelog

All notable changes to Hound are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions will follow
[Semantic Versioning](https://semver.org/) once the first release is tagged.

No version has been released yet. `pyproject.toml` says `1.0.0`, but whether the
first release is called `1.0.0` or `0.9.0` is an open owner decision (roadmap 14.3b).
Until then everything is listed under **Unreleased**.

## [Unreleased]

### Added
- **Reload without restart**: `python run.py reload` (token-authenticated
  `POST /api/admin/reload`) re-reads the blocklist, allowlist and risk settings and
  applies them between two batches; all or nothing, and learned DNS answers and device
  behaviour are kept (ADR-023).
- **Risk settings file** (`config/risk.toml`, `HOUND_RISK_CONFIG_PATH`): every weight and
  threshold of the risk engine in one commented TOML file (stdlib `tomllib`), strictly
  validated; explicitly set `HOUND_RISK_*` values override it; an invalid file stops the
  server with one clear line; `doctor` checks it (ADR-022).
- **Allowlist** (`config/allowlist.txt`, `HOUND_ALLOWLIST_PATH`): domains and devices
  (IP or CIDR) whose indicators are not counted. Suppressed indicators stay visible in a
  0-point `ALLOWLISTED` reason; an allowlisted device's blocklist hits still count
  (ADR-021).
- **`scripts/benchmark.py`**: reproducible throughput and latency measurement on a
  temporary database (dissection, parsing, processing at several batch sizes, API
  latency at a chosen database size, storage per event, peak memory), text or JSON.
- **`GET /api/metrics`**: events lost per pipeline stage (daemon queue, daemon delivery,
  server queue, processing) with a total, plus queue peak, batch latency p50/p95, ingest
  rejections by reason, WebSocket drops, database size and retention pruning. The capture
  daemon now sends its own counters with each batch (optional `daemon` field on
  `POST /api/ingest`), so split-mode losses are visible on the server (ADR-020).
- **`python run.py doctor [-i IFACE]`**: a read-only environment check (Python, packages
  vs. the lock, Npcap/libpcap, privileges, interface, bind address, port, cloud-synced
  data folder, database schema, ingest token) that names the fix for each problem; exit
  status 1 when something would stop Hound from working.
- **Dependency lock files** `requirements.lock` and `requirements-dev.lock`: exact
  versions with SHA-256 hashes, one file for Windows, macOS and Linux on Python 3.11+.
  CI installs the lock; a non-blocking CI job tries the newest versions the ranges allow.
  A test keeps the locks consistent with `requirements*.txt` (ADR-019).
- This changelog.
- **Automated dashboard tests** (12) using NiceGUI's user simulation against the real API,
  covering rendering, live updates, filters, pause, dialogs, the "API unreachable" banner
  and recovery, and mounting.
- **Capture daemon tests**: split mode end to end without privileges (fake sniffer → real
  parser → daemon → forwarder → live server → database), exit codes, API outage and
  recovery, proxy settings; a deterministic parser fuzz test (2 400 random, mutated and
  truncated frames).
- `CaptureDaemon.stop()` for tests and future service wrappers.
- **Database schema versioning**: version stored in `PRAGMA user_version`, ordered
  migrations applied atomically at start-up; databases from earlier builds are adopted
  when their structure matches exactly (ADR-018).
- Windows: interfaces can also be selected by Npcap device name (`\Device\NPF_{…}`).
- CI workflow (GitHub Actions: Linux, Windows, macOS × Python 3.11 and 3.13, plus a
  dependency audit) and `requirements-dev.txt` with ruff, mypy and pip-audit (ADR-017).

### Changed
- `.env.example` now keeps the `HOUND_RISK_*` variables commented out: copying it to
  `.env` no longer pins every risk value (which would override `config/risk.toml`).
- `python run.py doctor` prints only warnings/errors from the log, not INFO lines.
- Installation instructions use `pip install -r requirements.lock`;
  `requirements.txt` remains the list of supported version ranges.
- README Windows venv command uses `py -3` (any installed Python 3.11+) instead of
  `py -3.11`, which failed on machines without exactly 3.11.
- A database the running code cannot use (newer version, or not a Hound database) now
  stops `serve` with one clear error line and exit code 2, before the web server starts.
- Lint and type-check settings moved into `pyproject.toml`, so local runs match CI.

### Fixed
- The database path was built into a URL without encoding, so a project folder whose
  name contains `%XX` (e.g. `%20`) or `?` put the database in a different folder (Linux)
  or failed to open it (Windows). Found by the owner's Windows test run.
- The capture daemon honoured `HTTP(S)_PROXY` for its calls to the local API, so behind
  a proxy no events were delivered. It now always connects directly.
- Administrator detection on Windows (`_is_privileged()` always returned false).
- A test that depended on the host's network routes failed on some Windows machines;
  all test packets now use explicit addresses and the suite never consults host routes.
- Five issues reported by mypy 2.x (e.g. positional Pydantic `Field` defaults).

### Security
- Dependencies are installed hash-checked from the lock files, and CI audits the exact
  locked versions for known vulnerabilities.
- On Linux/macOS the data directory is created owner-only (`0700`), and the database and
  its `-wal`/`-shm` files are restricted to the owner (`0600`).

## Initial build (not released; labelled 1.0.0)

The first complete version: packet capture (Scapy, BPF for DNS and TCP SYN) with a
bounded queue; a privilege-separated capture daemon that forwards to the unprivileged
server with a token; enrichment (blocklist, simulated geolocation, DNS correlation); a
deterministic, explainable risk engine (SAFE / SUSPICIOUS / DANGEROUS); SQLite storage
with retention; a FastAPI REST API with filters and pagination, OpenAPI docs and a
WebSocket event stream; a NiceGUI dashboard; a demo mode through the same pipeline; a
test suite needing no root or real traffic; and the README.
