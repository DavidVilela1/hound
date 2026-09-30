# Hound — Architecture Decision Records

Lightweight ADRs for decisions that materially shape the project. Trivial implementation
details are not recorded here. Status values: **Accepted**, **Accepted (debt)** = an
intentional shortcut with a revisit trigger, **Superseded by ADR-NNN**, **Proposed**.

New decisions are appended with the next number; accepted ADRs are never edited except to
change their status or add a "Revisited" note.

| # | Decision | Status |
|---|---|---|
| 001 | Modular monolith in one repository, one server process | Accepted |
| 002 | Privilege separation: capture daemon forwards to the API | Accepted |
| 003 | SQLite (WAL) with a single writer thread | Accepted |
| 004 | Bounded queue between capture and processing, drop-on-full | Accepted |
| 005 | Threads for capture/processing, asyncio for API/UI | Accepted |
| 006 | WebSocket push with REST polling fallback | Accepted |
| 007 | Dashboard is an API client (NiceGUI mounted on the same server) | Accepted |
| 008 | Simulated geolocation behind a `GeoLocator` protocol | Superseded for live use by ADR-029 |
| 009 | Additive, deterministic, explainable risk scoring | Accepted |
| 010 | `HOUND_` prefix for all environment variables | Accepted |
| 011 | Package named `app`; entry points `run.py`, `python -m app`, `hound` | Accepted (debt) |
| 012 | One Pydantic `NetworkEvent` as the contract for every source | Accepted |
| 013 | DNS responses feed state but are not stored as events | Accepted |
| 014 | Loopback de-duplication and self-traffic filtering in capture | Accepted |
| 015 | Schema via `create_all`, no migrations yet | Superseded by ADR-018 |
| 016 | Stdlib-only HTTP forwarding in the privileged daemon | Accepted |
| 017 | CI on GitHub Actions; dev tools in `requirements-dev.txt`, config in `pyproject.toml` | Accepted |
| 018 | Versioned SQLite schema: frozen baseline + ordered atomic migrations | Accepted |
| 019 | Hash-checked, universal lock files generated with uv; CI installs the lock | Accepted |
| 020 | Pipeline metrics as in-process JSON; the daemon reports its counters inside ingest batches | Accepted |
| 021 | Allowlist: suppressed indicators stay visible; device entries never hide blocklist hits | Accepted |
| 022 | Risk settings in a strict TOML file; explicitly set environment values override it | Accepted |
| 023 | Reload detection settings via a token-protected endpoint; all-or-nothing swap between batches, learned state kept | Accepted |
| 024 | Backups via SQLite's online backup API; restore validates and moves the current database aside | Accepted |
| 025 | MIT licence; first release labelled 1.0.0 | Accepted |
| 026 | Deployment position chosen by the owner; Hound is explicit about what each position can see | Accepted (principle; implementation 16e) |

---

## ADR-001 — Modular monolith, one server process
* **Context:** single developer, local-only tool, must be easy to run (`python run.py`).
* **Options:** microservices (capture/API/UI as services); one process with clear packages.
* **Chosen:** one repository, packages per layer (`ingestion`, `services`, `api`,
  `frontend`, …), one server process; the only extra process is the optional capture
  daemon (ADR-002).
* **Reason:** operational simplicity; layers still communicate through interfaces
  (queue, repositories, HTTP/WS for the UI), so a split stays possible.
* **Consequences:** Uvicorn must run with **one worker** — runtime state (queue, risk
  windows, broadcaster) lives in process. Horizontal scaling is out of scope.

## ADR-002 — Privilege separation via an authenticated ingest API
* **Context:** raw capture needs root/Administrator/`CAP_NET_RAW`; running a web server
  and UI with those rights is an unnecessary risk.
* **Options:** run everything privileged; drop privileges after opening the socket
  (POSIX-only, fragile with Scapy threads); separate capture process.
* **Chosen:** `run.py capture` runs capture + parsing only and POSTs normalised events to
  `POST /api/ingest`, authenticated with a random token (auto-created `0600` file or
  `HOUND_INGEST_TOKEN`). All-in-one mode remains for convenience.
* **Reason:** smallest privileged surface; works identically on Linux, macOS and Windows.
* **Consequences:** events cross a localhost HTTP hop (batched; measured throughput far
  above home-network rates); the token file is a secret on disk (Windows ignores POSIX
  modes — see security roadmap S-6). Verified: server as `nobody` + daemon as root.

## ADR-003 — SQLite in WAL mode with a single writer
* **Context:** local persistence, zero setup, concurrent API reads during writes.
* **Options:** SQLite; PostgreSQL; embedded time-series stores; flat files.
* **Chosen:** SQLite via SQLAlchemy 2, WAL, `synchronous=NORMAL`, `busy_timeout=5000`;
  only the processing thread writes; API reads use short sessions.
* **Reason:** no server to install, good read concurrency under WAL, SQL for filtering.
* **Consequences:** write throughput bounded by one thread (measured ≈ 5 400 events/s
  batched on the dev sandbox — ample). Aggregate `COUNT` queries grow linearly with rows
  (≈ 71 ms for `/api/stats` at 250 000 rows). Non-SQLite URLs are untested.

## ADR-004 — Bounded queue, drop newest when full
* **Context:** capture callback must never block, or the kernel drops packets
  unpredictably and memory can grow without limit.
* **Options:** unbounded queue; blocking put; bounded with drop-oldest; drop-newest.
* **Chosen:** `queue.Queue(maxsize)` with non-blocking `offer`; overflow is counted and
  exposed (`events_dropped`).
* **Reason:** simplest bounded behaviour with observable loss.
* **Consequences:** under sustained overload the newest events are lost (not
  prioritised). Revisit if drops are ever observed in real use (priority lane for
  blocklist hits).

## ADR-005 — Threads for blocking work, asyncio for I/O-bound serving
* **Context:** Scapy sniffing and SQLite writes are blocking; FastAPI/NiceGUI are async.
* **Chosen:** capture (+ supervisor), processing, demo and forwarder run on dedicated
  daemon threads with stop events; the API/UI run on the asyncio loop; the worker hands
  events to the loop with `call_soon_threadsafe`.
* **Reason:** no async wrappers around inherently blocking libraries; no busy loops.
* **Consequences:** thread-safety discipline: the risk engine and DB writer are touched
  only by the processing thread; shared counters use locks.

## ADR-006 — WebSocket push, polling fallback
* **Context:** the dashboard must update without page reloads and without DB polling.
* **Options:** WebSocket; Server-Sent Events; polling.
* **Chosen:** `/ws/events` with per-client bounded queues and heartbeats; the dashboard
  polls `/api/events` every 5 s only while the socket is down.
* **Reason:** bidirectional-capable, supported natively by Starlette and `websockets`.
* **Consequences:** Origin checks are mandatory (browsers do not apply CORS to WS).

## ADR-007 — Dashboard talks to the backend only through the API
* **Context:** spec forbids UI → SQLite coupling; a remote/separate UI may come later.
* **Options:** NiceGUI calling services in-process; NiceGUI as an API client; Streamlit.
* **Chosen:** NiceGUI (event-driven, websocket-based, native to FastAPI) mounted on the
  same app, using `HoundApiClient` (httpx) and `LiveEventStream` (websockets) against
  `HOUND_API_URL` (default: itself).
* **Reason:** strict layering while keeping one port and one process. Streamlit's
  rerun-the-script model fits live feeds poorly.
* **Consequences:** a loopback HTTP hop per UI refresh; NiceGUI's page registry is
  process-global, so the dashboard can be mounted once per process.

## ADR-008 — Simulated geolocation behind a protocol
* **Context:** must work offline; no bundled commercial data.
* **Chosen:** `GeoLocator` protocol; default `SimulatedGeoLocator` = illustrative CIDR
  table + deterministic hash fallback; `mapping_only` mode available. Output is labelled
  "simulated" in API (`simulated: true`) and UI.
* **Consequences:** country data is not authoritative. A real implementation
  (e.g. GeoLite2) only needs a new class and a branch in `build_geolocator()`.

## ADR-009 — Additive, deterministic, explainable risk scoring
* **Context:** users must understand why something is flagged; no ML, no claims of
  certainty.
* **Chosen:** independent `RiskSignal`s return `RiskReason(code, points, description)`;
  `score = min(100, Σ points)`; SAFE < 25 ≤ SUSPICIOUS < 70 ≤ DANGEROUS (configurable).
  Behaviour windows use event timestamps, so identical input gives identical output.
* **Consequences:** tuning is manual; false positives are expected and must be reviewed on
  real traffic (Phase 16). Wording is always "indicators associated with elevated risk".

## ADR-010 — `HOUND_` environment prefix
* **Context:** spec listed `HOST`, `PORT`, … ; zsh sets `HOST` to the machine name on
  several systems, which could silently bind the API to a LAN-facing address.
* **Chosen:** every variable is `HOUND_<NAME>`; unprefixed variables are ignored (tested).
* **Consequences:** documented mapping table in the README.

## ADR-011 — Package name `app` (debt)
* **Context:** spec required `hound/app/…`.
* **Chosen:** keep `app`; entry points `python run.py`, `python -m app`, `hound` (after
  `pip install -e .`). No `python -m hound` shim.
* **Consequences / debt:** `app` is a generic top-level name that can collide with other
  projects if installed into a shared environment. **Revisit** before publishing a wheel
  (Phase 21): rename to `hound` in one mechanical change with an ADR.

## ADR-012 — One event contract for every source
* **Chosen:** frozen Pydantic `NetworkEvent` (validated IPs, ports, domain, UTC time) is
  produced by the parser, the demo generator (through the parser) and the ingest API.
  Raw Scapy packets never leave `app/ingestion`.
* **Consequences:** validation happens once at the edge; new observation types extend the
  enum rather than creating parallel models.

## ADR-013 — DNS responses are state, not events
* **Chosen:** responses update the IP→domain cache and NXDOMAIN counters; only queries and
  SYNs are stored. SYN-ACKs are ignored.
* **Reason:** avoids double-counting and keeps "events" meaning *device-initiated activity*
  (also the basis for country percentages).
* **Consequences:** DNS answers are not queryable historically.

## ADR-014 — Loopback de-duplication and self-traffic filter
* **Context (found during live testing):** on Linux a raw socket on `lo` sees each frame
  twice; capturing on the interface that carries the daemon's own POSTs created a feedback
  loop (≈ 1 300 events in seconds).
* **Chosen:** identical frames within 0.2 s are dropped on loopback interfaces only; the
  daemon ignores SYNs to the API's own address/port.
* **Consequences:** heuristic; negligible cost off-loopback.

## ADR-015 — Schema via `create_all`, no migrations (debt) — *superseded by ADR-018*
* **Context:** first release, no existing user data to migrate.
* **Chosen:** tables and indexes are created automatically; no versioning.
* **Consequences / debt:** *any* column change would break existing `data/hound.db` files
  or require deleting them. **Revisit trigger: before the first schema change** —
  scheduled as Phase 14 item 14.2 (`PRAGMA user_version` + ordered migration functions;
  Alembic considered heavier than needed for two tables).

## ADR-016 — Stdlib-only HTTP in the privileged daemon
* **Chosen:** the forwarder uses `urllib.request` (scheme restricted to http/https) and an
  injectable transport for tests.
* **Reason:** keep the privileged process's code surface minimal.
* **Consequences:** one TCP connection per batch (no keep-alive); fine at batch cadence.
* **Revisited 2026-09-28 (14.4a):** plain `urlopen` honours `HTTP(S)_PROXY` (and Windows'
  system proxy), so on a machine with a proxy and no `NO_PROXY` exception the daemon sent
  every batch to the proxy and delivered nothing. Found by a new test run in a fresh
  process; fixed with a module-level opener built with `ProxyHandler({})` for all
  daemon → API traffic. Decision unchanged (stdlib only); the local channel never uses
  proxies, matching the dashboard's clients.

## ADR-017 — CI on GitHub Actions; dev tooling declared in the repo
* **Context:** the owner develops on Windows, but everything had only ever run on Linux.
  Lint/type/audit tools (ruff, mypy, pip-audit) were used during development but not
  declared anywhere, and their settings lived in command-line flags.
* **Options:** no CI (manual runs per OS); GitHub Actions; other CI services; tox/nox.
* **Chosen:** `.github/workflows/ci.yml` — matrix Linux/Windows/macOS × Python 3.11/3.13
  running compileall, ruff, mypy, pytest and the demo smoke test, plus a `pip-audit` job.
  Tools are declared in `requirements-dev.txt` (includes `requirements.txt`); their
  settings live in `pyproject.toml` (`[tool.ruff.lint]`, `[tool.mypy]`) so a bare
  `ruff check` / `mypy` locally equals CI. No tox/nox: one requirements file and plain
  commands are enough for a single developer.
* **Reason:** the only practical way to execute the suite on Windows and macOS; free for
  public repos; no new runtime dependency.
* **Consequences:** tool ranges (`mypy<3`, `ruff<1`) can pull stricter releases — already
  observed when mypy 2.x flagged 5 issues that 1.x accepted. Mitigation: fix forward;
  the lock file (14.3) will make CI reproducible. Requires the project to be hosted on
  GitHub; until then the workflow is inert.
* **Revisited (2026-09-28):** the lock file exists now (ADR-019); the test matrix installs
  `requirements-dev.lock`, and the unpinned ranges run in a separate non-blocking job.

## ADR-018 — Versioned SQLite schema: frozen baseline + ordered atomic migrations
* **Context:** ADR-015's trigger fired — schema changes are coming (device identity, alerts)
  and the owner now has real `data/hound.db` files that must survive upgrades.
* **Options:** Alembic; keep `create_all` and add ad-hoc `ALTER`s; a small in-repo runner
  on `PRAGMA user_version`.
* **Chosen:** `app/database/migrations.py`. The version lives in `PRAGMA user_version`.
  Version 1 is the frozen DDL Hound 1.0.0 created; later versions are appended
  `Migration(n, description, apply)` steps. **Every** database (new or old) goes through
  the same ordered steps — no `create_all` shortcut for SQLite — each in a
  `BEGIN IMMEDIATE` transaction that also bumps the version, with the version read inside
  the transaction (safe if two processes start together). Pre-versioning databases
  (`user_version` 0 with tables) are adopted as v1 only if their structure matches the
  baseline exactly; a database newer than the code, or a non-Hound file, is refused
  without modification. A test asserts the migrated schema equals the ORM models, so
  `tables.py` and the migrations cannot drift apart silently. The CLI checks the database
  before starting the web server so refusals are a one-line message (exit code 2).
* **Reason:** Alembic brings a dependency, a config directory and an autogenerate workflow
  for two tables; SQLite's transactional DDL makes a ~240-line module (half of it the frozen DDL and docs) fully atomic.
  Verified: DDL and `user_version` roll back together (SQLite 3.45).
* **Consequences:** writing a migration is manual SQL (SQLite's limited `ALTER TABLE` means
  a table rebuild for most column changes). Non-SQLite URLs still use `create_all` without
  versioning (untested, ADR-003). On POSIX, the DB directory is created `0700` and the DB,
  `-wal` and `-shm` files are tightened to `0600` (roadmap S-8).

## ADR-019 — Hash-checked universal lock files; CI installs the lock
* **Context:** `requirements*.txt` hold version ranges, so every install (and CI) resolved
  to whatever was newest that day. That already changed results once (mypy 2.x) and made
  "CI passed" hard to reproduce. The owner installs on Windows; CI covers three OSes and
  two Python versions.
* **Options:** `pip freeze` from one machine (platform-specific, misses Windows-only
  packages); `pip-compile` from pip-tools (one lock per OS/Python); `uv pip compile
  --universal` (one lock for all platforms, environment markers where they differ); a
  full project manager (Poetry/PDM/`uv.lock`), which would change how everyone installs.
* **Chosen:** keep `requirements.txt` / `requirements-dev.txt` as the declared ranges and
  generate `requirements.lock` / `requirements-dev.lock` with `uv pip compile --universal
  --python-version 3.11 --generate-hashes` (the dev lock constrained by the runtime lock,
  so shared pins are identical). Installing needs only plain pip; uv is a maintainer tool
  for regenerating, not a dependency. CI's test matrix installs `requirements-dev.lock`
  (hash-checked); the audit job audits both locks; a non-blocking job installs the newest
  versions the ranges allow as an early warning. `tests/test_dependency_locks.py` fails if
  a lock drifts from its ranges, loses hashes, or the two locks disagree.
* **Reason:** one lock for every OS/Python keeps the repo simple; hashes turn "same
  versions" into "same bytes" (supply-chain integrity, roadmap S-10); plain pip keeps the
  owner's install instructions unchanged apart from the filename.
* **Consequences:** security fixes arrive only when someone re-locks (the audit job and
  the non-blocking newest-versions job signal when); regeneration needs network access and
  uv; `--universal` relies on uv's marker resolution — verified on 2026-09-28 by resolving
  the lock binary-only for Windows, macOS (x86-64/arm64) and Linux on Python 3.11–3.14.

## ADR-020 — In-process JSON metrics; daemon counters ride on ingest batches
* **Context:** a field trial must answer "did we lose anything, and where?" (ROADMAP
  Phase 15). Loss can happen in two processes: the capture daemon (local queue full,
  delivery given up) and the server (queue full, processing/database failures). The
  daemon's counters were only in its own log, invisible from the server.
* **Options:** Prometheus client + scrape endpoint (new dependency, needs a scraper the
  owner doesn't run); a separate daemon → server heartbeat endpoint (second channel,
  more auth surface); counters piggy-backed on the batches the daemon already POSTs.
* **Chosen:** `GET /api/metrics` returns plain JSON built by `HoundRuntime.metrics()` from
  counters the components already keep, plus a few new ones (queue high-water mark,
  batch count + latency window of 1 000 batches, ingest outcomes, retention pruned,
  DB/WAL size). `loss.total_events_lost` sums the stages; WebSocket drops and retention
  pruning are reported but not counted as loss (stored data is unaffected / deliberate).
  The daemon adds an optional, strictly validated `daemon` object (non-negative bounded
  integers, no unknown fields) to each authenticated ingest request; the server keeps the
  latest one with its arrival time.
* **Reason:** no dependency, no new endpoint to secure, works in both run modes; the
  report travels only when the daemon can reach the server anyway — which is exactly when
  it can be shown.
* **Consequences:** counters are in memory and reset on restart; while the API is down,
  the daemon's latest losses are shown only after its next successful delivery
  (`received_at` shows staleness); one report slot, so several daemons at once would
  overwrite each other (single-daemon design, ADR-002). An older server rejects the new
  field, so daemon and server must be the same version (they run from one checkout).

## ADR-021 — Allowlist semantics: visible suppression; devices never hide blocklist hits
* **Context:** the field trial will produce known false positives (CDN hostnames tripping
  the entropy signal, the owner's own devices that scan or connect a lot). The owner
  needs a way to say "I checked this" without weakening detection elsewhere.
* **Options:** (a) drop allowlisted events entirely; (b) keep them but cap the level at
  SAFE while keeping the score; (c) remove covered indicators from the score and record
  them in one 0-point reason; for devices: (i) cover everything, or (ii) cover
  behaviour only.
* **Chosen:** (c) + (ii). A domain entry covers every indicator of the event (an explicit
  decision about that name, overriding a blocklist entry above it). A device entry
  covers behavioural indicators only — `BLOCKLISTED_DOMAIN` still counts. The file
  (`config/allowlist.txt`, optional, `HOUND_ALLOWLIST_PATH`) is loaded at start;
  single-label entries are rejected, wide ranges logged. Stored as a normal reason in
  the existing `risk_reasons` JSON — no schema change.
* **Reason:** (a) would hide activity and break counts; (b) makes score and level
  disagree and still raises device risk; (c) keeps score, level and device aggregates
  consistent while every suppressed indicator stays visible. Device-wide trust that also
  silenced blocklist hits would blind Hound to exactly the case that matters most — a
  trusted device that gets compromised.
* **Consequences:** behaviour tracking still records allowlisted traffic (windows are
  unchanged); reload needs a restart until 16c; destination-based entries (e.g. "any
  device → my NAS on port 445") are not supported yet.

## ADR-022 — Risk settings file: strict TOML, environment overrides, refuse on error
* **Context:** tuning during the field trial needs every weight and threshold adjustable
  without editing code. Thresholds and lists were already `HOUND_RISK_*` settings;
  weights and domain heuristics were code only.
* **Options:** more environment variables (≈ 25 more, flat, no structure); a TOML file
  read with stdlib `tomllib`; YAML/JSON (a dependency, or no comments).
* **Chosen:** `config/risk.toml` (`HOUND_RISK_CONFIG_PATH`), sections `levels`,
  `behaviour`, `domains`, `ports`, `dns`, `weights`, parsed into Pydantic models with
  `extra="forbid"` and range checks. Precedence: defaults < file < settings that were
  **explicitly** set (`Settings.model_fields_set`: environment, `.env`, CLI). An invalid
  file stops `serve` with one line and exit 2 (like invalid environment values) and
  is a `doctor` failure. The shipped file lists every default, commented out; a test
  uncomments it and asserts equality with the code defaults. `.env.example` keeps the
  `HOUND_RISK_*` lines commented, because a copied `.env` would otherwise pin every value
  and make file edits silently ineffective (a test guards this too).
* **Reason:** one readable, commented place for tuning; no dependency; strictness turns
  typos into visible errors; letting explicit environment values win keeps existing
  setups working and matches 12-factor expectations.
* **Consequences:** two sources for the thresholds (documented; `doctor` lists
  overrides). Changes need a restart until 16c. Adding a signal means updating
  `RiskWeights`, the `[weights]` model and the shipped file (the drift test enforces it).
  Found while building it: a pattern-based key mapping sent `nxdomain_burst` to a
  non-existent field; mappings are explicit now.

## ADR-023 — Reloading detection settings in a running server
* **Context:** field-trial tuning is edit → observe → edit; a restart loses in-memory
  state (DNS answers used to name connections, per-device behaviour windows) and, in
  split mode, makes the capture daemon buffer and retry.
* **Options:** watch the files (surprising timing; half-saved files get applied);
  POSIX `SIGHUP` (no Windows equivalent — the owner's platform); an HTTP endpoint plus a
  CLI command.
* **Chosen:** `POST /api/admin/reload`, authenticated with the ingest token in the
  `X-Hound-Token` header, and `python run.py reload` which reads the token like the
  capture daemon does. The runtime loads and validates all three sources first; only
  then does `ProcessingService.reconfigure()` apply them under the lock that every batch
  holds, so no batch mixes old and new settings and a reload waits at most one batch.
  Components are updated in place: the enrichment service swaps its lists (DNS answer
  cache kept), the risk engine swaps its config (behaviour tracker kept unless the window
  length changes). Invalid risk settings → 400, nothing changed. Environment/`.env`
  values are not re-read.
* **Reason:** works the same on Windows, Linux and macOS; explicit and scriptable; the
  custom-header requirement means a web page in the owner's browser cannot trigger it
  (a cross-origin request with a custom header needs a CORS preflight, which Hound never
  grants) — the same property that protects ingest.
* **Consequences:** anyone with the ingest token can reload (they could already inject
  events). A missing blocklist or allowlist file on reload is not an error (same as at
  start-up); the response shows the entry counts, so an accidentally emptied blocklist is
  visible. Stored events are not rescored.

## ADR-024 — Backup with SQLite's online backup API; restore never deletes
* **Context:** the owner will run Hound for weeks (field trial) and upgrade it; the only
  advice was "copy `data/`", which is wrong while the server runs in WAL mode (recent
  commits live in `hound.db-wal`) and leaves permissions to chance.
* **Options:** manual file copy; `VACUUM INTO` (also consistent, and compacts — a valid
  alternative, not evaluated further); the backup API (`sqlite3.Connection.backup`, the
  documented mechanism for online copies and directly exposed by Python); an HTTP
  endpoint vs. CLI commands.
* **Chosen:** CLI `backup [PATH]` → `create_backup()` with the backup API in one step (a
  consistent snapshot while the server keeps writing); destination created with
  `O_EXCL` + mode 0600 before any data lands, parent directory 0700, then
  `journal_mode=DELETE` so the backup is one file, and `PRAGMA integrity_check` must
  return `ok` (the copy is deleted otherwise). Existing files are never overwritten.
  CLI `restore BACKUP` → refuses if a Hound answers on the configured port; validates the
  backup read-only (integrity, not newer, a Hound schema, not empty); moves the current
  database plus `-wal`/`-shm` aside with a timestamp (never deletes); copies the backup
  in (0600); rolls everything back if the copy fails. No HTTP endpoint: a backup is a
  file on the owner's disk, and restore must not run while the server does.
* **Reason:** consistent without stopping capture; private by construction; restore
  cannot lose data, even when used by mistake.
* **Consequences:** backups accumulate (no rotation yet); restore relies on the port
  probe to detect a running server (a server on a different port is not detected —
  on Windows the move then fails because the file is open, and everything is rolled
  back). Found while building: SQLite creates `-wal`/`-shm` with the database file's
  permissions — a note in ARCHITECTURE §3.11a claiming otherwise was corrected.
* **Revisited (2026-09-29, owner's Windows run):** the first rollback deleted the file at
  the database path whenever anything failed — including when the *move* of the original
  failed, i.e. it could delete the live database (Linux; Windows was saved by its file
  lock). The rollback now removes that file only after every original is aside and the
  copy has started. Lesson recorded: a rollback must know which state it is undoing.

## ADR-025 — MIT licence; version 1.0.0
* **Context:** release hygiene (14.3b) needed a licence and a version label. The
  dependency survey (2026-09-28) found Scapy core is GPL-2.0-only, which ruled out a
  clean GPL-3.0 story.
* **Chosen (owner, 2026-09-29):** MIT (`LICENSE`, `license = "MIT"` + `license-files` per
  PEP 639, so the build backend needs setuptools ≥ 77); label **1.0.0** for the M6 build.
* **Reason:** permissive, simple, and compatible with importing GPL-2.0-only Scapy (MIT
  code can be combined with GPL code; the combination, if distributed, follows the GPL).
  Hound ships its own source only; users install dependencies from PyPI.
* **Consequences:** anyone may reuse Hound's code, including in closed products. The
  roadmap's "tag 1.0 at M10" becomes "tag the current version at M10". Not legal advice.

## ADR-026 — The owner chooses the deployment position; Hound says what it can see
* **Context:** what Hound observes depends entirely on where it captures: on a Wi-Fi
  laptop it sees only that laptop; on the router, a switch mirror port or the DNS host it
  can see the household. Users easily misread an empty dashboard as "nothing happened".
* **Chosen (owner, 2026-09-29):** do not impose one topology. The user picks the position
  (laptop, router/gateway, mirror/SPAN port, DNS server); Hound is **opinionated about
  what each position can and cannot see** and says so where it matters: `doctor`, the
  dashboard (visible coverage note) and the README. Where possible Hound infers the
  position from traffic (e.g. only one source device seen → "this computer only").
* **Consequences:** a new slice 16e in the roadmap; a small setting or inference step;
  copy that must stay accurate per position.
* **Implemented (16e, 2026-09-29):** `HOUND_DEPLOYMENT_POSITION` = `auto` (default) |
  `this_computer` | `gateway` | `mirror` | `dns_server`; the copy for each position lives
  once, in `app/services/coverage.py`, and feeds `GET /api/coverage`, the dashboard's
  coverage line and dialog, and a `doctor` line (the README table is kept in step by a
  drift-guard test). The traffic check:
  * counts **local IPv4 addresses that started something** (a lookup or a connection
    attempt) in the last 24 h. IPv6 addresses are reported but never decide, because one
    computer uses several at once. Public IPv4 sources are counted separately (their
    usual cause: capturing on a router's WAN side);
  * gives no verdict before **50 lookups/connections spread over 15 minutes**, so a quiet
    first minute on a router is not called "one device";
  * never judges demo traffic;
  * flags a mismatch as a *warning* with its likely cause (one device on a gateway or
    mirror; several on `this_computer`; one address on a DNS server = router forwarding),
    and with the position unset only *infers* ("most likely just this computer").
  Blind spots of every position are stated as well: encrypted DNS, UDP/QUIC, IPv6
  connection attempts under the default filter (checked: libpcap 1.10.4 does not match
  an IPv6 SYN with `tcp[tcpflags]`; replaced by a neutral line when `HOUND_BPF_FILTER`
  is customised), and connection content.
* **Rejected:** counting every row of the device table (an address that only *receives*
  connections would also count); a hard verdict on one device (VMs, containers and
  inbound connections legitimately add addresses, so the wording is "most likely"/"check").

## ADR-027 — Export: streamed API downloads, spreadsheet-safe CSV
* **Context:** the field trial (16d) needs flagged events reviewed outside the dashboard
  (spreadsheet, notes), and a record kept. The event table holds up to 250 k rows by
  default (up to 50 M configured).
* **Chosen (17b, 2026-09-29):** two read-only endpoints, `GET /api/export/events`
  (same filters as `/api/events`, via one shared FastAPI dependency) and
  `GET /api/export/devices`, each `format=csv|json`, plus dashboard *Download* links.
  * **Bounded memory:** keyset pages of 1 000 rows (`id > last`), each page in its own
    short session — no connection or read transaction is held for the whole response,
    and no connection is used from two threads (Starlette iterates a sync generator
    in its thread pool). Measured: server peak RSS 83 MiB for 25 k and for 250 k rows.
  * **Snapshot:** the highest id is fixed when the request arrives (also making a
    database outage a 503 instead of a broken file); rows stored later are excluded.
  * **Order:** storage order (id), oldest first — the natural reading order for a review.
  * **CSV:** RFC 4180 (`csv` module, `\r\n`), UTF-8 with BOM for Excel on Windows;
    formula-like cells prefixed with `'` (OWASP CSV-injection advice), also after
    leading whitespace. Interface names arrive through ingest unvalidated beyond
    length, so this is a real path, not theory (verified: `=cmd|…` was accepted).
  * **JSON:** one array, written in chunks of 1 000 items (one chunk per item was 5×
    slower: 2.9 k vs 14 k rows/s at 250 k rows).
* **Rejected:** a CLI `export` reading the database directly (a second read path to
  keep correct; the endpoints already work from a browser, curl or PowerShell while
  Hound runs); NDJSON (less usable in spreadsheet tools); a `sep=` line for
  semicolon-locale Excel (breaks every other CSV reader).
* **Consequences:** an export of 250 k rows keeps one thread-pool worker busy ~20 s;
  a CSV cut off by a mid-export database error is not self-evidently incomplete (only
  the server log says so). Both accepted for a local, single-user tool.

## ADR-028 — Retention by count and age; device rows describe what is stored
* **Context:** events were limited by count only, checked every 50 batches — an idle
  server never pruned; `devices` rows were never removed and kept lifetime counters, so
  a device could show "5 000 events" with none left to inspect or export. A household
  monitor records browsing metadata, so an age limit is also a privacy control.
* **Chosen (17c, 2026-09-29):**
  * optional `HOUND_RETENTION_DAYS` (1–3650, unset = off) in addition to
    `HOUND_RETENTION_MAX_EVENTS`;
  * pruning tallies the deleted rows per device (grouped by type and level) and
    subtracts them from the device counters in the same transaction; a device with no
    stored event left is deleted (checked with an indexed `EXISTS`, not by trusting the
    counter; counters are clamped at 0 for databases whose counters had drifted).
    `first_seen`/`last_seen` are kept as observed — they are history, and recomputing
    them would cost a query per device;
  * pruning runs from the worker between batches and on a timer (start, 50 batches,
    5 min), not from `save()`.
* **Bug found and fixed on the way:** `save()` pruned after committing the batch, inside
  the worker's error handling — a failed prune (e.g. "database is locked") marked the
  already stored batch as failed, logged "batch dropped", added it to the loss metrics
  and skipped publishing it to the dashboard. Reproduced before the fix (50 stored, 1
  counted failed); regression test added.
* **Rejected:** recomputing device counters from the events table after each prune (cost
  grows with the table, not with what is deleted); keeping lifetime counters (they
  disagree with every view of the stored data).
* **Consequences:** a device that returns after being forgotten starts a new row; risk
  observations of a device are not trimmed (they are windowed already).

## ADR-029 — Real geolocation: DB-IP Lite, downloaded automatically
* **Context:** countries were simulated (ADR-008) even in live use, so the Countries tab
  and every event's country were invented. The owner asked for real data before the field
  trial, with no manual steps.
* **Chosen (owner + 2026-09-29):**
  * **Data:** DB-IP "IP to Country Lite" (owner's choice) — free, no account, monthly,
    CC BY 4.0 (credit "IP Geolocation by DB-IP" shown next to country data and in the
    README). Rejected: MaxMind GeoLite2 (account + licence key, 30-day deletion duty).
  * **Reader:** `maxminddb` (Apache-2.0, by MaxMind, wheels for Windows/macOS/Linux,
    pure-Python fallback) — the only new runtime dependency; the `.mmdb` format also
    lets a GeoLite2 file work later without code changes. Rejected: parsing DB-IP's CSV
    (~717 k rows into memory at every start) or a home-made `.mmdb` reader.
  * **Automatic updates (owner: "automatically"):** a background thread checks hourly;
    when the newest installed file is older than the current month it downloads
    `https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.mmdb.gz` (falling back
    to the previous month early in a month), at most once per 6 hours. Opt-out:
    `HOUND_GEOIP_AUTO_UPDATE=false`; manual: `python run.py geo update`. No thread in
    demo mode. Only that host is contacted (checked in code); the system proxy is used.
  * **Safety of the download:** caps on the compressed (64 MB) and unpacked (256 MB,
    enforced while streaming, so a decompression bomb never reaches memory) size; a
    truncated gzip is rejected; the file must open and answer 8.8.8.8 and 1.1.1.1 with
    a country before it replaces anything; a `.part` file is removed on any failure.
  * **Swap while running:** versioned file names (`dbip-country-lite-YYYY-MM.mmdb`), so a
    new file never overwrites an open one (Windows); the new reader is swapped in under
    the processing batch lock, then the old one is closed and its file removed (best
    effort). `python run.py reload` also picks up a newer file at once.
  * **No invented data in live use:** `HOUND_GEO_MODE=auto` (new default) uses DB-IP when
    installed; without it, countries are *Unknown* in live modes and simulated only in
    demo mode. `simulated` / `mapping_only` remain for demos and tests. `doctor` warns
    when illustrative data is configured, when there is no database and downloads are
    off, and when the database is more than ~2 months old.
  * `.env.example` no longer sets `HOUND_GEO_MODE=simulated` (a copied `.env` would
    have kept invented countries); a test guards it.
* **Consequences:** Hound now makes one outbound HTTPS request a month by default — the
  first network access that is not capture; documented in the README with the opt-out.
  Country names for all ISO codes are a static table (`app/enrichment/countries.py`).
  Not verified against a real DB-IP file from the development sandbox (its egress policy
  blocks download.db-ip.com); tests use `.mmdb` files written by `tests/mmdb.py` and
  read by the real reader (C extension and pure Python). The owner's first run is the
  first real download.

## ADR-030 — Capture restarts itself when the interface fails while running
* **Context:** before the week-long laptop trial, a check on Linux showed that Scapy's
  sniffer ends *quietly* (no exception, only a "Network is down" warning) when the
  interface goes down or disappears — even briefly — and never resumes. The supervisor
  then set state `error`, and the capture daemon exited with code 3: one Wi-Fi drop or
  sleep ended capture until someone noticed. Reproduced with the previous build on a veth
  interface (link down → "capture thread exited unexpectedly", exit 3).
* **Chosen (s19):** `PacketCaptureService` recovers by itself: new state `restarting`
  (with the reason), interface list re-read (`conf.ifaces.reload()`) and the interface
  re-resolved on every attempt, same filter mode (BPF or user-space fallback) relaunched,
  retries after 1, 2, 4 … s capped at 60 s, indefinitely until stopped. Counted as
  `restarts` and `downtime_seconds`, sent in the daemon report
  (`capture_restarts`, `capture_downtime_seconds`) and shown in `/api/metrics`; the
  dashboard shows *Reconnecting* for all-in-one capture. The daemon exits only on
  `error`, i.e. start-up failures (exit 2) or `restart=False`.
* **Rejected:** exiting and relying on an external restarter (no service manager yet —
  Phase 21 — so on Windows nothing would restart it); giving up after N attempts (a
  laptop may be asleep for hours; the retry costs one attempt a minute).
* **Consequences:** a misconfigured-but-running capture (interface permanently gone)
  now retries forever with one warning per minute instead of exiting; the reason is in
  the log and in `/health`. Traffic during an outage is not seen and is not counted as
  lost — the downtime counter is the measure. In split mode the server learns about
  restarts only with the next batch (reports ride on batches), so the dashboard does not
  show a daemon that is currently reconnecting. Windows/Npcap behaviour on sleep is not
  yet observed (the field trial will).
