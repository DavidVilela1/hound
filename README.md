# 🐕 Hound — local home-network security monitor

Hound watches the DNS lookups and TCP connection attempts on your home network,
enriches them with local threat and location metadata, scores them with a
transparent rule set, stores everything in SQLite and shows it live in a web
dashboard — entirely on your own machine, with no cloud service.

> **Authorised use only.** Hound captures network traffic. Only run it on networks
> you own or have explicit permission to monitor. Depending on where you live,
> monitoring other people's traffic without consent may be illegal.

---

## Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Features](#3-features)
4. [Requirements](#4-requirements)
5. [Installation](#5-installation)
6. [Virtual environment setup](#6-virtual-environment-setup)
7. [Dependency installation](#7-dependency-installation)
8. [Configuration](#8-configuration)
9. [Finding the network interface](#9-finding-the-network-interface)
10. [Running demo mode](#10-running-demo-mode)
11. [Running real packet capture](#11-running-real-packet-capture)
12. [Privilege requirements](#12-privilege-requirements)
13. [API documentation](#13-api-documentation)
14. [Dashboard usage](#14-dashboard-usage)
15. [Testing](#15-testing)
16. [Troubleshooting](#16-troubleshooting)
17. [Project structure](#17-project-structure)
18. [Security considerations](#18-security-considerations)
19. [Limitations](#19-limitations)
20. [Future improvements](#20-future-improvements)

**Project planning docs:** current state and next task in
[`docs/PROJECT_STATUS.md`](docs/PROJECT_STATUS.md); plan in [`docs/ROADMAP.md`](docs/ROADMAP.md);
design in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); decisions in
[`docs/DECISIONS.md`](docs/DECISIONS.md).

---

## 1. Overview

Hound focuses on two kinds of traffic that say a lot about what devices on a
network are doing, at very low volume:

* **DNS queries** – which names each device looks up (UDP/TCP port 53);
* **TCP SYN packets** – which hosts/ports each device *tries* to connect to.
  A SYN is recorded as a *connection attempt*; Hound never assumes the
  handshake completed.

Each observation becomes a normalised **event** (time, device, destination,
protocol, domain, …). The backend enriches it (blocklist match, simulated
country, domain inferred from earlier DNS answers), scores it with a
deterministic risk engine, persists it and pushes it to the dashboard over a
WebSocket.

Risk output is deliberately worded as *indicators*:
“Hound identified indicators associated with elevated risk” — never
“this device is infected”.

## 2. Architecture

```text
                    ┌───────────────────── privileged (only this part) ─────────────────────┐
  network ──▶ Scapy AsyncSniffer ──▶ PacketParser ──▶ bounded EventQueue ──▶ HttpEventForwarder
              (BPF filter, thread)    (normalise)       (drop-on-full)          (batched POST)
                    └──────────────────────────────────────────────────────────────┬────────┘
                                                                                   │ /api/ingest (token)
  ┌──────────────────────────────── unprivileged Hound server ─────────────────────▼─────────┐
  │                                                                                          │
  │  in-process sources (demo generator | optional local capture) ──▶ EventQueue ◀───────────┤
  │                                                                     │                    │
  │                                               ProcessingService (1 worker thread)        │
  │                                   validate → EnrichmentService → RiskEngine → SqlEventStore
  │                                                                     │          │ SQLite (WAL)
  │                                                           EventBroadcaster     │
  │                                                                     │          │
  │   FastAPI: /health  /api/events  /api/devices  /api/stats  /ws/events ◀────────┘
  │                                                                     │
  │   NiceGUI dashboard ── HoundApiClient (REST) + LiveEventStream (WebSocket)
  └──────────────────────────────────────────────────────────────────────────────────────────┘
```

**Layers and rules**

| Layer | Package | Responsibility | Never does |
|---|---|---|---|
| Ingestion | `app/ingestion` | capture, parse, demo traffic, forwarding | database/API/UI work |
| Backend | `app/services`, `app/enrichment`, `app/risk`, `app/database` | validate → enrich → score → persist → publish; queries | UI rendering |
| API | `app/api` | thin routes, validation, auth, WebSocket | business logic |
| Frontend | `app/frontend` | NiceGUI dashboard | touch SQLite (it only calls the API) |
| Shared | `app/models`, `app/core` | data contracts, config, logging, helpers | I/O-heavy work |

**Concurrency model.** Scapy capture is inherently blocking, so it runs on its
own thread and only parses + enqueues (non-blocking, bounded queue). One
processing thread owns the risk engine and the SQLite writer, so there are no
write races. The API runs on asyncio; its read endpoints use sync SQLAlchemy in
FastAPI's thread pool (SQLite WAL allows concurrent reads). The processing
thread hands new events to the event loop with `call_soon_threadsafe`; each
WebSocket client has a bounded queue, so a slow browser only loses its own
oldest messages. No component busy-waits or polls the database for new events.

**Structure decisions (deviations from the suggested layout)**

* `app/services/` was added for the pipeline, persistence, queries and the
  composition root (`runtime.py`), so routes stay thin and the frontend has no
  backend imports.
* The package is named `app` as requested, so the module entry point is
  `python -m app` (and `hound` after `pip install -e .`). A `python -m hound`
  alias would require a second top-level package with the same name as the
  project folder, which invites import confusion; `run.py` remains the main
  entry point.
* The dashboard is mounted on the same FastAPI/uvicorn server (one port) but
  talks to the backend only over HTTP/WebSocket, so it could run in a separate
  process by setting `HOUND_API_URL`.

## 3. Features

* Real-time capture with Scapy and a configurable BPF filter.
* DNS query/response parsing (IPv4 + IPv6, UDP + TCP), TCP SYN detection
  (SYN-ACKs ignored), graceful handling of malformed packets.
* DNS correlation: a SYN to `142.250.1.1` is labelled with the domain the device
  resolved to that address moments earlier.
* Local blocklist with parent-domain matching (plain, `*.wildcard` and hosts-file formats).
* Pluggable geolocation (`GeoLocator` protocol); default is **simulated**.
* Transparent, deterministic risk engine with 13 documented signals.
* SQLite storage with indexes, automatic schema creation and a retention limit.
* FastAPI REST API with pagination/filtering, OpenAPI docs at `/docs` and `/redoc`.
* WebSocket live feed; NiceGUI dashboard with overview, live feed, devices,
  country statistics and event/device detail views.
* Demo mode that runs the *real* parser and pipeline with synthetic packets.
* Privilege separation: only the capture daemon needs elevated rights.

## 4. Requirements

* **Python 3.11 or newer** (3.11–3.13 expected to work; developed on 3.11).
* For **live capture** only:
  * **Linux** – libpcap (`sudo apt install libpcap0.8` / `sudo dnf install libpcap`) for BPF compilation, plus root or `CAP_NET_RAW`.
  * **macOS** – libpcap is built in; read access to `/dev/bpf*` (root, or the ChmodBPF approach used by Wireshark).
  * **Windows** – [Npcap](https://npcap.com) installed (tick *“WinPcap API-compatible mode”*), and an Administrator shell for the capture daemon.
* Demo mode, the API, the dashboard and the tests need none of the above.

## 5. Installation

```bash
unzip hound.zip
cd hound
```

## 6. Virtual environment setup

Linux / macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows (PowerShell):

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
```

## 7. Dependency installation

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
# optional: installs the `hound` command
pip install -e .
```

`requirements.txt` contains only packages the code uses: FastAPI, Uvicorn,
Pydantic, pydantic-settings, SQLAlchemy, Scapy, NiceGUI, httpx, websockets and
pytest. The platform capture library (libpcap/Npcap) is **not** a pip package —
see [Requirements](#4-requirements).

## 8. Configuration

Configuration lives in `app/core/config.py` (`Settings`, validated by Pydantic)
and is read from, in increasing priority: defaults → `.env` file in the project
root → environment variables → command-line flags.

```bash
cp .env.example .env     # Windows: copy .env.example .env
```

All variables use the **`HOUND_` prefix**. The requested names map as follows
(the prefix avoids clashes such as zsh's `HOST` variable, which would otherwise
silently change the bind address):

| Requested | Hound variable | Default |
|---|---|---|
| `HOST` | `HOUND_HOST` | `127.0.0.1` |
| `PORT` | `HOUND_PORT` | `8000` |
| `DATABASE_URL` | `HOUND_DATABASE_URL` | `sqlite:///data/hound.db` |
| `NETWORK_INTERFACE` | `HOUND_NETWORK_INTERFACE` | system default |
| `BPF_FILTER` | `HOUND_BPF_FILTER` | `udp port 53 or tcp port 53 or (tcp[tcpflags] & tcp-syn != 0)` |
| `BLOCKLIST_PATH` | `HOUND_BLOCKLIST_PATH` | `config/blocklist.txt` |
| `LOG_LEVEL` | `HOUND_LOG_LEVEL` | `INFO` |

Other useful settings (full list with comments in `.env.example`):
`HOUND_ALLOWED_HOSTS`, `HOUND_API_URL`, `HOUND_INGEST_TOKEN`,
`HOUND_GEO_MODE` (`simulated` | `mapping_only`), `HOUND_GEO_RANGES_PATH`,
`HOUND_TRUSTED_DNS_SERVERS`, `HOUND_RETENTION_MAX_EVENTS`,
`HOUND_QUEUE_MAX_SIZE`, `HOUND_LOG_FORMAT` (`text` | `json`) and all
`HOUND_RISK_*` thresholds. Relative paths are resolved against the project
directory, never the current working directory, so no machine-specific paths
are needed. Invalid values stop start-up with a clear message.

**Blocklist** (`config/blocklist.txt`): one domain per line; `#` comments,
`*.domain` and hosts-file lines (`0.0.0.0 domain`) are accepted. The sample
entries use reserved TLDs (`.example`, `.test`, `.invalid`) so they never flag
a real website — replace them with a list you trust.

**Blocklist matching strategy.** Entries and observed names are normalised
(lower-case, trailing dot removed, URL scheme/path/port stripped, IDNA/punycode).
A domain matches if it *equals* an entry or is a *subdomain* of it, on label
boundaries: the entry `example.com` matches `example.com`, `www.example.com`,
`EXAMPLE.COM.` and `a.b.example.com`, but **not** `notexample.com` or
`example.com.evil.net`. `www.` is not stripped, so an entry `www.example.com`
does not block `example.com`.

## 9. Finding the network interface

```bash
python run.py interfaces
```

prints every interface Scapy can see, with its IPv4 address and the default
marked. Pick the one that carries your LAN traffic:

| OS | Typical names | Native command |
|---|---|---|
| Linux | `eth0`, `enp3s0`, `wlan0`, `wlp2s0` | `ip -br addr` |
| macOS | `en0` (Wi-Fi/Ethernet), `en1` | `ifconfig`, `networksetup -listallhardwareports` |
| Windows | `Ethernet`, `Wi-Fi` (Npcap names) | `Get-NetAdapter` |

On Windows you can pass either the friendly name shown in the DESCRIPTION
column or the `\Device\NPF_{…}` name.

**What you will see.** On a switched or Wi-Fi network a normal computer only
sees its *own* traffic (plus broadcast/multicast). To monitor every device, run
Hound on the router, on a machine attached to a switch **mirror/SPAN port**, or
on the host that serves DNS for the network (e.g. a Pi-hole box).

## 10. Running demo mode

No privileges, no network interface, no internet needed:

```bash
python run.py --demo
```

Open <http://127.0.0.1:8000>. Demo mode builds realistic Scapy packets
(normal browsing, blocklisted lookups, DGA-like NXDOMAIN bursts, a port scan,
a LAN telnet sweep, RDP/SMB attempts, TXT queries…), serialises them to bytes,
re-dissects them and feeds them through the **same** parser, queue, enrichment,
risk engine, database, API, WebSocket and dashboard as live capture.

```bash
python run.py --demo --demo-rate 20        # faster traffic
HOUND_DEMO_SEED=42 python run.py --demo     # reproducible scenario sequence
python run.py --demo --no-dashboard         # API only
```

## 11. Running real packet capture

### Recommended: split mode (only the capture daemon is privileged)

Terminal 1 – API + dashboard as your normal user:

```bash
python run.py
```

Terminal 2 – capture daemon with elevated rights:

```bash
# Linux / macOS (use the venv's interpreter explicitly under sudo)
sudo .venv/bin/python run.py capture --interface eth0
#   or: scripts/run_capture.sh eth0
```

```powershell
# Windows: in a PowerShell started "as Administrator"
.venv\Scripts\python.exe run.py capture --interface "Wi-Fi"
#   or: scripts\run_capture.ps1 -Interface "Wi-Fi"
```

The daemon parses packets and POSTs batches of normalised events to
`http://127.0.0.1:8000/api/ingest`. It authenticates with a token that the
server writes to `data/.ingest_token` (mode `0600`) on first start; the daemon
reads the same file, so no setup is needed. Alternatively set the same
`HOUND_INGEST_TOKEN` (≥ 24 characters) for both processes. Use `--api-url` if
the server listens elsewhere. The daemon ignores its own connections to the API,
so capturing on loopback does not create a feedback loop.

### All-in-one (simpler, whole process privileged)

```bash
sudo .venv/bin/python run.py --interface eth0
```

This runs capture inside the web server process, which then also runs with
elevated rights — acceptable for a quick test, but prefer split mode. If
capture cannot start (e.g. permission denied), the API and dashboard keep
running and show the error.

### Verifying capture

With the daemon capturing on loopback (`lo` / `lo0`):

```bash
python scripts/generate_test_traffic.py
```

sends two DNS queries (one for a sample-blocklist domain) and two TCP SYNs to
closed local ports; they appear in the dashboard within a second.

### Command summary

| Command | What runs | Privileges |
|---|---|---|
| `python run.py` | API + dashboard, waits for a capture daemon | none |
| `python run.py --demo` | API + dashboard + synthetic traffic | none |
| `python run.py --no-dashboard` | API only | none |
| `python run.py capture -i IFACE` | capture daemon only → forwards to API | capture rights |
| `python run.py -i IFACE` | everything in one process | capture rights |
| `python run.py interfaces` | list interfaces | none (usually) |

`python -m app …` and (after `pip install -e .`) `hound …` accept the same arguments.

## 12. Privilege requirements

Opening a raw capture socket is a privileged operation on every major OS.
Hound's architecture confines that need to `run.py capture`; the API, database
and dashboard never need it. **Do not run the whole application as root when
split mode works for you.**

**Linux**

* Run the daemon with `sudo` (as above), **or**
* grant capabilities to a *dedicated* interpreter instead of using sudo:

  ```bash
  cp "$(readlink -f .venv/bin/python)" .venv/bin/python-capture
  sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python-capture
  .venv/bin/python-capture run.py capture -i eth0
  ```

  Only give capabilities to a copy used for capture: every script run by that
  binary gets them. Never `setcap` the system `python3`.
* libpcap must be installed so Scapy can compile the BPF filter. Without it
  Hound falls back to filtering in Python (the default filter only) and logs a
  warning.

**macOS**

* `sudo .venv/bin/python run.py capture -i en0`, or install Wireshark's
  *ChmodBPF* helper, which grants your user access to `/dev/bpf*` so no sudo is
  needed.

**Windows**

* Install Npcap. During installation you may choose *“Restrict Npcap driver's
  access to Administrators only”*; if selected, the daemon must run from an
  elevated shell. Otherwise a normal shell can capture.
* The server (`python run.py`) never needs Administrator rights.

## 13. API documentation

Interactive docs: <http://127.0.0.1:8000/docs> (Swagger UI) and
<http://127.0.0.1:8000/redoc>; schema at `/openapi.json`.

| Method & path | Description | Main parameters |
|---|---|---|
| `GET /health` | status (`ok`/`degraded`), DB state, pipeline status. 503 if the DB is down | – |
| `GET /api/events` | events, newest first, paginated | `limit` (1–500), `offset`, `source_ip`, `destination_ip`, `domain` (substring), `risk_level`, `min_risk_level`, `packet_type`, `protocol`, `country`, `since`, `until` |
| `GET /api/events/{event_id}` | one event; 404 if missing | – |
| `GET /api/devices` | devices, paginated | `limit`, `offset`, `risk_level`, `sort` = `risk`\|`last_seen`\|`events`\|`first_seen` |
| `GET /api/devices/{ip}` | one device incl. recent observations | – |
| `GET /api/stats` | totals, per-level counts, last-minute count, pipeline status | – |
| `GET /api/stats/countries` | share of events by destination country | `include_local` (default false), `since_minutes` |
| `POST /api/ingest` | capture-daemon ingest (≤ 1000 events, ≤ 2 MB) | header `X-Hound-Token` |
| `WS /ws/events` | live stream: `{"type":"event","data":<Event>}`, plus `hello`/`heartbeat` | – |

Invalid input returns **422** with details; unknown IDs **404**; a bad ingest
token **401**; oversized ingest bodies **413**; database outages **503**.

Examples:

```bash
curl "http://127.0.0.1:8000/api/events?limit=20&min_risk_level=suspicious"
curl "http://127.0.0.1:8000/api/events?source_ip=192.168.1.57&since=2026-01-01T00:00:00Z"
curl "http://127.0.0.1:8000/api/devices?sort=risk&limit=10"
curl "http://127.0.0.1:8000/api/stats/countries?include_local=true"
```

**Country percentages** are computed over **events** — each stored DNS query or
TCP connection attempt counts once — grouped by the country of the event's
*destination* IP. DNS responses and SYN-ACKs are not events. By default LAN
destinations (e.g. your router as DNS resolver) are excluded.

## 14. Dashboard usage

Open <http://127.0.0.1:8000>.

* **Header** – run mode, event-source state and live-connection indicator; theme toggle.
* **Overview tiles** – total events, devices observed, suspicious and dangerous
  events, events in the last minute, and application status (Demo / Capturing /
  Listening / Degraded / Offline). Banners explain demo mode, a waiting capture
  daemon or a capture error.
* **Live feed** – newest first: time, device, destination, domain (“via DNS”
  when inferred from an earlier answer), protocol, country, risk badge (level +
  score) and top reason. Filter to *Suspicious +* or *Dangerous*, or *Pause* to
  read without rows moving. Click a row for full event details, including every
  risk indicator and its points.
* **Devices** – IP, first/last seen, event count, risk score and level. Click a
  device for its counters, recent observations and last 100 events.
* **Countries** – bar chart and table of the share of events by destination
  country (simulated geolocation), optionally including the local network.

Updates arrive over the WebSocket and are applied in small batches; if the
socket drops, the page shows *reconnecting*, polls the REST API every 5 s as a
fallback, and resumes streaming automatically.

## 15. Testing

```bash
pytest                         # unit, database and API tests
python scripts/smoke_test.py   # end-to-end: starts demo mode and checks every layer
```

The suite (200+ tests) needs no root privileges and no real network traffic;
packets are synthesised with Scapy and Scapy's sniffer is replaced by a fake
where capture behaviour is tested. It covers DNS extraction, packet
classification (SYN vs SYN-ACK, DNS over TCP, IPv6, malformed/truncated
packets), event normalisation, IP/domain validation, blocklist matching,
geolocation, risk scoring, configuration parsing, database
initialisation/insertion/filtering/persistence/retention, the processing
pipeline, the WebSocket stream, API validation/auth and the dashboard's API
client. `scripts/smoke_test.py` uses a temporary database and a free port.

## 16. Troubleshooting

| Symptom | Fix |
|---|---|
| `Permission denied opening interface …` | Run the capture daemon with sudo/Administrator or grant `CAP_NET_RAW` (see §12). The server itself keeps running. |
| `Network interface '…' not found` | Use a name from `python run.py interfaces`. |
| `Packet capture driver unavailable` / `libpcap is not available` | Install libpcap (Linux) or Npcap (Windows). |
| `Invalid BPF filter` | Check `HOUND_BPF_FILTER` syntax (tcpdump syntax). |
| Capture daemon: `No ingest token found` | Start `python run.py` first (it creates `data/.ingest_token`), or set `HOUND_INGEST_TOKEN` for both. |
| Daemon logs `API rejected the ingest token` | Both processes must use the same token/file. |
| `sudo: python: command not found` / missing modules under sudo | Use the venv interpreter explicitly: `sudo .venv/bin/python …`. |
| Only my own computer's traffic appears | Expected on switched/Wi-Fi networks — see §9 (mirror port, router, DNS server). |
| No SYN events for IPv6 | The default filter's `tcp[tcpflags]` only matches IPv4; see §19. |
| Dashboard says *reconnecting* | The page polls every 5 s meanwhile; check the server log. Behind a proxy set `HOUND_API_URL`. |
| `400 Invalid host header` | You bound to a LAN address: add it to `HOUND_ALLOWED_HOSTS`. |
| `attempt to write a readonly database` after using sudo | Files in `data/` were created by root in all-in-one mode: `sudo chown -R "$USER" data/`. |
| Port 8000 in use | `python run.py --port 8080` (and `--api-url http://127.0.0.1:8080` for the daemon). |
| Many events dropped under load | Raise `HOUND_QUEUE_MAX_SIZE` or narrow the BPF filter. |

Set `HOUND_LOG_LEVEL=DEBUG` for per-event diagnostics (this logs domain names).

## 17. Project structure

```text
hound/
├── app/
│   ├── __init__.py            # version
│   ├── __main__.py            # python -m app
│   ├── cli.py                 # serve / capture / interfaces commands
│   ├── api/
│   │   ├── app.py             # FastAPI factory: middleware, lifespan, routers
│   │   ├── deps.py            # dependency helpers, input validation
│   │   ├── openapi.py         # OpenAPI customisation
│   │   └── routes/            # health, events, devices, stats, ingest, ws
│   ├── core/
│   │   ├── config.py          # Settings (env/.env/CLI), path resolution
│   │   ├── logging_config.py  # text/JSON structured logging
│   │   ├── netutils.py        # IP/domain validation & normalisation, entropy
│   │   └── security.py        # ingest token handling
│   ├── database/
│   │   ├── engine.py          # engine, sessions, SQLite pragmas, auto-init
│   │   ├── tables.py          # ORM schema + indexes
│   │   └── repositories.py    # all SQL queries
│   ├── enrichment/
│   │   ├── blocklist.py       # file-based domain reputation
│   │   ├── geo.py             # GeoLocator protocol + simulated implementation
│   │   ├── dns_cache.py       # bounded IP→domain cache
│   │   └── service.py         # EnrichmentService
│   ├── frontend/
│   │   ├── client.py          # REST client + WebSocket stream
│   │   ├── components.py      # tables, tiles, chart options, detail views
│   │   ├── dashboard.py       # NiceGUI page, mounted on FastAPI
│   │   └── formatting.py      # pure presentation helpers
│   ├── ingestion/
│   │   ├── capture.py         # Scapy AsyncSniffer service, interface helpers
│   │   ├── parser.py          # packet → NetworkEvent
│   │   ├── demo.py            # synthetic traffic through the real parser
│   │   ├── queue.py           # bounded thread-safe EventQueue
│   │   ├── forwarder.py       # daemon → API batching/retries
│   │   ├── daemon.py          # stand-alone privileged capture process
│   │   └── sources.py         # EventSource protocol
│   ├── models/
│   │   ├── events.py          # NetworkEvent, enums
│   │   ├── risk.py            # RiskLevel, RiskReason, RiskAssessment
│   │   ├── processed.py       # Enrichment, ProcessedEvent
│   │   └── schemas.py         # public API schemas
│   ├── risk/
│   │   ├── config.py          # weights & thresholds
│   │   ├── behavior.py        # per-device sliding windows
│   │   ├── signals.py         # individual signals
│   │   └── engine.py          # RiskEngine
│   └── services/
│       ├── runtime.py         # composition root (wiring & lifecycle)
│       ├── processing.py      # worker: enrich → score → persist → publish
│       ├── store.py           # transactional persistence + retention
│       ├── queries.py         # read services for the API
│       ├── broadcaster.py     # WebSocket fan-out
│       └── mappers.py         # ORM → schema
├── config/
│   ├── blocklist.txt          # sample blocklist (reserved TLDs only)
│   └── geo_ranges.csv         # illustrative CIDR → country table
├── data/                      # SQLite DB and ingest token (created at runtime)
├── docs/                      # status, roadmap, architecture, decision records
├── scripts/
│   ├── smoke_test.py          # end-to-end check of demo mode
│   ├── generate_test_traffic.py
│   ├── run_capture.sh         # sudo wrapper for the daemon (Linux/macOS)
│   └── run_capture.ps1        # Windows helper
├── tests/                     # pytest suite
├── .env.example
├── .gitignore
├── pyproject.toml             # pytest config, optional `hound` command
├── requirements.txt
├── README.md
└── run.py
```

## 18. Security considerations

* **Local by default.** The server binds to `127.0.0.1`. The API has no user
  accounts; if you bind to a LAN address, anyone on that network can read your
  traffic metadata. A warning is logged when binding to a non-loopback address.
* **DNS-rebinding and cross-site protection.** A Host-header allow-list
  (`HOUND_ALLOWED_HOSTS`) is enforced, and the WebSocket rejects browser
  origins that are not on that list, so a malicious website cannot read your
  feed through your browser.
* **Least privilege.** Only the capture daemon needs raw-socket rights. It
  contains no web server, database or UI code and forwards with the standard
  library only.
* **Authenticated ingest.** `POST /api/ingest` requires a random token
  (constant-time comparison), checked **before** the body is read; bodies are
  capped at 2 MB and 1000 events and fully validated.
* **Input validation.** All query/path parameters are typed and bounded; IPs
  are parsed with `ipaddress`; domains are syntax-checked.
* **No injection.** SQL goes through SQLAlchemy expressions with bound
  parameters (`LIKE` wildcards escaped). No shell commands are executed.
* **Safe deserialisation.** Only JSON is parsed; stored JSON is re-validated
  when read. No `pickle`/`eval`.
* **Bounded memory.** Event queue, per-client WebSocket queues, DNS cache,
  behaviour tracker and the dashboard feed are all size-limited; the database
  has a retention limit.
* **Robustness.** Malformed packets are counted and skipped; database errors
  are logged, counted and surfaced in `/health` without stopping the pipeline;
  capture failures are reported in the UI.
* **Privacy.** Per-event details (domains) are logged only at DEBUG level.
  The database contains browsing metadata — protect `data/` accordingly.
* **No secrets in the repository.** `.env` is git-ignored; the ingest token is
  generated locally.
* Security response headers (`X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`) are set on HTTP responses.

## 19. Limitations

* **Geolocation is simulated** by default: `config/geo_ranges.csv` is
  illustrative and unknown addresses get a deterministic pseudo-random country.
  Do not treat country data as authoritative.
* **Risk scores are heuristics.** They surface indicators associated with
  elevated risk; false positives (e.g. CDN hostnames with random-looking labels)
  and false negatives are expected. They are not malware detection.
* **Visibility** is limited to traffic that reaches the capture interface (see §9).
* **Encrypted DNS** (DoH/DoT/DoQ) hides domain names; only the connection to the
  resolver is visible.
* **IPv6 SYNs:** the default BPF expression `tcp[tcpflags]` matches IPv4 only
  (libpcap limitation). DNS over IPv6 is captured. To include IPv6 SYNs without
  extension headers, append: `or (ip6 and ip6[6] == 6 and ip6[53] & 0x02 != 0)`.
* **Loopback on Linux** delivers each packet twice to raw sockets; Hound
  de-duplicates identical frames on loopback interfaces.
* **SQLite** is the supported database. Other SQLAlchemy URLs may work but are untested.
* **Single user, single process** design; the API has no authentication beyond
  the ingest token and is meant for localhost.
* Devices are identified by IP address; DHCP changes can merge or split history.
* Live capture on macOS and Windows has not been exercised by the automated
  tests (they run on Linux and do not open real sockets).

## 20. Future improvements

* Real GeoIP backend (e.g. MaxMind GeoLite2) implementing `GeoLocator`:

  ```python
  class MaxMindGeoLocator:
      def __init__(self, path: str) -> None:
          import geoip2.database
          self._reader = geoip2.database.Reader(path)
      def locate(self, ip: str) -> str | None:
          try:
              return self._reader.country(ip).country.iso_code
          except Exception:
              return None
  ```

  and return it from `build_geolocator()`.
* Scheduled blocklist updates from public feeds.
* MAC-address/DHCP-based device identity and friendly device names.
* TLS SNI extraction to label HTTPS connections without DNS visibility.
* Alerting (desktop notifications, e-mail, webhooks) for dangerous events.
* Optional dashboard authentication for LAN-wide deployments.
* Per-device baselines ("first time this device contacted this country").
* Packaged service units (systemd, launchd, Windows service).
