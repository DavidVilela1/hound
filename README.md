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
21. [License](#21-license)

**Project planning docs:** current state and next task in
[`docs/PROJECT_STATUS.md`](docs/PROJECT_STATUS.md); plan in [`docs/ROADMAP.md`](docs/ROADMAP.md);
design in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); decisions in
[`docs/DECISIONS.md`](docs/DECISIONS.md).
Field-trial procedure: [`docs/FIELD_TRIAL.md`](docs/FIELD_TRIAL.md).

---

## 1. Overview

Hound focuses on two kinds of traffic that say a lot about what devices on a
network are doing, at very low volume:

* **DNS queries** – which names each device looks up (UDP/TCP port 53);
* **TCP SYN packets** – which hosts/ports each device *tries* to connect to.
  A SYN is recorded as a *connection attempt*; Hound never assumes the
  handshake completed.

Each observation becomes a normalised **event** (time, device, destination,
protocol, domain, …). The backend enriches it (blocklist match, destination
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
* Real country data from the free DB-IP Lite database, downloaded and updated automatically
  (simulated only in demo mode without it).
* Transparent, deterministic risk engine with 13 documented signals.
* SQLite storage with indexes, automatic schema creation and retention (a row limit, plus an optional age limit).
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
py -3 -m venv .venv          # any installed Python 3.11 or newer (py -0 lists them)
.venv\Scripts\Activate.ps1
```

## 7. Dependency installation

```bash
pip install -r requirements.lock
# optional: installs the `hound` command
pip install -e .
```

`requirements.lock` pins the exact versions CI tests, with SHA-256 hashes that
pip checks on download, so every install gets the same, verified packages.
Ready-made wheels exist for every pinned version on Windows, macOS and Linux for
Python 3.11–3.14, so nothing needs compiling. `requirements.txt` holds the underlying
version *ranges*; `pip install -r requirements.txt` also works, but may pick
newer, untested releases.

The packages are only what the code uses: FastAPI, Uvicorn, Pydantic,
pydantic-settings, SQLAlchemy, Scapy, NiceGUI, httpx, websockets and pytest.
The platform capture library (libpcap/Npcap) is **not** a pip package — see
[Requirements](#4-requirements).

If pip reports *"hashes are required"* or a hash mismatch, the download was
altered or incomplete: retry, and do not bypass the check.

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
| `DEPLOYMENT_POSITION` | `HOUND_DEPLOYMENT_POSITION` | `auto` — where Hound captures: `this_computer`, `gateway`, `mirror`, `dns_server` (§9) |
| `BLOCKLIST_PATH` | `HOUND_BLOCKLIST_PATH` | `config/blocklist.txt` |
| `GEO_MODE` | `HOUND_GEO_MODE` | `auto` — DB-IP Lite when downloaded; `simulated` only for demos |
| `GEOIP_AUTO_UPDATE` | `HOUND_GEOIP_AUTO_UPDATE` | `true` — download the DB-IP database monthly (from download.db-ip.com) |
| `RETENTION_MAX_EVENTS` | `HOUND_RETENTION_MAX_EVENTS` | `250000` — the oldest events beyond this are deleted |
| `RETENTION_DAYS` | `HOUND_RETENTION_DAYS` | unset — also delete events older than this many days (1–3650) |
| `LOG_LEVEL` | `HOUND_LOG_LEVEL` | `INFO` |

Other useful settings (full list with comments in `.env.example`):
`HOUND_ALLOWED_HOSTS`, `HOUND_API_URL`, `HOUND_INGEST_TOKEN`,
`HOUND_ALLOWLIST_PATH`, `HOUND_GEO_MODE` (`auto` | `dbip` | `simulated` | `mapping_only`),
`HOUND_GEOIP_DIR`, `HOUND_GEOIP_AUTO_UPDATE`, `HOUND_GEO_RANGES_PATH`,
`HOUND_TRUSTED_DNS_SERVERS`,
`HOUND_QUEUE_MAX_SIZE`, `HOUND_LOG_FORMAT` (`text` | `json`),
`HOUND_RISK_CONFIG_PATH` and the `HOUND_RISK_*` thresholds (see *Risk settings*
below). Relative paths are resolved against the project
directory, never the current working directory, so no machine-specific paths
are needed. Invalid values stop start-up with a clear message.
`HOUND_DATABASE_URL` is a URL: if you write an explicit path containing `%`,
`?` or `#`, encode them (`%25`, `%3F`, `%23`). The project's own location may
contain any characters; Hound encodes it itself.

**Applying edits without a restart.** While the server runs, `python run.py
reload` re-reads the blocklist, allowlist and risk settings and applies them
between two processing batches. It is all or nothing: if the risk file is
invalid, the reload is refused with the reason and the previous settings stay in
effect. What Hound has learned is kept — the DNS answers used to name
connections and each device's recent behaviour (the behaviour windows restart
only if you change their length). Events already stored keep the score they got.
Values from the environment or `.env` are not re-read; restart for those. The
command authenticates with the ingest token (it reads `data/.ingest_token`,
like the capture daemon); `--api-url` points it at another port.

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

**Risk settings** (`config/risk.toml`): every weight and threshold the risk
engine uses — score levels, behaviour windows and counts, domain heuristics
(entropy, length, risky TLDs, unusual query types), port lists, trusted DNS
resolvers and the points per signal (`0` switches a signal off). The shipped
file lists every setting commented out with its built-in default; remove the
`# ` in front of a value to change it, then apply it with `python run.py reload`
(see below) or a restart. Unknown sections or keys are
errors — a typo must not silently do nothing — and an invalid file stops
start-up with one line naming the problem (`python run.py doctor` checks it
too). **Precedence:** built-in defaults < `config/risk.toml` < `HOUND_RISK_*` /
`HOUND_TRUSTED_DNS_SERVERS` values you set explicitly (environment or `.env`).
`.env.example` keeps those variables commented so that copying it does not
override the file; `doctor` shows which values the environment overrides.

**Allowlist** (`config/allowlist.txt`, optional): things you have checked and
trust, so their indicators stop being counted — for example a CDN whose
random-looking host names trip the entropy signal, or your NAS that legitimately
connects to many devices. One entry per line: a **domain** (matched like the
blocklist, including subdomains) or a **device** (an IP address or a CIDR range
such as `192.168.1.64/28`). Apply edits with `python run.py reload`.

* An allowlisted **domain** has none of its indicators counted, including a
  blocklist match on that exact name.
* An allowlisted **device** has its behaviour ignored (scans, repeated attempts,
  unusual ports…), but a **blocklist hit still counts** — trusting a device must
  not hide it contacting a known-bad domain.
* Nothing is hidden: affected events keep a 0-point `ALLOWLISTED` reason naming
  the entry and the indicators it covered, visible in the dashboard and API.
* Single words such as `com` are rejected; ranges wider than /24 (IPv4) or /64
  (IPv6) are accepted but logged as a warning.

**Database and upgrades.** The SQLite database (`data/hound.db` by default) is created
automatically and carries a schema version. When a newer Hound needs a different schema,
it upgrades the file on start-up, one atomic step at a time, keeping your data. Databases
created before versioning existed are recognised and adopted. Hound refuses to start —
without touching the file — on a database written by a *newer* Hound, or on a file that
isn't a Hound database.

**Where countries come from.** Hound uses the free **DB-IP "IP to Country Lite"**
database ([IP Geolocation by DB-IP](https://db-ip.com), CC BY 4.0). You do not
have to do anything: when the server starts it downloads the current month's file
(about 8 MB) into `data/geoip/`, checks it, and switches to it without a restart;
afterwards it checks hourly and fetches the new release once a month. Nothing else
is ever sent — it is one HTTPS download from `download.db-ip.com`, which sees your
public IP address like any website would.

```bash
python run.py geo status     # which database is installed
python run.py geo update     # download the latest now (then: python run.py reload)
```

* No internet, or you'd rather not? Set `HOUND_GEOIP_AUTO_UPDATE=false` and run
  `python run.py geo update` when you want (or copy a `dbip-country-lite-YYYY-MM.mmdb`
  file into `data/geoip/`). Without a database, countries show as *Unknown* —
  Hound never invents them outside demo mode.
* Behind a proxy, the download honours `HTTPS_PROXY`. If it keeps failing,
  `python run.py doctor` says so and the dashboard's Countries tab says
  "no geolocation database yet".
* Accuracy: country-level, approximate (see §19).

**How long data is kept.** Hound keeps the newest `HOUND_RETENTION_MAX_EVENTS`
events (250 000 by default) and, if you set `HOUND_RETENTION_DAYS`, deletes
events older than that many days too — a good idea for a monitor that records
your household's browsing (e.g. `HOUND_RETENTION_DAYS=30`). Retention runs at
start-up, every 50 batches and every 5 minutes, also while no traffic arrives.
A device's counters always describe the events still stored, and a device whose
last event was deleted disappears from the device list (if it shows up again it
starts afresh). Deleted events are counted in `GET /api/metrics`
(`storage.retention_pruned_events`, `retention_pruned_devices`) and are not
data loss. Take a backup first if you want to keep the history.

**Backups.** `python run.py backup` writes a consistent copy of the database to
`data/backups/hound-<date>-<time>.db` (or the path you give), and it is safe to
run while Hound is capturing. The copy is a single self-contained file, readable
only by you on Linux/macOS, and it passes SQLite's integrity check or is
deleted; existing files are never overwritten. Take one before upgrading Hound.
Do not copy `data/hound.db` by hand while Hound runs — recent changes may still
sit in `hound.db-wal`.

To go back to a backup, stop the server and the capture daemon, then run
`python run.py restore data/backups/<file>.db`. It refuses while Hound is still
running, and refuses backups that are damaged, written by a newer Hound or not a
Hound database. Your current database is not deleted: it is moved aside as
`hound.db.before-restore-<date>-<time>` (with its `-wal`/`-shm` files). Then
start Hound as usual; an older backup is upgraded automatically.

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

On Windows, use the value in the **NAME** column: it is the adapter's friendly
name, the same as the *Name* shown by `Get-NetAdapter` (for example `Wi-Fi`).
The DESCRIPTION column (the adapter model) and the Npcap device name
`\Device\NPF_{…}` are accepted too.

### Where to run Hound (what each position can see)

What Hound sees depends entirely on **where** it captures. You choose the
position; Hound tells you what that position can and cannot see — in the
dashboard (the line under the header, and *What Hound can't see*), in
`python run.py doctor`, and at `GET /api/coverage`. State the position in `.env`:

```bash
HOUND_DEPLOYMENT_POSITION=this_computer   # or gateway, mirror, dns_server
```

| Position (value) | Sees | Does not see |
|---|---|---|
| This computer only (`this_computer`) — a laptop or desktop, the usual start | DNS lookups and new TCP connections of this computer; connection attempts other devices make *to* it | **Other devices**: switches send each device only its own traffic, and Wi-Fi adapters (outside monitor mode) pass on only this computer's. Traffic inside a VPN, unless you capture on the VPN adapter |
| Router / gateway (`gateway`) — e.g. an OpenWrt router or a Linux box routing the LAN | Lookups and internet connections of every device that uses it — capture on the **LAN side** | Traffic between devices inside the LAN (often switched in hardware). On the WAN side, address translation makes every device look like the router |
| Mirror / SPAN port (`mirror`) — a machine on a managed switch's mirror port | Whatever the switch copies: mirror the router's port to see every device's internet traffic | Ports that are not mirrored (e.g. Wi-Fi clients of an access point not behind this switch); copies the switch drops under load — invisible to Hound's metrics |
| DNS server (`dns_server`) — the machine that answers the network's lookups (e.g. next to Pi-hole) | Which names **every** device looks up; this machine's own connections | Other devices' connections (so port-scan, sweep and suspicious-port signals apply only to this machine); devices using another DNS server; *which* device asked, if the router forwards lookups on the devices' behalf |

**In every position** Hound does not see: names looked up over encrypted DNS
(DNS over HTTPS/TLS, e.g. a browser's secure DNS or Android's Private DNS — the
connections are still seen, without a name); connections over UDP, including
QUIC/HTTP-3; IPv6 connection attempts with the default capture filter (see §19);
and the content of any connection.

**Checked against the traffic.** Hound counts the local IPv4 addresses that
looked up a name or started a connection in the last 24 hours (IPv6 addresses
are shown but not counted as devices, because one computer uses several). After
at least 50 lookups/connections over 15 minutes it compares that with the
position: one device on a *gateway* or *mirror* position, several on
*this_computer*, or a single address on *dns_server* is flagged with the likely
cause. With the position unset (`auto`), Hound says what it infers — for
example "only one device … most likely just the computer it runs on". In demo
mode the traffic is synthetic and is never used as evidence.

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

### First: check your setup

```bash
python run.py doctor                 # add -i "Wi-Fi" (or eth0, en0) to check an interface
```

`doctor` checks, without changing anything: the Python version, installed
packages against `requirements.lock`, the capture driver (Npcap on Windows,
libpcap elsewhere), privileges, the interface, the bind address, whether the
port is free or already used by a running Hound, cloud-synced data folders,
the database (readable, schema version, upgrades), the ingest token, the
risk settings file and the deployment position (what it cannot see, §9). Each
problem comes with the fix. It exits with status 1 if something would stop
Hound from working, so it can also be scripted.

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
so capturing on loopback does not create a feedback loop, and it always talks to the API
directly — `HTTP_PROXY`/`HTTPS_PROXY` and system proxy settings are not used for it.

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
closed local ports; they appear in the dashboard within a second, and
`curl http://127.0.0.1:8000/api/metrics` shows the daemon's counters with
`"total_events_lost": 0`.

### When the network drops (Wi-Fi, sleep, unplugged cable)

If the capture interface goes down or disappears while Hound is capturing — Wi-Fi
disconnects, the laptop sleeps, an adapter is unplugged — capture **restarts by
itself** as soon as the interface is back: it retries after 1, 2, 4 … seconds, then
once a minute, re-reading the interface list each time. You do not need to restart
the capture window. The daemon logs "Packet capture interrupted; restarting
automatically" and "Packet capture resumed … down_seconds=…". Traffic during the
outage is not seen (it never reached Hound); `GET /api/metrics` counts it as
`daemon.capture_restarts` and `daemon.capture_downtime_seconds` (for all-in-one
capture: `capture.restarts`, `capture.downtime_seconds`). Only a failure at start-up
(wrong interface name, no permission) still stops the daemon, with exit code 2.

### Command summary

| Command | What runs | Privileges |
|---|---|---|
| `python run.py` | API + dashboard, waits for a capture daemon | none |
| `python run.py --demo` | API + dashboard + synthetic traffic | none |
| `python run.py --no-dashboard` | API only | none |
| `python run.py capture -i IFACE` | capture daemon only → forwards to API | capture rights |
| `python run.py -i IFACE` | everything in one process | capture rights |
| `python run.py interfaces` | list interfaces | none (usually) |
| `python run.py doctor [-i IFACE]` | read-only environment check | none (run it elevated to check capture rights) |
| `python run.py reload` | apply edited blocklist/allowlist/risk settings to the running server | none |
| `python run.py backup [PATH]` | consistent database copy (safe while running) | none |
| `python run.py restore BACKUP` | replace the database with a backup (server stopped) | none |

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
* **Ingest token on Windows.** NTFS ignores the POSIX `0600` mode the server
  requests for `data\.ingest_token`; the file is protected by the folder's
  permissions instead. Inside your user profile (Documents, Desktop, OneDrive)
  only you, Administrators and SYSTEM can read it by default, which is what the
  elevated daemon needs. If the project lives in a shared folder such as
  `C:\hound`, set the same `HOUND_INGEST_TOKEN` in both shells instead of
  relying on the file.

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
| `GET /api/export/events` | every matching event as a download, oldest first, no paging (streamed) | `format` = `csv` (default) \| `json`, plus every filter of `GET /api/events` |
| `GET /api/export/devices` | every device as a download, in the order first seen | `format`, `risk_level` |
| `GET /api/coverage` | the deployment position, what it can and cannot see, and a check against the last 24 h of traffic (§9) | – |
| `GET /api/metrics` | loss per pipeline stage + queue/latency/storage counters (no domains or addresses) | – |
| `POST /api/ingest` | capture-daemon ingest (≤ 1000 events, ≤ 2 MB), optionally with the daemon's own counters | header `X-Hound-Token` |
| `POST /api/admin/reload` | re-read blocklist, allowlist and risk settings; 400 (nothing changed) if invalid | header `X-Hound-Token` |
| `WS /ws/events` | live stream: `{"type":"event","data":<Event>}`, plus `hello`/`heartbeat` | – |

Invalid input returns **422** with details; unknown IDs **404**; a bad ingest
token **401**; oversized ingest bodies **413**; database outages **503**.

Examples:

```bash
curl "http://127.0.0.1:8000/api/events?limit=20&min_risk_level=suspicious"
curl "http://127.0.0.1:8000/api/events?source_ip=192.168.1.57&since=2026-01-01T00:00:00Z"
curl "http://127.0.0.1:8000/api/devices?sort=risk&limit=10"
curl "http://127.0.0.1:8000/api/stats/countries?include_local=true"
curl -o flagged.csv "http://127.0.0.1:8000/api/export/events?min_risk_level=suspicious"
```

**Exports** (for reviewing a field trial in a spreadsheet, or keeping a record):
`/api/export/events` returns *all* events matching the same filters as
`/api/events` — oldest first, no page limit — and `/api/export/devices` all
devices. Open the URL in a browser to download, or use the *Download* links on
the dashboard; in PowerShell:
`Invoke-WebRequest "http://127.0.0.1:8000/api/export/events?min_risk_level=suspicious" -OutFile flagged.csv`.

* **JSON** is an array of the same objects as the API returns.
* **CSV** has one row per event with the same fields, plus `risk_reason_codes`
  (`CODE;CODE`) and `risk_reasons` (`description (+points) | …`); devices get
  `observation_codes` and `observations`. It is UTF-8 with a byte-order mark
  (so Excel shows non-ASCII text correctly) and comma-separated. In Excel with a
  locale that uses `;` as list separator (e.g. Portuguese), open it with
  *Data → From Text/CSV* instead of double-clicking.
* Any cell a spreadsheet would run as a formula (starting with `=`, `+`, `-`,
  `@`, tab or carriage return) is written with a leading `'` — captured names
  are untrusted input.
* Streamed page by page, so memory stays flat (measured: 250 000 events → 56 MB
  of CSV in ~21 s, server memory unchanged). Events stored after the download
  starts are not included. If the database fails mid-download the file is cut
  short: a JSON file then fails to parse, a CSV file just ends early (the
  server logs "Export interrupted").

**Did we lose anything?** `GET /api/metrics` answers it: `loss.total_events_lost`
is the sum of events lost at every stage — the capture daemon's queue, its
delivery to the server (retries exhausted, API down), the server's queue, and
processing/database failures — each also listed separately. The daemon's
counters travel with the event batches it already sends, so they appear once it
has delivered its first batch (`loss.daemon_reported`). Also reported: queue
peak (`queue.high_water` close to `capacity` means drops are near), batch
latency p50/p95, ingest rejections (a wrong token shows up in
`ingest.requests_unauthorized`), WebSocket messages dropped for a slow browser
tab, database size and retention pruning — the last two are not data loss.
Counters reset when the server or daemon restarts.

**Country percentages** are computed over **events** — each stored DNS query or
TCP connection attempt counts once — grouped by the country of the event's
*destination* IP. DNS responses and SYN-ACKs are not events. By default LAN
destinations (e.g. your router as DNS resolver) are excluded.

## 14. Dashboard usage

Open <http://127.0.0.1:8000>.

* **Header** – run mode, event-source state and live-connection indicator; theme toggle.
* **Coverage line** – what this deployment position can see, checked against
  the traffic (highlighted when the two disagree); *What Hound can't see* lists
  the blind spots (§9).
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
* **Downloads** – *Download CSV / JSON* on the live feed exports every stored
  event matching the feed's risk filter; the Devices tab exports all devices.
* **Countries** – bar chart and table of the share of events by destination
  country (DB-IP Lite; the *IP Geolocation by DB-IP* credit is shown there),
  optionally including the local network.

Updates arrive over the WebSocket and are applied in small batches; if the
socket drops, the page shows *reconnecting*, polls the REST API every 5 s as a
fallback, and resumes streaming automatically.

## 15. Testing

```bash
pytest                         # unit, database, API, capture-daemon and dashboard tests
python scripts/smoke_test.py   # end-to-end: starts demo mode and checks every layer
```

No test needs root, internet access or a browser: the dashboard tests use
NiceGUI's built-in user simulation against the real API, in-process.

Development tools (lint, type check, dependency audit) are in
`requirements-dev.txt`, locked in `requirements-dev.lock`:

```bash
pip install -r requirements-dev.lock
ruff check app tests scripts run.py
mypy
pip-audit -r requirements.lock --require-hashes --disable-pip
```

`.github/workflows/ci.yml` runs all of these, plus the smoke test, on Linux,
Windows and macOS with Python 3.11 and 3.13 for every push and pull request
once the project is on GitHub. A separate, non-blocking job installs the newest
versions the ranges allow, to warn before a new release breaks Hound.

### Updating dependencies

Edit the ranges in `requirements.txt` / `requirements-dev.txt`, then regenerate
both lock files with [uv](https://docs.astral.sh/uv/) (a maintainer tool, not
needed to run Hound; `pip install uv`):

```bash
uv pip compile requirements.txt --universal --python-version 3.11 --generate-hashes -o requirements.lock
uv pip compile requirements-dev.txt --universal --python-version 3.11 --generate-hashes -c requirements.lock -o requirements-dev.lock
```

Add `--upgrade` to move to the newest allowed versions. Then run the full
checks; `tests/test_dependency_locks.py` fails if a lock no longer matches its
ranges, lost its hashes, or the two locks disagree.

The suite (200+ tests) needs no root privileges and no real network traffic;
packets are synthesised with Scapy and Scapy's sniffer is replaced by a fake
where capture behaviour is tested. It covers DNS extraction, packet
classification (SYN vs SYN-ACK, DNS over TCP, IPv6, malformed/truncated
packets), event normalisation, IP/domain validation, blocklist matching,
geolocation, risk scoring, configuration parsing, database
initialisation/insertion/filtering/persistence/retention, the processing
pipeline, the WebSocket stream, API validation/auth and the dashboard's API
client. `scripts/smoke_test.py` uses a temporary database and a free port.

### Measuring performance

```bash
python scripts/benchmark.py                 # ~20 s: 50 000 stored events
python scripts/benchmark.py --rows 250000   # ~1 min: the default retention cap
python scripts/benchmark.py --json          # machine-readable
```

Runs entirely in-process on a temporary database (no network, no privileges,
`data/` untouched): Scapy dissection and parsing of demo traffic, processing
throughput at batch sizes 1/50/200 with batch latency, API response times at
the chosen database size, storage per event and peak memory. It ends with two
informational checks — headroom over a busy home network (100 events/s) and
`/api/stats` against the 200 ms optimisation trigger. Numbers depend on the
machine; compare runs on the same computer.

## 16. Troubleshooting

| Symptom | Fix |
|---|---|
| Not sure what is wrong | Run `python run.py doctor` (add `-i IFACE`); it names the fix for each problem it finds. |
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
| `database is locked` / sync conflicts in a OneDrive or Dropbox folder | Cloud sync is holding the SQLite files. Move the project, or set `HOUND_DATABASE_URL=sqlite:///C:/hound-data/hound.db` (any unsynced folder). |
| `Cannot start: The database uses schema version N, but this version of Hound supports up to version M` | The file was upgraded by a newer Hound. Update Hound, or use another file: `HOUND_DATABASE_URL=sqlite:///data/other.db`. |
| `Cannot start: The database file already contains tables that do not match any Hound schema` | `HOUND_DATABASE_URL` points at a file from another program (or a damaged one). Move it away or point Hound at a new file. Hound leaves it untouched. |
| Port 8000 in use | `python run.py --port 8080` (and `--api-url http://127.0.0.1:8080` for the daemon). |
| Many events dropped under load | Raise `HOUND_QUEUE_MAX_SIZE` or narrow the BPF filter. |

Set `HOUND_LOG_LEVEL=DEBUG` for per-event diagnostics (this logs domain names).

## 17. Project structure

```text
hound/
├── .github/workflows/ci.yml   # CI: lint, types, tests, smoke test on Linux/Windows/macOS
├── app/
│   ├── __init__.py            # version
│   ├── __main__.py            # python -m app
│   ├── cli.py                 # serve / capture / interfaces / doctor commands
│   ├── api/
│   │   ├── app.py             # FastAPI factory: middleware, lifespan, routers
│   │   ├── deps.py            # dependency helpers, input validation
│   │   ├── openapi.py         # OpenAPI customisation
│   │   └── routes/            # health, events, export, devices, stats, metrics, coverage, ingest, admin, ws
│   ├── core/
│   │   ├── config.py          # Settings (env/.env/CLI), path resolution
│   │   ├── logging_config.py  # text/JSON structured logging
│   │   ├── netutils.py        # IP/domain validation & normalisation, entropy
│   │   ├── privileges.py      # root / Administrator detection
│   │   └── security.py        # ingest token handling
│   ├── database/
│   │   ├── engine.py          # engine, sessions, SQLite pragmas, auto-init
│   │   ├── migrations.py      # schema versioning: frozen baseline + ordered migrations
│   │   ├── backup.py          # consistent backup + guarded restore
│   │   ├── inspect.py         # read-only classification of database files
│   │   ├── tables.py          # ORM schema + indexes
│   │   └── repositories.py    # all SQL queries
│   ├── enrichment/
│   │   ├── blocklist.py       # file-based domain reputation
│   │   ├── geo.py             # GeoLocator protocol, source selection, simulated demo data
│   │   ├── geoip.py           # DB-IP Lite database: reader, safe download, updater
│   │   ├── countries.py       # ISO country names
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
│       ├── doctor.py          # read-only environment checks (`doctor` command)
│       ├── runtime.py         # composition root (wiring & lifecycle)
│       ├── processing.py      # worker: enrich → score → persist → publish
│       ├── store.py           # transactional persistence + retention
│       ├── queries.py         # read services for the API
│       ├── export.py          # CSV/JSON export, streamed (ADR-027)
│       ├── coverage.py        # what each deployment position can see (ADR-026)
│       ├── broadcaster.py     # WebSocket fan-out
│       └── mappers.py         # ORM → schema
├── config/
│   ├── blocklist.txt          # sample blocklist (reserved TLDs only)
│   ├── allowlist.txt          # your trusted domains/devices (empty by default)
│   ├── risk.toml              # signal weights and thresholds (all defaults, commented)
│   └── geo_ranges.csv         # illustrative CIDR → country table
├── data/                      # SQLite DB and ingest token (created at runtime)
├── docs/                      # status, roadmap, architecture, decision records
├── scripts/
│   ├── smoke_test.py          # end-to-end check of demo mode
│   ├── benchmark.py           # throughput/latency measurement (temporary DB)
│   ├── generate_test_traffic.py
│   ├── run_capture.sh         # sudo wrapper for the daemon (Linux/macOS)
│   └── run_capture.ps1        # Windows helper
├── tests/                     # pytest suite
├── .env.example
├── .gitignore
├── pyproject.toml             # pytest/ruff/mypy config, optional `hound` command
├── requirements.txt           # supported version ranges
├── requirements.lock          # exact, hash-checked versions (generated; install this)
├── requirements-dev.txt       # ruff, mypy, pip-audit (development only)
├── requirements-dev.lock      # the above, locked (generated; CI installs this)
├── CHANGELOG.md
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
* **Exports cannot run formulas.** CSV cells that a spreadsheet would evaluate
  (`=`, `+`, `-`, `@`, tab, CR at the start) are prefixed with `'`, because
  domains and interface names come from the network or the ingest API.
* **Input validation.** All query/path parameters are typed and bounded; IPs
  are parsed with `ipaddress`; domains are syntax-checked.
* **No injection.** SQL goes through SQLAlchemy expressions with bound
  parameters (`LIKE` wildcards escaped). No shell commands are executed.
* **Safe deserialisation.** Only JSON is parsed; stored JSON is re-validated
  when read. No `pickle`/`eval`.
* **Bounded memory.** Event queue, per-client WebSocket queues, DNS cache,
  behaviour tracker and the dashboard feed are all size-limited; the database
  has a row limit and an optional age limit (`HOUND_RETENTION_DAYS`).
* **Robustness.** Malformed packets are counted and skipped; database errors
  are logged, counted and surfaced in `/health` without stopping the pipeline;
  capture failures are reported in the UI.
* **Privacy.** Per-event details (domains) are logged only at DEBUG level.
  The database contains browsing metadata — protect `data/` accordingly. On Linux and
  macOS Hound creates a new `data/` directory as owner-only (`0700`) and restricts the
  database files to `0600`; on Windows they inherit your profile folder's permissions.
  If the project sits in a cloud-synced folder (OneDrive, Dropbox, iCloud
  Drive), `data/` — the database and the ingest token — is uploaded too. Keep
  the project outside synced folders, or point `HOUND_DATABASE_URL` and
  `HOUND_INGEST_TOKEN_PATH` at a local folder that is not synced.
* **No secrets in the repository.** `.env` is git-ignored; the ingest token is
  generated locally.
* Security response headers (`X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`) are set on HTTP responses.

## 19. Limitations

* **Countries are approximate.** DB-IP Lite is a free, country-level database
  (DB-IP states ~81 % accuracy); VPNs, cloud providers and anycast services
  (e.g. 1.1.1.1) are placed where their address is registered, not where you
  connect. Until the database is downloaded, countries show as *Unknown*. Demo
  mode without a database uses illustrative, **simulated** data.
* **Risk scores are heuristics.** They surface indicators associated with
  elevated risk; false positives (e.g. CDN hostnames with random-looking labels)
  and false negatives are expected — use the allowlist (§8) for ones you have
  checked. They are not malware detection.
* **Visibility** is limited to traffic that reaches the capture interface; see
  §9 *Where to run Hound* for what each position can and cannot see.
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

* Scheduled blocklist updates from public feeds.
* MAC-address/DHCP-based device identity and friendly device names.
* TLS SNI extraction to label HTTPS connections without DNS visibility.
* Alerting (desktop notifications, e-mail, webhooks) for dangerous events.
* Optional dashboard authentication for LAN-wide deployments.
* Per-device baselines ("first time this device contacted this country").
* Packaged service units (systemd, launchd, Windows service).

## 21. License

Hound is released under the [MIT License](LICENSE). Its dependencies keep their own
licences — most are permissive (MIT, BSD, Apache-2.0, MPL-2.0); Scapy, used for packet
capture and parsing, is GPL-2.0-only. Hound only imports the packages you install
from PyPI and does not ship them.

Country data: [IP Geolocation by DB-IP](https://db-ip.com), licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Hound downloads the
"IP to Country Lite" database from db-ip.com; it is not part of this repository.
