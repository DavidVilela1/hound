# Field trial (16d → milestone M7)

> How to prove Hound on a real network. Position for the first trial: **this computer
> only** (the owner's Windows laptop). What this proves and what it does not is stated at
> the end.

## What "field-proofed" means (M7 acceptance)

| # | Criterion | Evidence |
|---|---|---|
| 1 | Hound ran on real traffic for **≥ 7 days** (days the laptop was in use count) | trial log: start/stop per day |
| 2 | **Nothing lost** — or every loss explained | `GET /api/metrics` → `loss.total_events_lost` each day |
| 3 | **Every** suspicious/dangerous event reviewed | flagged-events CSV with a verdict column |
| 4 | False-positive rate **written down and accepted** by the owner | summary at the end |
| 5 | No crash or stuck state without a documented cause | trial log, terminal output |

## Day 0 — setup (about 20 minutes)

1. **Update** to the latest Hound, then install the new dependency:
   `pip install -r requirements.lock` (inside the venv).
2. **Edit `.env`** (in the project folder):
   * delete the line `HOUND_GEO_MODE=simulated` if it is there (it forces invented
     countries);
   * add `HOUND_DEPLOYMENT_POSITION=this_computer`;
   * use a **fresh database for the trial**, so demo and test events do not mix in:
     `HOUND_DATABASE_URL=sqlite:///C:/hound-data/trial.db`;
   * optional: `HOUND_RETENTION_DAYS=30`.
3. `python run.py doctor` → **0 problems**. The *Geolocation* line may say "no DB-IP
   database yet" — the server downloads it when it starts.
4. Start Hound — two PowerShell windows, both in the project folder with the venv active:
   * normal window: `python run.py`
   * **Administrator** window: `python run.py capture -i "Wi-Fi"`
5. After ~15 minutes of normal use, open <http://127.0.0.1:8000> and check:
   * the coverage line says *"As expected for this position: one device (…)"*;
   * **Countries** tab: *"countries from DB-IP Lite 2026-…"* and the DB-IP credit link
     (if it says "no geolocation database yet", run `python run.py geo update`, then
     `python run.py reload`);
   * <http://127.0.0.1:8000/api/metrics>: `loss.total_events_lost` is `0`.
6. Start a **trial log** (a spreadsheet is fine) with two sheets:
   * **Days:** date · hours running · restarts/sleeps · `total_events_lost` · events that
     day · notes (errors, Wi-Fi changes, VPN on/off).
   * **Flagged:** event id · time · domain/destination · level · reason codes · verdict
     (*real concern* / *false positive* / *unsure*) · why · action taken.

## Every day (5 minutes)

1. **Is it capturing?** The *Last minute* tile moves while you browse. After the laptop
   **wakes from sleep** or **changes Wi-Fi**, check again — if it stopped, restart the
   capture window and write it in the log (this is exactly what the trial must find).
2. **Did we lose anything?** Open `/api/metrics`; note `loss.total_events_lost` (counters
   restart at zero when the server restarts — note restarts).
3. **Review what was flagged since yesterday:** download
   <http://127.0.0.1:8000/api/export/events?min_risk_level=suspicious> (or *Download CSV*
   on the Live feed with *Suspicious +* selected). For each new row, fill in the verdict.
   The `risk_reasons` column says why it was flagged.
4. **Days 1–3: observe only** — do not change settings, so there is an untuned baseline.
   **From day 4:** fix false positives you are sure about:
   * a domain or device you trust → a line in `config/allowlist.txt`;
   * a signal that is too eager → a value in `config/risk.toml`;
   then `python run.py reload`, and write the change and the date in the log.

## Day 7–8 — wrap up

1. Downloads: all events (`/api/export/events`), all devices (`/api/export/devices`),
   `/api/metrics` (save the page), and `python run.py backup`.
2. Numbers for the summary:
   * events in total, per day;
   * flagged events: suspicious / dangerous; how many were false positives
     → **false-positive rate = false positives ÷ flagged**, before and after tuning;
   * which reason codes caused the false positives;
   * `total_events_lost` per day, restarts, sleep/Wi-Fi problems.
3. Send the summary (and the reason codes behind false positives) for the tuning pass.
   **Privacy:** the CSV files are your browsing history — share only what you are
   comfortable with; reason codes and counts are enough for tuning.
4. Decide: is the false-positive rate acceptable? If yes, M7 is reached for the
   *this computer* position and the results are recorded in `docs/PROJECT_STATUS.md`
   and `docs/ROADMAP.md`.

## What a laptop-only trial proves — and what it does not

* **Proves:** Hound runs for a week on Windows with real traffic; capture survives (or
  does not survive) sleep and network changes; losses are measured; the risk signals'
  false-positive rate on real browsing; real countries; export and review workflow.
* **Does not prove:** anything about other devices — they are invisible from a laptop
  (README §9 *Where to run Hound*). A household-wide trial needs a machine that sees the
  network, e.g. a Raspberry Pi as the network's DNS server (`dns_server` position).
