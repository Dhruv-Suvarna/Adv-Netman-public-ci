# Version 2 Phase 6 — standalone challenge / operations console

**Status: implemented, tested, and accepted on the real host desktop (2026-10-06); pull request ready for human review.**
All five views and collectors exist and were exercised against the production lab, first under a virtual display (section 11) and
then on the operator's desktop session with the host-installed Tk (section 12). Not merged; see
[Remaining work](#remaining-work).

## 1. Objective

One desktop application that lets an operator watch the lab continuously — endpoint connectivity, the NMAS / monitoring stack,
NetBox (NSOT), NMAS automation activity and interface counters — **without the NMAS website**. It observes; it controls nothing.

It lives in `challenge_console/` at the repository root. It is not a Django application, is not served by Gunicorn, is not
installed into `nmas-web.service`, and needs no browser, no website login and no HTTP call to the website for its data.

## 2. Safety boundary: read-only by construction

Phase 6 ran while the real 7-day probation `SOAK-000001` was active on R1, so "read-only" is enforced structurally, not by
convention.

| Boundary | How it is enforced | Where |
|---|---|---|
| Processes | One function starts processes, and only argv on a fixed allowlist: `docker inspect`, `docker ps`, `docker exec <c> ping -n -c 1 -W 1 -4/-6 <literal address>`, `docker exec <c> ip -j … show`, `docker exec <c> Cli -p 15 -c "show … [| json]"`, `systemctl show <unit> -p <state property>`. No shell, no stdin, no `sudo`, no options on `docker exec`. Anything else raises before a process exists. | `adapters/process.py` |
| HTTP | The transport has no method parameter: it can only `GET`. | `adapters/http.py` |
| Database | SQLite URI `mode=ro` **and** `PRAGMA query_only = ON`; only fixed `SELECT` statements, every column named; a new connection per refresh, closed immediately. | `adapters/automation_db.py` |
| NetBox | `GET` on five list endpoints. The token is read from the protected `netbox/.env`, lives only in the reader object, is sent only to the configured NetBox origin, and is never logged. | `adapters/netbox.py` |
| UI | The five views contain no button at all. The window has exactly five navigation buttons and the close dialog's three. No menu bar. | `ui/` |
| Privilege | Nothing elevates. The console uses the operator account's existing Docker-group access, the same access the website's read-only device sessions already use. | — |

It never creates or executes a Change, never opens a configuration session, never touches VLAN 200, the soak, a bundle, NetBox
content, the topology file or a container's lifecycle. Tests assert each row of the table above
(`tests/test_readonly_contract.py`, `tests/test_automation.py`, `tests/test_nsot.py`, `tests/test_ui.py`).

## 3. Architecture

```
                 Tk main thread                                   worker threads (one per collector, for the whole app lifetime)
 ┌────────────────────────────────────────────┐          ┌───────────────────────────────────────────────────────────────────┐
 │ ConsoleApp: sidebar + 5 stacked views        │          │ Supervisor ── watchdog                                              │
 │   show(view) only raises a frame             │          │   ├─ ConnectivityCollector      every  5 s   (+ a probe pool)       │
 │ UiBridge._pump  (root.after, 300 ms)         │◀─topic──│   ├─ InterfaceCounterCollector  every 10 s   (+ a device pool)      │
 │   drains a queue, re-renders the VISIBLE     │  names   │   ├─ ServiceTelemetryCollector  every 15 s                          │
 │   view from StateStore snapshots             │  only    │   ├─ AutomationCollector        every 20 s                          │
 └───────────────────────┬────────────────────┘          │   └─ NsotCollector              every 120 s                         │
                         │ read (copies, under lock)       └───────────────┬───────────────────────────────────────────────────┘
                         ▼                                                 │ write (under lock)        │ publish Event
                 ┌──────────────────────────────── StateStore ─────────────┘                           ▼
                 │ current state + bounded history rings                                           EventBus ──▶ SessionLog (writer thread)
                 └──────────────────────────────────────────────────────────────────────────────                append-only JSONL spool
```

| Layer | Module | Role |
|---|---|---|
| Configuration | `config.py` | Every path, endpoint, container name, period and bound. `NMAS_CONSOLE_<FIELD>` overrides. No secret field exists. |
| Models | `models.py` | Typed records (`Event`, `ProbeSample`, `ServiceObservation`, `FreshnessRow`, `InterfaceCounters`, …). Plain data. |
| State + bus | `state.py` | `StateStore` (current state, history rings, snapshot documents) and `EventBus` (store + log + subscribers). |
| Lifecycle | `supervisor.py` | One thread per collector, error → event, bounded backoff, restart of a dead worker, stall detection, bounded join. |
| Adapters | `adapters/` | The only code that starts a process, opens a socket or opens the database. Parsing lives here too. |
| Collectors | `collectors/` | One per view. Turn adapter results into state and events. Know nothing about Tk. |
| Logging | `sessionlog.py`, `redact.py` | Append-only JSONL written by its own thread; every record scrubbed before it reaches disk. |
| Headless core | `runtime.py` | Wires the above. Runs with no display (`--headless`) and in tests. |
| UI | `ui/` | `app.py` (window, navigation, close workflow), `bridge.py` (thread crossing), `views/` (five views), `widgets.py`. |
| Pure helpers | `filters.py` | Filtering and formatting used by the views, testable without a display. |

### Thread boundary

* Network, device, process and database calls happen **only** on worker threads. The Tk thread never waits for any of them.
* A worker never touches a widget. Crossing to the UI is one operation: `UiBridge._on_event` puts a topic name on a queue.
* `UiBridge._pump` runs from `root.after` on the Tk thread, drains the queue and asks the application to re-render the visible view
  from store snapshots. Collectors do not wait for the queue to be drained, so a slow render cannot delay a probe.
* Store reads return copies taken under the store lock.

### Hidden views keep collecting

Collectors are started once by `ConsoleRuntime.start()` and stopped once by `ConsoleRuntime.stop()`. `ConsoleApp.show()` raises a
frame and re-renders it; it has no reference to a collector's lifecycle. All five views are built at start-up and never destroyed,
so navigation resets nothing. Only the visible view is drawn; hidden ones accumulate in the store and are drawn when shown.

### Failure handling

| Failure | Result |
|---|---|
| One probe / device / component fails | A recorded sample or event for that target; the rest of the cycle continues. |
| A whole cycle fails (NetBox down, database busy) | `collector.error` event with a fixed code, exponential backoff capped at 120 s, the view keeps the last good data marked **STALE**. |
| Unexpected exception in a collector | `collector.error` with the exception *class name* only. Other collectors and the UI are unaffected. |
| A worker thread dies | The watchdog restarts it and emits `collector.restart`. |
| A worker goes silent | `collector.stall`, then `collector.resumed` when it recovers. |

Exception text is never logged or shown: it can echo connection parameters. Every failure has a fixed code.

## 4. The five views

### 4.1 Continuous Connectivity

The matrix is derived from `inventory.yml` `hosts` — the same source as the website's traffic endpoint catalogue.

| Row | Probe (source → destination) |
|---|---|
| H1 IPv4 | H1 → H2 |
| H1 IPv6 | H1 → H2 |
| H2 IPv4 | H2 → H3 |
| H2 IPv6 | H2 → H3 |
| H3 IPv4 | H3 → H1 |
| H3 IPv6 | H3 → H4 |
| H4 IPv6 | H4 → H1 |

* **H4 has no IPv4 row.** H4 is IPv6-only by design, so IPv4 is not a required test, is not probed, and is not shown as a failure.
* Each endpoint probes the next endpoint that has the family (a ring), so every row crosses the switched / routed fabric.
* **Why probes start inside the endpoints:** the NMAS host has no route to the host VLANs (only to the VLAN 200 management
  network), so a ping from the host would test nothing. Each probe is `docker exec <endpoint> ping -n -c 1 -W 1`, using the `ping`
  already in the image. Nothing is installed or left behind. Load: 7 echo requests every 5 s.
* **Addresses are discovered**, not configured: `ip -j addr show` in each endpoint, global scope, excluding Containerlab's `eth0`.
  H1–H3 take theirs from DHCP; discovery is repeated every 60 s and whenever an address is missing.
* **Every probe is a sample.** Pass, timeout, unreachable and "the probe could not run" (`SOURCE_CONTAINER_NOT_RUNNING`,
  `NO_TARGET_ADDRESS`, `PROBE_ERROR`, …) are each a timestamped sample in the row's ring and a line in the log. A state change
  additionally emits `connectivity.failure` / `connectivity.recovery`.
* Shown per row: endpoint, family, source and target address, state, last RTT, consecutive failures, failures / samples, loss
  over the buffer, last sample / success / failure / change, and the last 40 results as a strip. Below: the scrolling sample
  history, filterable to failures or to the selected row.

**One-hour buffer.** Each row keeps a time-bounded ring (`deque`): default **2 hours**, and the configuration clamps the window to
at least 3600 s, so it cannot be set below one hour. The ring is also length-bounded, so memory stays fixed
(7 rows × ~1,800 samples). Longer history is the session log's job.

### 4.2 NMAS / Telemetry

| Component | Evidence checked |
|---|---|
| NMAS Web | `nmas-web.service` state **and** `GET /healthz` returning `ok` |
| NetBox | container health **and** authenticated `GET /api/status/` |
| InfluxDB | container health **and** `GET /health` → `status: pass` |
| Grafana | container health **and** `GET /api/health` → `database: ok` |
| FreeRADIUS | container health only — a RADIUS Status-Server probe would need the shared secret; the row says so |
| privacyIDEA | container health **and** `GET` on its HTTPS front end |
| Traffic runner | socket unit state **and** the socket path being a socket (never connected to: that would start the runner) |
| Probation soak timer | timer unit state **and** the last tick's result |
| Topology / telemetry API | unit state **and** `GET /healthz` |
| gNMI collector, syslog ingest, SNMP trap receiver | unit state (their output is what the freshness table below proves) |

State is `UP` only if every check passed; `DOWN` if the deepest check (the endpoint) failed; `DEGRADED` if the endpoint answers
but the service manager disagrees; `UNKNOWN` if nothing could be determined. Each row shows when it was observed, since when it
has been in that state, and when it was last seen `UP`.

**Telemetry freshness** uses the project's own definition, not a new one. Source: the topology service's `/api/topology`
(the document the website's health engine reads). Classes and boundaries are those of `web/core/services/health/thresholds.py`:
`FRESH` ≤ 60 s < `STALE` ≤ 120 s < `EXPIRED`, no sample = `UNKNOWN`; the running service's thresholds win over
`monitoring/config/topology.yml`. Shown per device: latest sample timestamp, age, class, health, CPU, memory. If the source is
unreachable the view says so, greys the last values and logs `telemetry.error` every cycle.

**NMAS down.** If the website is unreachable the row reads `NMAS Web: DOWN` and every other view carries on, because none of them
uses the website. See [NMAS-down proof](#nmas-down-independence).

### 4.3 NSOT

A read-only snapshot of NetBox every 120 s: devices (role, platform / type, status, managed scope, management IPv4 / IPv6),
their interfaces and assigned addresses, prefixes, VLANs. Search matches device name, role, type, management address, interface
name and interface address; role and scope filters narrow the table. Selecting a device lists its interfaces and addresses.

Consistency indicators per device compare NSOT with the tracked inventory and the running lab: management address vs
`inventory.yml`, managed scope vs `inventory.yml`, and whether the lab container is running. The summary line shows running lab
containers against the expected 15. No second NSOT database exists: a snapshot is held in memory and replaced on refresh. When
NetBox is unavailable the last snapshot stays visible, marked **STALE** with its age.

### 4.4 Automation

Transport: **direct read-only SQLite access to the deployment database**
(`/home/student/Scripts/clab_dualstack_lab-deploy/web/db.sqlite3`). The automation records are rows there, so this works with the
website down, and it is a deliberate data-access layer rather than HTML scraping. Django is not imported.

Shown: the probation soak panel, and tabs for executions, Changes, validation, configuration validation, precheck / postcheck,
bundles, traffic runs, provisioning requests, credential-rotation runs and the rotation schedule.

The soak panel shows soak id, Probation bundle and its root, device(s), state, started, due, elapsed, remaining, collector
freshness, last sample, configuration drift, health and Golden eligibility. It is read every 20 s and never assumed: when the
soak completes, fails or is invalidated the panel follows. Collector freshness and eligibility use the website's own rules
(`soak/overview.py`): `FRESH` = a sample within two sample intervals, `NO_SAMPLE`, `STALE`; `IN_PROBATION`,
`ELIGIBLE_DECISION_REQUIRED`, `DECIDED_*`, `NOT_ELIGIBLE`. There is no promotion control.

Not read, by construction: credential references and key material, bundle manifests, execution reports, raw traffic output,
candidate configuration.

### 4.5 Interface Counters

All nine managed devices (from `inventory.yml`: every network device with a management-VLAN address, so not R5), each with its
platform's own source:

| Platform | Devices | Read |
|---|---|---|
| cEOS | R1, R2, S1–S4, mgmt_swt | `Cli -p 15 -c "show interfaces \| json"` — `interfaceCounters`; the credential-free read the health engine's `DockerEosSession` already uses |
| Ubuntu / FRR | R3, R4 | `ip -j -s link show` — the kernel's 64-bit `stats64` |

Interfaces are whatever each device reports this cycle; nothing is a fixed list. Shown: admin and operational state, speed,
RX / TX rate (bit/s and packets/s), raw RX / TX bytes and packets, errors, drops, sample time, last change.

* **Rates** are `delta counter / delta time` between two consecutive samples of the same interface.
* No rate is shown until two samples exist, when the device was not read, or for an interface without counters (an SVI or
  loopback on cEOS). These show `-`, never `0`.
* **Reset / rollover:** if any counter went backwards the interval is flagged `counter reset` and yields no rate; the next
  interval is valid again. A 64-bit wrap cannot be told from a reset, so neither is turned into a number.
* Linux veth links expose no negotiated speed through iproute2; the column is left empty rather than invented.
* Filters: device, interface / description search, and state — Up, Down, Admin down, Errors / drops, Carrying traffic, Changed
  recently (state change, counter reset, new errors / drops, appeared or disappeared in the last 5 minutes).
* A device that cannot be read keeps its last counters, greyed, with the reason; `counters.error` is logged every failed cycle.

## 5. Polling periods

| Collector | Default | Why |
|---|---|---|
| Connectivity | 5 s | continuity without load: 7 single echoes per cycle |
| Interface counters | 10 s | near-real-time rates; one show command per device |
| Services / telemetry | 15 s | the telemetry sample period is 20 s |
| Automation | 20 s | records change on operator actions and 5-minute ticks |
| NSOT | 120 s | NetBox changes rarely |

## 6. Append-only session log

`sessionlog.py`. One JSON object per line:

```json
{"ts":"2026-10-06T11:38:05.123Z","collector":"connectivity","kind":"connectivity.sample","target":"H1/IPV4","outcome":"PASS",
 "data":{"destination":"H2","source_address":"192.168.10.102","target_address":"192.168.20.101","rtt_ms":3.95,"reason":""}}
```

* Opened `O_APPEND | O_EXCL`, mode `0600`; never rewritten, truncated or seeked. A dedicated thread writes, so no collector and no
  UI code waits on the disk.
* Record kinds: `session.meta`, `app.start`, `app.stop`, `session.summary`; `collector.start / stop / error / recovered /
  restart / stall / resumed`; `connectivity.plan / addresses / sample / failure / recovery / discovery_error`;
  `service.sample / transition`; `telemetry.sample / transition / error / recovered`; `nsot.snapshot`;
  `automation.snapshot / soak_change`; `counters.plan / sample / change / error / recovered`.
* `counters.sample` carries the raw counters of every interface, so rates can be recomputed from a saved session.
* **Secrets.** Collectors publish fixed codes and parsed facts only. Independently, `redact.py` scrubs every record on its way
  to disk: values under secret-named keys, bearer / token / basic credentials, NetBox v2 tokens, `key=value` credentials,
  credentials in URLs, crypt hashes and private-key blocks.
* While running, the log is a spool file under `~/.local/state/nmas-challenge-console/spool/` (`XDG_STATE_HOME`). It does not need
  InfluxDB and nothing is written inside the Git checkout.

Volume: 6.0 MB for the 63-minute live session (dominated by counter samples).

## 7. Closing: Save / Don't Save / Cancel

Closing the window opens a modal dialog with exactly those three buttons.

| Choice | Effect |
|---|---|
| **Save** | Stop collectors, write the closing `session.summary` and `app.stop`, flush and close the log, move it to the destination, exit. |
| **Don't Save** | Stop collectors, delete the session log, exit. |
| **Cancel** (also Escape, or closing the dialog) | Nothing happens. Collectors were never touched; history is intact. |

Default destination: `~/.local/share/nmas-challenge-console/sessions/nmas-challenge-console-<UTC start>-<session id>.jsonl`
(`XDG_DATA_HOME`; `--save-dir` / `NMAS_CONSOLE_SAVE_DIR`). "Change…" in the dialog picks another file. File names are sanitised
and an existing file is never overwritten. If the chosen location cannot be written, the session is kept in the spool and the
path is shown.

**Shutdown** (`ConsoleRuntime.stop`): set the shared stop event → collectors finish their current bounded call → probe / device
pools shut down → each worker is joined within a shared 6 s budget → summary and `app.stop` are logged → the log writer is joined
and the file fsynced → the Tk root is destroyed. Any worker still alive is named in `app.stop` and makes the exit status non-zero.
SIGINT / SIGTERM stop cleanly and leave the session in the spool.

## 8. Data sources

| View | Source | Access |
|---|---|---|
| Connectivity | H1–H4 containers | `docker exec … ip -j addr show`, `docker exec … ping -c 1` |
| NMAS / Telemetry | systemd, Docker, health endpoints, topology service | `systemctl show`, `docker inspect`, HTTP `GET` |
| NSOT | NetBox REST API | HTTP `GET` with the token from `<deploy>/netbox/.env` |
| NSOT consistency | `inventory.yml`, Docker | file read, `docker ps` |
| Automation | deployment `db.sqlite3` | SQLite `mode=ro` |
| Interface counters | nine managed device containers | `docker exec … Cli … show interfaces \| json`, `docker exec … ip -j -s link show` |

## 9. Launch

```
scripts/run_challenge_console.sh                 # the console
scripts/run_challenge_console.sh --headless 60   # collectors only, no display: prints a summary and saves the session
scripts/run_challenge_console.sh --print-config  # the effective configuration
python -m challenge_console                      # the same, from the repository root
```

The launcher uses the shared environment `/home/student/Scripts/.venv/bin/python` (`NMAS_CONSOLE_PYTHON` overrides).

**Dependencies.** Python standard library plus PyYAML (already in the shared environment). No new Python package.
Tkinter itself is a distribution package:

```
sudo apt install python3-tk
```

It is a host prerequisite. It was installed on the NMAS host by the operator on 2026-10-06 (`python3-tk 3.12.3-0ubuntu1`,
Tk 8.6.14); the shared virtual environment picks it up from the system Python with no further step. Without it the launcher prints
that command and exits with status 2. `--headless` needs neither Tkinter nor a display.

Configuration: any `ConsoleConfig` field through `NMAS_CONSOLE_<FIELD>`, for example
`NMAS_CONSOLE_CONNECTIVITY_INTERVAL=2`, `NMAS_CONSOLE_DEPLOY_ROOT=…`, `NMAS_CONSOLE_SAVE_DIR=…`.

## 10. Tests

| Suite | Tests | Covers |
|---|---|---|
| `tests/test_core.py` | 23 | five collectors concurrent; failure isolation; every failed cycle an event; backoff; restart; stall; bounded stop with no worker left; event bus under concurrency; append-only log; save / discard / cancel; redaction; configuration; one-hour ring |
| `tests/test_connectivity.py` | 13 | the seven required rows; no H4 IPv4; pass, timeout, recovery, consecutive failures; RTT parsing; discovery; a probe that cannot run; retention |
| `tests/test_services.py` | 12 | up, down, health-endpoint failure, degraded, unknown; NMAS web down; transitions; fresh / stale / expired / missing / recovery; thresholds equal the project's |
| `tests/test_nsot.py` | 11 | enumeration; interface / address parsing; pagination; empty; unavailable; stale read; token handling; GET only; search and filters |
| `tests/test_automation.py` | 15 | the SOAK-000001 picture; state read not assumed; collector freshness; running / completed / failed items; no secret column; the connection cannot write; each read-only layer (`mode=ro`, `query_only`) refuses writes on its own; busy / missing database; no control surface |
| `tests/test_counters.py` | 15 | both parsers; rate; no rate before two samples; zero traffic; reset / rollover; errors / drops; appear / disappear; filters; unavailable device |
| `tests/test_readonly_contract.py` | 8 | the process allowlist (8 allowed, 33 refused); no Django import; process / socket / database only in adapters; Tk only in `ui/`; no shell, `sudo`, Canvas or write verb |
| `tests/test_ui.py` | 16 | every collector keeps running while its view is hidden; history grows across view switches with no gap; only the visible view renders; widgets touched only on the Tk thread; a slow render does not delay collection; Save / Don't Save / Cancel; the dialog's three buttons; no control in any view |
| `web/core/tests/test_challenge_console.py` | 7 | every console query prepared against the migrated schema; no secret column; freshness and soak vocabulary equal the website's; the console is not a Django app. Also loads the 113 console tests into the Django gate. |

```
python -m unittest discover -s challenge_console/tests -t .            # 113 tests; the 16 Tk tests skip without a display
xvfb-run -a python -m unittest discover -s challenge_console/tests -t .   # all 113 (needs python3-tk); or run it on the desktop session
cd web && DJANGO_DEBUG=true python manage.py test core.tests.test_challenge_console
```

Unit tests use test doubles throughout; none reaches a device, a service or the network. The fake process runner still passes
every argv through the real allowlist.

**Mutation checks.** Each mutant removes one guarantee from a scratch copy of the package, and the suite must then fail.
Session 1 ran 22 (under the unpacked Tk). The final session re-ran 23 with the host Tk on the desktop display — history not
recorded, retention not pruned, counter reset ignored, database opened read-write, `query_only` dropped, a secret column selected,
Cancel exiting, navigation stopping collectors, a widget touched from a worker thread, hidden views rendered, a control button in
a view, no backoff, an unexpected failure not logged, a dead worker not restarted, samples logged only on transitions, a counter
failure not logged, H4 IPv4 probed, "active" alone reported as UP, EXPIRED never reported, EOS configuration commands allowed,
secret keys not redacted, Don't Save keeping the file, a world-readable log. **22 / 23 were caught by the 112 tests at `55e3ae1`.**
The survivor was "database opened read-write": with `PRAGMA query_only` still on, writes were still refused, so the product stayed
read-only, but the `mode=ro` layer had no behavioural test of its own. `e5554da` adds
`test_each_read_only_layer_refuses_writes_on_its_own`; **23 / 23 are caught at `e5554da`.**
Evidence: `docs/evidence/v2-phase6/mutation-checks.json`.

**Local Tier-3** (`tier3.py --base origin/main --mode full`) on the final executable commit `e5554da`: **PASS**, no warnings —
hygiene (8,432 added lines), syntax (717 files), Django check, migration drift, 2,276 Django tests, 476 monitoring tests, Grafana
drift. It ran with the desktop display available, so the 16 Tk tests executed inside the gate. The optional lab verifiers are
not part of the offline gate and were not run. Report: `docs/evidence/v2-phase6/tier3-local.json`. (The earlier run on `2781e77`
was also PASS, with 2,275 Django tests.) Commits after `e5554da` on this branch change documentation and evidence only.

`challenge_console` is a classified subsystem (`web/core/services/ci/rules.py`): a change under `challenge_console/**`
selects `core.tests.test_challenge_console`, and changes to models, migrations, the soak, health thresholds or the inventory
select it too, because the console's contract with them is tested there.

## 11. Live proof — 2026-10-06

Evidence: `docs/evidence/v2-phase6/live-proof.json`, produced by `python -m challenge_console.ui.live_proof` driving the real
application (real collectors, real views, real close dialog) against production under a virtual display. Read-only throughout.

| # | Requirement | Observed |
|---|---|---|
| 1 | All five views load | connectivity 7 rows, components 12, NSOT 11 devices, automation 3 executions, counters 84 interfaces |
| 2 | Five collectors run simultaneously | five `console-<collector>` threads alive together, plus probe / device pools, watchdog and log writer |
| 3, 10 | Connectivity continues while hidden | samples per row 8 → 13 with NSOT visible → 18 with Interface Counters visible; largest gap 5.49 s at a 5 s period; 0 restarts |
| 4 | H1–H3 IPv4 + IPv6 | six rows `UP`, 0 failures, RTT 2–7 ms |
| 5 | H4 IPv6 only | `H4/IPV6` `UP`; no `H4/IPV4` row exists |
| 6 | Service and freshness state | 12 / 12 components `UP`; R1–R4, S1–S4, mgmt_swt (and unmanaged R5) `FRESH`, thresholds 60 / 120 s |
| 7 | NSOT | 11 devices, 41 interfaces, 83 addresses, 33 prefixes, 9 VLANs; nine managed devices `MATCH` inventory; lab 15 / 15 |
| 8 | Automation shows the soak | `SOAK-000001`, `BND-PROB-000001`, R1, `RUNNING`, started 10:56:22Z, due 2026-10-13 10:56:22Z, collector `FRESH`, last sample `PASS`, drift `MATCH`, `HEALTHY`, `IN_PROBATION` |
| 9 | Counters change | 9 / 9 devices read; 58 interface counters changed between two reads; 60 interfaces with derived rates |
| 11 | Save | 446 records, 216 kB, mode `0600`, first `session.meta`, last `app.stop`; all five collectors in the log; no worker left |
| 12 | Cancel resumes | dialog showed `Save`, `Don't Save`, `Cancel`; after Cancel the window stayed open and every collector advanced |
| 13 | Don't Save, separate session | spool existed while running, gone afterwards; window closed; no worker left |

### Extended session — one hour of history

Evidence: `docs/evidence/v2-phase6/extended-run.json`. The real application ran for 63 minutes (11:44:37Z – 12:47:37Z) against
the lab, switching view every minute (63 switches), then closed with Save.

| Check | Observed |
|---|---|
| In-memory history per row | 756 samples spanning 3,774 s — more than one hour, all seven rows, nothing evicted |
| Continuity | largest gap between samples 5.84 s at a 5 s period; no gap above two periods; 0 failed probes |
| Collectors | connectivity 756 cycles, counters 378, services 252, automation 189, NSOT 32; 0 errors, 0 restarts, 0 stalls |
| UI | every view rendered 800+ times; slowest single UI iteration 0.27 s |
| Memory | resident size 55 MB after 30 s, 79 MB at the end |
| Saved session | 12,463 records, 6.0 MB; no `ERROR` record; no worker left |

SOAK-000001 took its own samples at 11:43, 11:59, 12:14, 12:29 and 12:44 during that hour: all `PASS` / `HEALTHY` / `FRESH`,
drift 0, no interference.

### NMAS-down independence

Evidence: `docs/evidence/v2-phase6/nmas-web-down.json`. The production website was **not** stopped. The console's NMAS-web
health URL was pointed at a closed local port, every other source being the live lab: `NMAS Web: DOWN`
(`http: CONNECTION_REFUSED`), the other 11 components `UP`, 7 / 7 paths `UP`, telemetry `FRESH`, NSOT and automation read, 9 / 9
devices' counters read, no collector error. The unit tests cover the same case with the service unit inactive as well, and a
contract test proves no module imports Django or the website.

### Production after the proof

| Check | Result |
|---|---|
| `srlceos01` | 15 / 15 running |
| `SOAK-000001` | `RUNNING`, start / due / baseline digest unchanged; 21 samples by 15:57Z, every one `PASS` / `HEALTHY` / `FRESH`, drift 0 |
| R1 `Loopback105` | `FOR-SOAK-TESTING`, `192.168.255.105/32`, `2001:db8:255::105/128` — unchanged |
| Deployment database | modified only by the soak collector's own ticks; unchanged across the console's reads between ticks |
| Changes, executions, bundles, traffic runs, audit rows | counts unchanged |
| `nmas-web`, soak timer, traffic runner socket | active; no `nmas-traffic` container |

## 12. Real desktop acceptance — 2026-10-06

Evidence: `docs/evidence/v2-phase6/real-desktop.json` and `docs/evidence/v2-phase6/screenshots/`.

**Prerequisite.** `python3-tk 3.12.3-0ubuntu1` installed on the host by the operator. `/usr/bin/python3` and
`/home/student/Scripts/.venv/bin/python` both import `tkinter`: `tkinter.TkVersion` 8.6, Tcl/Tk patch level 8.6.14, Tk library
`/usr/share/tcltk/tk8.6`. No `PYTHONPATH` / `LD_LIBRARY_PATH` override and no unpacked package was used anywhere in this pass.

**How it was done.** The console was started on the operator's own desktop session (GNOME on Wayland, seat0, unlocked; Tk draws
through the session's Xwayland, display `:0`, 1920x860) by the supported launchers, without `--headless` and without a virtual
display. The window was closed through the window manager (`WM_DELETE_WINDOW`). The views were read and their controls operated
from a second process over Tk `send` on the same display (button and checkbox `invoke`, combobox selection events, typing into
the search fields), and the window was screenshotted. **No person used the mouse**: this is the real application on the real
desktop, driven and inspected programmatically. Nothing in production was written or restarted.

| Check | Observed |
|---|---|
| Tk tests on the real display | 16 / 16 pass, none skipped. Whole console suite on the display: 113 pass, 0 skipped; without a display: 113 pass, 16 skipped (the Tk tests — the only skips, and legitimate) |
| Launch | Session A `scripts/run_challenge_console.sh` (16:27:03Z – 16:33:00Z); session B `python -m challenge_console`. Window 1500x791, title `NMAS Challenge Console 6.0.0 -- read-only`. Both exited 0 with empty stderr: no Tk callback or thread exception |
| Rendering | All five views drawn; no label, button, entry or combobox allocated less than it requests in any view. Cosmetic only: two table headings are cut by a few pixels ("Last sample", "Observed (UTC)") and the wide tables scroll horizontally |
| View switching | 20 consecutive switches: mean 33 ms, worst 57 ms |
| Connectivity | Exactly seven rows: H1, H2, H3 each IPv4 + IPv6, H4 IPv6 only; **no H4 IPv4 row**. 7 / 7 UP, RTT 2–9 ms, last-sample time and sample count advancing every 5 s (504 samples, 72 per row, in the saved session). "Failures only" → 0 rows; "Selected row only" on H4/IPv6 → only H4/IPv6 samples; both restore |
| NMAS / Telemetry | 12 / 12 components UP with live observation times: NMAS Web (systemd active + HTTP 200), NetBox, InfluxDB, Grafana, FreeRADIUS (container health), privacyIDEA, traffic runner socket, probation soak timer (last run success), topology API, gNMI collector, syslog ingest, SNMP trap receiver. Freshness: R1–R4, S1–S4, mgmt_swt and R5 `FRESH`, ages 11–22 s, latest samples 16:28:06Z–16:28:17Z at a 16:28:19Z read. The website was not stopped; the web-down behaviour stays proven as in section 11 |
| NSOT | 11 devices, 41 interfaces, 83 addresses, 33 prefixes, 9 VLANs; lab 15 / 15; nine managed devices `MATCH`. Search by management address → R1; by interface name `Vlan101` → R1, R3; by name `mgmt` → mgmt_swt. Role `Router` → R1–R4; scope `Unmanaged` → R5, WebServer; `Managed` → the nine. Selecting R1 lists its 10 interface / address rows. Prefixes and VLANs tabs populated. GET only |
| Automation | `SOAK-000001` (change `CHG-20261006-0002`), bundle `BND-PROB-000001` (root `BND-DEP-000001`), device R1, state `RUNNING`, started 2026-10-06 10:56:22Z, due 2026-10-13 10:56:22Z, elapsed 05:32:34 (3.30 %), remaining 6d 18:27:25, health `HEALTHY`, collector `FRESH` (23 samples), last sample `PASS`, drift `MATCH`, eligibility `IN_PROBATION`. Read from the production database, not assumed. Ten tabs read from production records (Provisioning is empty, as it is in production) |
| No control surface | The whole window holds five buttons, all navigation; no menu bar. The close dialog adds Save, Don't Save, Cancel and "Change…" (destination file) |
| Interface Counters | 9 / 9 managed devices read, 84 interfaces discovered (R1 9, R2 8, R3 10, R4 10, S1 12, S2 12, S3 6, S4 6, mgmt_swt 11), raw RX / TX bytes and packets, errors, drops, admin / oper state. Device filter `R3` → its 10 interfaces; name filter `Loopback` → 5 (including R1 `Loopback105`); state filters Up 84, Down 0, Admin down 0, Errors / drops 8, Carrying traffic 56, Changed recently 2. 56 raw counters moved within 11 s |
| No fabricated rate | Session B, immediately after the first counter read: 84 rows, 60 with raw counters, **0 with a rate**. Rates appeared only after the second read. Interfaces without counters (SVIs, loopbacks) show `-` throughout |
| Hidden collectors | Connectivity at 36 samples per row; NSOT shown for 42 s; back on Connectivity: 45 per row, largest gap in the history 6 s at a 5 s period (1 s display resolution). Counters: cycle 23 → 26 and the R1 Ethernet1 counters and sample time advanced while Telemetry was shown for 34 s. All five cycle counters kept rising throughout |
| Cancel | Window-manager close → dialog with Save / Don't Save / Cancel. Left open 8 s: collectors kept cycling behind it. Cancel: dialog gone, window still open, samples 57 → 61 per row, nothing reset |
| Save | Exit 0, `Session saved: …` printed, spool empty, no process or window left. File `~/.local/share/nmas-challenge-console/sessions/nmas-challenge-console-20261006T162703Z-ebd4c7b7003c.jsonl`, mode `0600`, 578,579 bytes, 1,205 JSON lines, first `session.meta`, last `app.stop` with `leftover_workers: []` |
| Don't Save | Spool file existed (mode `0600`) while running, gone afterwards; no saved file created; exit 0; no process or window left |

**The saved session.** Present: `session.meta` (application, version, schema, session id, configuration), `app.start` / `app.stop`,
`session.summary`, `collector.start` / `stop` for all five collectors, 504 `connectivity.sample`, 288 `service.sample` across the
12 components, 24 `telemetry.sample`, 3 `nsot.snapshot`, 18 `automation.snapshot` (carrying `SOAK-000001`), 324 `counters.sample`
(36 per device, all nine) and 24 `counters.change`. No collector error occurred, so no error record exists in it. Absent: no
secret-named key, bearer / basic / token credential, NetBox token, 40-hex token, `key=value` credential, URL credential, crypt
hash, private-key block, `otpauth` URI or base32 seed; and none of the secret values held in the deployment's own protected
files (`netbox/.env` and the other environment / runtime secret files, 11 values) occurs in the file. The scrubber tests
(`test_secrets_never_reach_the_file`, `test_redaction_helpers`) pass, and the "secret keys not redacted" mutant is caught.

**Column sorting** was left out: at 7 to 84 rows with device / name / state filters, the pass did not show it to be needed.

### Production after the desktop pass

| Check | Result |
|---|---|
| `srlceos01` | 15 / 15 running, before and after |
| `SOAK-000001` | `RUNNING`; start 2026-10-06 10:56:22.446525 and due 2026-10-13 10:56:22.446525 unchanged; baseline digest unchanged; 22 → 23 samples (the soak's own 16:27:44Z tick), every one `PASS`, drift 0 |
| R1 `Loopback105` | `FOR-SOAK-TESTING`, `192.168.255.105/32`, `2001:db8:255::105/128` — unchanged |
| Changes, executions, bundles, traffic runs, provisioning runs, Golden decisions | counts unchanged (4, 3, 2, 1, 0, 0) |
| `nmas-web`, soak timer, traffic runner socket | active; no `nmas-traffic` container; no console process left |

## Known limitations

1. **`python3-tk` is a host prerequisite** (`sudo apt install python3-tk`); the console does not install it. It is installed
   on the NMAS host now.
2. **The desktop pass was driven programmatically.** The console ran on the real desktop with the host Tk, but its controls
   were operated over Tk `send` and it was checked by reading widgets and screenshots, not by a person with a mouse. The longest
   run is still the scripted 63-minute session under a virtual display; the two desktop sessions lasted about 6 minutes and 20 seconds.
3. **FreeRADIUS** is judged by container health only (a protocol probe needs the shared secret).
4. **The automation tab reads the deployment database's schema directly.** A migration that renames a column the console reads
   is caught by `core.tests.test_challenge_console`, and at run time shows `DB_SCHEMA_MISMATCH` rather than wrong data.
5. **Linux interface speed** is not shown (not exposed for veth through iproute2).
6. **cEOS counters use the container's own `Cli`**, not SSH: no credential, no MFA prompt, and no dependency on the management
   VLAN — but it does depend on the operator's Docker-group access.
7. The Tk tests need a display; a gate run without one (hosted CI) skips those 16 and runs the other 97 console tests.
8. Tables are not sortable by column, and the views have no chart: the "recent" strip is text. No Tk `Canvas` is used.
9. Two table headings are cut by a few pixels at the default column widths, and the wide tables need horizontal scrolling at
   1500 px. Cosmetic.
10. NetBox does not model R1 `Loopback105` (the soak's test interface), so the NSOT view does not list it; the Interface
    Counters view, which reads the device, does. The console reports what each source holds and does not reconcile them.

## Remaining work

1. Human review of the pull request, and the merge decision.
2. Optional polish: column sorting, per-row sample export, wider default columns for the two headings that are cut.
