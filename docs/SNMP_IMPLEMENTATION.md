# SNMP Implementation

Status: implemented and verified against the live approved baseline
(R1, R2, R5, S1, S2, S3, S4, `mgmt_swt` as cEOS; R3, R4 as Ubuntu/FRR).
Containerlab lifecycle, topology, addressing, routing, VLANs, NAT, DHCP,
node kinds, and links were not touched. This document only claims a check as
complete where it was actually re-run and observed passing in this session;
see the evidence sections below.

## Architecture

SNMP is Infrastructure-as-Code end to end:

- `inventory.yml` declares, per device, the monitoring platform, management
  address (or `auto` to resolve the live container's data-plane address, used
  for R5), source interface, and the shared SNMPv3 policy (`nmas-monitor`,
  SHA-256 auth, AES-128 privacy, receiver `192.168.200.100`).
- `modules/snmp.py` is the single implementation: it renders per-platform
  configuration from `templates/monitoring/`, applies it, provisions the NMAS
  receiver's USM state, polls every device, and writes/reads back InfluxDB.
  It contains no device-specific logic outside the templates it renders.
- `master.py` is a thin orchestrator: it imports `ensure_snmp_infrastructure`
  from `modules/snmp.py` and calls it either as part of the full run or via
  `--snmp-only`. No SNMP logic is duplicated in `master.py`.
- Runtime secrets (`monitoring/runtime/snmp-secrets.json`,
  `monitoring/runtime/snmp-engines.json`, per-device state hashes) are
  generated on first run, mode `600`, and excluded from Git by
  `monitoring/runtime/*` in `.gitignore`. No SNMP password exists in Git.

## `master.py` SNMP integration

```
python3 master.py --snmp-only [--verbose]
```

`modules/nmas.py:entrypoint()` parses `--snmp-only` as mutually exclusive with
`--nmas-only`. It validates the venv bootstrap and inventory, then calls
`modules.snmp.ensure_snmp_infrastructure()` and exits — it does not deploy or
destroy Containerlab, and does not re-run Lab 1 routing/topology
configuration (`configure_host`, `bootstrap_linux_ssh`, and the netmiko-based
device provisioning in `master.py`'s `main()` are never imported on this
path). The full (no-flag) run calls the same `ensure_snmp_infrastructure()`
function after Lab 1 provisioning, so there is exactly one SNMP
implementation shared by both modes.

## `modules/snmp.py` summary

- `devices()` — reads `inventory.yml`, resolves each device's live container
  and management address, enforces the SHA-256/AES-only policy.
- `configure_device()` — cEOS: renders `templates/monitoring/ceos_snmp.j2`,
  diffs a SHA-256 hash of the rendered config and the live
  `show running-config | section snmp` output against a stored state file,
  and only pushes/`write memory`s when something actually changed. Ubuntu/FRR:
  renders `snmpd.conf.j2`, ships it plus the link-watcher script into the
  container over `docker exec ... python3 -c <script>` on stdin, and lets
  `provision_linux_snmp.py` do the idempotent convergence inside the
  container.
- `ensure_receiver()` — reads each device's authoritative SNMPv3 engine ID
  (cEOS via CLI, Ubuntu/FRR via a live `snmpget`), plus a second synthetic
  engine ID per Ubuntu/FRR device for its link-watcher notification
  originator, and converges the NMAS `snmptrapd` USM state to match.
- `collect()` / `verify_snmp()` — polls `sysName`, `sysUpTime`, the full
  interface table, and CPU; validates the response shape; writes line-protocol
  points to InfluxDB; queries the same write back before accepting the poll
  as verified.

## cEOS SNMP approach

Native EOS SNMP agent, configured entirely from the CLI
(`templates/monitoring/ceos_snmp.j2`): an ACL restricting SNMP to the NMAS
address, a read-only view (`iso`), an SNMPv3-only group (`priv` security
level), the `nmas-monitor` user with SHA-256/AES-128, a `trap` host pointing
at the receiver, and native `linkUp`/`linkDown` notification enablement. EOS
natively supports SNMPv3 authPriv notifications, so no companion process is
needed on cEOS.

## R3/R4 (Ubuntu/FRR) SNMP approach

R3 and R4 have no `systemd` — PID 1 is `sleep infinity` — so nothing can be
"enabled" as a service. `modules/snmp.py` and
`monitoring/scripts/provision_linux_snmp.py` instead:

1. Install `snmpd`/`snmp` via `apt-get` with a `policy-rc.d` guard so the
   package's postinst never starts a default agent.
2. Write a repository-owned `/etc/snmp/nmas-snmpd.conf`
   (`templates/monitoring/snmpd.conf.j2`) — SNMPv3-only, `rouser` read view,
   no community strings, no Event-MIB/`mteTrigger` configuration.
3. Persist the USM user directly into `/var/lib/snmp/snmpd.conf` via
   `createUser`, then start `snmpd` by hand under
   `start-stop-daemon --background --make-pidfile`, tracked by
   `/run/nmas-snmpd.pid`.
4. Re-run detection is PID-file + `/proc/<pid>/cmdline` based (there is no
   `systemctl status` without `systemd`), and only restarts the daemon when
   the rendered config or credentials actually changed.

### Why a Linux link-state watcher instead of the Event-MIB/`mteTrigger` path

An earlier iteration tried to get link-state notifications from `snmpd`'s own
internal Event-MIB (`mteTrigger`) polling engine, configured via
`defAuthType`/`defAuthPassphrase`/`defPrivType`/`defPrivPassphrase` directives
in `snmpd.conf`. Those directives are **client-side** `snmp.conf` tokens, not
valid `snmpd.conf` agent directives, so `snmpd` logged
`Unknown token: defAuthType` (and the matching `defPrivType`/passphrase
lines) on every start, and the internal `mteTrigger` query used to detect
interface changes then failed repeatedly (`failed to run mteTrigger query`)
because it had no working credentials to send itself authenticated
notifications.

The design was changed to a dedicated, repository-owned Python link-state
watcher (`monitoring/scripts/linux_link_notifications.py`), started and
tracked the same way as `snmpd` (PID file, idempotent restart-on-change,
no `systemd`). It polls `/sys/class/net/*/ifindex`, `flags`, and `operstate`
every 2 seconds, and on any `ifOperStatus` transition sends a real SNMPv3
`authPriv` `snmptrap` (SHA-256/AES-128) to `192.168.200.100:162` with
`ifIndex`/`ifAdminStatus`/`ifOperStatus` varbinds, using its own dedicated
notification-originator engine ID
(`0x80001f8804` + hex of `nmas-<device>-events`) — kept separate from the
polling agent's engine ID so the two roles cannot be confused, and both are
registered independently at the receiver.

**Current tracked state check:** `templates/monitoring/snmpd.conf.j2`
contains no `defAuthType`/`defAuthPassphrase`/`defPrivType`/
`defPrivPassphrase`/Event-MIB/`mteTrigger` directives, and the live
`/var/log/nmas-snmpd.log` on both R3 and R4 (522 lines, full session
history) contains zero occurrences of `Unknown token`, `mteTrigger`,
`defAuthType`, or `defPrivType` — confirmed by direct grep in this session.
The obsolete design is fully retired in the tracked desired state, not only
patched live.

## Linux watcher process/state evidence (this session)

```
R3: snmpd    pid=10338  /usr/sbin/snmpd -C -c /etc/snmp/nmas-snmpd.conf,/var/lib/snmp/snmpd.conf -p /run/nmas-snmpd.pid -Lf /var/log/nmas-snmpd.log
R3: watcher  pid=10341  /usr/bin/python3 /etc/snmp/nmas-link-events.py
R4: snmpd    pid=6622   /usr/sbin/snmpd -C -c /etc/snmp/nmas-snmpd.conf,/var/lib/snmp/snmpd.conf -p /run/nmas-snmpd.pid -Lf /var/log/nmas-snmpd.log
R4: watcher  pid=6625   /usr/bin/python3 /etc/snmp/nmas-link-events.py
```

Both PIDs were unchanged across two consecutive `--snmp-only` runs in this
session (no restart, since nothing changed — see Idempotency below).

## Link-state notification validation (real transitions, disposable interfaces)

For both R3 and R4, independently, in this session:

1. `docker exec <container> ip link add nmastest0 type dummy` — a disposable
   Linux dummy interface, never `eth1`/`eth2`/`eth3`/management/routing links.
2. `ip link set nmastest0 up`, wait, `ip link set nmastest0 down`.
3. `ip link delete nmastest0`, then confirmed removal (`ip link show
   nmastest0` returns "does not exist").
4. Watched NMAS's `snmptrapd` journal live throughout.

**R3** (dummy interface index 52):

```
NMAS_SNMP source=UDP: [192.168.200.3]:54114->... version=3 varbinds=... linkUp(.1.3.6.1.6.3.1.1.5.4)  ifIndex.52=52 ifAdminStatus.52=1 ifOperStatus.52=1
NMAS_SNMP source=UDP: [192.168.200.3]:38927->... version=3 varbinds=... linkDown(.1.3.6.1.6.3.1.1.5.3) ifIndex.52=52 ifAdminStatus.52=2 ifOperStatus.52=2
```

**R4** (dummy interface index 42):

```
NMAS_SNMP source=UDP: [192.168.200.4]:49402->... version=3 varbinds=... linkUp(.1.3.6.1.6.3.1.1.5.4)  ifIndex.42=42 ifAdminStatus.42=1 ifOperStatus.42=1
NMAS_SNMP source=UDP: [192.168.200.4]:58589->... version=3 varbinds=... linkDown(.1.3.6.1.6.3.1.1.5.3) ifIndex.42=42 ifAdminStatus.42=2 ifOperStatus.42=2
```

Both interfaces were confirmed removed immediately after the test. This is a
**real operational link-state transition**, decoded by the receiver as
authenticated SNMPv3 `authPriv` (`version=3`, correctly decrypted varbinds),
not a synthetic/simulated notification.

## cEOS notification validation

Two distinct things are validated, and are not the same claim:

- **Configured linkUp/linkDown support**: every cEOS device's rendered
  config includes `snmp-server enable traps snmp link-down` and
  `snmp-server enable traps snmp link-up` (confirmed present via
  `show running-config | section snmp` as part of every `--snmp-only` run's
  hash-based convergence check).
- **Synthetic test notification delivery**: EOS's built-in
  `test snmp notification` command was run on all eight cEOS devices in this
  session (`R1, R2, R5, S1, S2, S3, S4, mgmt_swt`). No live topology
  interface was shut down. Each generated an authenticated SNMPv3 `authPriv`
  test trap (Arista enterprise OID `.1.3.6.1.4.1.30065.3.3.0.0.1`,
  `NMAS_IAC_SAFE_TEST`), received and decoded by NMAS from every device's
  correct source address (`192.168.200.1/2/11/12/13/14/10`, and `172.20.20.16`
  for R5, which uses the `auto`-resolved data-plane address per
  `inventory.yml`).

No claim is made that a real physical `linkDown` was tested on any cEOS
device — only the vendor-provided safe synthetic test path was exercised, by
design, to avoid touching live topology interfaces.

## Receiver security audit

- `/etc/snmp/snmptrapd.conf` (live, confirmed by direct read):
  `agentAddress udp:192.168.200.100:162`, `disableAuthorization no`,
  `authUser log,execute nmas-monitor priv`, `format2 NMAS_SNMP ...`, and a
  `traphandle default` line (see Trap ingestion below). No
  `authCommunity`/v1/v2c line present anywhere in the active config.
  `execute` is only granted to the authenticated `nmas-monitor` USM identity —
  Net-SNMP's own access-control model (`authUser`), not a custom check —
  so only notifications that already passed SNMPv3 authPriv can ever reach
  the ingestion handler below.
- UDP 162 binds only to `192.168.200.100:162` (confirmed with `ss -ulnp`,
  single `snmptrapd` process holding the socket).
- Authoritative engine registrations: 12 (8 cEOS device engines + 2 Ubuntu/FRR
  polling-agent engines + 2 Ubuntu/FRR link-watcher notification-originator
  engines), all present in `/var/lib/snmp/snmptrapd.conf` (as localized
  `usmUser` entries for engines seen across a full daemon restart cycle, or
  as `createUser -e <engine>` entries for the two link-watcher engines, which
  this session proved functional end-to-end with a live authenticated trap
  before any subsequent restart converted them to the localized form).
- Two consecutive `--snmp-only` runs left the USM entry count and the
  `snmptrapd` PID unchanged — no duplicate registrations, no unnecessary
  restart.
- Runtime credentials (`monitoring/runtime/snmp-secrets.json`,
  `.../snmp-engines.json`, `/var/lib/snmp/snmptrapd.conf` on the host) are
  mode `600`; no SNMP password appears anywhere in Git (`git ls-files` shows
  only `monitoring/runtime/.gitkeep` tracked under that path).
- `snmptrapd` logs successful authenticated deliveries via `format2 NMAS_SNMP
  source=%b version=%s varbinds=%v` to the systemd journal (`-Lo` in
  `monitoring/config/snmptrapd-service.conf`).

## Idempotency bug found and fixed in this session

`monitoring/scripts/provision_linux_snmp.py`'s re-run check for the Ubuntu/FRR
SNMPv3 user searched `/var/lib/snmp/snmpd.conf` for the **plain-text**
username. Net-SNMP always persists `usmUser`/`createUser` security names
hex-encoded (e.g. `nmas-monitor` → `0x6e6d61732d6d6f6e69746f72`), so the
check could never match, and a second `--snmp-only` run failed on R3 with
`Missing USM user in an active daemon; refuse unsafe live key replacement`.
Fixed by checking for the hex-encoded form instead of the literal string.
This is a fix to the tracked script, not a live-container patch. See
`git diff` scope for the exact change.

## Link-watcher liveness-check bug found and fixed (CPU-threshold gap-repair session)

While live-verifying this session's CPU threshold alerting change, R3's
Ubuntu/FRR link-state watcher (`nmas-link-events.py`) was found to be a dead
zombie process (`ps` showed `[python3] <defunct>`) despite
`provision_linux_snmp.py` reporting "link watcher unchanged" on every run.

Root cause: R3/R4 have no init/reaper as PID 1 (`sleep infinity`, per
`AGENTS.md`), so an exited watcher becomes a zombie whose
`/proc/<pid>/cmdline` path still *exists* (confirmed live, as an empty
0-byte file) until something reaps it -- which here never happens. The
watcher's re-run liveness check,
`event_pid.exists() and (pathlib.Path('/proc')/pid/'cmdline').exists()`,
only tested path existence, not content, so it always reported a zombie as
"running" and never restarted it. The adjacent `snmpd` check on the same
line above was already correct (`b'nmas-snmpd.conf' in proc.read_bytes()`,
a content match), which is why only the watcher was affected.

Fixed in `monitoring/scripts/provision_linux_snmp.py` by making the
watcher's liveness check content-based, exactly mirroring the existing
`snmpd` pattern (`str(watcher).encode() in cmdline.read_bytes()`), and by
clearing a stale pidfile before asking `start-stop-daemon --start
--make-pidfile` to create a fresh one -- a stale pidfile's recorded PID
still "exists" in `/proc` for the same zombie-related reason, which
otherwise makes `start-stop-daemon` itself refuse to start a replacement
("process already running.", confirmed live).

**Live evidence after the fix, same session:** a fresh, real
`start-stop-daemon`-launched watcher PID (`13053` on R3) was confirmed alive
via `ps`, remained the same PID across two further consecutive
`--snmp-only` runs (idempotent, no unnecessary restart), and a disposable
dummy-interface up/down test produced both a real `linkUp` and a real
`linkDown` event stored in `snmp_trap` for R3 (ifindex 56) and, repeated
independently, for R4 (ifindex 44) -- confirming the fix restores genuine
link-down notification capability rather than only silencing the symptom.
This is a fix to the tracked script, not a live-container-only patch.

## Trap ingestion into InfluxDB

**Architecture.** The smallest robust option compatible with the existing
receiver: Net-SNMP's own `traphandle default <program>` directive
(`snmptrapd.conf(5)`), which invokes a program synchronously, once, for every
notification that has already been authenticated (SNMPv3 USM) **and**
authorized for `execute` processing (`authUser log,execute nmas-monitor
priv`) — the same access-control gate that already governs whether a
notification gets logged at all. There is no new daemon, no new listening
port, and no separate "ingestion service" to keep alive: `snmptrapd` itself
is the only process, and it re-invokes the handler fresh from disk for every
notification, so there is nothing that can be "not running" between traps.

`monitoring/scripts/ingest_snmp_trap.py` is deployed byte-identical to
`/etc/snmp/nmas-trap-ingest.py` (root-owned, `755`, no secrets). It reads the
notification off stdin in `snmptrapd`'s documented traphandle format
(hostname, transport address, then `sysUpTime.0`/`snmpTrapOID.0` followed by
the payload varbinds), classifies the event using the same OID names as
`monitoring/config/snmp_oids.yml` (`linkUp`, `linkDown`, `coldStart`,
`ceosTestNotification`, else `other`), extracts `ifIndex`/`ifAdminStatus`/
`ifOperStatus` when present, and writes one InfluxDB line-protocol point to
the existing bucket/org (same 30-day retention, nothing recreated). Every
step is wrapped so a failure logs to `/var/log/nmas-trap-ingest.log` and
exits quickly (5s HTTP timeout) rather than blocking or crashing
`snmptrapd`, which the Net-SNMP documentation notes blocks while a
traphandle program runs.

Non-secret lookup tables (`/etc/snmp/nmas-trap-oids.json`,
`/etc/snmp/nmas-trap-devices.json`, an IP→device map refreshed from
`inventory.yml` every run) are root-owned and world-readable. Only the
InfluxDB token lives in a protected file
(`/etc/snmp/nmas-trap-ingest.env`, owned `Debian-snmp:Debian-snmp`, mode
`600`) — `snmptrapd` runs as `Debian-snmp`, not root, and `/home/student` is
mode `750`, so nothing under the Git repository or `monitoring/runtime/`
(where the primary InfluxDB credentials live) is reachable by that account;
the ingestion path only ever holds a narrow, purpose-specific copy of the
write token.

**Schema.** Measurement `snmp_trap`. Tags: `device`, `source_ip`,
`source_protocol=snmp`, `event_type`, `notification_oid`, `severity`, and
`ifindex` when the notification carries one — all bounded, low-cardinality
sets. Fields: `value=1i` (so counting events is a plain aggregate query),
`ifadminstatus`/`ifoperstatus` (integers, when present), and
`raw_varbinds` (the full decoded varbind list, for audit, as a field rather
than a tag so it never inflates series cardinality). Timestamp is the
ingestion host's arrival time in nanoseconds. Each `snmptrapd` traphandle
invocation performs exactly one write; querying the same stored event
multiple times during verification does not create additional points — only
a fresh notification from a device does.

**A bug found and fixed getting here:** the first version granted only
`authUser log nmas-monitor priv`. `log` and `execute` are two independent
Net-SNMP authorization types — `log` permits console/file logging (which is
why the existing `format2` output already worked), but `traphandle` requires
`execute` specifically. With only `log` granted, notifications kept arriving
and getting logged, but the traphandle program was silently never invoked.
Fixed by changing the grant to `authUser log,execute nmas-monitor priv` in
both `monitoring/config/snmptrapd.conf` and the hardcoded `desired` string in
`monitoring/scripts/provision_snmp_receiver.py` (which mirror each other by
existing design — `install_nmas_receivers.sh` installs the tracked config
file directly, while the Python script separately owns USM/engine
convergence; both must render identical config text for the two convergence
checks to agree, exactly as they already did for the pre-existing config
lines).

**Live evidence (this session), device → SNMPv3 authPriv → snmptrapd →
ingestion → InfluxDB → query:**

- All 8 cEOS devices: `test snmp notification` fired on each; every one
  appears in `/var/log/nmas-trap-ingest.log` as `OK device=<X>
  event_type=ceosTestNotification` and is queryable back from InfluxDB.
- R3: real dummy-interface (`nmastest0`, ifIndex 53) up/down transition
  produced `OK device=R3 event_type=linkUp` then `OK device=R3
  event_type=linkDown`, both stored.
- R4: real dummy-interface (`nmastest0`, ifIndex 43) up/down transition
  produced `OK device=R4 event_type=linkUp` then `OK device=R4
  event_type=linkDown`, both stored. Both dummy interfaces were deleted and
  confirmed removed (`ip link show` → "does not exist") immediately after.

A pivoted query of R3's stored rows in this session returned, in full:

```
device=R3 event_type=linkUp   ifindex=53 ifadminstatus=1 ifoperstatus=1 severity=info    notification_oid=1.3.6.1.6.3.1.1.5.4 source_ip=192.168.200.3
device=R3 event_type=linkDown ifindex=53 ifadminstatus=2 ifoperstatus=2 severity=warning notification_oid=1.3.6.1.6.3.1.1.5.3 source_ip=192.168.200.3
```

A grouped count of every `snmp_trap` event written in this session's test
window matched the number of notifications actually sent, per device and
event type, with no inflation from re-querying.

**IaC / orchestration.** Nothing here requires a manual step: `ensure_receiver()`
in `modules/snmp.py` builds the ingestion payload (script text, OID subset,
device map, InfluxDB org/bucket/token) and ships it to
`provision_snmp_receiver.py`, which runs as root (via the existing `sudo -n`
path) and converges all four ingestion files idempotently — each is only
rewritten if its content differs, and none of those writes require restarting
`snmptrapd` (only a `snmptrapd.conf` content change does, via the
already-existing `changed`/`missing` restart gate). `python3 master.py
--snmp-only` provisions and structurally verifies the ingestion path
(`verify_trap_ingestion()`) every run, including one live, safe
`test snmp notification` proof against a cEOS device. Two consecutive
`--snmp-only` runs in this session left the `snmptrapd` PID, all four
ingestion file mtimes, and the USM entry count completely unchanged — no
duplicate processes or configuration.

## CPU monitoring: polling, plus collector-generated threshold alerting

CPU **values** are fulfilled entirely through the verified CPU OID polling
path described above (`1.3.6.1.2.1.25.3.3.1.2`, confirmed live on both
platforms). No native device-originated CPU **threshold notification** (SNMP
trap) capability has been found or is claimed on either cEOS 4.36.2F or
Ubuntu/FRR — neither platform exposes a verified native CPU threshold trap,
and none has been fabricated.

`LAB_REQUIREMENTS.md` section 4 "Notifications" explicitly anticipates this
and offers two accepted paths: (1) a platform-supported CPU threshold trap,
verified live, or (2) "NMAS-side threshold alerting generated from repeated
CPU polls, stored as an event and clearly labelled as collector-generated
rather than a device SNMP trap." Since path 1 does not exist on either live
platform, this implementation uses path 2.

### Architecture

`modules/cpu_alerts.py` is a small, repository-owned evaluator plugged
directly into the existing SNMP poll path — it never polls a device itself
and never fabricates a CPU sample:

- `modules/snmp.py:collect()` — the same function that already polls, walks,
  validates, and writes every device's `hrProcessorLoad` values to the
  `snmp_poll` measurement — takes the mean of those already-validated,
  already-real CPU values (across every polled logical processor index, the
  same aggregation the Grafana "Latest polled CPU"/"Polled CPU utilization"
  panels already perform) and passes it, plus the same write timestamp, to
  `modules.cpu_alerts.evaluate_cpu_threshold()`. No second poll, no
  independent polling architecture.
- `evaluate_cpu_threshold()` applies simple consecutive-sample and hysteresis
  state logic (below) and, only on a genuine NORMAL→ALERT or ALERT→RECOVERY
  transition, writes one event to the `collector_alert` InfluxDB measurement
  — deliberately not `snmp_trap`, which is reserved for device-originated
  SNMPv3 notifications (`linkUp`/`linkDown`/`coldStart`/test).
- `modules/snmp.py:ensure_snmp_infrastructure()` also calls
  `verify_cpu_threshold_alerting()` on every `--snmp-only` (and full) run —
  the same reproducible IaC entrypoint used for every other SNMP check, not
  a manual one-off command — to deterministically and safely demonstrate the
  alert and recovery transitions with live evidence every run (see
  "Safe verification" below).

### Production alerting policy

`monitoring/config/cpu_threshold_policy.yml` (no prior CPU-threshold policy
existed anywhere in the repository — checked before adding this file):

| Key | Value | Meaning |
|---|---:|---|
| `warning_pct` | 70 | Mean polled CPU % at/above which a WARNING alert may fire |
| `critical_pct` | 90 | Mean polled CPU % at/above which a CRITICAL alert may fire |
| `consecutive_samples` | 3 | Consecutive real SNMP CPU polls (i.e. 3 separate `--snmp-only`/full runs) required at/above a threshold before an ALERT is stored |
| `recovery_pct` | 60 | Hysteresis floor: CPU must fall to/below this (not merely below `warning_pct`) before a RECOVERY event fires and the device returns to NORMAL |

These values intentionally match the pre-existing Grafana CPU panel visual
thresholds (`orange=70`, `red=90` in
`monitoring/scripts/build_grafana_dashboards.py`) so the stored alert
severity and the dashboard's coloring never disagree for the same CPU value
— while remaining two clearly distinct things: Grafana's coloring is
display-only and was never itself a stored alert; `collector_alert` events
are the actual stored alert-equivalent record.

Because SNMP polling in this project runs once per `--snmp-only`/full
invocation rather than as a standing background loop, "repeated polls" means
repeated invocations over time. Per-device alert state is therefore
persisted (not purely in-memory) as one small JSON file under
`monitoring/runtime/cpu-alert-state/<device>.json` — mirroring the existing
`monitoring/runtime/<device>-snmp-state.json` convergence-state pattern
already used by `modules/snmp.py:configure_device()` — mode `600`, excluded
from Git by the existing `monitoring/runtime/*` `.gitignore` rule. State is
keyed per device, so one device's alert state can never affect another's.

### State machine

Per device: `NORMAL → (consecutive_samples consecutive polls at/above
warning_pct or critical_pct) → ALERT(severity) → (one poll at/below
recovery_pct) → RECOVERY → NORMAL`.

- A transient single high sample, when more than one consecutive sample is
  required, produces no event (the streak resets the moment a poll falls
  back below the threshold).
- Once alerting, continued high samples produce no duplicate event —
  `evaluate_cpu_threshold()` only fires when the new severity level is
  strictly higher than the currently-stored state (so a sustained CRITICAL
  reading after a CRITICAL alert never re-fires, but a WARNING alert that
  keeps climbing into CRITICAL territory for another `consecutive_samples`
  polls correctly escalates as a second, distinct, non-duplicate event).
- Falling to/below `recovery_pct` fires exactly one RECOVERY event and
  resets state to NORMAL.

### InfluxDB event schema

Measurement `collector_alert` (never `snmp_trap`):

- Tags: `device`, `platform`, `alert_type=cpu_threshold`, `source=collector`,
  `severity` (`warning`/`critical`/`info` for a recovery), `transition`
  (`alert`/`recovery`), `monitoring_method=snmp_polling`,
  `verification` (`true` only for the safe self-test path below, `false` for
  production alerts).
- Fields: `value=1i` (a plain count marker, matching the existing
  `snmp_trap` schema convention), `cpu_value` (the real polled CPU value that
  triggered the event), `threshold_pct` (the configured threshold that was
  crossed), `consecutive_samples` (how many consecutive polls led to this
  event), `previous_state` (the state the device was in immediately before
  this transition).
- Timestamp: the same `time.time_ns()` write timestamp already used for the
  underlying `snmp_poll` write for that device/poll cycle.

### Safe verification (no device stress, no fabricated CPU sample)

`modules/snmp.py:verify_cpu_threshold_alerting()`, run automatically as part
of `ensure_snmp_infrastructure()`:

1. Polls one real device's CPU through the exact same `poll()` function
   `collect()` uses — a real `hrProcessorLoad` SNMP walk, not a second/fake
   value.
2. Calls the production `evaluate_cpu_threshold()` function with a
   temporary, explicitly `verification=True`-tagged policy whose
   `warning_pct` is set just below that one real observed value (and
   `consecutive_samples=1`, so a single real sample is sufficient — the
   production policy's own 3-consecutive-sample requirement is separately
   proven, without touching any live device, by
   `monitoring/tests/test_cpu_alerts.py`). The real CPU value never changes;
   only the temporary verification threshold is lowered.
3. Confirms the resulting ALERT event is actually queryable back from
   InfluxDB (`confirm_stored()`), the same read-your-write pattern
   `collect()` already uses for `snmp_poll`.
4. Re-exercises the identical evaluator function with the verification
   threshold raised back above the same real observed CPU value, so the
   RECOVERY transition fires and is confirmed stored the same way.

The verification-only policy and its per-device state file
(`monitoring/runtime/cpu-alert-state/<device>-verification.json`) are
entirely separate from the production policy and production per-device state
file — running this verifier never weakens, resets, or is confused with
normal alerting for any device. Every stored verification event carries
`verification=true` so it is never mistaken for a production alert, and it
is never represented anywhere as a device-emitted trap.

## Not implemented / out of scope for this phase

`sysContact`/`sysLocation` and interface traffic counters are tracked
separately in `IMPLEMENTATION_PLAN.md`/`GAP_ANALYSIS.md` and are not claimed
as complete here. A native, device-originated CPU threshold SNMP trap
remains unavailable on both live platforms (cEOS 4.36.2F, Ubuntu/FRR) and is
not claimed — the collector-generated `collector_alert` path above is the
explicitly permitted alternative, not a substitute claim of native trap
support.
