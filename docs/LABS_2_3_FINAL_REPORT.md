# Advanced Network Automation Labs 2 & 3

Repository: `/home/student/Scripts/clab_dualstack_lab` (branch `main`).
Status: feature-frozen. This report synthesizes the subsystem documentation
under `docs/`, the requirement tracking in `LAB_REQUIREMENTS.md`,
`GAP_ANALYSIS.md`, and `IMPLEMENTATION_PLAN.md`, and live re-verification
performed while writing this report, into a single technical account of what
was built, how it works, how it was verified, and what remains limited.

## 1. Executive Summary

Labs 2 and 3 add a centralized Network Management and Automation System
(NMAS) on top of the frozen Lab 1 Containerlab deployment (`srlceos01`),
without altering its topology, addressing, routing, VLANs, NAT, DHCP, node
kinds, or links. Ten infrastructure devices are continuously monitored:
`R1, R2, R3, R4, R5, S1, S2, S3, S4, mgmt_swt`. The end-to-end solution
includes:

- SNMPv3 `authPriv` polling (SHA-256 authentication, AES-128 privacy) of
  system identity, uptime, interface state, and CPU on all 10 devices.
- SNMP notifications: native cEOS `linkUp`/`linkDown` traps plus a
  repository-owned Linux link watcher on R3/R4, all ingested into InfluxDB.
- An NMAS collector-generated CPU threshold alerting path
  (`collector_alert` measurement) that closes the requirement for CPU
  threshold behavior, since no native CPU threshold SNMP trap exists on
  either live platform.
- Critical (emergency/alert/critical) syslog collection from all 10 devices.
- gNMI/OpenConfig streaming telemetry (Subscribe STREAM+SAMPLE, 20s) from
  all 10 devices — native on the 8 cEOS nodes, through a repository-owned
  Linux/FRR adapter on R3/R4.
- NETCONF discrete `<get>` retrieval from all 10 devices — native cEOS
  NETCONF-over-SSH, and a repository-owned NETCONF-over-SSH adapter on
  R3/R4. R3 and R4 are **not** native gNMI/NETCONF devices; their
  telemetry and management-protocol support come from real, live
  `/proc`/`/sys`/FRR state served through these repository-owned adapters,
  never from FRR or Linux itself.
- A single centralized InfluxDB data lake holding SNMP polls/traps,
  collector alerts, syslog events, gNMI telemetry, and NETCONF snapshots.
- Four Grafana dashboards (39 panels, 8 variables, 47 queries) visualizing
  the same centralized data.
- A dynamic, auto-refreshing NetworkX topology visualization built from
  live Containerlab metadata, with real health overlays and dual-stack
  management addressing.
- Dual-stack (IPv4/IPv6) management addressing throughout the design.
- Infrastructure-as-Code automation: a thin `master.py` orchestrator calling
  into per-subsystem modules, all idempotent and safe to re-run.

The frozen Lab-1 network baseline — topology, routing, addressing, VLANs,
NAT, DHCP, node kinds, and links — was preserved throughout; every change in
Labs 2/3 is additive monitoring infrastructure.

## 2. Lab Environment

- Containerlab lab name: `srlceos01` (`srlceos01.clab.yml`).
- 15 Lab-1 containers plus 2 monitoring containers (`monitoring-influxdb-1`,
  `monitoring-grafana-1`) — 17 containers total, confirmed running live
  while writing this report.
- NMAS host: `192.168.200.100` (management VLAN) / `2001:db8:200::100`,
  reached from `mgmt_swt:eth9` over the dedicated host-side `nmas-mgmt`
  interface. NMAS also has a Containerlab-management-network address
  (`172.20.20.0/24` / `3fff:172:20:20::/64`, bridge `br-2c83d7955d69`) used
  as the deployment/bootstrap path.

### Device/platform matrix

| Nodes | Platform | Role in Labs 2/3 |
|---|---|---|
| R1, R2, R5, S1, S2, S3, S4, `mgmt_swt` | Arista cEOS 4.36.2F (engineering build) | Monitored; native SNMP, syslog, gNMI, NETCONF |
| R3, R4 | Ubuntu 24.04 + FRRouting 8.4.4 | Monitored; SNMP via installed `snmpd`, syslog via installed `rsyslog`, gNMI/NETCONF via repository-owned adapters |
| H1, H2, H3, H4, WebServer | Ubuntu 24.04 (plain hosts) | Unmonitored endpoint nodes — not network infrastructure, correctly shown as `UNKNOWN` in the dynamic topology |

### Management network design

Two separate management paths exist and are used for different purposes:

1. **Dedicated management VLAN (Vlan200)** — `192.168.200.0/24` and
   `2001:db8:200::/64`, dual-stack, carried to `mgmt_swt` and from there to
   R1-R4 and S1-S4. This is the SNMP/syslog/gNMI/NETCONF collection path for
   every device that has it. Per-device addresses (from `inventory.yml` and
   cross-checked live against `Vlan200`/interface state on each device):

   | Device | IPv4 | IPv6 |
   |---|---|---|
   | R1 | 192.168.200.1 | 2001:db8:200::1 |
   | R2 | 192.168.200.2 | 2001:db8:200::2 |
   | R3 | 192.168.200.3 | 2001:db8:200::3 |
   | R4 | 192.168.200.4 | 2001:db8:200::4 |
   | S1 | 192.168.200.11 | 2001:db8:200::11 |
   | S2 | 192.168.200.12 | 2001:db8:200::12 |
   | S3 | 192.168.200.13 | 2001:db8:200::13 |
   | S4 | 192.168.200.14 | 2001:db8:200::14 |
   | `mgmt_swt` | 192.168.200.10 | 2001:db8:200::10 |

2. **Containerlab management network** — `172.20.20.0/24` /
   `3fff:172:20:20::/64`. R5 and WebServer have no Vlan200 SVI (R5 peers
   EBGP directly on point-to-point links) and are reached only here; R5's
   monitoring address is resolved at collection time from the live
   Containerlab-assigned `Management0` address (`address: auto` in
   `inventory.yml`) rather than a hardcoded value, for both IPv4 and IPv6.

No management address in this report was invented: every value above is
either read directly from `inventory.yml`'s tracked desired state or
resolved live from Containerlab metadata, cross-checked against device CLI
output.

## 3. Architecture

```text
Devices
  |
  +-- SNMPv3 polls ----------------+
  +-- SNMP notifications ----------+
  +-- Critical syslog -------------+--> NMAS
  +-- gNMI STREAM/SAMPLE ----------+      |
  +-- NETCONF GET -----------------+      v
                                      InfluxDB
                                         |
                          +--------------+-------------+
                          |                            |
                       Grafana                 NetworkX topology
```

All five collection mechanisms write into one InfluxDB instance
(`network-monitoring` bucket, 30-day retention); no subsystem has its own
database. Grafana and the NetworkX topology service both read exclusively
from that same InfluxDB backend (plus, for topology, read-only Containerlab
metadata for node/link identity).

Native vs. repository-owned adapter, by mechanism:

| Mechanism | R1/R2/R5/S1-S4/`mgmt_swt` (cEOS) | R3/R4 (Ubuntu/FRR) |
|---|---|---|
| SNMP agent | Native EOS SNMP agent | Repository-owned `snmpd` installation (`provision_linux_snmp.py`) |
| Link-state notification | Native `linkUp`/`linkDown` traps | Repository-owned Linux link watcher (`linux_link_notifications.py`) sending real SNMPv3 traps |
| CPU threshold alert | NMAS collector-generated, both platforms alike (`modules/cpu_alerts.py`) | same |
| Syslog transport | Native EOS `logging host` (with a documented platform defect, see §8) | Genuinely working native `rsyslog` install |
| gNMI | Native cEOS gNMI/gRPC :6030, TLS | Repository-owned Linux gNMI adapter (`linux_gnmi_server.py`) reading real `/proc`/`/sys` state |
| NETCONF | Native cEOS NETCONF/SSH :830 | Repository-owned Linux NETCONF adapter (`linux_netconf_server.py`) |

## 4. NMAS Monitoring Infrastructure

NMAS hosts the entire centralized stack:

- **InfluxDB 2.7.11** (Compose service, `127.0.0.1:8086`) — the single
  time-series/event backend for every subsystem.
- **Grafana 11.5.2** (Compose service, `127.0.0.1:3000`) — visualization
  against the same InfluxDB datasource (`nmas-influxdb`).
- **`snmptrapd`** — SNMP trap receiver, bound only to `192.168.200.100:162`.
- **rsyslog** — syslog receiver, UDP/TCP `514` bound only to
  `192.168.200.100`.
- **Collectors** — `modules/snmp.py` (poll + trap-ingestion wiring),
  `syslog_ingest_daemon.py` (tails the raw syslog file into InfluxDB),
  `gnmi_collector.py` (persistent per-device gNMI Subscribe sessions),
  `modules/netconf.py` (discrete NETCONF `<get>` collection), and
  `modules/topology_graph.py`/`topology_server.py` (read-only visualization
  service).
- **Log rotation / retention** — raw syslog: `logrotate`, daily, 30 archives
  plus current (`monitoring/config/lab-monitoring-logrotate`). InfluxDB
  bucket: 30-day retention (2,592,000 seconds), applied via
  `monitoring/scripts/influxdb_retention.py` and verified through the
  InfluxDB API.
- **Secret handling** — all generated credentials (InfluxDB token/org,
  Grafana admin password, SNMPv3 auth/priv passphrases, gNMI/NETCONF
  password) live only in the git-ignored, mode-600
  `monitoring/runtime/` tree; nothing under that path is tracked except a
  `.gitkeep` placeholder.
- **Exposure** — InfluxDB, Grafana, `snmptrapd`, and rsyslog are all bound
  to `127.0.0.1` or `192.168.200.100` only; none are reachable from outside
  the management path.

Live NMAS verifier result (`monitoring/tests/verify_nmas_infrastructure.sh`),
re-run while preparing this report: **20/20 PASS** — rsyslog/`snmptrapd`
active and correctly bound, SNMP/NETCONF/gNMI client tooling present,
InfluxDB and Grafana containers healthy with passing HTTP health checks,
InfluxDB 30-day retention confirmed, logrotate configuration and timer
verified, and a synthetic InfluxDB write/query round-trip confirmed.

## 5. SNMP Monitoring

All 10 devices are polled over **SNMPv3 `authPriv`** (user `nmas-monitor`,
authentication **SHA-256**, privacy **AES-128**) from NMAS. `modules/snmp.py`
is the single implementation for both platforms; `master.py` only calls
`ensure_snmp_infrastructure()`.

Polled objects (walked, indexes discovered live rather than hardcoded):

- System identity (`sysName`, cross-checked against inventory) and uptime
  (`sysUpTime`).
- Interface admin/operational state and identity (`ifIndex`, `ifName`,
  `ifAdminStatus`, `ifOperStatus`) across the full interface table; a poll
  is rejected if the index sets returned by these four OIDs disagree.
- CPU utilization: `HOST-RESOURCES-MIB::hrProcessorLoad`,
  OID `1.3.6.1.2.1.25.3.3.1.2`, walked as an indexed table (one row per
  logical processor/core) on both platforms. The processor index differs by
  platform (small integers such as `4`/`6`/`9` on cEOS; a large
  kernel-assigned index such as `196608` on Ubuntu/FRR) — the OID and
  semantics are identical, and the mean of all returned processor rows is
  what both the Grafana CPU panels and the CPU threshold evaluator (§7)
  consume.

Live re-verification while preparing this report: **10/10 PASS** across
AGENT/AUTH/SYSNAME/UPTIME/CPU/IFSTATUS/STORAGE for
R1, R2, R3, R4, R5, S1, S2, S3, S4, `mgmt_swt`, plus trap-ingestion PASS.

## 6. SNMP Notifications

`IF-MIB` `linkUp`/`linkDown` notifications are the link-state mechanism on
both platforms, delivered as authenticated SNMPv3 `authPriv` traps to
`snmptrapd` and normalized into the `snmp_trap` InfluxDB measurement by a
`traphandle`-driven ingestion script (`ingest_snmp_trap.py`).

- **cEOS (native path)**: every device's rendered configuration enables
  `snmp-server enable traps snmp link-up`/`link-down`. Delivery was
  validated using EOS's built-in `test snmp notification` command on all 8
  cEOS devices — a safe, vendor-provided synthetic test path. No real
  topology interface was shut down on any cEOS device to produce this
  evidence.
- **R3/R4 (repository-owned watcher)**: `linux_link_notifications.py`
  polls `/sys/class/net/*/operstate` every 2 seconds and, on a genuine
  transition, sends a real SNMPv3 `authPriv` trap. This was verified with
  **real, non-synthetic** up/down transitions on disposable dummy
  interfaces (`nmastest0`, created and deleted the same session) on both
  R3 and R4 — never on a live topology interface (`eth1`/`eth2`/`eth3` or
  the management link).

These two verification methods are clearly distinct in the underlying
documentation and in this report: the cEOS evidence is a **safe synthetic
test notification**, and the R3/R4 evidence is a **real link-state
transition on a disposable, non-production interface**. Neither claims that
a production topology link was deliberately flapped.

## 7. CPU Threshold Alerting

Neither live platform exposes a verified native CPU threshold SNMP trap:
cEOS 4.36.2F and Ubuntu/FRR 8.4.4 were both checked live and neither has one.
`LAB_REQUIREMENTS.md` §14 item 5 explicitly permits an alternative:
"NMAS-side threshold alerting generated from repeated CPU polls, stored as
an event and clearly labelled as collector-generated rather than a device
SNMP trap." `modules/cpu_alerts.py` implements exactly this alternative,
closing the requirement.

The evaluator consumes the same real, already-validated `hrProcessorLoad`
mean that `modules/snmp.py:collect()` produces for every poll — it never
polls a device itself and never fabricates a CPU sample. On a genuine state
transition it writes one event to InfluxDB:

- Measurement: `collector_alert`
- Tags: `source=collector`, `alert_type=cpu_threshold`,
  `monitoring_method=snmp_polling`, plus `device`, `platform`, `severity`,
  `transition`, `verification`.

Production policy (`monitoring/config/cpu_threshold_policy.yml`):

| Parameter | Value |
|---|---|
| Warning | 70% |
| Critical | 90% |
| Consecutive samples required | 3 |
| Recovery (hysteresis floor) | 60% |

Per-device state is persisted (not purely in-memory, since SNMP polling
here runs once per invocation rather than as a standing loop) under
`monitoring/runtime/cpu-alert-state/<device>.json`, so one device's alert
state can never affect another's. The state machine:

```
NORMAL
 -> repeated threshold crossing (3 consecutive polls at/above a threshold)
 -> ALERT once

ALERT
 -> sustained high CPU (no duplicate event; only a strictly higher severity re-fires)
 -> no event storm

ALERT
 -> one poll at/below the 60% recovery floor
 -> RECOVERY once, state returns to NORMAL
```

**Safe verification method**: `verify_cpu_threshold_alerting()` polls one
real device's CPU through the same `poll()` path `collect()` uses (a real
`hrProcessorLoad` walk, not a second or fake value), then calls the
production `evaluate_cpu_threshold()` function with a temporary,
explicitly `verification=true`-tagged threshold set just below that one
real observed value (and `consecutive_samples=1`, so a single real sample
suffices for the safe self-test only). This is **not** the production
threshold — the production 70/90/3/60 policy is separately proven, without
touching any live device, by 11 unit tests in
`monitoring/tests/test_cpu_alerts.py`. Recorded live evidence from this
verification path: a real R1 CPU sample (55.6%-60.7% across separate runs)
producing a stored `collector_alert` ALERT (`severity=warning
transition=alert cpu_value=56.78 threshold_pct=55.78`) followed by a
RECOVERY (`severity=info transition=recovery cpu_value=56.78
threshold_pct=61.78`), both tagged `verification=true`.

Collector alerts are never stored in, or represented as, `snmp_trap`
records — a parallel query of `snmp_trap` over the same window contains
only `linkUp`/`linkDown`/`ceosTestNotification`/`other` events, with no
CPU-related entry ever written there. The two measurements are kept
architecturally and semantically distinct by design.

## 8. Critical Syslog

Only emergency(0)/alert(1)/critical(2) severities are forwarded from any
device — `logging trap critical` on cEOS, an equivalent `$syslogseverity <=
2` rule on R3/R4's installed rsyslog. NMAS's rsyslog receiver
(`192.168.200.100`, UDP/TCP `514`) writes matching lines to a raw retained
log (`/var/log/lab-monitoring/remote-syslog.log`), and an independent
tailer (`syslog_ingest_daemon.py`) parses that file into the `syslog_event`
InfluxDB measurement (tags: `device`, `source_ip`, `source_protocol=syslog`,
`severity`, `facility`, `platform`; fields: `message`, `hostname`,
`severity_code`, `facility_code`). Retention: 30 days on the raw log
(logrotate, daily, `rotate 30`/`maxage 30`) and 30 days on the InfluxDB
bucket.

**Platform limitation, documented honestly, not hidden**: this specific
cEOS-lab engineering build's own `rsyslog.service` cannot start
(`improg: failed to execute program '/usr/bin/tracepointReader':
Permission denied`, an internal Arista engineering toggle, confirmed on all
8 cEOS containers). EOS's standard `logging host` configuration is
therefore correct but not reliably functional as a transport on this image.
The mitigation is a repository-owned Python relay
(`ceos_syslog_forward.py`) that tails EOS's own internally-written
`/var/log/messages` and relays qualifying severities to NMAS directly over
UDP via `logger`, bypassing the broken local daemon — a genuinely working,
but explicitly best-effort, supplementary path, not depended on for the
pass/fail verdict. Deterministic verification instead uses a direct
`logger --udp` call from inside each device's own container/namespace, so
delivery evidence does not race the platform defect. R3/R4 have no
equivalent defect: their installed `rsyslog` is a genuinely working local
daemon.

Live re-verification while preparing this report: **10/10 PASS** across
CONFIG/CRITICAL/RAWLOG/STORAGE for all 10 devices.

## 9. gNMI / gRPC / OpenConfig Streaming Telemetry

**Native cEOS** (R1, R2, R5, S1, S2, S3, S4, `mgmt_swt`): gNMI/gRPC on TCP
`6030`, secured with TLS (`management security ssl profile NMAS_GNMI`,
reusing each node's Containerlab-issued certificate) and a dedicated
non-`admin` `nmas-telemetry` user. `Capabilities()` returns 298 supported
OpenConfig/Arista models; `Get()` and `Subscribe(STREAM, SAMPLE, 20s)` are
both verified live against real interface/system state.

**R3/R4**: FRR 8.4.4 and the Ubuntu image provide **no native gNMI
service**. `modules/linux_telemetry_adapter.py` and
`monitoring/scripts/linux_gnmi_server.py` implement a repository-owned gNMI
server, bound only to each router's management address
(`192.168.200.3`/`.4`), that reads real state from `/proc/stat`,
`/proc/meminfo`, and `/sys/class/net` at request time and serves it over
TLS with password authentication and the same Capabilities/Get/Subscribe
surface as the six configured paths. It is never represented as native FRR
gNMI support anywhere in the documentation or dashboards.

Representative streamed data (six paths, `gnmi_paths.yml`,
Subscribe STREAM+SAMPLE every 20 seconds, one persistent per-device session
covering all six):

- `hostname` (system identity)
- CPU (`system_cpu`, per-index instantaneous utilization)
- memory (`system_memory`: physical/used/free/reserved)
- interface admin state, interface operational state
- interface counters (in/out octets, errors, discards)

All of this is stored in a single InfluxDB measurement, `gnmi_telemetry`.
Live re-verification while preparing this report: **10/10 PASS** across the
GNMI/STREAM/INFLUX columns of `verify_telemetry.py` for all 10 devices.

## 10. NETCONF

**Native cEOS**: NETCONF-over-SSH on TCP `830`, using the same
`nmas-telemetry` credential as gNMI. `modules/netconf.py` performs a
`<hello>` capability exchange followed by a filtered `<get>` (e.g.
`openconfig-system:state/hostname`, `openconfig-interfaces:interfaces`),
validated against the device's real hostname and interface set.

**R3/R4**: `monitoring/scripts/linux_netconf_server.py` is a
repository-owned NETCONF-over-SSH adapter, bound only to the management
address, implementing base:1.0 EOM framing, `<hello>`, filtered read-only
`<get>`, and `<close-session>`; configuration RPCs correctly return
`operation-not-supported`. It retrieves real Linux/FRR state, not native
FRR NETCONF support.

**gNMI = continuous telemetry streaming; NETCONF = discrete
management/read retrieval in this implementation.** This distinction is
enforced in code, not just prose: `modules/netconf.py` records
`has_notifications`/`has_yang_push` as explicit `false` fields rather than
omitting them. A live `<hello>` exchange with cEOS 4.36.2F enumerated 351
capabilities, none of which is `:notification`, `:interleave`,
`subscribed-notifications`, or YANG Push — this cEOS build does not
advertise the notification/YANG-Push capability NETCONF streaming would
require. No NETCONF notification streaming is claimed anywhere in this
implementation.

Live re-verification while preparing this report: **10/10 PASS** across the
NETCONF/NC-GET columns of `verify_telemetry.py` for all 10 devices.

## 11. Centralized Data Lake

A single InfluxDB 2.7.11 instance, one organization, one bucket
(`network-monitoring`, 30-day retention), holds every measurement produced
by every monitoring mechanism in this project:

| Measurement | Written by | Content |
|---|---|---|
| `snmp_poll` | `modules/snmp.py` | Per-device/interface SNMP poll results |
| `snmp_trap` | `ingest_snmp_trap.py` | Device-originated linkUp/linkDown/coldStart/test notifications |
| `collector_alert` | `modules/cpu_alerts.py` | NMAS collector-generated CPU threshold ALERT/RECOVERY events |
| `syslog_event` | `syslog_ingest_daemon.py` | Critical-severity syslog messages |
| `gnmi_telemetry` | `gnmi_collector.py` | Streamed identity/CPU/memory/interface state/counters |
| `netconf_snapshot` | `modules/netconf.py` | Discrete NETCONF `<get>` capability/interface snapshots |

Every measurement carries device identity, platform, source-protocol, and
timestamp; high-cardinality data (raw messages, raw varbinds) is stored as a
field, never a tag, to keep series cardinality bounded. All retrieval in
this report — SNMP, trap, syslog, telemetry, NETCONF, Grafana, and topology
— reads from this one backend; no subsystem maintains a separate database.

## 12. Grafana Visualization

Live re-verification while preparing this report
(`monitoring/tests/verify_grafana.py --verbose`): **4 dashboards, 39
panels, 8 variables, 47 queries, datasource health PASS.**

| Dashboard | Panels | Variables |
|---|---:|---|
| NMAS Network Health Overview | 12 | `device`, `platform` |
| NMAS Streaming Telemetry | 11 | `device`, `platform`, `interface` |
| NMAS SNMP Monitoring | 10 | `device` |
| NMAS Critical Syslog | 6 | `device`, `severity` |

The **NMAS Collector CPU Alerts** panel (on `NMAS SNMP Monitoring`) shows
`collector_alert` events — `source=collector`/`alert_type=cpu_threshold`
— and is deliberately positioned and styled as visually and semantically
distinct from the "Recent SNMP notifications" panel directly above it,
which shows device-originated `snmp_trap` events. The dashboard never
conflates the two. A third, related but separate concept is the CPU trend
panel's visual color thresholds (orange at 70%, red at 90%) — these are
display-only coloring, intentionally set to match the production alerting
policy's own thresholds, but they are not themselves a stored alert record;
the `collector_alert` panel is the actual alert-equivalent evidence.

[SCREENSHOT: Grafana Network Health Overview]

[SCREENSHOT: SNMP CPU dashboard and NMAS Collector CPU Alerts]

[SCREENSHOT: gNMI streaming telemetry dashboard]

[SCREENSHOT: Critical syslog dashboard]

## 13. Dynamic NetworkX Topology

`modules/topology_graph.py` builds an authoritative `networkx.Graph` from
the active Containerlab metadata (`topology-data.json`), reconciled with a
read-only `containerlab inspect` call — never from the tracked
`srlceos01.clab.yml`, which is intentionally different (it does not encode
R3/R4 as Linux). The result is **15 nodes and 23 inter-container edges**;
one additional link record (`mgmt_swt:eth9` to the host-side `nmas-mgmt`
interface) is intentionally recorded as an **excluded host attachment**
rather than misrepresented as a Containerlab node.

Presentation is a deterministic, hierarchical layered diagram (tiers for
WebServer/R5/R3-R4/S3-S4/R1-R2/S1-S2/H1-H4, with `mgmt_swt` placed in its
own dedicated management column) computed from the real data-plane
adjacency by a barycenter crossing-reduction sweep — a cosmetic layout
choice that never alters which nodes or edges exist.

UI features: an **Operational Details** panel per selected node/link; a
**Show Addresses** toggle displaying each monitored device's management
interface, IPv4, and IPv6 address (dual-stack, sourced from `inventory.yml`
and live Containerlab data, never fabricated); zoom (`+`/`-`, mouse wheel,
`0.2x`-`4x` clamp); pan (click-drag on empty canvas); individual node drag
(client-side presentation offset only, never written back to the server);
**Reset View** (recomputes the deterministic camera fit); **Reset Node
Positions** (clears manual drag offsets); and automatic refresh every 20
seconds (backend cache: 10 seconds).

**Safe/synthetic link-down demonstration**: a UI checkbox calls
`/api/topology?demo=safe-link-down`, which creates a response-local overlay
on one deterministic data-plane edge, clearly labelled
`DEMO/SYNTHETIC — NO REAL NETWORK CHANGE` in both the API and UI. Nothing is
written to InfluxDB or disk, no collector is altered, and the real
`snmp_trap`/telemetry-derived edge state (`real_status`) is preserved
alongside the overlay. **No real production topology link was deliberately
failed** — this demonstration mode exists specifically because disruptive
link tests are prohibited without separate approval, and none was sought or
performed in this project.

The acceptance verifier (`monitoring/tests/verify_topology.py`) was
hardened against an intermittent, previously-documented race between two
independent, asynchronous observations of the same device — the topology
API's cached snapshot and a direct, subsequent InfluxDB read — that could
occasionally disagree by roughly one gNMI sample interval. The hardened
check (`evaluate_real_node`) keeps every substantive requirement (the
device must have real InfluxDB evidence, the API health must be exactly
`HEALTHY`, and the direct evidence must itself be genuinely recent) while
replacing exact timestamp equality with a bounded, justified tolerance
(45 seconds, comfortably inside the 60-second healthy threshold). This
changes only how the verifier compares two legitimate observations of the
same real state — it does not change the topology service's own health
semantics, precedence rules, or what counts as `HEALTHY`/`STALE`/`OFFLINE`
in production.

Live evidence gathered while preparing this report: **10 consecutive runs
of the hardened verifier, 19/19 PASS on every run**, nodes=15/edges=23 on
every run, no timestamp-race failure observed.

[SCREENSHOT: Dynamic NetworkX topology with dual-stack addresses]

## 14. Infrastructure as Code

`master.py` is a thin orchestrator: after the existing Lab-1 device
provisioning flow, it makes exactly one call per monitoring subsystem —
`ensure_nmas_infrastructure()`, `ensure_snmp_infrastructure()`,
`ensure_syslog_infrastructure()`, `ensure_telemetry_infrastructure()`,
`ensure_grafana_infrastructure()`, `ensure_topology_infrastructure()` — with
no subsystem logic embedded in `master.py` itself. Every subsystem also has
a standalone execution mode (`--nmas-only`, `--snmp-only`, `--syslog-only`,
`--telemetry-only`, `--grafana-only`, `--topology-only`) that exits before
any Lab-1 device configuration import, for isolated provisioning and
verification.

Persistent desired state lives entirely under version control:

- `modules/` — one Python module per subsystem, the only place subsystem
  logic lives.
- `monitoring/config/` — policy/config files (CPU threshold policy, gNMI
  paths, SNMP OIDs, syslog/trap receiver config, topology config).
- `monitoring/scripts/` — provisioning and collector scripts deployed onto
  NMAS or the routers.
- `templates/` — Jinja2 templates for cEOS/Linux device-side configuration.
- `monitoring/grafana/provisioning/` — file-provisioned datasource and
  dashboard JSON.
- `monitoring/tests/` — unit tests and live acceptance verifiers.
- `docs/` — the subsystem documentation this report synthesizes.

Idempotency is enforced per-module by hash/PID/content-comparison
convergence checks (e.g. a rendered configuration is hash-compared against
the live device state before pushing; a Linux daemon's PID and
`/proc/<pid>/cmdline` content are checked before restarting it). Every
subsystem was independently observed, across the session history recorded
in `docs/`, to report "unchanged" on a second consecutive run with stable
PIDs/container IDs/hashes.

## 15. Security

- SNMPv3 `authPriv` throughout, with SHA-256 authentication and AES-128
  privacy — no SNMPv1/v2c community string is used anywhere in the active
  configuration.
- gNMI is TLS-secured on every device (native cEOS certificates on cEOS;
  a preserved per-router self-signed certificate on the R3/R4 adapter), with
  a dedicated non-`admin` `nmas-telemetry` credential; a wrong password is
  verified to be rejected on both native and adapter targets.
- NETCONF runs over SSH on every device, using the same `nmas-telemetry`
  credential where authentication is required.
- Runtime secrets (SNMPv3 passphrases, InfluxDB token, Grafana admin
  password, gNMI/NETCONF password) are confined to the git-ignored
  `monitoring/runtime/` tree, mode 600, and never committed.
- InfluxDB and Grafana credentials are generated at first run into that
  same ignored tree; no credential value appears in any tracked file.
- InfluxDB, Grafana, `snmptrapd`, and rsyslog are all bound to `127.0.0.1`
  or the management address `192.168.200.100` only — none is reachable
  outside the management path.
- Pre-existing Lab-1 baseline default credentials (`admin`/`[REMOVED_PHASE23_PLAINTEXT]` for
  cEOS, `[REMOVED_PHASE23_PLAINTEXT]` for host root) are frozen Lab-1 defaults, out of scope
  per `AGENTS.md`, and are clearly distinguished in the documentation from
  the new monitoring-specific secret handling described above — none of the
  monitoring subsystems reuse or depend on those defaults.

No secret value is reproduced anywhere in this report.

## Installation and Configuration Summary

The supported installation path is the repository-owned Infrastructure-as-Code
workflow. Run it from the authoritative checkout with the project virtual
environment; do not redeploy Containerlab. Each mutually exclusive mode below
exits before the preserved full Lab-1 device-provisioning flow and is safe to
rerun against the already-deployed topology:

```bash
cd /home/student/Scripts/clab_dualstack_lab

/home/student/Scripts/.venv/bin/python3 master.py --nmas-only
/home/student/Scripts/.venv/bin/python3 master.py --snmp-only
/home/student/Scripts/.venv/bin/python3 master.py --syslog-only
/home/student/Scripts/.venv/bin/python3 master.py --telemetry-only
/home/student/Scripts/.venv/bin/python3 master.py --grafana-only
/home/student/Scripts/.venv/bin/python3 master.py --topology-only
```

| Mode | Repository-owned action |
|---|---|
| `--nmas-only` | Installs only missing NMAS host/Python dependencies, converges the management-bound rsyslog and `snmptrapd` receivers and logrotate policy, starts/reuses the Compose InfluxDB/Grafana stack, enforces 30-day InfluxDB retention, and requires the 20-check NMAS health gate. |
| `--snmp-only` | Checks NMAS, generates or reuses protected SNMPv3 secrets, converges cEOS and R3/R4 SNMP desired state, registers trap-originator engines, polls and stores the verified OIDs, checks trap ingestion, safely proves collector CPU alert/recovery storage, and rechecks NMAS. |
| `--syslog-only` | Converges cEOS critical logging and its documented supplementary forwarder, R3/R4 rsyslog forwarding, and the NMAS ingestion service; then sends uniquely marked critical test events and verifies raw-log and InfluxDB storage. |
| `--telemetry-only` | Converges cEOS gNMI TLS/authentication, the R3/R4 gNMI/NETCONF adapters, and the persistent NMAS gNMI collector; then verifies gNMI Capabilities/Get/Subscribe, fresh stored streams, NETCONF hello/filtered GET, snapshot storage, and NMAS health. |
| `--grafana-only` | Reuses and verifies the NMAS stack, validates the Git-owned dashboard source, reloads the provisioned datasource/dashboard provider, and executes all dashboard and variable queries against real stored data. |
| `--topology-only` | Reuses and verifies NMAS, reconciles active Containerlab metadata through read-only inspection, converges the localhost NetworkX service, and runs its live acceptance verifier. |

Add `--verbose` to any mode to display stage details. These commands configure
only their monitoring scope; none deploys, destroys, or recreates the
Containerlab topology.

### cEOS SNMP

Run `master.py --snmp-only`; do not enter credentials on the command line.
`modules/snmp.py` generates or reuses the protected runtime passphrases,
renders `templates/monitoring/ceos_snmp.j2` for each of the eight cEOS
devices, applies only a changed configuration through EOS CLI, verifies it,
and saves it with `write memory`. The rendered configuration provides:

- SNMPv3 user `nmas-monitor` in an SNMPv3-only group at the `priv`
  (`authPriv`) security level, with SHA-256 authentication and AES-128
  privacy; no SNMPv1/v2c community is configured.
- A read-only `iso` view and the `NMAS_SNMP` IPv4 ACL, applied to the SNMP
  agent, which permits only the NMAS management address
  `192.168.200.100`.
- A version-3 `priv` trap destination at NMAS, the inventory-defined
  management source interface, and native EOS `link-up`/`link-down`
  notification enablement.

The template contains placeholders resolved only at runtime; generated
passphrases remain in ignored, mode-600 files under `monitoring/runtime/`.
`modules/snmp.py` also owns live hash comparison, receiver USM registration,
polling, storage, and verification, so no one-off device commands are needed.

### Ubuntu/FRR R3/R4 SNMP

The same `--snmp-only` workflow sends tracked desired state to
`monitoring/scripts/provision_linux_snmp.py` inside R3 and R4. The provisioner
installs `snmpd`/SNMP tools only when absent, blocks package post-install
service startup, writes the rendered
`templates/monitoring/snmpd.conf.j2`, and persists the protected SNMPv3 USM
identity. The agent is SNMPv3-only, binds UDP/161 only to the router's
management address (`192.168.200.3` or `.4`), exposes a read-only `priv` view,
and is started and tracked directly by pidfile. This is required because the
containers run `sleep infinity` as PID 1 and do not provide normal systemd.

Net-SNMP exposes `HOST-RESOURCES-MIB::hrProcessorLoad` for CPU and IF-MIB for
interface identity/state. Because the attempted Net-SNMP Event-MIB trigger
path was not viable, the tracked
`monitoring/scripts/linux_link_notifications.py` watcher reads real
`/sys/class/net` state every two seconds and emits authenticated SNMPv3
`linkUp`/`linkDown` notifications on actual transitions. It is managed
without systemd, uses its own registered notification engine ID, and does not
change interface state.

### Syslog

Run `master.py --syslog-only`. For cEOS, `modules/syslog.py` renders
`templates/monitoring/ceos_syslog.j2` with the NMAS destination, the
inventory management source interface, and `logging trap critical`; the
repository-owned supplementary forwarder preserves the cEOS engineering-build
limitation described in §8. For R3/R4,
`monitoring/scripts/provision_linux_syslog.py` installs and directly manages
rsyslog without systemd and renders
`templates/monitoring/linux_syslog.conf.j2`. Both platforms forward only
severity 0-2 events to `192.168.200.100:514`. NMAS retains the raw log using
the tracked daily `rotate 30`/`maxage 30` policy and normalizes events into
`syslog_event`.

### cEOS gNMI / gRPC

Run `master.py --telemetry-only`. `modules/gnmi.py` uses
`templates/monitoring/ceos_gnmi_security.j2` and
`templates/monitoring/ceos_gnmi_enable.j2` to converge the native cEOS gNMI
service on TCP/6030. It creates or reuses the dedicated `nmas-telemetry`
identity, reuses each device's existing Containerlab-issued certificate,
waits for the `NMAS_GNMI` TLS profile to become valid, and only then binds
that profile to the native gRPC transport. The password is generated into
`monitoring/runtime/telemetry-secrets.json`, not Git, and wrong-password
authentication is tested.

The persistent `nmas-gnmi-collector.service`, provisioned from
`monitoring/scripts/gnmi_collector.py` by
`monitoring/scripts/provision_gnmi_collector.py`, opens one authenticated TLS
session per device. It subscribes to the six verified OpenConfig paths in
`monitoring/config/gnmi_paths.yml` using `Subscribe` mode `STREAM`, submode
`SAMPLE`, at a 20-second interval.

### R3/R4 gNMI / gRPC

Ubuntu/FRR does not natively expose the required gNMI service. The same
telemetry workflow therefore uses `modules/linux_telemetry_adapter.py` and
`monitoring/scripts/provision_linux_telemetry.py` to install and manage the
explicitly labelled repository-owned adapter. Its
`monitoring/scripts/linux_gnmi_server.py` endpoint binds only to the router's
management address on TCP/6030, uses TLS and password authentication, and
implements read-only Capabilities, Get, and Subscribe STREAM+SAMPLE. Values
are read live by `monitoring/scripts/nmas_linux_telemetry_metrics.py` from
`/proc/stat`, `/proc/meminfo`, and `/sys/class/net`; this is real Linux state,
not native FRR gNMI and not canned data. Set and ON_CHANGE remain unsupported.

### cEOS NETCONF

The frozen cEOS Lab-1 baseline already enables the native
`management api netconf` SSH transport on TCP/830, so Labs 2/3 do not install
a duplicate NETCONF service or render a separate NETCONF enablement template.
`--telemetry-only` first ensures the authenticated `nmas-telemetry` local
identity through the cEOS gNMI security template, then `modules/netconf.py`
connects over SSH, performs the hello/capability exchange, issues filtered
read-only GETs for OpenConfig system hostname and interface inventory, checks
the results against real device identity/state, and stores a normalized
snapshot.

### R3/R4 NETCONF

R3/R4 have no native FRR or Ubuntu NETCONF server. The repository-owned
`monitoring/scripts/linux_netconf_server.py`, deployed and process-managed by
`monitoring/scripts/provision_linux_telemetry.py`, binds only to each
management address on TCP/830. It authenticates over SSH and implements
NETCONF base:1.0 hello/capabilities, filtered read-only GET for the supported
OpenConfig hostname/interface subsets, and close-session. Configuration RPCs
return `operation-not-supported`; notification subscriptions and YANG Push
are not advertised.

In this implementation, **gNMI is continuous streaming telemetry; NETCONF is
discrete read-only state retrieval**. The live cEOS server advertises none of
the notification, subscribed-notifications, interleave, or YANG-Push
capabilities needed for continuous NETCONF streaming. This is a verified
live-platform capability limit, not functionality hidden by the collector.

### Data-Lake Deployment

`master.py --nmas-only` is the reproducible NMAS foundation workflow. The
repository-owned `monitoring/scripts/bootstrap_nmas.sh`,
`monitoring/scripts/install_nmas_receivers.sh`,
`monitoring/scripts/start_nmas_monitoring.sh`,
`monitoring/docker-compose.yml`, and
`monitoring/scripts/influxdb_retention.py` create or reuse one InfluxDB
instance and the single `network-monitoring` bucket with 30-day retention;
they do not create per-protocol databases. Secrets are generated once into
the ignored, mode-600
`monitoring/runtime/monitoring.env`. The common bucket contains
`snmp_poll`, `snmp_trap`, `collector_alert`, `syslog_event`,
`gnmi_telemetry`, and `netconf_snapshot`.

### Grafana / Visualization Deployment

Run `/home/student/Scripts/.venv/bin/python3 master.py --grafana-only` from
the repository. Grafana and InfluxDB are the existing Compose monitoring
services; `modules/grafana.py` validates the Git-owned source, preserves the
stable `nmas-influxdb` datasource UID, reloads the file provider, and verifies
all queries. `monitoring/scripts/build_grafana_dashboards.py` deterministically
generates the checked-in dashboards under
`monitoring/grafana/provisioning/`, so reproducibility requires no manual
dashboard construction. The expected result is four stable-UID dashboards,
39 panels, 8 variables, and 47 executed queries covering SNMP polls/traps and
collector alerts, streaming telemetry and NETCONF snapshots, critical
syslog, and fleet health.

For the extra-credit visualization, run
`/home/student/Scripts/.venv/bin/python3 master.py --topology-only`.
`modules/topology.py` and `modules/topology_graph.py` build a NetworkX graph
from active Containerlab metadata and read-only inspection, overlay InfluxDB
health evidence, and provision the auto-refreshing service only on
`127.0.0.1:8050`. This reads the deployed topology; it does not redeploy or
rewrite it.

Detailed procedures and evidence remain in the focused documents:

| Subsystem | Detailed documentation |
|---|---|
| SNMP | `docs/SNMP_IMPLEMENTATION.md`; `docs/SNMP_OIDS.md` |
| Syslog | `docs/SYSLOG_IMPLEMENTATION.md` |
| gNMI / NETCONF | `docs/STREAMING_TELEMETRY_IMPLEMENTATION.md`; `docs/TELEMETRY_STREAMS.md` |
| Grafana | `docs/GRAFANA_DASHBOARDS.md` |
| Topology | `docs/DYNAMIC_TOPOLOGY.md` |
| Compliance | `docs/FINAL_COMPLIANCE_AUDIT.md` |

## SNMP OID Catalog

The same verified standard objects are used for all eight cEOS devices and
both Ubuntu/FRR devices; an artificial per-device duplicate list is therefore
unnecessary. All table indexes (`ifIndex` and `hrProcessorIndex`) are
discovered by live walks and correlated at collection time, never hardcoded.
The authoritative machine-readable list is
`monitoring/config/snmp_oids.yml`.

| Purpose | MIB/Object | OID | Applicable Platforms | Collection Method / Notes |
|---|---|---|---|---|
| Device identity | `SNMPv2-MIB::sysName.0` | `1.3.6.1.2.1.1.5.0` | cEOS; Ubuntu/FRR | Scalar GET; must match the inventory name. Used as the stored hostname tag rather than a separate metric point. |
| Uptime/liveness | `SNMPv2-MIB::sysUpTime.0` | `1.3.6.1.2.1.1.3.0` | cEOS; Ubuntu/FRR | Scalar GET; stored in `snmp_poll` as TimeTicks. |
| Interface index discovery | `IF-MIB::ifIndex` | `1.3.6.1.2.1.2.2.1.1` | cEOS; Ubuntu/FRR | Walk; supplies the dynamic key used to correlate all interface columns. |
| Legacy interface description | `IF-MIB::ifDescr` | `1.3.6.1.2.1.2.2.1.2` | cEOS; Ubuntu/FRR | Walked by the current poll path but not stored as a metric; `ifName` is the canonical storage tag. |
| Interface name | `IF-MIB::ifXTable.ifName` | `1.3.6.1.2.1.31.1.1.1.1` | cEOS; Ubuntu/FRR | Walk; correlated by discovered index and stored as the `interface` tag. |
| Interface administrative state | `IF-MIB::ifAdminStatus` | `1.3.6.1.2.1.2.2.1.7` | cEOS; Ubuntu/FRR | Walk; indexed values (`1=up`, `2=down`, `3=testing`) stored in `snmp_poll`. |
| Interface operational state | `IF-MIB::ifOperStatus` | `1.3.6.1.2.1.2.2.1.8` | cEOS; Ubuntu/FRR | Walk; indexed IF-MIB values `1`-`7` stored in `snmp_poll`. The collector rejects mismatched interface index sets. |
| CPU utilization | `HOST-RESOURCES-MIB::hrProcessorLoad` | `1.3.6.1.2.1.25.3.3.1.2` | cEOS; Ubuntu/FRR | Walk; one `0`-`100` value per discovered logical processor. The mean drives Grafana and the collector threshold evaluator. No Arista enterprise CPU OID is used. |
| USM engine discovery | `SNMP-FRAMEWORK-MIB::snmpEngineID.0` | `1.3.6.1.6.3.10.2.1.1.0` | Ubuntu/FRR for polling; cEOS uses `show snmp engineID` | Provisioning-only scalar GET used to register authoritative engines with `snmptrapd`; not stored as a periodic metric. |
| Link-down notification | `IF-MIB::linkDown` (`snmpTraps.3`) | `1.3.6.1.6.3.1.1.5.3` | Native cEOS; R3/R4 link watcher | **Notification OID, not polled.** Received with indexed `ifIndex`, `ifAdminStatus`, and `ifOperStatus` varbinds and stored in `snmp_trap`. |
| Link-up notification | `IF-MIB::linkUp` (`snmpTraps.4`) | `1.3.6.1.6.3.1.1.5.4` | Native cEOS; R3/R4 link watcher | **Notification OID, not polled.** Same correlated interface varbind set as `linkDown`; stored in `snmp_trap`. |

`linkUp`/`linkDown` are genuine SNMP notifications, and CPU values are
genuinely polled over SNMP. Neither selected live platform exposes a
**verified native CPU-threshold SNMP trap**. NMAS therefore evaluates the
real `hrProcessorLoad` polls and stores threshold transitions as
`collector_alert`, deliberately never as `snmp_trap`. This supplies CPU
threshold behavior while preserving the difference between a device
notification and a collector-generated alert.

## Telemetry Data Catalog

The eight cEOS devices use native gNMI and NETCONF; R3/R4 use the explicitly
labelled repository-owned adapters. All ten devices populate the same NMAS
storage model. The six gNMI sources below are the exact paths in
`monitoring/config/gnmi_paths.yml` and are continuously sampled every 20
seconds.

| Data Category | Protocol | Source | Applicable Devices | Destination Measurement | Notes |
|---|---|---|---|---|---|
| Hostname / identity | gNMI | OpenConfig `/system/state/hostname` | All 10; native cEOS, adapter on R3/R4 | `gnmi_telemetry` | Stored as `category=system_identity`, field `hostname`; cross-checked against inventory. |
| CPU | gNMI | OpenConfig `/system/cpus/cpu[index=*]/state/total/instant` | All 10 | `gnmi_telemetry` | Per reported CPU index, field `cpu_total_pct`. R3/R4 derives real delta utilization from `/proc/stat`. |
| Memory | gNMI | OpenConfig `/system/memory/state` | All 10 | `gnmi_telemetry` | Physical, used, free, and reserved byte fields; R3/R4 reads `/proc/meminfo`. |
| Interface operational state | gNMI | OpenConfig `/interfaces/interface[name=*]/state/oper-status` | All 10 | `gnmi_telemetry` | Per dynamically keyed interface, `category=interface_state`. |
| Interface administrative state | gNMI | OpenConfig `/interfaces/interface[name=*]/state/admin-status` | All 10 | `gnmi_telemetry` | Per dynamically keyed interface, `category=interface_state`. |
| Interface counters | gNMI | OpenConfig `/interfaces/interface[name=*]/state/counters` | All 10 | `gnmi_telemetry` | Stores in/out octets, errors, and discards. Packet and routing-session telemetry are not claimed. |
| System hostname/state validation | NETCONF | Hello plus filtered OpenConfig system `<get>` | All 10; native cEOS, adapter on R3/R4 | `netconf_snapshot` | Discrete retrieval validates the returned hostname. The normalized snapshot stores metadata/counts, not a continuous hostname stream. |
| Interface inventory | NETCONF | Filtered OpenConfig interfaces `<get>` | All 10 | `netconf_snapshot` | Retrieves real interface names and stores `interface_count`; it does not claim continuous interface-state updates. |
| Capabilities metadata / snapshot | NETCONF | Server `<hello>` capability set | All 10 | `netconf_snapshot` | Stores `capabilities_count`, `interface_count`, `has_notifications`, and `has_yang_push`; the last two are verified false in the current implementation. |

Continuous updates come from gNMI Subscribe STREAM+SAMPLE. NETCONF rows are
point-in-time read-only snapshots created by the verification/collection
workflow; routing-neighbor/session state is not part of the stored schema and
is not implied by this catalog.

## Reproducible Verification Commands

From the authoritative checkout, the following existing verifiers reproduce
the documented subsystem acceptance checks without any Containerlab lifecycle
operation or real-link flap:

```bash
cd /home/student/Scripts/clab_dualstack_lab

# NMAS receivers, bindings, dependencies, health, retention, and data-lake round trip
monitoring/tests/verify_nmas_infrastructure.sh

# SNMPv3 polls/OIDs/storage plus safe cEOS synthetic trap-ingestion smoke test
/home/student/Scripts/.venv/bin/python3 monitoring/tests/verify_snmp.py

# Full SNMP convergence plus safe collector-generated CPU ALERT/RECOVERY proof
/home/student/Scripts/.venv/bin/python3 master.py --snmp-only

# Critical syslog configuration, unique test events, raw log, and InfluxDB storage
/home/student/Scripts/.venv/bin/python3 monitoring/tests/verify_syslog.py

# gNMI Capabilities/Get, persistent STREAM freshness/storage, and NETCONF hello/GET
/home/student/Scripts/.venv/bin/python3 monitoring/tests/verify_telemetry.py

# Provisioned datasource, dashboards, variables, all 47 Flux queries, and real data
/home/student/Scripts/.venv/bin/python3 monitoring/tests/verify_grafana.py --verbose

# NetworkX service/API/schema, active 15-node/23-edge graph, overlays, and safe demo
/home/student/Scripts/.venv/bin/python3 monitoring/tests/verify_topology.py
```

The NMAS verifier writes and retrieves a labelled local `nmas_test` point;
the SNMP verifier writes current poll results and emits EOS's safe synthetic
test notification; the syslog verifier emits uniquely labelled critical test
messages; and telemetry verification writes discrete NETCONF snapshots while
checking the already-running gNMI stream. These are intentional verification
artifacts under the same 30-day retention policy, not topology changes.
Actual link-state notification evidence remains the native cEOS
`linkUp`/`linkDown` configuration plus the real R3/R4 transitions on temporary
`nmastest0` interfaces documented in §6 and
`docs/SNMP_IMPLEMENTATION.md`; the automated verifier does not flap a real
topology link. The separately required video and the screenshot placeholders
in this report remain student capture deliverables; these commands and this
report do not replace the video.

## 16. Verification Results

All figures below were re-confirmed live while preparing this report
(re-run against the running, unmodified lab), except where noted as carried
forward from stored evidence in `docs/FINAL_COMPLIANCE_AUDIT.md`.

| Check | Result |
|---|---|
| NMAS | 20/20 PASS |
| SNMP | 10/10 PASS |
| SNMP traps | PASS |
| CPU threshold alert | PASS (stored evidence, `docs/FINAL_COMPLIANCE_AUDIT.md`) |
| Syslog | 10/10 PASS |
| gNMI | 10/10 PASS |
| NETCONF | 10/10 PASS |
| Grafana | 4 dashboards / 39 panels / 47 queries PASS |
| Dynamic topology | 19/19 PASS, 10 consecutive runs |
| Python unit tests | 84/84 PASS |
| Compliance matrix | 16 PASS / 0 PARTIAL / 0 FAIL |

## 17. Requirements Compliance

`docs/FINAL_COMPLIANCE_AUDIT.md` tracks all 16 requirement rows drawn from
`LAB_REQUIREMENTS.md`/`GAP_ANALYSIS.md` — NMAS infrastructure, SNMP polling,
the CPU OID, SNMP notifications (including the CPU threshold gap closed in
the "Implement collector CPU threshold alerting" commit), critical syslog,
retention, Grafana, dynamic topology, automation/IaC, idempotency,
security/secrets, and frozen-baseline preservation — and reports **16 PASS
/ 0 PARTIAL / 0 FAIL**.

**Mandatory gaps: None.** Every mandatory item in `LAB_REQUIREMENTS.md` §14
(SNMP polling, CPU OID, interface state/counters, link-down notification,
CPU threshold behavior, critical syslog, gNMI telemetry, NETCONF-derived
data where supported, Grafana dashboards, and documented unsupported
features) has stored and, in this report, freshly re-confirmed live
evidence.

Two additional demonstrations were not performed and are not required to
establish the mandatory compliance results above: a controlled failure of a
real production topology link, which was intentionally avoided under the
frozen-baseline safety policy, and a single-session back-to-back convergence
run of every subsystem. Equivalent safe failure evidence and per-subsystem
idempotency evidence were demonstrated separately.

## 18. Known Limitations

- **cEOS engineering-build remote syslog defect**: this specific
  `4.36.2F-49692632.4362F.1` engineering image's own `rsyslog.service`
  cannot start (`tracepointReader` permission denial). Standard `logging
  host` configuration is correctly applied but not reliably functional as a
  transport; mitigated by a repository-owned direct-UDP relay, with
  deterministic verification independent of the defect. See §8.
- **cEOS AAA/authorization limitation**: this engineering build was proven
  to not enforce role-based command authorization (a `network-operator`
  role and a custom deny-role test user could both still enter config
  mode); reverted immediately after proof. The `nmas-telemetry` account
  remains a credential-separation control, not a functioning technical
  read-only enforcement boundary, on this specific image.
- **R3/R4 gNMI/NETCONF are repository-owned adapters, not native FRR
  features.** They serve real live `/proc`/`/sys`/FRR state, but FRR 8.4.4
  and the Ubuntu image have no native gNMI or NETCONF server.
- **NETCONF is discrete retrieval, not notification streaming**, on every
  platform in this project — cEOS 4.36.2F's NETCONF server advertises no
  `:notification`/`:interleave`/YANG-Push capability among 351 enumerated
  capabilities.
- **H1 → WebServer connectivity** is a pre-existing Lab-1 application-layer
  issue, out of scope per `AGENTS.md`/`GAP_ANALYSIS.md`, and did not block
  any mandatory Labs 2/3 verification.
- **A real production topology link failure was intentionally not
  performed.** Disruptive link tests are prohibited under the frozen-
  baseline safety policy; the safe, clearly labelled synthetic topology
  demo and disposable-dummy-interface trap evidence (real transitions on
  interfaces created and destroyed solely for that test) substitute for it.
- **R3/R4 have no init/reaper as PID 1** (`sleep infinity`), so an exited
  monitoring helper process becomes a permanent zombie rather than being
  reaped. This was found to mask a dead link watcher in one prior session
  and was fixed with a content-based liveness check; the underlying
  no-init/no-reaper characteristic itself remains a genuine, documented
  platform property of these containers, not a defect this project can
  eliminate.
- NETCONF SSH host-key pinning is not implemented (`hostkey_verify=False`),
  an accepted, stated lab-scope limitation — SSH transport confidentiality
  and integrity are still in effect; only host-identity pinning is skipped.

## 19. Conclusion

This project demonstrates a working, centrally-managed, multi-protocol
observability platform layered on a frozen, unmodified Lab-1 network: SNMP
polling and notifications, an NMAS-generated CPU threshold alerting path
that substitutes for a native trap neither live platform provides,
critical-severity event ingestion from syslog, continuous gNMI/OpenConfig
streaming telemetry, discrete NETCONF state retrieval, and a single
centralized InfluxDB data lake behind both a Grafana visualization layer
and a live, dynamically-refreshing NetworkX topology view with dual-stack
addressing. Every device-side and collection mechanism is described
accurately as native or adapter-based, every safety-motivated
simplification (synthetic test traps, disposable dummy interfaces, the
safe topology demo) is clearly and consistently labelled as such throughout
the documentation, and the entire stack is deployed and re-verified through
reproducible, idempotent Infrastructure-as-Code.
