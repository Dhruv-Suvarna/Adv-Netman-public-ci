# Grafana Network Monitoring Dashboards

> **Note (Phase 2, 2026-09-20):** this document is a dated historical record
> of the original four-dashboard Labs 2/3 implementation described below and
> is preserved unchanged. The four dashboards it describes still exist and
> are still live-verified (now tagged `legacy` in Grafana), but the current
> seven-dashboard structure -- the three additional canonical dashboards
> mapping to the future Django Monitoring pages (Resources / Link Events /
> Link State & Traffic), the CPU-alert-panel verifier fix, and the current
> Django integration contract -- is documented in
> `docs/GRAFANA_MONITORING_TAXONOMY.md`.

Status: implemented and verified on 2026-09-07 against the frozen 10-device
monitoring baseline. This phase changed only repository-owned Grafana desired
state and its orchestration/verification. It did not change Containerlab,
device configuration, routing, addressing, collection schemas, InfluxDB
retention, or either monitoring container.

## Architecture

```text
SNMP polls/traps ----\
gNMI telemetry ------> existing InfluxDB network-monitoring bucket (30 days)
critical syslog -----/                         |
                                               v
                             existing Grafana 11.5.2
                             datasource UID: nmas-influxdb
                                               |
                                               v
                             file-provisioned NMAS dashboards
```

Grafana and InfluxDB remain the existing Compose services in
`monitoring/docker-compose.yml`. The dashboard provider reads JSON from the
already-mounted read-only `/etc/grafana/provisioning` tree. No database,
bucket, organization, datasource, receiver, collector, or Grafana instance is
duplicated.

## Datasource design

The existing datasource is retained exactly once:

- Name: `NMAS InfluxDB`
- UID: `nmas-influxdb`
- Type/query language: InfluxDB / Flux
- Access: Grafana server-side proxy
- URL inside Compose: `http://influxdb:8086`
- Default: yes
- Provisioned/read-only: yes

`monitoring/grafana/provisioning/datasources/influxdb.yml` obtains the
organization, bucket, and token through Grafana's `$__env{...}` expansion.
The values come from the existing ignored, mode-600
`monitoring/runtime/monitoring.env`; the token never appears in a dashboard,
provider file, API output, or tracked source.

## Dashboard inventory

All dashboards live in the Grafana folder `NMAS Network Monitoring` (folder
UID `nmas-network-monitoring`), are read-only in the UI, refresh every 20
seconds, and use stable UIDs.

| Dashboard | UID | Panels | Variables |
|---|---|---:|---|
| NMAS Network Health Overview | `nmas-fleet-overview` | 12 | `device`, `platform` |
| NMAS Streaming Telemetry | `nmas-streaming-telemetry` | 11 | `device`, `platform`, `interface` |
| NMAS SNMP Monitoring | `nmas-snmp-monitoring` | 10 | `device` |
| NMAS Critical Syslog | `nmas-critical-syslog` | 6 | `device`, `severity` |

### NMAS Network Health Overview

The overview is the first operational landing page. It shows devices that
actually reported in the last five minutes, current non-UP interface count,
critical syslog and trap counts for the selected time range, latest CPU,
worst telemetry age, a per-device freshness/health table, current non-UP
interfaces, CPU and memory trends, recent linkDown notifications, and recent
critical syslog. Missing telemetry is never translated into an `UP` value.

Freshness classification is explicit: under 60 seconds is `HEALTHY`, 60-120
seconds is `STALE`, and over 120 seconds is `OFFLINE`. The query searches the
30-day retained window so a stopped device remains visible as stale/offline
instead of disappearing as soon as the dashboard time range changes. A
device with no record anywhere in retention remains absent rather than being
fabricated.

### NMAS Streaming Telemetry

This dashboard primarily uses `gnmi_telemetry` for latest/freshness, CPU,
derived memory utilization, admin/oper state timelines, current non-UP
interfaces, traffic rate derived from octets, error/discard rates, and latest
raw counters. A separately labelled table uses `netconf_snapshot` for the
latest discrete read-only RPC result and age. The freshness table contains a
`source` column that labels cEOS as
`native cEOS gNMI` and R3/R4 as `Linux read-only adapter`; the implementation
difference is intentionally visible.

The collection schema stores octets, errors, and discards. Although native
cEOS sends additional packet leaves on the wire, the established collector
does not store packet counters, so no packet panel is invented in this phase.

### NMAS SNMP Monitoring

This dashboard uses the actual `snmp_poll` and `snmp_trap` schemas. It shows
poll freshness/device uptime, latest and historical HOST-RESOURCES-MIB CPU,
latest IF-MIB admin/oper state, current non-UP count, trap volume, event types,
source/device/OID/interface identity, timestamps, and decoded varbinds.
`ceosTestNotification` stays visibly distinct from `linkUp`/`linkDown`.

SNMP CPU is polling data, not a trap. Neither cEOS 4.36.2F nor Ubuntu/FRR
exposes a verified native CPU threshold SNMP trap (see
`docs/SNMP_IMPLEMENTATION.md`). The dashboard's "NMAS Collector CPU Alerts"
panel instead shows the explicitly permitted second path: `collector_alert`
events generated by `modules/cpu_alerts.py` from repeated real SNMP CPU
polls, tagged `source=collector`/`alert_type=cpu_threshold`/
`monitoring_method=snmp_polling`. This is a genuinely different InfluxDB
measurement from `snmp_trap`, and the panel is visually and semantically
separated from "Recent SNMP notifications" (device-originated) directly
above it -- the dashboard never represents a collector alert as a device
trap. Rows tagged `verification=true` are the safe, clearly-labelled
deterministic self-test evidence (real polled CPU value, temporary
verification-only threshold); `verification=false` rows are production
alerts derived from the unmodified repository policy in
`monitoring/config/cpu_threshold_policy.yml`.

### NMAS Critical Syslog

This dashboard uses only the `syslog_event.message` series for event counts
and tables, preserving device/source/platform/severity/facility tags. It shows
event count, volume over time, events by device, severity distribution,
facility distribution, and a 500-row recent-event table. Dashboard device and
severity variables make the event table useful for targeted searches.

The deployed policy admits emergency/alert/critical only; current live data is
`crit`. Lower severities are not hidden by Grafana—they are absent because the
device-side policy does not forward them. Old records created before hostname
normalization used `mgmt-swt`; dashboard Flux normalizes those rows to the
canonical `mgmt_swt` label without rewriting retained data.

## Flux/query strategy

- Dashboard time controls use `v.timeRangeStart`, `v.timeRangeStop`, and
  `v.windowPeriod` for trends and event counts.
- Multi-value variables use escaped Grafana regex expansion, for example
  `r.device =~ /^${device:regex}$/`; the All value is `.*`.
- Latest interface state groups by device/interface/field, applies `last()`,
  and then pivots admin/oper fields into a readable table.
- Memory percentage pivots used and physical byte fields captured at the same
  telemetry timestamp and computes `100 * used / physical` only when physical
  memory is present and nonzero.
- Traffic rate uses the non-negative derivative of raw octet counters and
  converts bytes/second to bits/second. Error/discard panels use non-negative
  counter derivatives.
- Mixed-type event fields are not unsafely pivoted. Event tables select the
  string message/raw-varbind field and preserve event metadata as tags.
- Freshness/current-state queries use a fixed recent or retained window by
  design; trend and event panels honor the selected dashboard time range.

Every query names the inspected `network-monitoring` bucket and the verified
measurement/field/tag schema. No collection-layer change was required.

## Reproducible provisioning

Tracked desired state:

- `monitoring/grafana/provisioning/dashboards/provider.yml`
- `monitoring/grafana/provisioning/dashboards/json/*.json`
- `monitoring/scripts/build_grafana_dashboards.py`
- `modules/grafana.py`
- `monitoring/tests/verify_grafana.py`

The Python builder deterministically generates the four checked-in JSON
files. Validate drift without changing files:

```bash
python3 monitoring/scripts/build_grafana_dashboards.py --check
```

Provision and verify dashboards without entering Lab 1 device configuration:

```bash
python3 master.py --grafana-only
python3 monitoring/tests/verify_grafana.py --verbose
```

`--grafana-only` first converges/verifies the existing NMAS stack, then asks
Grafana's admin provisioning endpoint to reload the file provider. Because
the directory is already bind-mounted, this requires no container restart or
recreation. A fresh installation loads the same provider during normal
Grafana startup. The full `master.py` workflow calls the same
`ensure_grafana_infrastructure()` module after telemetry; `master.py` contains
no dashboard implementation.

## Idempotency evidence

Two consecutive `python3 master.py --grafana-only` runs converged and passed.
The before/after comparison proved:

- exactly one datasource UID `nmas-influxdb`;
- exactly four NMAS dashboard UIDs, with stable Grafana database IDs and
  unchanged versions across the final repeated run;
- stable folder UID `nmas-network-monitoring`;
- unchanged Grafana and InfluxDB container IDs and `StartedAt` timestamps;
- no restart, recreation, bucket operation, datasource duplication, or token
  regeneration.

The second run ended with `IDEMPOTENCY_PASS`.

## Automated verification

`monitoring/tests/verify_grafana.py` does more than test HTTP 200. It verifies
Grafana health, datasource uniqueness and live InfluxDB health, deterministic
source generation, exact dashboard UIDs/titles, required panels and variables,
API retrieval, datasource binding on every panel, secret absence, Flux syntax,
and recent real results through Grafana's datasource query API.

Observed acceptance matrix after convergence:

```text
DASHBOARD                         API PANELS VARIABLES QUERIES DATA
nmas-fleet-overview               PASS PASS   PASS      PASS    PASS
nmas-streaming-telemetry          PASS PASS   PASS      PASS    PASS
nmas-snmp-monitoring              PASS PASS   PASS      PASS    PASS
nmas-critical-syslog              PASS PASS   PASS      PASS    PASS
SUMMARY: dashboards=4 panels=39 variables=8 queries=47 datasource=OK secrets=PASS
```

Panel/query counts increased from the previously-documented 38/46 to 39/47 with
the addition of the "NMAS Collector CPU Alerts" panel on `nmas-snmp-monitoring`
(see that dashboard's section above); every other dashboard/panel/query is
unchanged.

All 47 panel/variable Flux queries executed successfully through Grafana, not
only directly against InfluxDB. Empty results are permitted only for the two
condition/event panels where absence is operationally valid: current non-UP
interfaces and recent linkDown notifications.

## Representative direct InfluxDB evidence

At `2026-09-07T18:58:49Z`, independent Flux queries returned:

- devices with a real identity update in five minutes: `10`;
- worst fleet telemetry age: `17.75 seconds`;
- current observed non-UP interfaces: `0`;
- latest gNMI CPU percentages: R1 47.78, R2 49.78, R3 48.00, R4 48.00,
  R5 47.89, S1 48.33, S2 48.44, S3 47.33, S4 46.89, `mgmt_swt` 47.89;
- latest memory percentages: approximately 25.71-26.95 percent across the
  fleet;
- SNMP traps in 24 hours: `166` (`ceosTestNotification=18`, `linkDown=2`,
  `linkUp=2`, `other=144`);
- critical syslog messages in 24 hours: `83`, spanning all 10 canonical
  device names.

These values are runtime evidence, not static expected values in dashboard
code. They will naturally change as telemetry and verification events arrive.

## Regression and preservation evidence

After dashboard provisioning:

- SNMP: 10/10 devices passed agent/auth/sysName/uptime/CPU/interface/storage;
  a fresh R1 safe test notification was ingested into InfluxDB.
- Syslog: 10/10 devices passed config/critical/raw-log/storage with fresh
  markers.
- Telemetry: 10/10 passed gNMI/TLS/auth/capabilities/Subscribe, persistent
  stream/InfluxDB, NETCONF hello/capabilities, and read-only GET.
- NMAS: the existing 20/20 health gate passed after each workflow.
- Containers: 15/15 lab and 2/2 monitoring containers remained running;
  Grafana and InfluxDB were healthy.
- Routing: R3 and R4 each retained two Full OSPFv2 and two Full OSPFv3
  neighbors; R5 retained two Established IPv4 and two Established IPv6 BGP
  peers.
- Topology: the working-tree and HEAD blob hashes for
  `srlceos01.clab.yml` both remained
  `e03064e8b38760b186657e936c3842646f893541`.

No real topology interface was shut or flapped.

## Access

Grafana is intentionally published only on `127.0.0.1:3000` on NMAS. Open it
locally at `http://127.0.0.1:3000`, or use an SSH local-forward when accessing
NMAS remotely:

```bash
ssh -L 3000:127.0.0.1:3000 student@<nmas-host>
```

Then open `http://127.0.0.1:3000` in a browser. Use the protected Grafana
username/password from `monitoring/runtime/monitoring.env`; do not copy them
into screenshots, recordings, shell history, or documentation.

## Concise demo evidence checklist

1. Capture the `NMAS Network Monitoring` folder and all four dashboard names.
2. On the overview, show 10 reporting devices, freshness, CPU/memory, interface
   state, critical syslog count, and trap count with the current timestamp.
3. On streaming telemetry, select one cEOS device and R3 or R4; show the
   source label, CPU/memory, interface filters, traffic, and error/discard
   panels.
4. On SNMP, show CPU polling, IF-MIB state, trap type/source, and a stored
   linkUp/linkDown or labelled test notification.
5. On Syslog, filter one device and show volume, severity/facility, and a
   recent critical event row.
6. Capture `verify_grafana.py` and the existing monitoring regression summary;
   keep all credentials off screen.

## Limitations

- NetworkX/dynamic topology is deliberately not implemented in this phase.
- R3/R4 gNMI/NETCONF data comes from the documented read-only lab adapter,
  not native FRR services.
- Packet counters and routing/control-plane telemetry are not stored by the
  current gNMI stream set; dashboards expose only real available fields.
- SNMP polls are produced by the verification workflow rather than a
  continuous SNMP polling daemon, so the poll-freshness table can age between
  runs. gNMI remains the continuous performance source.
- No native CPU SNMP threshold trap exists in the current evidence. Dashboard
  CPU thresholds are visual thresholds, not a claim of device notification.
- The documented cEOS engineering-build syslog transport defect and its
  existing mitigation remain unchanged.
- No disruptive live-failure demonstration was performed. Existing stored
  safe test events and disposable-interface evidence back the event panels;
  current live telemetry showed zero non-UP interfaces.
