# gNMI Telemetry Stream Inventory

Source of truth for the actual configuration:
`monitoring/config/gnmi_paths.yml`. This document explains and cross-checks
it against the live discovery evidence; if the two ever disagree, the YAML
file is authoritative for the collector's runtime behavior.

Every path below was first verified with a live `pygnmi` `Get()`/`Subscribe()`
call against R1 (4.36.2F) before being added to the collector, then verified
again against both R3/R4 adapters -- none were taken from vendor
documentation alone. See
`docs/STREAMING_TELEMETRY_IMPLEMENTATION.md` "OpenConfig path discovery" for
the raw discovery transcript.

Device coverage for every stream below: R1, R2, R5, S1, S2, S3, S4,
`mgmt_swt` (native cEOS 4.36.2F) and R3/R4 (Ubuntu/FRR, repository-owned
read-only lab adapter). The latter is not native FRR gNMI support; its values
come from live `/proc` and `/sys/class/net` state at sample time.

Subscription mode: **STREAM + SAMPLE**, `sample_interval_ns = 20000000000`
(20 seconds) for every path -- a single subscribe request per device covers
all six paths below. ON_CHANGE was evaluated (accepted by the RPC, returns
an initial sync value, no error) but not adopted for production streams
because verifying real change-triggered delivery would require flapping a
real topology interface, which AGENTS.md prohibits.

## Streams

| # | gNMI path | OpenConfig/YANG model | Field(s) written | Tags | Meaning |
|---|---|---|---|---|---|
| 1 | `/system/state/hostname` | `openconfig-system.yang` | `hostname` (string) | `category=system_identity` | Device identity, cross-checked against inventory by the collector's own verification step. |
| 2 | `/system/cpus/cpu[index=*]/state/total/instant` | `openconfig-system.yang` | `cpu_total_pct` (int, 0-100) | `category=system_cpu`, `cpu_index` | Instantaneous total CPU utilization percentage, per reported CPU index. |
| 3 | `/system/memory/state` | `openconfig-system.yang` | `mem_physical_bytes`, `mem_used_bytes`, `mem_free_bytes`, `mem_reserved_bytes` (int, bytes) | `category=system_memory` | System memory accounting; one row per sample covers all four counters (container-valued gNMI update). |
| 4 | `/interfaces/interface[name=*]/state/oper-status` | `openconfig-interfaces.yang` | `oper_status` (string: UP/DOWN/...) | `category=interface_state`, `interface` | Per-interface operational state, every interface on the device. |
| 5 | `/interfaces/interface[name=*]/state/admin-status` | `openconfig-interfaces.yang` | `admin_status` (string: UP/DOWN/TESTING) | `category=interface_state`, `interface` | Per-interface administrative state. |
| 6 | `/interfaces/interface[name=*]/state/counters` | `openconfig-interfaces.yang` | `in_octets`, `out_octets`, `in_errors`, `out_errors`, `in_discards`, `out_discards` (int) | `category=interface_counters`, `interface` | Per-interface byte/error/discard counters; one row per interface per sample covers all six counters. |

Storage measurement for all six: `gnmi_telemetry`, in the existing
`network-monitoring` InfluxDB bucket (30-day retention, unchanged).

## Field-mapping notes (why the collector renames some device keys)

The raw gNMI JSON keys are namespaced (e.g.
`openconfig-interfaces:in-octets`) and, for the CPU path, the raw leaf name
is generic (`instant`). `monitoring/scripts/gnmi_collector.py`'s `classify()`
function strips the `module:` prefix and renames leaves to the
self-describing field names in the table above (`instant` ->
`cpu_total_pct` only under the `system_cpu` category) so a Grafana query
never has to know the raw OpenConfig key names. Any raw cEOS sub-field not listed
above (e.g. `in-unicast-pkts`, `carrier-transitions`) is present on the wire
but intentionally not stored, keeping the schema to the fields this lab
actually needs per `LAB_REQUIREMENTS.md` Phase 3 guidance ("select a
minimal useful stream set").

## Limitations (see `monitoring/config/gnmi_paths.yml` for the canonical list)

- R3/R4 have no native gNMI server. The lab adapter implements only the six
  paths above, Capabilities/Get/STREAM+SAMPLE, TLS, and password authentication;
  Set and ON_CHANGE are deliberately unsupported.
- Routing/control-plane OpenConfig state (BGP/OSPF neighbor tables via
  `openconfig-network-instance`, confirmed present in `Capabilities()`) was
  not added to keep the initial stream set small and stable; adding it is a
  config-only change (see implementation doc TODO #3).
- ON_CHANGE mode is not used for any path (see above).

## Live proof this inventory is what's actually running

```
$ cat /etc/nmas-gnmi/paths.json | python3 -m json.tool | grep '"path"'
    "path": "/system/state/hostname",
    "path": "/system/cpus/cpu[index=*]/state/total/instant",
    "path": "/system/memory/state",
    "path": "/interfaces/interface[name=*]/state/oper-status",
    "path": "/interfaces/interface[name=*]/state/admin-status",
    "path": "/interfaces/interface[name=*]/state/counters"
```
This is the exact file `provision_gnmi_collector.py` wrote to the running
collector from `monitoring/config/gnmi_paths.yml` -- not a separate,
possibly-drifted copy.

The companion `/etc/nmas-gnmi/devices.json` was verified to contain exactly
10 targets. A five-minute InfluxDB query after convergence returned all five
categories for both adapters:

```
R3: identity=4 cpu=4 memory=16 interface_state=80 interface_counters=240
R4: identity=4 cpu=4 memory=16 interface_state=80 interface_counters=240
```

## Query examples (real data, this session)

```flux
// A single device's most recent points across all six streams
from(bucket: "network-monitoring")
  |> range(start: -5m)
  |> filter(fn: (r) => r._measurement == "gnmi_telemetry" and r.device == "R1")

// CPU utilization trend for one device
from(bucket: "network-monitoring")
  |> range(start: -1h)
  |> filter(fn: (r) => r._measurement == "gnmi_telemetry"
                    and r.category == "system_cpu" and r.device == "R1")

// Interface error counters across the fleet, for future Grafana alerting
from(bucket: "network-monitoring")
  |> range(start: -1h)
  |> filter(fn: (r) => r._measurement == "gnmi_telemetry"
                    and r.category == "interface_counters"
                    and (r._field == "in_errors" or r._field == "out_errors"))
  |> filter(fn: (r) => r._value > 0)
```
