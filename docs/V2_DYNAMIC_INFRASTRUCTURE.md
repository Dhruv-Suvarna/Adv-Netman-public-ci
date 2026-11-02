# V2 Phase 8 — Dynamic infrastructure (NetBox / NSOT, topology, monitoring, Grafana)

Lifecycle facts drive three projections through the durable transactional outbox. Nothing is inferred: links come from
verified attachments / approved management paths, addresses from the admission or commissioning record, monitoring
addresses from the Phase 4 management selector.

## Flow

```
lifecycle action ──events.record()──► DeviceLifecycleEvent (hash chain)
                         └─ emit_fact() ─► outbox.record_fact() ─► 3 × LifecycleOutboxEvent (same transaction)
Phase 7 ── outbox.record_fact(device, DECOMMISSION_REQUESTED | DECOMMISSIONED | DECOMMISSION_CANCELLED | RESTORED, actor, detail)
                                                     │
nmas_infrastructure dispatch / UI POST ─► dispatcher.dispatch() ─► nsot.apply | topology.apply | monitoring.apply
                                                     └─ outbox.deliver (same txn as the projection write) | outbox.fail(code, backoff)
```

## Outbox fact contract (contract_version 2)

Topics `NSOT_DEVICE_STATE`, `TOPOLOGY_DEVICE_STATE`, `MONITORING_TARGET_STATE`; payload fields exactly
`device_id, name, platform, role, fact, lifecycle_state, admission_state, sequence, detail`. `sequence` is per-device
monotonic (max recorded + 1 under the device row lock), shared by the three events of one fact. Idempotency key =
sha256(topic | device | fact | sequence). `detail` is ≤16 keys / ≤2 KiB and is **refused** (not redacted) when
secret-shaped. `record_fact` writes no lifecycle event of its own, so the hook cannot recurse.

Automatic emission (`events.record` → `events.emit_fact` → `outbox.emit_for_event`), ADVANCED/RECORDED outcomes only:
DISCOVER→DISCOVERED, VERIFY_IDENTITY→IDENTITY_VERIFIED, BOOTSTRAP→BOOTSTRAPPED, ISOLATE / COMMISSION_ABORT /
COMMISSION_READY_WITHDRAW→ISOLATED, COMMISSION_READY→COMMISSIONING_READY, COMMISSION→COMMISSIONING_STARTED,
COMMISSION_COMPLETE→COMMISSIONED, FAIL→HEALTH_CHANGED, ATTACHMENT_APPROVE / ATTACHMENT_REVOKE / OBSERVE_ATTACHMENT→
ATTACHMENT_CHANGED, MGMT_PATH_APPROVE / MGMT_PATH_REVOKE / MGMT_{ACTIVATE,FAILOVER,FAILBACK,LOST,RECOVERED,DEACTIVATE,
RESTART_RECOVERY}→MANAGEMENT_PATH_CHANGED. Never: refusals, OUTBOX_*, DECOMMISSION*, RESTORE* (Phase 7 emits those
explicitly). Kill switch: `settings.NMAS_INFRASTRUCTURE_FACTS = False`. MAINTENANCE_ENTERED/EXITED are in the vocabulary but the
maintenance engine does not call `events.record`; it (or the integration owner) must call `record_fact` — consumers still read
the maintenance engine's live state (`MaintenanceRecord` in `IN_MAINTENANCE`) on every apply.

Retry: `fail()` stores a fixed code and `next_attempt_at`; the first retry is immediate (next batch), then 60 s × 2^(n-2),
capped at 1 h (`NMAS_OUTBOX_BACKOFF_BASE_SECONDS`, `NMAS_OUTBOX_BACKOFF_MAX_SECONDS`). `pending()` only returns due events.

## Dispatcher

Per event: lock (`select_for_update`, `skip_locked` where supported) → consumer → `deliver` in the same transaction. Any
exception rolls back the projection write; `fail` records `NSOT_UNAVAILABLE` or `<CONSUMER>_CONSUMER_ERROR` (never exception
text). Ordering: a consumer applies a fact only if `sequence > projection.last_sequence`; older facts are acknowledged as
SUPERSEDED. Admission hand-offs (sequence 0) always re-derive. Every consumer re-derives from the database, so replays and
restarts converge (`topology.rebuild()` repairs drift). `dispatch(consumer, limit=, actor=)` returns a JSON-serializable
summary `{consumer, processed, counts, results[]}`.

## State mappings

| Lifecycle | NetBox status | Topology node | Monitoring |
|---|---|---|---|
| REGISTERED, DISCOVERED | planned | PLANNED / DISCOVERED | BLOCKED (never registered) |
| BOOTSTRAPPED | staged | AUTHENTICATED | BLOCKED |
| ISOLATED, READY_FOR_COMMISSIONING | staged | ISOLATED | BLOCKED |
| COMMISSIONING (or IN_SERVICE not admitted) | staged / active | COMMISSIONED | BLOCKED |
| IN_SERVICE + ADMITTED/LEGACY_PREEXISTING | active | IN_SERVICE (MAINTENANCE while the engine says so) | ACTIVE if the selector has an ACTIVE healthy path |
| maintenance | active (NetBox 4 has no maintenance device status; `desired.maintenance=true`) | MAINTENANCE | stays ACTIVE, `maintenance` flag exported |
| DECOMMISSION_PENDING | decommissioning | IN_SERVICE (still carries traffic) | stays ACTIVE |
| DECOMMISSIONED, WITHDRAWN | offline (object kept) | DECOMMISSIONED, edges inactive | RETIRED (row + history kept) |
| FAILED | failed | UNCERTAIN | SUSPENDED if it was registered |

Monitoring generation +1 on registration, management-path / address change (history `PATH_CHANGED`, `reconnect_required`)
and restore. No usable path → SUSPENDED (`PATH_LOST`); a device with no registered paths (LEGACY) is never registered — the
inventory address is not used. Collectors: arista_ceos snmp+syslog+gnmi; ubuntu_frr snmp (NMAS snmpd), syslog, gnmi via the
read-only Linux adapter; any other platform: all disabled with `PLATFORM_COLLECTOR_UNVERIFIED`. Export:
`monitoring.export_targets()` / `write_runtime_targets()` → `monitoring/runtime/nmas-dynamic-targets.json` (git-ignored, atomic
write, credential *references* only). The dynamic collector below consumes that file.

### Dynamic, management-path-aware collector

`core/services/infrastructure/collector.py`, `manage.py nmas_infrastructure collect [--targets FILE] [--url --org --bucket]`.
It reads the exported file and re-checks every entry against the database before any connection: target still ACTIVE for the
same device record (`TARGET_NOT_ACTIVE`), same generation / path / address (`STALE_TARGET`), the one management resolver still
answering that path (`MGMT_NO_USABLE_PATH` / `STALE_TARGET`), a verified reader for the platform (cEOS only;
`PLATFORM_UNSUPPORTED`). The session is the health engine's `EosSession`: privileged EXEC, `show` commands from the fixed
allowlist (`show version | json`, `show interfaces counters | json`, `show interfaces | json`), opened through
`nsot_live.get_live_target` → `ssh_transport.connect_eos` — socket bound to the path's NMAS interface and source, host key pinned
to the path's expected key, the path's own credential, revoked / unapproved paths refused. No Docker console, no inventory
fallback. Points: `nmas_dynamic_device` (tags device, device_id, platform, management_path, path_type, collector, error — `none` when collected;
fields generation, reachable, uptime_seconds, mem_total_kb, mem_free_kb) and `nmas_dynamic_interface` (+ interface; generation,
oper_up, admin_up, in/out octets, discards, unicast packets — only counters the device reported). A refused or failed entry still
yields `reachable=0` with its `error` code. The `error` tag is on every device point so each series keeps one tag set: found
live, Grafana 11.5.2's Flux decoder panics (`arrow/array: index out of range`) when one group mixes tables with and without it;
the dashboard panel also `keep`s only the columns it plots, so older mixed data renders. A pinned-host-key refusal on a path is
`ManagedConnectionRejected("HOST_KEY_MISMATCH")` from `ssh_transport.connect_eos` (reported as `CONNECTION_FAILED`, never as a
timeout: Netmiko otherwise re-raises the Paramiko refusal as `NetmikoTimeoutException` — also found live). EOS field names are the
ones cEOS 4.36.2F returned live.

### Restored successor (Phase 7)

RESTORED is recorded on a NEW `ManagedDevice` (origin RESTORED, `predecessor` FK, same name). Projections stay 1:1 per device;
the old rows remain as history. Topology: the successor's node is the name's node in `graph()` (replaced registrations are
omitted from the active graph); a successor without its own verified attachments inherits its predecessor's verified links
(`facts.inherited_from`); inbound edges pointing at the name reactivate. Monitoring: the successor target continues the
predecessor's generation (+1, history RESTORED). NetBox: the old registration's projection becomes `superseded_by` and never
touches NetBox again; the successor's projection owns the NetBox object. Grafana: one state series per name (newest
registration), events from both histories.

## NetBox reconciliation

Desired: status (above), interfaces = local interfaces of APPROVED+VERIFIED attachments, cables only between verified
endpoints whose peer device + interface already exist in NetBox, management IP from the admission payload or the
ProvisioningRun only. Missing device → `NETBOX_DEVICE_MISSING`; missing IP → `MGMT_IP_NOT_IN_IPAM`; IP on another device →
`MGMT_IP_ASSIGNED_ELSEWHERE`; peer missing → `CABLE_PEER_*`; wrong cable → `CABLE_MISMATCH`; a cable endpoint whose NetBox
interface type cannot take a cable (NetBox's own `NONCONNECTABLE_IFACE_TYPES`: virtual, LAG, bridge, channel, wireless,
cellular) → `CABLE_ENDPOINT_NOT_CONNECTABLE` (found live: the production model declares every lab interface `virtual`; NMAS
never changes an interface type). VLANs are verify-only: the attachment's VLAN must exist (`VLAN_NOT_IN_NETBOX`) and be carried
by the peer port (untagged, or tagged for a trunk; `VLAN_PEER_INTERFACE_MISSING`, `VLAN_MISMATCH`). The management VRF comes
from the ACTIVE approved path: an existing VRF is set on the NMAS-assigned address (`set_ip_vrf`); a missing VRF
(`VRF_NOT_IN_NETBOX`) or an address in another VRF (`VRF_MISMATCH`) is a discrepancy. NMAS never creates devices, IPs, VLANs,
VRFs or allocations. Writes only when `NMAS_NSOT_RECONCILE_WRITE=True` (default False → PLANNED with the operations stored).
The client is injectable (`lookup`/`apply`); production uses `nsot.PynetboxClient` over `nsot_netbox._client()`.

## Topology

PRODUCTION edges only from APPROVED + VERIFIED production attachments; MANAGEMENT edges from APPROVED management paths (peer
= adjacent switch, or `nmas:<attachment>` for routed paths). Adjacent addressing never creates an edge. `graph()` →
`networkx.MultiGraph`, node id = device id, unmanaged peers `unmanaged:<name>` (state UNMANAGED). A live managed device
referenced as a peer gets its node when the edge is reconciled, even if it emitted no fact since Phase 8 (found live: an adopted
`mgmt_swt` otherwise showed UNMANAGED until a rebuild), so the incremental graph equals `rebuild()` and a full replay of the
delivered facts changes nothing (`test_topology_reconstruction`, live in `netbox-reconcile.json`).
`downstream_dependents(name)` (used by Phase 7) returns live devices depending on `name` through active PRODUCTION edges,
VERIFIED approved production attachments (so it is correct even before the dispatcher runs) or ACTIVE
CommissioningDependency, recursively, each with `name, device_id, lifecycle_state, admission_state, via, parent`.

## Grafana

`grafana.lifecycle_points()` → measurement `nmas_device_lifecycle` (tags device, device_id, platform, lifecycle_state,
monitoring_state, management_path, maintenance; fields generation, admitted, monitored) and `nmas_device_lifecycle_event`
(tags device, device_id, event; field generation), for **registered** targets only (an expected-only registration yields no
point). `grafana.push()` posts to InfluxDB v2 `/api/v2/write`; token from the argument or `NMAS_INFLUX_TOKEN` / `INFLUXDB_TOKEN`,
never stored; failures are fixed codes. Dashboard: provisioned at
`monitoring/grafana/provisioning/dashboards/json/device-lifecycle.json` (uid `nmas-device-lifecycle`, not editable, `$device`
from the data), pinned in `modules/grafana.EXPECTED` (partition `LIFECYCLE`), so `validate_source` / `verify` drift controls
cover it. Panels: lifecycle / monitoring state, management path, generation, decommission / restore events, and
"Dynamic collection by management path" (`nmas_dynamic_device.reachable` per device and path). Every query must read one of
`grafana.DASHBOARD_MEASUREMENTS` on the provisioned datasource.

## UI / command

`core/infrastructure_views.py` + routes in `core/urls.py` (overview, JSON, POST dispatch — CSRF, APPROVE, audited as
`INFRASTRUCTURE_RECONCILED`). `manage.py nmas_infrastructure dispatch|status|export-targets|push-grafana|collect`.

## What is proven

Contract level (unit tests, in-memory `FakeNetbox`, Phase 4 selector state written through its own helpers): facts, ordering,
idempotency, backoff, NetBox planning / write / unavailable, topology provenance and replay, monitoring failover / retire /
restore, the collector's refusals, Grafana points and the dashboard contract, UI RBAC / CSRF / audit.

Live, this release (`docs/evidence/v2-phase8-closure/`):

| Evidence | Environment | What it shows |
|---|---|---|
| `netbox-reconcile.json` | disposable NetBox v4.7 (`labs/managed-scope-isolated/netbox.sh`, 127.0.0.1:18069, seeded with the production model); NMAS on the Django test database | write disabled → PLANNED only; status written; `CABLE_ENDPOINT_NOT_CONNECTABLE` on the model's `virtual` interface, then a real cable once the operator made the port physical (IN_SYNC); replay creates nothing (1 cable); `VLAN_MISMATCH` on VLAN drift; admission sets the management address's VRF `MGMT`; `MGMT_IP_ASSIGNED_ELSEWHERE` (held by R2); maintenance status; NetBox paused → `NSOT_UNAVAILABLE` with backoff, then IN_SYNC after restart; decommissioned → `offline`; restored successor → `active`, the old registration `superseded_by` the successor and inert. NetworkX: the incremental graph equals `rebuild()` (same nodes / edges / states). |
| `dynamic-telemetry.json` | `labs/mgmt-multihoming-isolated` (cEOS 4.36.2F DUT1, management switches, NMAS namespace) + disposable InfluxDB 2.7.11 / Grafana 11.5.2 in the NMAS namespace (`tsdb.sh`, loopback only) | lifecycle → MonitoringTarget → exported file → collector → InfluxDB → Grafana. Collected over OOB (generation 1); the pre-failover file is refused `STALE_TARGET`; failover via SW1 (gen 2) and to the routed management VRF (gen 3); failback to OOB (gen 4) — every collection on the selected path's bound interface and source; wrong pinned host key → `CONNECTION_FAILED` (refused before authentication: `test_wrong_host_key_is_refused_before_authentication`), restored key → collected; active path revoked → the collector refuses `MGMT_NO_USABLE_PATH` before the consumer, the export becomes empty, the target SUSPENDED. Grafana loaded the repository dashboard as provisioned (not editable, the contract's six panels), and its own panel query returned one series per management path (MPATH-000001/2/3). |

Earlier: `docs/evidence/v2-phase7-9/phase8/grafana-lifecycle-live.json` (lifecycle points through Grafana `/api/ds/query`).

Not performed: any write to production NetBox, production InfluxDB / Grafana, or a production device. Production provisioning of
the dashboard happens only when the release is deployed (the file is in the provisioned dashboards directory and pinned by the
drift controls).
