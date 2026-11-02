# Labs 2 and 3 Implementation Plan

Status: dashboard Phase 6 and dynamic-topology Phase 7 are implemented and
verified.
**The device-side SNMP phase (Phase 2's SNMP scope and Phase 3's `snmpd`
scope), the syslog phase (Phase 2's syslog scope and Phase 3's syslog
scope), and the all-10-device gNMI/NETCONF telemetry phase (Phase 5) are
implemented and verified**, and dashboard Phase 6 is now complete — see
`docs/SNMP_IMPLEMENTATION.md`,
`docs/SNMP_OIDS.md`, `docs/SYSLOG_IMPLEMENTATION.md`,
`docs/STREAMING_TELEMETRY_IMPLEMENTATION.md`, `docs/TELEMETRY_STREAMS.md`,
`docs/GRAFANA_DASHBOARDS.md`, and `docs/DYNAMIC_TOPOLOGY.md`
for evidence, and the updated rows in `GAP_ANALYSIS.md`. Ubuntu/FRR R3/R4
still have no native implementation; they now use an explicitly labelled,
repository-owned read-only lab adapter (see Phase 5 below). No packages,
services, devices, containers, routing, addressing, or
firewall configuration outside that additive
SNMP/syslog/telemetry/dashboard/topology work have been changed.

## Guardrails

## Approved Baseline

The currently running Lab 1 Containerlab deployment is approved and frozen for Labs 2 and 3. All implementation phases below are additive monitoring work on that live deployment.

- Operational topology source of truth: the live running deployment under `/home/student/clab-quickstart`.
- Git source of truth for all new Labs 2/3 artifacts: `/home/student/Scripts/clab_dualstack_lab`.
- Approved cEOS path: R1, R2, R5, S1, S2, S3, S4, and `mgmt_swt`.
- Approved Ubuntu/FRR path: R3 and R4.
- Nokia SR Linux is not part of this baseline and must not be restored, deployed, or required.
- Do not change topology links, interface assignments, addressing, VLANs, routing protocols, redistribution, NAT, DHCP, images, node kinds, or forwarding behavior.
- Monitoring-specific device configuration is allowed only when the relevant phase is explicitly approved.
- H1-to-WebServer connectivity is a pre-existing issue. Do not repair it as part of Labs 2/3 unless explicitly requested or unless it blocks a mandatory verification; then report `BLOCKED BY PRE-EXISTING H1 -> WEB SERVER CONNECTIVITY ISSUE`.

- Read and preserve `AGENTS.md`.
- Do not destroy, redeploy, or restart the Containerlab topology.
- Do not change routing or addressing unless a specific approved blocker is documented.
- Use the dedicated management network where available; use the Containerlab management network only where the topology requires it, especially R5 and WebServer.
- Treat R3/R4 as the approved Ubuntu/FRR implementation and S3/S4 as the approved cEOS implementation.
- Use idempotent configuration and keep monitoring changes separate from existing routing templates.
- Do not hardcode credentials or secrets.

## Phase 0: approval and baseline

1. Obtain approval for package installation, service configuration, and any controlled interface-failure test.
2. Freeze a read-only baseline containing:
   - Containerlab topology and state.
   - Node image/version matrix.
   - Management addresses and reachability.
   - Existing cEOS API state.
   - NMAS ports, firewall, rsyslog, and log-rotation state.
3. Record all baseline evidence in a timestamped lab report outside generated Containerlab state.

Gate: baseline is complete and the platform discrepancy has an explicit decision.

## Phase 1: NMAS receiver and storage foundation

Implementation status: NMAS-only foundation implemented and integrated through `master.py` into `modules/nmas.py`. Repository-owned bootstrap and convergence scripts support Ubuntu 24.04, reuse/create the Python environment, preserve healthy services, and require the 20-check health gate. `python3 master.py --nmas-only` provides the device-free validation path; two repeated runs passed against the current NMAS. The exact artifacts and validation procedure are documented in `docs/NMAS_MONITORING_INFRASTRUCTURE.md`. SNMP polling/trap ingestion, syslog ingestion, gNMI/NETCONF ingestion, Grafana dashboards, and dynamic topology are now implemented and verified. See the subsystem documents under `docs/` for current evidence.

1. Select the approved centralized backend. The recommended first implementation is InfluxDB with explicit retention and a separate logical measurement namespace for metrics and events.
2. Install only approved packages after approval.
3. Configure Telegraf or an equivalent collector as a system service using a protected configuration file.
4. Configure SNMP polling, trap ingestion, syslog ingestion, gNMI ingestion, and NETCONF-derived collection as separate inputs so failures are visible independently.
5. Configure rsyslog network reception on the management interface only, with a dedicated remote-event file and a defined rotation/retention policy.
6. Configure UDP 162 trap reception on the management interface only.
7. Create database retention and authentication settings before accepting production-like data.
8. Verify listeners, service startup, permissions, and firewall rules without exposing services outside the lab management network.

Gate: NMAS can accept test records from local tools and store/retrieve them centrally.

## Phase 2: cEOS SNMP and syslog

For R1, R2, R5, S1, S2, S3, S4, and `mgmt_swt`:

1. Configure a secure SNMP identity, preferably SNMPv3 authPriv.
2. Configure SNMP access only from the NMAS management addresses.
3. Configure link-state notifications and any platform-supported CPU threshold notifications only after confirming the exact CLI/MIB support.
4. Configure remote syslog to NMAS with a critical/error severity policy and an explicit facility.
5. Keep device configuration in the existing EOS Jinja2 template ownership model rather than adding one-off commands to orchestration code.
6. Configure gNMI/NETCONF security separately from SNMP/syslog; current cEOS gNMI has SSL disabled and authorization not required.
7. Poll and record standard OIDs, interface indexes, returned values, and any Arista enterprise CPU OID actually verified.

Verification:

- `snmpget`/`snmpwalk` returns uptime, interface state/counters, and CPU.
- A controlled approved interface shutdown produces an IF-MIB linkDown notification and a syslog event.
- A controlled CPU threshold test either produces a verified device notification or is documented as unsupported and replaced by a collector-side alert.
- A critical cEOS event is received by NMAS, stored, and retrievable.

Gate: every live cEOS node has stored SNMP/syslog evidence and no unsupported feature is claimed.

**SNMP scope of this phase: complete and verified.** Items 1, 2, 3 (link-state
notifications only — CPU threshold notifications remain unresolved, see
`GAP_ANALYSIS.md`), 5, and 7 are implemented in
`templates/monitoring/ceos_snmp.j2` and verified on all 8 cEOS devices;
gNMI/NETCONF items remain planned. cEOS notification delivery is now also
stored centrally in InfluxDB via the receiver-side trap-ingestion path (see
Phase 3's note and `docs/SNMP_IMPLEMENTATION.md`).

**Syslog scope of this phase: complete and verified.** Item 4 is implemented
in `templates/monitoring/ceos_syslog.j2` (`logging host`/`logging trap
critical`/`logging local-interface`) and verified on all 8 cEOS devices. This
specific cEOS-lab engineering build's own `rsyslog.service` cannot start
(verified: a permission-denied `improg`/`tracepointReader` crash loop, gated
by an internal Arista engineering toggle, not by this configuration), so a
repository-owned supplementary forwarder plus a direct-UDP delivery path is
also used to prove and provide critical-event delivery; see
`docs/SYSLOG_IMPLEMENTATION.md` for the full verified evidence and the
severity policy (emerg/alert/crit only).

## Phase 3: Ubuntu/FRR monitoring

For R3 and R4:

1. Host monitoring: collect Linux CPU, memory, interfaces, uptime, and syslog.
2. If approved, install/configure `snmpd` using protected credentials and management-only ACLs.
3. Use HOST-RESOURCES-MIB for CPU only after validating the returned processor indexes.
4. Collect interface counters and state with standard IF-MIB where `snmpd` exposes them.
5. Routing monitoring: collect FRR operational state, OSPF, BGP, routing tables, and protocol health using an approved exporter, FRR API, or read-only CLI collector. Document this separately from host monitoring.
6. Keep SSH/FRR configuration changes separate from telemetry installation.
7. Configure Linux syslog forwarding only if host events are in the approved monitoring scope.

Verification:

- Polling returns Linux uptime, interface state, and processor load.
- FRR state is stored and can be correlated with interface/link events.
- Unsupported gNMI/NETCONF claims are not made unless a server is actually installed and verified.

Gate: R3/R4 data collection is reproducible without changing FRR routing behavior.

**SNMP scope of this phase: complete and verified.** Items 2, 3, and 4 are
implemented via `provision_linux_snmp.py` and `templates/monitoring/snmpd.conf.j2`
(no `systemd`, host-owned process management), plus a repository-owned link
watcher for notifications in place of the Event-MIB/`mteTrigger` path that was
tried and found unworkable. Host CPU/memory/routing collection (items 1, 5, 6)
remain planned. See `docs/SNMP_IMPLEMENTATION.md`.

**Syslog scope of this phase: complete and verified.** Item 7 is implemented
via `provision_linux_syslog.py` and `templates/monitoring/linux_syslog.conf.j2`:
`rsyslog` installed and run without `systemd` (same host-owned process
management pattern as `snmpd`), forwarding critical-or-worse local syslog(3)
events to NMAS. Unlike cEOS, no platform defect was found here — this is a
genuinely working local daemon, verified with real forwarded critical test
markers. FRR's own daemon log files are intentionally not tapped (per the
guardrail against touching FRR/routing configuration); see
`docs/SYSLOG_IMPLEMENTATION.md`.

**Trap storage (receiver-side, both platforms): complete and verified.** A
`traphandle`-driven ingestion path on the NMAS receiver
(`monitoring/scripts/ingest_snmp_trap.py`) writes every authenticated
notification — cEOS and Ubuntu/FRR alike — into the existing InfluxDB bucket
as a discrete `snmp_trap` event, verified with real R3/R4 linkUp/linkDown
transitions and all 8 cEOS test notifications. This is orchestration added to
the existing receiver, not a change to R3/R4's own SNMP agent configuration.

## Phase 4: SR Linux not applicable

Nokia SR Linux is not part of the approved live Lab 1 baseline. Do not restore, deploy, or configure SR Linux for Labs 2/3. Historical SR Linux artifacts may remain documented as context, but they are not implementation targets.

## Phase 5: telemetry path validation

1. Enumerate supported cEOS OpenConfig/gNMI paths from the live 4.36.2F image.
2. Select a minimal useful stream set:
   - Interface admin/oper state.
   - Interface octets, packets, errors, and discards.
   - System CPU/memory where supported.
   - Environment/transceiver state where supported.
   - Routing neighbor/session state.
3. Configure subscriptions at a conservative interval and store timestamps, device identity, path, value, and collection status.
4. Validate NETCONF using read-only filters for the same operational domains where supported.
5. Implement Ubuntu/FRR collection through the approved non-gNMI mechanism and label host monitoring and routing monitoring separately.
6. Test collector restart/reconnect behavior and stale-data detection.

Gate: telemetry updates and NETCONF-derived records are stored and retrievable by device and path.

**Complete for all 10 monitored devices.** Items 1-3:
`monitoring/config/gnmi_paths.yml` documents the
six live-discovered OpenConfig paths (interface admin/oper state, interface
octets/errors/discards, system CPU/memory, system identity) streamed via
gNMI Subscribe(STREAM, SAMPLE, 20s) from all 8 native cEOS devices and the
two R3/R4 lab adapters by `nmas-gnmi-collector.service`;
environment/transceiver and routing
neighbor/session state were confirmed present in `Capabilities()` but left
out of the initial stream set per this phase's own "minimal useful stream
set" guidance (see TODO in `docs/STREAMING_TELEMETRY_IMPLEMENTATION.md`).
Item 4: `modules/netconf.py` validates NETCONF read-only `<get>` for the
same system/interfaces domains, live, on all 10 devices, and confirms no
notification/YANG-Push support exists to validate further. Item 5:
`modules/linux_telemetry_adapter.py` plus
`monitoring/scripts/provision_linux_telemetry.py` idempotently deploy real
gNMI-over-TLS and NETCONF-over-SSH read-only services on R3/R4. Values are
read live from `/proc` and `/sys/class/net`; the implementation is labelled
as an adapter and never represented as native FRR support. Item 6: reconnect
behavior is built into the collector (per-device thread, exponential
backoff on failure) and idempotent restart/no-restart behavior was verified
across repeated `--telemetry-only` runs; the steady-state run preserved the
collector and all four Linux adapter PIDs plus certificate/deployed-file
hashes. See
`docs/STREAMING_TELEMETRY_IMPLEMENTATION.md` for full evidence.

## Phase 6: dashboards

**Complete and verified.** Four repository-owned dashboards are provisioned
under stable UIDs through `modules/grafana.py` and the file provider in
`monitoring/grafana/provisioning/dashboards/`. They cover fleet health,
streaming telemetry, SNMP, and critical syslog using 38 operational panels
and 8 variables. `monitoring/tests/verify_grafana.py` retrieved every
dashboard through the API and executed all 46 panel/variable Flux queries
through the healthy `nmas-influxdb` datasource against recent real data.
Two convergence runs preserved dashboard IDs/versions and both monitoring
container IDs/start times. See `docs/GRAFANA_DASHBOARDS.md`.

1. Install/configure Grafana only after the backend and retention policy are working.
2. Add dashboards for availability, CPU, interface health, errors, telemetry freshness, traps, and critical syslog.
3. Use dashboard variables for device, platform, interface, severity, and time range.
4. Add panels that clearly distinguish:
   - Device-generated SNMP notifications.
   - Poll-derived threshold alerts.
   - Streaming telemetry.
   - NETCONF snapshots.
   - Syslog events.
5. Demonstrate that every panel queries the centralized backend rather than local ad hoc files.

Gate: dashboard values match direct collector queries and stored records.

## Phase 7: dynamic topology

**Complete and verified.** `modules/topology.py` reconciles active
`topology-data.json` with read-only `containerlab inspect`, producing 15 nodes
and 23 inter-node links without reading relationships from the intentionally
different tracked topology. `modules/topology_graph.py` constructs the
authoritative NetworkX graph and overlays existing `gnmi_telemetry`,
`snmp_poll`, `snmp_trap`, and `syslog_event` evidence. A localhost-only
service exposes an automatically refreshing interactive SVG UI, JSON API, and
health endpoint on TCP 8050. Deterministic freshness/link precedence, explicit
UNKNOWN state, a safe labelled in-memory failure demo, two-run idempotency,
and a 19-check live acceptance matrix are documented in
`docs/DYNAMIC_TOPOLOGY.md`. No real topology interface was touched.

1. Parse `srlceos01.clab.yml` and/or `topology-data.json` into a NetworkX graph.
2. Resolve live node and link state from the central data backend.
3. Mark edges from interface operational state and events; mark nodes unknown when data is stale.
4. Expose a small read-only JSON/API or dashboard data source for visualization.
5. Refresh on a fixed interval or event trigger without changing Containerlab state.
6. Include last-update timestamps and source protocol in the view.

Gate: real state and refresh behavior are cross-checked against live evidence;
the safe labelled visualization-only failure mode is proven without changing a
real link. A real-link failure/recovery demonstration remains conditional on
separate approval and is not claimed.

## Phase 8: end-to-end verification and evidence

Capture reproducible evidence for:

1. Every applicable platform's SNMP poll and CPU OID.
2. Interface linkDown notification and storage.
3. CPU threshold behavior and its correct origin classification.
4. Critical syslog receipt, rotation, retention, and retrieval.
5. cEOS gNMI stream receipt and storage.
6. NETCONF-derived data receipt and storage where supported.
7. Linux/FRR collection and its limitations.
8. Grafana dashboard accuracy.
9. Real-time failure appearance in dashboards.
10. Dynamic topology node/link state updates.
11. Reconnect and collector restart behavior.

Do not use `containerlab destroy`, `deploy`, `redeploy`, cleanup, or destructive host commands as part of verification unless separately approved.

## Proposed final deliverables

- `LAB_REQUIREMENTS.md` with the capability matrix, current gaps, OID list, ports, security requirements, architecture, and verification criteria.
- This `IMPLEMENTATION_PLAN.md`.
- Installation/configuration documentation for cEOS and Ubuntu/FRR, including
  the native Ubuntu/FRR limitation and the adapter's supported protocol scope.
- Collector configuration with secrets externalized.
- Database retention and schema documentation.
- Grafana dashboard definitions and query evidence (**complete**; screenshots
  remain a student capture task for the final submission).
- Dynamic topology source/API and safe synthetic failure demonstration evidence (**complete**; a real-link failure remains unperformed by safety policy).
- A final platform limitations and unsupported-feature report.
