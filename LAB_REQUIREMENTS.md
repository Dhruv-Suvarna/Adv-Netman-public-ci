# Labs 2 and 3 Assessment

Status: this file preserves the original reconnaissance baseline. Current
implementation status is maintained in `GAP_ANALYSIS.md`; SNMP, Syslog,
all-10-device telemetry collection, Grafana dashboards, and the dynamic
NetworkX topology are now implemented. R3/R4 still have no
native gNMI/NETCONF support and use the explicitly labelled read-only lab
adapter documented in `docs/STREAMING_TELEMETRY_IMPLEMENTATION.md`.

## Approved Baseline

The currently running Lab 1 Containerlab deployment is the approved and frozen baseline for Labs 2 and 3. Labs 2 and 3 will be implemented additively on top of the running environment.

- The live deployment is the operational topology source of truth.
- `/home/student/Scripts/clab_dualstack_lab` is the Git-controlled source repository for new Labs 2 and 3 artifacts.
- `/home/student/clab-quickstart` remains the operational Containerlab deployment/runtime directory.
- Do not restore Nokia SR Linux, replace R3/R4 or S3/S4, change device images or node kinds, alter links/interface assignments, change addressing, redesign routing, or redeploy the topology.
- Existing forwarding, VLAN, routing, NAT, DHCP, management, and host behavior must remain unchanged. Monitoring-specific configuration is allowed only after the relevant implementation phase is approved.
- H1-to-WebServer connectivity is a pre-existing Lab 1 issue. It must not be repaired as part of monitoring work unless explicitly requested or unless it directly blocks a mandatory Labs 2/3 verification; report `BLOCKED BY PRE-EXISTING H1 -> WEB SERVER CONNECTIVITY ISSUE` in that case.

## 1. Current topology

The active Containerlab topology is `srlceos01`, defined in `srlceos01.clab.yml`. It has 15 running containers and a host-side management link named `nmas-mgmt`.

Data-plane relationships:

- R3--S3 and R4--S4.
- S3--S4.
- S3--R1 and S4--R2.
- R3--R5 and R4--R5.
- R5--WebServer.
- R1--S1 and R2--S2.
- S1--S2.
- S1--H1/H2 and S2--H3/H4.
- `mgmt_swt` has dedicated management links to R1, R2, R3, R4, S1, S2, S3, and S4.
- `mgmt_swt:eth9` is connected to the NMAS host interface `nmas-mgmt`.
- R5 and WebServer are not connected to the dedicated physical management LAN, but they are reachable on the Containerlab management network.

Containerlab management network observed from `topology-data.json`:

- IPv4: `172.20.20.0/24`, gateway `172.20.20.1`.
- IPv6: `3fff:172:20:20::/64`, gateway `3fff:172:20:20::1`.
- Bridge: `br-2c83d7955d69`.

NMAS observed management addresses:

- `nmas-mgmt`: `192.168.200.100/24`.
- `nmas-mgmt`: `2001:db8:200::100/64`.

All `172.20.20.2` through `172.20.20.16` management addresses responded to one-packet ICMP probes during reconnaissance.

## 2. Device and platform matrix

The live environment, not the stale generated SR Linux files, is the source of truth for this assessment.

| Nodes | Live image/OS | Live version evidence | Current monitoring relevance |
|---|---|---|---|
| R1, R2, R5, S1, S2, S3, S4, `mgmt_swt` | Arista cEOS | Arista cEOSLab `4.36.2F-49692632.4362F.1`, engineering build | cEOS SNMP, syslog, gNMI, NETCONF, HTTPS APIs |
| R3, R4 | Ubuntu Linux | Ubuntu `24.04.4 LTS`; FRRouting `8.4.4` | Linux/FRR has no active SNMP, gNMI, or NETCONF listener |
| H1-H4, WebServer | Ubuntu Linux | Ubuntu `24.04` image; not network infrastructure | Normally monitored as hosts only if required by the lab scope |
| Historical SR Linux entries in AGENTS.md | Nokia SR Linux | Not part of the approved live baseline | Not applicable to Labs 2/3; must not be treated as live evidence or restored |

Historical discrepancy: `AGENTS.md`, old SR Linux `config.json` files, and parts of the external lab history describe R3/R4/S3/S4 as Nokia SR Linux. The approved live baseline intentionally uses R3/R4 as Ubuntu/FRR and S3/S4 as cEOS. The historical SR Linux artifacts are informational only and must not drive Labs 2/3 implementation.

## 3. Management address matrix

| Node | Live kind | IPv4 management | IPv6 management | Collection path proposed |
|---|---|---:|---|---|
| H1 | Linux | 172.20.20.2 | 3fff:172:20:20::2 | Containerlab management, host metrics optional |
| H2 | Linux | 172.20.20.8 | 3fff:172:20:20::8 | Containerlab management, host metrics optional |
| H3 | Linux | 172.20.20.10 | 3fff:172:20:20::a | Containerlab management, host metrics optional |
| H4 | Linux | 172.20.20.14 | 3fff:172:20:20::e | Containerlab management, host metrics optional |
| R1 | cEOS | 172.20.20.12 | 3fff:172:20:20::c | Dedicated management path and/or Containerlab management |
| R2 | cEOS | 172.20.20.5 | 3fff:172:20:20::5 | Dedicated management path and/or Containerlab management |
| R3 | Ubuntu/FRR | 172.20.20.6 | 3fff:172:20:20::6 | Dedicated management path and Containerlab management |
| R4 | Ubuntu/FRR | 172.20.20.15 | 3fff:172:20:20::f | Dedicated management path and Containerlab management |
| R5 | cEOS | 172.20.20.16 | 3fff:172:20:20::10 | Containerlab management; no dedicated management link |
| S1 | cEOS | 172.20.20.13 | 3fff:172:20:20::d | Dedicated management path and/or Containerlab management |
| S2 | cEOS | 172.20.20.7 | 3fff:172:20:20::7 | Dedicated management path and/or Containerlab management |
| S3 | cEOS | 172.20.20.4 | 3fff:172:20:20::4 | Dedicated management path and/or Containerlab management |
| S4 | cEOS | 172.20.20.9 | 3fff:172:20:20::9 | Dedicated management path and/or Containerlab management |
| WebServer | Linux | 172.20.20.11 | 3fff:172:20:20::b | Containerlab management; no dedicated management link |
| `mgmt_swt` | cEOS | 172.20.20.3 | 3fff:172:20:20::3 | Dedicated management path and/or Containerlab management |

The preferred collection path for infrastructure devices is the dedicated management network where available. The Containerlab management network is the current bootstrap/reachability path and is required for R5 and WebServer unless the topology is explicitly changed.

## 4. SNMP capability and OIDs

### Live cEOS

Observed on R1 and consistently present in the cEOS startup configuration for the other cEOS nodes:

- SNMP agent code and Arista SNMP plugins exist in the image.
- `show snmp` reports the agent enabled in the default VRF but disabled because no communities or users are configured.
- No SNMP listener was observed on UDP 161.
- No trap receiver is currently configured.

The initial polling set should use standard MIB-2 and HOST-RESOURCES-MIB objects, with interface indexes discovered per device rather than hardcoded:

| Purpose | OID |
|---|---|
| System uptime | `1.3.6.1.2.1.1.3.0` (`sysUpTime.0`) |
| Interface admin state | `1.3.6.1.2.1.2.2.1.7.<ifIndex>` |
| Interface operational state | `1.3.6.1.2.1.2.2.1.8.<ifIndex>` |
| Interface input octets | `1.3.6.1.2.1.2.2.1.10.<ifIndex>`; prefer HC counters when available |
| Interface output octets | `1.3.6.1.2.1.2.2.1.16.<ifIndex>`; prefer HC counters when available |
| High-capacity input octets | `1.3.6.1.2.1.31.1.1.1.6.<ifIndex>` |
| High-capacity output octets | `1.3.6.1.2.1.31.1.1.1.10.<ifIndex>` |
| Input errors | `1.3.6.1.2.1.2.2.1.14.<ifIndex>` |
| Output errors | `1.3.6.1.2.1.2.2.1.20.<ifIndex>` |
| Processor load | `1.3.6.1.2.1.25.3.3.1.2.<hrProcessorIndex>` (`hrProcessorLoad`) |

The standard processor OID is the evidence-based first choice for both cEOS and Linux, but the returned indexes and support must be verified with `snmpwalk` after an approved SNMP configuration. An Arista enterprise CPU OID must not be guessed; it should be selected from the cEOS-supported MIB or a successful numeric walk if the standard table does not return data.

### Linux/FRR

R3 and R4 have FRR compiled with SNMP support, but that is not an SNMP agent. No `snmpd`, UDP 161, UDP 162, gNMI, or NETCONF service was observed. Linux SNMP polling therefore requires an approved host `snmpd` installation/configuration, or an explicitly approved alternative collector. CPU monitoring can then use `HOST-RESOURCES-MIB::hrProcessorLoad` and Linux host metrics. FRR protocol state should be collected separately through `vtysh`, FRR APIs, or an approved exporter.

### SR Linux historical artifacts

No SR Linux node is part of the approved live Lab 1 baseline. Stale generated SR Linux artifacts contain `snmp_server`, `netconf_mgr`, gNMI features, SNMP trap features, and an SNMP configuration section, but these files are historical and not implementation targets for Labs 2/3. SR Linux is not required to satisfy the approved live baseline.

### Notifications

Link-state notifications should use `IF-MIB` linkUp/linkDown notifications and be verified with a controlled interface shutdown only after approval. CPU is normally a polled measurement, not an automatic SNMP notification. A legitimate CPU-notification deliverable therefore requires one of:

1. A platform-supported CPU threshold/event trap, verified in the platform CLI/MIB and tested; or
2. NMAS-side threshold alerting generated from repeated CPU polls, stored as an event and clearly labelled as collector-generated rather than a device SNMP trap.

The implementation must not claim that a CPU trap exists unless the live platform exposes and emits it.

## 5. Syslog capability

cEOS reports syslog logging enabled locally, but its `show logging` output has no active external configuration and no remote destination. The image supports syslog configuration and severity/facility filtering. The implementation must configure an approved NMAS destination and critical-event filter, then verify receipt with a controlled test event.

NMAS has `rsyslog` `8.2312.0-3ubuntu9.3` active. Its UDP and TCP 514 input modules are currently commented out, so it is not currently acting as a network syslog receiver. Existing local logs are rotated weekly with four retained rotations for the default rsyslog rule; the monitoring design needs an explicit retention policy for remote network events and automatic deletion/rotation.

Linux R3/R4 have `/etc/rsyslog.d` but no observed remote-monitoring service or configured network receiver. Linux host syslog forwarding is optional unless the lab scope includes host events.

## 6. gRPC, gNMI, OpenConfig, and NETCONF

### Live cEOS

R1 was queried directly and showed:

- gNMI enabled and running on TCP 6030 in the default VRF.
- gNMI SSL profile: none.
- gNMI authorization required: no.
- NETCONF enabled and running on TCP 830 in the default VRF.
- HTTPS management API enabled on TCP 443.
- OpenConfig/provider models are present; current model availability and supported paths must be enumerated through the live API before selecting telemetry paths.

The same `management api gnmi` and `management api netconf` configuration is present in the cEOS startup configurations. These services are currently exposed without the desired TLS/authentication posture, so security hardening is a prerequisite before production-like collection.

Proposed cEOS data: interface operational/admin state, counters, errors, transceiver/environment state where exposed, system CPU/memory, routing protocol neighbor/session state, route summaries, and interface/link events. Exact paths must be validated against cEOS 4.36.2F OpenConfig support and recorded in the implementation.

### Live Linux/FRR

No gNMI or NETCONF server was observed on R3/R4. FRR provides operational CLI and routing daemons, but that does not satisfy a gNMI/NETCONF streaming endpoint. Use an approved FRR exporter/collector or SSH/CLI polling for Linux/FRR state, and document it as a different mechanism.

### SR Linux historical artifacts

SR Linux generated artifacts advertise gNMI services, OpenConfig, NETCONF, SNMP, and telemetry features, but SR Linux is not part of the approved live baseline. These artifacts are informational only and no SR Linux deployment or restoration is required.

## 7. Current NMAS services and storage

Observed NMAS state:

- `rsyslog` is active.
- SNMP libraries are installed, but `snmpget`, `snmpwalk`, `snmpd`, `snmptrapd`, and `snmptranslate` executables are not installed.
- No Telegraf, InfluxDB, Grafana, Prometheus, Loki, Vector, Elasticsearch, or comparable monitoring service/package was found.
- No monitoring Docker container is running.
- Existing listening services include SSH, DNS, DHCP, mDNS, local development listeners, and port 8080; the required monitoring ports are not currently listening.
- No existing monitoring database path was found in the checked standard locations.

## 8. Proposed collection and centralized storage

The preferred architecture is an NMAS-hosted, centralized stack, subject to approval and package availability:

- Telegraf for scheduled SNMP polling, gNMI subscriptions where its plugin supports the selected paths, and syslog/trap ingestion.
- A small dedicated trap receiver such as `snmptrapd` if Telegraf's trap input is insufficient.
- A small NETCONF collector using the chosen Python NETCONF library where a direct Telegraf input is unavailable. It must store normalized observations in the same backend.
- InfluxDB as the centralized time-series/event backend, with measurements for `snmp_poll`, `snmp_trap`, `gnmi`, `netconf`, and `syslog`.
- Retention policies or bucket retention to enforce the required data lifetime.
- Device identity, platform, management path, interface index, severity, event type, and raw/normalized payload fields must be retained so demonstrations can retrieve the original evidence.

This is a proposal only. No packages or services have been installed.

## 9. Proposed visualization

Use Grafana against the centralized backend, not independent data sources. Initial dashboards should include:

- Device availability and management reachability.
- CPU, memory, interface state, utilization, errors, and packet counters.
- gNMI/NETCONF subscription health and last-update age.
- SNMP polling success/failure and trap counts.
- Syslog severity timeline and critical-event table.
- Link-down events with device/interface identity.

A demonstration must correlate a controlled failure with an interface-state change, SNMP notification or collector alert, syslog event, stored record, and dashboard update. The dashboard must distinguish device-generated traps from collector-generated threshold alerts.

## 10. Dynamic topology visualization

**Implemented and verified.** `modules/topology_graph.py` constructs the
authoritative NetworkX graph from active `topology-data.json`, reconciled with
read-only `containerlab inspect`, and overlays real InfluxDB telemetry/events.
The localhost-only service exposes interactive HTML, `/api/topology`, and
`/healthz` on TCP 8050. It automatically refreshes every 20 seconds, includes
timestamps/freshness and deterministic layout, and uses explicit unknown state
when evidence is unavailable. See `docs/DYNAMIC_TOPOLOGY.md`.

The result contains the active 15 Containerlab nodes and 23 inter-node links;
the host-side `nmas-mgmt` attachment is recorded as excluded rather than
misrepresented as a Containerlab node. It does not rewrite the tracked or
runtime topology.

## 11. Required ports and protocols

Current/proposed paths:

| Port/protocol | Direction | Purpose | Current state |
|---|---|---|---|
| UDP 161 | NMAS -> devices | SNMP polling | cEOS agent disabled; Linux absent |
| UDP 162 | devices -> NMAS | SNMP traps | no receiver currently |
| UDP/TCP 514 | devices -> NMAS | Syslog | NMAS input commented out |
| TCP 6030 | NMAS <-> cEOS | gNMI | cEOS enabled, SSL none |
| TCP 830 | NMAS <-> cEOS | NETCONF | cEOS enabled |
| TCP 443 | NMAS -> cEOS | HTTPS/OpenConfig/API support | cEOS enabled |
| TCP 22 | NMAS -> Linux/devices | SSH bootstrap/CLI fallback | active/reachable |
| TCP 8086 | local clients -> InfluxDB | Proposed storage API | not installed/listening |
| TCP 3000 | local clients -> Grafana | Proposed dashboard | not installed/listening |
| TCP 8050 | local browser/API -> NetworkX service | Dynamic topology HTML/JSON/health | implemented; bound only to `127.0.0.1` |

All proposed ports must be restricted to the management path and reviewed against host/container firewall state before activation.

## 12. Security and credentials

- Do not hardcode credentials in collectors, dashboards, templates, or scripts.
- Existing inventories and legacy scripts contain placeholder/default credentials; they must not be copied into the monitoring implementation.
- Prefer SNMPv3 `authPriv`; use SNMPv2c only if a lab limitation requires it and document the limitation.
- Use TLS and authentication for gNMI and NETCONF where supported. Current cEOS gNMI has no SSL profile and no authorization requirement, which is not an acceptable final security posture.
- Store secrets in environment-protected files, a secret manager, or the approved VM credential mechanism.
- Restrict collectors and databases to NMAS management interfaces, use least privilege, and avoid exposing Grafana/InfluxDB beyond the lab management network.

## 13. Known limitations and blockers

- The approved live topology intentionally uses S3/S4 as cEOS and R3/R4 as Ubuntu/FRR; the older SR Linux matrix is not applicable to this implementation.
- cEOS SNMP is present but disabled; cEOS remote syslog is not configured.
- Linux/FRR has no SNMP/gNMI/NETCONF server installed or running.
- NMAS has rsyslog but no network input enabled and no monitoring database/visualization stack.
- CPU SNMP notifications are not established as a device capability; collector-side threshold events may be required.
- Standard CPU and interface OIDs are proposed, but returned indexes and vendor-specific CPU tables require live SNMP walks after approved enablement.
- H1-to-WebServer connectivity is a pre-existing Lab 1 issue and is outside scope unless it directly blocks a mandatory monitoring verification.
- No configuration changes, installations, deployments, or failure tests can be performed until approval is given.

## 14. Verification requirements

The implementation must not be considered complete until it demonstrates, with stored evidence:

1. SNMP polling from NMAS for every applicable device/platform.
2. CPU values retrieved using verified OIDs.
3. Interface state and counters retrieved using verified indexes.
4. Link-down notification receipt and storage.
5. CPU threshold behavior, clearly identified as a device trap or collector-generated alert.
6. Critical syslog receipt, rotation, retention, and retrieval.
7. gNMI telemetry received, timestamped, stored, and retrievable.
8. NETCONF-derived data received where supported, stored, and retrievable.
9. Grafana dashboards representing the stored data accurately.
10. A controlled failure appearing in the dashboard and dynamic topology in real time. The dynamic topology's clearly labelled, opt-in in-memory demo is implemented; a real topology-link failure remains unperformed because disruptive link tests are prohibited without separate approval.
11. Unsupported platform features documented with CLI/software evidence rather than simulated results.
