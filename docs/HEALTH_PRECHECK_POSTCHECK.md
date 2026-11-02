# Phase 15 — Health, Prechecks and the Reusable Postcheck Engine

Phase 15 adds **read-only** operational health and verification infrastructure that the later execution phases
(16/17) will call. It answers four different questions with four separate mechanisms, and it deploys nothing:

* **Fleet Quick** — is the fleet healthy *right now*, according to the telemetry we already collect?
* **Deep Health** — what does *one* device say about itself when asked (explicit, live, read-only)?
* **Precheck** — can this CURRENT validated CURRENT plan be attempted safely *now*?
* **Postcheck** — after a (future) deployment, did the intended state appear?

It consumes Phase 13 (validation) and Phase 14 (plan / Configlets) and re-implements neither. There is no new
monitoring stack, no new threshold system, no new connection library, and no device mutation of any kind.

Contents: 1 Architecture · 2 Fleet Quick · 3 Deep Health · 4 Precheck · 5 Postcheck · 6 The four compared ·
7 Telemetry sources · 8 Live read-only sources · 9 Platform capabilities · 10 Statuses · 11 Check result schema ·
12 Stable check codes · 13 Freshness · 14 CPU/memory thresholds · 15 Interface health · 16 Routing health ·
17 BGP · 18 OSPF · 19 Static routes · 20 Services · 21 DHCP health reuse · 22 ACL / NAT boundaries ·
23 Monitoring-pipeline health · 24 Affected-device scope · 25 Validation prerequisites · 26 Plan prerequisites ·
27 Configlet → requirement mapping · 28 Precheck expectations · 29 Postcheck expectations · 30 Evidence precedence ·
31 UNKNOWN semantics · 32 Blocking policy · 33 Run persistence · 34 Security · 35 Credential handling ·
36 Read-only guarantees · 37 No deployment · 38 No rollback · 39 Phase-16/17 handoff · 40 Known limitations ·
Descriptor extension · UI · Test strategy · Live verification evidence.

## 1. Health architecture

```
 existing telemetry (gNMI/SNMP/syslog -> InfluxDB) ──> topology service /api/topology ──┐
 monitoring_service (Grafana health)                                                    │  Fleet Quick
 nsot_netbox.health() (read-only source reachability)                                   ├─> health/telemetry.py ─> health/fleet.py
                                                                                        │
 explicit, bounded, read-only live queries ─> health/live.py (fixed allowlists) ────────┴─> health/device.py (Deep Health)

 Change ─> latest validation (CURRENT, PASS*) ─┐
        ─> latest plan (CURRENT, pinned)       ├─> health/prechecks.py ─> health/scope.py (plan-derived devices)
                                               │                      ─> health/evaluators.py (PRECHECK expectations)
 later phase, after a push ────────────────────┴─> health/postchecks.py ─> health/evaluators.py (POSTCHECK expectations)

 every explicit run ─> health/persistence.py ─> ONE append-only OperationalCheckRun (+ one AuditEvent)
```

Modules under `web/core/services/health/` (public API: `core/services/health_service.py`):

| Module | Job |
|---|---|
| `codes.py` | vocabularies, the stable check-code catalogue, the blocking policy table |
| `thresholds.py` | freshness / CPU / memory thresholds — read from the **existing** monitoring config |
| `results.py` | `CheckResult` (structured evidence), bounded serialization, aggregation rules |
| `evidence.py` | normalized per-device fact groups with source + timestamp; evidence precedence |
| `inventory.py` | managed devices and live targets from `inventory.yml` only |
| `telemetry.py` | Fleet-Quick adapter over the existing topology / monitoring services |
| `live.py` | Deep-Health read-only adapters: fixed per-platform allowlists + parsers |
| `fleet.py` / `device.py` | Fleet Quick / Deep Health |
| `requirements.py` / `evaluators.py` | Phase-14 descriptors → executable requirements; the reusable engine |
| `scope.py` / `prechecks.py` / `postchecks.py` | affected scope, precheck, postcheck wrapper |
| `persistence.py` | the one run model, audit, bounded sanitized report |

Public API (`health_service`): `get_fleet_health()`, `get_device_quick(device)`, `run_device_health(device, actor=)`,
`record_fleet_snapshot(actor=)`, `build_affected_scope(plan)`, `run_change_precheck(change, actor=)`,
`evaluate_plan_requirements(plan, phase, evidence)`, `run_plan_postcheck(plan, ...)`, `serialize_health_run(run)`.
Views only call this facade.

## 2. Fleet Quick

Fast, fleet-wide, **passive**. One read of the existing topology service (which already overlays InfluxDB telemetry on the
NetworkX graph), for every device in `inventory.yml` `network_devices` (R1–R5, S1–S4, `mgmt_swt`). It performs **no**
SSH, no `docker exec`, no subprocess, no InfluxDB query. Per device it reports telemetry freshness, CPU, memory, link
health (adjacent edges from the topology service), recent critical syslog / SNMP-trap counts, platform and last-evidence
time. A metric the source does not carry is `None` → *not available* in the UI, never `0`. **Routing / adjacency state is not in the stored
telemetry schema**, so Fleet Quick reports it as `NOT_AVAILABLE` rather than guessing; use Deep Health for it.
Loading `/health/` writes nothing (no run, no audit row). Recording a snapshot is a separate explicit POST.

Fleet conditions (shown *beside*, never folded into, device health): topology service reachable, monitoring backend
(InfluxDB as reported by the topology service), collector silence (no fresh device although the backend is up), NetBox
reachable (a read-only *source*, not a health engine), Grafana reachable. The fleet `overall` is derived from the devices
only, so a NetBox or Grafana outage is not reported as a network fault. If the topology service or InfluxDB is down, every
device is **UNKNOWN** — never UNHEALTHY.

## 3. Deep Health

Explicit operator action, **one managed device at a time** (`POST /health/device/<device>/deep/`, CSRF). It combines the
device's telemetry with a bounded live read-only query and applies the evidence precedence of §30. It reports:
reachability, freshness, CPU/memory, addressed-interface admin/oper state, OSPF adjacency and BGP session state, and — for the
device that hosts the secondary DHCP server (derived from `inventory.yml`, never from a name) — the DHCP service state. A
timeout or refusal never crashes: it becomes UNKNOWN `DEVICE_UNREACHABLE` with a sanitized reason code, and every other check
still runs. `GET /health/device/<device>/` shows the Quick evidence and the latest stored run; it never connects.

## 4. Precheck

`POST /device-builder/changes/<change_id>/precheck/run/` (CSRF). It asks: *can this CURRENT validated CURRENT plan be handed
to a future deployment engine right now?* It requires the latest validation CURRENT and `PASS`/`PASS_WITH_WARNINGS` and the
latest plan CURRENT and pinned to it. **It never re-runs validation and never rebuilds the plan.** If a prerequisite fails
it refuses *before any device is contacted* and records the refusal (BLOCKED / INCOMPLETE) as a run. Otherwise it evaluates only
the plan-derived affected scope (§24): reachability and telemetry of the target devices, CPU/memory, monitoring-pipeline
availability, DHCP service health when the plan touches a relay, and the plan's requirements with **PRECHECK** expectations (§28).
Result: `PASS`, `PASS_WITH_WARNINGS`, `BLOCKED`, `INCOMPLETE`.

## 5. Postcheck

The reusable engine `evaluate_plan_requirements(plan, "POSTCHECK", evidence)` (pure; no I/O) plus the wrapper
`run_plan_postcheck(plan, ...)`. It evaluates what the plan *changed*, not a generic fleet suite. Result: `PASS`,
`PASS_WITH_WARNINGS`, `FAIL`, `INCOMPLETE`. Phase 15 never deploys, so it is proven only with synthetic/fake evidence and
(for the "undeployed plan must FAIL" demonstration) real read-only live evidence of the unchanged network. There is no
postcheck button or route: a later execution phase calls it after a push.

## 6. The four compared

| | Fleet Quick | Deep Health | Precheck | Postcheck |
|---|---|---|---|---|
| Trigger | page view (GET) | explicit POST | explicit POST | called by a later phase |
| Scope | whole managed fleet | one device | plan-derived devices | plan-derived devices |
| Evidence | existing telemetry only | telemetry + live read-only | telemetry + live read-only + DHCP verifier | supplied evidence (live after a push) |
| Device access | none | yes, bounded, read-only | yes, bounded, read-only | caller-supplied / live read-only |
| Question | is anything wrong? | what is this device's state? | is it safe to attempt? | did the intended state appear? |
| Result | HEALTHY … UNKNOWN | HEALTHY … UNKNOWN | PASS … INCOMPLETE | PASS … INCOMPLETE |
| Persisted | only on explicit snapshot | yes | yes | yes (service-level) |

## 6a. IP connectivity (Phase 22)

Explicit operator action, one managed device at a time (`POST /health/device/<device>/connectivity/`, CSRF): a bounded,
read-only ping FROM the device TO an operator-selected destination. Unlike every other Deep Health group, this check takes a
parameter -- the destination -- so it is deliberately isolated in its own module (`health/connectivity.py`) rather than added
to `live.py`'s fixed, zero-argument command allowlists (`CEOS_COMMANDS`/`LINUX_COMMANDS`).

**Destination selection is closed, never free text.** `connectivity.ping_targets(device)` is the server-owned menu: NMAS
(`inventory.yml: management.nmas_ipv4/nmas_ipv6`) plus every OTHER managed device that has a recorded management address
(never the device itself; R5 is excluded because its address is Containerlab-assigned and unknown at inventory time). The
browser only ever supplies which KEY of that menu it wants; an unknown key is refused with 400 before any session opens
(`connectivity.UnknownDestinationError`). The resolved address is then re-validated by `live.validate_ping_destination`
(a strict `ipaddress.ip_address` parse) before it can reach a session -- two independent gates, not one.

**Transport reuses the existing per-platform sessions** (`live.EosSession` / `live.LinuxSession` / `live.DockerEosSession`),
each gaining one new `.ping(dest, count=3)` method: EOS builds a fixed-shape command string (`ping <validated-ip> repeat 3
timeout 1`, asserted against a regex + the shared forbidden-token list before it is ever sent); Linux/FRR appends the
validated address as one more `docker exec` argv element (`ping -4|-6 -c 3 -W 2 <address>`, `shell=False`). Because the
address is a parsed `ipaddress` object turned back into a canonical string, no shell metacharacter can ever reach either
transport regardless of what the original destination text contained.

Both platforms are Linux-based, so one parser (`live.parse_ping_output`) reads the standard iputils summary line
(`N packets transmitted, M received, L% packet loss`) and RTT line for both. Normalized fields: `destination`,
`destination_label`, `address`, `family`, `transmitted`, `received`, `loss_percent`, `rtt_min_ms`, `rtt_avg_ms`, `rtt_max_ms`.
Status: `CONNECTIVITY_REACHABLE` (PASS, 0% loss), `CONNECTIVITY_DEGRADED` (WARN, partial loss), `CONNECTIVITY_UNREACHABLE`
(FAIL, no replies), `CONNECTIVITY_CHECK_UNAVAILABLE` (UNKNOWN: unsupported platform, no address for the requested family,
or the live session itself could not be opened -- never a crash).

**Persistence reuses `OperationalCheckRun`** (mode `DEVICE_DEEP`, tagged `summary.check_type = "CONNECTIVITY"` /
`report.check_type = "CONNECTIVITY"`) -- no new model, no migration. `connectivity.latest_connectivity_run(device)` filters
the shared per-device DEVICE_DEEP history by that tag so the device page can show the latest ping result next to the latest
Deep Health result without confusing the two. `GET /health/device/<device>/` renders the destination menu and the latest
connectivity result; it never opens a session.

This check is deliberately **not** wired into the automatic precheck/postcheck policy (§28/§29): those evaluate a plan's
OWN declared requirements against a fixed, deterministic descriptor -> check-type mapping (`requirements.REQUIREMENT_MAP`),
and "ping an operator-chosen destination" has no natural place in a per-Configlet requirement descriptor. It remains
available as an explicit, operator-triggered check before and after a change, exactly like Deep Health itself.

## 7. Telemetry sources

The only telemetry source is the topology service's `GET /api/topology` (already consumed by Phase 5 through
`topology_service`): per node `last_telemetry_timestamp`, `cpu_percent`, `memory_percent`, `recent_critical_syslog_count`,
`recent_snmp_trap_count`; per edge `status` and per-endpoint fresh admin/oper state; `backend.status` for InfluxDB;
`health_thresholds_seconds`. Those come from gNMI streaming, SNMP polling/traps and syslog in InfluxDB. `health/telemetry.py`
contains no Flux, no InfluxDB client and no HTTP library (a contract test enforces it). Ages are **recomputed from the
timestamps** at evaluation time, not trusted from the payload.

## 8. Live read-only sources

`health/live.py` is the only health module that may open a session or spawn a process (contract-tested).

* **cEOS** — Netmiko SSH to the inventory management address with the inventory credentials, reusing the Phase-7
  `nsot_live.get_live_target`; privileged EXEC only (`check_enable_mode()` / `enable()`), never configuration mode. Commands
  (`CEOS_COMMANDS`): `show interfaces | json`, `show ip interface | json`, `show ipv6 interface | json`, `show ip route | json`,
  `show ipv6 route | json`, `show ip ospf neighbor | json`, `show ipv6 ospf neighbor | json`, `show ip bgp summary | json`,
  `show ipv6 bgp summary | json`, `show running-config` (parsed to a few facts; the raw text is dropped).
* **Ubuntu/FRR** — `docker exec <container> <fixed argv>` (list, `shell=False`, timeout), the credential-free read pattern
  already used by `modules/snmp.py` and `netbox/scripts/verify_dhcp_servers.py`. Commands (`LINUX_COMMANDS`): `ip -j addr show`,
  `ip -j -4 route show`, `ip -j -6 route show`, `vtysh -c "show ip ospf neighbor json"`, `vtysh -c "show ipv6 ospf6 neighbor json"`,
  `vtysh -c "show bgp summary json"`, `nft list ruleset`.
* **DHCP** — `live.dhcp_service_state()` calls the existing `verify_dhcp_servers.nmas_status()` / `r2_status()` (§21).

A session runs a command only **by allowlist key**; nothing from a browser, plan or Configlet is ever placed in a command.

## 9. Platform health capabilities

Independent of *configuration* support. Vocabulary matches the project's capability philosophy.

| Platform key | Health capability | Transport | Evidence |
|---|---|---|---|
| `ceos` (Arista cEOS) | `SUPPORTED` | Netmiko SSH | Phase-7 pattern; `master.py::verify_eos()`; live-verified |
| `linux` (Ubuntu/FRR) | `SUPPORTED` | `docker exec` | `modules/snmp.py`, `verify_dhcp_servers.py`; live-verified |
| `nokia_srlinux` | `UNSUPPORTED` | — | not in the approved live Labs 2/3 baseline |
| `cisco_c8000v_iosxe` | `NOT_IMPLEMENTED` | — | C8000V/IOS XE artifact exists, but NMAS has no live session |
| `cisco_iosxr` | `NOT_IMPLEMENTED` | — | no IOS XR runtime artifact or NMAS live session |
| `sonic` | `NOT_IMPLEMENTED` | — | no repository evidence of a session |
| anything else | `UNKNOWN` | — | never assumed supported |

An unsupported platform is **never contacted**; its live checks are NOT_APPLICABLE and telemetry alone is used.

## 10. Health statuses

* Check status: `PASS`, `WARN`, `FAIL`, `UNKNOWN`, `NOT_APPLICABLE`.
* Aggregate (Fleet / Deep): `HEALTHY`, `DEGRADED`, `UNHEALTHY`, `UNKNOWN`. Rule: any FAIL → UNHEALTHY; else any WARN → DEGRADED;
  else the *liveness* (core) checks decide — if none PASSED, UNKNOWN; else HEALTHY. A non-core UNKNOWN (for example an
  unavailable memory metric) is reported but does not downgrade. There is **no numeric health score**.
* Precheck: `PASS`, `PASS_WITH_WARNINGS`, `BLOCKED` (a blocking FAIL), `INCOMPLETE` (a blocking UNKNOWN).
* Postcheck: `PASS`, `PASS_WITH_WARNINGS`, `FAIL`, `INCOMPLETE` (any UNKNOWN, or nothing verified).

These are deliberately not the Phase-13 validation statuses and never conflated with them.

## 11. Check result schema

Every result is structured (never prose alone). Fields: `check_code`, `status`, `category`, `device`, `message`, `source`
(`LIVE`/`TELEMETRY`/`PLAN`/…), `observed`, `expected`, `timestamp` (evaluation time), `observed_at` (when the fact was
observed), `freshness` (`FRESH`/`STALE`/`EXPIRED`/`UNKNOWN`), `blocking`, `remediation`, plus `role`
(`FLEET`/`TARGET`/`PEER`/`PLAN`), `phase`, `requirement`, `cfg_id`, `subject`. Strings are clipped, lists and depth bounded, and
secret-shaped keys are **replaced** (key and value) before anything is stored.

## 12. Stable check codes

Codes are stable identifiers: a PASS uses the "EXPECTED"/"FRESH" spelling, a failure the problem spelling. `FAIL blocks` /
`UNKNOWN blocks` are the *default policy* for a TARGET device or a PLAN-level gate (§32). Generated from `health/codes.py`.

| Code | Category | FAIL blocks | UNKNOWN blocks | Liveness | Meaning |
|---|---|---|---|---|---|
| `DEVICE_TELEMETRY_FRESH` | TELEMETRY | — | — | core | Telemetry for the device is recent. |
| `DEVICE_TELEMETRY_STALE` | TELEMETRY | yes | — | core | Telemetry for the device is older than the freshness threshold. |
| `DEVICE_TELEMETRY_UNAVAILABLE` | TELEMETRY | — | yes | core | No telemetry evidence exists for the device (or the source is down). |
| `DEVICE_REACHABLE` | REACHABILITY | — | — | core | A read-only live query to the device succeeded. |
| `DEVICE_UNREACHABLE` | REACHABILITY | yes | yes | core | A read-only live query to the device did not complete. |
| `CRITICAL_EVENTS_RECENT` | TELEMETRY | — | — | — | Critical syslog events or SNMP traps were recorded recently. |
| `CPU_HIGH` | RESOURCE | yes | — | — | CPU utilisation against the project alert thresholds. |
| `MEMORY_HIGH` | RESOURCE | yes | — | — | Memory utilisation against the dashboard thresholds. |
| `INTERFACE_EXPECTED_UP` | INTERFACE | — | — | — | An interface is administratively and operationally up. |
| `INTERFACE_OPER_DOWN` | INTERFACE | yes | — | — | An interface is administratively up but operationally down. |
| `INTERFACE_ADMIN_DOWN` | INTERFACE | — | — | — | An addressed interface is administratively down. |
| `INTERFACE_EXPECTED_PRESENT` | INTERFACE | — | — | — | An expected interface exists on the device. |
| `INTERFACE_MISSING` | INTERFACE | yes | — | — | An expected interface does not exist on the device. |
| `INTERFACE_STATE_MISMATCH` | INTERFACE | yes | — | — | An interface's admin state differs from the requirement. |
| `LINK_HEALTH_DEGRADED` | INTERFACE | — | — | — | A link adjacent to the device is down or degraded. |
| `ADDRESS_EXPECTED_PRESENT` | ROUTING | — | — | — | An expected address is configured on its interface. |
| `ADDRESS_MISSING` | ROUTING | yes | — | — | An expected address is not configured on its interface. |
| `ROUTE_EXPECTED_PRESENT` | ROUTING | — | — | — | An expected route is in the routing table. |
| `ROUTE_MISSING` | ROUTING | yes | — | — | An expected route is not in the routing table. |
| `OSPF_EXPECTED_FULL` | ROUTING | — | — | — | An OSPF adjacency is FULL. |
| `OSPF_ADJACENCY_DOWN` | ROUTING | yes | — | — | An OSPF adjacency is not FULL. |
| `ISIS_EXPECTED_UP` | ROUTING | — | — | — | An IS-IS adjacency is UP. |
| `ISIS_ADJACENCY_DOWN` | ROUTING | yes | — | — | An IS-IS adjacency is not UP. |
| `ISIS_ROUTE_PRESENT` | ROUTING | — | — | — | An IS-IS route is installed with the expected paths. |
| `ISIS_ROUTE_ABSENT` | ROUTING | — | — | — | An IS-IS route that must be absent is absent. |
| `ISIS_ROUTE_MISSING` | ROUTING | yes | — | — | An expected IS-IS route is not installed. |
| `ISIS_ROUTE_PATH_MISMATCH` | ROUTING | yes | — | — | An IS-IS route is installed over different paths than expected. |
| `ISIS_ROUTE_UNEXPECTED` | ROUTING | yes | — | — | An IS-IS route that must be absent is installed. |
| `RIP_ROUTE_PRESENT` | ROUTING | — | — | — | A RIP route is installed with the expected paths. |
| `RIP_ROUTE_ABSENT` | ROUTING | — | — | — | A RIP route that must be absent is absent. |
| `RIP_ROUTE_MISSING` | ROUTING | yes | — | — | An expected RIP route is not installed. |
| `RIP_ROUTE_PATH_MISMATCH` | ROUTING | yes | — | — | A RIP route is installed over different paths than expected. |
| `RIP_ROUTE_UNEXPECTED` | ROUTING | yes | — | — | A RIP route that must be absent is installed. |
| `RIP_NEIGHBOR_PRESENT` | ROUTING | — | — | — | A RIP peer is present on the interface. |
| `RIP_NEIGHBOR_ABSENT` | ROUTING | — | — | — | No RIP peer exists on an interface where none is intended. |
| `RIP_NEIGHBOR_MISSING` | ROUTING | yes | — | — | An expected RIP peer was not observed. |
| `RIP_NEIGHBOR_UNEXPECTED` | ROUTING | yes | — | — | A RIP peer exists on an interface where none is intended. |
| `BGP_EXPECTED_ESTABLISHED` | ROUTING | — | — | — | A BGP session is Established. |
| `BGP_SESSION_DOWN` | ROUTING | yes | — | — | A BGP session is not Established. |
| `FHRP_VIP_EXPECTED_PRESENT` | SERVICE | — | — | — | A virtual router address is configured. |
| `FHRP_VIP_MISSING` | SERVICE | yes | — | — | A virtual router address is not configured. |
| `DHCP_RELAY_EXPECTED_PRESENT` | SERVICE | — | — | — | A DHCP relay destination is configured on its interface. |
| `DHCP_RELAY_MISSING` | SERVICE | yes | — | — | A DHCP relay destination is not configured on its interface. |
| `ACL_DEFINITION_EXPECTED_PRESENT` | SERVICE | — | — | — | An ACL is defined on the device. |
| `ACL_DEFINITION_MISSING` | SERVICE | yes | — | — | An ACL is not defined on the device. |
| `ACL_ATTACHMENT_EXPECTED_PRESENT` | SERVICE | — | — | — | An ACL is attached to its interface and direction. |
| `ACL_ATTACHMENT_MISSING` | SERVICE | yes | — | — | An ACL is not attached to its interface and direction. |
| `PBR_POLICY_EXPECTED_PRESENT` | SERVICE | — | — | — | A PBR policy is defined and every intended sequence is installed. |
| `PBR_POLICY_MISSING` | SERVICE | yes | — | — | A PBR policy is not defined, or an intended sequence is missing or not installed. |
| `PBR_ATTACHMENT_EXPECTED_PRESENT` | SERVICE | — | — | — | A PBR policy is applied to its ingress interface. |
| `PBR_ATTACHMENT_MISSING` | SERVICE | yes | — | — | A PBR policy is not applied (or not valid) on its ingress interface. |
| `NAT_RULE_EXPECTED_PRESENT` | SERVICE | — | — | — | A NAT rule is present on the device. |
| `NAT_RULE_MISSING` | SERVICE | yes | — | — | A NAT rule is not present on the device. |
| `CONFIG_REMOVED_CONFIRMED` | VERIFICATION | — | — | — | The configuration selected for removal is absent from the running configuration. |
| `CONFIG_STILL_PRESENT` | VERIFICATION | yes | — | — | Configuration selected for removal is still present after execution. |
| `MGMT_CONFIG_PRESENT` | VERIFICATION | — | — | — | The cEOS management VRF requirement matches sanitized configuration signatures or normalized service-enabled facts. |
| `MGMT_CONFIG_MISSING` | VERIFICATION | yes | — | — | The cEOS management VRF requirement is absent or differs in the running configuration. |
| `REMOVAL_TARGET_PRESENT` | VERIFICATION | — | — | — | The configuration selected for removal is present before execution (precheck). |
| `REMOVAL_TARGET_ALREADY_ABSENT` | VERIFICATION | — | — | — | Already absent before execution (precheck WARN); nothing is sent for it. |
| `REMOVAL_TARGET_DRIFTED` | VERIFICATION | yes | — | — | Only part of the selected configuration is present; the removal must be rebuilt. |
| `DHCP_SERVICE_UNHEALTHY` | SERVICE | yes | yes | — | The DHCP servers report an inactive service. |
| `MONITORING_PIPELINE_UNHEALTHY` | MONITORING | yes | yes | — | The monitoring backend or telemetry collection is unhealthy. |
| `TOPOLOGY_SERVICE_UNAVAILABLE` | MONITORING | — | — | — | The topology service cannot be read. |
| `NETBOX_SOURCE_UNAVAILABLE` | MONITORING | — | — | — | NetBox (a read-only source) cannot be read. |
| `GRAFANA_UNAVAILABLE` | MONITORING | — | — | — | Grafana cannot be read. |
| `TELEMETRY_COLLECTOR_SILENT` | MONITORING | — | — | — | No monitored device has fresh telemetry although the backend is reachable. |
| `PLAN_VALIDATION_CURRENT` | PLAN | — | — | — | The pinned validation is current and passing. |
| `PLAN_CURRENT` | PLAN | — | — | — | The plan is current and pinned to the current validation. |
| `PLAN_VALIDATION_STALE` | PLAN | yes | — | — | The pinned validation is no longer current. |
| `PLAN_STALE` | PLAN | yes | — | — | The plan is no longer current. |
| `PLAN_MISSING` | PLAN | yes | yes | — | No plan has been built for the Change. |
| `VALIDATION_NOT_PASSING` | PLAN | yes | yes | — | The latest validation is not PASS / PASS_WITH_WARNINGS. |
| `PLAN_HEALTH_PRECONDITION_FAILED` | PLAN | yes | — | — | One or more blocking health preconditions failed. |
| `POSTCHECK_REQUIREMENT_FAILED` | VERIFICATION | yes | — | — | One or more plan verification requirements failed. |
| `PRECHECK_DATA_UNAVAILABLE` | VERIFICATION | yes | yes | — | Evidence needed to evaluate a prerequisite is unavailable. |
| `POSTCHECK_DATA_UNAVAILABLE` | VERIFICATION | yes | yes | — | Evidence needed to evaluate a requirement is unavailable. |
| `REQUIREMENT_NOT_IMPLEMENTED` | VERIFICATION | — | — | — | No evaluator exists for this requirement; it is NOT verified. |
| `REQUIREMENT_UNKNOWN_TYPE` | VERIFICATION | — | — | — | The requirement type is not known to the health engine. |
| `REQUIREMENT_DESCRIPTOR_INCOMPLETE` | VERIFICATION | — | yes | — | The plan's requirement descriptor carries no expected facts (older plan). |
| `EVIDENCE_CONFLICT` | VERIFICATION | — | — | — | Live evidence contradicts older telemetry; the live value was used. |
| `CONNECTIVITY_REACHABLE` | CONNECTIVITY | — | — | — | A read-only ping from the device to the destination succeeded with no packet loss. |
| `CONNECTIVITY_DEGRADED` | CONNECTIVITY | — | — | — | A read-only ping from the device to the destination showed partial packet loss. |
| `CONNECTIVITY_UNREACHABLE` | CONNECTIVITY | yes | — | — | A read-only ping from the device to the destination failed (no replies). |
| `CONNECTIVITY_CHECK_UNAVAILABLE` | CONNECTIVITY | — | yes | — | The connectivity check could not be attempted. |

## 13. Freshness

`FRESH` ≤ `healthy_seconds` (60) < `STALE` ≤ `stale_seconds` (120) < `EXPIRED`; no timestamp → `UNKNOWN`. Boundaries are inclusive on
the lower class, exactly as the topology service classifies nodes (values come from `monitoring/config/topology.yml`; the running
service's own `health_thresholds_seconds` win when present). "A last value exists" is not "healthy": age is always computed.
Telemetry FRESH → PASS; STALE → WARN; EXPIRED → FAIL `DEVICE_TELEMETRY_STALE` (WARN instead when a live read proved the device
reachable). EXPIRED evidence is **never** used to PASS or FAIL a requirement (→ UNKNOWN).

## 14. CPU / memory thresholds

One threshold system, consumed not redefined: CPU warning/critical from `monitoring/config/cpu_threshold_policy.yml`
(70 / 90 %); memory 75 / 90 %, mirroring the Grafana "Memory utilization" panel (a test parses
`build_grafana_dashboards.py` and fails on drift). A metric that does not exist is UNKNOWN, never 0; a metric older than the
freshness limit is UNKNOWN. Critical values FAIL (blocking for a TARGET), warning values WARN.

## 15. Interface health

Deep Health checks **addressed** interfaces (an interface with an address is expected up): admin down → WARN
`INTERFACE_ADMIN_DOWN`; admin up / oper down → FAIL `INTERFACE_OPER_DOWN`; otherwise one PASS summary. Link health in Fleet Quick
comes from the topology service's edges (DOWN → FAIL, DEGRADED → WARN, non-blocking). For a **plan**, interface requirements are
`INTERFACE_PRESENT`, `INTERFACE_ADMIN_STATE`, `INTERFACE_OPER_STATE`, `ADDRESS_PRESENT`. Operational state depends on the far end,
so an oper-down after deployment is a **WARN**, not a FAIL (a false FAIL could drive a rollback); a definite configuration
deviation (interface missing, admin state wrong, address missing) is a FAIL. A *new* interface is never required to exist
before the plan that creates it.

## 16. Routing health

Fleet Quick has no routing telemetry (NOT_AVAILABLE). Deep Health reads live routing state. The plan-level routing
requirements are static route, OSPF adjacency and BGP session (§17–§19). Routing-process definitions, BGP network advertisements,
RIP bindings and NAT pools have **no evaluator** and are reported UNKNOWN / `REQUIREMENT_NOT_IMPLEMENTED`. PBR policies and
attachments are evaluated from the Ubuntu/FRR `pbr` group; a platform that reports no such group is UNKNOWN (data unavailable).

## 17. BGP

Post: the neighbor from the descriptor (`peer`) must be present and `Established` → PASS `BGP_EXPECTED_ESTABLISHED`; present but
any other state, or absent → FAIL `BGP_SESSION_DOWN` (the observed state is in the evidence). A shut-down neighbor →
NOT_APPLICABLE. Address-family activation requirements use the same evaluator. Pre: a *planned new peer legitimately does not
exist yet* — its requirement is future-state and never fails a precheck. BGP convergence time is the deployment engine's concern
(it should evaluate after a settling window); this engine reports the state it is given.

## 18. OSPF

Post: an adjacency on the bound interface (matching family, v2/v3) must be `FULL` → PASS; neighbors present but not FULL → FAIL
`OSPF_ADJACENCY_DOWN`; none observed → FAIL, **unless** the pinned validation flagged that end `OSPF_ONE_SIDED` (no validated peer
relationship: NOT_APPLICABLE); passive interface → NOT_APPLICABLE. Pre: only the underlay prerequisite (the bound interface
exists and is up unless the plan creates it). Deep Health accepts `FULL` and `TWO_WAY` (the normal DROTHER-to-DROTHER state).

## 19. Static routes

Post: the prefix must be in the routing table with the descriptor's next hop and/or exit interface → PASS
`ROUTE_EXPECTED_PRESENT`; else FAIL `ROUTE_MISSING` (the route's protocol/type is deliberately not required). Pre: only the exit
interface prerequisite (must exist and be up unless the plan creates it); next-hop-only routes have no prerequisite.

## 20. Services

* FHRP (VARP): the virtual addresses must be present on the interface (`FHRP_VIP_EXPECTED_PRESENT` / `FHRP_VIP_MISSING`). cEOS only
  (the Linux adapter provides no virtual-address evidence → UNKNOWN).
* DHCP relay: the `interface` + `destination` pair in the running configuration (`DHCP_RELAY_EXPECTED_PRESENT` / `..._MISSING`).
* ACL definition and attachment: `ip access-list <name>` and `ip access-group <name> in|out` on the interface.
* NAT (Ubuntu/FRR): an nftables rule with `masquerade`/`snat` on the outside interface.

## 21. DHCP health reuse

`live.dhcp_service_state()` imports and calls the existing `netbox/scripts/verify_dhcp_servers.py` (`nmas_status()`,
`r2_status()`); its own semantics are kept — a server is healthy when **at least one address family is active**. A plan containing
a DHCP relay requires both servers healthy at precheck: a server with no active family → FAIL `DHCP_SERVICE_UNHEALTHY`
(BLOCKED); an inspection failure → UNKNOWN (INCOMPLETE). A plan with no relay never inspects the servers. Deep Health of the
secondary DHCP host (R2, derived from `management.backup_dhcp_ipv4`) includes the same check. No server-health logic is duplicated.

## 22. ACL / NAT verification boundaries

Phase 13 already performed the conservative ACL semantic analysis; Phase 15 does **not** prove application traffic. It verifies
that the ACL exists and is attached (and, in future, critical observable management/control flow where supported). NAT: rule
presence in the observable ruleset only. **No traffic is generated**, no packet crafted, no synthetic flow sent. NAT pool and PBR
verification are NOT_IMPLEMENTED.

## 23. Monitoring-pipeline health

Fleet: topology service reachable; InfluxDB via the topology service's `backend.status`; collector silence; Grafana. Precheck: a
future deployment should have postcheck visibility. If the pipeline is healthy → PASS. If it is down but **every target device can
be verified by live read-only queries** → WARN (non-blocking). If some target can only be verified through telemetry: backend
reported ERROR → FAIL (BLOCKED); topology service unreadable (state unknown) → UNKNOWN (INCOMPLETE). A pipeline outage never
makes devices UNHEALTHY — only UNKNOWN.

## 24. Affected-device scope

Deterministic, from persisted Phase-13/14 facts only (never hostname patterns): **TARGET** = every device owning a plan Configlet
(cross-device Configlet dependency edges only ever join TARGETs and are recorded as `DEPENDS_ON:` / `DEPENDED_ON_BY:` reasons);
**PEER** = a non-target device linked by the pinned validation: `BGP_PEER_RESOLVED.peer_device`, `FHRP_DOMAIN.devices`, or a finding's
`related_devices`. PEERs supply postcheck evidence but never block (WARN at most). A device outside the scope is never judged: a
telemetry problem on S4 does not block a change to R1/R2.

## 25. Validation prerequisites

Latest validation must be CURRENT (`get_validation_currency`, source freshness checked read-only) **and** `PASS`/`PASS_WITH_WARNINGS`.
Never run → INCOMPLETE (`VALIDATION_NOT_PASSING`); STALE → BLOCKED (`PLAN_VALIDATION_STALE`); BLOCKED → BLOCKED; INCOMPLETE →
INCOMPLETE. No validation is ever run, rewritten or superseded by a precheck.

## 26. Plan prerequisites

A plan must exist (else INCOMPLETE `PLAN_MISSING`) and be CURRENT and pinned to the current validation (`get_plan_currency`; a
superseded validation, changed accepted intent, changed source or planner version → BLOCKED `PLAN_STALE`). A plan is never
rebuilt, edited or re-pinned.

## 27. Configlet → verification-requirement mapping

Table-driven (`health/requirements.py::REQUIREMENT_MAP`); no hostname/vendor conditionals. The Phase-14 catalogue's requirement kind
per object type maps to Phase-15 check types. Kinds without an evaluator are honest gaps.

| Phase-14 requirement kind | Produced by (object type) | Phase-15 check type(s) |
|---|---|---|
| `ACL_ATTACHMENT_INTENDED` | acl_attachment | `ACL_ATTACHMENT_PRESENT` |
| `ACL_DEFINED` | acl | `ACL_DEFINITION_PRESENT` |
| `ADDRESS_PRESENT` | address | `ADDRESS_PRESENT` |
| `BGP_AF_ACTIVATION_INTENDED` | bgp_neighbor_af | `BGP_NEIGHBOR_EXPECTED` |
| `BGP_NETWORK_INTENDED` | bgp_network | **NOT_IMPLEMENTED** (UNKNOWN in a postcheck, not applicable in a precheck) |
| `BGP_PEER_INTENDED` | bgp_neighbor | `BGP_NEIGHBOR_EXPECTED` |
| `DHCP_RELAY_INTENDED` | dhcp_relay | `DHCP_RELAY_CONFIG_PRESENT` |
| `FHRP_GROUP_INTENDED` | fhrp | `FHRP_VIRTUAL_ADDRESS_PRESENT` |
| `IDENTITY_PRESENT` | device_identity | **NOT_IMPLEMENTED** (UNKNOWN in a postcheck, not applicable in a precheck) |
| `INTERFACE_PRESENT` | interface | `INTERFACE_PRESENT`, `INTERFACE_ADMIN_STATE`, `INTERFACE_OPER_STATE` |
| `MGMT_VRF_PRESENT` | mgmt_vrf | `MGMT_VRF_PRESENT` — exact cEOS VRF definition in sanitized running configuration |
| `MGMT_VRF_BOUND` | mgmt_vrf_binding | `MGMT_VRF_BOUND` — interface binding and intended addresses in sanitized running configuration |
| `MGMT_VRF_ROUTE_PRESENT` | mgmt_vrf_route | `MGMT_VRF_ROUTE_PRESENT` — route in the named VRF; a default-VRF route never satisfies it |
| `MGMT_SERVICE_IN_VRF` | mgmt_vrf_service | `MGMT_SERVICE_IN_VRF` — exact supported cEOS service and VRF binding; unsupported service read-back stays UNKNOWN |
| `NAT_POOL_INTENDED` | nat_pool | **NOT_IMPLEMENTED** (UNKNOWN in a postcheck, not applicable in a precheck) |
| `NAT_RULE_INTENDED` | nat_rule | `NAT_RULE_PRESENT` |
| `CONFIG_REMOVED` | config_removal (Remove Configuration) | `CONFIG_OBJECT_ABSENT` — the removed statements' header-qualified signatures must be absent from the sanitized running config (evidence group `config_paths`, derived from the same `show running-config` output the `config` group already reads; no raw text is retained) |
| `PBR_ATTACHMENT_INTENDED` | pbr_attachment | `PBR_ATTACHMENT_PRESENT` — the policy is applied and valid on its ingress interface (Ubuntu/FRR `pbr` group: `show pbr interface json`) |
| `PBR_POLICY_DEFINED` | pbr_policy | `PBR_POLICY_PRESENT` — the map is valid and every intended sequence is installed with its prefixes and next hop (Ubuntu/FRR `pbr` group: `show pbr map json` + `show pbr nexthop-groups json`) |
| `ISIS_ROUTE_INTENDED` | stated by a migration stage (no Device Builder object emits it) | `ISIS_ROUTE_EXPECTED` — an IS-IS route is installed over exactly the expected paths, or (`present: false`) no IS-IS route for the prefix exists |
| `RIP_ROUTE_INTENDED` | stated by a migration stage (no Device Builder object emits it) | `RIP_ROUTE_EXPECTED` — a RIP route is installed over exactly the expected paths, or (`present: false`) absent |
| `RIP_PEERING_INTENDED` | stated by a migration stage (no Device Builder object emits it) | `RIP_NEIGHBOR_EXPECTED` — a RIP peer exists on the interface, or (`present: false`) none does; peers, never advertised prefixes |
| `ROUTE_INTENDED` | static_route | `STATIC_ROUTE_PRESENT` |
| `ROUTING_INTERFACE_ENABLED` | routing_binding | `OSPF_NEIGHBOR_EXPECTED` (only when `{'protocol': 'ospf'}`), `ISIS_NEIGHBOR_EXPECTED` (only when `{'protocol': 'isis'}`) |
| `ROUTING_PROCESS_INTENDED` | routing_bgp, routing_eigrp, routing_isis, routing_ospf, routing_rip | **NOT_IMPLEMENTED** (UNKNOWN in a postcheck, not applicable in a precheck) |

SSH, eAPI and gNMI service checks consume the read-only collector's `management_services` booleans. The evaluator does
not construct service-enable commands, open a session or invoke governed execution; absent or disabled service facts fail,
and unavailable or partial evidence remains UNKNOWN.

A test asserts every kind the planner can emit is either mapped or listed as NOT_IMPLEMENTED, and an *unrecognised* kind evaluates
to UNKNOWN `REQUIREMENT_UNKNOWN_TYPE` — never PASS.

## 28. Precheck expectations

Two classes (`evaluators.EVALUATORS`):

* **FUTURE_STATE** — what the plan creates: `INTERFACE_PRESENT/ADMIN_STATE/OPER_STATE`, `ADDRESS_PRESENT`, `BGP_NEIGHBOR_EXPECTED`,
  `ACL_DEFINITION_PRESENT`. Pre-change absence is *expected*: NOT_APPLICABLE (or an informational PASS "already satisfied;
  idempotent"). They can never FAIL, WARN or block a precheck.
* **PREREQUISITE** — what must already hold: the base interface of a static route (exit interface), OSPF binding, FHRP, DHCP relay,
  ACL attachment and NAT rule must exist and be up **unless the plan creates that interface**. Missing → FAIL `INTERFACE_MISSING`;
  oper down → FAIL `INTERFACE_OPER_DOWN`; admin down → WARN; partial evidence → UNKNOWN `PRECHECK_DATA_UNAVAILABLE`.

## 29. Postcheck expectations

Every requirement is *required*. The descriptor's expected state is compared with observed evidence: a demonstrated deviation
FAILs; missing, unavailable or EXPIRED evidence is UNKNOWN `POSTCHECK_DATA_UNAVAILABLE`; an unverifiable requirement is UNKNOWN
`REQUIREMENT_NOT_IMPLEMENTED`; an older plan without expected facts is UNKNOWN `REQUIREMENT_DESCRIPTOR_INCOMPLETE`. Result: FAIL if
any FAIL; INCOMPLETE if any UNKNOWN or nothing verified; PASS_WITH_WARNINGS if any WARN; else PASS. A persisted failing postcheck
also carries a plan-level `POSTCHECK_REQUIREMENT_FAILED` summary row. The same ADDRESS_PRESENT requirement is NOT_APPLICABLE in
the precheck and FAIL in the postcheck when the address is absent — proven by test.

## 30. Evidence precedence

Per fact group, **LIVE (this run) > TELEMETRY**: an available live group replaces the telemetry group; the two are never blended,
and every result names its `source`, `observed_at` and `freshness`. When both exist and disagree the live value is used and an
`EVIDENCE_CONFLICT` WARN records it. The telemetry interface group covers only monitored link endpoints and is marked *partial*
(absence from it never proves absence on the device → UNKNOWN). Fleet Quick has only telemetry and says so.

## 31. UNKNOWN semantics

UNKNOWN means *evidence unavailable*; FAIL means *evidence demonstrates a failure*. UNKNOWN never becomes PASS or FAIL. A
live failure alone is UNKNOWN `DEVICE_UNREACHABLE`; it becomes FAIL only when the device's telemetry is independently EXPIRED.
A monitoring outage makes devices UNKNOWN. In a precheck, an UNKNOWN on an `UNKNOWN blocks` code → INCOMPLETE; a postcheck with
any UNKNOWN → INCOMPLETE.

## 32. Blocking policy

Only on a **TARGET** device or a **PLAN**-level gate: a FAIL of a `blocking` code → BLOCKED; an UNKNOWN of an `unknown_blocks`
code → INCOMPLETE. WARN never blocks; PEER and FLEET results never block. Blocking FAILs: target unreachable (with expired
telemetry), stale target telemetry (no live read), critical CPU/memory, missing/oper-down prerequisite interface, stale validation
or plan, unhealthy DHCP service (relay changes), monitoring backend down when a target needs telemetry. Warnings only: moderate
CPU/memory, stale telemetry when a live read succeeded, degraded links, peer-device faults, monitoring down when every target is
live-verifiable. A missing CPU metric never blocks.

## 33. Run persistence / history

One generalized append-only model, `OperationalCheckRun` (migration `0005`): `run_id`, `mode` (`FLEET_QUICK`, `DEVICE_DEEP`,
`CHANGE_PRECHECK`, `CHANGE_POSTCHECK`), `status`, `device`, `change` (CASCADE), `plan` (SET_NULL), `engine_version`, `started_at`,
`finished_at`, `created_by`, `summary`, `report`. Status is validated per mode; a run is never modified. `ChangeValidationRun` is not
reused (health is not validation). Reports store only normalized facts and results — never raw command output — bounded to 400
results, 384 KiB, clipped strings, depth 4, lists of 25; optional heavy sections are dropped first. Each explicit run writes one
`AuditEvent` (`HEALTH_RUN_RECORDED`, `PRECHECK_RECORDED`, `POSTCHECK_RECORDED`: actor, mode, scope, run id, status, counts).
Passive page views write nothing. No notification is sent.

## 34. Security

POST + CSRF for every active action; GET is read-only and never opens a device session. The device comes from the URL and is looked
up in `inventory.yml` (an unknown name is 404 and is never probed); the browser supplies no command, source URL, query, host or
target — every POST field is ignored. Runs are addressed through their owner (a precheck only through its Change; a foreign or wrong-mode
run is 404). All output is auto-escaped (no `|safe`); JSON downloads are attachments with a server-derived filename and
`nosniff`. No shell, no `eval`/`exec`/dynamic import (AST-tested).

## 35. Credential handling

cEOS credentials come from the existing `inventory.yml` through `nsot_live.get_live_target` and never leave `live.py`. The Linux path
needs none. No credential, token or key is copied into a run, audit event, report, doc or error: failures become fixed reason codes
(`TIMEOUT`, `AUTH_FAILED`, `CONNECTION_FAILED`, `COMMAND_FAILED`, `PARSE_ERROR`, …), never an exception text; report keys that look
secret-shaped are replaced; the shared `secret_policy` is asserted on every stored report.

## 36. Read-only device guarantees

The command allowlists are validated at import time (`_assert_read_only`): every cEOS command is a `show` command (optionally
`| json`); every Linux command is `ip -j … show`, `vtysh -c "show …"`, or `nft list ruleset`. No configuration mode, write, clear,
reload, restart, save, commit, `ip link set`, `systemctl`, `nft add/delete`, route replace, or shell exists. Contract tests scan the
whole package for mutation methods and command-shaped strings. Live verification confirmed R1/R2 running-config and R3 address/route/NAT state
were byte-identical before and after (§Live verification).

## 37. No deployment

No Configlet is executed, no configuration pushed, no lifecycle state advanced (the Change stays `DRAFT`), no Complete/Partial (UAT)
acknowledgement, no Golden/Probation/soak. The precheck page has no deployment control.

## 38. No rollback

No rollback, no previous-state capture and no `rollback_config` is created or edited (Phase 14's `UNKNOWN_DEFERRED` previous-state
marker is untouched). Phase 17 owns capture and rollback.

## 39. Phase-16 / Phase-17 handoff

* Phase 16 (GitHub Actions Tier-3 change-effect validation) can call `evaluate_plan_requirements(plan, "POSTCHECK", evidence)` with
  synthetic evidence in CI; the engine has no HTTP or Django-view dependency.
* Phase 17 (execution) should: run `run_change_precheck` and refuse on anything but `PASS`/`PASS_WITH_WARNINGS`; re-check AUTO
  addresses (Phase 14) immediately before use; after each push collect evidence with `collect_scope_evidence(scope, snapshot)` or
  `run_plan_postcheck(plan, ...)` after a settling window; treat `INCOMPLETE` as "cannot confirm", not success; wire notifications
  from *postcheck FAIL / probation issues* (none are sent in Phase 15); and add previous-state capture for rollback.

## 40. Known limitations

* Fleet Quick has no routing/adjacency telemetry (the stored schema has none); routing is a Deep-Health / live concern.
* Plans built **before** Phase 15 lack the descriptors' `expected` facts and evaluate to INCOMPLETE until rebuilt (their frozen rows are not rewritten).
* Requirements with no evaluator (routing-process definition, BGP network advertisement, RIP binding, NAT pool, PBR, hostname
  identity) are reported UNKNOWN, so a plan containing them can at best be postchecked INCOMPLETE.
* OSPF adjacency expectations rely on the pinned validation: a far end outside the Change is indistinguishable from "one-sided"
  unless a neighbor is actually observed.
* FHRP evidence is cEOS-only; ACL/DHCP-relay evidence parses `show running-config` (cEOS); NAT evidence is the nftables ruleset (Linux).
  Linux address/route/OSPF/BGP parsing is verified against FRR 8.4.4 output only.
* Linux/FRR live reads need Docker access for the server process (the same requirement as the DHCP verifier); without it the reads
  are UNKNOWN `DOCKER_UNAVAILABLE`, not failures.
* Precheck live reads run synchronously inside the POST (bounded by `HEALTH_LIVE_TIMEOUT_SECONDS`, default 8 s per connection/command).
* The precheck's source-freshness check reuses the Phase-13 source snapshot, which performs **read-only** git metadata reads
  (`rev-parse`, `log -1`, `status --porcelain`); nothing is written.
* The NetBox condition on `/health/` performs one bounded read-only request per page view.
* No BGP/OSPF settling window is applied inside the engine. (Phase 17 adds a bounded settling poll in the *execution* engine around this engine; see `docs/STRUCTURED_EXECUTION_COMPLETE_PARTIAL_UAT.md` section 11.)

## Descriptor extension (why the Phase-14 schema changed)

Phase 14 stored only `{requirement, device, subject, status: DEFERRED, owner: PHASE_15}` — no expected values, so an address or a
neighbor could not be verified without re-deriving intent, which Phase 15 must not do. The planner therefore now records an optional,
secret-free `expected` fact block on each descriptor (descriptor `schema_version` 2), taken from the same hydrated accepted objects it
already renders (interface name, address, prefix / next hop, peer / remote AS, virtual addresses, relay destination, ACL name /
direction, NAT interfaces). It is frozen with the Configlet (`verification_spec` is a frozen plan field), needs **no migration**,
does not enter `plan_hash`, and leaves `status: DEFERRED` / `owner: PHASE_15` untouched. Historical plans are not rewritten.

## UI

* `/health/` — aggregate, source conditions, per-device table (platform, health, freshness, CPU, memory, link issues, routing
  *not available*, last evidence, issues), explicit *Record snapshot*, recent runs. Sidebar item **Health**; the Automation "Fleet Health"
  / "Per-Device Health" cards now link here.
* `/health/device/<device>/` — capability, Quick evidence, explicit *Run Deep Health*, latest run (interfaces, OSPF, BGP, routes,
  evidence sources, findings), history.
* `/health/runs/<run_id>/` (+ `report.json`) — a stored fleet/device run.
* `/device-builder/changes/<change_id>/precheck/` — prerequisites, affected scope, requirement summary, explicit *Run Precheck*, latest
  result, history; `…/precheck/<run_id>/` shows a stored run. No deployment button.

## Test strategy

Rationalized policy followed: subsystem-named modules, matrices with labelled `subTest`, fakes for every external system, endpoint rules added as
rows to `test_view_boundaries`, architecture contracts in `test_contracts`. New modules: `test_health_engine` (19), `test_health_sources` (14),
`test_change_precheck` (12), `test_health_views` (3) plus 5 contract methods in `test_contracts`; the 717-test baseline became **770** (+53 methods,
≈ +11 s: 41.0 s → 52.1 s, dominated by building real validated plans as fixtures). Mutation
checks (six deliberate defects: CPU-unknown blocking, Fleet reading live, future-state failing a precheck, missing evidence as PASS, whole-fleet scope, a
mutating command in the allowlist) each failed the relevant test and were reverted byte-for-byte.

## Live verification evidence

Against the real lab (read-only): Fleet Quick over real telemetry (10/10 HEALTHY, 0 device calls, 0.33 s for two pages); R1 (cEOS) and R3 (Ubuntu/FRR)
Deep Health HEALTHY with LIVE groups and OSPF/BGP facts; a synthetic Change validated against real NetBox/topology/inventory → plan → **precheck
PASS** (21 PASS, 2 future-state NOT_APPLICABLE); stale-plan precheck **BLOCKED** with no device contact; postcheck evaluator: fake "everything deployed"
PASS, one missing address FAIL, real undeployed network FAIL (`ADDRESS_MISSING`); R1/R2 running-config, R3 address/route/NAT hashes, containers and
listeners identical before/after; synthetic rows removed (DB back to baseline).
# Routing configuration postcheck codes

`ROUTING_CONFIG_PRESENT` confirms a process, interface binding, BGP neighbor or
network from normalized running configuration. `ROUTING_CONFIG_MISMATCH` records
a concrete semantic difference. Operational adjacency and session checks remain
separate requirements.

An interface counts as bound to an OSPFv2 process in either form the device
accepts: its own `ip ospf area` line, or a process `network <prefix> area <id>`
statement covering one of its IPv4 addresses (the most specific statement
decides the area). The statement form carries no passive flag in the normalized
model, so it confirms only a non-passive expectation; a requested area that
differs is still `ROUTING_CONFIG_MISMATCH`.
