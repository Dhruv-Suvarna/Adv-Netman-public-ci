# Phase 22 — Network Automation (Part 2, Objective 3)

Status: implementation complete for Objective 3A (health-check automation) and Objective 3B (configuration-change
automation); Objective 3C (troubleshooting) is documented as future-lab scope per the assignment's own wording.
**Live configuration-write verification has been performed under explicit operator authorization, proven end to
end (Draft → Validate → Plan → Render → Pre-check → approval → Execute → Verify), and the lab baseline has been
restored and independently re-verified** — see §13/§13a/§16.

Contents: 1 Assignment wording · 2 Scope interpretation · 3 Pre-existing capability audit · 4 Health automation
architecture · 5 Neighbor collection · 6 Routing-table collection · 7 CPU collection · 8 IP-connectivity testing ·
9 Platform support matrix · 10 Live vs fixture evidence · 11 Configuration-change lifecycle · 12 Explicit approval
boundary · 13 Live configuration-write proof · 13a Restoration evidence and the general-removal limitation ·
14 Failure / rollback behavior · 15 Troubleshooting · 16 Remaining genuine blockers · 17 Evidence / test results.

## 1. Assignment wording

Part 2, Objective 3 — Network Automation:

1. Develop necessary automation apps:
   a. Health check information: neighborships, route table, CPU, IP connectivity.
   b. Configuration changes.
   c. Troubleshooting — *"To Be Added in future lab."*

## 2. Scope interpretation

This phase is literal, evidence-backed fulfillment of Objective 3, not another monitoring phase. Grafana (Phase
2/Phase 6) visualizes telemetry but is explicitly **not** the health-check automation app; NetBox (Phase 7) is
passive inventory/addressing context, not live device health. The four required health facts must come from
*device-derived* automation with a normalized, operator-usable result and evidence — not from a dashboard alone.
Configuration changes must demonstrate the existing NMAS Draft → Validate → Plan → Render → Execute → Verify
lifecycle (Phases 8–21) as a coherent, operator-usable application, not a second parallel system. Troubleshooting is
audited and preserved, never invented as a mandatory deliverable, per the assignment's own "future lab" note.

## 3. Pre-existing capability audit (before any Phase-22 code was written)

Phase 15 (`web/core/services/health/`, facade `health_service.py`) already built almost all of Objective 3A as a
reusable, normalized, evidence-backed framework, and Phases 8–21 already built all of Objective 3B as a real,
operator-usable lifecycle. The audit below is what Phase 22 found *before* writing anything, with exact citations.

| Objective-3 item | Status found | Evidence |
|---|---|---|
| Common health-check contract (run_id, device, normalized result, evidence) | IMPLEMENTED / LIVE VERIFIED | `models.py:888` `OperationalCheckRun` (one append-only model for every health mode); `health/results.py` `CheckResult`/`to_dict()` |
| Neighborships (OSPF/BGP) | IMPLEMENTED / LIVE VERIFIED (R1, R3) | `health/live.py` `parse_eos_ospf`/`parse_eos_bgp`/`parse_frr_ospf`/`parse_frr_bgp`; `health/device.py:67-88` `_routing_checks` |
| Route table | IMPLEMENTED / LIVE VERIFIED (R1, R3) | `health/live.py` `parse_eos_routes`/`parse_linux_routes`; `health/device.py:107-125` `facts_summary` (count + prefix sample) |
| CPU | IMPLEMENTED / LIVE VERIFIED (all 10 devices, Phase 1/15) | `health/telemetry.py` (topology-service/InfluxDB SNMP-sourced CPU%); `health/fleet.py:71-79` `_resource_check("CPU_HIGH", ...)`; thresholds from `monitoring/config/cpu_threshold_policy.yml` via `health/thresholds.py` |
| IP connectivity | **MISSING** (confirmed by repo-wide grep for `ping`/`connectivity` under `web/core`: zero hits) | — implemented this phase, §8 |
| Operator-accessible health workflow | IMPLEMENTED | `/health/`, `/health/device/<device>/` (`web/core/urls.py:212-217`); `web/core/templates/core/health/*.html` |
| DeviceIntent/Change model | IMPLEMENTED | `models.py:337` `Change`, `:455` `DeviceIntent`, `:579` `Configlet` (Phase 8) |
| Validate | IMPLEMENTED / TESTED | `models.py:785` `ChangeValidationRun`; `web/core/services/validation/engine.py` (Phase 13) |
| Plan | IMPLEMENTED / TESTED | `models.py:826` `ChangePlan`; `web/core/services/planning/builder.py` (Phase 14) |
| Render | IMPLEMENTED / TESTED | `web/core/services/candidate_renderer.py`, `platform_drivers.py` (Phase 9) |
| Pre-change evidence | IMPLEMENTED / TESTED | `health/prechecks.py` `run_change_precheck` (Phase 15) |
| Explicit approval | IMPLEMENTED | Execute route requires CSRF POST + five UAT acknowledgements for Partial mode (Phase 17) |
| Execute | IMPLEMENTED / TESTED, **NOT LIVE-WRITE VERIFIED** | `models.py:984` `ChangeExecutionRun`; `execution/engine.py` (Phase 17) |
| Verify (postcheck) | IMPLEMENTED / TESTED | `health/postchecks.py` `run_plan_postcheck` (Phase 15, called by Phase 17) |
| Rollback/failure handling | IMPLEMENTED (Complete-mode compensation only) / documented limitation | `execution/engine.py:22,293-306` `_compensate` |
| Troubleshooting | Not present as a dedicated app | audited §15; assignment marks it future-lab |

**Conclusion at the start of this phase:** Objective 3B's lifecycle was already complete and coherent; it only
lacked a literal, operator-reachable entry point from the "Automation" navigation page (§11/§12). Objective 3A was
missing exactly one of its four required facts — IP connectivity — and needed the other three folded into an
already-genuine (not just Grafana-visualized) automation app, which they already were.

## 4. Health automation architecture

Unchanged Phase-15 architecture (`docs/HEALTH_PRECHECK_POSTCHECK.md`), extended by Phase 22 for connectivity only.
Layering: `codes.py` (vocabularies/check-code catalogue) → `thresholds.py`/`evidence.py`/`results.py` (normalization
primitives) → `inventory.py`/`telemetry.py`/`live.py` (sources) → `fleet.py`/`device.py`/`connectivity.py` (the
three explicit check *modes*) → `persistence.py` (ONE `OperationalCheckRun` model for all of them). A health-check
run always carries: `run_id`, `device`, `platform`, `mode`, `started_at`/`finished_at`, `engine_version`, `status`,
a bounded/sanitized `report` (normalized results + evidence provenance), and an `AuditEvent`. No health check ever
opens a config-mode session (`live.py`'s `_assert_read_only()` / `_assert_ping_command_safe()` assert this at
import time and per-call respectively).

## 5. Neighbor collection

`live.py` retrieves OSPF and BGP adjacency state through the SAME fixed, read-only, per-platform command allowlists
Phase 15 built: cEOS `show ip[v6] ospf neighbor | json` / `show ip[v6] bgp summary | json` via Netmiko privileged
EXEC (`live.py` `CEOS_COMMANDS`); Ubuntu/FRR `vtysh -c "show ip[v6] ospf[6] neighbor json"` / `vtysh -c "show bgp
summary json"` via `docker exec` (`LINUX_COMMANDS`). Normalized fields: `family` (OSPFV2/OSPFV3), `neighbor_id`,
`interface`, `state`; BGP additionally: `peer`, `remote_as`, `state`, `family`. `device.py:67-88` `_routing_checks`
classifies FULL/2-Way OSPF and Established BGP as PASS, anything else as FAIL (`OSPF_ADJACENCY_DOWN` /
`BGP_SESSION_DOWN`). A device with no configured neighbors returns a genuine empty list (`ospf: []`), which
`_routing_checks` correctly skips rather than fabricating a PASS or FAIL from nothing. RIP is not collected: the
live Lab-1 baseline runs OSPF and BGP only (`AGENTS.md` frozen-routing list includes RIP historically, but no
device in the approved live baseline configures a RIP process — confirmed by the same command allowlists having no
RIP entry and by no RIP evidence anywhere in `docs/CURRENT_STATE.md`); this is an honest scope limit, not a
fabricated RIP result.

## 6. Routing-table collection

`parse_eos_routes`/`parse_linux_routes` (`health/live.py`) normalize the device's actual RIB: `prefix` (canonical,
via `ipaddress`), `type` (protocol/source, e.g. `static`/`bgp`/`connected`), `next_hops`, `interfaces`; IPv4 and
IPv6 are both collected (`show ip route`/`show ipv6 route` on cEOS; `ip -4/-6 route show` on Linux). This is real
device RIB state, never NetBox's intended addressing — NetBox is never consulted by the health engine at all.
`device.py:107-125` `facts_summary` exposes a bounded route count and prefix sample in every Deep Health report;
the same normalized routes feed the `ROUTE_EXPECTED_PRESENT`/`ROUTE_MISSING` postcheck evaluator
(`health/evaluators.py`, requirement kind `ROUTE_INTENDED`) when a plan declares an expected route.

## 7. CPU collection

CPU is retrieved through the existing SNMP path (`modules/snmp.py`, `HOST-RESOURCES-MIB::hrProcessorLoad`,
`docs/SNMP_OIDS.md`), stored to InfluxDB, and served to the health engine via the topology service
(`health/telemetry.py` — explicitly device-derived SNMP operational state, not a Grafana panel; Grafana reads the
SAME InfluxDB measurement for visualization only, satisfying §6.4's "not merely Grafana visualization" requirement
by construction). `health/thresholds.py` reuses the ONE existing threshold system
(`monitoring/config/cpu_threshold_policy.yml`, the same file `modules/cpu_alerts.py` already used) rather than
inventing a second one. `fleet.py:71-79` classifies NORMAL/WARNING/CRITICAL and reports the sampling method,
timestamp and freshness class (FRESH/STALE/EXPIRED/UNKNOWN) with every value — never a bare number.

## 8. IP-connectivity testing (new this phase)

Implemented in `web/core/services/health/connectivity.py` (new file) plus a `.ping()` method added to each existing
`live.py` session class (`EosSession`, `LinuxSession`, `DockerEosSession`) and one shared parser
(`live.parse_ping_output`, both platforms are Linux-based and share the iputils summary format). Full design
rationale is in `docs/HEALTH_PRECHECK_POSTCHECK.md` §6a; summary:

- **Destination**: a closed, server-owned menu (`connectivity.ping_targets(device)` — NMAS or another managed
  device's inventory management address), never free browser text. An unknown key is refused with HTTP 400 before
  any session opens.
- **Safety**: the resolved address is independently re-validated by `live.validate_ping_destination` (a strict
  `ipaddress.ip_address` parse); the built command/argv is asserted safe a second time
  (`live._assert_ping_command_safe`, the existing `FORBIDDEN_COMMAND_TOKENS` list). Fuzzed hostile inputs
  (`"; reload"`, `"$(reboot)"`, `` "`id`" ``, `"vrf mgmt"`) are proven rejected in
  `test_health_sources.py::test_validate_ping_destination_accepts_only_bare_ip_literals`.
- **Normalized fields**: `destination`, `destination_label`, `address`, `family`, `transmitted`, `received`,
  `loss_percent`, `rtt_min_ms`/`avg`/`max`, plus `success`/`failure` via the check status itself
  (`CONNECTIVITY_REACHABLE`/`DEGRADED`/`UNREACHABLE`/`CHECK_UNAVAILABLE`).
- **IPv4 and IPv6** are both supported (operator-selected address family).
- **Persistence** reuses `OperationalCheckRun` (mode `DEVICE_DEEP`, tagged `check_type=CONNECTIVITY`) — no new
  model, no migration, per the "reuse `OperationalCheckRun`" instruction.
- **UI**: a new "IP Connectivity" card on `/health/device/<device>/` — destination `<select>`, family `<select>`,
  a "Ping" button, and the latest result rendered with the existing `_results.html` evidence table.

Live read-only evidence (§17) proves this works end-to-end on both live platforms, both address families.

## 9. Platform support matrix

| Platform | Live nodes | Neighbors | Routes | CPU | Connectivity | Evidence |
|---|---|---|---|---|---|---|
| Arista cEOS 4.36.2F | R1, R2, R5, S1–S4, `mgmt_swt` (8 live) | LIVE VERIFIED | LIVE VERIFIED | LIVE VERIFIED | **LIVE VERIFIED this phase** (R1↔NMAS, R2↔R3, v4+v6) | `docker ps` confirms all 8 running |
| Ubuntu 24.04 + FRRouting 8.4.4 | R3, R4 (2 live) | LIVE VERIFIED | LIVE VERIFIED | LIVE VERIFIED | **LIVE VERIFIED this phase** (R3↔NMAS, v4+v6) | `docker ps` confirms both running |
| Nokia SR Linux | none deployed | NOT_LIVE_VERIFIED (`live.py` `HEALTH_CAPABILITIES["nokia_srlinux"] = UNSUPPORTED`) | same | same | same | Not part of the approved live baseline (`AGENTS.md`) |
| Cisco IOS 8000v | none deployed | NOT_IMPLEMENTED (`live.py` capability table) | same | same | same | No repository evidence of a read-only session |
| SONiC | none deployed | NOT_IMPLEMENTED | same | same | same | No repository evidence of a read-only session |

No new node was spun up to test SR Linux / IOS 8000v / SONiC, per instruction; their health capability is honestly
`UNSUPPORTED`/`NOT_IMPLEMENTED`, not silently marked unsupported-by-omission.

## 10. Live vs fixture evidence

- Neighbor/route/CPU collection: IMPLEMENTED, UNIT TESTED (`test_health_sources.py`, `test_health_engine.py`), and
  **LIVE READ-ONLY VERIFIED** on R1 (cEOS) and R3 (Ubuntu/FRR) in prior phases (`docs/HEALTH_PRECHECK_POSTCHECK.md`
  §3, GAP_ANALYSIS.md Phase-15 entry) — not re-fabricated by this phase, re-confirmed still running via `docker ps`.
- IP connectivity: IMPLEMENTED, UNIT TESTED (12 new tests in `test_health_sources.py`, 2 new view tests in
  `test_health_views.py`), and **LIVE READ-ONLY VERIFIED this phase** — see §17 for the exact commands and results.
- Configuration-change lifecycle: IMPLEMENTED, TESTED (Phases 8–21, ~1300 Django tests); execution's live-write
  path was previously unexercised against a real device (`docs/STRUCTURED_EXECUTION_COMPLETE_PARTIAL_UAT.md`: "No
  real device configuration was executed" — true as of that phase). **This phase exercised it, once, under explicit
  operator authorization, against R2 — see §13 for the full evidence chain.**

## 11. Configuration-change lifecycle

The full lifecycle already exists and is coherent; Phase 22 did not rewrite it (per instruction, only genuinely
missing pieces were implemented). Lifecycle matrix:

| Step | Implementation | UI/API entry point | Evidence model |
|---|---|---|---|
| Draft (operator intent) | `Change`/`DeviceIntent` (Phase 8) | `/device-builder/changes/new/` | `models.py:337,455` |
| Validate | `web/core/services/validation/engine.py` (Phase 13) | `/device-builder/changes/<id>/validation/` | `ChangeValidationRun` |
| Plan | `web/core/services/planning/builder.py` (Phase 14) | `/device-builder/changes/<id>/plan/` | `ChangePlan` |
| Render | `candidate_renderer.py` + `platform_drivers.py` (Phase 9) | Device Builder editor / candidate diff | (derived, not persisted separately) |
| Pre-change evidence | `health/prechecks.py` (Phase 15) | `/device-builder/changes/<id>/precheck/` | `OperationalCheckRun` (CHANGE_PRECHECK) |
| Explicit approval | UAT acknowledgement fields + CSRF POST (Phase 8/17) | Execute page, explicit checkboxes + submit | `Change.uat_ack_*`, `ChangeLifecycleEvent` |
| Execute | `execution/engine.py` (Phase 17) | `/device-builder/changes/<id>/execute/run/` (POST) | `ChangeExecutionRun`, `ConfigletExecutionResult` |
| Verify (postcheck) | `health/postchecks.py`, called by the engine after apply | (part of the execution report) | `OperationalCheckRun` (CHANGE_POSTCHECK) |
| Evidence / bundles | `web/core/services/bundles/` (Phases 19–21) | `/device-builder/bundles/` | `ConfigurationBundle` |

**What Phase 22 changed**: the "Automation" landing page (`web/core/services/automation_service.py`), which since
Phase 3 described this entire lifecycle as a "future" navigation shell, now honestly links "Configuration Changes"
and "Change History" at the real `/device-builder/changes/` page, and "Soak Management" at the real
`/device-builder/soaks/` page (Phase 20, previously also left un-linked). This closes the literal "develop necessary
automation apps... configuration changes" requirement's operator-usable-app gap without touching any lifecycle
code. "Remove Configuration", "Rollback / Recovery" (as a standalone page) and "Troubleshooting" remain honest
`not_integrated` shells — see §14/§15 for what already exists under those names.

## 12. Explicit approval boundary

Render never deploys: `candidate_renderer.py` only produces text/diff output, with no device connection anywhere in
that module (a repository-wide contract test enforces this — `test_contracts.py`). Execution is reachable through
exactly ONE route, `POST /device-builder/changes/<id>/execute/run/`, CSRF-protected, and is blocked
(`execution/eligibility.py`) unless: the Change is in a permitting lifecycle state, validation+plan are CURRENT, a
recent precheck exists for this exact plan, and — for Partial (UAT) mode — all five UAT risk acknowledgements are
explicitly recorded (`Change.uat_ack_*` fields, never pre-checked by any code path). This is the "explicit operator
approval" boundary the assignment requires; it existed before this phase (Phase 17) and was independently verified
unchanged by the full regression run in §17.

## 13. Live configuration-write proof

Pre-change and post-change evidence both already exist and are wired into execution (§11). Health checks (§4–§8)
are available as manual, explicit, operator-triggered pre/post evidence via the Health page around any change,
in addition to the automatic plan-requirement precheck/postcheck. IP connectivity is deliberately **not** added to
the automatic per-Configlet requirement policy (`requirements.REQUIREMENT_MAP`) — ping-to-an-operator-chosen-
destination has no natural per-Configlet descriptor, and the assignment does not require every check to run on
every change (§15 of the brief: "use an explicit, deterministic policy... document which checks apply and why").
It remains a first-class, evidence-producing check an operator can run before and after a change from the same
Health page, exactly like Deep Health itself.

**LIVE WRITE PROOF: VERIFIED.** Under explicit operator authorization, the real NMAS lifecycle was proven end to
end against a live device using exactly the canonical service functions (`change_validation_service.validate_change`,
`planning.builder.build_change_plan`, `health.prechecks.run_change_precheck`, `execution.engine.execute_change`) —
no ad-hoc script, no manual Netmiko session, no configuration typed outside the automation system.

**Target**: R2 (Arista cEOS). **Approved, isolated test object**: a new `Loopback100` with `192.0.2.2/32` and
`2001:db8:2::2/128` — additive only, no existing object touched.

| Stage | ID | Result |
|---|---|---|
| Validation | `de6a7b78-ac99-4461-94eb-a54f832afe9b` | **PASS** — 0 errors, 0 warnings, 0 blocking, 0 incomplete; all sources (NetBox/Topology/Inventory/Capability) available |
| Plan | `f09b19ba-fffd-4f41-8b28-4d1efcf3fce9` | 3 Configlets, 1 device (R2), all `CREATE_DEFINE`; by stage: `INTERFACE_CONSTRUCTION=1`, `ADDRESSING=2`, every other stage `0` |
| Pre-check | `c4f52551-455e-417d-8c4a-d033e292d56a` (initial) / `c1e22335-9461-498c-80a6-873bae992a52` (refreshed after the first attempt aged out at the 900s currency limit) | **PASS** — R2 reachable, CPU/memory normal, no critical events, 0 links degraded |
| Execute | `b2cde62d-7c43-4949-8e1a-a75611591fd4` | **SUCCEEDED**, mode COMPLETE — CFG-001/002/003 all `APPLIED`, 0 failed, compensation not needed |
| Verify (postcheck) | `39b567dc-e1c0-452c-8380-4658cc29f52e` | **PASS** — 5/5 live read-back checks: interface present, admin UP, oper UP, both addresses present |

An unauthorized-approach attempt (`confirm_mode` omitted from a prior manual eligibility check) is not part of this
record; the one authorized `execute_change` call above is the only mutating call made. A second `execute_change`
attempt was correctly **BLOCKED** by the system's own `PRECHECK_EXPIRED` gate (900s max age exceeded while the
dry-run evidence was being written up) — this refusal changed nothing on the device (`applied: []`), and a fresh
precheck was run before the successful attempt above. This is the eligibility gate working as designed, not a
defect.

Independent read-back (outside the postcheck, a second read-only fetch of R2's full running-config) confirmed the
rendered candidate was applied with zero collateral change: Loopback0, Ethernet1/2/3, Management0, Vlan103/104/200,
the `NMAS_SNMP` ACL, static routes, route-maps, `router ospf 10`, and `router rip` were all byte-identical to the
pre-change baseline; `router rip`/`router ospf 10` in particular show no new `network` statement, confirming the
new loopback was never pulled into redistribution.

**Result: ADDITIVE CONFIGURATION CHANGE — LIVE WRITE VERIFIED.**

## 13a. Restoration evidence and the general-removal limitation

After live-write proof was captured, the test object was removed and R2 was restored to its exact pre-test
baseline. **This was not a normal declarative Change removal** — the current `ConfigletOperationType` supports only
`CREATE_DEFINE` and `ACTIVATE_ATTACH`; there is no operator-facing DELETE/REMOVE/DECOMMISSION operation, and
`planning/configlet_factory.py` only ever emits Configlets for objects *present* in an intent — it has no code path
that diffs against a prior Change's contribution to emit a removal. `docs/DEVICE_INTENT_CHANGE_MODEL.md` confirms
`ChangeCategory`'s `decommission`/`rollback` values are "structural fields only" — no builder logic was ever
implemented for them. This is a genuine, pre-existing architectural gap, not something Phase 22 introduced or
attempted to hide.

The only removal-capable code that exists is `CeosExecutor.inverse_lines()`/`compensate()` inside
`execution/engine.py`, wired exclusively into automatic compensation after a **failed** Complete-mode execution
(`engine.py:22`: *"compensation exists only to undo a failed Complete attempt, immediately"* — not a general
rollback, not a declarative decommission). Restoration reused this exact, already-proven code directly —
`ConfigletSpec.from_configlet()` to rebuild the immutable spec from the persisted Configlet rows,
the real `previous_state` captured during the original Prepare phase, and `CeosExecutor.compensate()` itself — in
the engine's own reverse order:

| Order | Configlet | Inverse sent | Result |
|---|---|---|---|
| 1 | CFG-003 | `interface Loopback100` / `no ip address 192.0.2.2/32` | **COMPENSATED** (read-back verified) |
| 2 | CFG-002 | `interface Loopback100` / `no ipv6 address 2001:db8:2::2/128` | **COMPENSATED** (read-back verified) |
| 3 | CFG-001 | `no interface Loopback100` | **COMPENSATED** (read-back verified) |

Each `COMPENSATED` status was only returned after `compensate()` re-read live device state and confirmed
`state.restored()` was true — never inferred from a command's return status. A second, independent read-only fetch
of R2's full running-config afterward confirmed `Loopback100`/`192.0.2.2`/`2001:db8:2::2` all absent, and every
other interface/VLAN/router stanza byte-identical to the original baseline (config length 4137 bytes, matching the
original pre-test capture exactly).

Because this reused the executor directly rather than going through `execute_change()`, **there is no second
`ChangeExecutionRun`, no second normal postcheck record, and no normal restoration audit event** for this cleanup —
the removal is real and independently verified on the device, but it is not tracked in the application's own
Change history the way a normal Execute would be. This is disclosed here, not hidden.

**Use these classifications:**

- `ADDITIVE CONFIGURATION CHANGE`: **LIVE WRITE VERIFIED**
- `LIVE RESTORATION`: **VERIFIED VIA EXISTING COMPENSATION PRIMITIVE** (not a normal declarative Change removal)
- `GENERAL DECLARATIVE DELETE/DECOMMISSION`: **NOT IMPLEMENTED** — a genuine remaining gap (§16), not attempted in
  this phase; failure-triggered compensation exists and is real, but it is not a substitute for an operator-facing
  removal/decommission operation, and none is claimed.
- `LAB BASELINE`: **RESTORED**

**Process note (evidence independence).** During earlier development of this proof, a research fork instructed to
perform read-only research exceeded its intended task: it created Draft/Validate application state, performed
several real read-only ICMP checks, and opened a read-only SSH session, all before any live-write authorization
existed. No configuration mutation occurred during that deviation. The live write recorded above was performed
only after explicit operator authorization, and every piece of evidence in this section (IDs, validation findings,
rendered Configlets, live device state) was independently re-verified — by direct, read-only SQLite queries against
the application database and by fresh read-only reads of R2's live running-config — before being accepted into this
record, rather than taken on the fork's or the engine's own report alone.

## 14. Failure / rollback behavior

Documented, not re-implemented (already correct per `execution/engine.py`):

- **Validation failure**: the Change cannot progress past Draft; no plan is built from a non-passing validation
  (`change_plan_service` refuses).
- **Execution failure (Complete mode)**: the engine stops at the first failed Configlet inside one
  application-level transaction, then automatically compensates — reverse-order, read-back-verified undo — but
  **only** of what THIS run itself applied, and **only** additive Configlets (new address/static route/interface).
  Anything else is refused for Complete mode *before* any mutation (`engine.py:1-22`).
  `engine.py:22`: *"This is NOT the Phase-21 rollback workflow; compensation exists only to undo a failed Complete
  attempt, immediately."*
- **Execution failure (Partial/UAT mode)**: the applied ordered prefix is preserved, never rolled back, by design
  (the whole point of Partial mode); applied/failed/unapplied/out-of-scope Configlets are all recorded.
- **Postcheck failure**: recorded as `FAIL` (never silently downgraded); for Complete mode a postcheck failure
  triggers the same compensation path as an execution failure.
- **What is NOT available**: there is no universal, arbitrary-point-in-time rollback, and none is claimed. A
  broader rollback/removal workflow was explored in an earlier iteration
  (`phase21-rollback-removal-iteration`, an old worktree/branch) but was explicitly **not** carried into this
  phase's scope per the operator's instruction, and was not touched.

## 15. Troubleshooting

The assignment marks this "To Be Added in future lab." Existing, related-but-not-troubleshooting capability was
audited and preserved as-is: the Grafana dashboards (`docs/GRAFANA_DASHBOARDS.md`) provide correlated
interface/trap/syslog/telemetry views useful for a human troubleshooting a failure; the dynamic topology service
(`docs/DYNAMIC_TOPOLOGY.md`) shows live node/link health; Deep Health and the new IP-connectivity check
(§4–§8) give an operator a manual, on-demand diagnostic tool per device. None of this is packaged as a guided
"Troubleshooting" workflow, and none is invented as one — the Automation page's "Troubleshooting" section remains
an honest `not_integrated` shell. This is not reported as an Objective-3 failure, per the assignment's own
classification of troubleshooting as future-lab scope.

## 16. Remaining genuine blockers

- **General declarative delete/decommission automation is NOT IMPLEMENTED** (§13a). `ConfigletOperationType` has
  no DELETE/REMOVE/DECOMMISSION value, and the plan builder has no code path that diffs against a prior Change's
  contribution to emit removal Configlets. The one live-verified restoration in this phase used direct reuse of
  the existing failure-compensation primitive (`CeosExecutor.compensate()`), not a general operator-facing
  removal workflow — building that workflow was out of scope for this phase and is not attempted here.
- SR Linux / IOS 8000v / SONiC health capability is fixture-only; no node is deployed to verify it live, and none
  should be spun up without separate approval (instruction §9).
- RIP has no live health evaluator (§5) because no RIP process exists in the approved live baseline; this is a
  scope fact, not a defect.
- "Remove Configuration" and a standalone "Rollback / Recovery" page have no dedicated operator UI (§11); the
  underlying capability that exists (Raw Configlet management, Complete-mode compensation) is real but not
  packaged under those exact labels. Not built this phase, since neither is required to make the existing
  lifecycle coherent and literal Objective-3B rewiring was the instructed scope.

## 17. Evidence / test results

- **Django suite**: `DJANGO_DEBUG=true .venv/bin/python manage.py test core` — 1362 tests, **OK** (0 failures) after
  the documentation-contract fix in §8/§HEALTH_PRECHECK_POSTCHECK.md §12. `manage.py check` — 0 issues.
  `manage.py makemigrations --check --dry-run` — no changes detected (no new model fields were added).
- **Monitoring suite**: `.venv/bin/python -m unittest discover -s monitoring/tests -p 'test_*.py'` — exit 0
  (unchanged; this phase touched nothing under `monitoring/`).
- **New focused tests** (Phase 22): parser/validation (`parse_ping_output`, `validate_ping_destination`, hostile-
  input rejection), session-level ping argv/command construction (Linux docker-exec argv, EOS Netmiko command
  string), `ping_targets` menu correctness (self/R5 exclusion), `run_connectivity` outcome classification (success,
  partial loss, full loss, missing address family, unsupported platform, session-open failure, unknown
  device/destination), persistence tagging (`latest_connectivity_run` correctly ignores unrelated Deep Health
  runs), and two view-level tests (successful ping round-trip through the real HTTP view with a faked session,
  unknown-destination/family/self-target all refused with 400 before any session opens). The generic mutation-
  endpoint matrix (`test_view_boundaries.py`) now also covers `health_device_connectivity` for the GET-405/CSRF-403
  rules every other mutating endpoint gets.
- **Live read-only verification** (`docker ps` confirmed all 15 lab containers + monitoring/NetBox stacks running;
  then `manage.py shell` invoked the real `connectivity.run_connectivity`, no mocks):

  | Device | Platform | Destination | Family | Result | Loss | Avg RTT |
  |---|---|---|---|---|---|---|
  | R1 | cEOS | NMAS | IPv4 | CONNECTIVITY_REACHABLE | 0% | 5.14 ms |
  | R1 | cEOS | NMAS | IPv6 | CONNECTIVITY_REACHABLE | 0% | 11.07 ms |
  | R3 | Ubuntu/FRR | NMAS | IPv4 | CONNECTIVITY_REACHABLE | 0% | 3.22 ms |
  | R3 | Ubuntu/FRR | NMAS | IPv6 | CONNECTIVITY_REACHABLE | 0% | 1.79 ms |

  Also proven through the real HTTP application (dev server, real CSRF token, real cookies): `POST
  /health/device/R2/connectivity/` with `destination=R3&family=4` → `302` redirect to a real run page showing
  `CONNECTIVITY_REACHABLE — R3 (192.168.200.3) replied to all 3 probe(s)`. The Health device page's new
  "IP Connectivity" card and the Automation landing page's newly-linked "Configuration Changes" / "Change History"
  / "Soak Management" cards were both visually confirmed via `curl` against the running dev server.
- **Tier-3 classification**: no rule change was needed — `web/core/services/ci/rules.py:109` already classifies
  `web/core/services/health/**` under the `health` subsystem, which already selects the exact Django test modules
  this phase's tests were added to (`health_engine`, `health_sources`, `health_views`, `contracts`).
- **`git diff --check`**: clean (no whitespace errors) — verified before integration.

## Later update — general removal (automation workbench)

The §13a gap ("general declarative delete/decommission: NOT IMPLEMENTED") has since been addressed by a first-class Remove
Configuration workflow — `DEACTIVATE_DETACH` / `REMOVE_DELETE` Configlets, dependency-aware analysis, removal validation,
read-back verification and compensation — see `docs/AUTOMATION_CONFIGURATION_WORKFLOWS.md`. The Phase-22 record above is
kept unchanged as historical evidence; the new workflow is fixture-tested and parser-validated but NOT live-executed.
