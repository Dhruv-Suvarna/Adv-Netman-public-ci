# V2 Maintenance Mode

Status of this document (2026-10-17, pre-merge review): implementation complete; proven in unit tests, on the simulated
sandbox and on the REAL disposable cEOS 4.36.2F / FRR 8.4.4 sandbox (section 18.1). **No maintenance was entered on any
production lab device. No production network device was written.** No
deployed database was migrated. Maintenance Mode is **not live-verified**; a controlled live pilot is a later, separately
authorized phase (section 16). The foundation this builds on is `docs/V2_MAINTENANCE_MODE_FOUNDATION.md`; where the two
differ, this document is current.

Package `web/core/services/maintenance_mode/`; pages `web/core/maintenance_views.py` and
`web/core/templates/core/maintenance/`; commands `nmas_maintenance` (operator) and `maintenance_tick` (worker); timer
`deploy/systemd/nmas-maintenance-tick.{service,timer}`, installer `deploy/scripts/install_maintenance_timer.sh`; models
`MaintenanceRecord`, `MaintenanceEvidence` (migration `0030_maintenance_record`, after `0029_configuration_validation_run`).

## 1. The rule

    ACTIVE PRODUCTION TRAFFIC + NO PROVEN, EXISTING, LOSSLESS WAY TO MOVE IT  =  BLOCK
    PRODUCTION TRAFFIC PROVEN QUIESCED                                         =  may proceed without redundancy
    UNKNOWN                                                                    =  BLOCK (never read as quiet or safe)

Maintenance Mode is not "shut the device", "disable routing", "remove links", "assume redundancy" or "drain blindly". It
is a controlled transition that proves, per address family, direction and flow, that traffic can be moved away by
redundancy that already exists in this network, moves it, proves it moved with zero production loss, and later puts the
device back exactly as it was and proves that too. No new routing mechanism is introduced; the routing architecture
(RIP and IS-IS on the access side, OSPFv2/OSPFv3 in the core, BGP from R3/R4 to R5, VLAN 200 management) is unchanged.

## 2. Reconciliation with main

The branch `v2-maintenance-mode` (foundation `d3b76bf`) was paused while main moved on. On 2026-10-17:

1. the uncommitted 2026-10-12 work found in the worktree was preserved unchanged as `8c6bdee` (it had 4 failing tests);
2. `origin/main` `87c5ebb` (Configuration Validation #54 and hotfixes #55-#57) was merged without rewriting history
   (`7917463`); every auto-merged file was reviewed: the Configuration Validation gate and the maintenance conflict are
   independent blockers in `execution/eligibility.py`;
3. migration `0029_maintenance_record` collided with `0029_configuration_validation_run`; it was rebuilt as
   `0030_maintenance_record` depending on `0029_configuration_validation_run` (never applied anywhere).
   `makemigrations --check`: no changes; `migrate --plan` lists `0030` as the last `core` migration; `manage.py check`: clean.
4. On a scratch copy of the deployed database (SQLite backup API from a read-only connection, 2026-10-17; the deployed
   file's SHA-256 was unchanged afterwards): its latest applied migration was `0029_configuration_validation_run`,
   `0030_maintenance_record` was the only pending one and applied cleanly, `migrate --check` then reported nothing
   pending, and `maintenance_tick --dry-run` / one idle `maintenance_tick` pass ran against it (0 items). The copy was
   discarded. The deployed database itself was not migrated.

## 3. Modules

| Module | Responsibility |
|---|---|
| `model.py` | vocabulary: `Request`, `Flow`, `Dependency`, `Mechanism`, `DrainProof`, `Finding`, `Report`; 7-day cycle |
| `policy.py` | the existing drain mechanism per role and cell, read from `route_shield.readiness` |
| `topology.py` | pure derivation from cabling + device evidence: roles, access relations, paths (every ECMP branch), single-homed hosts, management cut |
| `collector.py` | the read-only observation (section 6) |
| `readiness.py` | the verdict per (family, direction) and the per-flow explanation rows |
| `plan.py` | drain steps, proof findings, and the immutable plan document with its hash, basis and staleness |
| `drain.py` | the drain and restore operations of a boundary router, their checks, `capture` of the pre-state |
| `executor.py` | the staged run: gates, read-back, loss checks, persistence, compensation |
| `protection.py` | VLAN 200, management interfaces and the writable scope: refused at planning and before every write |
| `gates.py` | the fail-closed entry gate |
| `lifecycle.py` | the state machine of one record |
| `store.py` | the row form of a record |
| `evidence.py` | the append-only, hash-chained evidence and its audit events |
| `service.py` | the operable workflow: request, evaluate, approve, queue, enter, leave, tick, conflict, status |
| `visibility.py` | status row and device warning |

## 4. State machine

    REQUESTED -> READINESS_BLOCKED | READY -> PLANNED -> APPROVED -> ENTERING -> ACTIVE -> RESTORING -> RESTORED
    ENTERING  -> RESTORING (trigger ENTRY_ABORT) -> ENTRY_ABORTED_RESTORED | RESTORE_FAILED_ESCALATED
    RESTORING -> RESTORE_FAILED_ESCALATED -> (operator retry) RESTORING
    REQUESTED | READINESS_BLOCKED | READY | PLANNED | APPROVED -> CANCELLED

- A new evaluation (from any pre-entry state, `APPROVED` included) discards the plan and the approval.
- `READY` becomes `READINESS_BLOCKED` when no executable plan exists (pre-state not the baseline, the devices do not
  match the tracked design, an operation would touch the protected scope).
- A refused entry leaves the record `APPROVED` with its findings.
- `ACTIVE` only when every planned direction is proven: moved, packet-loss evidence present and zero, alternate healthy.
- An entry whose worker stopped (`ENTERING` with a dead claim) is interrupted: aborted and restored, never assumed done.
- Under maintenance: `ENTERING`, `ACTIVE`, `RESTORING`, `RESTORE_FAILED_ESCALATED`.

## 5. Readiness semantics

The verdict is formed per address family and direction (`IPV4`/`IPV6` x `NORTHBOUND`/`SOUTHBOUND`) from the observed
production flows of that cell, never from a device-level "redundant" flag:

| Cell observation | Verdict |
|---|---|
| no production flow of the cell classified | `BLOCKED` `PRODUCTION_TRAFFIC_UNKNOWN` |
| a flow's activity unknown, or active with a path that cannot be followed | `BLOCKED` `PRODUCTION_TRAFFIC_UNKNOWN` |
| active traffic through the device, no mechanism for the cell | `BLOCKED` `ACTIVE_TRAFFIC_NO_LOSSLESS_DRAIN` |
| active traffic, mechanism not `READY` | `BLOCKED` `DRAIN_MECHANISM_NOT_READY` |
| active traffic, the path it would move to not verified healthy | `BLOCKED` `ALTERNATE_PATH_UNHEALTHY` |
| active traffic, mechanism `READY`, alternate healthy | `DRAINABLE` |
| quiet traffic through the device, mechanism `READY`, alternate healthy | `DRAINABLE` (preventive: the traffic must not find the device again) |
| quiet traffic, or traffic that does not pass the device | `CLEAR` |

Critical dependencies (management reachability of the other devices, VARP gateway addresses, the backup DHCP role) block
when stranded or not established. The backup DHCP server (R2) is free only when the primary (the NMAS host) reports
`active` for both IPv4 and IPv6 in the verifier's own report (`verify_dhcp_servers.nmas_status`); a missing family is not
established, any other state is not active. (Until the post-merge live observation this read a key the verifier never
returns, so every live R2 evaluation was blocked as "primary not active".) The per-flow page shows, for each flow: family, direction, source and destination, the
derived path, whether it passes the device, its activity and evidence, the redundancy that exists for it, the drain
mechanism and its state, whether a proven drain exists, the resulting readiness and the blocking reason.

What this means for the lab today (derived, not hard-coded by device name):

| Target | Cell | Mechanism | Today |
|---|---|---|---|
| R1 / R2 | IPv6 northbound | IS-IS access metric steer (`ISIS_METRIC_STEER`) | `PROVEN_NOT_AUTHORIZED`: blocks when active |
| R1 / R2 | IPv6 southbound | OSPFv3 external metric steer (`OSPFV3_EXTERNAL_METRIC_STEER`) | `NOT_READY`: one lossless cycle measured on the real sandbox without any core cover (18.1), no repetition series, not reviewed; blocks when active |
| R1 / R2 | IPv4 both | none proven (RIP) | blocks only when IPv4 production traffic is active |
| S1 / S2 | every cell | none: single-homed hosts | an active attached workload blocks and is named; quiesced is ready |
| mgmt_swt | - | - | always blocked: every managed device loses management (VLAN 200 is not redundant) |
| R5, WebServer | - | - | outside the writable managed scope: cannot be requested |

Northbound readiness never implies southbound readiness: each cell is evaluated on its own.

## 6. Observation sources

`collector.observe(device, sources)` is read-only and reuses existing primitives only:

| Fact | Source |
|---|---|
| interfaces, addresses, VARP gateway addresses, routes, OSPFv2/v3, IS-IS, RIP neighbours, BGP sessions, sanitized configuration signatures | `health.live.read_device` of every managed device (the health engine's reader) |
| roles, access relations, paths of every flow (every ECMP branch), ECMP fan-out, single-homed hosts, management cut | `topology.py` over that evidence and the tracked cabling (`srlceos01.clab.yml`) |
| traffic activity per host, family and direction | the client hosts' own unicast IP counters (`/proc/net/dev_snmp6`, `/proc/net/snmp`, `/proc/net/netstat`), read twice, 20 s apart, by `docker exec` (read-only) |
| node and link telemetry, its freshness | `health.telemetry` over the topology service (no second monitoring path); link utilization is not carried by that source and is reported as not available |
| MLAG | presence of an `mlag configuration` statement (none in this lab) |
| DHCP dependency | `health.inventory.dhcp_hosts`, `health.live.dhcp_service_state` |

Provenance: the observation stores, per device and fact group, its source, observation time, availability, completeness
and sanitized error; per host the two counter read times and the source; per ceos device the digest of its sanitized
running configuration. Raw command output is never stored. Freshness uses the one threshold system
(`health.thresholds.classify_age`); an unavailable group is `UNKNOWN`, never `FRESH`.

Fail closed, everywhere: an unreadable device, a branch of a path toward a device that could not be read, a counter that
could not be read twice (or that decreased, or is missing), a path that cannot be followed to its end on any branch with
active traffic on it, a host with no address whose counters do not prove silence: all `UNKNOWN`, all blocking. Every
address a host holds in a family is traced southbound. An observation whose devices were not read `FRESH` builds no plan
and enters nothing (`OBSERVATION_NOT_FRESH`).

Found on the real sandbox (pre-merge review) and fixed:

- IPv4 activity counted `InReceives`, which includes multicast of a group the host never joined (RIP updates on the
  client VLANs: production S1/S2 run RIP on 192.168.10/20/30) and that the kernel drops before `InMcastPkts`. Every
  host therefore looked IPv4-active forever: fail-closed, but no access-switch maintenance could ever be quiesced. IPv4
  received now counts delivered packets (`InDelivers` minus delivered multicast and broadcast).
- Management interfaces were recognized by name, `eth0` included, on every device. They are now each device's own
  (`Topology.management_ports`: the inventory's source interface, the port cabled to the management switch,
  `Management0/1` and Containerlab's `eth0`); the naming convention is only the fallback for a device without an entry.

## 7. Drain mechanisms

Only mechanisms that already exist in the topology, with the statements proven on the route-shield sandbox:

| Direction | Mechanism | Statements |
|---|---|---|
| IPv6 northbound (hosts to the core) | IS-IS metric of the switch's uplink toward the router, under the /33 shield pair toward the path about to carry the traffic | `ipv6 route 2001:db8::/33 ...`, `interface Ethernet1` / `isis metric 1000`, shield removed |
| IPv6 southbound (core to the hosts) | the router's own OSPFv3 external metric in the existing `ISIS6-TO-OSPF3` route map (the cores already have both routers as equal-cost next hops) | `route-map ISIS6-TO-OSPF3 permit 10` / `set metric 10000` |
| IPv4 | none proven | - |

Nothing is shut; the router keeps forwarding in both directions until the traffic has left it (make before break). The
captured value (`isis metric 10` today) is what the restore puts back, never a constant.

**No write to a core router (pre-merge review, 2026-10-17).** The first PR #58 head installed the R3/R4 temporary kernel
/63 covers (`route_shield.core_cover`) around the southbound step. Those covers were a guard of the static-to-IS-IS
migration only (`docs/V2_ISIS_LIVE_MIGRATION_RUNBOOK.md`: "temporary, removed by the same run"); a read-only check of
the live R3/R4 on 2026-10-17 shows no /63 cover (only the management default). Installing them for a maintenance would
create forwarding state the topology does not have in order to manufacture a lossless southbound drain: an
architectural deviation. They were removed from the maintenance drain. Now:

- `drain.operations` writes the switch and the router only; the cores' next hops are read from their routing table
  (`drain.installed_hops`), not from the cover definition;
- every environment hands R3/R4 out as `executor.CoreReader` (read methods only; any write method raises);
- `protection` refuses any operation that is a kernel cover, any statement outside the closed set of drain primitives
  (an interface's `isis metric`, an existing route map's `set metric` / `no set metric`, and the switch's /33 shield
  halves of the aggregate), and any write to a device whose platform is not cEOS -- at planning and before every write;
- the final checks prove the cores hold no non-dynamic route and no FRR configuration they did not hold before.

Without the covers FRR replaces the client routes on each core when the external metric changes (delete then add in the
kernel). Whether that loses traffic is measured on the real sandbox (section 18); `OSPFV3_EXTERNAL_METRIC_STEER`
stays `NOT_READY` until a reviewed change cites such evidence, so on the managed network an R1/R2 entry with active
southbound IPv6 traffic is refused; quiesced southbound traffic follows the ordinary policy.

### 7.1 Audit of every drain primitive

| Direction / AF | Mechanism | Exists before Maintenance? | Maintenance changes it temporarily? | Previously approved? | Verdict |
|---|---|---|---|---|---|
| IPv6 northbound | IS-IS metric of the switch uplink | yes: IS-IS on S1/S2/R1/R2 since CHG-20261012-0002; metric 10 | yes, 10 -> 1000, captured value restored | designed and proven as `ISIS_METRIC_STEER` (`drain20`, 0 of 1,018,183 lost); `PROVEN_NOT_AUTHORIZED` | kept; not executable on the managed network until authorized |
| IPv6 northbound | /33 shield pair on the switch (temporary static) | the path it points at exists (S1-VLAN99-S2-R2, which IS-IS itself chooses after the metric) | yes, installed and removed inside the step, never persisted | part of the proven `ISIS_METRIC_STEER` design (route-shield doc 2.1) | kept; it creates no new path, only bridges the switch's own route replacement. The only static routes a maintenance may name |
| IPv6 southbound | OSPFv3 external metric in the existing `ISIS6-TO-OSPF3` route map | yes: the route map and redistribution exist on R1/R2 (read live, read-only) | yes, `set metric 10000`, removed on restore | no: `OSPFV3_EXTERNAL_METRIC_STEER` `NOT_READY` | kept as a metric on an existing path; blocks active traffic until measured and approved |
| IPv6 southbound | R3/R4 kernel /63 covers | **no**: migration guard, removed when the migration completed | (was: installed and removed) | only for `STATIC_IPV6_TO_ISIS` | **removed from Maintenance Mode** (deviation) |
| IPv4 | RIP | yes | no | no RIP drain exists | no mechanism: active IPv4 blocks, quiesced proceeds |
| either | BGP (R3/R4 to R5) | yes | no | - | never touched; R5 not writable |
| either | ECMP on the cores | yes (R3/R4 to R1 and R2) | no (it is what the southbound metric selects within) | - | observed only |
| IPv4/IPv6 gateways | FHRP (VARP on S1/S2) | yes | no | - | observed: a gateway held by only the target is a stranded dependency |
| - | MLAG / VCP | not configured in this lab | no | - | observed (absent) |
| - | interface shutdown / no switchport | - | no: refused by the primitive allow-list | - | never a maintenance step |
| - | any other static route | - | no: refused by the primitive allow-list | - | never a maintenance step |

## 8. The plan

A READY record gets one immutable plan document (`plan.document`), stored in the record and in the evidence chain,
SHA-256 hashed (`plan_hash`). It names: the target and its role; the request (operator intent); the readiness verdict per
cell and the drain steps; the mechanism states; the baseline (observation time, configuration digests, protocol state,
the devices the plan leans on, the derived access relations and the captured pre-state: uplink metric, route map, running
and startup digests of S1/R1/S2/R2, the cores' static-route, FRR and boot digests, adjacencies and target next hops); the
affected flows and dependencies; every drain operation in order (device, kind, exact lines, exact inverse, the checks
before and after, the pause, the undo gates); the drain's final verification, persistence and compensation rule; the
restore guards, every restore operation in order, the restore's final and post verification and persistence; the
deadline rule; the protected scope (VLAN 200, the management interfaces per device, the writable scope).

Planning reads the devices through executor sessions (`drain.capture`) and writes nothing. Approval names the plan hash it
was shown (`PLAN_HASH_MISMATCH` otherwise). A plan is valid for 2 hours (`PLAN_EXPIRED`). At entry the plan is built
again from fresh facts; when its basis (everything except the clock and the momentary packet activity of each flow)
differs from the approved one, the plan is `STALE`, the entry is refused before anything is written, and the operator
evaluates again.

## 9. Entry (drain executor)

`service.enter`, under the record's claim:

1. fresh observation and readiness; the approved plan rebuilt and compared (stale or expired refuses);
2. mechanism readiness (`route_shield.readiness`, a reviewed constant; on the managed network a mechanism that is not
   `READY` refuses, no argument lifts it);
3. every device the plan leans on read FRESH (`health.thresholds`, `OBSERVATION_NOT_FRESH` otherwise; the same gate
   refuses a plan at evaluation); production probes and host resource gate (`route_shield.probes`, `route_shield.gates`),
   startup equal to running on the devices that will be persisted, no maintenance-only statement already present, no
   unresolved maintenance on an intersecting device;
4. the shared device locks (section 12);
5. the pre-state is stored, then `executor.Run.drive`: per operation the protection guard, the state digest unchanged
   since this run's last step, assess, apply, read-back, the after-checks, zero lost probes, the pause, zero lost probes;
   between stages the window guard;
6. final checks (exactly the planned maintenance statements, no temporary shield, cores holding nothing new),
   persistence of exactly the verified running configuration (section 10.1);
7. a fresh observation proves every planned direction moved (every production flow of the cell now avoids the device on
   a path followed to its end), zero loss and a healthy alternate; only then `ACTIVE`.

Any failure: everything applied is compensated newest first, each undo gated and verified, the startup configuration
follows the restored running one; the record ends `ENTRY_ABORTED_RESTORED` after a fresh observation shows the baseline,
or `RESTORE_FAILED_ESCALATED` with what remains. A drain that succeeded but could not be proven is taken out again by the
restore workflow (section 10). The target is never left half drained silently.

## 10. Restoration

Restoration is its own workflow, built only from the stored pre-state:

1. guards before the first write: the router is healthy enough to take traffic (access adjacency up, client prefixes by
   IS-IS, the aggregate, a Full OSPFv3 adjacency with every core); the devices that carry the traffic now are unchanged
   since the maintenance became active (for an aborted entry: since the pre-state was captured); startup equal to running,
   or still the captured pre-state startup;
2. southbound back first (the router is offered traffic only once verified healthy), then northbound under the shield
   toward the uplink; an operation already in place is accepted (an interrupted restore is finished);
3. final checks: the switch is byte-for-byte the captured state, the route map is the captured one, no maintenance
   statement remains, the cores hold nothing new; persistence;
4. post verification by a fresh observation against the pre-maintenance one (up to 3 attempts): every device that was
   reachable is (management reachability), every adjacency is back, every production interface that was up is up, every
   flow that passed the device does again and every path can be followed, no dependency is stranded that was not.

Only then `RESTORED`. Anything else is `RESTORE_FAILED_ESCALATED` with the remaining maintenance-only state read from
the devices and every finding kept; a blocked restore writes nothing and keeps the drained state.

### 10.1 Startup persistence (decision)

| Question | Answer |
|---|---|
| Why persist at all | the drained state must survive a reload inside the 7-day window: R1 is reloaded during its own maintenance (that is often the work), and an unrelated reload of S1 must not silently put traffic back on a device under maintenance |
| When | only in `Run.finish`, after every operation was read back, every after-check passed, the final checks (exactly the planned statements, no temporary shield, cores unchanged) passed and zero probes were lost; device by device, each one verified `startup == running` |
| A failure before verification | persists nothing: the startup is still the captured pre-state |
| Temporary state | never persisted: a shield is removed inside its step, and a shield still present fails the final check before persistence |
| Compensation | restores the startup this run wrote to the run's own starting startup, verified by digest |
| After a successful restore | the verified baseline running configuration is persisted and `startup == running` is verified on the switch and the router |
| Interrupted between the two devices | the restore precheck accepts either `startup == running` or the captured pre-state startup, and the restore persists both |

A process restart therefore cannot strand a drain in startup: what is persisted is only a verified drain whose record
is `ACTIVE` (with its deadline) or an entry the recovery aborts and restores.

## 11. Deadline, worker and timer

Two separate values: the requested duration (operator intent, shown, not capped, ends nothing) and the hard maintenance
cycle deadline (entry + 7 days). When the deadline passes on an `ACTIVE` record the worker starts the same restore as a
manual exit (trigger `DEADLINE`): restored when proven, escalated when not. Never a blind return.

`manage.py maintenance_tick` is one worker pass (`nmas-maintenance-tick.timer`, every minute, `Persistent=true`):

1. recover every `ENTERING` / `RESTORING` record whose claim has no heartbeat for 20 minutes (or has none): the dead
   run's probes are stopped (their run ids are in the journal), then an interrupted entry is aborted and restored and an
   interrupted restore is run again; a re-run never repeats a write blindly (every operation is assessed first and one
   already in place is accepted), and a stage interrupted with its temporary state still installed is escalated;
2. release stale claims of any other step;
3. run queued operator requests (`EVALUATE`, `ENTER`, `RESTORE`) in queue order;
4. start the deadline restore of every due `ACTIVE` record.

Every item is claimed first (a conditional update: one holder); concurrent passes never act twice; an idle pass reads one
table and builds no runtime (no NetBox, inventory or device access); an escalated restore makes the pass exit non-zero.
The timer is not installed anywhere yet: `install_maintenance_timer.sh` refuses a deployment whose database is behind.

## 12. Concurrency

- Record claim (`claim_token`, `claim_action`, `heartbeat_at`): every device-contacting step; every executor event beats.
- Device locks: the same `ExecutionDeviceLock` table the Change engine uses, now holdable by a maintenance (exactly one of
  `run` / `maintenance`, a check constraint). A Change and a drain or restore can never write to the same device at once.
- Changes during maintenance (`execution/eligibility.py`, `DEVICE_UNDER_MAINTENANCE`): execution is refused on a device
  whose maintenance is `ENTERING`, `ACTIVE`, `RESTORING` or `RESTORE_FAILED_ESCALATED`, also when its plan has no step: the
  restore puts back and verifies the state captured at entry, so a Change in between would be overwritten or read as a
  failed restore. It is also refused on every device the maintenance leans on (its switch, the other switch and router,
  the cores) while it is unresolved, which only a plan that moves traffic has. Drafting, validation, planning and
  prechecks are not affected, nor is any other device. An entry also holds the target's device lock (with no step to
  write as well), so a Change that is executing on it refuses the entry with `DEVICE_LOCKED`; the Change engine re-checks
  eligibility inside its own locks, so one that starts later sees the maintenance.

## 13. Escalation

`RESTORE_FAILED_ESCALATED` keeps the complete evidence and the remaining maintenance-only state. It refuses a new entry on
the device and on any device whose plan intersects it, and refuses Changes on both. It blocks unrelated infrastructure
only when the baseline itself became untrustworthy (`baseline_untrusted`: compensation incomplete, the restore could not
be assessed, the pre-state is missing). An operator resolves the cause and runs the restore again; the escalation stays on
record.

## 14. Evidence and audit

`MaintenanceEvidence` is append-only (row, queryset and manager refuse update and delete) and hash-chained per record:
`entry_digest` covers the record, sequence, kind, time, actor, transition, payload digest and the previous entry's digest;
`evidence.verify` (and `nmas_maintenance verify`) recomputes it and detects a removed or altered entry, also below the
ORM. Entries: request, observation (with the readiness report), plan, approval, queue, every refusal, transitions, the
entry run, the restore run with its verification, stale-claim releases, and the step journal (`STEP`: "before X" written
ahead of each write and "after X" once it is verified, durable at once, so a worker that dies leaves exactly where it
stopped; `evidence.journal` reads it and the recovery records it). Each entry except a journal step also writes one `AuditEvent`
(`MAINTENANCE_TRANSITION`, `MAINTENANCE_REFUSED`, `MAINTENANCE_QUEUED`) with ids, states, the plan hash and finding codes;
website requests are additionally audited as `WEB_ACTION` with the authenticated user. No configuration secret is stored.

## 15. Pages and RBAC

Under Automation -> Maintenance Mode, in the existing theme. GET pages read the database and the tracked topology; they
contact no device.

| Page / action | Route | Permission |
|---|---|---|
| list (under maintenance, blocked, pending, history) | `maintenance_list` | View |
| overview / active (timings, requested window, hard deadline, dependencies, runs, locks, evidence) | `maintenance_detail` | View |
| readiness (per cell, per flow, protocols, provenance and freshness) | `maintenance_readiness` | View |
| plan (hash, validity, every operation, checks, inverse, compensation) | `maintenance_plan` | View |
| history (evidence chain, lifecycle) | `maintenance_history` | View |
| request | `maintenance_request` (GET form, POST) | Edit (Operator) |
| cancel before entry | `maintenance_cancel` | Edit (Operator) |
| evaluate readiness (queued) | `maintenance_evaluate` | Validate (Operator) |
| approve the plan, by its hash | `maintenance_approve` | Approve (Approver) |
| enter maintenance (queued) | `maintenance_enter` | Execute (Executor) |
| restore (queued) | `maintenance_restore` | Execute (Executor) |

Every action is POST with CSRF, an explicit confirmation, and for cancel / enter / restore the record id typed again.
The browser supplies only the record, the plan hash it was shown and the confirmation. No new permission exists; the
Maintenance models carry no Django model permissions. Authentication, website MFA and the route table are the existing
ones (`core.middleware`, `identity.policy`).

## 16. Configuration Validation: a separate bounded workflow (decision)

Maintenance changes are **not** ordinary NMAS Changes and do not pass through Configuration Validation. Reasons:

- An ordinary Change carries permanent intent toward a desired configuration; a maintenance drain is temporary operational
  state that must be reversed to exactly the captured pre-state, with a mandatory deadline. Validating it as intent would
  either reject it (it contradicts the intended templates) or make the drained state look like accepted intent.
- Its safety proof is traffic, not configuration: per-flow readiness, a probe matrix with zero loss, moved paths. The
  Configuration Validation bundle cannot express that.
- The statements are a closed, reviewed set (`drain.py`), not operator-authored text; there is nothing for a generic
  validator to add.
- `route_shield` set the precedent: a controlled transition is not runnable by the general execution engine
  (`TRANSITION_CHANGE_NOT_GENERIC`).

Substitute controls, control by control:

| Configuration Validation control | Maintenance Mode equivalent |
|---|---|
| immutable, hash-bound candidate | immutable plan document, SHA-256 `plan_hash`; approval and entry name it; rebuilt at entry and compared (`PLAN_STALE`) |
| exact candidate / step representation | every operation's device, exact lines, exact inverse, checks and pauses are in the plan |
| platform validation | `protection`: a write only to a cEOS device of the writable scope; cores are `CoreReader` |
| syntax validation | `protection.statement_violation`: a closed set of statement shapes (addresses parsed); anything else is refused at planning and before every write. The shapes were applied and read back on real cEOS 4.36.2F (section 18) |
| capability gating | `route_shield.readiness` per mechanism (reviewed constant) |
| fresh preconditions | fresh observation at entry, `OBSERVATION_NOT_FRESH`, plan staleness, probes and host gate, startup in sync |
| human approval | Approver role, by plan hash |
| read-back | every operation is assessed again after apply (`READ_BACK_MISMATCH`) and its after-checks read the device |
| compensation | newest first, gated and verified per step |
| audit evidence | hash-chained evidence, step journal, audit events |

No Maintenance path reaches a device without these: the operator command `nmas_maintenance enter/exit` and the worker
call the same `service.enter` / `service.leave`, which build and check the plan and run the guard before each write.
GitHub never executes devices: nothing in this workflow is dispatched to GitHub.

What is preserved instead: hash binding (the plan hash names exactly what is approved and entered), the immutable plan,
precheck gates and read-back per operation, human approval (Approver role) separate from execution (Executor role), no
device execution from GitHub (nothing in this workflow is dispatched to GitHub), and complete, verifiable evidence.
Ordinary Changes keep their Configuration Validation gate untouched; a Change on a device under maintenance is refused
by the separate `DEVICE_UNDER_MAINTENANCE` blocker.

## 17. Contract changes made deliberately

- `test_contracts`: the Maintenance executor is the second caller of `save_startup` (the drained state and the restored
  state must survive a reload: an unrelated reboot of S1 must not silently undo a drain). The general engine still
  cannot reach it.
- `route_shield.readiness` gains `OSPFV3_EXTERNAL_METRIC_STEER = NOT_READY`; `test_route_shield` pins it.
- `ExecutionDeviceLock.run` is nullable with a `maintenance` holder (exactly one, check constraint).
- `test_services` records the graduated "Maintenance Mode" Automation section.

## 18. Sandbox and tests

`core/tests/test_maintenance_sandbox.py` is the production-shaped sandbox: the REAL service, plan, `drain.capture` /
`operations`, route-shield checks, executor, compensation, collector and worker against a simulated post-migration lab
(S1/S2/R1/R2 derive their IPv6 routing tables from their configured statements; R3/R4 are the real
`KernelCoverExecutor` over an emulated kernel). Scenarios, all passing:

| # | Scenario | Result |
|---|---|---|
| 1 | READY with valid existing redundancy (R1, active IPv6 both ways) | plan of 4 operations: 3 northbound (S1), 1 southbound (R1); nothing on a core |
| 2 | BLOCKED: active traffic lacks a lossless drain | S1 with H1 active: `ACTIVE_TRAFFIC_NO_LOSSLESS_DRAIN`; R1 with active IPv4: `DRAIN_MECHANISM_NOT_READY` |
| 3 | allowed because quiesced | S1 enters and leaves with zero writes |
| 4 | successful drain | uplink metric 1000, external metric 10000, shields gone, no command sent to a core, startup = running |
| 5 | traffic moved | H1 north now `S1 > S2 > R2 > R3\|R4 > R5`; south avoids R1; 0 probes lost |
| 6 | successful restore | every device, startup and core kernel equal to the start; southbound offered first |
| 7 | failure during entry | R1 rejects its metric: compensated, `ENTRY_ABORTED_RESTORED`, exact start state; also a lost probe |
| 8 | deadline restore | nothing at the requested window; `RESTORED (DEADLINE)` at entry + 7 days |
| 9 | failed restore | R1's adjacency down: nothing written, `RESTORE_FAILED_ESCALATED`, intersecting entry refused, unrelated not frozen; retry restores |
| 10 | stale facts | an out-of-band change on S2: `PLAN_STALE`; an unreadable core: `PRODUCTION_TRAFFIC_UNKNOWN`; an expired plan: `PLAN_EXPIRED`; zero writes |
| 11 | VLAN 200 never altered | unchanged on every device; no command names it; a VLAN 200 operation is refused before sending; the management switch is never ready |
| 12 | R5 / out of scope never targeted | request refused; only S1 and R1 written; an R5 operation is refused by the guard |

The sandbox found and fixed one fail-open defect of the inherited collector (an ECMP branch toward an unreadable device
was dropped silently), and the production wiring test found that the inherited cabling parser failed on the tracked
`srlceos01.clab.yml` (host link).

Focused tests: `test_maintenance_mode` (foundation), `test_maintenance_live` (topology, collector, drain plan, executor,
service, worker, commands, production wiring), `test_maintenance_web` (RBAC per role, CSRF, POST-only, rendering, audit),
`test_maintenance_sandbox`.

### 18.1 Real cEOS / FRR sandbox (pre-merge review)

Topology: the disposable `isisbx` sandbox of the route-shield work (`docs/evidence/v2-route-shield/sandbox/up.sh`,
`configure.sh`, `core_frr.sh`; plain Docker, every object labelled `nmas-sandbox=isisbx`, internal networks, never part of
`srlceos01`): R1, R2, S1, S2 and the edge R5 (`pe`) as cEOS 4.36.2F, R3/R4 as FRR 8.4.4 with the production daemons and
the kernel as forwarding plane, hosts H1-H4 and the web server. It was first taken through the production history with
the NMAS migration (`nmas_lifecycle.py forward`: 48 operations, 0 of 858,898 probes lost, both cores left with 0 covers),
so it is in the post-migration state of production: IS-IS access, `ISIS6-TO-OSPF3`, OSPFv3 ECMP on the cores, no cover.
A VLAN 200 sentinel was added to S1/S2. Harness: `docs/evidence/v2-maintenance-mode/sandbox/run.py` -- the product's
service, collector, drain, executor, protection and worker unchanged, the health reader and cEOS executor over `docker
exec`, an isolated SQLite database; summaries in `docs/evidence/v2-maintenance-mode/results/`. Where a scenario needs a
mechanism to be READY the harness passes it to the collector for that run; the reviewed constants were not changed.

| # | Scenario | Result on real devices |
|---|---|---|
| 1 | read-only observation | role, access relations and cores derived; every flow classified; every path complete (`S1 > R1 > R3\|R4 > R5`); alternates healthy; all device digests unchanged |
| 2 | READY with existing redundancy | R1, active IPv6 workload both ways: PLANNED, 4 operations on S1 and R1 only |
| 3 | active traffic without a safe drain | production constants: both IPv6 cells `DRAIN_MECHANISM_NOT_READY`; northbound READY only: northbound `DRAINABLE`, southbound `BLOCKED` (device blocked); active IPv4: IPv4 blocked; S1 with active hosts: `ACTIVE_TRAFFIC_NO_LOSSLESS_DRAIN`; nothing written |
| 4 | quiesced traffic | all hosts quiet, northbound READY / southbound NOT_READY: only the northbound cell planned and entered |
| 5 | drain | 3 operations applied and read back on S1 (shield, `isis metric 1000`, shield removed); 0 of 121,086 probes lost; H1 north proven moved to `S1 > S2 > R2 > R3\|R4 > R5`; R1, R3, R4 untouched; S1 startup = running (drained) |
| 5b | both directions, workload running, **no core cover** | `ACTIVE`: 4 operations (the southbound `set metric 10000` on R1 included), 0 of 147,916 probes lost; restored with 0 lost; cores' kernel, FRR running and boot configuration unchanged. One cycle |
| 6 | restore | `RESTORED`: 0 of 132,607 probes lost, verification clean, every device's running and startup equal to the start, startup = running on R1, R2, S1, S2 |
| 7 | entry failure (injected after the metric) | compensated newest first (metric, then shield), both `COMPENSATED`; `ENTRY_ABORTED_RESTORED`; exact baseline |
| 8 | restore failure (S2 changed out of band while active) | `RESTORE_FAILED_ESCALATED` before any write, the drained metric kept, no device lock left; after the operator removed the change, the retried restore `RESTORED` the exact baseline |
| 9 | stale observation (real reads served 150 s old) | `OBSERVATION_NOT_FRESH`: no plan; nothing written |
| 10 | stale plan (S2 changed after approval) | `PLAN_STALE` (also `OUT_OF_BAND_CHANGE`): entry refused, still `APPROVED`, nothing written |
| 11 | VLAN 200 | an injected VLAN 200 operation: `PROTECTED_SCOPE_VIOLATION`, no plan; the sentinel's digest identical before and after every scenario |
| 12 | R5 | request refused `TARGET_OUTSIDE_WRITABLE_SCOPE`; an R5 operation refused by the guard; R5 running and startup unchanged |
| 13 | worker retry | a second ENTER request `RECORD_BUSY`; two concurrent worker passes: one entered, the other did nothing; one entry run; repeated and idle passes did nothing; the queued restore ran once |
| 14 | deadline | the worker's `DEADLINE` item restored the exact baseline |
| 11b | worker process killed (SIGKILL) mid-drain | at a step boundary (after the shield was removed: the drain in place, unpersisted): while the claim was fresh no pass touched it; once stale the worker recovered it, stopped the dead run's probes, restored the exact baseline: `ENTRY_ABORTED_RESTORED`. Inside the northbound stage (after the metric, shield still installed): the recovery escalated with nothing written (`INTERRUPTED_STAGE_STATE_PRESENT`, the exact remaining statements listed); after the operator's manual recovery the retried restore returned the exact baseline |

The real sandbox found, beyond the cover deviation, four defects that the simulation and the unit tests could not; all
are fixed with regression tests:

1. IPv4 activity read RIP multicast as production traffic (section 6);
2. management interfaces were recognized by the name `eth0` on every device (section 6);
3. the probe files of `route_shield.probes` were named by generation only: a killed worker's still-running probes wrote
   into the next run's files and the recovery measured 93,052 "lost" probes. Each probe instance now has its own files,
   and every probe ends on its own after 900 s;
4. those orphaned probes still doubled the probe load and read as loss. Every run now journals its probe run id, and the
   recovery stops exactly the dead run's probes (only processes that still are `ping`) before it measures.

Both of the last two failed closed (the recovery escalated with nothing written), as designed. A fifth finding was a
design weakness rather than a defect: a recovery facing the drain's own shield (interrupted inside a stage) used to
attempt the restore, which failed its gate and compensated. Such a state is now refused before any write.

## 19. Limitations

- Not live-verified. The southbound mechanism has one lossless cycle on the real sandbox, not a repetition series;
  `OSPFV3_EXTERNAL_METRIC_STEER` stays `NOT_READY` and `ISIS_METRIC_STEER` stays `PROVEN_NOT_AUTHORIZED`, so on the
  managed network an R1/R2 entry with active IPv6 traffic through the router is refused today. IPv4 has no drain.
- An escalated record refuses an entry (not a plan) on an intersecting device: the real sandbox planned R2 while R1 was
  escalated; the entry gate (`PRIOR_MAINTENANCE_UNRESOLVED`) is where it is refused (simulated scenario 9).
- A drain interrupted inside its northbound stage (its temporary shield still installed) is not restored
  automatically: the recovery escalates with nothing written and lists the exact remaining statements (the plan holds
  their inverse). An interruption at a step boundary is recovered automatically. The step journal (section 14) records
  where the worker stopped.
- Approval and execution are separate roles (Approver authorizes a plan hash; Executor runs entry and restore), but the
  same human may hold both: two-person separation is not enforced (the lab has one operator account). Requester,
  approver and executor are each recorded in the evidence. This is a known limitation, not an assumption.
- Quiescence is "0 unicast packets in the 20 s counter window": a workload that is idle for longer than that and then
  resumes is classified quiesced. A counter that cannot be read twice, decreased (reset) or is missing is `UNKNOWN`.
- Link utilization is not available from the telemetry source; activity comes from the hosts' own counters.
- Production probes at the proven rates load this host (route-shield doc 10.4); the probe set is the route-shield one.
- The worker runs one item at a time: a long drain delays other queued requests.
- The evidence chain is tamper-evident, not tamper-proof: someone with database write access can rebuild a chain.

## 20. Prerequisites for a controlled live pilot

1. Review and merge; promote the deployment checkout; back up the deployed database; apply `0030`; restart `nmas-web`.
2. A read-only production observation (`nmas_maintenance request` + `readiness` on a quiet target, e.g. S1 in a quiet
   window) to compare the collector's derived topology, paths and provenance with the real devices.
3. A repetition series on the real sandbox (as `drain20`: 20 drains and restores of R1 and of R2, both directions, with
   the probe matrix and TCP/HTTP sessions) of the cover-free southbound mechanism; only then may an operator decide
   `OSPFV3_EXTERNAL_METRIC_STEER` (and authorize `ISIS_METRIC_STEER`) in a reviewed change of `route_shield/readiness.py`.
4. Install the worker timer (`install_maintenance_timer.sh`) and prove one idle tick.
5. Pilot first on a target whose traffic is quiesced (no writes), then an approved, observed drain in a window.

## 21. Reuse by Commission / Decommission

Nothing below is maintenance-specific; a Commission / Decommission phase can call it directly:

- `collector.observe` and `topology` (roles, paths, dependencies, provenance) for "what depends on this device";
- `readiness.evaluate` and `flow_rows` for "can its traffic be moved away" (decommission) or "is nothing using it yet";
- `drain.capture` / `drain.operations` / `executor.Run` for a verified drain with compensation, and the same with
  `drain=False` for bringing a device into service under the same proofs;
- `plan.document` / `digest` / `staleness` for any hash-bound, reviewable plan;
- `protection.violations`, the claim / lock helpers of `service.py`, `evidence.append` / `verify`, and the worker shape
  of `tick`.

## 22. Operating it

    python manage.py nmas_maintenance request   --device S1 --actor <name> --reason "<why>" --hours 4
    python manage.py nmas_maintenance readiness --id MNT-000001          read-only observation, verdict and plan
    python manage.py nmas_maintenance show      --id MNT-000001          the plan hash is in the output
    python manage.py nmas_maintenance approve   --id MNT-000001 --actor <name> --plan-hash <hash>
    python manage.py nmas_maintenance enter     --id MNT-000001 --actor <name> --confirm MNT-000001
    python manage.py nmas_maintenance exit      --id MNT-000001 --actor <name> --confirm MNT-000001
    python manage.py nmas_maintenance verify    --id MNT-000001          recompute the evidence chain
    python manage.py maintenance_tick [--dry-run]                          one worker pass
