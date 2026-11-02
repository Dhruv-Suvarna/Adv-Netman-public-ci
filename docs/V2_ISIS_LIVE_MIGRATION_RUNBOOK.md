# Runbook: static IPv6 to IS-IS (execution only)

**Not executed.** `STATIC_IPV6_TO_ISIS` is `READY` in `web/core/services/route_shield/readiness.py`, following the
explicit operator authorization of 2026-10-12. `READY` does not allow arbitrary execution: a live run still goes
through the deployed NMAS lifecycle (Change -> validation -> Plan -> Precheck -> approval -> execute) and still needs
a fresh passing production precheck, healthy probes and host resource gate, and the explicit live-window
authorization against the deployed commit. Permanent IS-IS scope is R1, R2, S1 and S2 only; R3 and R4 remain OSPFv3
and receive only the temporary migration covers. `ISIS_TO_STATIC_IPV6_REVERT` (section 8) and `ISIS_METRIC_STEER`
remain `PROVEN_NOT_AUTHORIZED`; no option of the command changes a readiness state.
This runbook describes the code as it is (`web/core/services/route_shield/`), so that the live change needs no
design decision and no command outside NMAS. Design and evidence:
`docs/V2_LOSSLESS_ROUTE_SHIELD.md`. IPv4 and RIP are not touched by any step.

Every command below is `python manage.py nmas_isis_migration <subcommand>` run from the deployed `web/` directory.
There is no option that forces a step, skips the precheck, ignores probe loss or disables the automatic reverse path.

## 1. Affected devices

| Devices | What is written | Kind |
|---|---|---|
| **R1, R2, S1, S2** (permanent devices) | routing configuration: IS-IS, boundary policy, removal of the superseded IPv6 statics | permanent |
| R1, R2, S1, S2 | their startup configuration, once, after the final state is verified (`copy running-config startup-config`) | permanent |
| R1, R2, S1, S2 | shield static routes and floating static routes | temporary, removed by the same run |
| **R3, R4** (temporary-cover devices) | three kernel routes each (`ip -6 route`, not FRR configuration) | temporary, removed by the same run |

Nothing else is written anywhere. On R3 and R4 nothing is persisted: `/etc/frr/frr.conf` and the FRR running
configuration must be identical before and after, and the run verifies both.

Authorizations required before section 4 step 6 (given by the operator on 2026-10-12; the live-window authorization
must name the deployed commit that is executed):

1. Live routing changes on R1, R2, S1, S2, including their startup configuration.
2. Temporary kernel routes on R3 and R4.
3. The readiness state of `STATIC_IPV6_TO_ISIS` changed to `READY` by a reviewed code change that cites the
   authorization (done: `readiness.py`).

## 2. The six temporary routes on R3 and R4

The inventory is a constant of the code (`core_cover.APPROVED_COVERS`). No setting, argument, Change field or plan row
can add to it; the production executor refuses any other prefix, next hop, interface or device.
Next hops are the link-local addresses of R1 (`fe80::21c:73ff:fe20:ab82`) and R2 (`fe80::21c:73ff:fe17:db73`).

| Device | Prefix | Next hops | Install (sent by NMAS) | Removal (sent by NMAS) |
|---|---|---|---|---|
| R3 | `2001:db8:10::/63` | R1 on `Vlan101`, R2 on `Vlan103` | `ip -6 route add 2001:db8:10::/63 nexthop via fe80::21c:73ff:fe20:ab82 dev Vlan101 nexthop via fe80::21c:73ff:fe17:db73 dev Vlan103` | `ip -6 route del 2001:db8:10::/63` |
| R3 | `2001:db8:20::/63` | same | same with `2001:db8:20::/63` | `ip -6 route del 2001:db8:20::/63` |
| R3 | `2001:db8:30::/63` | same | same with `2001:db8:30::/63` | `ip -6 route del 2001:db8:30::/63` |
| R4 | `2001:db8:10::/63` | R1 on `Vlan102`, R2 on `Vlan104` | `ip -6 route add 2001:db8:10::/63 nexthop via fe80::21c:73ff:fe20:ab82 dev Vlan102 nexthop via fe80::21c:73ff:fe17:db73 dev Vlan104` | `ip -6 route del 2001:db8:10::/63` |
| R4 | `2001:db8:20::/63` | same | same with `2001:db8:20::/63` | `ip -6 route del 2001:db8:20::/63` |
| R4 | `2001:db8:30::/63` | same | same with `2001:db8:30::/63` | `ip -6 route del 2001:db8:30::/63` |

For each of the six routes:

| Item | Value |
|---|---|
| Expected pre-state | no route for the /63; nothing else inside it except the client /64; the client /64 installed by OSPFv3 toward exactly the two next hops above; both are Full OSPFv3 neighbours on those interfaces; neither interface is the one the default route uses |
| Expected installed state | exactly one route for the /63, protocol `boot`, those two next hops; a lookup of `<prefix>:1::1` leaves toward R1 or R2 |
| Verification | read back from the kernel after install and after removal; OSPFv3 adjacencies unchanged; FRR running configuration and `/etc/frr/frr.conf` unchanged; non-dynamic kernel routes equal to the pre-state after removal |
| When removed | after the last change on R1/R2/S1/S2, once both cores have left every client /64 untouched for 120 s and no temporary line remains on any access device |
| If the pre-state is different | the precheck blocks; a route that already exists is never overwritten |
| If install or verification fails | the run stops before any change on R1/R2/S1/S2 and removes the covers it installed |
| If a later stage fails | the covers stay while the old routing is restored, then are removed |
| If removal fails or is not safe | the run ends `FAILED_COMPENSATION_INCOMPLETE`, names every route that remains, and blocks every further transition run |

## 3. The resource window

The window is a state of the host, checked by NMAS itself (`gates.window_host_gate`) in `dry-run`, in `precheck` and
again inside `execute` before the first write. A failed condition is the blocker `HOST_RESOURCE_GATE_FAILED` with the
reason in words.

| Condition | How NMAS checks it | Operator action before the window |
|---|---|---|
| Challenge Console stopped | no `python -m challenge_console` process | stop it (with explicit approval) |
| No disposable sandbox | no container named `isisbx-*` or `clab-nmas-cap-validation-*` | remove them by exact name |
| No test suite | no `manage.py test`, `pytest` or `tier3.py` process | wait for it or stop it |
| No swap in use | swap used is 0 MB | find what is swapping; do not start |
| Host CPU below the warning state | before the probes start: busy CPU over 5 s below `warning_pct` of `monitoring/config/cpu_threshold_policy.yml` (70 %) | stop the unrelated job |
| Load at the quiet baseline | before the probes start: 1-minute and 5-minute load at or below 9.09 (measured quiet maximum 6.06 on this 8-CPU host, times 1.5; `docs/evidence/v2-route-shield/closure/host_baseline.json`) | wait until it settles |
| With the probes running | the dedicated probes alone take the host to 80-84 % CPU and a load above 17 (measured: `closure/host_probes.json`). From then on CPU must stay below `critical_pct` (90 %); load is recorded, not judged; every other condition still applies | none |
| Between two stages of `execute` | the same gate again before every stage and before the final validation. It must fail `consecutive_samples` (3) samples in a row to count, a single busy sample is a spike. Every probe flow must also have delivered at least half of the samples its rate calls for since the previous stage | none: the run aborts by itself before the next stage (section 6) |

The probe rates are the proven ones (IPv6 100 and 50 per second, IPv4 10 per second) and are not lowered for the
window: they are what made sub-millisecond route replacement gaps visible.
| Memory | at least 4 GB available | none expected |

Unrelated batch jobs are not detected by name; they show up as CPU or load above the gate. The dedicated migration
probes are started by NMAS and stay running for the whole transaction.

After the window: restart the Challenge Console, verify one process, 4 of 4 connectivity panes and the counters
collector.

## 4. The transaction, stage by stage

| # | NMAS command | Evidence produced | Success | Failure | Automatic compensation | Operator decision |
|---|---|---|---|---|---|---|
| 0 | `dry-run --output <file>` | the read-only report: transport, identity, digests, routes, R3/R4 kernel state, probes, NetBox, tracked intent | `PRODUCTION_READ_ONLY_DRY_RUN = PASS` and `PRODUCTION_PRECHECK = PASS` | either is not `PASS`; the report names each failed check or blocker | none needed: nothing is written or recorded | proceed only on two `PASS` |
| 1 | `create --actor <name>` | a Change with its six targets | prints `CHG-...` | none | none | none |
| 2 | `validate --change CHG --actor <name>` | an immutable validation run | `PASS`, no findings | `BLOCKED` with findings; nothing can be planned | none | fix the cause |
| 3 | `plan --change CHG --actor <name>` | the immutable plan: 48 operations, each PERMANENT or TEMPORARY, plus the persistence stage | 48 operations, 24 temporary | `VALIDATION_NOT_CURRENT` | none | validate again |
| 4 | `precheck --change CHG --actor <name>` | an immutable precheck run from fresh reads of all six devices, with the probes running | `PASS` | `BLOCKED` with every blocker; no approval is possible | none | resolve each blocker and run it again |
| 5 | `approve --change CHG --actor <approver> --confirm CHG --ack window_authorized --ack core_kernel_routes --ack access_routing_configuration --ack host_quiet` | a lifecycle event binding the approval to this plan and this precheck | lifecycle `READY_TO_DEPLOY` | a missing acknowledgement, a wrong confirmation, or a precheck that did not pass | none | this is the go / no-go decision |
| 6 | `execute --change CHG --actor <name> --confirm CHG` | the execution run, one result per operation, the postcheck run with the persistence evidence | outcome `SUCCEEDED`, `temporary_remaining` empty, `persistence.status` `VERIFIED`, probes lost 0 | any other outcome (section 6) | section 6 | none during the run |
| 7 | `show --change CHG` | the run, its persistence status, every operation and its status | every operation `DEPLOYED` | section 6 | none | none |

`execute` is accepted only when all of these hold; each is a named blocker otherwise:

| Requirement | Blocker |
|---|---|
| the exact Change id typed as `--confirm` | `CONFIRMATION_MISMATCH` |
| the plan is the one the current design produces, from a passing validation, and not older than 12 hours | `PLAN_STALE` |
| the approved precheck is the latest passing one and not older than 15 minutes | `PRECHECK_NOT_PASSED`, `PRECHECK_STALE` |
| the Change is approved for this plan, with all four acknowledgements | `NOT_APPROVED` |
| no earlier run of this Change is unresolved, and no transition run of any Change is | `PRIOR_RUN_UNRESOLVED`, `PRIOR_TRANSITION_UNRESOLVED` |
| the transition is `READY` | `TRANSITION_PROVEN_NOT_AUTHORIZED` |
| inside the lock: the precheck passes again (probes healthy, host gate, startup equal to running) and no device changed since the approved one | the precheck's own blockers, `CONFIG_BASELINE_STALE` |

## 5. Stages inside `execute`

One lock on all six devices. Every operation is assessed, applied, read back and verified; the probes are read after
every operation; before every stage the host gate and the progress of every probe flow are checked again; any
failure starts the reverse path of section 6.

| Stage | Devices | Content | State | Success condition | On failure |
|---|---|---|---|---|---|
| Precheck (inside the lock) | all six | the precheck of step 4 again | read-only | no blocker; every digest equal to the approved precheck | `BLOCKED`, nothing written |
| Core covers | R3, R4 | the six routes of section 2 | temporary | each route is exact and forwards; adjacencies unchanged | covers removed, `FAILED_ROLLED_BACK` |
| VLAN99 IPv6 | S1, S2 | `ipv6 address 2001:db8:110:3::1/64` and `::2/64` on `Vlan99` | permanent | read back | reverse path |
| IS-IS formation | R1, R2, S1, S2 | `router isis NMAS` (Level-2), IS-IS on the access links and VLAN99 | permanent | adjacencies R1-S1, R2-S2, S1-S2 up | reverse path |
| Boundary policy | S1, S2, R1, R2 | client SVIs passive; prefix list, route-maps and the three aggregate anchors; aggregate into IS-IS; IS-IS into OSPFv3 with external distance 130 | permanent | IS-IS holds every prefix while the statics still own the routes | reverse path |
| Shields, side R1/S1 | S1, R1 | `2001:db8::/33` and `2001:db8:8000::/33` on S1; `2001:db8:10::/63`, `:20::/63`, `:30::/63` on R1 | temporary | shields programmed; lookups go through them | reverse path |
| Protected removal | S1, R1 | S1 static aggregate removed; R1 floating copies (distance 250) added; R1 client statics removed; floating copies removed once IS-IS owns the routes; old `redistribute static` and `STATIC6-TO-OSPF` removed | permanent, floating copies temporary | IS-IS owns the aggregate and the client routes | reverse path |
| Shield removal | R1, S1 | R1 shield removed, then S1 shield | temporary | take-over next hops answer; shields gone; forwarding by IS-IS | reverse path |
| The same three stages for side R2/S2 | S2, R2 | next hops `2001:db8:110:2::1` and `2001:db8:110:2::2` | as above | as above | reverse path |
| Core cover removal | R3, R4 | the six routes removed | temporary | no temporary line on any access device; both cores quiet for 120 s; each route verified absent | reverse path; a cover that cannot be removed safely stays and is reported |
| Final validation | all six | read-only | read-only | IS-IS owns the aggregate and the client routes; every permanent statement present; nothing temporary anywhere; R3/R4 kernel state, FRR running configuration and `/etc/frr/frr.conf` equal to the pre-state; probes lost 0 | reverse path, `POSTCHECK_FAILED_ROLLED_BACK` |
| Persistence | R1, R2, S1, S2 | `copy running-config startup-config`, one device at a time | permanent | before the write the running configuration is still the verified one; after it startup, running and intended digests are equal, no temporary statement and every permanent change is in the startup configuration; R3/R4 boot configuration unchanged | reverse path, then the startup configuration of every device already written is written back and must equal its pre-run digest |

The run is `SUCCEEDED` only after the persistence stage is verified. The final configuration digests of R1, R2, S1 and
S2 are recorded as the new baseline (`permanent_intent.baseline_digests`).

## 6. Failure behaviour (automatic)

| Where it fails | What NMAS does | Outcome |
|---|---|---|
| Steps 0 to 5, or the in-lock precheck | nothing is written | `BLOCKED` |
| While installing the covers | removes the covers it installed, verifies the pre-state | `FAILED_ROLLED_BACK` |
| Anywhere after that, including a lost probe | undoes every applied operation in reverse order, each by its exact inverse and read back: shields back first, statics restored under them, shields removed, IS-IS and VLAN99 addresses removed, then the covers after the 120 s quiet period. Configuration digests of R1, R2, S1, S2 and the kernel, FRR and boot state of R3, R4 must equal the pre-state | `FAILED_ROLLED_BACK` |
| Between two stages: the host reached the critical CPU condition or left another window condition (`WINDOW_CONDITION_LOST`), or a probe flow stopped delivering samples (`PROBE_TIMING_UNRELIABLE`) | the next stage is not started; the same reverse path. Samples that were never taken are not read as "nothing lost" | `FAILED_ROLLED_BACK`, or `FAILED_NO_MUTATION` before the first write |
| Final validation or persistence | the same reverse path; every startup configuration this run wrote is written back from the restored running configuration and must equal its pre-run digest | `POSTCHECK_FAILED_ROLLED_BACK` |
| A step of the reverse path cannot be proven safe or restored, or a startup configuration cannot be written back | stops there; lists every temporary statement and route still present and every device whose startup configuration is not restored; no transition run of any Change is accepted until it is resolved | `FAILED_COMPENSATION_INCOMPLETE` or `POSTCHECK_FAILED_COMPENSATION_INCOMPLETE` |

After an `..._COMPENSATION_INCOMPLETE` outcome: read `temporary_remaining` and `persistence` from `show`, and treat it
as an incident. The remaining items are named exactly; what to do about them is a decision for the operator on duty,
not a step of this runbook.

## 7. After `SUCCEEDED`: the permanent source of truth

Runtime is not the only copy. `source-of-truth` prints this list and the current state of the tracked templates.

| Target | Kind | Update | Verification |
|---|---|---|---|
| startup configuration of R1, R2, S1, S2 | permanent intent | done by the run (persistence stage) | run report: `persistence.status` `VERIFIED` |
| `templates/R1.cfg.j2`, `R2`, `S1`, `S2` | permanent intent | a normal reviewed pull request that replaces each with its copy in `docs/evidence/v2-route-shield/intent/templates/` (generated from the plan by `source_of_truth.intent_template`; superseded IPv6 statics and the static redistribution removed, IS-IS baseline added) | `source-of-truth` and `dry-run` report every template `POST_MIGRATION` with no temporary statement |
| NetBox IPAM and `netbox/ipam.yml` | permanent intent | the prefix `2001:db8:110:3::/64` on VLAN 99 is already recorded; in the same pull request add the interface addresses S1 `Vlan99` `2001:db8:110:3::1/64` and S2 `Vlan99` `2001:db8:110:3::2/64` (deliberately absent until a device holds them) | `dry-run`: `netbox_vlan99_ipv6.state` `POST_MIGRATION`, `conflicts` empty |
| NMAS Golden bundle | permanent intent | a new Golden captured from the migrated devices with the existing Golden workflow | its configuration digests equal `permanent_intent.baseline_digests` of the run |
| R3/R4 covers, shields, floating statics | temporary execution evidence | none, ever: they exist only in the run report (`temporary_state`) | `temporary_remaining` empty; R3/R4 boot configuration digest unchanged |

Until the template pull request is merged, a rebuild from the tracked templates would configure the superseded
static routing again. Merge it in the same window, after `SUCCEEDED` and before anyone redeploys.

Then: restart the Challenge Console; verify one process, 4 of 4 connectivity panes and the counters collector.

## 8. Revert of a completed migration (operator-initiated)

Not automatic compensation: the migration `SUCCEEDED` and the operator later decides to return to the static baseline.
It is a Change of its own that names the migration run, and it is refused while `ISIS_TO_STATIC_IPV6_REVERT` is
`PROVEN_NOT_AUTHORIZED`.

| # | NMAS command | Success | Failure |
|---|---|---|---|
| 1 | `create-revert --actor <name> --migration-run <run id>` | prints the revert `CHG-...`; the run must be a `SUCCEEDED` migration with verified persistence and not already reverted | `REVERT_SOURCE_NOT_SUCCEEDED`, `REVERT_BASELINE_UNAVAILABLE`, `REVERT_ALREADY_RUN` |
| 2 | `validate`, `plan` | 48 operations: the migration's operations in the opposite order, each replaced by its exact inverse | as in section 4 |
| 3 | `precheck` | `PASS`: the devices are still exactly what the migration run recorded, IS-IS owns the routes, the covers are absent, probes and host gate pass | `REVERT_BASIS_DRIFTED` and the blockers of section 4 |
| 4 | `approve` with the Change id and the four acknowledgements | `READY_TO_DEPLOY` | as in section 4 |
| 5 | `execute` | `SUCCEEDED`: running and startup configuration of R1, R2, S1, S2 equal to the pre-migration digests the migration run recorded; nothing temporary; probes lost 0 | the reverse path returns the devices to the migrated state |

Order inside `execute`: the six R3/R4 covers in; per side the shields back, the old statics and the static
redistribution restored under them, the shields removed; the IS-IS policy, the IS-IS process and the VLAN99 addresses
removed; the covers out after the 120 s quiet period; final validation; persistence. After a revert the tracked
templates must be the pre-migration ones again (revert the template pull request).

## 9. Activation checklist

The binary checklist with its current values is in `docs/V2_LOSSLESS_ROUTE_SHIELD.md`, section 11. Any item false:
production migration blocked.
