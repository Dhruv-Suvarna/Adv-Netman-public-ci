# V2 Maintenance Mode: lifecycle foundation

> **Superseded as the current description by `docs/V2_MAINTENANCE_MODE.md` (2026-10-17)**, which completes this foundation
> (observation, plan, executor, restore, worker, pages). This document is kept as the record of the foundation as
> committed in `d3b76bf`; its section 8 ("Not done") is closed there. The migration is now `0030_maintenance_record`.

Status of this document: product logic and mocked tests only. **No maintenance transition was executed anywhere, and
nothing in this package can execute one.** No device, deployed database, NetBox or routing change. Package:
`web/core/services/maintenance_mode/`; tests: `web/core/tests/test_maintenance_mode.py`.

## 1. The rule

    ACTIVE PRODUCTION TRAFFIC + NO PROVEN LOSSLESS WAY TO MOVE IT = BLOCK

Missing redundancy alone is not a failure. When the relevant production traffic is verified quiesced, the device is
ready for maintenance whether or not another path exists. There is no device-level "redundant" flag.

    SAFE DRAIN = production traffic moved away AND alternate healthy where one is needed
                 AND zero observed production loss AND no critical dependency stranded

## 2. Modules

| Module | Content |
|---|---|
| `model.py` | `Request` (device, operator, reason, requested duration as the operator's intended window), `Flow` (workload, family, direction, traffic class, ACTIVE / QUIESCED / UNKNOWN), `Dependency`, `Mechanism`, `DrainProof`, `Finding`, `Report` |
| `policy.py` | role of each device and its existing drain mechanisms (section 4) |
| `readiness.py` | the verdict per (family, direction): `CLEAR`, `DRAINABLE` or `BLOCKED`, with the workloads that block |
| `plan.py` | one drain step per cell with active production traffic, and the proof each step owes |
| `gates.py` | the fail-closed gate in front of entry |
| `lifecycle.py` | the record of one maintenance and its state machine, deadline included |
| `visibility.py` | the status row and the warning for pages that change a device |

## 3. Lifecycle states

`REQUESTED` -> `READINESS_BLOCKED` or `READY` -> `PLANNED` -> `APPROVED` -> `ENTERING` -> `ACTIVE` -> `RESTORING` ->
`RESTORED`. Also: `ENTRY_ABORTED_RESTORED` (the drain was not proven clear and the device is verified back),
`RESTORE_FAILED_ESCALATED` (maintenance-only state remains; an operator must act) and `CANCELLED` (before entry only).

A new readiness evaluation discards the plan and the approval. A refused entry leaves the record `APPROVED` and keeps
the findings. A device counts as under maintenance in `ENTERING`, `ACTIVE`, `RESTORING` and `RESTORE_FAILED_ESCALATED`.

## 4. Policy of this lab

| Device | Cell | Mechanism | State today |
|---|---|---|---|
| R1, R2 | IPv6 northbound | existing IS-IS access-side metric steering | read from `route_shield.readiness` (`ISIS_METRIC_STEER`: `PROVEN_NOT_AUTHORIZED`) |
| R1, R2 | IPv6 southbound | existing OSPFv3 core-side steering | `NOT_READY` (not built, not measured) |
| R1, R2 | IPv4, both directions | RIP | `NOT_READY` (no proven drain); blocks only when the cell carries active production traffic |
| S1, S2 | every cell | none: single-homed hosts are allowed topology and nothing moves them | active attached production traffic blocks and names the workload; quiesced traffic is ready |

R1/R2 may be `ACTIVE` in maintenance only when every planned direction has a proof: moved, loss evidence present and
zero, alternate healthy. Northbound alone is not enough.

## 5. Entry gate

Entry is refused on any of: production traffic classification unknown (a cell with no classified production flow
included), a required mechanism not `READY`, an alternate not verified healthy where traffic must move, a stranded or
unestablished critical dependency, readiness not current, production probes not healthy, packet-loss evidence missing,
any packet lost, stale baseline, out-of-band change (or not established), unresolved earlier maintenance (or not
established). No function takes a force, skip, ignore or override argument; a test asserts that.

## 6. Timing

Two separate values. The **requested duration** is the operator's intended window; it is shown (`requested_until`,
`past_requested_window`) and ends nothing. The **maintenance cycle deadline** is entry time plus 7 days. At that
deadline `on_deadline` moves the record to `RESTORING` (trigger `DEADLINE`): the restore workflow for the
maintenance-only changes is owed and its result must be validated. `finish_restore` needs the list of maintenance-only
statements still present to be stated explicitly; with any restore finding (an unhealthy device is one) or anything
remaining the record becomes `RESTORE_FAILED_ESCALATED`. A device is never returned to service blindly.

### 6.1 Scope of an escalated restore

`RESTORE_FAILED_ESCALATED` on one device refuses a new entry on: that device; a device whose plan intersects it
(`policy.intersecting`: the path its traffic would move to and its attached devices, or the set the caller's own
forwarding and dependency analysis supplies); and every device only when the restore was closed with
`baseline_untrusted`, meaning the unresolved state makes the topology baseline untrustworthy. An unrelated device
proceeds on its own readiness.

## 7. Storage and visibility

`core.models.MaintenanceRecord` (migration `0029_maintenance_record` at the time, now `0030_maintenance_record`; not applied to any deployed database) is the
stored form of a lifecycle record; `store.save` / `store.load` round-trip it. `store.notices` lists the devices under
maintenance with who requested it, the reason, the requested duration, the state, the block reasons, the requested window, the safety
deadline and the restore state. The context processor `maintenance_context` puts that list on every Device Builder and Automation
page, and `base.html` renders one plain line per device. A deployment without the table shows no notice.

## 8. Not done

- No page or command creates, evaluates, approves or exits a maintenance; only the lifecycle functions and the store
  exist. The notice is the only thing an operator can see.
- The notice lists every device under maintenance on those pages; it is not filtered to the device being edited, and
  nothing refuses a Change for a device under maintenance.
- `store.start_due_restores` moves overdue records to `RESTORING`, but no timer or scheduler calls it, and no restore
  workflow exists to run afterwards.
- No collector produces `Flow`, `Dependency`, `gates.Facts` or `DrainProof` from the live network.
- No executor: neither directional drain is run by this package. The southbound OSPFv3 component and any IPv4 drain
  are not built or measured; the northbound component is proven on the sandbox and not authorized.
- Nothing was validated on the sandbox or on production. Only the focused unit tests were run locally; the full
  regression and hosted Tier-3 were not.
