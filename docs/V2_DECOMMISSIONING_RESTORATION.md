# NMAS V2 Phase 7 — Governed decommissioning, recovery and restoration

Code: `web/core/services/decommission/` (`eos`, `readiness`, `observe`, `dependencies`, `service`), the governed single-device
transaction `web/core/services/isolation/transaction.py`, the management resolver `web/core/services/management/resolve.py`, views
`web/core/decommission_views.py`, models `DeviceConfigSnapshot`, `DecommissionRecord`, `RestorationRecord` (migration `0035`).
Live evidence of this release: `docs/evidence/v2-phase7-closure/` (earlier runs: `docs/evidence/v2-phase7-9/phase7/`).

**Production runtime stays disabled.** `NMAS_DECOMMISSION_RUNTIME` is unset in production; every execute / recovery / restoration
call there refuses with `DECOMMISSION_RUNTIME_UNAVAILABLE`. Nothing in this phase changed a production device, database or service.

## Flow

```
request -> evaluate (baseline snapshot + live observation + dependency analysis + plan) -> approve (second operator, plan hash, TTL)
        -> execute (re-observe; refuse if readiness changed) -> DECOMMISSIONED | ROLLED_BACK | BLOCKED | UNCERTAIN
UNCERTAIN -> plan_recovery (read-only) -> approve_recovery (second operator) -> execute_recovery -> ROLLED_BACK + IN_SERVICE
          -> reconcile (read-only: device digest == baseline -> ROLLED_BACK; else stays UNCERTAIN)
DECOMMISSIONED -> restoration request -> check -> approve -> execute -> RESTORED (successor device, origin RESTORED)
```

Every device write goes through the governed single-device transaction: declared inverses, plan-hash approval by a second
operator, a preflight baseline digest, and digest-verified compensation newest first.

## Readiness verdicts

| Verdict | Meaning | Device action |
|---|---|---|
| `QUIESCENT` | no monitored production flow crosses the device in any family / direction | remove routing, shut production ports |
| `REDUNDANT_TRANSITION` | traffic crosses it, an existing OSPF process is FULL, and a live-derived alternate avoids it | `max-metric router-lsa` (v2 + v3), wait until every flow left the device, then removal under a continuous probe |
| `BLOCKED` | active traffic without a lossless alternate, blind spot, stranded dependency, conflicting operation | nothing; per-blocker operator instruction ("stop or relocate the traffic outside NMAS") |

Management interfaces are never touched. Non-cEOS platforms refuse with `DECOMMISSION_PLATFORM_NOT_IMPLEMENTED`. Pre-admission
devices are retired without device writes.

## What this release adds

**Lost-session handling (transaction).** A session failure is one of `SESSION_ERRORS` (executor transport codes, `OSError`,
`EOFError`, timeouts, Paramiko `SSHException`). The step whose call did not return is recorded as *possibly applied*.
Compensation then runs on one fresh session from the run's own executor factory (same transport, same identity). Each undo is
still digest-verified. When no session can be opened, nothing is sent and every applied step stays `NOT_COMPENSATED`: the record
goes `UNCERTAIN` and never claims a rollback. A fresh session has no assess-time state, so a declared-inverse statement takes its
exact inverse from the frozen plan (`CeosExecutor._compensate_config_block`).

**Ordering of the cost-out undo.** The cost-out is undone last. It is undone only after the re-enabled links carry FULL OSPF
adjacencies in every baseline family, plus one settle period (`await_adjacencies`). This applies both to in-run compensation and
to governed recovery. The transaction emits `before` / `compensate:<key>` for each undo so the decommission service can wait
there. A hook that raises is recorded (`compensate-hook FAILED`) and the undo still runs. This was found live: removing the
cost-out early lost IPv6 probes in recovery (`43a`, 1145/1200) and in in-run compensation (`40a`, 2926/3000). Both now lose 0.

**Governed recovery of an UNCERTAIN run.**
- `plan_recovery` is read-only. It derives the inverse of what the device still holds from the run's own frozen operations, using
  `eos.render_recovery`. A partly present effect is a `RECOVERY_CONFLICT`, and nothing is planned for it.
- Recovery needs a second-operator approval of the plan hash.
- `execute_recovery` runs through the transaction and requires the baseline digest itself. It marks the unresolved run
  `reconciled`, an append-only `AuditEvent`, which reopens the device for later governed changes.

**Retirement.**
- A decommissioned device's `DeviceCredential` rows get `rotation_enabled=False`, status `BLOCKED` and code
  `DEVICE_DECOMMISSIONED`. The secret stays in its provider so an exact restoration remains possible.
- The management resolver answers `DEVICE_RETIRED` (BLOCKED) for a name whose newest record is terminal. Health, rotation and
  executors cannot fall back to the inventory address.
- Only a governed restoration reaches the device, inside `resolve.retired_device_access(name)`. Even then, only a device that
  had no registered management paths is reachable: those paths were retired with it, so the restoration stops at
  `RESTORATION_REENROLLMENT_REQUIRED` without contacting the device.
- A successful restoration reinstates exactly the credential rows that are still in the retired state.

**Concurrency.**
- While another execution holds the device (the real `DeviceMutex` / `ExecutionDeviceLock`), execute ends `BLOCKED` with
  `DEVICE_LOCKED` and no write. Once the lock is released, the record is re-evaluated and approved again.
- Two operators executing the same approved record produce one governed run. The stale copy is refused.

## Restoration

Restoration never bypasses isolation or commissioning. It requires:
- the snapshot's integrity;
- the same platform;
- no live-name conflict;
- free attachment ports;
- the predecessor's verified identity (equal SSH host key) and admission.

Otherwise it stops at `RESTORATION_REENROLLMENT_REQUIRED`. Success requires the exact baseline digest and FULL adjacencies within
the timeout (`await_adjacencies`).

## Live acceptance (isolated fixture `labs/decommission-isolated`, cEOS 4.36.2F, this release's code)

Topology:
- HA–E1–{T1, T2 (cost 100)}–E2–HB, with STUB off E2;
- dual-stack OSPFv2/v3;
- NMAS runs in the fixture's own network namespace and manages every router over SSH on a fixture-only management bridge
  (10.254.70.0/24).

Probes are continuous HA→HB pings (IPv4 and IPv6) during the operation. Nothing outside the fixture was touched. The fixture
settings disable the configuration-validation gate (`NMAS_CONFIGURATION_VALIDATION_ENABLED = False`), as in every isolated
fixture.

| Evidence | Case | Result |
|---|---|---|
| 10 / 11 | STUB, quiescent, non-redundant | QUIESCENT → DECOMMISSIONED. Restore SUCCEEDED with the exact baseline digest; OSPF FULL to E2 in both families. |
| 20 / 21 | E2, gateway of active traffic | BLOCKED in all four cells (IPv4/IPv6 × north/southbound, `DECOMMISSION_TRAFFIC_BLOCKED`, cause `ALTERNATE_PATH_UNHEALTHY`) with the operator instruction; running-config unchanged; then cancelled. |
| 30 | T1 carries traffic, alternate T2 | REDUNDANT_TRANSITION → DECOMMISSIONED. Traffic moved to E1>T2>E2 in both directions and families. Probe 3000/3000 IPv4 and 3000/3000 IPv6. After retirement the resolver answers `DEVICE_RETIRED`; a fresh executor session refuses with `NOT_CONFIGURED`; the running-config is unreadable through NMAS. |
| 31 | T1 restore | SUCCEEDED, exact baseline digest, E1 back via T1. Self-approval refused (`RESTORATION_SELF_APPROVAL`). |
| 40 | T1, the session dies right after the device accepted `shutdown Ethernet2` | FAILED_ROLLED_BACK. Compensation ran on a fresh session; the adjacency wait was recorded before the cost-out undo. Digest equals the baseline. Probe 3000/3000 IPv4, 3000/3000 IPv6. |
| 40a | the same case before the compensation adjacency wait | FAILED_ROLLED_BACK, IPv6 2926/3000 (the defect fixed here) |
| 42 | T1, the management link goes down mid-run (no session can be opened) | FAILED_COMPENSATION_INCOMPLETE → `UNCERTAIN`. Nothing sent, no false rollback claim. Probe 3000/3000 / 3000/3000 (traffic stayed on T2). Management link restored afterwards. |
| 43 | governed recovery of 42 | UNCERTAIN → ROLLED_BACK, IN_SERVICE, digest equals the baseline. Unresolved runs on T1: 1 → 0. Probe 1200/1200 IPv4, 1200/1200 IPv6. |
| 43a | the same recovery before the adjacency wait | IPv6 1145/1200 (the defect fixed earlier in this phase) |
| 44 | a new decommission of T1 after recovery | evaluates REDUNDANT_TRANSITION again (the device is not stranded), then cancelled |
| 90 / 91 / 99 | lifecycle facts, records, index | — |

`credentials_retired` is empty in the live run because the fixture authenticates with environment credentials and has no
`DeviceCredential` rows. Retirement and reinstatement of rows are covered by `test_decommission_retirement`.

## Tests

- `test_decommission_lost_session`: lost responses before and after apply, a fresh-session compensation, no session, the
  recovery plan / approval / execution, `RecoveryOrderTests`, `CompensationOrderTests`, and the transaction helpers.
- `test_decommission_retirement`: the resolver blocks a retired name; the restoration scope; re-enrollment when paths existed;
  credential retire and reinstate.
- `test_decommission_concurrency`: device lock held; two operators with the same record.
- `test_decommission_service`: the Phase 7 contract suite.

## Known limitations

- cEOS only. Only OSPF stub-router is a recognised traffic-moving mechanism; BGP / RIP transitions are BLOCKED.
- In the fixture, routers are observed through NMAS's own SSH executor sessions over the management bridge (read-only `show`
  commands). Only the two end hosts' probes and interface counters run through the fixture (`nsenter` into their namespaces);
  the hosts stand in for production traffic and are not managed devices. In production, `NMAS_DECOMMISSION_RUNTIME` names the
  observer and probe implementation.
- Restoration of a device that had registered management paths needs re-enrollment: its paths are retired with it and are not
  revived automatically.
- `NMAS_DECOMMISSION_RUNTIME` must stay unset in production until an operator approves a production runtime.
