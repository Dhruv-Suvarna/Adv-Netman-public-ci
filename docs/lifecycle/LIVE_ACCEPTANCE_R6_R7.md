# R6 / R7 live commissioning acceptance: gates, runbook and disruptive-change prerequisites

**Status:** the source integration is complete: PR #12 is `9208f9d` and PR #13 is `fdd1de1` on `main`. The executable
acceptance gates below are implemented and were run read-only against production.

**No live R6/R7 acceptance has been performed.** R6 and R7 stay IN_SERVICE / ADMITTED (Lab 8: ADM-000001, ADM-000003). Every
live step below needs a separately approved, device-specific live-change scope (§4).

## 1. The tool

`manage.py nmas_commissioning_acceptance` (`core/services/commissioning/acceptance.py`) is read-only:
- On SQLite it sets `PRAGMA query_only` for the command.
- It contacts no device and performs no lifecycle step.
- It composes verdicts that the lifecycle services already own; it does not add a parallel check framework.

```
check  --devices R6 R7 [--scope S.json] [--flow SRC:DST:PROTO:FAMILY[:HOP+HOP]]... [--completed DEV:OP]... [--json] [--out F]
plan   (same arguments)     prerequisites + the ordered governed steps, each with its rollback and the gate re-run after it
scope-template --devices R6 R7     an UNAPPROVED nmas.lifecycle.live-scope/1 skeleton
```

**Exit codes:**
- `0` READY: every precondition the scope names holds. READY is **not** an authorization.
- `3` BLOCKED: a prerequisite is missing.
- `2` FAIL: an invariant is broken. Stop.

**PLANNED** marks a prerequisite that a scoped step itself produces, for example a bootstrap authorization or a management
path. It does not block. Once you pass `--completed DEV:OP` for that step, the prerequisite must really hold, so a failed step
cannot hide behind PLANNED.

**Running it in production:** run it with production's environment file (`nmas-lab89/prod_run.sh` semantics, `settings_demo`).

## 2. Gates

| Gate | What it requires | Source (reused) | Assignment item |
|---|---|---|---|
| ORDER | The requested order equals the dependency order (R6 before R7) and there is no cycle | `commissioning.dependencies.order` | R6-before-R7 |
| LIVE_SCOPE | A schema-valid scope:<br>• second-person approval<br>• aware, open window<br>• allowed operations only<br>• `retain_management`<br>• continuity mode<br>• declared flows | this module | device/session authorization |
| TRAFFIC_BASELINE | Every declared flow has a PASSED traffic-runner run no older than `--freshness` (default 900 s) | `TrafficRun` (traffic runner) | existing production flows |
| LIFECYCLE | The lifecycle evidence chain is intact. The stage projection is recorded as the baseline. | `devices.stage_report` | topology and lifecycle states |
| IDENTITY | Identity is VERIFIED from independent evidence, with the SSH host key pinned | `stage_report.identity_verdict` | identity and admission evidence |
| DEPENDENCY | Every ACTIVE dependency is satisfied. An attachment on an NMAS-onboarded upstream needs a declared dependency. | `dependencies.unmet` / `satisfied` | R6-before-R7 |
| UPSTREAM | Every live attachment rides on a trusted upstream. Single-homing is recorded. | `devices.attachments.upstream_problems` | upstream neighbor |
| BOOTSTRAP_AUTHORIZATION | No open grant outside a scope. A scoped re-bootstrap needs a grant that covers the window. Closed grants must be refused now. | `ztp.policy.authorization_problems` | authorization and expiry |
| DHCP_LEASE_RELAY | Lease and renewal state (an OVERDUE window fails). For a scoped re-bootstrap: a valid bootstrap network, a declared trusted relay, and a documented native retry. | `ztp.lease.status` / `renewal_status` / `renewal_window_seconds`, `ztp.policy.stored_network_problems` / `relay_for` | DHCP expiry, renewal, relay |
| ISOLATION | Upstream isolation is complete:<br>• every check OK (read-back, L2, management plane, routing, attachment, traffic)<br>• IPv4 and IPv6 elements, so OSPFv2 and OSPFv3 are excluded<br>• an exact inverse plan<br>• not DRIFTED, UNCERTAIN or BLOCKED<br>• RELEASED for an in-service device | `IsolationPolicy` records | unauthorized adjacencies/routes; upstream rollback |
| MANAGEMENT | An approved, HEALTHY in-band path: `ROUTED_VRF` with a VRF, or `VLAN_ADJACENT_SWITCH` on VLAN 200. No reconciliation pending. | `ManagementPath`, `stage_report.management_verdict` | Management VRF / VLAN 200 |
| QUIESCENCE | No DEPLOYING Change (FAIL) and no pending Change (BLOCKED) on the device or its upstreams. The device is ready and not in maintenance. | `ChangeTarget`, `stage_report.readiness_verdict` | — |
| CONTINUITY | A flow that traverses a single-homed device cannot be ZERO_LOSS; it needs an approved outage window. | UPSTREAM + scope | traffic continuity, paths and redundancy |

## 3. Current production result (read-only, 2026-11-28)

**Inputs.** The gates read a consistent SQLite backup of the production database taken 2026-11-28 ~07:12Z. Both production's
code lineage (staged copy) and `main` give identical verdicts. The declared flows were:
- H5→WebServer: ICMP and TCP_CONNECT, IPv4 and IPv6, through R4, R6 and R7.
- H1→H2: ICMP, IPv4.

Overall verdict: **BLOCKED** (checked without a scope, as today no live step is authorized).

**PASS for both R6 and R7:**
- ORDER (R6, R7)
- LIFECYCLE (chains intact)
- IDENTITY
- DEPENDENCY (R7→R6 ATTACHMENT_UPSTREAM, "admitted by ADM-000001")
- UPSTREAM (R4:eth4 legacy; R6:Ethernet2)
- BOOTSTRAP_AUTHORIZATION (BAUTH-000001 REVOKED and BAUTH-000002 CONSUMED and expired: both refused now)
- DHCP_LEASE_RELAY (post-delivery leases ended)
- ISOLATION (ISO-000001 nftables on FRR R4 and ISO-000002 ACLs on cEOS R6: RELEASED, all six checks OK, dual-stack, exact inverse)

**BLOCKED**, the prerequisites in §4:
- MANAGEMENT (`MANAGEMENT_PATH_NOT_APPROVED`: neither device has any `ManagementPath`)
- QUIESCENCE (`CHANGE_PENDING`)
- CONTINUITY (`NO_REDUNDANT_PATH`)
- TRAFFIC_BASELINE (`TRAFFIC_BASELINE_STALE`: last runs 2026-11-03)
- LIVE_SCOPE (none)

With a scope that re-bootstraps R6, its old network `demo-r6-ztp` also BLOCKS (`BOOTSTRAP_NETWORK_INVALID`): R6's own addresses now
lie inside it. Nothing FAILs.

## 4. Exact prerequisites before any disruptive R6/R7 step

1. **Approved live scope**: `scope-template` filled in by the operator.
   - It names the device-specific operations, the window and the change id.
   - `approved_by` must be a different authorized person.
   - The scope digest is recorded in the change record.
2. **Close the two stale pending Changes on R6.** Both are READY_TO_DEPLOY leftovers whose work completed through later Changes
   (ISO-000002 RELEASED, ADM-000003 ADMITTED):
   - `CHG-20261027-0008` "Trusted isolation of R7 on R6:Ethernet2"
   - `CHG-20261103-0005` "Production admission of R7: release isolation on R6:Ethernet2"

   Close or supersede them through the website's governed workflow. Never edit them in the database.
3. **In-band management for R6 and R7**: register a Management VRF path or a VLAN 200 adjacent-switch path for each device,
   have a second person approve it, and let it probe HEALTHY.
   - This must happen before any other step, because the scope requires management to be retained.
   - Today both devices are reached only through the commissioning SSH proxies (`nmas-demo-ssh-proxy-r6/r7`).
4. **Fresh traffic baseline**: run every scope flow through the traffic runner within 15 minutes of step 1. Today's last runs
   are 2026-11-03.
5. **Continuity decision.** Both devices are single-homed:
   - R6 attaches to R4:eth4.
   - R7 attaches to R6:Ethernet2.
   - H5 sits behind R7.

   So any re-onboarding of R6 or R7 interrupts H5's traffic. ZERO_LOSS is impossible without a redundant physical path, and
   adding links is excluded. The scope must therefore be `APPROVED_OUTAGE_WINDOW` with an explicit `max_outage_seconds`, limited
   to the flows that traverse R6/R7. Every other flow, such as H1→H2, must stay at zero loss.
6. **For a re-bootstrap (`ZTP_REBOOTSTRAP`):**
   - a new bootstrap authorization with second-person approval, whose `valid_until` covers the window;
   - a new, valid bootstrap network: the historical ones now contain the devices' own addresses, and the config root must be
     an isolated NMAS directory;
   - a declared trusted relay on the upstream;
   - each device's saved startup-config as the restore artefact.
7. **R6 completely ADMITTED before any R7 step.** The ORDER and DEPENDENCY gates enforce this, and R7's attachment is refused
   (`UPSTREAM_NOT_TRUSTED`) while R6 is commissioning.

## 5. Runbook

Generate it with `nmas_commissioning_acceptance plan --devices R6 R7 --scope S.json`.

1. **Step 0:** `check` must exit 0. Record its digest.
2. **Each scoped operation, in this order:**
   - MANAGEMENT_PATH_APPROVE
   - BOOTSTRAP_AUTHORIZE
   - ISOLATION_ENFORCE
   - ZTP_REBOOTSTRAP
   - DHCP_RENEWAL_WINDOW
   - COMMISSIONING_CONFIGURE
   - ADMISSION

   Each one runs through its own governed workflow and is followed by `check ... --completed` with every step done so far.
   - **Pass:** the workflow reports success, no gate FAILs, MANAGEMENT stays PASS, and the protected flows stay within the scope's
     continuity.
   - **Fail:** run that operation's rollback (`acceptance.OPERATIONS`), then re-run the gate until it matches the step-0
     baseline:

     | Operation | Rollback |
     |---|---|
     | ISOLATION_ENFORCE | isolation release of the exact inverse |
     | ZTP_REBOOTSTRAP | saved startup-config restore and DHCP policy rollback |
     | COMMISSIONING_CONFIGURE | commissioning abort and restore |
     | ADMISSION | a failed verification restores the upstream byte-identical and re-verifies isolation |
     | MANAGEMENT_PATH_APPROVE | revoke the path |
     | BOOTSTRAP_AUTHORIZE | revoke the authorization |
3. **Close:**
   - `nmas_lifecycle_report --verify` passes.
   - Every device is ADMITTED / IN_SERVICE.
   - Every flow is FRESH_PASS.
   - The lifecycle evidence is exported.

The isolated-fixture rehearsal of the same sequence, R4→R6→R7 analogue UP1→NEW1→NEW2 (`ACCEPTANCE.md` §2.1), is the reference
for each step's expected evidence.
