# Phase 17 — Structured Execution: Complete and Partial (UAT)

Phase 17 is the first phase allowed to configure a device. It executes **only the structured Configlets of the CURRENT, validated,
prechecked Phase-14 plan**, on an **explicit operator POST**, in the plan's own order, and records exactly what happened. It is a
reusable Python engine (`web/core/services/execution/`, facade `execution_service.py`); Django views are thin adapters.

It is **not** raw/arbitrary CLI (Phase 18), Golden/Probation bundles (Phase 19), soak/promotion (Phase 20), general rollback/removal
tooling (Phase 21) or from-scratch reconstruction (Phase 22). No lifecycle state changes, no NetBox write, no Git/GitHub action.

Contents: 1 Architecture · 2 Eligibility · 3 Scope · 4 Preparation · 5 Complete · 6 Partial (UAT) · 7 Outcomes · 8 Compensation boundary ·
9 Platform support · 10 Precheck · 11 Postcheck and settling · 12 AUTO/IPAM recheck · 13 Persistence · 14 Concurrency · 15 Security ·
16 Audit and notifications · 17 UI / operator workflow · 18 Tier-3 · 19 Verification evidence · 20 Known limitations.

## 1. Architecture

```
 Django view / CLI / future orchestrator
        │  execute_change(change, actor=…)            (the ONLY mutating entry point; one call site: the POST view)
        v
 execution/engine.py
   1 eligibility.py      read-only gate → stable blocker codes           (BLOCKED run recorded if refused)
   2 locking.py          RUNNING run + per-device locks, atomically      (DB UNIQUE constraints)
   3 prepare             recheck gate in-lock · connect · AUTO recheck · assess EVERY Configlet · (Complete) prove compensation
   4 apply               plan order · write-ahead result row · stop at first failure
   5 verify              Phase-15 postcheck on the executed scope, bounded settling poll
   6 compensate          Complete only · reverse order · read-back verified
   7 finalise            one immutable outcome · locks released · audit · notification (persist first, Slack second)
        │
        └─ executors/    ceos.py (Netmiko config mode) · linux.py (docker exec argv) · registry.py · state.py (pure evidence model)
```

Reused, not reimplemented: validation/plan currency (`change_validation_service`, `change_plan_service`), the precheck
(`health_service.run_change_precheck` → `OperationalCheckRun`), requirement verifiability (`health_service.normalize_plan`), the
postcheck engine (`evaluate_requirements`, now with a `cfg_ids` scope and a separable `record_postcheck_run`), the live read
allowlists (`health.live.read_device`) for previous-state capture *and* compensation read-back, the inventory
(`health.inventory`), the notification service, `secret_policy`, and the Phase-13 addressing derivation for the AUTO recheck.

## 2. Eligibility (all gates are evaluated; every blocker has a stable code, a fixed message and a remediation)

| Gate | Blocker code(s) |
|---|---|
| lifecycle ∈ {Draft, Validated, Ready to deploy} (nothing in Phases 13–15 advances it, so Draft must be executable) | `CHANGE_LIFECYCLE_NOT_EXECUTABLE` |
| operator confirmed the Change's own mode | `MODE_CONFIRMATION_MISMATCH` |
| validation exists, is CURRENT (intent **and** sources, read-only), PASS / PASS_WITH_WARNINGS | `VALIDATION_NEVER_RUN`, `VALIDATION_STALE`, `VALIDATION_NOT_PASSING` |
| a plan exists, is CURRENT, pinned to the current validation, provenance hashes/engine consistent | `PLAN_MISSING`, `PLAN_STALE`, `PLAN_PROVENANCE_INVALID` |
| a precheck was run **for this plan**, permits (PASS / PASS_WITH_WARNINGS), is younger than `EXECUTION_PRECHECK_MAX_AGE_SECONDS` (900) and no execution attempt happened after it | `PRECHECK_MISSING`, `PRECHECK_WRONG_PLAN`, `PRECHECK_NOT_PERMITTING`, `PRECHECK_EXPIRED`, `PRECHECK_BEFORE_LAST_EXECUTION` |
| plan order/dependencies consistent; plan non-empty | `PLAN_ORDER_INVALID`, `PLAN_EMPTY` |
| target devices are inventory-managed and platform-consistent (NEW_DEVICE targets are refused) | `TARGET_DEVICE_UNRESOLVABLE`, `PLATFORM_MISMATCH` |
| every Configlet has a SUPPORTED apply path | `PLATFORM_EXECUTION_UNSUPPORTED` |
| Complete: compensation SUPPORTED for every Configlet and every requirement verifiable | `COMPLETE_COMPENSATION_UNAVAILABLE`, `COMPLETE_POSTCHECK_UNVERIFIABLE` |
| Partial: five acknowledgements + explicit `through` scope | `UAT_ACK_MISSING`, `UAT_SCOPE_REQUIRED`, `UAT_SCOPE_INVALID` |
| VLAN 200 stays static (defence in depth beyond Phase 13) | `VLAN200_AUTO_FORBIDDEN` |
| no unresolved / already-applied history for this plan | `PLAN_STATE_UNRESOLVED`, `PLAN_ALREADY_APPLIED` |
| no concurrent run / device overlap | `EXECUTION_IN_PROGRESS`, `DEVICE_LOCKED` |

Nothing is refreshed silently: a stale validation, plan or precheck **blocks** and the message says what to re-run. Refusals are
recorded as an append-only `BLOCKED` run (or an audit event when no plan exists) — visible in history, never notified. A management-interface
Configlet is a **warning** (`TOUCHES_MANAGEMENT_INTERFACE`). The gate is re-evaluated (intent level) *inside* the lock.

## 3. Scope

The Phase-14 plan is the authority; nothing is re-planned or re-ordered.

* **Complete** — the entire plan.
* **Partial (UAT)** — an **ordered prefix** of the plan up to an explicit `through` Configlet. Repository evidence defines no subset
  semantics (the five acknowledgements speak of "partial success may remain applied" and "dependent stages may stop", i.e. an ordered run that
  halts), so the conservative reading is used: a prefix of a topological order is dependency-closed by construction, and closure is still
  verified explicitly (a scope whose prerequisite is not inside it is refused, never guessed). The `through` value is only a lookup key
  against the plan's own CFG ids.

## 4. Preparation — before the first mutation

Connect every device (read-only), recheck AUTO addresses (§12), then `assess` every Configlet: capture its **previous state from the current
device state** (Phase-15 evidence groups), decide `APPLY` / `SKIP_SATISFIED` (state already holds; nothing sent, nothing to compensate) /
`REFUSE`, and whether exact compensation is provable. Any failure here means the first mutation never happens: an operational failure
(cannot connect/read) → `FAILED_NO_MUTATION`; a proof failure (capability, unrestorable state, AUTO) → `BLOCKED`. Bounded previous-state facts
are persisted on each result and referenced from `Configlet.previous_state_ref` (replacing Phase 14's `UNKNOWN_DEFERRED`); no rollback text is fabricated.

## 5. Complete

Application-level transaction — **not** a claim of a native distributed ACID transaction. Contract: prove the whole scope can be undone →
apply in plan order → stop at the first failure → the Phase-15 postcheck must confirm the intended state → otherwise compensate what **this run**
applied, in reverse order, verifying each undo. Success requires: every Configlet applied or already satisfied, none UNKNOWN/skipped, a
completed postcheck whose result is PASS/PASS_WITH_WARNINGS. Exit status 0 is never success. Missing evidence is never PASS: a postcheck that is
INCOMPLETE fails the run and compensates. Because an unverifiable requirement (routing-process definition, BGP network, hostname, …) could never
confirm success, Complete is **refused up front** for plans containing one (`COMPLETE_POSTCHECK_UNVERIFIABLE`).

## 6. Partial (UAT)

Exact mode name preserved. All five model acknowledgements (`uat_ack_*`) must be supplied **in the same POST** (never pre-ticked, never
inherited from an earlier run); on an executing run they are recorded on the Change with actor and time. Execution is in plan order, stops at
the first failure, **preserves** the successful prefix and never rolls back. The run records what succeeded, where it stopped, what stayed
unapplied and what lies outside the requested scope. The postcheck evaluates only the **executed** Configlets (future Configlets are not demanded);
after a failure it evaluates the preserved prefix as informational evidence. A run that completed its requested scope is a success *for that scope*
(`UAT_SCOPE_APPLIED`); it is never presented as Complete.

## 7. Outcomes (`ExecutionOutcome`; deliberately not validation/precheck words)

| Outcome | Meaning |
|---|---|
| `SUCCEEDED` | Complete: all applied, postcheck confirmed. |
| `UAT_SCOPE_APPLIED` / `_UNVERIFIED` / `_POSTCHECK_FAILED` | Partial scope applied; postcheck PASS / INCOMPLETE / FAIL. Never rolled back. |
| `FAILED_PARTIAL_APPLIED` | Partial stopped at a failure; earlier work preserved; the failed Configlet may be partly applied. |
| `FAILED_NO_MUTATION` | Failed before any device change (connection/read failure, first Configlet rejected with no effect, nothing to undo). |
| `FAILED_ROLLED_BACK` / `POSTCHECK_FAILED_ROLLED_BACK` | Complete failed (apply / postcheck); compensation verified. |
| `FAILED_COMPENSATION_INCOMPLETE` / `POSTCHECK_FAILED_COMPENSATION_INCOMPLETE` | Compensation incomplete or unproven — reported, never PASS; the plan becomes `PLAN_STATE_UNRESOLVED`. |
| `BLOCKED` | Refused before any device change. |
| `INTERRUPTED` | Lease expired while RUNNING (crash); device state unknown; plan becomes unresolved. |

Per-Configlet result statuses: `APPLIED`, `ALREADY_SATISFIED`, `FAILED`, `UNKNOWN` (ambiguous timeout/transport/engine error — treated as possibly applied),
`NOT_ATTEMPTED`, and for compensation `COMPENSATED`, `COMPENSATION_FAILED`, `COMPENSATION_UNVERIFIED`. Transport acceptance, command acceptance and operational
verification are distinct; only the postcheck decides success.

## 8. Rollback / compensation boundary

Compensation exists only to undo a **failed Complete attempt, immediately**. It is not Phase-21 granular rollback: no operator-selected rollback, no
removal of an earlier run, no later iteration. Strategy is **additive-only**: the inverse of what a Configlet *added* is exact, and restoration is provable
with the same read groups the postcheck uses. It is implemented for:

* `address` — inverse `no ip address …` / `ip addr del …`; refused when applying would **replace** an existing primary IPv4 address on cEOS;
* `static_route` (cEOS) — inverse `no ip route …`;
* `interface` — `no interface X` / `ip link delete X`, **only when the interface did not exist beforehand** (a Configlet that also creates a VLAN is not provable).

Compensation first re-reads the device: if the captured state already holds, nothing is sent; otherwise it sends the exact inverse and **reads back** to verify.
Everything else (modifying an existing interface, routing processes, BGP, OSPF binding, FHRP, DHCP relay, ACL, …) has **no provable inverse** → Complete is refused
before the first mutation; Partial (UAT) still applies them. Not compensated here: the failed Configlet is compensated only if it may have had effects.

## 9. Platform support (evidence-based)

| Platform | Apply | Compensation (Complete) | Evidence |
|---|---|---|---|
| **Arista cEOS** (`arista_ceos`) | SUPPORTED: interface, address, static route, RIP/OSPF/BGP process + binding + neighbor + AF + network, FHRP, DHCP relay, ACL + attachment | SUPPORTED: address, static route, created interface; NOT_IMPLEMENTED for the rest | `master.py::push_eos` (Netmiko `configure terminal`, `send_config_set(cmd_verify=True)`, four EOS rejection strings), `modules.eos_render.eos_commands` flattening, `nsot_live.get_live_target`, Phase-15 `health.live` reads |
| **Ubuntu/FRR** (`ubuntu_frr`) | SUPPORTED: interface, address (iproute2, strict grammar, `docker exec <container> <argv>`, no shell, no credentials) | SUPPORTED: address, created interface | tracked R3/R4 iproute2 scripts; Phase-15 docker-exec transport |
| Ubuntu/FRR FRR routing, static routes, NAT | **NOT_IMPLEMENTED** | — | `master.py` applies FRR only as a whole `frr.conf` + `vtysh -b`; nftables NAT needs a multi-rule table merge (Phase-14 limitation) |
| device identity (hostname rename), NAT pool, PBR, IS-IS (every platform except cEOS), EIGRP | **NOT_IMPLEMENTED** | — | no verifier / no renderer |
| Nokia SR Linux | **UNSUPPORTED** | — | not in the approved Labs 2/3 baseline; no session code |
| Cisco IOS 8000v, SONiC | **NOT_IMPLEMENTED** | — | no repository evidence of a session or apply path |
| any other platform | **UNKNOWN** | — | never assumed |

## 10. Precheck

Reuses Phase 15 exactly. Execute never runs, repeats or repairs a precheck: it requires the operator's own recent, permitting precheck for the current plan
(and requires a **new** one after any attempt that contacted devices). `INCOMPLETE`/`BLOCKED` prechecks refuse execution.

## 11. Postcheck and settling

`health_service.run_plan_postcheck(plan, cfg_ids=…)` evaluates the executed scope with the same evaluators; the final evaluation is persisted once as a
`CHANGE_POSTCHECK` run and linked from the execution run. **Settling** is a bounded poll (not a fixed sleep): re-evaluate every `EXECUTION_SETTLE_INTERVAL_SECONDS`
(3) up to `EXECUTION_SETTLE_TIMEOUT_SECONDS` (30), but only while a non-passing result is a convergence-sensitive check (OSPF/BGP adjacency, interface oper state, static
route presence) or evidence is temporarily unavailable; an absent address or interface is never "waited for". The run records attempts, timeout and whether it settled.

## 12. AUTO / IPAM recheck

Phase 13 AUTO addresses are read-only proposals ("not reserved, must be rechecked immediately before deployment"). Immediately before the first mutation the engine
re-derives them from **current** NetBox/inventory evidence with the same Phase-13 addressing code (`auto_recheck.py`) and refuses on any difference, on unavailable NetBox,
or on changed accepted intent. **Option B (refuse if it cannot be guaranteed) is implemented, not option A (reserve):** the project has no static-address reservation write
path (its "reservation" concept is DHCP assignment-mode custom fields), and Python must not invent a NetBox write to make a deployment work. Therefore: **no NetBox write is
performed**, nothing is reserved so nothing needs releasing on a Complete failure, accepted intent is never touched, and the recheck cannot lock NetBox against a concurrent allocator.
A deployed AUTO address must be recorded in IPAM separately (warning `AUTO_ADDRESS_NOT_RECORDED_IN_NETBOX`). VLAN 200 remains static: AUTO on Vlan200 is refused at execution as
well as at validation.

## 13. Persistence (migration `0006`)

* `ChangeExecutionRun` — plan, validation run, precheck run, postcheck run, mode, state (`RUNNING`→`FINISHED`, once), outcome, actor, engine version, `plan_hash`, validation
  input/source hashes, scope, devices, start/finish/lease times, bounded `summary` / `report`. Immutable once finished. Partial unique index: one RUNNING run per Change.
* `ConfigletExecutionResult` — per Configlet per phase (APPLY / COMPENSATE): CFG id, device, object type, operation, status, sanitized `error_code`, `partial_effects`, lines sent,
  start/finish, bounded previous-state facts. Write-ahead (IN_PROGRESS before mutation), finalised once, immutable.
* `ExecutionDeviceLock` — transient; UNIQUE per device; deleted at finalisation.
* `AuditEventType.DEPLOYMENT_RECORDED` / `ROLLBACK_RECORDED` (reserved since Phase 8) are now emitted; only their labels changed.
* `Configlet.execution_status` mirrors the latest attempt (a writable field); the run's results are the history. **No raw device output, credentials, exception text or unbounded text is stored.**

## 14. Concurrency

Enforced by the database, not the browser: `unique_active_execution_per_change` and `ExecutionDeviceLock.device` UNIQUE; run + all locks are created in one transaction (all-or-nothing).
A refused acquisition changes nothing. Every run holds a lease (`EXECUTION_LEASE_SECONDS`, 1800, heartbeat per Configlet); an expired-lease run is reaped as `INTERRUPTED` before the gate and its
plan stays unresolved. Retry is never a silent resume: it is a new attempt that re-runs the whole gate and needs a fresh precheck.

## 15. Security

POST + CSRF (project-wide middleware); the browser supplies only the mode confirmation, the five acknowledgements and a `through` CFG id (a lookup key, never echoed) — no command, config, device, path or URL.
Devices/order/syntax come from the current plan. Executors: cEOS credentials via `nsot_live.get_live_target` go straight into `ConnectHandler` (historical inventory credentials are **not** spread, stored,
logged or echoed); Linux needs none. Every failure is reduced to a fixed code; exception/device text never leaves an executor. Linux lines must match a strict grammar (the exact shapes the feature templates
emit) and become validated argv lists; the only process spawn is `subprocess.run(["docker","exec",container,*argv], shell=False)`. No `eval`/`exec`/`shell=True`. Contract tests enforce: only `ceos.py`
imports Netmiko, only `linux.py` imports `subprocess`, no lifecycle/NetBox-writer/Slack/Git/CI import, no `write memory`/reload/containerlab/git text, exactly one caller of `execute_change` (the POST view).

## 16. Audit and notifications

One `DEPLOYMENT_RECORDED` event at start and one at finish (outcome, applied/failed/unapplied/compensated CFG ids, compensation and postcheck status); `ROLLBACK_RECORDED` when compensation ran;
a `BLOCKED` audit for refusals. One notification per finished run through the existing service (persist first, Slack second; failure never affects the run): `DEPLOYMENT_SUCCEEDED`, `UAT_PARTIAL`,
`DEPLOYMENT_FAILED`, `ROLLBACK_SUCCEEDED`, `ROLLBACK_FAILED` (CRITICAL). Refusals are not published.

## 17. UI / operator workflow

`/device-builder/changes/<id>/execute/` (GET read-only): mode and what it means, validation/plan/precheck status, blockers with remediation, ordered scope with per-Configlet apply/compensation capability,
history. The form: a mode-confirmation checkbox; for Partial the `through` selector and the five unticked acknowledgements; a POST-only, CSRF-protected **Execute** button (disabled when ineligible — the server re-checks
regardless). `…/executions/` lists history; `…/executions/<run>/` shows a distinct banner per outcome, requested/executed scope, applied/failed/unapplied/out-of-scope/compensated Configlets, per-Configlet results,
compensation table and postcheck evidence; `…/report.json` is a sanitized attachment. Workflow: Validate → Build Plan → Precheck → (Tier-3 in CI, separately) → Execute.

### 17a. Deployment transport capability (Phase 20.5)

The Execute page's **Deployment Transport** card (`core/services/execution/
transport_capability.py`) shows, per platform present in the Change, which
transport will actually be used and why every other one is not -- this is
capability-driven disclosure, never an operator choice: there is at most one
`SUPPORTED` row per platform, matching the one real, tested mechanism
`executors.registry.EXECUTORS` selects (`arista_ceos` -> Netmiko SSH
configuration-mode session; `ubuntu_frr` -> `docker exec` container
transport; every other platform -> no executor, deployment unavailable).

NETCONF and gNMI Set are explicit disclosure rows whose states distinguish
read-only monitoring, unimplemented software, fixture-tested but disabled
software, image-dependent capability, and a live-available executor. The
only new model-driven writer in Phase 20.5 is the SR Linux CLI-origin gNMI
Set translator: it is fixture/mock tested, runtime-disabled, absent from the
executor registry, and therefore never selectable. cEOS model-driven
sessions remain read-only to NMAS; IOS XR has no release-pinned native-YANG
translator; SONiC transport capability remains image-dependent. See
`PHASE_20_5_PLATFORM_CAPABILITY_AUDIT.md` for the per-platform evidence and
blockers. A device advertising a writable protocol never makes an NMAS
transport `AVAILABLE` by itself.

## 18. Tier-3

New subsystem `execution` (path rule `web/core/services/execution/**` + `execution_service.py`), edges `models_schema`/`planning`/`health`/`validation` → `execution`, selection
(`execution_engine`, `execution_executors`, `execution_views`, `change_precheck`, `contracts`). GitHub Actions remains validation-only: no deployment credentials, no execution trigger.

## 19. Verification evidence

See the Phase-17 final report. Unit/fake tests (51 methods in 4 files + rows in `test_view_boundaries`) prove the engine, executors (against real rendered Configlet lines), views and contracts on a
**simulated** network. **No real device configuration was executed**: no approved, documented, reversible live UAT mutation exists, so live mutating acceptance was not performed and the real cEOS/Linux
executors are verified only against fake transports. This is a documented limitation, not a weakening of the implementation.

## 20. Known limitations

* **Live mutation untested.** Real Netmiko/`docker exec` paths and the additive inverses are unproven on real devices.
* **Complete is narrow by design**: only additive address / static-route / created-interface Configlets (cEOS) and address / created-interface (Linux). Plans that modify existing interfaces or contain routing/BGP/FHRP/ACL/DHCP objects need Partial (UAT).
* **Running configuration only** — the startup configuration is not written (a restart reverts an unpersisted change); persistence belongs to the Golden/Probation phases.
* **FRR routing, FRR static routes and nftables NAT are NOT_IMPLEMENTED** for execution (no incremental-apply precedent).
* **AUTO race not closed**: read-only recheck only; no NetBox reservation/write; a deployed AUTO address is not recorded in NetBox.
* **Partial scope is a prefix**, not an arbitrary subset (no repository evidence for subsets).
* **Postcheck coverage is Phase-15's**: requirements with no evaluator make a Partial run `…_UNVERIFIED` and forbid Complete.
* A Partial postcheck reads every device of the plan's scope, not only the touched ones.
* An `INTERRUPTED` / compensation-incomplete plan cannot be re-executed; recovery needs manual verification and a new validation/plan (general tooling is Phase 21).
* Execution runs synchronously inside the POST (bounded per-device timeouts and the settling deadline).
