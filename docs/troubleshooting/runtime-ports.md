# Runtime safety ports and persistent soak monitoring

Source: `web/core/services/troubleshooting/runtime_ports.py`, `verification.py`, `web/core/management/commands/troubleshooting_monitor.py`.
Tests: `web/core/tests/test_troubleshooting_runtime_ports.py` (RP-01 .. RP-27). Source base HEAD `cbb9c96` plus the preexisting working-tree edits (not committed here).

## What is composed (and what is refused)

`runtime_ports.build_ports(PortConfig, actor=, case=)` returns a `governance.Ports`. Writes are **off** by default.

| Governance port | Existing service used | Fails closed when |
|---|---|---|
| `device_state` | `health.inventory.managed_devices` (authority), `Change`/`ChangeTarget` decommission lifecycle, optional maintenance/golden providers | device absent -> `NOT_IN_INVENTORY` (not `UNKNOWN`, so `case.target_states` can no longer substitute); inventory unreadable; maintenance provider absent -> `None` -> precheck blocks |
| `alternate_paths` | injected provider describing an *already configured* mechanism, edges verified UP via `health.telemetry` | no provider/answer, edge not UP, telemetry unavailable -> `NO_VERIFIED_ALTERNATE_PATH`; redundancy is never inferred from topology |
| `flow_sample` | injected production-flow source (monitoring/NetFlow); persists to `TsProductionFlowMonitor.sample_windows` | no source / no number / coverage out of range -> `loss_pct=None, coverage=0` (never 0% loss); non-PRODUCTION flows are excluded |
| `step_up`/approval | injected verifier (NMAS has **no** MFA service); governance enforces human, distinct approver, acknowledgements | no verifier or verifier error -> `STEP_UP_REQUIRED` |
| `executor` | `governance.ChangeEngineExecutor` -> `execution.eligibility` (read-only); execution is a hand-off to the Change page, never `execution.engine` | `WriteGuardedExecutor`: `supports()` is False unless `writes_enabled=True`, and the hand-off executor never supports execution (`unsupported_reason` shown on the plan); apply/compensate raise `WRITES_DISABLED` / `EXECUTION_VIA_CHANGE_WORKFLOW` |
| read-back | injected config reader -> sha256 digest per device | unreadable -> `READBACK_UNAVAILABLE` (restoration unprovable) |
| compensation | `rollback_service.execute_rollback` on a *pre-built* `RollbackPlan` (`rollback_runner_from_service`). **Public repository: the legacy Phase-21 rollback service is not ported, so this always refuses with `COMPENSATION_UNAVAILABLE`** | no plan -> `COMPENSATION_UNAVAILABLE`; any non-`SUCCEEDED` step -> `COMPENSATION_FAILED` -> `ABORTED_UNRESTORED` |

Gaps in NMAS itself (no per-device maintenance/lifecycle model, no MFA, no redundancy service) are surfaced as refusals, not simulated.

## Persistent soak ledger

Stored in `TsRemediationPlan.approval["soak_ledger"]` (existing mutable JSON column; no migration). Pinned at start: window (>= 30 min, a caller may lengthen but never shorten), interval (60 s), max gap (180 s), min bucket coverage (0.8), loss threshold and baseline from the execution. Judgement (`assess_ledger`) is recomputed from persisted data each time:

* `DEGRADED` (sticky): any sample whose loss rose above the threshold. Later recovered samples never clear it.
* `INTERRUPTED` (sticky): any stretch > max gap without a *usable* sample (leading edge from the applied time, interior, live trailing edge). Unmeasurable/low-coverage samples are unusable, so telemetry loss is a gap, never health.
* `INCOMPLETE`: window elapsed but bucket coverage < minimum, or no samples at all (a deadline alone never passes).
* `PASSED`: window elapsed, no degraded sample, no gap, coverage met.
* Backward clock samples are rejected (`rejected` counter). `reset_window` (human, reason, audited, history kept) is the only way past DEGRADED/INTERRUPTED.

`verification.verify` now consults the ledger (mandatory when `soak_required`), requires every named flow (impacted + surrounding + baseline) to have a measured post-change sample with adequate coverage, and fails traffic-affecting plans naming no flow. The injected `soak_status` (core soak run) is optional *additional* evidence; both must pass.

## Operation

```
python manage.py troubleshooting_monitor sample --tenant T --actor nmas-monitor [--flow-source pkg.mod.factory] [--iterations N --sleep S]
python manage.py troubleshooting_monitor status --tenant T --actor A --plan RPL-...
python manage.py troubleshooting_monitor reset-window --tenant T --actor A --plan RPL-... --reason "..."
```
`sample` is read-only and restart-safe; run it at least every `--interval` seconds (cron/systemd). Without a flow source it records unusable samples and no soak can pass. Flow source: `settings.TROUBLESHOOTING_FLOW_SOURCE` or `--flow-source` (factory returning `source(flow) -> {"loss_pct","coverage"}` or `{"sent","lost","expected"}`, or `None`).

## Test results

`cd web && DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test /opt/ai-orchestrator/nmas-env/bin/python manage.py test core.tests.test_troubleshooting_runtime_ports` -> 27 tests OK (local run, fake providers; **not** gateway-attested and **not** live-device evidence).

Combined with governance/runtime/views/ai_runtime suites: 103 tests, 2 failures, both in `test_troubleshooting_governance.py` (out of this subtask's write scope) and both encode the closed bypass (deadline-only soak):
`test_ut077_soak_prevents_premature_success_then_completes` (expects VERIFIED after the deadline with no samples) and `test_ut088_metrics_exclude_unresolved_from_mttr` (uses `soak_window=0`). They must be updated to drive `runtime_ports.tick` (see RP-13) or use `soak_required=False`.

## Not done / external prerequisites (INCOMPLETE_WORK)

* No live gateway evidence: production flow source, redundancy provider, MFA verifier, maintenance provider and config reader are injection points; real NMAS bindings for them do not exist yet.
* Writes stay disabled; enabling them needs an operator decision and a `change_loader` bound to a validated Change.
