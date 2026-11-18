# Remediation governance and verification (M5) — `governance.py`, `verification.py`

## Plan lifecycle
`PROPOSED → RISK_ASSESSED → DRY_RUN_PASS → APPROVED|PREAUTHORIZED → PRECHECK_PASS → EXECUTING → VERIFYING → SOAKING → RESOLVED`;
terminal/side states `REJECTED, BLOCKED, EXPIRED, ABORTED_RESTORED, ABORTED_UNRESTORED, INTERRUPTED` (`_NEXT` enforces transitions).

## Controls
- **Risk / blast radius:** `assess()` classifies each operation (`OP_KINDS`: traffic-affecting flag + base risk) into tiers using
  impacted flows and device/interface criticality; approval is mandatory above the pre-authorizable tier. Proposer ≠ approver;
  agent actors can never approve (`approve` refuses, UT-066).
- **Dry run** (`dry_run`) must pass before approval; approval expires (`EXPIRED`).
- **Pre-checks** (`precheck`): maintenance window/capability, existing change-engine eligibility, expected-deviation guard,
  verified alternate path for `DRAIN_LIKE` ops (`no alternate path → BLOCKED`, UT-070), traffic guard sample availability.
- **Locks / idempotency / rate limits:** one active lease per device (`_device_locked`), required `idempotency_key`
  (duplicate returns same result), per-device/per-case rate window (`DEFAULT_RATE`).
- **Execution** via `Ports`. `UnconfiguredExecutor` is the default and refuses every write. The production binding
  `ChangeEngineExecutor` is a **hand-off**: it runs the read-only execution-eligibility gate, but `supports()` is False and `apply`
  refuses `EXECUTION_VIA_CHANGE_WORKFLOW`. The referenced Change is executed from its Change page, because the public change engine
  has exactly one caller, the explicit execution POST view (`core.tests.test_contracts`). Letting troubleshooting execute directly
  would widen that boundary and needs separate approval.
- **Production-loss abort:** after each step `_breach()` compares before/after flow health to `DEFAULT_ABORT`; breach →
  `_abort()` compensates and reads back. Successful restore → `ABORTED_RESTORED`; failed rollback/readback →
  `ABORTED_UNRESTORED` (honest, alert-raising, UT-075).
- **Restart recovery:** `recover()` marks expired/orphan EXECUTING leases `INTERRUPTED` and attempts compensation.

## Verification (`verification.py`)
`verify()` runs service checks, re-runs the originating diagnostics and compares flows; soak (`DEFAULT_SOAK` 30 min) must elapse
with clean results before `RESOLVED`. `finalize()` computes one of `OUTCOMES` (`RESOLVED_VERIFIED`,
`ROOT_CAUSE_IDENTIFIED_REMEDIATION_PENDING`, `EXPECTED_BEHAVIOR_CONFIRMED`, `INCONCLUSIVE_ESCALATED`,
`EXTERNAL_PREREQUISITE_BLOCKED`, `REMEDIATION_FAILED_RESTORED`, `REMEDIATION_FAILED_UNRESTORED`); no outcome is resolved
before soak completion (no premature resolution, UT-077/078).

## Tests
`core.tests.test_troubleshooting_governance` (34 tests; UT-065–080 and fault injection).
