# Checkpoint 04 Manifest — Initial Golden baseline (one-time legacy bootstrap)

Prepared: 2026-09-22

This checkpoint is **not** created by an implementation phase, a merge or a test suite (see `docs/PROBATION_SOAK_AND_PROMOTION.md` §17, which
explicitly reserved this exact wording: "Checkpoint 4 is not created by Phase 20A"). It is created here, as a **separate, explicit action**, only
because the operator's one-time legacy-baseline bootstrap has genuinely finished: a real 30-minute observation ran to completion, and the operator
explicitly approved the result.

## 1. Prerequisite chain (all satisfied before this document was written)

| Step | Status |
|---|---|
| Phase 20A (probation soak implementation) merged to `main` | `e70367d` (PR #5), merged as `6f68f3f` |
| Legacy-bootstrap implementation (this checkpoint's own code) merged to `main` | `03b92d8` (PR #6), merged as `984ac0f` |
| Local dev database migrated (`0006`–`0010`) | confirmed via `showmigrations core` — all `[X]` |
| Read-only readiness probe | `READY`, 0 blockers, 10/10 devices reachable |
| Baseline captured (read-only, sanitized, all-or-nothing) | `BND-LEGACY-000001`, 10 devices, integrity `INTACT` |
| 30-minute real observation run to completion | `BOOT-000001`, `COMPLETED / PASS`, `TECHNICAL_PASS` |
| Operator's explicit approval (decision-time re-read confirmed no drift) | `LegacyBootstrapDecision` by `operator`, `config_recheck_result = MATCH` |
| Initial Golden created and integrity-verified | `BND-GOLD-000001`, `INTACT` |

## 2. INITIAL GOLDEN SOURCE: LEGACY_BOOTSTRAP

```
Golden bundle id       BND-GOLD-000001
Golden bundle digest   43c9a53cbf5b2b99176801f2cd35c2c1c0b83529015a0fc3bfdc15ea5592abb0
Golden payload digest  71ae6edfe081a5a033e1cc210461bdf08ea85cd36a4a90bb1f69132d79d6f634
                       (identical to the candidate's payload digest -- the payload was never re-read after approval)
provenance             LEGACY_BOOTSTRAP
created_at             2026-09-22T01:21:33.188979Z
approved_at            2026-09-22T01:21:25.183934Z  by operator
integrity              INTACT (bundle) / INTACT (standalone manifest.json export)
```

The Golden bundle's `lineage.legacy_bootstrap` block (covered by the bundle digest) pins:

```
candidate_bundle_id             BND-LEGACY-000001
candidate_bundle_digest         b7a0d7b2b2a447c5062fe6da0f9ecbe2552c54f18b056b04351d6c6e5cd7d5d3
baseline_digest                 71ae6edfe081a5a033e1cc210461bdf08ea85cd36a4a90bb1f69132d79d6f634
observation_run_id              BOOT-000001
observation_duration_seconds    1800
observation_started_at          2026-09-21T23:58:08.877799Z
observation_required_end_at     2026-09-22T00:28:08.877799Z
observation_completed_at        2026-09-22T00:28:10.382821Z
evidence_digest                 2df6b18120ce5a161a62c47567db78528fc5ba8234271864eb4c2cfb7638e50d
decision                        APPROVE
decided_by                      operator
decided_at                      2026-09-22T01:21:25.183934Z
predates_automation_framework   true
config_recheck_at               2026-09-22T01:21:25.183934Z
config_recheck_result           MATCH
```

**No Change, plan, validation run, execution run, postcheck run, UAT bundle, Probation bundle or `ProbationSoakRun` exists behind this Golden** —
`change_id` / `plan_id` / `validation_run_id` / `execution_run_id` / `postcheck_run_id` / `source_uat_id` are all `None` on the bundle row, and a
database count taken immediately after approval shows `Change=0, ChangePlan=0, ChangeValidationRun=0, ChangeExecutionRun=0, ProbationSoakRun=0,
GoldenDecision=0` (the normal-lifecycle `GoldenDecision` model — this Golden's decision lives in the separate `LegacyBootstrapDecision` table, one
row). Nothing was fabricated to satisfy the normal lineage.

Captured devices: R1, R2, R3, R4, R5, S1, S2, S3, S4, mgmt_swt (all ten managed inventory devices; none excluded). 32 secret-bearing lines were
redacted before anything was stored (local-user secrets, the SNMPv3 auth/priv key, the gNMI TLS certificate key reference); the stored configuration
is sanitized, not byte-identical to the device configuration (see `docs/LEGACY_BASELINE_BOOTSTRAP.md` §7).

## 3. NORMAL PROBATION POLICY: 7 DAYS

Confirmed, read directly from the running application **after** the bootstrap completed:

```
soak_service.current_policy().duration_seconds        = 604800   (168.0 hours)
soak_service.current_policy().production_duration_seconds = 604800
soak_service.current_policy().is_production_duration   = True
soak_service.current_policy().version                  = "20.0.0"
```

The bootstrap policy (`LEGACY_BOOTSTRAP_POLICY_V1`) is a separate object that never reads or writes `PROBATION_SOAK_*`; `web/core/services/soak/policy.py`
was not touched by this work (contract-tested: `test_bootstrap.py::BootstrapBoundaryTests::test_the_normal_seven_day_policy_source_is_untouched_by_the_bootstrap`).
**This initial Golden did NOT pass a seven-day probation soak.** Every future Golden bundle — for any change made from this point forward — follows
the normal, unchanged lifecycle: Change → validation → `ChangePlan` → precheck → execution → UAT bundle → Probation bundle → the real 168-hour soak →
the operator's decision.

## 4. BOOTSTRAP EXCEPTION: 30 MINUTES, ONE TIME ONLY

```
bootstrap_service.current_policy().duration_seconds    = 1800   (30 minutes)
bootstrap_service.current_policy().sample_interval_seconds = 300
bootstrap_service.current_policy().min_coverage_percent = 80
bootstrap_service.current_policy().version              = "LEGACY_BOOTSTRAP_POLICY_V1"
```

The real observation ran the full 1800 real, elapsed seconds (`started_at` 2026-09-21T23:58:08.877799Z → `finished_at`
2026-09-22T00:28:10.382821Z), never backdated, sleep-skipped or patched: server clock only, driven by
`python manage.py legacy_bootstrap observe` with a bounded, non-busy wait loop. Seven samples were taken (T+0, T+5, T+10, T+15, T+20, T+25, and the
closing sample at T+30), all `PASS`, 100% interval coverage, maximum gap 300.0 s (well under the 600 s limit), no configuration drift, no execution
interference, integrity `INTACT` throughout.

**This exception is now permanently closed.** Verified with `python manage.py legacy_bootstrap verify` immediately after approval:

```
gate: ["LEGACY_BOOTSTRAP_ALREADY_COMPLETED"]
```

and by attempting a second capture, which was refused with the same code (`BASELINE NOT CAPTURED (nothing was created)`). The lockout is enforced by
a database unique constraint (`unique_legacy_bootstrap_golden`, on `ConfigurationBundle` where `kind=GOLDEN AND provenance=LEGACY_BOOTSTRAP`) in
addition to the application-level gate, so it survives a server restart and cannot be worked around through the API, the CLI or direct row
manipulation of the gate check alone.

## 5. Phase 21 readiness

`bundle_service.known_good_baseline()` now returns:

```
valid   = True
source  = LEGACY_BOOTSTRAP
golden  = BND-GOLD-000001
```

Phase 21 (rollback / recovery) may treat `BND-GOLD-000001` as its known-good baseline, with its source honestly and permanently recorded as
`LEGACY_BOOTSTRAP` — never presented as, or conflated with, a normal-lifecycle Golden. **Phase 21 may now begin.**

## 6. Manifest / evidence artifacts

* Initial Golden manifest export: `/device-builder/bundles/BND-GOLD-000001/manifest.json` (also `bundle_service.export_json`, verified
  self-consistent with `verify_export`, no live database read required).
* Legacy baseline candidate: `/device-builder/bundles/BND-LEGACY-000001/` (integrity `INTACT`).
* Observation record: `/device-builder/bootstrap/runs/BOOT-000001/` (7 samples, evidence digest above).
* Implementation source: PR #6, commit `03b92d8`, merged to `main` as `984ac0f`; hosted Tier-3 `SUCCESS`.
* Full documentation of the design, guarantees and limitations: `docs/LEGACY_BASELINE_BOOTSTRAP.md`.

## 7. What this checkpoint does **not** claim

* It does not claim the initial Golden passed a seven-day soak — it did not, and the artifact says so in structured, digest-covered provenance.
* It does not claim any Change, plan, execution, UAT bundle or Probation bundle exists behind it — none does.
* It does not weaken, shorten or reuse the normal probation policy for any future Golden — confirmed unchanged at 604800 s.
* It does not claim the bootstrap shortcut remains available — it is now permanently locked out.
