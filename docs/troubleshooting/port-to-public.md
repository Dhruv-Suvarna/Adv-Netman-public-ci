# Port of the troubleshooting subsystem to the authoritative repository

| Item | Value |
|---|---|
| Source (legacy archive, read-only) | `/home/student/Scripts/clab_dualstack_lab`, branch `phase21-rollback-removal-iteration`, HEAD `cbb9c96` + untracked JOB-9AA10B4E7CA7 work |
| Target | `/home/student/Scripts/nmas-public-dev-troubleshooting`, branch `troubleshooting/job-9aa10b4e7ca7-port`, base `origin/main` `4f950b3` |
| Method | Source-level copy of the troubleshooting-only files (136) plus reviewed integration edits. No legacy Git history, commit, cherry-pick or unrelated Phase-21 work. Nothing staged or committed. |

## Copied unchanged (then cleaned for the public quality gate)

`web/core/services/troubleshooting/**` (43 modules), `web/core/troubleshooting_{views,urls}.py`, templates
`core/troubleshooting/{list,detail,intake}.html`, management commands `troubleshooting_{ai,monitor}.py`, 30 test modules and the
`tests/fixtures/troubleshooting_{collectors,runbooks}` fixtures, `docs/troubleshooting/**` (including all validation reports).

**Not copied:** legacy migration `0012` (regenerated), the Phase-21 rollback service/models (`rollback_service.py`, `rollback/`,
`Rollback*` models: unreviewed legacy work, not part of this subsystem), and every other dirty legacy file.

## Integration changes in the public repository

| Area | Change | Why |
|---|---|---|
| Schema | `Ts*` model block appended to `web/core/models.py`; `migrations/0037_troubleshooting.py` generated (depends on `0036`) | Same 18 models, 4 constraints, 2 indexes as legacy `0012` (operation-by-operation identical); FKs only between `Ts*` models |
| Routes | include in `core/urls.py`; the single `<action>` plan route split into one named route per action (`dry_run`, `precheck`, `approve`, `reject`, `execute`) for UI and API | The public `NmasAccessMiddleware` authorizes by route name; one route could not carry VALIDATE, APPROVE and EXECUTE at once |
| Access policy | every troubleshooting route classified in `core/services/identity/policy.py` (reads, audited sensitive reads, mutations) | The public site is default-deny: unclassified routes are refused |
| Middleware | `ts_api_*` routes answer JSON 401/403 instead of an HTML login redirect | Versioned API clients |
| Views | `Principal.nmas_actions`; `PLAN_ACTION_PERMISSION`; buttons disabled and server-side recheck refused when the NMAS permission is missing | UT-089: never show an enabled action the platform will refuse |
| Compensation | `rollback_runner_from_service` refuses with `COMPENSATION_UNAVAILABLE` when the rollback service is absent (it is) instead of raising `ImportError` mid-abort | Fail closed with a governed code |
| Execution boundary | `ChangeEngineExecutor` became a hand-off: read-only eligibility dry run kept, `supports()` False, `apply` refuses `EXECUTION_VIA_CHANGE_WORKFLOW`; `WriteGuardedExecutor.unsupported_reason` surfaces why on the plan | The public `test_contracts` boundary: the change engine has exactly one caller, the explicit execution POST view. Production behaviour is unchanged with the default `writes_enabled=False`; only the opt-in direct-engine path is gone |
| Device locks | legacy `rollback.locking` probe removed from `governance._device_locked` | Module does not exist here; `ExecutionDeviceLock` (checked) and the engine's `DeviceMutex` remain authoritative |
| Admission providers | new `adapters/nmas_providers.py`: `inventory` (resolver.engine_devices) and `lifecycle` (ManagedDevice + MaintenanceRecord) | Authoritative lifecycle/admission state now exists in NMAS (absent from the legacy base) |
| CI | `troubleshooting` subsystem, path rule, impact edges (models, identity, health, execution, soak, bundles, nsot, topology), Django-wide consumer, 31 selected test modules | Tier-3 had 144 unclassified paths (forced full mode) |
| Quality | 0 critical / 0 files over the Pylint baseline: unused imports and variables removed, lambda assignments converted, inconsistent returns fixed, `PHYSICAL_KINDS` frozen, 45 deliberate fail-closed `except Exception` and 4 long flat parsers annotated inline with the reason | Public `quality.pylint` gate |

## Behavioural differences a reviewer should know

* Opening an expected-anomaly exception now needs NMAS **APPROVE** (an operator alone is refused). Approving still needs the
  `ts-approver` role as well.
* An operator's approve or execute is refused 403 by the access layer before the view's 409 availability check.
* Unknown plan actions have no URL (404) instead of a 400 from the view.
* Troubleshooting never executes a Change: with writes enabled, execute stays disabled with the reason "execute the referenced
  Change from its Change page". Restoring direct execution means adding a second change-engine caller, a platform boundary
  decision that needs separate approval.
* `test_troubleshooting_views.PORTS_FACTORY` is derived from `__name__`: a whole-app run (`manage.py test core`) imports most test
  modules as `web.core.tests.*`, and a hard-coded `core.tests.*` path pointed at a second copy of the module's shared state.
* Anonymous page requests redirect to NMAS login (was 403).

## Tests added for the port

* `test_troubleshooting_access` (TSACC-001..021): classification completeness, route/permission map equality, layered refusals,
  MFA pending, tenant scope with full NMAS permissions, button gating, server-side recheck.
* `test_troubleshooting_nmas_providers` (NP01..09): authoritative lifecycle admission.
* `test_troubleshooting_runtime_ports.test_rp10`: missing rollback service is `COMPENSATION_UNAVAILABLE`.
* Shared helper `tests/helpers/troubleshooting.py` signs in through the real session + MFA marker (the suite-wide auto-login
  operator is disabled for these tests so role checks are real).
* `test_troubleshooting_readiness` (RDY01..RDY13, continuation phase 1): read-only per-device and per-runbook readiness report, and the
  capture-script provenance fix (`capture_live.py` imported collectors from the legacy archive path; it now imports its own worktree).
