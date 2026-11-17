# JOB-9AA10B4E7CA7 — continuation from checkpoint #23 (attested-source recovery)

Date: 2026-11-10. Author: standalone Claude CLI engineering agent on VM 1, working outside the orchestrator.

Status: **INCOMPLETE_WORK, now resumable.** The blocker that stopped every attested run (Blocker A, the source pin) is removed: the
work is now in an authorized worktree that the installed gateway helper pins without error. All 30 completed subtasks are kept as
source. None of them was redone.

Not done here, by design:

* No gateway-attested run, because only the orchestrator's dispatcher can call the gateway.
* No live fault campaign, deployment, commit, push, PR, or job mutation.
* No change to the gateway, firewall, proxy, permissions, or the paused compatibility matrix.

## 1. Inventory

| Item | State |
|---|---|
| Legacy implementation | `/home/student/Scripts/clab_dualstack_lab`, branch `phase21-rollback-removal-iteration` `cbb9c96`. Origin is the private `Adv-Netman` archive. It is untouched and dirty (troubleshooting plus unrelated Phase-21 work, preserved). |
| **New authorized worktree** | `/home/student/Scripts/nmas-public-dev-troubleshooting`, branch `troubleshooting/job-9aa10b4e7ca7-port`, base `origin/main` `4f950b3` (`Adv-Netman-public-ci`). 5 tracked files modified, 43 untracked paths. Nothing staged or committed. |
| Other worktrees | All 12 other `nmas-public-*` / `job-433a-*` worktrees are untouched. `nmas-public-dev` (`lab9/isolation-control-plane`, dirty) is preserved. |
| Port record | [`../port-to-public.md`](../port-to-public.md) lists the 136 copied files, what was not copied, and every integration edit. |

## 2. Gap matrix (what checkpoint #23 lacked → what exists now)

| Gap at attempt 10 | Files | Now |
|---|---|---|
| No attested pin is possible (PermissionError, wrong origin) | the whole tree | Ported to an authorized worktree. The installed `sandbox_pin.py` pins it (§6). |
| Routes are unreachable under the public default-deny access layer | `core/services/identity/policy.py`, `core/troubleshooting_urls.py`, `core/middleware.py` | Every route is classified. Plan actions are split per permission. The API returns JSON 401/403. |
| UI offers actions the platform refuses (UT-089) | `core/troubleshooting_views.py`, `templates/core/troubleshooting/detail.html` | NMAS permission gating, plus a server-side recheck |
| No authoritative lifecycle/admission provider | `services/troubleshooting/adapters/nmas_providers.py` (new) | `inventory` and `lifecycle` are bound to `resolver.engine_devices()`, `ManagedDevice` and `MaintenanceRecord` |
| Compensation raises `ImportError` mid-abort when the rollback service is absent | `services/troubleshooting/runtime_ports.py` | Refused with the governed code `COMPENSATION_UNAVAILABLE` |
| Ported executor added a second caller of the public change engine (`test_contracts` boundary failed in the full regression) | `services/troubleshooting/governance.py`, `runtime_ports.py` | `ChangeEngineExecutor` became a hand-off: read-only eligibility dry run kept, execution refused `EXECUTION_VIA_CHANGE_WORKFLOW`, reason shown on the plan. Default production behaviour (writes disabled) is unchanged. |
| Dead legacy lock probe | `services/troubleshooting/governance.py` | Removed. `ExecutionDeviceLock` and `DeviceMutex` remain authoritative. |
| Tier-3 forced full mode (144 unclassified paths); quality gate failing | `services/ci/rules.py`, 40+ troubleshooting modules | `troubleshooting` subsystem, 8 impact edges, 32-module selection. Pylint: 0 critical, 0 over baseline. |
| Schema absent in public repo | `core/models.py`, `migrations/0037_troubleshooting.py` | Same 18 models, 4 constraints and 2 indexes as legacy `0012` |
| Version, site readers, fixtures, AI provider | — | Still open: external prerequisites (§9) |

## 3. Source-pin root cause

The full analysis is in [`source-pin-rca.md`](source-pin-rca.md). In summary:

* **Primary cause:** the job ran in the private legacy archive, whose origin the gateway policy (`412ef58e…`) does not authorize.
* **Why the PermissionError appeared:** `sandbox_pin.walk()` is not gitignore-aware. It reached the `vmware`-owned 0700 InfluxDB runtime directory before the origin check could run.
* **Contributing cause:** `LAB_REQUIREMENTS.md`, `IMPLEMENTATION_PLAN.md` and `GAP_ANALYSIS.md` still name the archive as the place for new work. They need a separately approved edit.

**Fix:** port the work to the authorized repository. The gateway needs no change. Making the pin walk gitignore-aware is
recommended hardening, not staged.

## 4. Changes made

See [`../port-to-public.md`](../port-to-public.md) for the change table and the behaviour differences a reviewer should know.

* New tests: `test_troubleshooting_access` (TSACC, 11 tests) and `test_troubleshooting_nmas_providers` (NP01–09).
* Extended tests: `test_rp10`, and `ChangeEngineExecutorTests`, which now checks that the hand-off never calls the engine.
* Fixed `test_troubleshooting_views.PORTS_FACTORY`, which broke under whole-app discovery (see §5).
* New test helper: `tests/helpers/troubleshooting.py`.

## 5. Test results (local, in `web/`, `/opt/ai-orchestrator/nmas-env`, env `DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test`)

These are **local** results, **not gateway-attested**.

| Scope | Command | Result |
|---|---|---|
| Full troubleshooting suite (32 modules, serial) | `manage.py test $(ls core/tests/test_troubleshooting_*.py → labels) --noinput --parallel 1` | before the hand-off change: 706 tests, OK (293 s). Final tree: **707 tests, OK** (294 s; +1 hand-off test) |
| Tier-3, CI, governance, identity | `manage.py test core.tests.test_tier3_{changes,execution,selection} core.tests.test_*governance* core.tests.test_identity_access --noinput` | 362 tests, OK |
| Tier-3 required static checks (plan: targeted, 148 files, 0 unclassified, 160 selected modules) | `static.hygiene`, `static.syntax`, `django.check`, `django.migrations`, `governance.catalog`, `quality.pylint` through `core.services.ci.execute` | 6 PASS |
| Full `core` regression, run 1 (serial; started before the `rules.py` / hand-off / test-path fixes) | `manage.py test core --noinput --parallel 1` | 8,723 tests in 2,646 s: **6 failures**, 44 skipped. See the analysis below. |
| The 6 failing tests, rerun under the same whole-app discovery after the fixes | `build_suite(["core"])`, filtered to the 6 failing tests' classes | 38 tests, OK |
| Contract + affected troubleshooting modules | `core.tests.test_contracts` + troubleshooting governance, runtime_ports, views, runtime, deployment, access | 172 tests, OK |
| Full `core` regression, run 2 (final tree, serial) | `manage.py test core --noinput --parallel 1` | **8,733 tests in 2,117 s: OK** (44 skipped, 0 failures) |

Run 1 failure analysis:

* **3 already fixed before run 1 finished.** `test_tier3_selection` classification and the two `test_test_governance` inventory/catalog
  tests failed because run 1 began before the `rules.py` path rule existed. They passed in the 362-test rerun.
* **1 real boundary conflict.** `test_contracts…the_mutating_engine_has_exactly_one_caller` failed because the ported
  `ChangeEngineExecutor.apply` called `execution.engine.execute_change`. It was fixed by the hand-off (§2). The contract was not changed.
* **2 discovery-order failures.** `test_troubleshooting_views` `test_ut089` and `test_it13` failed only in the whole-app run. With the
  `core` label, discovery imports most test modules as `web.core.tests.*` (8,158 of 8,732 tests, an existing repository behaviour).
  The test's hard-coded `core.tests.…fake_ports` path therefore read a second, empty copy of its shared `_PORTS` state. The path is now
  derived from `__name__`. Tier-3 and the gateway pass dotted `core.tests.<module>` labels and were not affected.

Evidence-class note: every runbook and HC result in these suites uses inputs with **SIMULATED** provenance (the replay fixtures). Those
inputs prove the logic. They do not prove live behaviour.

## 6. Gateway evidence

| Item | Value |
|---|---|
| Attested runs from this continuation | **None.** The gateway's only client is the dispatcher, and I did not call it. |
| Local pin with the installed helper (`python3 -I -S -B /opt/ai-orchestrator/gateway/sandbox_pin.py hash /home/student/Scripts/nmas-public-dev-troubleshooting`) | OK. head `4f950b36`, branch `troubleshooting/job-9aa10b4e7ca7-port`, origin `Adv-Netman-public-ci`, 1,954 files / 58.8 MB, 149 dirty paths, `tree_sha256` `00a003353d566d2a7811b77ff6127812e3e9b5542836d3db825061e71f94aeb6`. This was computed on the tree just before this value was written into this file, so this edit changes it. The gateway records its own pin per run. |
| Gateway preconditions, checked read-only against `aiorch_gateway.py` and the policy source with the installed digest | Project `Scripts` → `/home/student/Scripts`. The worktree is a direct child. The origin is allowlisted. The git common dir `/home/student/Scripts/nmas-public-dev/.git` is inside the project, and the gitdir is under `…/.git/worktrees/`. All are satisfied. |
| Limits to plan around | 480 s per run, 64 labels, 256 KiB output, 20,000 files / 400 MB tree |

The local pin is a reproducibility check, not attestation. The pin changes whenever the tree changes, so the gateway records its own
pin per run.

## 7. Runbook operational acceptance matrix

| Runbook | Plain-English doc | DAG + checks (simulated, incl. negatives) | Live fault/recovery bundle | Needed for live acceptance | Classification |
|---|---|---|---|---|---|
| RB01 link flapping | `runbooks/RB01-link-flapping.md` | 6 tests | none | site physical/event reader; approved isolated flap fixture | IMPLEMENTED_NOT_LIVE_VERIFIED |
| RB02 reachability (rich host, HC01–HC28) | `runbooks/RB02-reachability.md` | 34 tests incl. UT-040 (≥20 applicable checks), applicability matrix of 28 | none | flow/probe runners, FIB/ACL/DNS readers, admitted devices with version | IMPLEMENTED_NOT_LIVE_VERIFIED |
| RB03 routing neighborship | `runbooks/RB03-routing-neighborship.md` | 6 tests | none | qualified protocol reader per AF; isolated neighbor fault fixture | IMPLEMENTED_NOT_LIVE_VERIFIED |
| RB04 STP loops / TC | `runbooks/RB04-stp-loops.md` | 6 tests | none | STP/L2 reader; isolated L2 fixture (no production loop injection) | IMPLEMENTED_NOT_LIVE_VERIFIED |
| RB05 DNS | `runbooks/RB05-dns.md` | 7 tests | none | DNS resolver runner + authoritative zone source | IMPLEMENTED_NOT_LIVE_VERIFIED |
| RB06 MTU / PMTUD | `runbooks/RB06-mtu-pmtud.md` | 5 tests | none | PMTU probe runner; isolated MTU-mismatch fixture | IMPLEMENTED_NOT_LIVE_VERIFIED |
| RB07 Layer 1 | `runbooks/RB07-layer1.md` | 6 tests | none | real optics/FEC hardware; virtual cEOS optics answer `UNSUPPORTED_OPERATION` | EXTERNALLY_BLOCKED (hardware) |

No live bundle exists for any runbook. Producing one requires the §9 prerequisites and explicit authorization. **No fault was
injected.**

## 8. Requirement matrix

Classification key:

* **VERIFIED:** proven by executed tests against the real NMAS code path, with no simulated device or provider standing in for the requirement.
* **IMPLEMENTED_NOT_LIVE_VERIFIED:** the code and tests exist, but the evidence is simulated.
* **INCOMPLETE:** missing work that can be done in-repo.
* **EXTERNALLY_BLOCKED:** needs a site, an approval or hardware.

### Spec §9 acceptance criteria

| # | Criterion (short) | Classification | Basis / what is missing |
|---|---|---|---|
| 1 | Stage 1 steps, structured tables, provenance | IMPLEMENTED_NOT_LIVE_VERIFIED | engine/evidence/collectors suites; live collectors not bound |
| 2 | Cross-vendor normalization | IMPLEMENTED_NOT_LIVE_VERIFIED | normalization + source-contract suites; no operational qualification |
| 3 | Rich host ≥20 applicable tests, isolated root cause | IMPLEMENTED_NOT_LIVE_VERIFIED | UT-040 on the simulated fixture |
| 4 | Seven runbooks with real/simulated fault validation and negatives | IMPLEMENTED_NOT_LIVE_VERIFIED | simulated half done; real half EXTERNALLY_BLOCKED (fixtures) |
| 5 | Golden/approval/history/soak in correlation and governance | IMPLEMENTED_NOT_LIVE_VERIFIED | baseline-history / config-snapshot suites; site history not accepted |
| 6 | Storm deduplication, topology-aware primary | IMPLEMENTED_NOT_LIVE_VERIFIED | simulated storm scenario |
| 7 | AI handoff with dossier; AI read-only continuation | IMPLEMENTED_NOT_LIVE_VERIFIED | ai/ai_runtime suites; operational AI campaign EXTERNALLY_BLOCKED (provider + approval) |
| 8 | TCP-vs-ICMP/UDP distinction, narrow suppression | IMPLEMENTED_NOT_LIVE_VERIFIED | flow-runtime/flow-wire suites |
| 9 | Remediation risk/approval/dry-run/lock/idempotency/rollback/traffic guard | IMPLEMENTED_NOT_LIVE_VERIFIED; compensation **INCOMPLETE**; troubleshooting-initiated execution **EXTERNALLY_BLOCKED** (boundary approval) | The rollback service is not in the public repo, so compensation refuses (`COMPENSATION_UNAVAILABLE`). Execution is a hand-off to the Change page. A direct path needs approval to add a second change-engine caller. The governed state machine, abort and traffic guard are tested with fake executors. |
| 10 | Complete case report | IMPLEMENTED_NOT_LIVE_VERIFIED | reporting/views suites on simulated cases |
| 11a | Access controls (RBAC, MFA, tenant scope, audited reads) | **VERIFIED** (local; attestation pending) | TSACC-001..021 through the real `NmasAccessMiddleware` |
| 11b | Interoperation with NMAS device identity/lifecycle | **VERIFIED** (local; attestation pending) | NP01–09 through the real `adopt_existing`, `ManagedDevice` and `MaintenanceRecord` |
| 11c | OS-version admission | EXTERNALLY_BLOCKED | NMAS persists no observed per-device version |
| 11d | Restart-safe, idempotent, audited, redacted | IMPLEMENTED_NOT_LIVE_VERIFIED | runtime/governance suites |
| 12 | Versioned documentation | IMPLEMENTED_NOT_LIVE_VERIFIED | 30+ docs + 7 runbooks present; examples are simulated |
| 13 | Focused, integration and regression testing, plus live fixtures | INCOMPLETE (attested) / EXTERNALLY_BLOCKED (live) | local runs in §5; attested runs pending; no approved fixtures |
| 14 | Final deliverable | INCOMPLETE | this report; final acceptance depends on the attested and live campaign |

### UT-001..090 / IT-01..20 traceability

* **UT:** 48 of 90 IDs are referenced explicitly in tests or docs: UT001 004 010 012 013 017 020 022 024–028 030–032 035 038 040 041
  045–047 049 050 053–055 057 063–066 069 070 075 077 080–090. The other 42 IDs have behaviour coverage in the suites but no explicit
  ID mapping. Mapping them is **INCOMPLETE** in-repo work. It is documentation only and needs no new code.
* **IT:** IT01 07 08 11 12 13 14 16 20 are referenced, all with simulated inputs (IMPLEMENTED_NOT_LIVE_VERIFIED).
  IT02–06, 09, 10, 15 and 17–19 need live fault-injection fixtures: **EXTERNALLY_BLOCKED**.

## 9. External prerequisites (exact)

1. **Gateway-attested runs.** These must be requested by the orchestrator. See §11.
2. **Authoritative observed OS version per device.** NMAS has no such record. It needs a reviewed model or provider, for example
   persisting `show version` from the management probes with provenance. Until it exists, every device stays `VERSION_UNKNOWN`
   and nothing is probed.
3. **Device adoption and identity verification.** Lab devices must be adopted (*Adopt Existing Device*) and identity-VERIFIED
   through the existing workflow. Until then they answer `UNREGISTERED` or `IDENTITY_UNVERIFIED`.
4. **Site readers and runners, qualified and bound in settings:**
   * flow/probe runners
   * DNS resolver
   * FIB, QoS, physical, protocol and STP/L2 readers
   * baseline/history/config-snapshot sources
   * production-flow and service-health providers
5. **Approved isolated fault fixtures.** RB01–RB06 and the IT campaign need these. RB07 also needs real optics hardware, or an accepted documented limitation.
6. **Execution-boundary decision.** Either keep remediation execution as a hand-off to the Change page (current, fail-closed), or
   approve troubleshooting as a second, governed caller of the change engine. The second option changes `core.tests.test_contracts`.
7. **Rollback service.** A reviewed public port of the rollback service is needed before compensation can run. Until then, abort with compensation fails closed.
8. **AI provider and approval** for the operational AI investigation campaign.
9. **Documentation fix.** `LAB_REQUIREMENTS.md`, `IMPLEMENTATION_PLAN.md` and `GAP_ANALYSIS.md` must stop pointing new work at the legacy archive (separate approval).

## 10. Deployment and rollback plan (not executed; needs authorization)

1. **Review.** Get approval to commit the worktree on `troubleshooting/job-9aa10b4e7ca7-port`, then push and open a PR against `main`.
   None of this is done without authorization.
2. **CI.** The PR runs Tier-3 in targeted mode: the 6 static checks plus 160 selected Django test modules.
3. **Deploy (operator).**
   * Apply `0037_troubleshooting`. It is additive: 18 new tables, no change to existing tables.
   * Optionally set `NMAS_TS_DEPLOYMENT = {"inventory": "core.services.troubleshooting.adapters.nmas_providers.inventory", "lifecycle_provider": "…nmas_providers.lifecycle"}`.
   * Do not configure a version provider. Admission then stays fail-closed, as intended.
   * No production device or orchestration-service change.
4. **Rollback.**
   * Revert the merge commit.
   * `manage.py migrate core 0036` drops only the `Ts*` tables. Export any case data first through the API export route (`ts_api_export`).
   * Remove the `NMAS_TS_DEPLOYMENT` settings.
   * The routes disappear together with their policy entries, because both live in the same commit.

## 11. Resume instructions for JOB-9AA10B4E7CA7 (from checkpoint #23)

* Do **not** repeat the 30 completed subtasks: their source is ported unchanged apart from the integration and quality edits listed
  in the port record.
* Work only in `nmas-public-dev-troubleshooting`, never in `clab_dualstack_lab`.
* **Step 1. First attested evidence.** Run in batches so each finishes inside the 480 s limit, for example:
  * `python3 -I /opt/ai-orchestrator/gateway/client/aiorch_gw.py test nmas-public-dev-troubleshooting core.tests.test_troubleshooting_access core.tests.test_troubleshooting_nmas_providers core.tests.test_troubleshooting_deployment core.tests.test_troubleshooting_runtime_ports`
  * then the remaining `test_troubleshooting_*` modules in groups of about 8.
  * Record each run ID, its `source_pin` and `worktree_changed_during_run=false`.
* **Step 2. Traceability.** Complete the UT/IT traceability mapping: the 42 unmapped UT IDs.
* **Step 3. Blocked work.** Every remaining item is an external prerequisite in §9. Request each one rather than simulating it.
