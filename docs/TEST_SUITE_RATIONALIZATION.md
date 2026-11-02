# Django / `core` test-suite rationalization (Phase 14, Stage 0)

Stage 0 of Phase 14 audited the Django `core` suite and removed accumulated
phase-by-phase duplication **without dropping behavioral coverage**. Test count
is not a quality metric here; the numbers below are reported alongside the
evidence that each removed test's assertion still exists somewhere.

Contents: 1 Baseline · 2 Test architecture · 3 Duplication sources ·
4 Tests removed · 5 Tests consolidated · 6 Parameterized matrices ·
7 Helper / fixture consolidation · 8 Security contracts retained ·
9 Side-effect contracts retained · 10 Validation contracts retained ·
11 Runtime before/after · 12 Count before/after · 13 Behavioral coverage ·
14 Deliberately NOT removed · 15 Remaining test debt · 16 Rules for future phases ·
Production change found during Stage 0.

## 1. Pre-optimization baseline

Measured from `web/` with
`time DJANGO_DEBUG=true …/python3 manage.py test core` before any Stage-0 edit
(HEAD `9e472e3` + uncommitted Phases 11–13):

| | |
|---|---|
| Tests | **1075**, all pass |
| Reported test time | 105.1 s (a second, per-test-instrumented run: 106.3 s) |
| Wall clock / user / sys | **1 m 46.5 s** / 1 m 04.0 s / 0.4 s |
| `manage.py check` | no issues |
| `makemigrations --check --dry-run` | no changes |

`real` exceeded `user + sys` by ~42 s: the suite was **waiting on the network**
(§11), not computing.

## 2. Current test architecture

Four layers, each with one home. A new invariant belongs to exactly one layer.

| Layer | What it proves | Where |
|---|---|---|
| **A. Unit / algorithm** | validators, capability registry, routing/interface/policy services, candidate renderer, validation engine algorithms (addressing, ACL matcher, dependency graph, ordering) | `test_field_validators`, `test_field_commit`, `test_routing_service`, `test_interface_service`, `test_capabilities`, `test_candidate_renderer`, `test_interface_renderer`, `test_routing_renderer`, `test_phase12_service_policy`, `test_phase13_*` |
| **B. Contract** | architecture / security / side-effect invariants asserted across the whole module set | `test_contracts`, `test_js_contract`, `test_phase13_architecture`, `test_control_plane` |
| **C. HTTP / view boundary** | method, CSRF, ownership, draft-only, escaping, response shape — representative, *not* the semantic matrix | `test_view_boundaries`, `test_editor_views`, `test_routes`, `test_phase13_views` |
| **D. External verifiers** | monitoring, Grafana, topology, NetBox, DHCP, NMAS — run **once** at the final phase gate, never re-implemented in Django tests | `monitoring/tests`, `netbox/scripts`, `verify_*` |

Shared helpers live in `web/core/tests/helpers/` (§7).

## 3. Duplication sources

1. **Per-phase copies of the same contract.** "no Netmiko/Paramiko/subprocess import"
   existed in six files (Phases 3, 9, 10, 11, 12, 13); "typing makes no request" in
   four JS-contract files; "Change stays DRAFT / no Configlet" in three.
2. **Per-endpoint copies of the same HTTP rule.** POST-only, CSRF, cross-candidate
   ID rejection, non-DRAFT refusal and XSS escaping were re-asserted for every
   endpoint in Phases 8–12.
3. **Matrix explosion.** ~110 Phase-11 routing methods were each "commit VALUE to
   FIELD, expect VALID/INVALID"; 30 validator methods were `(input) → (ok, value)`.
4. **Superseded historical expectations.** `test_no_schema_migration_needed_for_phase10/11`,
   `test_no_phase12_model_or_migration` asserted only that a file/class with a
   particular name did not exist (trivially true, and false to intent once Phases
   13 and 14 legitimately added a model). The Phase-8/9 "Basic/Advanced share state"
   test was repeated in Phases 10 and 12.
5. **Repeated route smoke.** "home / NSOT / monitoring load" appeared in three modules.
6. **Expensive repeated fixtures.** The Phase-13 tests spent **~190 ms building
   identical setup and ~15 ms validating** (measured); each of ~300 methods rebuilt it.
7. **An unfaked external call** (§11): four tests hit a real NetBox.

## 4. Tests removed

Only where the assertion is provably carried by a stronger/central test (§13
maps every high-value invariant):

* `test_phase{9,10,11,12}_architecture` / `test_architecture` import tests → `test_contracts`
* `test_phase{9,10,11}_js_contract`, Phase-12 JS tests → `test_js_contract`
* per-endpoint GET-405 / CSRF-403 / foreign-ID / non-DRAFT / XSS copies → `test_view_boundaries`
* `test_no_schema_migration_needed_for_phase10/11`, `test_no_phase12_model_or_migration`,
  `test_no_schema_migration_required` (superseded, see §3.4)
* three duplicate route-smoke tests, three sidebar-membership tests already implied by
  the exact-labels navigation test, two "POST-only / CSRF" IPAM tests (matrix covers the endpoint)
* registry-shape copies (five platforms / four statuses / matrix counts)

496 test methods across 31 files were removed as *files*; their behavior is in
the consolidated modules below.

## 5. Tests consolidated

| Old (files → methods) | New | Methods |
|---|---|---|
| Phase 9/10/11 JS contracts (+ Phase 12 JS) → 32 | `test_js_contract` | 6 |
| Phase 3/9/10/11/12 architecture + Phase 8 forbidden imports → 41 | `test_contracts` | 14 |
| Phase 8/9/10/11/12 view tests (+ Phase 13 boundary copies) → ~121 | `test_view_boundaries` + `test_editor_views` + trimmed `test_phase13_views` | 16 + 12 + 15 |
| Phase 11 bgp/ospf/rip/eigrp/isis/static/routing_service → 110 | `test_routing_service` | 18 |
| Phase 11 renderer + BGP/OSPF/RIP rendering → 18 | `test_routing_renderer` | 5 |
| Phase 10 + 11 capabilities → 23 | `test_capabilities` | 6 |
| Phase 9 validators + Phase 10 scalar validators → 30 | `test_field_validators` | 2 |
| Phase 9 commit service + Phase 10 dynamic field validation → 35 | `test_field_commit` | 13 |
| Phase 10 interface service → 24 | `test_interface_service` | 11 |
| Phase 10 renderer → 16 | `test_interface_renderer` | 4 |
| Phase 9 renderer/registry → 14 | `test_candidate_renderer` | 6 |
| Phase 8 models + services → 59 | `test_control_plane` | 13 |
| Phase 10 IPAM → 13 | `test_ipam_refresh` | 6 |
| route / navigation / services smoke → 26 | `test_routes`, `test_navigation`, `test_services` | 10 |

## 6. Parameterized matrices created

Every case has a label (`subTest(case=…)`), so a failure names the row.

| Matrix | Rows |
|---|---|
| `test_routing_service.FIELD_CASES` (commit value → VALID/INVALID, accepted value) | 43 |
| `test_field_validators.rows()` | 47 |
| `test_view_boundaries`: mutation endpoints × {GET→405, no-CSRF→403} | 24 endpoints × 2 |
| `test_view_boundaries`: add / remove / non-DRAFT / foreign-ID | 10 add + 8 remove endpoints |
| `test_view_boundaries`: escaping surfaces | 7 |
| `test_interface_renderer.SYNTAX_CASES`, `test_routing_renderer.SYNTAX_CASES` | 11 + 6 |
| `test_contracts`: (module × forbidden import / text / write) | ~250 sub-cases |
| `test_routing_service`: capability gate by platform | 8 |
| `test_capabilities`: selectable kinds per platform, status semantics | 5 + 5 |

## 7. Helper / fixture consolidation

* `phase10_helpers`, `phase11_helpers`, `phase12_helpers` (11 and 12 re-exported 10) →
  **`helpers/candidates.py`**.
* `phase13_helpers` → **`helpers/validation.py`** (multi-device Changes, fake NetBox/topology/inventory bundles).
* **`helpers/fakes.py`**: `netbox_unreachable()` for any test that renders an NSOT page.
* **`setUpTestData`**: 37 fixture-only `setUp` methods now build once per class
  (Django rolls the DB back per test and deep-copies attributes). Patch/client-based
  `setUp`s were deliberately left alone.
* Verified order-independent: the suite passes `--reverse` and `--shuffle 4242` / `--shuffle 7`.

## 8. Security contracts retained (`test_contracts`, `test_js_contract`)

No Netmiko/Paramiko/pynetbox/subprocess/requests/git/influxdb import in any Device
Builder module, in `views.py`, or in the Phase-8 control-plane modules (an alias-aware
scan, stricter than the old one); no live-adapter import; no HTTP module in the
commit/render path; no `eval`/`exec`/`__import__`/shell call; no NetBox write in
Device Builder code or the IPAM service; mutation views expose no execution
surface; allowlisted (not generic JSON-path) field registry; stable opaque IDs;
secret **references** only (`password_ref`); browser never renders vendor CLI and
never names a backend system; XSS escaping across 7 surfaces.

## 9. Side-effect contracts retained

Editing interfaces/routing/FHRP/ACL keeps the Change `DRAFT`, creates no
Configlet, no lifecycle event, no deployment/rollback audit event
(`test_contracts.EditingHasNoSideEffectsTests`); a commit never advances the
lifecycle (`test_field_commit`); Phase-13 validation writes exactly one run and one
audit event with `socket`/`subprocess`/`urllib` disabled (`test_phase13_architecture`,
unchanged); no Containerlab lifecycle text anywhere.

## 10. Validation contracts retained

All 325 Phase-13 tests are retained (accepted-only snapshots, deterministic hashing,
stale detection, source-failure → INCOMPLETE, exact-IP collisions, DHCP pool /
reservation conflicts, AUTO unreserved semantics, BGP/OSPF cross-device checks, FHRP
shared VIP semantics, conservative first-match ACL analysis, dependency
missing/cycle detection, lifecycle untouched). Only the *HTTP boundary* duplicates in
`test_phase13_views` (10 methods) were folded into the central matrix, and the
brittle "Phase 13 appears in the first 4000 characters of CURRENT_STATE.md" check was
relaxed to "the Phase 13 update note is still present".

## 11. Runtime before / after

| | Before | After | Change |
|---|---|---|---|
| Reported test time | 105.1 s | **33.4 s** | −68 % |
| Wall clock (`real`) | 1 m 46.5 s | **34.8 s** | **−67 %** |
| User CPU | 64.0 s | 33.2 s | −48 % |

Where the time went (measured with a per-test timing runner):

1. **~43 s (41 %) was network wait.** Four tests (`test_nsot` ×3, `test_phase8_views` ×1)
   rendered `core:nsot` with `clear_nsot_cache()` and no NetBox fake, so each waited ~10 s
   on a real outbound connection — contradicting the file's own docstring ("every
   NetBox call is mocked"). A fifth (Phase 9 route smoke) only looked fast because the
   cache happened to be warm (an order dependency). All now use
   `helpers.fakes.netbox_unreachable()`; those 59 tests run in ~1.6 s.
2. **Fixture rebuilding.** Phase-13 tests: ~190 ms setup vs ~15 ms validation. Moving
   fixture-only setup to `setUpTestData` and grouping matrix rows by target object
   removed most of it. `add_interface` (~47 ms) is the dominant builder.
3. Fewer redundant tests.

## 12. Count before / after

| | Before | After |
|---|---|---|
| Django-reported tests | **1075** | **682** |
| Reduction | | **−393 (−36.6 %)** — inside the 25–40 % target |
| Test modules (`test_*.py`) | 59 | 43 (+ `helpers/` package) |

Per-file after-counts are in `git status` / the file list; the 325 Phase-13 methods
are unchanged except the folded view boundary tests.

## 13. Behavioral coverage retained

Because one method can now stand for many cases, both numbers are reported:

* **After (measured):** 682 methods, of which 91 use `subTest`, executing
  **1,094 sub-cases → 1,685 behavioral cases**.
* **Before (estimated, not instrumented):** the deleted per-phase files contained ~560
  sub-case executions (module × forbidden-import product loops, the 264-iteration
  admin-surface loop, platform/validator loops), i.e. **≈ 1,600 behavioral cases**.

So behavioral coverage is **not lower**; the *method* count fell because
one-assertion-per-method copies became labelled rows. Every distinct assertion of
each removed test was carried into a consolidated test, except where noted (§4);
two assertions I initially added were stricter than the originals and were
relaxed to the original scope (a blanket "success returns no message";
"the vault reference text is absent from a comment") — no assertion was weakened.

| Must-not-lose invariant | Now asserted in |
|---|---|
| accepted vs draft separation; field-local rollback | `test_field_commit`, `test_view_boundaries.FieldCommitEndpointContractTests` |
| stable object IDs | `test_contracts`, `test_interface_service`, `test_routing_service` |
| deterministic rendering; Basic/Advanced same state | `test_interface_renderer`, `test_routing_renderer`, `test_editor_views.BasicAdvancedParityTests` |
| platform-change intent preservation | `test_capabilities`, `test_routing_service`, `test_editor_views`, `test_phase12_service_policy` |
| VLAN 200 static management | `test_editor_views.Vlan200ViewTests`, `test_ipam_refresh`, `test_phase13_addressing` |
| no NetBox write / device / Git / Containerlab | `test_contracts`, `test_phase13_architecture` |
| secret-reference policy | `test_control_plane`, `test_routing_service`, `test_contracts` |
| XSS escaping; POST/CSRF; ownership | `test_view_boundaries` |
| validation stale / source-failure / hashing / collisions / ACL / dependencies | `test_phase13_*` (unchanged) |
| Change remains DRAFT; Configlets not executed | `test_contracts`, `test_phase13_architecture` |

## 14. Deliberately NOT removed

The 325 Phase-13 methods (each drives a different finding path); notification (52),
NSOT (43), monitoring/topology integration (49), Slack (15), themes, artwork,
secret policy; the Phase-12 service tests except registry-shape and two central
duplicates; the two `test_admin_surface` tests.

## 15. Known remaining test debt

* Phase-13 finding tests could be folded into finding-code matrices where the
  fixture is identical (e.g. NAT pool conflicts, FHRP variants); left as-is because
  the fixtures differ per test and setup cost is now amortized.
* `add_interface` (~47 ms) is slow in production code; not changed in Stage 0.
* Baseline behavioral-case count is an estimate (files were replaced before it
  could be instrumented).
* Two pre-existing "is escaped" checks were vacuous: the Phase-8 configlet-description
  test asserts only the *absence* of raw markup on a detail page that never renders
  descriptions, and the editor does not render an ACL `description`. The first is kept
  (guards a future template) and marked as "not rendered today" in
  `test_view_boundaries`; the second was not carried over.
* Source-grep contract tests (`_new_id("if")`, regex names) are brittle by nature;
  they are kept in one file so they are cheap to update.

## 16. Rules for future phases (testing policy)

Before adding a test:

1. Does an existing test already prove the invariant? Then do not add one.
2. Does the case belong in an existing matrix (`FIELD_CASES`, `SYNTAX_CASES`,
   `mutation_urls()`, `rows()`)? Add a **row**, not a method.
3. Add a distinct method only for a distinct behavior or boundary.
4. No phase-number duplication: name tests for the subsystem (`test_routing_service`),
   never for the phase that introduced it; do not create `phaseNN_helpers`.
5. Architectural invariants go in `test_contracts`; add the module to its module set.
6. External systems are faked in unit/view tests (`helpers/fakes.py`); an unmocked
   network call is a test defect.
7. Real external verifiers run **once** per final regression gate.
8. New test count is not an acceptance metric; a `subTest` must carry a label.
9. Fixture-only setup uses `setUpTestData`; keep tests order-independent
   (`--reverse`/`--shuffle` must pass).

## Production change found during Stage 0 (separate from the test work)

The boundary matrix found a real, pre-existing defect: the three Phase-12 mutation
endpoints (`device_builder_phase12_add`, `_remove`, `device_builder_service_mode`)
caught only `service_policy_intent_service.CollectionMutationError`, but the shared
DRAFT-only guard raises `interface_intent_service.DraftOnlyError` (a different
class). POSTing to them for a non-DRAFT Change therefore surfaced as an **HTTP 500**
while every other add endpoint refused gracefully. `views.py` now catches both
(`_PHASE12_MUTATION_ERRORS`) and returns the usual redirect-with-error. Regression
coverage: `test_view_boundaries.ExplicitAddRemoveTests.test_non_draft_change_refuses_every_add`
(fhrp + acl rows). No other production code changed in Stage 0.

## Phase-14 addition after Stage 0

Stage 1 followed the policy above: 35 new methods (24 service, 8 view, 3 in the shared
contract extensions) rather than one per bullet -- eligibility, priority /
operation, failure modes and snippet content are matrices (`subTest`); plan endpoints
joined `test_view_boundaries` (GET 405, CSRF 403, unknown Change 404, read-only pages)
and the planning modules joined `test_contracts` (imports, no deployment text, no
NetBox write, no vendor syntax or hostname literals, thin views). Full suite after
Phase 14: **717 tests, ~43 s** (682 + 35). Fixtures use `setUpTestData`; failure-matrix
rows that create validation runs are isolated in rolled-back transactions.
