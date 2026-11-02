# Checkpoint 03 Manifest — Phases 11 through 15

Prepared: 2026-09-21

This is a review and staging manifest only. **Nothing was staged or committed while preparing it**, and the staging and
commit commands below were **not executed**.

## 1. Baseline and scope

Baseline commit (unchanged; still `HEAD`):

```text
9e472e3 Phase 6-10 checkpoint: monitoring, NSOT and Device Builder foundations
```

Branch: `main`. Checkpoint 03 contains the intentional, currently uncommitted work of Phases 11, 12, 13, 14 and 15
(including the Phase-14 test-suite rationalization, which **deletes 18 tracked test files on purpose**). It excludes the
two tracked runtime-log deltas and every ignored database, generated, cache or secret path.

Counts: 164 changed paths at the start of the audit (34 modified, 18 deleted, 112 untracked), plus this manifest = 165
(2 runtime, 163 included).

## 2. Phase 11 summary — structured routing intent

Static routing, RIPv2/RIPng, OSPFv2/OSPFv3, IS-IS, EIGRP and BGP in `sections["routing"]` using the Phase-10 stable-ID /
Tier-1-validator / single-renderer pattern (no new model). A second evidence-backed capability matrix
(`platform_drivers.ROUTING_CAPABILITIES`) filters selectable objects per platform; cEOS and Ubuntu/FRR get real syntax
verified against the tracked R1–R5 configs, while SR Linux / IOS 8000v / SONiC / IS-IS / RIPng / EIGRP stay honestly
`NOT_IMPLEMENTED`/`UNSUPPORTED`. BGP neighbor authentication is `password_ref`-only. Docs: `docs/DEVICE_BUILDER_ROUTING.md`.

## 3. Phase 12 summary — services / security / policy intent

Structured FHRP, NAT, DHCP/DHCPv6 and DNS inheritance, ACL and PBR foundations in the versioned revision schema (no
migration). Repository evidence enables cEOS VARP, DHCPv4/v6 relay, IPv4 ACL and Ubuntu nftables NAT44/PAT; everything else
stays unavailable. DHCP defaults still inherit the NMAS-primary / R2-secondary architecture; VLAN 200 stays static.
Docs: `docs/DEVICE_BUILDER_SERVICES_SECURITY_POLICY.md`.

## 4. Phase 13 summary — Tier-2 Change validation

A Python-owned, project-aware validation of a whole Change's *accepted* intent against NetBox (read-only), topology,
inventory and the same capability registries the renderer uses: deterministic snapshot + SHA-256 input hash, source
fingerprints, stale detection (STALE is a currency, not a result), stable finding codes, derived facts (including read-only
PROPOSED AUTO addresses), a typed semantic dependency graph, PASS / PASS_WITH_WARNINGS / BLOCKED / INCOMPLETE. One
append-only `ChangeValidationRun` model (migration `0003`). Docs: `docs/CHANGE_VALIDATION_AND_DEPENDENCIES.md`.

## 5. Phase 14 summary — plan builder (and Stage 0)

From the latest CURRENT passing validation (never re-run implicitly) it builds granular Configlets on the existing Phase-8
models, pinned to the exact validation run, ordered by a deterministic dependency-first topological sort over nine priority
classes; DEFINE kept distinct from ACTIVATE/ATTACH; one append-only `ChangePlan` (migration `0004`). No deployment.
Docs: `docs/CHANGE_PLAN_AND_CONFIGLETS.md`.

## 6. Phase 15 summary — health, prechecks and the postcheck engine

Fleet Quick (existing telemetry only), explicit per-device Deep Health (fixed read-only allowlists: cEOS Netmiko,
Ubuntu/FRR `docker exec`), change-aware precheck over the plan-derived scope, a reusable postcheck engine
(`evaluate_plan_requirements`), one append-only `OperationalCheckRun` model (migration `0005`), the Health / precheck UI, and a
minimal secret-free `expected` block added to the Phase-14 verification descriptors (descriptor schema 2; no migration for
it; `plan_hash` and historical plans unchanged). Nothing deploys, mutates a device, writes NetBox/Git, sends a notification,
advances a lifecycle or rolls back. Docs: `docs/HEALTH_PRECHECK_POSTCHECK.md`.

## 7. Stage-0 test-rationalization summary

Phase 14 Stage 0 replaced phase-number-based test duplication with subsystem-named modules and labelled matrices:
**1075 → 682 tests (−36.6 %)**, wall clock **106.5 s → 34.8 s**, behavioral cases not reduced (≈ 1,600 before → 1,685 after),
one real Phase-12 HTTP-500 defect fixed (`DraftOnlyError` not caught by three mutation endpoints), one 43 s unmocked-NetBox
wait removed. Phase 14 Stage 1 added 35 (717); Phase 15 adds 53 (**770**). The rules for future phases are in
`docs/TEST_SUITE_RATIONALIZATION.md` §16 and were followed: no `phaseNN`-named duplicates, endpoint rules added as rows of
`test_view_boundaries`, architectural invariants in `test_contracts`, fakes for every external system, order-independence checked.

## 8. Intentional tracked deletions

The 18 tracked files below are **deleted on purpose** by Stage 0; their assertions live in the replacement modules
(mapping in `docs/TEST_SUITE_RATIONALIZATION.md` §4–§5). They must **not** be restored. Every other tracked change under
`web/core/tests/` was also audited as intentional: `test_architecture.py` (import tests moved to `test_contracts`),
`test_navigation.py` (Phase 15 adds the Health sidebar item), `test_notification_model.py` (the retained Phase-8 schema
contract), `test_nsot.py` (NetBox fake so four tests no longer wait on the network), `test_routes.py` (smoke tests folded into
one matrix), `test_services.py` (Phase 15 graduates two Automation sections) and `test_themes.py` (Device Builder theme wiring
moved from the deleted Phase-9/10 view tests). Scoping `git add -u` to `web/core/tests/` is therefore safe.

| Deleted file | Carried by |
|---|---|
| `web/core/tests/phase10_helpers.py` | `tests/helpers/candidates.py` |
| `web/core/tests/test_phase10_architecture.py` | `test_contracts.py` |
| `web/core/tests/test_phase10_capabilities.py` | `test_capabilities.py` |
| `web/core/tests/test_phase10_field_validation.py` | `test_field_commit.py` |
| `web/core/tests/test_phase10_interface_service.py` | `test_interface_service.py` |
| `web/core/tests/test_phase10_ipam.py` | `test_ipam_refresh.py` |
| `web/core/tests/test_phase10_js_contract.py` | `test_js_contract.py` |
| `web/core/tests/test_phase10_renderer.py` | `test_interface_renderer.py` |
| `web/core/tests/test_phase10_views.py` | `test_editor_views.py / test_view_boundaries.py` |
| `web/core/tests/test_phase8_models.py` | `test_control_plane.py` |
| `web/core/tests/test_phase8_services.py` | `test_control_plane.py` |
| `web/core/tests/test_phase8_views.py` | `test_view_boundaries.py / test_control_plane.py` |
| `web/core/tests/test_phase9_architecture.py` | `test_contracts.py` |
| `web/core/tests/test_phase9_candidate_renderer.py` | `test_candidate_renderer.py` |
| `web/core/tests/test_phase9_field_commit_service.py` | `test_field_commit.py` |
| `web/core/tests/test_phase9_field_validators.py` | `test_field_validators.py` |
| `web/core/tests/test_phase9_js_contract.py` | `test_js_contract.py` |
| `web/core/tests/test_phase9_views.py` | `test_editor_views.py / test_view_boundaries.py` |

## 9. Included paths

Classification of **every** path (rule table applied to `git status -uall`; none left unclassified). "×N" collapses a new
package directory whose files are all untracked.

### Phase 11 — structured routing intent — 13 paths

| Status | Path | Note |
|---|---|---|
| `??` | `docs/DEVICE_BUILDER_ROUTING.md` | routing intent |
| `??` | `templates/features/ceos/routing_bgp.j2` | routing intent |
| `??` | `templates/features/ceos/routing_ospfv2.j2` | routing intent |
| `??` | `templates/features/ceos/routing_ospfv3.j2` | routing intent |
| `??` | `templates/features/ceos/routing_rip.j2` | routing intent |
| `??` | `templates/features/ceos/routing_static_route.j2` | routing intent |
| `??` | `templates/features/ubuntu_frr/routing_bgp.j2` | routing intent |
| `??` | `templates/features/ubuntu_frr/routing_ospfv2.j2` | routing intent |
| `??` | `templates/features/ubuntu_frr/routing_ospfv3.j2` | routing intent |
| `??` | `templates/features/ubuntu_frr/routing_static_route.j2` | routing intent |
| `??` | `web/core/services/routing_intent_service.py` | routing intent |
| `??` | `web/core/tests/test_routing_renderer.py` | routing intent |
| `??` | `web/core/tests/test_routing_service.py` | routing intent |

### Phase 12 — services / security / policy intent — 6 paths

| Status | Path | Note |
|---|---|---|
| `??` | `docs/DEVICE_BUILDER_SERVICES_SECURITY_POLICY.md` | services / security / policy intent |
| `??` | `templates/features/ceos/acl_ipv4.j2` | services / security / policy intent |
| `??` | `templates/features/ceos/fhrp_varp.j2` | services / security / policy intent |
| `??` | `templates/features/ubuntu_frr/nat_pat.j2` | services / security / policy intent |
| `??` | `web/core/services/service_policy_intent_service.py` | services / security / policy intent |
| `??` | `web/core/tests/test_phase12_service_policy.py` | services / security / policy intent |

### Phases 11 and 12 — shared Device Builder modules (routing + services/policy additions in the same files) — 11 paths

| Status | Path | Note |
|---|---|---|
| `M` | `web/core/services/candidate_renderer.py` | shared Device Builder registry / drivers / renderer / editor |
| `M` | `web/core/services/device_builder_service.py` | shared Device Builder registry / drivers / renderer / editor |
| `M` | `web/core/services/field_commit_service.py` | shared Device Builder registry / drivers / renderer / editor |
| `M` | `web/core/services/field_registry.py` | shared Device Builder registry / drivers / renderer / editor |
| `M` | `web/core/services/field_validators.py` | shared Device Builder registry / drivers / renderer / editor |
| `M` | `web/core/services/interface_intent_service.py` | shared Device Builder registry / drivers / renderer / editor |
| `M` | `web/core/services/nsot_netbox.py` | shared Device Builder registry / drivers / renderer / editor |
| `M` | `web/core/services/platform_drivers.py` | shared Device Builder registry / drivers / renderer / editor |
| `M` | `web/core/static/core/js/device_builder.js` | shared Device Builder registry / drivers / renderer / editor |
| `M` | `web/core/templates/core/device_builder/capabilities.html` | shared Device Builder registry / drivers / renderer / editor |
| `M` | `web/core/templates/core/device_builder/editor.html` | shared Device Builder registry / drivers / renderer / editor |

### Phase 13 — Tier-2 project-aware Change validation — 30 paths

| Status | Path | Note |
|---|---|---|
| `??` | `docs/CHANGE_VALIDATION_AND_DEPENDENCIES.md` | Tier-2 change validation |
| `??` | `web/core/migrations/0003_phase13_change_validation_run.py` | Tier-2 change validation |
| `??` | `web/core/services/change_validation_service.py` | Tier-2 change validation |
| `??` ×14 | `web/core/services/validation/*` | Tier-2 change validation |
| `??` | `web/core/templates/core/device_builder/validation.html` | Tier-2 change validation |
| `??` | `web/core/tests/test_phase13_addressing.py` | Tier-2 change validation |
| `??` | `web/core/tests/test_phase13_architecture.py` | Tier-2 change validation |
| `??` | `web/core/tests/test_phase13_capabilities.py` | Tier-2 change validation |
| `??` | `web/core/tests/test_phase13_dependencies.py` | Tier-2 change validation |
| `??` | `web/core/tests/test_phase13_engine.py` | Tier-2 change validation |
| `??` | `web/core/tests/test_phase13_routing.py` | Tier-2 change validation |
| `??` | `web/core/tests/test_phase13_services_policy.py` | Tier-2 change validation |
| `??` | `web/core/tests/test_phase13_snapshot.py` | Tier-2 change validation |
| `??` | `web/core/tests/test_phase13_sources.py` | Tier-2 change validation |
| `??` | `web/core/tests/test_phase13_topology.py` | Tier-2 change validation |
| `??` | `web/core/tests/test_phase13_validation_runs.py` | Tier-2 change validation |
| `??` | `web/core/tests/test_phase13_views.py` | Tier-2 change validation |

### Phase 14 — plan builder and Stage-0 test rationalization — 59 paths

| Status | Path | Note |
|---|---|---|
| `??` | `docs/CHANGE_PLAN_AND_CONFIGLETS.md` | plan builder + Stage-0 test rationalization docs |
| `??` | `docs/TEST_SUITE_RATIONALIZATION.md` | plan builder + Stage-0 test rationalization docs |
| `??` | `web/core/migrations/0004_phase14_change_plan.py` | plan builder + Stage-0 test rationalization docs |
| `??` | `web/core/services/change_plan_service.py` | plan builder + Stage-0 test rationalization docs |
| `M` | `web/core/services/configlet_service.py` | plan-less Configlet sequencing |
| `??` ×9 | `web/core/services/planning/*` | plan builder + Stage-0 test rationalization docs |
| `??` | `web/core/templates/core/device_builder/plan.html` | plan builder + Stage-0 test rationalization docs |
| `??` ×4 | `web/core/tests/helpers/*` | consolidated test helpers (Stage 0) |
| `D` | `web/core/tests/phase10_helpers.py` | intentional Stage-0 test-suite rationalization deletion |
| `??` | `web/core/tests/test_admin_surface.py` | consolidated test module (Stage 0); Phase 15 adds rows/contracts to contracts + view_boundaries |
| `M` | `web/core/tests/test_architecture.py` | tracked test edited by Stage 0 (Phase 15 also edits navigation + services) |
| `??` | `web/core/tests/test_candidate_renderer.py` | consolidated test module (Stage 0); Phase 15 adds rows/contracts to contracts + view_boundaries |
| `??` | `web/core/tests/test_capabilities.py` | consolidated test module (Stage 0); Phase 15 adds rows/contracts to contracts + view_boundaries |
| `??` | `web/core/tests/test_change_plan_service.py` | plan builder + Stage-0 test rationalization docs |
| `??` | `web/core/tests/test_change_plan_views.py` | plan builder + Stage-0 test rationalization docs |
| `??` | `web/core/tests/test_contracts.py` | consolidated test module (Stage 0); Phase 15 adds rows/contracts to contracts + view_boundaries |
| `??` | `web/core/tests/test_control_plane.py` | consolidated test module (Stage 0); Phase 15 adds rows/contracts to contracts + view_boundaries |
| `??` | `web/core/tests/test_editor_views.py` | consolidated test module (Stage 0); Phase 15 adds rows/contracts to contracts + view_boundaries |
| `??` | `web/core/tests/test_field_commit.py` | consolidated test module (Stage 0); Phase 15 adds rows/contracts to contracts + view_boundaries |
| `??` | `web/core/tests/test_field_validators.py` | consolidated test module (Stage 0); Phase 15 adds rows/contracts to contracts + view_boundaries |
| `??` | `web/core/tests/test_interface_renderer.py` | consolidated test module (Stage 0); Phase 15 adds rows/contracts to contracts + view_boundaries |
| `??` | `web/core/tests/test_interface_service.py` | consolidated test module (Stage 0); Phase 15 adds rows/contracts to contracts + view_boundaries |
| `??` | `web/core/tests/test_ipam_refresh.py` | consolidated test module (Stage 0); Phase 15 adds rows/contracts to contracts + view_boundaries |
| `??` | `web/core/tests/test_js_contract.py` | consolidated test module (Stage 0); Phase 15 adds rows/contracts to contracts + view_boundaries |
| `M` | `web/core/tests/test_navigation.py` | tracked test edited by Stage 0 (Phase 15 also edits navigation + services) |
| `M` | `web/core/tests/test_notification_model.py` | tracked test edited by Stage 0 (Phase 15 also edits navigation + services) |
| `M` | `web/core/tests/test_nsot.py` | tracked test edited by Stage 0 (Phase 15 also edits navigation + services) |
| `D` | `web/core/tests/test_phase10_architecture.py` | intentional Stage-0 test-suite rationalization deletion |
| `D` | `web/core/tests/test_phase10_capabilities.py` | intentional Stage-0 test-suite rationalization deletion |
| `D` | `web/core/tests/test_phase10_field_validation.py` | intentional Stage-0 test-suite rationalization deletion |
| `D` | `web/core/tests/test_phase10_interface_service.py` | intentional Stage-0 test-suite rationalization deletion |
| `D` | `web/core/tests/test_phase10_ipam.py` | intentional Stage-0 test-suite rationalization deletion |
| `D` | `web/core/tests/test_phase10_js_contract.py` | intentional Stage-0 test-suite rationalization deletion |
| `D` | `web/core/tests/test_phase10_renderer.py` | intentional Stage-0 test-suite rationalization deletion |
| `D` | `web/core/tests/test_phase10_views.py` | intentional Stage-0 test-suite rationalization deletion |
| `D` | `web/core/tests/test_phase8_models.py` | intentional Stage-0 test-suite rationalization deletion |
| `D` | `web/core/tests/test_phase8_services.py` | intentional Stage-0 test-suite rationalization deletion |
| `D` | `web/core/tests/test_phase8_views.py` | intentional Stage-0 test-suite rationalization deletion |
| `D` | `web/core/tests/test_phase9_architecture.py` | intentional Stage-0 test-suite rationalization deletion |
| `D` | `web/core/tests/test_phase9_candidate_renderer.py` | intentional Stage-0 test-suite rationalization deletion |
| `D` | `web/core/tests/test_phase9_field_commit_service.py` | intentional Stage-0 test-suite rationalization deletion |
| `D` | `web/core/tests/test_phase9_field_validators.py` | intentional Stage-0 test-suite rationalization deletion |
| `D` | `web/core/tests/test_phase9_js_contract.py` | intentional Stage-0 test-suite rationalization deletion |
| `D` | `web/core/tests/test_phase9_views.py` | intentional Stage-0 test-suite rationalization deletion |
| `M` | `web/core/tests/test_routes.py` | tracked test edited by Stage 0 (Phase 15 also edits navigation + services) |
| `M` | `web/core/tests/test_services.py` | tracked test edited by Stage 0 (Phase 15 also edits navigation + services) |
| `M` | `web/core/tests/test_themes.py` | tracked test edited by Stage 0 (Phase 15 also edits navigation + services) |
| `??` | `web/core/tests/test_view_boundaries.py` | consolidated test module (Stage 0); Phase 15 adds rows/contracts to contracts + view_boundaries |

### Phase 15 — health, prechecks, postcheck engine — 38 paths

| Status | Path | Note |
|---|---|---|
| `??` | `docs/CHECKPOINT_03_MANIFEST.md` | this manifest |
| `??` | `docs/HEALTH_PRECHECK_POSTCHECK.md` | Phase-15 docs |
| `M` | `web/config/settings.py` | HEALTH_LIVE_TIMEOUT_SECONDS only |
| `??` | `web/core/migrations/0005_phase15_operational_check_run.py` | OperationalCheckRun + audit event types |
| `M` | `web/core/services/automation_service.py` | sidebar / automation graduation / badge filters |
| `??` ×16 | `web/core/services/health/*` | health package |
| `??` | `web/core/services/health_service.py` | health facade |
| `M` | `web/core/templates/core/automation/landing.html` | sidebar / automation graduation / badge filters |
| `M` | `web/core/templates/core/automation/section.html` | sidebar / automation graduation / badge filters |
| `M` | `web/core/templates/core/base.html` | sidebar / automation graduation / badge filters |
| `??` | `web/core/templates/core/device_builder/precheck.html` | precheck page |
| `??` ×5 | `web/core/templates/core/health/*` | health templates |
| `M` | `web/core/templatetags/core_extras.py` | sidebar / automation graduation / badge filters |
| `??` ×1 | `web/core/tests/helpers/*` | Phase-15 test fixtures |
| `??` | `web/core/tests/test_change_precheck.py` | Phase-15 tests (subsystem-named) |
| `??` | `web/core/tests/test_health_engine.py` | Phase-15 tests (subsystem-named) |
| `??` | `web/core/tests/test_health_sources.py` | Phase-15 tests (subsystem-named) |
| `??` | `web/core/tests/test_health_views.py` | Phase-15 tests (subsystem-named) |
| `M` | `web/core/theme_registry.py` | sidebar / automation graduation / badge filters |

### Cumulative shared files (each phase appended to them) — 6 paths

| Status | Path | Note |
|---|---|---|
| `M` | `docs/CURRENT_STATE.md` | cumulative shared file (each phase appended) |
| `M` | `web/core/context_processors.py` | cumulative shared file (each phase appended) |
| `M` | `web/core/models.py` | cumulative shared file (each phase appended) |
| `M` | `web/core/templates/core/device_builder/change_detail.html` | cumulative shared file (each phase appended) |
| `M` | `web/core/urls.py` | cumulative shared file (each phase appended) |
| `M` | `web/core/views.py` | cumulative shared file (each phase appended) |

## 10. Excluded paths

| Path / pattern | Class | Why |
|---|---|---|
| `Run_Logs.log` | EXCLUDE — RUNTIME | tracked runtime log rewritten by orchestrator runs (Phase 15 never imports `master.py`; it was already modified before this phase) |
| `logs/R2.log` | EXCLUDE — RUNTIME | tracked runtime log written by the R2 device logging |
| `web/db.sqlite3` | ignored | development database (migration `0005` applied and re-applied as a no-op) |
| `web/staticfiles/` | ignored | generated |
| `netbox/.env`, `netbox/runtime/` | ignored | NetBox secrets / candidate renders |
| `monitoring/runtime/*` | ignored | monitoring secrets and state |
| `__pycache__/`, `*.pyc` | ignored | caches |
| live-verification scripts and captures | outside the repo | kept only in the session scratchpad; no browser artifacts, JSON downloads, sockets or PIDs were created in the tree |

No path needs an operator inclusion decision (`NEEDS OPERATOR DECISION`: none).

## 11. Secrets / runtime audit

* **Pattern scan** (Slack webhook, private keys, cloud keys, GitHub/Slack tokens, Django `SECRET_KEY` literals, literal
  credential assignments, 40-hex tokens) over the added lines of the 25 modified files and the full content of the untracked
  files (144 paths scanned): **1 hit**, `web/core/tests/test_health_sources.py` — a deliberately fake canary string
  (`hunter2-SECRET-…`) that the sanitization test asserts never appears in a stored report or audit event. Not a credential.
* **Real-value scan**: the project's actual secret values (13: inventory cEOS password, `master.py` root password, the
  monitoring and NetBox runtime secrets) were read in-process and searched for in every included path, values never printed.
  Values of 6+ characters (12 of the 13): **one match**, `web/core/tests/test_nsot.py` — a *negative* assertion (strings the NSOT
  page must never render) that is **already present at committed `HEAD` 9e472e3 (Phase 7)** and not in any line this checkpoint
  adds. The 13th value (the cEOS inventory credential) is a 5-character everyday word, so a substring scan of it is inherently
  noisy; a whole-word check of the three documents written or extended this phase (this manifest,
  `HEALTH_PRECHECK_POSTCHECK.md`, `CURRENT_STATE.md`) found it only as ordinary technical prose (a test file name and
  interface-state wording), never as a credential. `inventory.yml` itself is unchanged by this checkpoint. Nothing new leaks.
* `git diff --check` (tracked changes, runtime logs excluded): clean. Untracked files: 0 trailing-whitespace lines, 0 conflict markers.
* No Slack webhook, NetBox token, device password, private key, Django `SECRET_KEY` or cloud credential is in the checkpoint.
* No synthetic application rows remain (dev DB after the live verification: 0 Changes / runs / plans / Configlets / notifications,
  312 pre-existing audit rows — identical to before). No test server or verification process is running (`runserver` never used).
* **Operator observation (pre-existing, outside this checkpoint):** committed files already contain lab credentials —
  `master.py` (`ROOT_PASSWORD`), `hostserv.py`, `address_report.py` and `inventory.yml` (`ceos_password`). They were committed
  before Phase 11 and are untouched here. Phase 15 does not copy them anywhere: cEOS uses the existing `inventory.yml` path, and
  the Linux adapter uses `docker exec` and needs no credential. Consider moving them to the ignored runtime secrets area in a
  separate change.

## 12. Validation results (all observed 2026-09-21; nothing reported without being run)

| Gate | Result |
|---|---|
| Django `manage.py test core` | **770 tests OK** in 52.1 s (wall 53.8 s). Baseline before Phase 15: 717 in 41.0 s (wall 42.4 s) |
| Order independence | `--reverse` 770 OK; `--shuffle 4242` 770 OK; `--shuffle 7` 770 OK |
| `manage.py check` | no issues |
| `makemigrations --check --dry-run` | no changes |
| `manage.py migrate` (twice) | `0005` applied; second run "No migrations to apply" |
| Monitoring `unittest discover` | **446 OK** (unchanged baseline) |
| `verify_grafana.py --verbose` | PASS — dashboards=7 panels=62 variables=23 queries=79 datasource=OK secrets=PASS |
| `verify_topology.py` | PASS — 19/19, nodes=15 edges=23, real_mode=PASS demo_mode=PASS |
| `verify_netbox_model.py` | 392/392 |
| `populate_netbox.py --check` | UNCHANGED=318 |
| `verify_reservations.py` | READY (0 reservation targets) |
| `verify_dhcp_servers.py` | PASS — NMAS active/active, R2 active/active |
| `verify_nmas_infrastructure.sh` | PASS=20 FAIL=0 |
| Mutation checks (6 deliberate defects) | each caught by the intended test; files restored byte-for-byte (one post-check found a mis-reverted `CPU_HIGH` flag, fixed, suite re-run) |
| Live verification (real lab, read-only) | Fleet Quick 10/10 HEALTHY, 0 device calls; R1 + R3 Deep Health HEALTHY; synthetic Change → real-source validation PASS → plan → precheck PASS; stale precheck BLOCKED without device contact; postcheck fake PASS / missing address FAIL / real undeployed network FAIL; R1/R2 running-config, R3 address/route/NAT, containers and listeners byte-identical before and after; synthetic rows removed |

## 13. Known limitations

* Fleet Quick has no routing/adjacency telemetry (the stored schema has none); routing is a live Deep-Health concern.
* Plans built before Phase 15 lack the descriptors' `expected` facts and evaluate INCOMPLETE until rebuilt (none exist in the dev DB).
* No evaluator exists for routing-process definition, BGP network advertisement, RIP binding, NAT pool, PBR or hostname
  identity; such requirements are UNKNOWN, so a plan containing them can at best be postchecked INCOMPLETE.
* OSPF adjacency expectation relies on the pinned validation (`OSPF_ONE_SIDED`); no BGP/OSPF settling window is in the engine.
* FHRP / ACL / DHCP-relay evidence is cEOS-only (running-config parsing); NAT evidence is Linux-only (nftables); Linux parsing is
  verified against FRR 8.4.4. Linux live reads need Docker access for the server process.
* Precheck live reads run synchronously inside the POST, bounded by `HEALTH_LIVE_TIMEOUT_SECONDS` (default 8 s).
* The precheck's source-freshness check reuses the Phase-13 source snapshot, whose read-only git metadata reads
  (`rev-parse`, `log -1`, `status --porcelain`) are the only subprocess calls a refused precheck makes.
* Carried from earlier phases (see their docs): Phase 13's graph has no cross-device edges today; Ubuntu/FRR NAT snippets repeat
  the table header per rule; foundation/monitoring/persistence plan stages are empty by design.
* The 446-test monitoring suite prints a mocked DHCP table ("inactive") from its own unit test; the real verifier is active/active.

## 14. Exact recommended staging commands

Run from `/home/student/Scripts/clab_dualstack_lab` after review. **Do not execute blindly.** They never use `git add .`,
`git add -A` or `git commit -a`, and deliberately omit `Run_Logs.log` and `logs/R2.log`. The only bulk forms are (a)
`git add -u -- web/core/tests/`, justified in §8, and (b) whole new package directories that contain only intended files.

```bash
# 0. preconditions (expected: main / 9e472e3 / nothing staged)
git branch --show-current
git rev-parse --short HEAD
git diff --cached --name-only

# 1. tracked files modified by Phases 11-15 (explicit, non-test)
git add -- docs/CURRENT_STATE.md
git add -- web/config/settings.py
git add -- web/core/context_processors.py
git add -- web/core/models.py
git add -- web/core/services/automation_service.py
git add -- web/core/services/candidate_renderer.py
git add -- web/core/services/configlet_service.py
git add -- web/core/services/device_builder_service.py
git add -- web/core/services/field_commit_service.py
git add -- web/core/services/field_registry.py
git add -- web/core/services/field_validators.py
git add -- web/core/services/interface_intent_service.py
git add -- web/core/services/nsot_netbox.py
git add -- web/core/services/platform_drivers.py
git add -- web/core/static/core/js/device_builder.js
git add -- web/core/templates/core/automation/landing.html
git add -- web/core/templates/core/automation/section.html
git add -- web/core/templates/core/base.html
git add -- web/core/templates/core/device_builder/capabilities.html
git add -- web/core/templates/core/device_builder/change_detail.html
git add -- web/core/templates/core/device_builder/editor.html
git add -- web/core/templatetags/core_extras.py
git add -- web/core/theme_registry.py
git add -- web/core/urls.py
git add -- web/core/views.py

# 2. tests: tracked modifications AND the intentional Phase-14 deletions under this one path (all audited, section 8)
git add -u -- web/core/tests/

# 3. new documentation
git add -- docs/CHANGE_PLAN_AND_CONFIGLETS.md
git add -- docs/CHANGE_VALIDATION_AND_DEPENDENCIES.md
git add -- docs/CHECKPOINT_03_MANIFEST.md
git add -- docs/DEVICE_BUILDER_ROUTING.md
git add -- docs/DEVICE_BUILDER_SERVICES_SECURITY_POLICY.md
git add -- docs/HEALTH_PRECHECK_POSTCHECK.md
git add -- docs/TEST_SUITE_RATIONALIZATION.md

# 4. new feature templates
git add -- templates/features/ceos/acl_ipv4.j2
git add -- templates/features/ceos/fhrp_varp.j2
git add -- templates/features/ceos/routing_bgp.j2
git add -- templates/features/ceos/routing_ospfv2.j2
git add -- templates/features/ceos/routing_ospfv3.j2
git add -- templates/features/ceos/routing_rip.j2
git add -- templates/features/ceos/routing_static_route.j2
git add -- templates/features/ubuntu_frr/nat_pat.j2
git add -- templates/features/ubuntu_frr/routing_bgp.j2
git add -- templates/features/ubuntu_frr/routing_ospfv2.j2
git add -- templates/features/ubuntu_frr/routing_ospfv3.j2
git add -- templates/features/ubuntu_frr/routing_static_route.j2

# 5. new migrations
git add -- web/core/migrations/0003_phase13_change_validation_run.py
git add -- web/core/migrations/0004_phase14_change_plan.py
git add -- web/core/migrations/0005_phase15_operational_check_run.py

# 6. new service modules and packages (packages contain only intended .py files; __pycache__ is ignored)
git add -- web/core/services/change_plan_service.py
git add -- web/core/services/change_validation_service.py
git add -- web/core/services/health_service.py
git add -- web/core/services/routing_intent_service.py
git add -- web/core/services/service_policy_intent_service.py
git add -- web/core/services/planning/
git add -- web/core/services/validation/
git add -- web/core/services/health/

# 7. new templates
git add -- web/core/templates/core/device_builder/plan.html
git add -- web/core/templates/core/device_builder/precheck.html
git add -- web/core/templates/core/device_builder/validation.html
git add -- web/core/templates/core/health/

# 8. new (consolidated + Phase 11-15) test modules and shared helpers
git add -- web/core/tests/helpers/
git add -- web/core/tests/test_admin_surface.py
git add -- web/core/tests/test_candidate_renderer.py
git add -- web/core/tests/test_capabilities.py
git add -- web/core/tests/test_change_plan_service.py
git add -- web/core/tests/test_change_plan_views.py
git add -- web/core/tests/test_change_precheck.py
git add -- web/core/tests/test_contracts.py
git add -- web/core/tests/test_control_plane.py
git add -- web/core/tests/test_editor_views.py
git add -- web/core/tests/test_field_commit.py
git add -- web/core/tests/test_field_validators.py
git add -- web/core/tests/test_health_engine.py
git add -- web/core/tests/test_health_sources.py
git add -- web/core/tests/test_health_views.py
git add -- web/core/tests/test_interface_renderer.py
git add -- web/core/tests/test_interface_service.py
git add -- web/core/tests/test_ipam_refresh.py
git add -- web/core/tests/test_js_contract.py
git add -- web/core/tests/test_phase12_service_policy.py
git add -- web/core/tests/test_phase13_addressing.py
git add -- web/core/tests/test_phase13_architecture.py
git add -- web/core/tests/test_phase13_capabilities.py
git add -- web/core/tests/test_phase13_dependencies.py
git add -- web/core/tests/test_phase13_engine.py
git add -- web/core/tests/test_phase13_routing.py
git add -- web/core/tests/test_phase13_services_policy.py
git add -- web/core/tests/test_phase13_snapshot.py
git add -- web/core/tests/test_phase13_sources.py
git add -- web/core/tests/test_phase13_topology.py
git add -- web/core/tests/test_phase13_validation_runs.py
git add -- web/core/tests/test_phase13_views.py
git add -- web/core/tests/test_routing_renderer.py
git add -- web/core/tests/test_routing_service.py
git add -- web/core/tests/test_view_boundaries.py

# 9. review before committing
git diff --cached --check
git status --short
git diff --cached --stat | tail -5
git diff --cached --name-only | grep -E '^(Run_Logs\.log|logs/)' && echo 'STOP: a runtime log is staged' || echo 'ok: no runtime log staged'
```

Optional pre-check that each new package directory holds only intended files:

```bash
git ls-files --others --exclude-standard -- web/core/services/planning/ web/core/services/validation/ web/core/services/health/ \
  web/core/tests/helpers/ web/core/templates/core/health/
```

## 15. Exact recommended commit command

After human review of the staged manifest and diff:

```bash
git commit -m "Phase 11-15 checkpoint: intent, validation, planning and health verification"
```

Do not run this until the staged content has been reviewed.

## 16. Phase-16 handoff

Proceed to **Phase 16: GitHub Actions Tier-3 change-effect, integration and regression validation.** Reuse: the pure
`evaluate_plan_requirements(plan, "POSTCHECK", evidence)` with synthetic evidence in CI; the plan's `plan_hash` and validation
provenance; the deterministic Phase-13/14 outputs; and the rationalized test policy (subsystem modules, labelled matrices, fakes
for external systems, real verifiers once at the gate). Keep in mind: no `.github/` workflows exist yet; CI must not have access
to the lab, so device-facing checks stay behind the explicit runtime verifiers. Deployment, transactional execution, rollback
and Complete/Partial (UAT) acknowledgement remain Phase 17.
