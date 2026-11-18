# Device-scoped golden and soak baselines

Implemented in `web/core/services/troubleshooting/baselines.py` (`DjangoBaselineSources.golden` → `_load_golden_scope` + pure `select_golden_scope`). Tests: `web/core/tests/test_troubleshooting_baseline_scope.py` (IDs BLSCOPE-001..012 pure/SIMULATED, BLSCOPE-020..025 real simulated-network bundles via `core.tests.helpers.bundles/soak`). No network, credentials, settings deployment or remote writes.

## Selection rules
- Scope is the case's device list. **No devices → `unavailable`** (the globally newest golden is never a fallback).
- Per device: the newest `GOLDEN` `ConfigurationBundle` (by `created_at`, `id`) that has a `ConfigurationBundleItem` for *that device*. A newer golden touching only other devices is ignored for it. Older golden revisions for the device are listed in `superseded_for_device`; the next older is `previous_revision`.
- Each `device_scope[]` entry keeps the exact bundle id, `bundle_digest`, direct `core:bundle_detail` URL, `link_ok` (route resolves and row exists) and the device's items (`cfg_id`, `payload_hash`, `item_digest`, `operation`, `sequence`). Devices with no golden item are `UNCOVERED` (intended config UNKNOWN, never "conforming").
- No covered device → `unavailable`.

## Coverage / mixed-revision behaviour (explicit)
| `coverage` | meaning | top-level `revision`/`digest`/`url` |
|---|---|---|
| `FULL` | all devices covered by one revision | that revision |
| `PARTIAL_FULL` | one revision, some devices uncovered (`uncovered_devices`, ambiguity `PARTIAL_COVERAGE`) | that revision |
| `MIXED` | devices map to different revisions (`revisions`, ambiguity `MIXED_REVISION`) | **empty**, `link_ok` False — no single revision is claimed; use `device_scope` |
| `PARTIAL_MIXED` | both | empty |

Legacy consumer keys (`status, source, revision, digest, url, link_ok, created_at, approved_change_id, provenance, previous_revision, previous_url, soak{soak_id,state,result,started_at,required_end_at,url,bundle_id,active}`) are preserved. `persist_baselines` additionally stores `coverage, device_scope, revisions, uncovered_devices, ambiguities` in the GOLDEN_CONFIG record data.

## Soak selection
Candidates are only soaks (a) of the PROBATION parent of a selected golden, or (b) `RUNNING` on a PROBATION bundle with an item for a scoped device (change id/lifecycle recorded; `relation` = `PARENT_OF_SELECTED_GOLDEN` / `ACTIVE_CANDIDATE_FOR_DEVICES`). A running soak on unrelated devices is never loaded.
- exactly one active candidate → `soak`; more than one → `soak: None`, ambiguity `MULTIPLE_ACTIVE_SOAKS`;
- none active and a single selected revision → latest parent soak; mixed revisions → `soak: None`, ambiguity `SOAK_WITHOUT_SINGLE_REVISION`.
`soaks` lists all relevant candidates. `soak: None` is safe for `classify_changes`/`soak_window` (state NONE).

## Test results
Gateway attested run (`aiorch_gw.py test clab_dualstack_lab core.tests.test_troubleshooting_baseline_scope`) **failed to start**: `source pin failed: PermissionError ... monitoring/runtime/influxdb2-engine` (environment issue; unmet, NOT attested). Non-attested local run:

`cd web; DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test-only /home/student/Scripts/.venv/bin/python manage.py test core.tests.test_troubleshooting_baseline_scope` → 18 tests OK.
Regression: same command with `core.tests.test_troubleshooting_engine core.tests.test_troubleshooting_flow_runtime` added → 56 tests OK.

## Limitations
- Real-lineage mixed-revision is not exercised: both fixture goldens cover R1,R2; mixed/partial-mixed are tested with simulated dicts (BLSCOPE-004/006).
- Device matching is by exact `ConfigurationBundleItem.device` name.
