# Historical and snapshot baselines

Code: `web/core/services/troubleshooting/adapters/baseline_history.py` (adapters), wired into `baselines.DjangoBaselineSources` (`history`, `configs`) and `baselines.assess_drift` (per-device UNKNOWN rows). Tests: `web/core/tests/test_troubleshooting_baseline_history.py` (BLHIST-001..008 snapshot comparison, 020..026 history, 030..031 wiring, 040..042 ORM + persisted baselines). All SIMULATED/ORM-test-DB; nothing is gateway-recorded live evidence. No schema change, network, credentials or device contact.

## Functioning integrations (real sources)
| Baseline | Source used | Behaviour |
|---|---|---|
| Running config (`configs`) | immutable `TsEvidenceRef` (`source_type` `config`/`config_snapshot`, command contains `running`) + redacted content-addressed `TsEvidenceBlob`, tenant + device scoped via `Actor`; golden side = exact `ConfigurationBundleItem.payload` of the per-device golden selection | needs `DjangoBaselineSources(actor=...)` (or `config_adapter=`). Blob sha is re-verified; golden `payload_hash` re-verified. |
| Golden coverage, timestamps, soak | existing `select_golden_scope` (unchanged) | per-device revision/digest/URL/`created_at`; the adapter reads each device's own revision, never a global one. |
| Approved change relationship | `assess_drift` + `changes` source; adapter `explain(device, line, golden_entry) -> change_id` | a diff is APPROVED only if the change id is known to the change source as approved; otherwise UNAPPROVED. Soak membership still comes from `classify_changes`/`soak_window`. |
| History (`history`) | injected bounded `reader(request) -> [{t,value}]`; `FluxHistoryReader(query_fn, bucket)` builds Flux validated against `monitoring/config/gnmi_paths.yml` | `DjangoBaselineSources(history_reader=...)`; series declared in `flow_scope['history_series']` (`ref, device, measurement, field, kind gauge|counter`). |

## Rules
- **Scope match only**: just the lines the device's golden items define are compared (whitespace-normalised, comments ignored, containment). Extra running config is out of scope (neither drift nor conformity). Items with an operation other than `CREATE_DEFINE`/`ACTIVATE_ATTACH`, golden lines containing `[REDACTED]`, or no comparable lines → UNKNOWN.
- **Per-device UNKNOWN reasons** (in `unknown_devices`, rendered as `drift_kind=UNKNOWN`): `NO_GOLDEN_COVERAGE, NO_SNAPSHOT, SNAPSHOT_INTEGRITY, SNAPSHOT_UNDATED, STALE_SNAPSHOT` (>24h, CONFIG_SNAPSHOT profile), `SNAPSHOT_PREDATES_GOLDEN, SCOPE_MISMATCH` (snapshot `scope.platform` differs from item platform; an absent platform is compared but `platform_verified=false`), `GOLDEN_INTEGRITY, PAYLOAD_DENIED/UNAVAILABLE, UNSUPPORTED_OPERATION, NOTHING_COMPARABLE, SNAPSHOT_TOO_LARGE`. `configs.status=available` with `coverage=PARTIAL` when only some devices compare; all-unknown → `unavailable`.
- Each compared device keeps golden revision/digest/URL, `snapshot_evidence_id`, `snapshot_at`, age, hashes.
- **History**: devices outside the case scope are never queried (`DENIED`); reader `PermissionError` → `DENIED`, other failures → `UNAVAILABLE` (class name only). Samples: invalid/future/duplicate dropped and counted; counters become rates and the interval across a reset is discarded (`resets` counted, never a negative rate); bounded by `max_series=16`, `max_points=2000`, `window_days=30`. Per series: `learn_history` state (`LEARNED/STALE/UNKNOWN`, <12 samples = UNKNOWN), `sample_freshness` FRESH/AGED (default 1h), `newest`, `lkg_at`; result `coverage` FULL/PARTIAL/NONE with `devices_covered/uncovered`.
- `persist_baselines` stores these fields unchanged (history `stats`, `lkg_at`; golden `device_scope`); unavailable sources are persisted as MISSING quality.

## Remaining site prerequisites (INCOMPLETE until provided)
1. **No scheduled running-config collector writes `TsEvidenceRef` config snapshots yet**; until the collection stage stores `show running-config` evidence (with `scope.platform`), `configs` is UNKNOWN per device. The adapter is ready; it does not collect.
2. **No telemetry history reader is wired by default.** The site must supply an InfluxDB `query_fn` (credentials stay outside NMAS) and confirm the device tag name (`device_tag`, default `device`) and that counters/gauges in `gnmi_telemetry` match `field`; that tag schema was not verified live here. Syslog/flow history is out of this adapter.
3. Mapping a missing golden line to an approved change needs an `explain` callable (e.g. from Change/Configlet payload data); none is provided, so such drift reports UNAPPROVED (conservative).
4. Containment comparison cannot detect extra/unwanted running lines or context (parent block) differences; it is a scoped conformity check, not a full config diff.

## Test results
`cd web; DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test-only /home/student/Scripts/.venv/bin/python manage.py test core.tests.test_troubleshooting_baseline_history core.tests.test_troubleshooting_baseline_scope core.tests.test_troubleshooting_engine core.tests.test_troubleshooting_flow_runtime` → 76 tests OK (20 new). Not run through the attested gateway (known source-pin PermissionError for baseline-scope); no live evidence claimed.
