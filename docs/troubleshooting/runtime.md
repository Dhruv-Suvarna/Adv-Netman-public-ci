# Troubleshooting runtime orchestration (subtask f1-runtime)

Module: `web/core/services/troubleshooting/runtime.py`. Composes the existing collectors, adapters, contracts, repository,
`DjangoBaselineSources`, `Engine` and `reporting`. It adds no collector, store or database.

## Flow
1. **Admission** (`resolve_admission`): resolved from the authoritative inventory (`core.services.health.inventory.managed_devices`)
   plus an optional lifecycle provider. Client `target_states` are discarded and overwritten on the case (audited).
   Non-admitted (for example withdrawn) devices are never probed.
2. **Collection** (`CollectorProvider.collect`): runs the existing collectors through the injected transport. Without a
   transport every device source is recorded as unavailable (missing-data records, no values).
3. **Mapping** (`map_observations`): collector observation to engine observation. `target` is the device name and `key` is
   `<canonical key>@<subject>`. Raw hash, pointer, parser identity and gateway provenance are kept in the evidence `scope`.
   Partial or untrusted parser results become gaps or UNTRUSTED quality. Rate and reset keys need two SNMP polls.
4. **Engine and report**: `Engine.run()` then `reporting.build_report`.

## Budgets and idempotency
`RuntimeBudget.clamp` caps client-requested budgets at server limits (devices, wall clock, collection runs). Wall-clock
exhaustion is recorded as a gap. The same `(case, run_key)` is restart-safe: finished collection runs are reused, devices are
not recontacted, and no duplicate observations are written.

## Endpoint
`POST /api/v1/troubleshooting/cases/<case_id>/run/` (`ts_api_run`, role operator or higher, tenant-scoped).
Body: `{runbook?, run_key?, budget?}`. `target_states` is ignored and reported in `ignored_client_fields`.
The deployment hook `NMAS_TS_RUNTIME_FACTORY` (a dotted path) supplies `RuntimeDeps` such as a gateway-backed transport.
The default has no transports, so all device evidence is UNAVAILABLE.

## Tests (`web/core/tests/test_troubleshooting_runtime.py`)
IDs RT001-RT015: mapping with provenance, no-transport means unavailable, partial parse, untrusted parse, inventory-based
admission, withdrawn device, budget clamp and exhaustion, restart and mid-device crash resume, all seven runbooks on actual
collector output without fabrication, two-poll rate rule, endpoint auth/idempotency/fail-closed, and the factory hook.

## Verification status (this run)
- Command: `cd web && DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test /opt/ai-orchestrator/nmas-env/bin/python manage.py test core.tests.test_troubleshooting_runtime core.tests.test_troubleshooting_views`
  Result: 33 tests, OK (local run on the NMAS test venv; NOT a gateway-attested run).
- The gateway `test` op could not be used: source pinning failed with `PermissionError` on
  `monitoring/runtime/influxdb2-engine` (outside this write scope). INCOMPLETE_WORK: attested rerun once that is fixed.
- No live-fixture evidence was collected; all device output is replayed through the real collectors via simulated transports.
- Findings: the real inventory carries no `os_version`, so version-gated parsers report `VERSION_UNKNOWN` gaps until a lifecycle
  provider supplies it. The default SNMP poll needs ~14 requests, so the default `max_commands` is 16.
- INCOMPLETE_WORK: RB04 (STP) and RB05 (DNS) have no validated collector/parser for `stp.state` / DNS answers; they receive explicit
  gaps only. Gateway-backed transports are supplied through `NMAS_TS_RUNTIME_FACTORY`; none is wired by default.
