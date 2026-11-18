# Running-config snapshot ingestion (runtime -> baseline)

Scope: `web/core/services/troubleshooting/adapters/config_snapshot.py`, the `CollectorProvider._config_snapshot` hook and `run_case` default sources in `runtime.py`,
tests `web/core/tests/test_troubleshooting_config_snapshot.py` (CFGSNAP-001..010). Provenance of every result below: **SIMULATED** (replayed through the real
collector/runtime/ORM with injected transports); nothing is gateway-recorded live evidence.

## Behaviour
* Trigger: the engine's plan asks the provider for the `configs` key (runbook RB02 / HC02). The provider collects the running config **during the collect stage**, so the
  engine's baseline stage (`DjangoBaselineSources.configs`) sees it in the same run.
* Scope: only devices already admitted by the authoritative inventory (`resolve_admission`) and in the case scope; one read per device through the existing
  `CliCollector` and catalogue (`running_config` for ceos/iosxe, `frr_config` for linux). No new command, collector, store or database; no default network runner
  (`RuntimeDeps.cli_transport` stays `None` => `NOT_CONFIGURED` gap, nothing contacted).
* Gates (before any transport call): platform has a catalogued read (else UNSUPPORTED_PLATFORM); `CONFIG_SNAPSHOT` capability/admission via `collectors.check_admission`
  (the CLI collector only gates the CLI source type); command budget (`used_commands + 1 <= max_commands`, else BUDGET_EXCEEDED); collector byte/time/retry budgets and
  PermissionDenied/Timeout handling are the collector's. All refusals are explicit missing-data records (key `config.snapshot`), never values.
* Persistence: `repository.store_evidence` (redacted, content-addressed immutable `TsEvidenceBlob`; `source_type=config_snapshot`) with scope
  `platform`, `os_version`, `snapshot_kind=running-config`, collector provenance and verbatim gateway provenance. `platform` was previously absent from the scope although
  `orm_snapshot_reader` reads it.
* Empty output is a failed read: evidence quality PARTIAL + EMPTY missing record (otherwise every golden line would look like drift).
* Reading: `run_case` default sources are now `config_snapshot.baseline_sources(actor)`; `guarded_reader` wraps `orm_snapshot_reader` with per-device fail-closed states:
  DENIED (actor cannot see device), PARTIAL (non-GOOD quality), EMPTY. Stale (>24h), predating-golden, foreign-platform and corrupt handling stays in
  `ConfigSnapshotBaseline`. All of these yield UNKNOWN for the device, never "conforming" or "drift".
* Idempotency: evidence ids derive from (case, source, device, command, collected_at, raw hash, pointer); a restarted run key does not recontact finished devices; identical
  content shares one blob; the newest snapshot per device wins.

## Local results
Command (root-owned test env, from `web/`):
`DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test /opt/ai-orchestrator/nmas-env/bin/python manage.py test core.tests.test_troubleshooting_config_snapshot core.tests.test_troubleshooting_runtime core.tests.test_troubleshooting_baseline_history core.tests.test_troubleshooting_baseline_scope core.tests.test_troubleshooting_engine core.tests.test_troubleshooting_collectors core.tests.test_troubleshooting_views`
=> `Ran 208 tests ... OK` (CFGSNAP-001..010 included: usable, missing, partial, stale, denied (transport/capability/actor), budget, duplicate/restart).

## Remaining operational prerequisites (INCOMPLETE_WORK)
* A deployment must inject an authorized read-only `cli_transport` (e.g. gateway `NetmikoAdapter`); none is wired by default.
* Golden bundle items must exist for the device and platform names of `ConfigurationBundleItem.platform` must match the canonical snapshot platform (`ceos`/`iosxe`/`linux`),
  otherwise the device is UNKNOWN (`SCOPE_MISMATCH`).
* No live (gateway-recorded) verification was performed for this subtask.
* Only RB02/HC02 requests `configs`; other runbooks do not collect snapshots.
