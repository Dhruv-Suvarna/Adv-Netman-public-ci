# Troubleshooting evidence, journal and report contracts (M1)

All contracts are plain serializable dicts with a `schema` field `"<name>/<major>"`. `contracts.validate(payload, expected=None)` returns
a list of problems (`[]` = valid); unknown schema/version, missing required fields, **unexpected fields**, wrong types or enum values fail.
`contracts.assert_valid` raises `ValueError`. Python module: `core.services.troubleshooting.contracts` (pure; no ORM, no I/O).

Type tokens: `str int num bool dict list any iso8601`; `enum(...)`.
Enums — verdict: PASS FAIL INCONCLUSIVE SKIPPED UNAVAILABLE · basis: OBSERVED DERIVED AI_INFERRED OPERATOR_CONFIRMED · quality: GOOD PARTIAL
AMBIGUOUS UNTRUSTED MISSING · run status: PENDING RUNNING SUCCEEDED FAILED PARTIAL DENIED UNAVAILABLE SKIPPED · stage: COLLECT NORMALIZE
BASELINE CORRELATE TEST DIAGNOSE AI REMEDIATE VERIFY DOCUMENT.

## observation/1
Required: `key` (canonical metric, e.g. `interface.oper_state`), `target` (device), `observed_at` (ISO-8601, UTC `Z`), `source`, `quality`,
`basis`. Optional: `value` (any JSON), `unit`, `max_age_seconds` (default 300), `confidence`, `parser_version`, `raw_hash`, `raw_pointer`,
`redaction_status`, `evidence_id`, `is_missing_data`, `missing_reason`, `dedupe_key`, `stage_decision`.
Rules: `is_missing_data=true` ⇒ stored with `quality=MISSING`, `value=null` (permission denied / unsupported / timeout — never a value).
An `OBSERVED` observation must cite evidence in the same case. `dedupe_key` makes replay idempotent.

## collection_bundle/1  (collector → `repository.ingest_collection_bundle`)
Required: `case_id`, `collector`, `adapter`, `adapter_version`, `idempotency_key`, `targets[]`, `command_or_api`, `status` (run status),
`observations[]` (each a valid `observation/1`). Optional: `started_at`, `finished_at`, `attempts`, `timeout_seconds`, `rate_budget`,
`privileges` (must be `read-only`), `error`, `raw` (`{source_type, text, parser, parser_version, pointer, operator_url}`), `evidence_id`.
Effects (one transaction): probe-gate every target, create/return the run by `(case, idempotency_key)`, store redacted raw evidence,
write observations, finalise the run. Re-ingesting the same bundle returns the same run and adds nothing.

## test_verdict/1  (test engine → `repository.record_test`)
Required: `test_id` (stable catalogue id, e.g. `HC07`), `test_version`, `target`, `expected`, `verdict`, `reason`. Optional: `hypothesis`
(record id), `hypothesized_condition`, `preconditions[]`, `command_or_api`, `observed{}`, `observed_summary`, `interpretation`,
`next_action`, `evidence_ids[]`, `executed_at`, `basis`, `attempt`.
Rules: PASS/FAIL must cite evidence; every non-PASS verdict needs a specific reason (≥8 chars); a retry (`attempt>1`) keeps the test's
sequence slot; all five verdicts are persisted and rendered.

## ai_handoff/1
Required: `case_id`, `coverage_manifest{}`, `trigger_uncertainty`, `allowed_tools[]`, `allowed_targets[]`, `budget{}`, `evidence_ids[]`,
`return_conditions[]`. Optional: `reasoning_log[]`, `agent_identity`, `checkpoint{}`. M1 provides the schema and the `ai_handoff` record
kind; population/policy belongs to the AI milestone.

## incident_report/1  (`reporting.build_report`)
Required: `case_id`, `generated_at`, `section_order[]`, `sections{}`, `limitations[]`, `evidence_index{}`. Optional: `filters`, `freshness`.
`sections` holds the eleven keys in spec order — `incident_summary, collection, normalization, baseline, correlation, test_matrix,
deterministic_diagnosis, ai_investigation, remediation_governance, verification_soak, final_disposition` — each
`{title, columns[], rows[], row_count[, summary]}`. Rows carry `basis` and `evidence` (list of `{evidence_id, operator_url, link_status,
note}`). A stage with no records renders one row `NOT PERFORMED / NO RECORDS` plus an explanation (never blank, never "healthy").
`evidence_index` maps evidence IDs to metadata and the raw hash/pointer/size — **never raw content**. `limitations` lists stale, untrusted,
missing-data, unavailable-test, unverified-hypothesis, missing/broken-link and audit-integrity findings.
Filters on `build_report`: device, verdict, basis, since/until (case/flow/protocol/change filters are applied by selecting the case and the
records the caller attaches to it).

## Persistence guarantees tested
Immutability (ORM instance, queryset, out-of-band SQL tamper detection), redaction (blob, JSON, audit text, report), tenant and device
scoping, privileged raw reads, export integrity/retention labelling, bounded retries, restart idempotency, freshness → UNKNOWN.

## Results
Commands run (local, `DJANGO_DEBUG=1 /opt/ai-orchestrator/nmas-env/bin/python manage.py …` from `clab_dualstack_lab/web`):

* `makemigrations --check --dry-run` → `No changes detected` (0012 depends on 0011).
* `test core.tests.test_troubleshooting_evidence` → `Ran 29 tests … OK` (UT-001–012 plus UT-024 persistence part, UT-081/082/083/084/087/090 parts, contract, freshness, exception-expiry and audit-tamper negatives).
* `test core.tests.test_architecture core.tests.test_contracts core.tests.test_admin_surface core.tests.test_troubleshooting_evidence` → `Ran 80 tests … OK` (existing architecture/contract suites unaffected by the additive models).
* Attested gateway run `aiorch_gw.py test clab_dualstack_lab core.tests.test_troubleshooting_evidence` → **not obtained**: `source pin failed: PermissionError: … /clab_dualstack_lab/monitoring/runtime/influxdb2-engine` (an unreadable runtime directory outside M1 scope). The results above are therefore local, not gateway-attested.
* `test core --parallel 4` (whole suite) aborted after ~5 min with `TypeError: cannot pickle 'traceback' object` (a worker failure that cannot be pickled back; not diagnosed — other milestones' files were being edited concurrently). A serial whole-suite run was not completed by M1; the master owns the regression campaign.
