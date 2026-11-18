# NMAS V2 troubleshooting — M1 architecture (case / evidence / journal substrate)

Scope of this document: milestone **M1** of `NMAS_V2_TROUBLESHOOTING_IMPLEMENTATION_SPEC.md` (spec §2 data model, §2.1 evidence,
§7.1 report). Collectors, normalizers, the test DAG, runbooks, AI handoff and remediation (other milestones) build ON this substrate
and must import only `core.services.troubleshooting.{contracts,repository,reporting}`.

Source pin at time of writing: tracked HEAD `cbb9c96` plus the pre-existing uncommitted edits (models/urls/views/…, untracked
migration `0011`). Nothing was committed. All results below are from local Django test runs on **fixture/replay data created inside
the tests**; none is live-device evidence.

> **Port to the authoritative repository (2026-11-10).** This subsystem was first built in the legacy archive checkout
> (`clab_dualstack_lab`, origin `Adv-Netman`). It is now ported as reviewed source on branch `troubleshooting/job-9aa10b4e7ca7-port`
> of `Adv-Netman-public-ci` (base `4f950b3`). Sections 1–2 below describe the legacy discovery and are kept as history; the
> public-repository integration (migration `0037_troubleshooting`, NMAS access policy, lifecycle registry, CI classification) is in
> [`port-to-public.md`](port-to-public.md), which supersedes them where they differ.

## 1. Discovered integration points (verified by reading the source)

| Need (spec §1.3) | What exists | How M1 uses it |
|---|---|---|
| ORM / migrations | `web/core/models.py`; migrations `0001…0010` tracked, `0011_phase21_rollback_removal_remediation` untracked | New entities appended at end of `models.py`; new `0012_troubleshooting.py` depends on `0011` (verified; `makemigrations --check` → "No changes detected"). |
| Append-only idiom | `_forbid_row_mutation`, `_ImmutableQuerySet/_ImmutableManager` (bundles), `RollbackActionResult` finalise-once pattern | Same three patterns: `_TsAppendOnly` (+queryset that refuses `update/bulk_update/delete`), finalise-once `TsCollectionRun`. |
| Secret policy | `core.services.secret_policy.assert_no_secret_shaped_keys` (`*_ref` exempt) | Enforced on every JSON field of every Ts* model at `save()`. Value-level redaction is new (`contracts.redact_*`) because the existing policy only inspects keys. |
| Audit | `core.models.AuditEvent` (flat, per-change, no hash chain) | **Not reused**: it has no hash chain and is keyed to `Change`. `TsAuditEvent` is a separate per-case hash chain (spec: "evidence hash chain where existing pattern permits"; none exists). The name `AuditEvent` was already taken, hence the `Ts` prefix on all entities. |
| Golden config / soak | `ConfigurationBundle` (`BND-GOLD-…`, `bundle_digest`), `ProbationSoakRun`, routes `bundle_detail` (`device-builder/bundles/<id>/`) | `TsBaselineReference` stores revision + hash + **supplied** operator URL + soak state as plain data. M1 does **not** import these services (no coupling, no I/O); the M3 baseline worker supplies values and URL via `reverse("bundle_detail")`. A missing/broken link is stored as `MISSING`/`BROKEN`. |
| Device identity / admission / lifecycle | **No single admission-state model exists** (grep of `models.py`: only `ChangeCategory.DECOMMISSION`; inventory lives in NetBox/`nsot_service`, execution gate in `execution/eligibility.py`) | Probe gate takes the per-device state captured at intake (`TsCase.target_states`, set by the intake caller from the real source). Only `VERIFIED` is probe-able; unknown ⇒ refuse. This is an explicit seam, not an invented source of truth. |
| NetBox / topology / telemetry | `nsot_netbox.py`, `topology_service.py`, `monitoring_service.py`, `health_service.py` | Not called from M1. Their outputs enter as `TsEvidenceRef` + `TsObservation`/`TsTopologyPath` via the repository. |
| Auth / MFA / tenancy | No per-user tenant model in `core` | `Actor(name, actor_type, tenant, devices, tool_id)` is the scoping contract; the view/API layer (later milestone) builds it from the authenticated session. `tenant` is an immutable column on `TsCase`. |
| Gateway evidence | `aiorch_gw` evidence `seq` | Stored verbatim in `TsEvidenceRef.raw_pointer`; no URL is synthesised. |

## 2. Schema decisions (migration `0012_troubleshooting`)

Spec entity → model: `TroubleshootingCase`→`TsCase`, `CollectionRun`→`TsCollectionRun`, `Observation`→`TsObservation`,
`BaselineReference`→`TsBaselineReference`, `DriftAssessment`→`TsDriftAssessment`, `TopologyPath`→`TsTopologyPath`,
`Hypothesis`→`TsHypothesis`, `DiagnosticTest`→`TsDiagnosticTest`, `CorrelationRecord`→`TsCorrelationRecord`,
`ProductionFlowMonitor`→`TsProductionFlowMonitor`, `ExceptionPolicy`→`TsExceptionPolicy`, `AIHandoff`→`TsAIHandoff`,
`RemediationPlan`→`TsRemediationPlan`, `ActionExecution`→`TsActionExecution`, `VerificationRecord`→`TsVerificationRecord`,
`AuditEvent`→`TsAuditEvent`. Two supporting entities were added: `TsEvidenceRef` (provenance + operator URL + link status) and
`TsEvidenceBlob` (content-addressed, **already-redacted** raw text).

* **History classes.** Append-only (never update/delete, instance or queryset): evidence blob/ref, observation, diagnostic test,
  drift, correlation, topology path, baseline, audit event. Finalise-once: collection run (frozen at SUCCEEDED/FAILED/PARTIAL/DENIED/
  UNAVAILABLE/SKIPPED). Lifecycle-mutable (state changes audited by the repository): case, hypothesis, flow monitor, exception,
  AI handoff, remediation plan, action execution, verification. A case's `case_id`, `tenant`, `trigger_source`, `opened_at`,
  `idempotency_key` are immutable; a terminal case cannot change state; cases cannot be deleted.
* **Common envelope** (`_TsRecord`): `record_id`, `case`, `schema_version`, `basis` (OBSERVED / DERIVED / AI_INFERRED /
  OPERATOR_CONFIRMED), `stage`, `stage_decision`, `evidence_ids`. This is what makes every claim traceable to evidence and a stage
  decision (UT-010) and keeps observation / inference / hypothesis / plan / execution distinct.
* **Idempotency/restart.** Unique `(tenant, idempotency_key)` on cases; `(case, seq)` and `(case, idempotency_key)` on collection runs;
  `(case, dedupe_key)` on observations; evidence IDs are a hash of `(case, source, device, command, time, raw hash, pointer)`;
  tests are unique on `(case, seq, attempt)`; audit unique on `(case, seq)`.
* **Audit chain.** `event_hash = sha256(prev_hash | canonical_json(fields))`; `verify_audit_chain` recomputes it and reports gaps,
  broken links and tampered content (also catches edits that bypass the ORM). Observations are deliberately *not* individually audited
  (volume); evidence, runs, tests, records, probe refusals, state changes, raw reads and exports are.
* **Redaction.** Raw text is redacted before it is stored (device secrets, SNMP communities, tokens, PEM keys, bearer headers, e-mail);
  only the hash of the original is kept (`raw_sha256`) — the unredacted original is never persisted. Secret-shaped dict keys lose the
  value and are renamed `<key>_redacted_ref`. `*_ref` keys stay (references, not values).
* **Freshness.** Each observation carries `observed_at` + `max_age_seconds`; `current_state()` returns `HEALTHY`/`FAULT` only for FRESH,
  trusted data and `UNKNOWN` for stale/missing/untrusted/future-dated (beyond 120 s skew) data.
* **Exact placeholders are not evidence.** `operator_url` is stored exactly as supplied; blank ⇒ `link_status=MISSING`; an injected
  `link_checker` yields `OK`/`BROKEN`; none ⇒ `UNVERIFIED`. The report never turns a non-OK link into a hyperlink.

## 3. Public callable surface (for M3/M4 and later workers)

`repository` (all take an `Actor`; none performs device I/O):
`open_case`, `get_case`, `list_cases`, `transition_case`, `close_case`, `authorize_probe`, `store_evidence`, `get_evidence`,
`read_raw_evidence(privileged=True)`, `begin_collection_run`, `start_attempt`, `finish_run`, `resumable_runs`, `record_observation`,
`record_missing_data`, `current_state`, `ingest_collection_bundle(bundle)`, `record_test(test_verdict/1)`,
`record(actor, case, kind, …)` with kinds `baseline drift topology_path hypothesis correlation flow_monitor exception ai_handoff
remediation_plan verification`, `update_hypothesis`, `exception_status`, `trace_claim`, `stage_journal`, `audit`, `verify_audit_chain`,
`export_case`. Errors: `AccessDenied`, `TargetRefused`, `IntegrityError_`, `ValueError` (contract/semantic violations).

`reporting`: `build_report(actor, case, now=, device=, verdict=, basis=, since=, until=)` → `incident_report/1` dict;
`to_markdown(report)`, `to_html(report)`.

Schemas, enums and the dependency-free validator are documented in `evidence-contracts.md`.

## 4. Test evidence (M1)

Focused module: `core.tests.test_troubleshooting_evidence` — see the "Results" section of `evidence-contracts.md` for the exact commands
and outcomes. Not covered by M1 (belongs to other milestones): UT-013…UT-080, UT-085, UT-086, UT-088, UT-089 and every IT-* case.
