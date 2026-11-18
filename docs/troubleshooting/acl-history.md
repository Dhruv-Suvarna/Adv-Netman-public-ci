# Restart-safe scoped ACL counter history

Status: SIMULATED only (tests ACLHIST-001..012); no gateway-recorded run, nothing here claims live verification.

## What exists
- `deployment.py`: new `acl_context_provider` key (both `build_runtime_deps` and settings-driven `runtime_deps`). Lazy typed `LazyContext(AclContext)`: nothing is called at construction; a provider that raises or returns a non-`AclContext` falls back to an empty in-memory `AclContext` (no history => counter deltas UNKNOWN) and logs only the exception class in `deployment_problems`. A provider path that cannot be loaded leaves `RuntimeDeps.acl_context = None`. The `RuntimeDeps.acl_context` field/contract is unchanged.
- `adapters/acl.py`: `PersistentAclHistory(actor, case_id, parser_version=None)` and `persistent_acl_context(...)`. Each accepted complete sample is stored via `repository.store_evidence` (immutable, append-only, audited; `adapter=acl-counter-history`, `command_or_api=acl.counter_history@<sha256(acl)[:24]>`) with scope `{schema, tenant, case_id, device, acl, parser_version}`. Each rule carries `{seq, text, hits, id}` where `id` = digest of sequence+text (rule identity). The first `previous()` of a (device, ACL) after a restart loads the newest matching evidence.
- Binding example: `"acl_context_provider": lambda: persistent_acl_context(actor, case_id)`.

## Safeguards
`normalization.normalize_acl_rules` still decides usability: first sample (`no_history`), short span < `ACL_MIN_SPAN_S` (`short_history`), gap > `ACL_MAX_GAP_S` (`stale_history`), counter decrease (`counter_reset`), changed rule text (`rule_changed`), and partial parses (never recorded; non-advancing timestamps are never recorded). Persistence adds: foreign tenant/case/device/ACL/parser-version, scope mismatch, `complete != true`, sample time not equal to the evidence time, rule-identity mismatch, duplicate/non-integer sequence, negative or non-integer hits, malformed JSON or any DB failure => no history (delta UNKNOWN, never zero). Persist/load failures are contained and listed (class name only) in `history.problems`; construction performs no DB access or device contact.

## Per-case composition and cadence prerequisites
- The provider is per case: the tenant comes from the actor, so a provider instance must never be reused for another case/tenant. No default wiring exists; the caller composing the case runtime supplies actor + case id.
- The case must exist (`repository.get_case`) with the actor in scope; otherwise history is unknown and nothing persists.
- Polling cadence must be >= `ACL_MIN_SPAN_S` (10 s) and <= `ACL_MAX_GAP_S` (900 s) between consecutive complete samples; a restart longer than the gap yields `stale_history` until a new window accumulates. Site schedule/owner not yet defined.
- Rule edits or counter clears (`counter_reset`) intentionally discard that rule's delta for one window. A parser version bump discards continuity.
- One evidence row per device/ACL/sample accrues per case; retention follows case retention; high-frequency sites may need a sampling interval or pruning policy.
- Only IPv4 ACLs on supported cEOS 4.28..<5.0 are covered (see `acl-source.md`).

## Commands
`cd web && DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test /opt/ai-orchestrator/nmas-env/bin/python manage.py test core.tests.test_troubleshooting_acl_history core.tests.test_troubleshooting_acl_source core.tests.test_troubleshooting_deployment core.tests.test_troubleshooting_l2_history`  (59 tests OK)
