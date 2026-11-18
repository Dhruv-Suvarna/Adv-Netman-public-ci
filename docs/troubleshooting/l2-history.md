# Restart-safe scoped L2 (MAC) history

Status: SIMULATED only (tests L2HIST-001..010); no gateway-recorded run, nothing here claims live verification.

## What exists
- `deployment.py`: new `l2_context_provider` key (both `build_runtime_deps` and settings-driven `runtime_deps`). Lazy typed `LazyContext(L2Context)`: nothing is called at construction; a provider that raises or returns a non-`L2Context` falls back to an in-memory `L2Context` and logs only the exception class in `deployment_problems`.
- `adapters/l2.py`: `PersistentMacHistory(actor, case_id, parser_version=None)` and `persistent_l2_context(...)`. Each accepted sample is stored via `repository.store_evidence` (immutable, append-only, audited; `adapter=l2-mac-history`, `command_or_api=l2.mac_history@vlan<N>`) with scope `{tenant, case_id, device, vlan, parser_version, schema}`. After a restart the first `previous()` for a key loads the newest matching evidence.
- Binding example: `"l2_context_provider": lambda: persistent_l2_context(actor, case_id)` (a provider is per case; the tenant comes from the actor, so one provider instance must never be reused for another case).

## Safeguards
`normalization.normalize_mac_table` still decides usability: first sample, short span (`mac_history_too_short`), gap > `MAC_MAX_GAP_S` (`mac_history_gap`), non-monotonic samples and partial parses (never recorded). Persistence adds: foreign tenant/case/device/VLAN/parser-version, scope mismatch, malformed or unreadable evidence, or any DB failure => no history (movement UNKNOWN, never zero). Persist failures are contained and listed in `history.problems`.

## Remaining site requirements
- Polling cadence must stay within `MAC_MAX_GAP_S` and long enough to reach `MAC_MIN_SPAN_S`; a restart longer than the gap yields `mac_history_gap` until a new window accumulates. Site schedule/owner not yet defined.
- The caller must supply the per-case provider (actor + case id); no default wiring exists, and `runtime.py` is unchanged.
- One evidence row per device/VLAN/sample accrues per case; retention follows case retention. High-churn sites may need a sampling interval or pruning policy.
- A parser version bump intentionally discards continuity.

## Commands
`cd web && DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test /opt/ai-orchestrator/nmas-env/bin/python manage.py test core.tests.test_troubleshooting_l2_history core.tests.test_troubleshooting_l2_source core.tests.test_troubleshooting_deployment core.tests.test_troubleshooting_runtime`
