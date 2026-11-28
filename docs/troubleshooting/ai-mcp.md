# AI / MCP continuation (M4) — `services/troubleshooting/ai.py`

Source pin: HEAD `cbb9c96` plus uncommitted working-tree changes (no commits made).

## Gate
`exhaustion_report()` blocks AI until the deterministic dossier is complete: every applicable catalog test for the case
has a non-pending verdict and evidence, or is explicitly marked unavailable/UNKNOWN with a reason. `open_handoff()` raises
`AiRefused` for an incomplete dossier (UT-055) and records the refusal. The handoff gets a bound agent identity
(`actor_type=agent`), a budget (`DEFAULT_BUDGET`: tool calls, wall seconds, bytes, devices, iterations), an expiry and the
case tenant scope.

## Tool registry (`TOOLS`)
Read-only: `get_case_summary`, `get_normalized_observations`, `get_baseline_and_golden_link`, `get_change_and_soak_history`,
`get_topology_and_paths`, `get_test_matrix`, `request_diagnostic_test`, `get_evidence`, `get_production_flow_health`,
`get_capability_and_maintenance_state`. Non-read-only, proposal-only: `propose_remediation` (creates a PROPOSED plan; it can never
approve or execute). Terminal: `submit_investigation_result`.
Arguments are schema-validated; keys such as `command`, `config`, `approve`, `tier`, `role`, `force`, `idempotency_key`, and
write verbs in any string value are rejected and audited (`call_tool` → `_deny`). Nonces make calls replay-safe; rate/size limits
cap rows. `request_diagnostic_test` runs only catalog tests through the injected `Runtime`; additional read-only investigation
(UT-057/058) produces new evidence records tied to the hypothesis.

## Iteration and persistence
`investigate()` loops agent → tool calls, records cited hypotheses (`_record_hypotheses`; citations must resolve to evidence in the
same case/tenant), appends a log and checkpoints after every call. `resume()` restores from the checkpoint after a restart.
`close_handoff()` ends with one of `RETURN_CONDITIONS`. Root-cause claims without citations are downgraded; unavailable
tools/fixtures yield UNKNOWN, never success. Only evidence with a gateway-recorded source counts as live; the `Runtime` in tests is a
fake and is labelled non-live.

## Tests
`core.tests.test_troubleshooting_ai` (25 tests; UT-055–064 plus IT-style fault cases).
