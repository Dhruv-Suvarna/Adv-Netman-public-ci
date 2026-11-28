# STP runtime evidence source (RB04)

Task JOB-6B9EE60379AA, attempt 2. Source HEAD cbb9c96 plus existing uncommitted troubleshooting implementation. This subtask changes only the six assigned files. No production, gateway policy, topology, compatibility ledger, remote repository, or credentials were changed/read.

## Existing path and contract

`CliCollector` catalogue `spanning_tree` invokes the existing read-only `show spanning-tree | json` operation. Parser `stp.state` / `eos-json-1.0` normalizes to the existing observation/1 contract. `runtime.map_observations` emits RB04 `stp.state@<vlan>` and `stp.port_protection@<interface>`; existing evidence storage retains raw hash/pointer, collection time, command, parser version and transport gateway provenance. No new collector, database or migration.

The parser is gated to cEOS EOS >=4.28 and <5.0; this is a simulated compatibility envelope, not a live qualification of every version. Unknown/unsupported versions are refused before transport execution. IOS XE remains evidence-only, without an STP parser. Runtime requests for port protection also select the spanning-tree collector.

`StpContext` is caller-owned per-case history, injected via `RuntimeDeps.stp_context`. Polling uses existing collector budgets/freshness (default 300 seconds), read-only validation, admission, retries, output limits and backpressure. There is no background scheduler or additional subscription. Callers must supply a cadence and retain context across polls; absent/restarted history fails closed. History is in memory and is not restart-persistent. Collect no faster than operationally approved polling limits.

## Canonical observations and safety

State includes root/bridge IDs, root port, roles/states, BPDU counters, topology-change totals, windowed TCN count, observed root-change history, loop/inconsistency indicators and explicit uncertainty. Protection fields include guard/filter/loop-guard and observed link type. Only JSON booleans are accepted for flags; negative/nonfinite counters/times and malformed IDs are unknown. Missing protection fields or link type produce untrusted protection observations.

TCN deltas are retained as interval buckets for the rolling hour: a zero next-poll delta cannot erase a recent storm. A positive bucket crossing the hour boundary remains unknown until it expires. Counter reset, a poll interval over one hour, or missing data never becomes a fabricated zero or extrapolated hourly rate. Root history requires 24 hours of sample coverage; short coverage, duplicate/regressed timestamps and partial parses remain explicitly uncertain. A reset/gap restarts coverage. Root transitions between polls can still be missed; counts describe sampled observations, not a continuous device event log.

RB04 currently consumes the whole STP state object. Therefore runtime conservatively retains uncertain state as `UNTRUSTED` (normalized value remains inspectable), preventing both false PASS and unsupported fault assertions. This can delay diagnosis until history is available; a future per-field RB04 interface can safely use independently trustworthy current roles/root data earlier. Parser errors never advance history. Production remediation remains separately governed.

`VL<n>` maps to VLAN `<n>`. Caller-supplied VLAN aliases apply only to a sole RSTP instance or sole MST0 common instance; multiple MST instances or MST1 require explicit future VLAN-to-instance mapping and are never guessed. Empty instances produce `EMPTY` gaps; only authoritative intent can declare STP-free EVPN/VXLAN exclusions, which RB04 stores as verdict `SKIPPED`, applicability `NOT_APPLICABLE`.

## Validation and source provenance

All fixture documents are **SIMULATED**, hand-written JSON, nominal cEOS 4.36.2F, three-switch triangle with a blocking alternate port in the healthy state. They are embedded in `web/core/tests/test_troubleshooting_stp_source.py`; fixture times start 2026-11-09T12:00:00Z. Seeded two-day history is simulated, not an observation of the lab. Evidence provenance tests preserve a fixture gateway dictionary with `live=false`; no test result here is gateway-attested or live-device verification.

On this attempt `python3 -I /opt/ai-orchestrator/gateway/client/aiorch_gw.py help` returned `gateway not available for this run (HTTP/1.1 503 Blocked)`. No external access or sandbox bypass was attempted. `describe_source()` labels SIMULATED/RECORDED, and LIVE_GATEWAY_PINNED only for boolean gateway.live=true supplied by the trusted transport boundary; this helper is a label, not an attestation verifier.

Stable tests STPSRC-001..018 support spec UT-020/UT-024/UT-049 and simulated IT-07: root/roles, windowed counters/root changes, loop indicators, malformed/partial JSON, version/platform refusal, empty instances, alias restrictions, source labels, parser-to-runtime-to-RB04 fault/healthy/recovery, STP-free applicability, incomplete history, reset/gap, no-contact unsupported version, retained storm window, and malformed boolean/counter safety. Runtime tests use exhaustive mode so causal loop isolation does not intentionally skip the TCN check.

Exact commands (repository root):

- `DJANGO_DEBUG=1 /home/student/Scripts/.venv-ci/bin/python web/manage.py test core.tests.test_troubleshooting_stp_source core.tests.test_troubleshooting_runbooks --verbosity 1`: **44 tests PASS** (18 source + 26 runbook tests).
- `DJANGO_DEBUG=1 /home/student/Scripts/.venv-ci/bin/python web/manage.py test core.tests.test_troubleshooting_stp_source --verbosity 1`: **18 tests PASS** on the final code.
- `DJANGO_DEBUG=1 /home/student/Scripts/.venv-ci/bin/python web/manage.py test core.tests.test_troubleshooting_stp_source core.tests.test_troubleshooting_collectors --verbosity 1`: earlier revision **115/116 PASS**, one stale assertion at `test_troubleshooting_collectors.py:903` expects `PARSER_UNAVAILABLE` for empty STP instances; now correctly yields `EMPTY`. That test is outside this worker's write scope.
- `python3 -m py_compile web/core/services/troubleshooting/{normalization,collectors,runtime}.py web/core/services/troubleshooting/adapters/stp.py web/core/tests/test_troubleshooting_stp_source.py`: PASS.
- Initial system `python3 manage.py test ...` lacked Django; using the existing local `.venv-ci` and development test settings enabled the real Django test database. No dependencies downloaded.

## INCOMPLETE_WORK for integration owner

No live cEOS JSON/schema pin or live physical fault/recovery is claimed. MST configuration, MAC churn, storm control, overlay evidence and persistent history are outside this parser scope. Global acceptance remains the master agent's responsibility. Update the out-of-scope collector assertion above; existing runtime RT003 likewise expects the former parser-unavailable behavior for `{}` (now PARSE_FAILED). Preserve those as explicit integration follow-ups.

## Final source pins (SHA-256)

```text
60be4f0018b57d001cc236b770e298c8cc6fdbceb7f0bc0932d6c06220f34d92  web/core/services/troubleshooting/normalization.py
1ebc142459d8c3990be070a9b0388045734ee36b9293ccdc7934486274734e38  web/core/services/troubleshooting/collectors.py
4b7d7f9901fc009dd97083909b31ce3f02dcf879eedeb4cea09adb955b715d06  web/core/services/troubleshooting/runtime.py
431d09f88c4e2160f0fc18588ad8bb14329c85ab5172819da62211a0650117b5  web/core/services/troubleshooting/adapters/stp.py
ecf1c931a1344f26bb1aca84e6ae7af96465d5f90f48d1caa6c10a7d60cc5c38  web/core/tests/test_troubleshooting_stp_source.py
```
