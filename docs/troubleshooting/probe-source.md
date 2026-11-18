# Active-probe source (HC22 `service.probe`, HC17 `path.trace`)

Status: implemented against an injected runner contract; **no live evidence**. All test inputs are SIMULATED; no gateway-recorded probe output is pinned and no socket was opened.

## Flow
`RuntimeDeps.probe_runner` + `probe_context` -> `adapters/probes.requests_for_device` / `policy_for` -> `collectors.ProbeCollector` -> `adapters/probes.parse_response`
(parsers `probe.tcp`, `probe.trace`, `probe-json-1.0`) -> `runtime.map_observations` -> engine keys `service.probe@tcp`, `path.trace@<flow dst>` on the flow-source device.
Deployment keys: `probe_runner_factory`, `probe_context_provider` (shared `deployment.runtime_deps` factory; runner wrapped by `ReadOnlyProbe`, which exposes only
`execute`/`capabilities`/`provenance` and rejects runners without `capabilities()`).

## Gates (in order; a failure is a missing-data record with `extra.engine_key`, never a value)
1. device admission/lifecycle (existing) -> `NOT_ADMITTED`; 2. runner absent -> `NOT_CONFIGURED` (runtime); probe context absent -> `NOT_CONFIGURED`;
3. active-probe authorization (`id`, `case_id` equal to the case, unexpired `expires_at`) -> `PERMISSION_DENIED`; 4. runner `capabilities()` must list the op -> `UNSUPPORTED_OPERATION`;
5. scope -> `COMMAND_NOT_ALLOWED`: source == collecting device and in `admitted_sources`; src/dst/protocol/port equal the case flow tuple; destination and port authorized; destination a
   routable IP from the address book; tcp only; `count` 1..`max_count`; `max_hops` <= 30; 6. budgets -> `BUDGET_EXCEEDED`: total TCP attempts <= `max_probes`, command/time/byte budgets, response <= 64 KiB;
7. exactly one runner call per request, **no retries** (a retry is more traffic on a possibly impaired path). Timeout/transport/permission/unexpected runner errors are sanitized gaps.

## Response validation
Schema `nmas.probe.response/1`; op, destination address/port, protocol and (trace) method must equal the request; the reported vantage device must equal the requested source
(`VANTAGE_MISMATCH` -> `PARSE_FAILED`); attempts/hops sequence-checked and bounded; rtt finite and within the timeout; timestamps ISO with finished >= started. Observation time is the runner's
`finished_at`. Local runner `error` attempts are excluded from `sent` (quality PARTIAL); short samples are flagged `SHORT_SAMPLE`.
Trace: an unmapped responding hop address or a silent hop before a responding hop makes the observation `UNTRUSTED_PARSE`, so HC17 is INCONCLUSIVE rather than a false path divergence.

## What results do NOT prove (carried in every value)
TCP connect proves only the SYN/SYN-ACK exchange from the stated vantage: `l7_verified=false`, `production_flow_equivalent=false`. Traces are forward-path only; non-TCP traces do not prove the TCP flow's path.
Known limitation outside this scope: `runbooks/hc.py` HC22 summary text says "handshakes succeed" -> "production service healthy"; the interpretation string over-reads a connect result and should be softened by the runbook owner. HC23 `service.probe@icmp/udp` is not served (explicit gap).

## Tests
`DJANGO_DEBUG=1 /home/student/Scripts/.venv-ci/bin/python manage.py test core.tests.test_troubleshooting_probe_source` (from `web/`): PRBSRC-001..021 pass (refusal, timeout, malformed, out-of-scope, budget, vantage, deployment, runtime->RB02, restart/resume).
Wider run (probe_source, runtime, deployment, dns_source, collectors, l2_source, runtime_ports; 222 tests): 1 failure, preexisting and out of scope: `test_RT003` line 133 (mac.table now PARSE_FAILED; integration owner must update the assertion).

## Source pins (sha256, paths under `web/core/`)
- services/troubleshooting/collectors.py a61086a83bece245c4656ec114efc43ce7d1cdbd22d93eb4f6ecb177f7a497fa
- services/troubleshooting/runtime.py b3288e5b5b103fa535e014d4af7ea6fdf9268cc6340bfedec9f3602da52c4d5e
- services/troubleshooting/deployment.py f4f2128ad4050e9aad09f11ed436b2c000b8def09225634d6628ce5c45d613ec
- services/troubleshooting/adapters/probes.py d2cd18d772bbe1800ccce8ad7038eed3273d5c94d25c50b8fcd9f83211c04ed5
- tests/test_troubleshooting_probe_source.py bf55611249adc854640413fc89333992cde4609ad210b82a2f493a4b1b938b99
(collectors/runtime/deployment also carry other workers' edits; pins are of the file state at completion.)

## Remaining operational prerequisites (INCOMPLETE_WORK until done)
- A deployment-owned runner (e.g. gateway-attested, executing a bounded non-blocking TCP connect / TTL-limited probe from the named source namespace). None exists; **no default socket runner is provided by design**.
- Settings: `NMAS_TS_DEPLOYMENT["probe_runner_factory"]` and `["probe_context_provider"]` (authorization record with case binding and expiry, admitted sources, destinations, ports, address book, hop owners). Not deployed here.
- A gateway-recorded probe/trace transcript from a disposable fixture, pinned, before any LIVE label (`describe_source` only reports LIVE when `gateway.live is True`).
- Runner-side enforcement of the same scope (the module gate is defense in depth, not the only control).
- ICMP/UDP diagnostic probes (HC23) and PMTU probing (`path.pmtu`) are not implemented.
