# PMTU size-dependent probe source (`path.pmtu`)

Status: implemented as an **injected-runner** source; **SIMULATED fixtures only**. No gateway-recorded PMTU output is pinned, no socket/shell default exists, and
nothing here is live verification. Without a deployment-supplied runner, an explicit size-probe opt-in and a case authorization listing `pmtu_probe`, `path.pmtu` is
an explicit gap (UNKNOWN), never a value.

## Flow
`runtime.CollectorProvider` -> `adapters/probes.requests_for_device` / `policy_for` -> `collectors.ProbeCollector` (admission -> authorization -> `pmtu_probe`
authorization -> runner capability -> scope -> packet/byte budgets -> runner) -> `adapters/probes._pmtu` (parser `probe.pmtu`) -> generic runtime mapping to
`path.pmtu@<dst>` -> `hc.pmtu_assess` -> HC21 and RB06 MT03/MT05. Runtime mapping code is unchanged (the generic retained-key branch carries it).

## Authorization and scope (all must hold, else nothing is sent)
* case-bound, unexpired authorization whose `operations` lists `pmtu_probe` (a generic probe authorization does **not** enable size probes);
* `ProbeContext.pmtu_protocols` non-empty (explicit opt-in; empty => no request at all) with protocol in `icmp|udp` (TCP is never used for size probes; UDP also needs an authorized port);
* source = case flow source and admitted, destination = case flow destination and authorized, address family matches the destination and is authorized (`pmtu_families`);
* DF must be set. Bounds: sizes <= `pmtu_max_sizes` (cap 16) distinct payloads <= `pmtu_max_payload` (cap 9000), trials/size <= cap 5, rate <= cap 10 pps, packets/rate must fit
  `max_seconds` (cap 120 s), total wire bytes <= `pmtu_max_packet_bytes` (cap 200 000), packets also count against the shared `max_probes` budget and bytes are accumulated across requests.

## Evidence contract (`nmas.pmtu/1`, value of `path.pmtu`)
* **Payload vs packet size**: runner rows carry `payload_bytes` and `packet_bytes`; the parser rejects any row where `packet_bytes != payload + IP header (20/40) + L4 header (8)`.
  Value keys use `data_bytes`/`max_ok_size` etc. (names containing "payload" are redacted by the platform, which would corrupt the value); `max_ok` is the largest passing **payload**, `max_ok_packet` the packet size, `header_overhead` the difference.
* Per size: `sent, reply, ptb, timeout, local_errors, status` in `pass|fail|partial|unknown`. `local_too_big`/`error` trials are excluded (a local EMSGSIZE says nothing about the path).
* `ptb_received`/`ptb_mtu` only from actual `ptb` trials (next-hop MTU must be plausible and below the probe packet). `ptb_visibility` is `observed`, or the runner's declaration `observable|not_observable|unknown`.
* `complete`, `largest_tested_size`, `tested_sizes`, `monotonic`; incomplete coverage or non-monotonic/intermittent results give quality PARTIAL with flags `PMTU_COVERAGE_INCOMPLETE` / `PMTU_NON_MONOTONIC`.
* `tcp_behavior_verified` and `production_flow_equivalent` are always `False`; `limitations` are carried in every value.

## Interpretation (`runbooks/hc.pmtu_assess`)
| State | Condition | HC21 / MT03 |
|---|---|---|
| OK | a DF probe with size >= need was answered, monotonic | PASS (ICMP/UDP only) |
| UNKNOWN | no probe at size >= need completed, DF unset, partial/non-monotonic loss at the need size | INCONCLUSIVE |
| LIMIT | loss/PTB at >= need and a PTB was received (PMTUD signalling works) | FAIL, non-causal, no black-hole claim |
| BLACKHOLE | DF loss at >= need, no PTB, vantage declared `ptb_visibility=observable` | FAIL (`F-pmtud`; causal only together with an interface MTU below intent) |
| LOSS_UNCONFIRMED | same loss but PTB visibility unknown/not observable | HC21: INCONCLUSIVE (FAIL `F-mtu` only if an interface MTU is below intent, black hole not claimed); MT03: FAIL at lower confidence, wording "NOT confirmed" |

Missing large-size trials or unknown PTB visibility never become a successful PMTUD or a confirmed black hole. Values **without** `schema == nmas.pmtu/1` (legacy
hand-written scenario fixtures) keep the original `max_ok`/`ptb_received` rule; they are SIMULATED and not produced by this source. MT05 derives an MSS limit only
from a probe where something passed (`max_ok` not null).

## Known gaps (INCOMPLETE_WORK)
* No production runner exists; a runner must perform the DF ICMP/UDP ladder from the flow source, report `ptb_visibility` truthfully and obey the wire bounds. `dep.build_runtime_deps`
  (deployment.py) forwards the runner's own `capabilities()`, so a runner declaring `pmtu_probe` works through it unchanged (not separately tested here).
* Actual TCP production behaviour (MSS clamping, TCP options, path asymmetry) is not measured; no gateway/live PMTU evidence was collected.

## Tests
`web/core/tests/test_troubleshooting_pmtu_source.py` (PMTUSRC-001..024): request derivation, payload/packet separation, IPv6 overhead, authorization/scope refusals that never
reach the runner, unbounded request refusal, shared packet/byte budget, runner failures, 19 malformed-response cases, missing large trials, local errors, unknown vs observable
PTB visibility, received PTB, intermittent/non-monotonic loss, legacy fixtures, runtime->HC21 end-to-end (PASS/FAIL/INCONCLUSIVE), absent runner/authorization, restart idempotency, MT03/MT05.

Command: `cd web && DJANGO_DEBUG=1 /opt/ai-orchestrator/nmas-env/bin/python manage.py test core.tests.test_troubleshooting_pmtu_source` (results recorded in the subtask report).
