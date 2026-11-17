# RB06 v1.0.0 -- MTU mismatches and PMTUD black holes

Show whether loss is size-dependent, find the limiting hop, and whether ICMP packet-too-big reaches the sender; avoid false MTU inference from blocked diagnostics.

> Stage 1 is deterministic and read-only. Unavailable evidence is UNKNOWN. Results in this document come from SIMULATED replay fixtures unless stated otherwise (see `deterministic-engine.md`).

## Symptoms
Small packets work but large transfers stall (black hole), tunnels or VPNs lose large frames.

## Triggering signals
TCP stalls after handshake, fragmentation/PTB counters, application timeouts with healthy ping.

## Production contracts
The service payload size and the intended MTU per link and tunnel.

## Worked before / what changed
Approved MTU/tunnel changes and learned giant/oversize counters.

## Scope
Forward path of the flow, tunnel interfaces and ICMP policy along the path.

## Collectors and permissions
Read-only bounded DF probes at rate limits, interface MTU, tunnel encapsulation, ICMP PTB counters, MSS, ACL counters.

## Baselines
Intent = NetBox MTU; golden = MTU in the bundle; historical = oversize counters.

## Hypothesis tree and tests
The tables below are generated from the executable DAG (`python -m core.services.troubleshooting.runbooks write`); edit the code, not the table.

## Hypothesis tree
Each hypothesis lists the tests that confirm or eliminate it; counter-evidence from passing tests is kept in the report.

<!-- DAG:BEGIN -->
Runbook-Id: RB06
Runbook-Version: 1.0.0
Strategies: follow-the-path, top-down

| Step | Test | Title | Layer | Hypothesis | Class | Hard prerequisite | Expected (healthy) |
|---|---|---|---|---|---|---|---|
| 1 | MT01 v1 | Size-dependent loss on the real service protocol | L3 | H-size | CONTEXT | - | no size-dependent loss |
| 2 | MT03 v1 | Bounded DF/PMTUD probes | L3 | H-mtu | DISCRIMINATING | MT01 | probes up to the service payload pass |
| 3 | MT02 v1 | Per-hop physical/logical/tunnel MTU and encapsulation overhead | L3 | H-mtu | DISCRIMINATING | MT01 | effective MTU >= intent |
| 4 | MT06 v1 | LAG / subinterface / VRF MTU consistency | L3 | H-mtu | DISCRIMINATING | MT01 | parent and member MTUs consistent |
| 5 | MT07 v1 | Interface giant / MTU-exceeded drops | L2 | H-mtu | DISCRIMINATING | MT01 | no size-based drops |
| 6 | MT04 v1 | ICMP packet-too-big / frag-needed delivery | L3 | H-ptb | DISCRIMINATING | MT01 | PTB generated is delivered |
| 7 | MT08 v1 | Firewall/ACL filtering of PTB and fragments; asymmetry | L4 | H-ptb | DISCRIMINATING | MT01 | PTB permitted end to end |
| 8 | MT05 v1 | MSS negotiation and clamping | L4 | H-mss | DISCRIMINATING | MT01 | MSS fits the path |

| Hypothesis | Statement | Domain | Tests |
|---|---|---|---|
| H-ptb | ICMP packet-too-big is filtered (PMTUD black hole) | policy | MT04, MT08 |
| H-size | Loss is size dependent | L3 | MT01 |
| H-mtu | A hop, tunnel or LAG limits the effective MTU | L3 | MT02, MT03, MT06, MT07 |
| H-mss | MSS is not clamped to the path | L4 | MT05 |

<!-- DAG:END -->

## Tests and expected outcomes
Every test states its healthy expectation before execution, records the actual output with evidence ids, interpretation and next action. PASS = expectation held; FAIL = fault condition present; INCONCLUSIVE/UNAVAILABLE carry a specific reason; SKIPPED rows carry NOT_APPLICABLE / UNSAFE_TO_EXECUTE / SKIPPED_AFTER_CONFIRMED_ISOLATION with the exact reason.

## Platform adaptations
Platforms without DF probe support yield UNAVAILABLE; blocked ICMP test traffic is not service impact.

## Causal isolation
Establish size dependence first, then the effective path MTU, DF probes, PTB generation versus delivery, MSS and filtering.

## Alternative explanations
Interface MTU mismatch, tunnel overhead, PTB filtering, MSS not clamped, parent/child MTU, giant drops.

## Safe stopping criteria
Stop after a proven mismatch or filter; size-independent loss is not an MTU signature.

## AI handoff gate
Only when the size signature is irregular and discriminating tests are exhausted.

## Proposed remediations
Proposals only; nothing here is executed. Each is Tier 2 or higher unless it is explicitly 'none', requires operator approval and is subject to NMAS governance.

* **F-mss** (tier 2): MSS clamp at the tunnel/edge where authorised. Approvals: operator approval. Never: broad protocol change on speculation.
* **F-path-mtu** (tier 2): align the limiting interface/tunnel MTU with intent (or clamp MSS) via approved change. Approvals: operator approval. Never: global MTU increase, disabling PMTUD.
* **F-ptb-filter** (tier 2): narrowly permit ICMPv4 type 3 code 4 / ICMPv6 type 2 on the filtering device. Approvals: operator approval, dry-run, continuous production-flow guard. Never: permit icmp any any, lowering interface MTU to hide the filter.

## Pre- and post-tests
* F-mss: before MT05; after MT01, MT05.
* F-path-mtu: before MT02, MT03; after MT01, MT03.
* F-ptb-filter: before MT04, MT08; after MT01, MT03, MT04.

## Rollback
Restore the previous MTU/policy; never raise MTU speculatively.

## Soak
Changes in the soak window are correlated, not blamed.

## Documentation example
1472-byte probes fail, r1:Eth2 MTU 1400, PTB generated but never received, r2 ACL drops ICMP packet-too-big -> F-path-mtu with F-ptb-filter.
