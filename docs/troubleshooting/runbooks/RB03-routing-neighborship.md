# RB03 v1.0.0 -- Routing-protocol neighborship formation failures

Find why two routers do not form (or lose) a routing adjacency and verify routes install and forward once corrected.

> Stage 1 is deterministic and read-only. Unavailable evidence is UNKNOWN. Results in this document come from SIMULATED replay fixtures unless stated otherwise (see `deterministic-engine.md`).

> **Unattended intake (2026-11-17):** live monitoring classifies this fault deterministically before any model call, and records a remediation decision (`faults.decide`). See `../MULTI_FAULT_CLASSIFICATION.md`. Operational-down, flapping, degradation, routing and reachability faults are `DIAGNOSE_AND_ESCALATE`: no automatic bounce, shutdown, counter clear, routing or process change. An administrative enable is valid only for an interface observed administratively down.

## Symptoms
An OSPF/BGP/IS-IS/RIP/EIGRP adjacency does not form, flaps, or sticks in a pre-established state.

## Triggering signals
Neighbor-down syslog/trap, gNMI neighbor state events, missing routes reported by RB02.

## Production contracts
Which adjacency (device, neighbor, protocol, AF, VRF) must exist and which prefix it must carry.

## Worked before / what changed
Device-reported last error, approved protocol/ACL changes, golden soak overlap.

## Scope
Two devices and the interface between them (and the BGP transport address).

## Collectors and permissions
Read-only protocol configuration (secrets never read), neighbor detail, interface VRF/address/MTU, control-plane ACL counters, BFD, RIB/FIB.

## Baselines
Intent = NetBox peering and VRF; golden = protocol blocks of the active bundle; historical = last time the adjacency was established.

## Hypothesis tree and tests
The tables below are generated from the executable DAG (`python -m core.services.troubleshooting.runbooks write`); edit the code, not the table.

## Hypothesis tree
Each hypothesis lists the tests that confirm or eliminate it; counter-evidence from passing tests is kept in the report.

<!-- DAG:BEGIN -->
Runbook-Id: RB03
Runbook-Version: 1.0.0
Strategies: bottom-up, follow-the-path

| Step | Test | Title | Layer | Hypothesis | Class | Hard prerequisite | Expected (healthy) |
|---|---|---|---|---|---|---|---|
| 1 | NB01 v1 | Protocol/AF capability on the platform | CTRL | H-cap | CONTEXT | - | protocol supported by capability evidence |
| 2 | NB02 v1 | Interface state, VRF and address-family reachability | L3 | H-l3 | DISCRIMINATING | NB01 | same VRF/subnet, interfaces up |
| 3 | NB03 v1 | Transport reachability (BGP TCP/179) | L4 | H-l3 | DISCRIMINATING | NB01 | TCP/179 reachable |
| 4 | NB07 v1 | Interface MTU agreement | L3 | H-params | DISCRIMINATING | NB01 | equal MTU |
| 5 | NB08 v1 | Passive interface, control-plane ACL, TTL/GTSM, BFD | L3-control | H-ctrl | DISCRIMINATING | NB01 | control plane unobstructed |
| 6 | NB04 v1 | Instance, area/AS/level, network type, AF/VRF parameters | L3-control | H-params | DISCRIMINATING | NB01 | identity parameters agree |
| 7 | NB05 v1 | Hello/dead (hold) timers | L3-control | H-params | DISCRIMINATING | NB01 | timers compatible |
| 8 | NB06 v1 | Authentication / key fingerprint (never the secret) | L3-control | H-auth | DISCRIMINATING | NB01 | auth state and fingerprint agree |
| 9 | NB09 v1 | Device-reported rejection reason | L3-control | H-reason | CONTEXT | NB01 | neighbor established / no error |
| 10 | NB10 v1 | RIB/FIB installation and forwarding after adjacency | L3 | H-install | DISCRIMINATING | NB01 | protocol routes installed in RIB and FIB |

| Hypothesis | Statement | Domain | Tests |
|---|---|---|---|
| H-cap | Protocol or address family is not supported on the platform | ctrl | NB01 |
| H-params | Protocol parameters (area/AS/level/type/AF/VRF/timers/MTU) differ | L3-control | NB04, NB05, NB07 |
| H-auth | Auth/key mismatch | L3-control | NB06 |
| H-l3 | Interface, VRF, subnet or transport prevents the session | L3 | NB02, NB03 |
| H-reason | The device reports a specific rejection reason | L3-control | NB09 |
| H-ctrl | Passive interface, control-plane filter, TTL/GTSM or BFD | L3-control | NB08 |
| H-install | Adjacency up but routes not installed/forwarded | L3 | NB10 |

<!-- DAG:END -->

## Tests and expected outcomes
Every test states its healthy expectation before execution, records the actual output with evidence ids, interpretation and next action. PASS = expectation held; FAIL = fault condition present; INCONCLUSIVE/UNAVAILABLE carry a specific reason; SKIPPED rows carry NOT_APPLICABLE / UNSAFE_TO_EXECUTE / SKIPPED_AFTER_CONFIRMED_ISOLATION with the exact reason.

## Platform adaptations
EIGRP and other protocols run only when capability evidence says the platform supports them; otherwise UNAVAILABLE, never simulated.

## Causal isolation
Start from the device's own rejection reason, then interface, transport, control plane, identity parameters, timers, authentication, MTU.

## Alternative explanations
Interface/VRF fault, transport block, passive interface, auth mismatch, MTU mismatch, protocol parameter mismatch, adjacency up but routes not installed.

## Safe stopping criteria
Stop after a proven causal parameter mismatch; context tests still run.

## AI handoff gate
Only when the device reason and every applicable test leave the cause open.

## Proposed remediations
Proposals only; nothing here is executed. Each is Tier 2 or higher unless it is explicitly 'none', requires operator approval and is subject to NMAS governance.

* **F-auth** (tier 2): re-provision key via the secret manager on the deviating end. Approvals: operator approval, security owner. Never: logging key material.
* **F-iface-l3** (tier 2): correct interface VRF/address. Approvals: operator approval. Never: n/a.
* **F-proto-config** (tier 2): minimal parameter correction on the deviating end (config-diff against NetBox/golden). Approvals: operator approval, dry-run pass. Never: clear ip bgp *, clear ip ospf process, indiscriminate neighbor reset.
* **F-timers** (tier 2): align hello/dead (hold) timers with the golden value. Approvals: operator approval. Never: neighbor reset.

## Pre- and post-tests
* F-auth: before NB06; after NB09.
* F-iface-l3: before NB02; after NB02, NB09.
* F-proto-config: before NB04, NB05, NB09; after NB09, NB10.
* F-timers: before NB05; after NB09, NB10.

## Rollback
Restore the previous parameter and verify adjacency and routes; never clear sessions indiscriminately.

## Soak
A protocol change inside the soak window is correlated, not blamed.

## Documentation example
OSPF area 0.0.0.0 vs 0.0.0.1 with the neighbor in ExStart -> F-proto-config; BGP neighbor activated for ipv6 only in VRF BLUE on one side -> AF/VRF mismatch.
