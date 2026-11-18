# RB04 v1.0.0 -- STP loops and topology changes

Detect and isolate spanning-tree instability or L2 loops, and exclude STP-free EVPN/VXLAN domains from STP actions.

> Stage 1 is deterministic and read-only. Unavailable evidence is UNKNOWN. Results in this document come from SIMULATED replay fixtures unless stated otherwise (see `deterministic-engine.md`).

## Symptoms
Broadcast storms, MAC flapping, topology-change notifications, root bridge moves or a suspected Layer-2 loop.

## Triggering signals
TCN counters, MAC-move syslog, storm-control events, high CPU on switches.

## Production contracts
The VLAN/domain, the intended STP mode per switch and the intended root from NetBox.

## Worked before / what changed
Root/TCN history against the learned normal and approved Layer-2 changes.

## Scope
The switches of one STP domain and one VLAN.

## Collectors and permissions
Read-only STP state, port protection settings, MST digests, LACP, LLDP, MAC table and storm-control state.

## Baselines
Intent = NetBox L2 design and root; historical = TCN per hour; golden = STP blocks of the bundle.

## Hypothesis tree and tests
The tables below are generated from the executable DAG (`python -m core.services.troubleshooting.runbooks write`); edit the code, not the table.

## Hypothesis tree
Each hypothesis lists the tests that confirm or eliminate it; counter-evidence from passing tests is kept in the report.

<!-- DAG:BEGIN -->
Runbook-Id: RB04
Runbook-Version: 1.0.0
Strategies: bottom-up, top-down

| Step | Test | Title | Layer | Hypothesis | Class | Hard prerequisite | Expected (healthy) |
|---|---|---|---|---|---|---|---|
| 1 | ST01 v1 | STP domain eligibility (excludes STP-free EVPN domains) | L2 | H-domain | CONTEXT | - | domain runs spanning tree |
| 2 | ST08 v1 | Cabling graph vs NetBox (unrecorded loops) | L2 | H-loop | DISCRIMINATING | ST01 | observed adjacency equals intent |
| 3 | ST06 v1 | BPDU reception, guard, filter, loop guard | L2 | H-guard | DISCRIMINATING | ST01 | BPDU path intact, guards present |
| 4 | ST07 v1 | Port-channel / LACP consistency | L2 | H-guard | DISCRIMINATING | ST01 | LAG members bundled |
| 5 | ST04 v1 | Port roles/states vs cabling graph (blocked port in every cycle) | L2 | H-loop | DISCRIMINATING | ST01 | a port blocks in each physical cycle |
| 6 | ST02 v1 | Root and designated bridge consistency | L2 | H-root | DISCRIMINATING | ST01 | single stable root as intended |
| 7 | ST05 v1 | VLAN/MST instance consistency | L2 | H-root | DISCRIMINATING | ST01 | identical MST region config |
| 8 | ST03 v1 | TCN rate and origin | L2 | H-root | DISCRIMINATING | ST01 | TCN within normal |
| 9 | ST09 v1 | MAC-table churn and storm control | L2 | H-loop | DISCRIMINATING | ST01 | no MAC flaps/storm |
| 10 | ST10 v1 | VTEP / L2 overlay boundary (EVPN-VXLAN) | L2 | H-overlay | DISCRIMINATING | - | overlay loop prevention healthy |

| Hypothesis | Statement | Domain | Tests |
|---|---|---|---|
| H-domain | The domain is (not) a spanning-tree domain | L2 | ST01 |
| H-guard | BPDU filter/guard/loop-guard/LACP configuration defeats loop prevention | L2 | ST06, ST07 |
| H-loop | A forwarding loop exists (no blocked port, extra cable, storm) | L2 | ST04, ST08, ST09 |
| H-root | Root bridge / TCN / MST instability | L2 | ST02, ST03, ST05 |
| H-overlay | EVPN-VXLAN overlay MAC mobility / duplicate MAC | overlay | ST10 |

<!-- DAG:END -->

## Tests and expected outcomes
Every test states its healthy expectation before execution, records the actual output with evidence ids, interpretation and next action. PASS = expectation held; FAIL = fault condition present; INCONCLUSIVE/UNAVAILABLE carry a specific reason; SKIPPED rows carry NOT_APPLICABLE / UNSAFE_TO_EXECUTE / SKIPPED_AFTER_CONFIRMED_ISOLATION with the exact reason.

## Platform adaptations
EVPN-VXLAN or STP-free domains exclude the spanning-tree tests and remediation; overlay tests run instead.

## Causal isolation
Domain type, root stability, TCN origin, blocking-port census on cyclic topology, MST region, BPDU filter/guard, bundles, cabling, MAC/broadcast symptoms.

## Alternative explanations
Root change, BPDU filter on inter-switch link, MST mismatch, unrecorded cabling, LACP inconsistency, EVPN duplicate MAC.

## Safe stopping criteria
A BPDU-suppression or topology-evidence cause ends the search; symptoms such as MAC flaps are kept as secondary.

## AI handoff gate
Only for domains that remain unexplained after all applicable tests ran.

## Proposed remediations
Proposals only; nothing here is executed. Each is Tier 2 or higher unless it is explicitly 'none', requires operator approval and is subject to NMAS governance.

* **F-bpdu-filter** (tier 2): remove bpdu-filter from inter-switch port (or add BPDU guard on edge) -- NOT root/priority changes while the loop is live. Approvals: operator approval, verified blast radius. Never: bridge-priority change during the loop, mass shutdown of ports.
* **F-cabling-loop** (tier 2): external: remove or record the unrecorded cable. Approvals: operator acknowledgement. Never: n/a.
* **F-evpn-dup** (tier 2): locate the duplicate MAC / L2 attachment; no STP in the overlay. Approvals: operator approval. Never: enabling spanning tree in an EVPN-VXLAN domain.
* **F-loop** (tier 2): bounded containment: shut ONE redundant port only with approval and verified alternate path. Approvals: operator approval, traffic guard. Never: automated root election changes.

## Pre- and post-tests
* F-bpdu-filter: before ST04, ST06; after ST04, ST03, ST09.
* F-cabling-loop: before ST08; after ST04, ST08.
* F-evpn-dup: before ST10; after ST10.
* F-loop: before ST04, ST09; after ST04, ST09.

## Rollback
Remove the added filter or restore the previous priority; do not change root/port state while a loop is live.

## Soak
Layer-2 changes inside the soak window are correlated without blame.

## Documentation example
Triangle sw1-sw2-sw3 with all ports forwarding, bpdu-filter on sw3:Eth2, 900 MAC moves/min and 40 TCN/h -> F-bpdu-filter (cause) with F-storm retained as symptom.
