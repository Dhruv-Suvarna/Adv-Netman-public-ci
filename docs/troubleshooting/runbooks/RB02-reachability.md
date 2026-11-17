# RB02 v1.0.0 -- Reachability / host connectivity (HC01-HC28)

Decide whether a production service is really impaired, where on the path, and why, using the 28-test host-connectivity catalogue with forward and return path checks.

> Stage 1 is deterministic and read-only. Unavailable evidence is UNKNOWN. Results in this document come from SIMULATED replay fixtures unless stated otherwise (see `deterministic-engine.md`).

## Symptoms
A host cannot reach a service (timeouts, refused, slow, partial loss, intermittent).

## Triggering signals
Operator report, flow-monitor SLO breach, synthetic probe failure, alert-storm group whose primary is a link or neighbor failure.

## Production contracts
Protocol/port/source/destination of the production service and its SLO (what must work and what is intentionally blocked, e.g. ICMP). Failure of a diagnostic protocol while the production protocol is healthy is not an outage.

## Worked before / what changed
Last-known-good timestamp, approved changes and unrecorded drift in the lookback window, active golden soak.

## Scope
Source host, the intended path from NetBox/topology (forward and reverse), first-hop redundancy, DNS name when the service is addressed by name.

## Collectors and permissions
Read-only allowlisted show commands / gNMI / SNMP / syslog / flow records / bounded probes. Each observation carries source, timestamp, parser version and freshness.

## Baselines
Three distinct references with their own provenance: intended design (NetBox + golden revision with direct URL), historical normal (hour-of-day statistics, honest confidence, stale detection), production contract (SLO).

## Hypothesis tree and tests
The tables below are generated from the executable DAG (`python -m core.services.troubleshooting.runbooks write`); edit the code, not the table.

## Hypothesis tree
Each hypothesis lists the tests that confirm or eliminate it; counter-evidence from passing tests is kept in the report.

<!-- DAG:BEGIN -->
Runbook-Id: RB02
Runbook-Version: 1.0.0
Strategies: bottom-up, divide-and-conquer, follow-the-path, top-down

| Step | Test | Title | Layer | Hypothesis | Class | Hard prerequisite | Expected (healthy) |
|---|---|---|---|---|---|---|---|
| 1 | HC01 v1 | Service definition, protocol/port and last-known-good | SVC | H-svc | CONTEXT | - | production contract defined; worked-before determinable |
| 2 | HC02 v1 | Recent approved/unauthorized changes and golden soak | CTRL | H-change | CONTEXT | - | no unapproved change precedes onset |
| 3 | HC12 v1 | Maintenance / decommission / isolation state | CTRL | H-svc | CONTEXT | - | no intentional disruption on path |
| 4 | HC27 v1 | Production flow loss/latency/SLO | SVC | H-impact | CONTEXT | - | measured loss within SLO |
| 5 | HC03 v1 | Source host NIC admin/oper and carrier | L1 | H-l1 | DISCRIMINATING | - | NIC up with carrier |
| 6 | HC04 v1 | Optics/cable/PHY/speed/duplex/autoneg | L1 | H-l1 | DISCRIMINATING | - | speed/duplex agree, DOM within thresholds |
| 7 | HC05 v1 | CRC/FCS/input/output/error/discard rate | L1 | H-l1 | DISCRIMINATING | - | error rates at baseline; resets excluded |
| 8 | HC20 v1 | Congestion, utilization, microbursts | L1 | H-cong | DISCRIMINATING | - | utilization < 85%, no microburst |
| 9 | HC13 v1 | Interface, VRF and neighbor topology vs NetBox | CTRL | H-topology | DISCRIMINATING | - | LLDP adjacency equals intent |
| 10 | HC06 v1 | Source IP/IPv6 address, prefix, VRF binding | L3 | H-addr | DISCRIMINATING | - | address in intended prefix and VRF |
| 11 | HC07 v1 | DHCP lease / RA-SLAAC / DHCPv6 | L3 | H-addr | DISCRIMINATING | - | lease BOUND with intended gateway |
| 12 | HC08 v1 | VLAN tagging, port mode, allowed VLANs | L2 | H-l2 | DISCRIMINATING | - | access/trunk carry the host VLAN |
| 13 | HC09 v1 | MAC learning / aging / movement / flooding | L2 | H-l2 | DISCRIMINATING | - | stable MAC table |
| 14 | HC26 v1 | L2 STP/root/TCN/loop state | L2 | H-l2 | DISCRIMINATING | - | stable root, TCN below threshold |
| 15 | HC10 v1 | ARP/ND resolution and duplicate-address check | L2 | H-addr | DISCRIMINATING | - | gateway resolved, no duplicates |
| 16 | HC11 v1 | Gateway virtual protocol / first hop state | L3 | H-addr | DISCRIMINATING | - | exactly one FHRP master |
| 17 | HC14 v1 | Routing protocol neighbor state and last transitions | L3 | H-routing | DISCRIMINATING | - | adjacencies Full/Established |
| 18 | HC15 v1 | Source and intermediate RIB for service prefix | L3 | H-routing | DISCRIMINATING | - | route present with intended next hop on every L3 hop |
| 19 | HC16 v1 | Source and intermediate FIB / adjacency / ECMP | L3 | H-routing | DISCRIMINATING | HC15 | FIB agrees with RIB |
| 20 | HC24 v1 | Stateful firewall, NAT, return path, asymmetry | L4 | H-routing | DISCRIMINATING | - | symmetric return path, sessions found |
| 21 | HC18 v1 | ACL / firewall / zone policies and counters | L4 | H-policy | DISCRIMINATING | - | no deny matches the production tuple |
| 22 | HC19 v1 | QoS classification, policing, shaping and queue drops | L4 | H-qos | DISCRIMINATING | - | no drops in the flow's class |
| 23 | HC21 v1 | MTU, DF/PMTUD and effective path MTU | L3 | H-mtu | DISCRIMINATING | - | path MTU carries the service payload |
| 24 | HC25 v1 | DNS resolution, cache and endpoint selection | L7 | H-dns | DISCRIMINATING | - | name resolves to the intended endpoint |
| 25 | HC22 v1 | TCP application handshake / L7 health | L7 | H-impact | CONTEXT | - | authorised probes succeed within SLO |
| 26 | HC23 v1 | UDP/ICMP behaviour separately | L4 | H-policy | CONTEXT | - | diagnostic protocols as intended |
| 27 | HC17 v1 | Bounded traceroute / path trace vs intended path | L3 | H-routing | DISCRIMINATING | - | trace reaches destination along intended path |
| 28 | HC28 v1 | Redundant alternate path / failover eligibility (read-only) | CTRL | H-alt | SAFETY | - | existing alternate path evaluated; never assumed lossless |

| Hypothesis | Statement | Domain | Tests |
|---|---|---|---|
| H-impact | The production service is genuinely impaired (not merely a diagnostic-protocol artefact) | svc | HC22, HC27 |
| H-svc | Service contract unknown or an intentional maintenance explains the symptom | ops | HC01, HC12 |
| H-change | A recent change (approved or not) caused the symptom | change | HC02 |
| H-policy | Directional ACL/firewall policy blocks the production flow | policy | HC18, HC23 |
| H-addr | Host addressing, provisioning, first-hop resolution or FHRP fault | L3 | HC06, HC07, HC10, HC11 |
| H-l1 | Layer-1 fault at the source or on a path link (NIC, optics, cable, errors) | L1 | HC03, HC04, HC05 |
| H-l2 | Layer-2 fault: VLAN, MAC instability, STP loop | L2 | HC08, HC09, HC26 |
| H-routing | Routing control or forwarding plane fault (neighbors, RIB, FIB, forward/return path) | L3 | HC14, HC15, HC16, HC17, HC24 |
| H-qos | QoS policing/queueing drops the production class | qos | HC19 |
| H-topology | Physical/logical attachment differs from NetBox intent | topology | HC13 |
| H-cong | Congestion or microbursts on a path link | L1/L2 | HC20 |
| H-dns | Name resolution returns a wrong or no endpoint | dns | HC25 |
| H-mtu | MTU mismatch / PMTUD black hole | L3 | HC21 |
| H-alt | A pre-existing alternate path could contain the impact (mitigation, not cause) | ctrl | HC28 |

<!-- DAG:END -->

## Tests and expected outcomes
Every test states its healthy expectation before execution, records the actual output with evidence ids, interpretation and next action. PASS = expectation held; FAIL = fault condition present; INCONCLUSIVE/UNAVAILABLE carry a specific reason; SKIPPED rows carry NOT_APPLICABLE / UNSAFE_TO_EXECUTE / SKIPPED_AFTER_CONFIRMED_ISOLATION with the exact reason.

## Platform adaptations
Commands missing on a platform are recorded as UNAVAILABLE with the reason. The current ACL source supports a restricted cEOS IPv4 grammar; independent FIB and QoS runtime sources remain unavailable. HC18 requires an explicit supported permit to exclude a filtering explanation; no explicit match leaves implicit/default deny unproven and is INCONCLUSIVE. See `../acl-source.md` and `../forwarding-source.md` for exact source limitations.

## Causal isolation
Follow-the-path (or the strategy chosen by the selector, recorded with its rationale): service impact first, then per-hop RIB, FIB and return path, then policy counters by direction and time window.

## Alternative explanations
Intentional ICMP block, maintenance/drain, approved-change side effect, congestion/QoS, MTU, DNS/endpoint selection, return-path/stateful asymmetry.

## Safe stopping criteria
A causal finding (confidence >= 0.85) that no impact test contradicts stops further discriminating tests; context and safety tests still run and every skipped test keeps its reason.

## AI handoff gate
Refused while safe applicable tests remain unexamined or fewer than three tests ran; permitted only for an unresolved case after the deterministic coverage is exhausted.

## Proposed remediations
Proposals only; nothing here is executed. Each is Tier 2 or higher unless it is explicitly 'none', requires operator approval and is subject to NMAS governance.

* **F-acl-deny** (tier 2): narrowly scoped correction of the denying ACL entry (never a blanket permit). Approvals: operator approval, dry-run + precheck, continuous production-flow guard. Never: auto-revert to golden because of drift alone, traffic reroute without a verified alternate path.
* **F-diag-unexplained** (tier 1): none: record intent as an operator-confirmed scoped exception. Approvals: owner confirmation. Never: remediating while production is healthy.
* **F-fib** (tier 2): escalate with hardware-programming evidence; clearing routes requires approval. Approvals: operator approval. Never: clear ip route *.
* **F-maintenance** (tier 1): none: intentional maintenance. Approvals: none. Never: remediating an intentional drain.
* **F-qos-drop** (tier 2): adjust policer/queue after capacity review. Approvals: operator approval. Never: rolling back solely for golden conformity.
* **F-rib** (tier 2): restore the missing route/adjacency per RB03 evidence. Approvals: operator approval. Never: metric changes without path-impact assessment.

## Pre- and post-tests
* F-acl-deny: before HC18, HC02, HC28; after HC22, HC27, HC18.
* F-diag-unexplained: before HC22, HC23; after HC23.
* F-fib: before HC15, HC16; after HC16, HC22.
* F-maintenance: before HC12; after HC22.
* F-qos-drop: before HC19, HC20; after HC22, HC27.
* F-rib: before HC14, HC15; after HC15, HC16, HC22.

## Rollback
Golden-config conformity is never a reason for automatic rollback; a guarded fix needs Tier-2 approval, dry run and continuous production-flow guard.

## Soak
Active soak overlap is correlated to timing and device distance; approved drift is preserved while production is unimpacted.

## Documentation example
Fault: TCP/443 fails 20/20, ACL EDGE-IN seq 5 denies the tuple with hits incrementing -> F-acl-deny (HC18). Recovery: ACL corrected -> same tests pass. Variant: TCP healthy and ICMP denied -> expected protocol distinction.
