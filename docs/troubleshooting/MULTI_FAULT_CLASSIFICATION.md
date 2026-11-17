# Multi-fault classification and safe non-remediation

Code: `web/core/services/troubleshooting/faults.py` (pure, deterministic), `routing.py` (pure routing analysis: adjacency and
RIB parsing for cEOS and FRR, route and source-count classification, redistribution correlation, forwarding-path
reconstruction, path-aware correlation), `intake.py` (live monitoring), `governance.py` and `recovery.py` (enforcement).
Tests: `web/core/tests/test_troubleshooting_multifault.py` and `test_troubleshooting_routing.py` (replays of live captures in
`web/core/tests/fixtures/troubleshooting_routing/`).

Classification is deterministic and never calls a model. When Codex is unavailable, NMAS still detects the fault and records
it. It persists the evidence, records the classification and decision, and escalates by email. The dispatcher is retried every
120 s, at most 15 times.

## 1. Observations (read-only)

| Evidence | Source | Fields |
|---|---|---|
| Administrative state | cEOS `show interfaces \| json` (`interfaceStatus == disabled`). The running config is cross-checked (`show running-config interfaces X`) before a `disabled` interface is called admin DOWN. | intended (tracked template), observed, sample time, freshness, source |
| Operational state | same read | `interfaceStatus` / `lineProtocolStatus`; oper UP = `connected` + protocol `up` |
| Link transitions | poll-to-poll edges, plus the device's own `linkStatusChanges` counter (counts transitions shorter than the 10 s poll) and `lastStatusChangeTimestamp` | timestamped edges, count in a 300 s window, time stable, severity, admin-driven toggles flagged |
| Errors / discards | `interfaceCounters` | deltas per interval, error rate, discard ratio, utilization; a counter that goes backwards is marked `reset` and its interval is never used |
| Routing adjacencies | `show ip ospf neighbor`, `show ipv6 ospf neighbor`, `show ip bgp summary`, `show ipv6 bgp summary` (`\| json`; R1, R2, R5, S1, S2, every 3rd pass) | expected adjacency (labelled `LEARNED_BASELINE`, not intent), observed state; FRR equivalents parse in `routing.frr_adjacency_samples` (replay only: R3/R4 are not admitted) |
| Route sources | `show ip route summary \| json`, `show ipv6 route summary \| json` (same devices and cadence) | per-protocol counts normalised to rip / ospf / ospf_external / ospf3 / ospf3_external / isis / bgp; the learned baseline only rises while healthy |
| RIB / forwarding path | `show ip[v6] route \| json` (cEOS), `ip -j -4/-6 route` (Linux); replay and callers only | `RibEntry` (prefix, normalised source, next hops); RIB, not validated FIB |
| Reachability | classifier and replay only (`classify_reachability`) | source, destination, address family, loss samples vs baseline, correlated route evidence |

Case evidence is stored under observation key `intake.interface_state@<interface>` (target `<device>`). The classification
and the decision are stored as one evidence blob (`deterministic_classification`). The decision is also recorded as a
`REMEDIATION_DECISION` audit event.

## 2. Categories

| Category | Rule | Cause status |
|---|---|---|
| `ADMIN_STATE_MISMATCH` | admin down, intent up, confirmed for 30 s | CONFIRMED (administrative shutdown) |
| `OPERATIONAL_LINK_DOWN` | admin UP, oper down for ≥ 30 s | UNDETERMINED; possible causes are listed, never asserted |
| `LINK_FLAPPING` | ≥ 4 transitions in 300 s, admin up throughout | UNDETERMINED |
| `INTERFACE_DEGRADATION` | (errors ≥ 10 and ≥ 0.05/s) or (discards ≥ 100 and ≥ 1 % of packets), in 2 consecutive intervals; resets excluded; lifetime totals alone never count | UNDETERMINED |
| `ROUTING_ADJACENCY_FAILURE` | an expected adjacency is absent or not FULL/Established for ≥ 30 s | UNDETERMINED; a link incident on the same device within 300 s is recorded as `possibly_secondary_to` |
| `ROUTE_OR_REACHABILITY_FAILURE` | expected route missing (`MISSING_ROUTE`, with the covering route that now carries the traffic), wrong next hop (`WRONG_NEXT_HOP`; a surviving ECMP member is not wrong), different source protocol (`UNEXPECTED_SOURCE`, flagged `redistribution_related` when an OSPF external is involved), a learned route source down by half or more for 30 s (`SOURCE_COLLAPSE`, live in intake), or ≥ 50 % loss above baseline in 2 consecutive samples | CONFIRMED only when a correlated route fault explains it; the `subtype` is in the evidence and the expectation source is always recorded |
| `INDETERMINATE` | unreadable, no intent, or still inside debounce | INSUFFICIENT_EVIDENCE |

**Redistribution.** `routing.correlate_redistribution` checks whether the prefix is still present in the origin protocol at
the redistributing router. Origin present there but absent from every reader gives `REDISTRIBUTION_FAULT_DOMAIN`. Origin
absent gives `ORIGIN_LOST`: redistribution is not implicated. Absent at only some readers gives `PARTIAL`. An unreadable
reader is listed and lowers evidence quality; it is never assumed. Live chains (2026-11-17): R5 static → eBGP at R3/R4 →
OSPF external (BGP4-TO-OSPF) at R1/R2 → RIP (OSPF-TO-RIP) at S1/S2; IPv6: BGP → OSPFv3 and IS-IS → OSPFv3 at R1/R2.

**Multi-device and path correlation.** `correlation.correlate_alarms` groups by topology and time: the earliest physical
alarm on a known link, endpoint or downstream symptoms. `routing.correlate_with_paths` adds rule R5: a flow or route symptom
that R3 rejects on a redundant topology joins the link's incident only if its **baseline forwarding path**
(`reconstruct_all_paths`, every ECMP branch) egressed that link. An SVI hop is matched to a physical port only with explicit
L2 membership. Unrelated faults stay separate groups, so one incident is opened per common fault and independent faults
get independent incidents. `flow_impact` classifies a flow UNCHANGED, REROUTED, BROKEN or UNKNOWN. `evidence_quality`
reports stale or missing devices.

**Link correlation.** Both ends of one link form one incident (`LINK:a|b`). An admin shutdown at one end explains the loss
of carrier at the other end. If both ends are admin UP and oper down, the incident is an operational link fault with no
administrative cause.

## 3. Remediation decision (`faults.decide`)

| Outcome | When |
|---|---|
| `AUTO_REMEDIATE` | Only `ADMIN_STATE_MISMATCH`, and only when an **active standing policy names that exact device/interface/operation**. Every gate is still re-verified on live facts before the Change Engine runs. |
| `PROPOSE_FOR_APPROVAL` | Technically appropriate (for example, enabling an admin-down interface) but no policy covers it. Also used for any Codex proposal that no policy covers (`recovery.record_plan_decision`). |
| `DIAGNOSE_AND_ESCALATE` | Operational-down, flapping, degradation, routing and reachability faults. No registered safe correction exists, so the evidence is preserved and an engineer is emailed. |
| `INSUFFICIENT_EVIDENCE` | The condition is not confirmed. |
| `NO_ACTION_REQUIRED` | Healthy. |

Every refusal lists coded reasons, for example:
- `INTERFACE_ENABLE_INEFFECTIVE`
- `STANDING_POLICIES_COVER_ONLY_interface_enable`
- `AUTOMATIC_BOUNCE_OR_SHUTDOWN_UNSAFE`
- `PHYSICAL_OR_PEER_CAUSE_UNDETERMINED`
- `COUNTER_CLEAR_DESTROYS_EVIDENCE`
- `ROUTING_PROCESS_OR_NEIGHBOR_CHANGE_NOT_AUTHORIZED`
- `SPECULATIVE_ROUTE_CHANGE_NOT_AUTHORIZED`

## 4. Enforcement (defence in depth)

1. **`governance.propose`** rejects `interface_enable` when the case's freshest stored observation (from the intake or a worker
   test, ≤ 900 s old) shows the interface administratively UP. The result is `INEFFECTIVE_OPERATION`, plus a
   `PROPOSAL_REJECTED` audit. The model has to escalate instead.
2. **`governance.evaluate_recovery_policy`** now also receives the live oper state:
   - admin UP + oper DOWN → `INEFFECTIVE_OPERATION_ADMIN_UP_OPER_DOWN`. This is a refusal, not the idempotent no-op it used to be.
   - admin DOWN + oper UP → `CONTRADICTORY_EVIDENCE`.
   - The existing gates are unchanged.
3. **`recovery.undecided_plans` / `record_plan_decision`.** Every fresh proposal that no active policy covers gets exactly one
   `PROPOSE_FOR_APPROVAL` decision and an email. It is never executed and never silently ignored.
4. Standing policies can still only ever cover `interface_enable` (`RECOVERY_OPERATIONS`). Bounce, shutdown, routing,
   neighbor and process operations can never be pre-authorized.

## 5. Investigation order for Codex (also in the model instructions)

1. Define the symptom.
2. Establish the scope.
3. Form competing hypotheses from the evidence.
4. Test them.
5. Name the most likely fault domain.
6. Decide whether a registered correction is supported.
7. Check authorization (NMAS does this deterministically).
8. Recommend the safe next action.
9. Verify the conclusion against live observations.
10. Document what remains uncertain.

An administrative enable can only correct an interface that is administratively down. When no safe correction applies, the
correct output is an evidence-backed escalation.

## 6. Lifecycle of an escalated case

- The intake opens the case and records the evidence, classification and decision.
- Codex investigates. A refused or absent proposal leaves the case in TESTING.
- When the fault clears **without NMAS acting**, and the link has been up/up and stable for 60 s plus a 30 s confirmation, the intake does the following:
  1. re-reads both ends
  2. measures the protected flows
  3. records `FAULT_CLEARED_VERIFIED`
  4. closes the case `UNRESOLVED`, with disposition `SAFE_NON_REMEDIATION`, `cleared_externally=true` and `nmas_performed_repair=false`

  It is never closed `RESOLVED_VERIFIED`, because NMAS did not repair it. Cases decided `AUTO_REMEDIATE` stay with the recovery service.
- Maintenance on an incident device suppresses intake with the reason `MAINTENANCE_ACTIVE (...)`. The suppression is logged and emailed once.

## 7. Fault harness (lab owner channel, `break.py`)

`fault_type` may be one of:
- `admin_shutdown` (campaigns 001–011)
- `carrier_loss`: the kernel end of the Containerlab veth goes down inside the node, while the device configuration stays `no shutdown`
- `link_flap`: `{cycles 2–6, down_seconds 3–20, up_seconds 5–60}`, and the whole sequence must end 30 s before `maximum_seconds`
- `peer_carrier_loss` (campaigns 014–017): the Linux END HOST on an allowlisted topology link takes its NIC down, so the observed
  cEOS interface stays configured and admin UP but goes oper DOWN. The host's `keep_addr_on_down` is set for the outage and
  restored on rollback. **Since campaign 017** the baseline refuses a peer that holds any *dynamic* global address
  (`PEER_ADDRESS_NOT_PRESERVABLE`). Linux keeps only permanent addresses across a link down, and restoring a DHCPv6 lease by
  hand would fabricate host state.

Link faults have these safety properties:
- They are persisted `ACTIVE`, with the hard deadline, **before** the link is touched, so `break.py rollback` always works.
- The flap is synchronous: the link is always left up in a `finally` block, and the flap stops early if a protected flow degrades.
- The baseline is the interface configuration digest plus kernel UP + carrier.
