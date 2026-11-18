# NMAS V2 Troubleshooter support matrix (2026-11-18, bulk topology admission)

Earlier revisions: this file's git history, `CHG-NMAS-20261117-MULTIFAULT-010/` (multi-fault milestone) and
`CHG-NMAS-20261117-ROUTING-018/` (this revision). The campaign evidence is in `~/nmas-evidence/fault-campaigns/`; nothing
there was rewritten.

## Evidence classes

| Class | Meaning |
|---|---|
| **LIVE** (live verified) | Proven on the lab with a real fault, end to end through the production path |
| **LIVE-RO** | Proven on live read-only data with no fault injected (e.g. "healthy lab → no false positive") |
| **REPLAY** (replay verified) | Live device documents captured verbatim; one mutation each; run through production code |
| **FIXTURE** (fixture verified) | Unit / integration tests with synthetic inputs only |
| **DEPLOYED** (deployment verified) | Code running in production (md5-verified) and exercised live without a fault |
| **BLOCKED-AUTH** | Needs an approval that has not been given; the exact approval is stated |
| **BLOCKED-SAFETY** | Not provable within the safety rules; the reason is stated |
| **NO** (not implemented) | Not supported, deliberately or not yet; stated |

Replay-only routing results are **not** live validation and are not described as such.

## Support levels

| Level | Meaning |
|---|---|
| L1 Detect | The unattended intake notices it |
| L2 Classify | Deterministic category, with confirmed / possible / insufficient cause |
| L3 Evidence | Structured observations and the classification are persisted on the case without any model |
| L4 Diagnose | Runbook plus Codex investigation reach a conclusion consistent with the evidence |
| L5 Decide | Deterministic remediation decision recorded (`REMEDIATION_DECISION`) |
| L6 Guard | Ineffective or unauthorized operations are refused deterministically, with an audit trail |
| L7 Execute | Autonomous Change Engine execution under an exact standing policy |
| L8 Close | Verified closure: `RESOLVED_VERIFIED` after an NMAS repair, or `UNRESOLVED` + `cleared_externally` after verified external clearance |

## Fault categories

| Category | L1 | L2 | L3 | L4 | L5 | L6 | L7 | L8 |
|---|---|---|---|---|---|---|---|---|
| `ADMIN_STATE_MISMATCH` (R2 Et1) | LIVE (010, 011) | FIXTURE + LIVE-RO | FIXTURE | LIVE (009, 011) | FIXTURE (`AUTO_REMEDIATE`) | LIVE (009, 011) | **LIVE** (ARP-R2-E1-002, 011) | LIVE (011 `RESOLVED_VERIFIED`) |
| `ADMIN_STATE_MISMATCH` (other interfaces) | DEPLOYED (same intake) | FIXTURE | FIXTURE | FIXTURE | FIXTURE (`PROPOSE_FOR_APPROVAL`) | LIVE-RO | **NO** (no policy) | FIXTURE |
| `OPERATIONAL_LINK_DOWN` (S2 Et4) | **LIVE** (017) | **LIVE** (017, hold-checked) | **LIVE** (017: intake observation + worker `interface.admin_state=up` / `oper_state=down`) | **LIVE** (017: Codex "physical/peer-side carrier-loss fault domain") | **LIVE** (017 `DIAGNOSE_AND_ESCALATE`) | **LIVE** (017: no proposal, no Change) + FIXTURE / LIVE-RO refusal gate | **NO** (no safe correction) | **LIVE** (017 `FAULT_CLEARED_VERIFIED` → `UNRESOLVED`, `cleared_externally`) |
| `OPERATIONAL_LINK_DOWN` (R2 Et1 via `carrier_loss`) | BLOCKED-SAFETY (012: cEOS reasserts the link within about 1 s) | FIXTURE | FIXTURE | FIXTURE | FIXTURE | FIXTURE | **NO** | FIXTURE |
| `LINK_FLAPPING` | **LIVE** (013) | **LIVE** (013) | **LIVE** (013) | **LIVE** (013) | **LIVE** (013) | LIVE-RO + FIXTURE | **NO** | **LIVE** (013) |
| `INTERFACE_DEGRADATION` | REPLAY | REPLAY | REPLAY | REPLAY (real Codex, `INCONCLUSIVE_ESCALATED`) | REPLAY | FIXTURE + LIVE-RO | **NO** | REPLAY |
| `ROUTING_ADJACENCY_FAILURE`: OSPFv2, OSPFv3, BGP-IPv4, BGP-IPv6 on cEOS R1/R2/R5 | DEPLOYED (intake reads all four families live; healthy lab → no incident); fault: REPLAY + FIXTURE | REPLAY (cEOS JSON) | FIXTURE | catalogue (RB03); worker R2/S2 only | REPLAY + FIXTURE (`DIAGNOSE_AND_ESCALATE`) | FIXTURE | **NO** | **NO** auto-close (ADJ cases stay with humans) |
| `ROUTING_ADJACENCY_FAILURE`: FRR R3/R4 (ospfd, ospf6d, bgpd) | DEPLOYED (intake reads R3/R4 live; healthy lab -> no incident); fault: REPLAY | REPLAY (FRR JSON, incl. `Full/Backup` and `state` vs `peerState`) | FIXTURE | worker LIVE via broker (R3/R4 admitted) | REPLAY | FIXTURE | **NO** | **NO** auto-close |
| `ROUTE_OR_REACHABILITY_FAILURE` / `SOURCE_COLLAPSE` (RIP, OSPF, OSPF externals, OSPFv3, IS-IS, BGP; IPv4 + IPv6 summaries; R1/R2/R5/S1/S2) | DEPLOYED (learned baseline, live counts read; no false positive); fault: FIXTURE | REPLAY + FIXTURE | FIXTURE | catalogue (RB02/RB03) | FIXTURE (`DIAGNOSE_AND_ESCALATE`) | FIXTURE | **NO** | **NO** auto-close |
| `ROUTE_OR_REACHABILITY_FAILURE` / `MISSING_ROUTE`, `WRONG_NEXT_HOP` (per prefix) | **NO** (no authoritative per-prefix expectation; see note 3) | REPLAY (live RIB captures, both families) | FIXTURE | catalogue (RB02) | REPLAY | FIXTURE | **NO** | **NO** |
| `ROUTE_OR_REACHABILITY_FAILURE` / `UNEXPECTED_SOURCE` (redistribution mismatch) | **NO** live per prefix; source-collapse covers loss of redistributed externals | REPLAY (RIP↔OSPF at R1, BGP→OSPF chain) | FIXTURE | catalogue | REPLAY | FIXTURE | **NO** | **NO** |
| Reachability loss ± route correlation | FIXTURE | REPLAY (Campaign C) | FIXTURE | catalogue | REPLAY | FIXTURE | **NO** | FIXTURE |

## Routing analysis capabilities (`core/services/troubleshooting/routing.py`)

| Capability | Evidence | Notes |
|---|---|---|
| cEOS RIB parsing (`show ip[v6] route | json`), Linux RIB (`ip -j -4/-6 route`) | REPLAY (R1, R2, R5, S1, S2, R3, R4, H1, H2) | RIB, not validated FIB; zebra's `ospf` label on IPv6 is normalised to `ospf3` |
| RIP | REPLAY + DEPLOYED (RIB route type, summary counts) | cEOS 4.36.2F returns "This is an unconverted command" for `show ip rip neighbors | json`; RIP neighbors are therefore **NO**; RIP health = learned RIP route counts |
| IS-IS (IPv6 on R1/R2/S1/S2) | REPLAY + DEPLOYED (counts) | adjacency parsing **NO** (not requested) |
| Forwarding-path reconstruction (hop by hop, ECMP branches) | REPLAY | H1→H2 v4/v6 = H1→S1 (VARP gateway resolved as the sole topology peer); H1→WebServer v4/v6 = S1→R1→{R3,R4}→R5, both branches DELIVERED in the forward RIBs |
| Redistribution correlation (`correlate_redistribution`) | REPLAY | `REDISTRIBUTION_FAULT_DOMAIN` vs `ORIGIN_LOST` vs `PARTIAL`; unreadable readers lower evidence quality and are never assumed |
| Path-aware multi-device correlation (`correlate_with_paths`) | REPLAY + FIXTURE | One incident for a common link fault, including a flow symptom on a redundant topology whose baseline path used the link; an unrelated link fault is a separate group; an SVI hop is claimed only with explicit L2 membership |
| Service-flow impact (`flow_impact`) | REPLAY | UNCHANGED / REROUTED / BROKEN / UNKNOWN |
| Evidence quality / freshness (`evidence_quality`) | FIXTURE | stale or missing devices → PARTIAL / NONE |
| Case-page display of path reconstruction / routing correlation | FIXTURE (TSACC-031) + REPLAY (TS-20261118-C82A083C, live RIBs, HTTP 200) | `TsTopologyPath` rows + TOPOLOGY_PATHS audit per new monitoring case; 'Topology-aware investigation' section |

## Device coverage (2026-11-18, after bulk admission CHG-NMAS-20261117-BULK-ADMISSION-019)

All nine managed devices: identity VERIFIED, ManagementPath APPROVED/ACTIVE/HEALTHY, a dedicated read-only `nmas-diag`
identity with live-proven RBAC, and LIVE worker reads (code=OK, dispatcher uid 972). Full matrix and evidence:
`TOPOLOGY_ADMISSION_ACCEPTANCE.md`. The R3/R4 authorization blockers of the previous revision are closed: their host-key
pins were enrolled from console evidence and their paths were approved inside the owner's exact-target single-admin windows.

| Device | Path | Diagnostic identity | Intake (live, read-only) | Telemetry |
|---|---|---|---|---|
| R1, R2, S1, S2, S3, S4, mgmt_swt (cEOS) | MPATH-000001..7 | nmas-diag network-operator, priv 1 | interfaces; routing on R1/R2/S1/S2 | gNMI |
| R3, R4 (FRR) | MPATH-000008/9 (Linux probe via broker) | nmas-diag forced-command broker | interfaces (`ip -j -s link`), OSPFv2/v3/BGP v4/v6, route counts | Linux adapter |

Topology-wide forwarding-path evidence on every new monitoring case: REPLAY_VERIFIED (TS-20261118-C82A083C, live RIBs).

## Notes

1. **Operational-down live (017).** Proven through peer carrier loss on H4 eth1. The harness's automatic restore failed:
   H4's DHCPv6 address is dynamic, and Linux `keep_addr_on_down` keeps only permanent addresses. The address was restored
   manually and the restore was verified by the harness. The harness now refuses such a peer (`PEER_ADDRESS_NOT_PRESERVABLE`).
   A repeat needs fresh owner authorization and a peer whose state can be restored without fabricating it.
2. **The ineffective-proposal gate in `governance.propose`** is LIVE-RO plus FIXTURE. It was evaluated read-only against
   live case evidence during 014 (`NMAS-S2-E4-20261117-014.live-gates.txt`: `INEFFECTIVE_OPERATION`), but Codex has never
   actually proposed `interface_enable` in a live case (013, 015–017).
3. **Per-prefix route expectations.** There is still no authoritative per-prefix source (intent or NetBox), so the live
   intake monitors learned route-source counts, not individual prefixes. Per-prefix classification needs a caller-supplied,
   labelled expectation.
4. **Autonomous execution** is still exactly one operation (`interface_enable`, R2 Ethernet1, ARP-R2-E1-002). This milestone
   added **no** write permission.
5. **Pre-existing H1→WebServer issue.** Out of scope and not repaired. The forward RIB paths are intact in both families,
   so the issue is not a missing forward route. The return path was not reconstructed (WebServer and R5 return RIBs were not analysed).
