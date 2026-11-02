# V2 — IS-IS / RIP live-migration readiness

Status (2026-10-10): **not ready, not executed, not authorized.** R1, R2, S1 and S2 production routing is unchanged.
Readiness closure reduced the blockers but did not remove them all; section 9 lists what is still open. Design and
first-round evidence: `docs/V2_IPV6_ISIS_ACCESS_REDUNDANCY.md`.

## 1. SOAK-000001 — the record stands

`SOAK-000001` ended **COMPLETED / FAIL**, reason `RESOURCE_CRITICAL_SUSTAINED`, at 2026-10-10 00:45:43 UTC: R1 CPU 91%,
91% and 90% on three consecutive samples. It recorded 344 samples, **zero configuration drift and zero interference**.
The result is preserved exactly. The failing samples coincide with a five-container cEOS sandbox and two full local
test runs on the NMAS host; cEOS lab containers report host-wide CPU. No replacement soak is started: the next soak
validates the post-migration baseline (section 8).

## 2. Two-core sandbox

Seven disposable cEOS 4.36.2F containers and two host containers, built from the tracked candidate files, removed
afterwards. Never part of `srlceos01`.

```
              pe  (service 2001:db8:3050::10, 172.30.50.10; core loopback 2001:db8:255::5)
             /  \
           c3    c4            two distinct core routers (the R3 / R4 roles)
           | \  / |
           |  \/  |
           |  /\  |
           r1    r2
           |      |
           s1 == s2            trunk: VLAN 10, 20, 30, 99
           |      |
           h1     h3           hosts in VLAN 10, default gateway = the VARP address
```

It first reproduced today's design, including S2 reaching the R1 side over Vlan10. Probes ran from the hosts through
the VARP gateway at five per second.

## 3. Northbound boundary policy — result

Policy under test: R1 and R2 each hold `2001:db8::/32` as static routes whose next hops are reached only through
OSPFv3-learned routes, and redistribute that prefix into IS-IS. Anchors: on R1 `2001:db8:100:103::2` (R3) and
`2001:db8:100:104::2` (R4) on the far-side transits plus the service address; mirrored on R2 with `101::2` and `102::2`.

| Case | Behaviour | Probes lost |
|---|---|---|
| Migration, stages 1-6 | static -> IS-IS with all three anchors | 0 of 548 on each of five host flows |
| A. Normal | S1 prefers R1 (10), S2 prefers R2 (10); both routers advertise | — |
| B. One core link lost (R1, then R2) | aggregate kept through the remaining core router; switch path unchanged | 0 of 130 + 130, both routers |
| Service prefix withdrawn (one-core run) | aggregate kept through the other anchors | 0 of 3 check pings |
| **C. Both core links lost on R1** | R1 withdrew the aggregate, learned R2's, S1 moved to `S1 -> S2 -> R2` | **14 of 199 and 14 of 200 (about 2.8 s)** |
| **C. Both core links lost on R2** | mirrored | **5 of 200 and 5 of 200 (about 1 s)** |
| D. Restore (R1, then R2) | advertisement returned, normal preference restored | 0 of 373 + 374, both routers |

What each anchor proves, and the failure cases:

- **R3 fails:** the R3 anchor and R3's path to the service disappear; the R4 anchor still resolves. Aggregate kept.
- **R4 fails:** mirrored.
- **Service prefix disappears:** the two core-router anchors still resolve. Aggregate kept; the service itself is
  unreachable from everywhere, which is correct.
- **One core adjacency survives:** all remaining anchors resolve through it. Aggregate kept.
- **A router loses both core paths:** no anchor resolves. EOS does not resolve them through the management default
  route or through the identical aggregate learned from the other router, so the static routes are removed and the
  IS-IS advertisement is withdrawn. Proven on both routers.
- No OSPFv3 route enters IS-IS, so the routers cannot prefer each other's copies. Vlan200 is not in IS-IS.

The R3-fails and R4-fails cases were exercised as loss of the link to that core router, not by stopping the core
router itself.

**The policy does everything required except one thing: case C is not loss-free.** An abrupt loss of every core link
is detected, flooded and recomputed, and packets already heading to that router are lost for one to three seconds. The
readiness brief required zero observed loss in case C and said to stop if any test failed. **So the boundary policy is
not accepted as final, it is not modelled in NMAS, and no workaround was added.** Two facts for the decision:

- Case C is failure convergence, not planned work. The planned path — draining a router with the IS-IS metric before
  touching it — stayed loss-free in every run.
- Today's static design never recovers from case C at all: the switch keeps sending to the isolated router.

## 4. IPv4: RIP cleanup, staged

EOS has no RIP passive-interface. The client-SVI `network` lines cause the S1<->S2 adjacency over Vlan10/Vlan20;
removing them directly cost about 25 s on one flow in the first sandbox and is forbidden.

| Stage | Action | Proof in the two-core sandbox |
|---|---|---|
| A | `distribute-list out route-map RIP-CLIENT-VLAN-DEPREF Vlan10\|Vlan20` (`set metric 8`) on S1 and S2 | within 30 s both switches reached the other side over Vlan99 |
| B | remove `network 192.168.10.0/24`, `.20.0/24`, `.30.0/24` on S1, then S2 | RIP peers: uplink and the Vlan99 peer only |
| C | remove the temporary policy | no `RIP-CLIENT-VLAN-DEPREF` left |

After the cleanup R1 and the core still learned `192.168.10.0/24` and `192.168.20.0/24`: the prefixes are advertised
as connected routes with no peer on the client VLAN.

Loss, 215 s at five probes per second: **0 of 1071 on each of five host flows** (IPv4 and IPv6 to the service, host to
host). Switch-loopback flows: 0 of 1066 on S1 -> R2, and **2 of 1065 on S2 -> R1 in the first run**. A second run with
timestamped probes lost 0 of 991 and 0 of 992, so the two losses could not be reproduced or placed in a stage; the host
was at a load average above 30 with nine sandbox containers. That flow is therefore not proven loss-free.

**VARP:** the virtual addresses on Vlan10, Vlan20 and Vlan30, their `active` state and the virtual MAC were identical
before and after (same digest over the `show` output and configuration). The hosts' gateway MAC was
`00:1c:73:00:00:99` afterwards, and they used the gateway throughout.

## 5. Metric-only change through the NMAS executor

On the sandbox switch, through the production cEOS executor and read path (`routing_binding`, lines
`interface Ethernet1` / `isis metric 1000`):

| Step | Result |
|---|---|
| Baseline read | binding metric 10; aggregate `isisL2` via Ethernet1; adjacencies UP on Ethernet1 and Vlan99 |
| Assess | `APPLY`, restorable (inverse = the captured `isis metric 10`) |
| Apply + read-back | metric 1000 in the read-back binding; aggregate via Vlan99; adjacency on the drained link still UP |
| Compensate | `COMPENSATED`; configuration digest identical to baseline; metric 10; aggregate via Ethernet1 |
| Second compensate | `COMPENSATED / NONE_NEEDED`; configuration still identical |
| Host probes | 0 of 349 + 349 |

This is the executor lifecycle (assess, apply, read-back, compensate). **It did not go through intent, validation,
plan and precheck**: no Device Builder path was exercised that produces a metric-only Configlet for an existing device.

## 6. NMAS capability

| Capability | Status |
|---|---|
| A reconciled Change cannot be executed again (`BLOCKED_SUPERSEDED_BY_RECONCILIATION`, names the record) | Done here |
| Drift view: one row per reconciled device, in sync only at the accepted digest | Done here |
| IS-IS process and bindings: model, render, validate, execute, compensate, read-back, import, adjacency postcheck | Done (PR #44, #46) |
| Exact inverse for an existing `isis metric` | Done (PR #46); proven through the executor here |
| IS-IS route postcheck: present with exactly the expected paths, or absent (`ISIS_ROUTE_EXPECTED`) | Done here |
| cEOS RIP peer read (`show ip rip neighbors`, text) and postcheck per interface, present or absent (`RIP_NEIGHBOR_EXPECTED`) | Done here |
| Boundary policy (prefix lists, route maps, anchored static routes, redistribution, OSPFv3 distance) in the intent model | **Not built** — stopped with the policy decision (section 3) |
| Staged RIP cleanup as an NMAS workflow that records original state, the temporary step and each inverse | **Not built** — the stages exist as tracked candidate files and this document only |
| A metric-only Change through intent, validation, plan and precheck | **Not proven** |
| A planner object that emits the two new requirement kinds | **Not built** — the evaluators exist and are tested; nothing calls them from a plan yet |

Unsupported operations fail closed. Other platforms still report IS-IS as not implemented.

## 7. Candidates and the live procedure

- Permanent design only: `docs/evidence/v2-isis/final/{R1,R2,S1,S2}.final.cfg`.
- Staged migration, with temporary lines: `docs/evidence/v2-isis/{R1,R2,S1,S2}.candidate.cfg` and `*.rollback.cfg`.

**Abort rule, every stage: any lost probe, or any failure condition, stops the migration.** Apply that stage's
rollback, verify the previous stage's success condition, record sequence number and time, report.

| Stage | Action | Success | Failure | Rollback |
|---|---|---|---|---|
| A. Precheck | Resource gate (section 8); R1/R2/S1/S2 deep health without failures; running configuration equals the accepted baseline (`REC-000001`, `REC-000002`, and a recorded digest for R1/S1); `populate_netbox.py --check` unchanged; each anchor OSPFv3-learned; route-table, neighbour and digest snapshots; probes started (H1-H4 to both service addresses, host to host, switch loopbacks) and loss-free for 2 minutes | all pass | any miss | none; do not start |
| B. VLAN99 IPv6 | candidate stage 1 on S1, S2 | `::1` pings `::2`; IPv4 on Vlan99 unchanged | no reply | remove the address |
| C. IS-IS | candidate stage 2 on all four | adjacencies UP on S1-R1, S2-R2, S1-S2 (`ISIS_NEIGHBOR_EXPECTED`); `show ip route isis` empty | not UP in 60 s | `no router isis NMAS`, remove `isis` lines |
| D. Prefixes | candidate stages 3 and 4 | client /64s and both aggregates in the IS-IS database; static routes still active; no `2001:db8:200::/64` in IS-IS | missing prefix; management prefix present | rollback stage 2 of the R files; remove `isis` lines from the SVIs |
| E. Alternate proof | `isis metric 1000` on S1 Ethernet1, verify, restore to 10; mirror on S2 | aggregate moves to Vlan99 and back (`ISIS_ROUTE_EXPECTED` with the path); configuration digest restored | path does not move; digest differs | re-apply the captured metric |
| F. RIP cleanup | section 4 stages A, B, C | both switches via Vlan99 before B; after C `RIP_NEIGHBOR_EXPECTED` present on Vlan99, absent on Vlan10/20/30; R1/R2 still learn the client /24s; VARP unchanged | still via Vlan10 after 90 s; client prefix missing upstream | re-add `network` lines; remove the temporary policy |
| G. Static IPv6 removal | candidate stage 6: S1, S2, then R1, R2 | IS-IS routes active; core has the client /64s from both routers | missing route | rollback stage 1 on all four |
| H. Persistence | `write memory` on all four; `templates/{R1,R2,S1,S2}.cfg.j2`, the S1/S2 Vlan99 addresses in `netbox/ipam.yml`, NetBox and NMAS records updated together | tracked source, NetBox and runtime agree | any disagreement | fix before closing |
| I. Final validation | IPv4 and IPv6 probes totalled; OSPFv2/v3, RIP, IS-IS, BGP neighbours; VARP; management reachability; route tables compared with stage A; new configuration digests recorded | zero loss; nothing unexpected changed | anything else | report; do not start the soak |

While the static routes exist, the IS-IS aggregate is not the active route on the switches, so the stage E metric test
proves the alternate in the IS-IS database and route candidates, not in forwarding. A forwarding proof is only
possible after stage G; a second metric test belongs in stage I.

## 8. Resource gate and the next soak

Measured on this host (8 cores, 96 GB RAM, 4 GB swap, swap unused throughout):

| Condition | 1-minute load average |
|---|---|
| Quiet, 15 lab containers, no sandbox (three readings) | 4.6 - 6.0 |
| Challenge console polling devices (two processes), nothing else | 19 - 29 |
| Sandbox of 5-9 cEOS containers running | 28 - 40 |
| Seven cEOS containers booting | 93 |

Lab cEOS containers showed 55-60% CPU each while the console was polling. R1's telemetry read 70% (warning) and then
90-91% (critical) in the window that failed the soak.

Gate, checked immediately before stage A and before starting a soak; refuse to start unless all hold:

- no container or network labelled `nmas-sandbox` exists;
- no local test run or other batch job is running on the host;
- the challenge console is not polling (it is optional load; required monitoring stays on);
- 1-minute and 5-minute load averages are both at the quiet level measured above, that is at or below 8 (one per
  core); swap in use is zero;
- CPU telemetry for R1, R2, S1 and S2 is below the warning threshold.

The next soak is a new record. It starts only after stage I passes and the new baseline is sealed; `SOAK-000001` is not
reused.

## 9. Blockers before live activation

1. Explicit authorization.
2. **A decision on the boundary policy.** It meets every requirement except loss-free failover on an abrupt total core
   loss (1 to 3 s lost). Either that requirement is restated for planned work only, or a different mechanism is chosen
   and proven.
3. The boundary policy and the staged RIP cleanup are not modelled in NMAS. As things stand they would be applied from
   the tracked candidate files.
4. The S2 -> R1 loopback flow lost 2 probes in one of two staged RIP runs; not reproduced, not explained.
5. A metric-only Change has not gone through intent, validation, plan and precheck.
6. The new postchecks are not yet called from any plan.
7. The October 6 Changes `-0003`, `-0004` and `-0005` are not referenced by a reconciliation record and stay executable.
   `-0003` would add temporary static routes to R2. A further record is needed to cover them.
8. The gate and drift changes are in a branch, not deployed. Until merged and promoted, the reconciled Changes are still
   executable in production.
9. Host load must be at the quiet level; the challenge console was polling during this work.
