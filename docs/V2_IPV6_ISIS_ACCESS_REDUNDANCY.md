# V2 — IPv6 IS-IS access redundancy and the VLAN99 dual-stack transit

Status (2026-10-09): **designed, proven in a disposable sandbox, source support implemented, candidates prepared.
LIVE ACTIVATION DEFERRED UNTIL SOAK-000001 COMPLETES.** No routing configuration on R1, R2, S1 or S2 was changed.
`SOAK-000001` is `RUNNING` until 2026-10-13 10:56 UTC and covers R1.

This document is the design, the evidence and the activation runbook. It is not Maintenance Mode.

> **Update 2026-10-10.** `SOAK-000001` ended COMPLETED / FAIL (resource only; zero drift, zero interference). The
> single-anchor aggregate described below was re-examined and replaced by a multi-anchor aggregate, and several NMAS
> gaps listed in section 6 were closed. The current boundary recommendation, capability table, staged plan and
> blockers are in `docs/V2_ISIS_RIP_LIVE_MIGRATION_READINESS.md`, which supersedes sections 5, 6 and 8 here.

## 1. What changes and what does not

| Domain | Devices | IPv4 | IPv6 |
|---|---|---|---|
| Access | R1, R2, S1, S2 | RIPv2 (unchanged protocol) | **IS-IS** (replaces static routes) |
| Core | R1, R2, R3, R4 | OSPFv2 | OSPFv3 |
| PE | R3, R4, R5 | eBGP | eBGP |

- No OSPF or BGP is introduced on any access interface. RIPv2 stays the IPv4 access protocol.
- VARP stays on S1/S2 and is not touched. There is no MLAG or LAG in this lab and none is added.
- VLAN 200, Containerlab management and R5 are out of scope and unchanged.
- VLAN99 becomes the one deliberate S1<->S2 routing transit for both families.

```
            R1                     R2
             |                     |
     RIP v4 / IS-IS v6     RIP v4 / IS-IS v6
             |                     |
            S1=====================S2
                 VLAN99 transit
```

## 2. State found before the change (read-only, 2026-10-09)

- IPv6 access routing is static: R1/R2 hold three client /64 routes each toward their own switch, S1/S2 hold
  `2001:db8::/32` toward their own router. There is no IPv6 path across VLAN99, and VLAN99 has no IPv6 address.
- IPv4: S1 and S2 are RIP neighbours over **both** Vlan99 and Vlan10, because `network 192.168.10.0/24` enables RIP on
  the client SVIs and VLAN10 spans both switches. S1 reaches the R2 side over Vlan99; S2 reaches the R1 side over
  Vlan10 (`192.168.10.2`). The two paths have the same hop count, so each switch simply kept the one it learned first.
  Nothing requires the client-VLAN adjacency.
- Core OSPFv2/OSPFv3 Full on R1 and R2; no IS-IS process anywhere; no Port-Channel or MLAG configuration.

## 3. What the sandbox proved (cEOS 4.36.2F, five disposable containers, never part of `srlceos01`)

The sandbox replicated the current design first (it reproduced the Vlan10 behaviour exactly), then each change.

### IS-IS

| Question | Result |
|---|---|
| IPv6-only IS-IS | Yes. `address-family ipv6 unicast` alone; LSPs carry `NLPID: 0x8E(IPv6)` only and `show ip route isis` is empty. |
| NET / level | `net 49.0110.<system-id>.00`, `is-type level-2`; one area, level 2 only. |
| Multi-topology | Not required. |
| Adjacency over a routed port and an SVI | Both `UP` (default broadcast network type and point-to-point were each tested). |
| Passive advertisement | `isis enable <tag>` + `isis passive` on a client SVI advertises its /64 and forms no adjacency. |
| Metric | **`isis metric N` steers traffic. `isis ipv6 metric N` does not** in single topology — it changed nothing. |
| Redistribution | `redistribute isis level-2 route-map` into OSPFv3; `redistribute static route-map` into IS-IS; `match tag`, `set tag`, `match ipv6 address prefix-list` all accepted. |
| Not available in this image | IS-IS `summary-address`, an IS-IS default-originate, any OSPFv3 inbound filter or per-prefix distance. |
| Management leak | `2001:db8:200::/64` never appears in the IS-IS database (Vlan200 is not enabled for IS-IS). |

### Why northbound is a tracked aggregate, not OSPFv3 specifics

Redistributing OSPFv3 routes into IS-IS on both R1 and R2 was tried and **rejected on evidence**: R1 preferred R2's
IS-IS copy of the service prefix over its own OSPFv3 route and the route state became inconsistent. The cause is
structural. At each boundary router two comparisons use the same knob:

- client prefixes: native IS-IS must beat the other router's OSPFv3 external copy;
- core external prefixes: OSPFv3 external must beat the other router's IS-IS copy.

Both are "IS-IS versus OSPFv3 external", and this image has no per-prefix distance. So core prefixes are **not**
redistributed into IS-IS at all. R1 and R2 each advertise one aggregate, `2001:db8::/32` — the same scope the switches'
static route has today — from a static route whose next hop is the OSPFv3-learned service address
`2001:db8:3050::10`. The static route, and therefore the IS-IS advertisement, exists only while that router really
reaches the core: with R1's core link down the aggregate was withdrawn and S1 moved to S2/R2 on its own, including with
a management default route present. Client prefixes are redistributed IS-IS -> OSPFv3 only, filtered by the existing
`CLIENT-V6` prefix list and tagged 6200; `distance ospf external 130` on the OSPFv3 process (mirroring the existing
OSPFv2 line) keeps native IS-IS preferred for them. No route can travel OSPFv3 -> IS-IS -> OSPFv3.

### RIP: making VLAN99 the IPv4 transit

- **EOS RIP has no passive-interface.** `router rip` offers only `network`, `distribute-list`, `redistribute`,
  `distance`, `metric default`, `timers`, `ecmp`, `shutdown`.
- A `network` statement selects the interfaces RIP **runs on**; connected prefixes are advertised regardless. With
  the client `network` lines removed, a capture on S1's uplink still showed `192.168.10.0/24` and `192.168.20.0/24`
  at metric 1, no RIP packet was seen on Vlan10, the neighbours were the uplink and Vlan99 only, and both switches
  used Vlan99 for the other side. VARP stayed `active`.
- Removing the statements directly lost about 25 s of S2 -> R1-loopback traffic (S2's Vlan10 routes were withdrawn
  before the Vlan99 ones were installed). Production-style flows were unaffected, but that is still loss.
- **Loss-free sequence:** first advertise a worse metric on the client VLANs
  (`distribute-list out route-map RIP-CLIENT-VLAN-DEPREF Vlan10|Vlan20`, `set metric 8`), wait until both switches
  have moved to Vlan99, then remove the `network` lines, then remove the temporary policy. Measured: 0 lost of 1383,
  1386 and 1384 probes.

### Measured results

| Test | Probes lost |
|---|---|
| Candidate files, stages 1-6 (static -> IS-IS), five flows | 0 of 1079 / 1080 / 1083 / 1084 / 1079 |
| Rollback files, two stages (IS-IS -> static), four flows | 0 of 590 / 591 / 592 / 593 |
| R1 drain by `isis metric 1000` on S1 Ethernet1, then restore | 0 of 736 / 734 / 738 / 739 (with the mirrored R2 test in the same run) |
| RIP cleanup with the temporary de-preference | 0 of 1383 / 1386 / 1384 |
| RIP cleanup without it | 128 of 1333 on S2 -> R1 loopback; 0 on the other three flows |

## 4. Design

- **Process:** `router isis NMAS`, `is-type level-2`, `address-family ipv6 unicast` only.
- **NET:** `49.0110.1921.6825.50NN.00` from Loopback0 `192.168.255.NN` — R1 `5001`, R2 `5002`, S1 `5011`, S2 `5012`.
- **Adjacency interfaces (metric 10 each, recorded explicitly):** R1 Ethernet2 – S1 Ethernet1, R2 Ethernet2 – S2
  Ethernet1, S1 Vlan99 – S2 Vlan99.
- **Passive:** Vlan10, Vlan20, Vlan30 on S1 and S2.
- **Never enabled for IS-IS:** R1/R2 Ethernet1, Vlan101-104, Vlan200, Management0, anything toward R5.
- **VLAN99 IPv6:** NetBox prefix `2001:db8:110:3::/64`, S1 `::1`, S2 `::2`.
- **Original metrics:** 10 on every adjacency interface. S1 -> north costs 10 via R1 and 20 via S2/R2; mirrored on S2.

Candidate and rollback configuration: `docs/evidence/v2-isis/{R1,R2,S1,S2}.{candidate,rollback}.cfg`.

## 5. Activation runbook (not executed)

Precondition: `SOAK-000001` finished cleanly. If it failed, drifted or was interfered with, stop.

Start continuous IPv6 probes before the first change and keep them running to the end: H1, H2, H3, H4 to the
WebServer loopback `2001:db8:3050::10`, and host to host across the switches. **Any lost probe stops the migration:**
apply the rollback stages, verify recovery, report the sequence number and time. Convergence loss is not acceptable.

| Stage | Devices | Action |
|---|---|---|
| 1 | S1, S2 | Vlan99 IPv6 address |
| 2 | all four | IS-IS process and adjacency interfaces |
| 3 | S1, S2 | passive client SVIs |
| 4 | R1, R2 | policy, tracked aggregate, both redistributions |
| 5 | — | verify: three adjacencies UP; client /64s and both aggregates in the IS-IS database; no management prefix; static routes still installed |
| 6 | S1, S2, then R1, R2 | remove the static routes and the old static redistribution |

Each stage is applied on every listed device before the next one starts. Rollback is the two stages in the
`*.rollback.cfg` files, also device-complete per stage. The IPv4 RIP stages A-C are a separate window with IPv4 probes.
After activation: write startup-config, update `templates/{R1,R2,S1,S2}.cfg.j2` and add the S1/S2 Vlan99 addresses to
`netbox/ipam.yml` in the same commit, so tracked source, NetBox and runtime agree.

## 6. NMAS support

| IS-IS operation (cEOS) | Status |
|---|---|
| Intent model: NET, level, IPv4/IPv6 address family, binding passive and metric | Fully supported (existed) |
| Render: process, `isis enable`, `isis metric`, `isis passive` inside the owning interface | **Implemented here** |
| Validation: NET syntax, level, metric range, capability gate | Fully supported (existed); cEOS is now selectable |
| Execution and compensation: new process, new binding | **Implemented here** (captured running-config inverse, like OSPF/RIP) |
| Changing an existing metric (the future drain lever) | **Missing** — it replaces a configured value, so no exact undo is provable yet |
| Network type per binding (point-to-point) | Missing — the default broadcast type is used and was proven |
| Instance tag | Fixed to `NMAS`; the model has no tag field |
| Redistribution, route maps, prefix lists, protocol distance | Missing for every protocol in the intent model |
| IS-IS neighbour read / adjacency postcheck | Missing — the postcheck is configuration read-back only |
| Config import of `router isis` | Partial — recognised as a section, not parsed into intent |

Consequence: the IS-IS process and bindings can go through NMAS, the boundary policy cannot. Live activation therefore
uses the staged candidate files with the tracked startup templates as the persistent source. FRR, SR Linux, IOS XE,
IOS XR and SONiC still report IS-IS as not implemented.

RIP needed no new renderer: a binding is a `network` statement, so the redesign is the removal of the client-SVI
bindings. The cEOS driver keeps reporting a RIP `passive` binding as having no EOS command, which the sandbox confirmed.

## 7. Planned drain versus failure convergence

A future planned drain must **pre-drain**: start evidence, validate the alternate, raise the existing IS-IS metric,
verify traffic moved, verify zero loss, and only then isolate the target. Shutting a router and waiting for IS-IS to
converge is failure convergence, not maintenance, and is not the model. The sandbox drain test followed the first
sequence and lost nothing; the core-link shutdown test was a failure test and did lose packets, as expected.

Two limits to carry forward:

- The IS-IS metric on a switch uplink drains **egress** toward that router. Traffic arriving from the core still
  enters through whichever of R1/R2 the core prefers; draining that direction needs the existing OSPFv3 cost.
- H1/H2 are single-homed to S1 and H3/H4 to S2. Neither IS-IS nor VARP changes that. For switch maintenance, active
  attached production traffic blocks; once it is verified absent, the lack of a second switch does not.

Redundancy is evaluated per traffic class, address family and direction — for example "IPv6 access, primary S1->R1,
alternate S1->VLAN99->S2->R2, mechanism IS-IS" — never as "is R1 redundant".

## 8. Remaining limitations

- Nothing here is live. Every result above is from the sandbox.
- The aggregate tracks reachability of the single service prefix `2001:db8:3050::10`. If that prefix is withdrawn
  while the core is otherwise healthy, both routers withdraw the aggregate.
- A pre-existing IPv4 hazard was observed in the sandbox and left alone: with `distance ospf external 130`, R1 can
  prefer a RIP copy of the service /32 learned around the access ring over its own OSPF external route. The live R1
  currently uses the OSPF route.
