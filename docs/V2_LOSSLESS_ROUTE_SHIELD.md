# V2 lossless route shield: static IPv6 to IS-IS, and planned R1/R2 maintenance

Status of this document: sandbox evidence and design. **Nothing described here was applied to R1, R2, S1, S2, R3 or
R4.** The forwarding mechanism, including the temporary R3/R4 covers, is accepted as the design (2026-10-11). NMAS
owns the whole migration as one transaction (section 8), including startup persistence and an operator-initiated
revert of a completed migration (section 10). Production was read by the read-only dry run (section 10.3) and not
written. `STATIC_IPV6_TO_ISIS` is `READY` in `core/services/route_shield/readiness.py`, following the explicit operator
authorization of 2026-10-12. That does not allow arbitrary execution: a live run still requires the deployed NMAS
lifecycle (Change -> validation -> Plan -> Precheck -> approval -> execute), a fresh passing production precheck,
healthy probes and host resource gate, and the explicit live-window authorization against the deployed commit.
Permanent IS-IS scope remains R1, R2, S1 and S2 only; R3 and R4 remain OSPFv3 and receive only temporary migration
covers. `ISIS_TO_STATIC_IPV6_REVERT` and `ISIS_METRIC_STEER` remain `PROVEN_NOT_AUTHORIZED`. The activation checklist
is section 11.

## 1. The problem

cEOS-lab replaces a route by deleting it and then installing the new one. A packet forwarded in between has no route:
a transit packet is dropped inside the device, a locally originated one follows the management default. This was
established in the previous phase and is the reason every planned transition was `NOT_READY`.

This phase found three further places where the same thing happens during the static-to-IS-IS migration:

| Where | What happens | Consequence without protection |
|---|---|---|
| S1 / S2 | the aggregate `2001:db8::/32` changes owner (static to IS-IS) | upstream transit packets dropped in the switch |
| R1 / R2 | the three client /64 routes change owner | downstream transit packets dropped in the router |
| R1 / R2 | deleting the only static of a prefix withdraws its OSPFv3 external LSA and re-originates it 5 s later; other routing changes re-originate it sporadically | every core router replaces its client routes |
| R3 / R4 (FRR 8.4.4) | zebra updates an IPv6 route by delete-then-add in the kernel, which is its forwarding plane; the only less-specific route behind a client /64 is the management default | downstream packets leave through the management network for 5 to 750 microseconds per event |

The last row matters because the production core is not cEOS: R3 and R4 are FRR with ECMP toward R1 and R2, and R5
learns the client prefixes from them by eBGP `network` statements. The first sandbox core was cEOS and hid this.
The sandbox core was rebuilt to the production shape before the proof run (section 5).

## 2. The mechanism

A shield is a temporary static route that keeps a valid forwarding entry in place while another entry is replaced.
Two shapes are used; a third was tried and is refused.

### 2.1 Switch aggregate: the two /33 halves (more-specific pair)

| Item | Value |
|---|---|
| Protected route | `2001:db8::/32` on S1 and S2 |
| Shield routes | `ipv6 route 2001:db8::/33 <next hop>` and `ipv6 route 2001:db8:8000::/33 <next hop>`, administrative distance 1 |
| Next hop, baseline migration and its rollback | the switch's own router on the uplink: S1 `2001:db8:110:1::1`, S2 `2001:db8:110:2::1` |
| Next hop, maintenance drain | the other switch on VLAN99: S1 `2001:db8:110:3::2`, S2 `2001:db8:110:3::1` |
| Next hop, maintenance restore | the switch's own router on the uplink |
| Install order | verify the next hop answers, add both halves, verify both are programmed toward the expected interface |
| Removal order | verify the route that takes over is programmed and its next hop is a resolved neighbour, remove both halves, verify none remains |

Why the alternate path is valid: the shield always points at the path that is about to carry the traffic (or, for the
baseline migration, the path that carries it both before and after). The next hop is a directly connected neighbour
that already forwards the same traffic.

Why no loop: during a drain the shield on S1 points at S2, and S2 forwards the aggregate to R2 over its own uplink.
The shield is refused if the far switch's own aggregate does not leave through its uplink, and only one side is
drained at a time.

Why management cannot become the data path: the pair is more specific than the management default and is present for
the whole replacement, so no lookup for `2001:db8::/32` can fall through to `::/0`. The workflow refuses a shield
whose next hop resolves through a management interface.

Rollback: `no ipv6 route 2001:db8::/33 <next hop>` and `no ipv6 route 2001:db8:8000::/33 <next hop>`.

### 2.2 Router client prefixes: one /63 under each /64 (less-specific cover)

| Item | Value |
|---|---|
| Protected routes | `2001:db8:10::/64`, `2001:db8:20::/64`, `2001:db8:30::/64` on R1 and R2 |
| Shield routes | `ipv6 route 2001:db8:10::/63 <switch>`, `ipv6 route 2001:db8:20::/63 <switch>`, `ipv6 route 2001:db8:30::/63 <switch>`, distance 1 |
| Next hop | the router's own switch: R1 `2001:db8:110:1::2`, R2 `2001:db8:110:2::2` |
| When it forwards | only in the gap while the /64 is being replaced; otherwise the /64 wins |

A more-specific pair of /65 routes was tried first and **is lossy**: removing a /65 that carries traffic drops packets
inside the router on every attempt (captured: packets entered the router from the core and never left). A cover
longer than /64 is therefore refused by the model. The /63 never carries traffic except in the gap, so adding and
removing it never touches a route in use.

The extra space a /63 covers (`2001:db8:10:1::/64`, `2001:db8:20:1::/64`, `2001:db8:30:1::/64`) is unassigned. While
the shield is installed a packet to one of those unassigned addresses is forwarded router to switch to router until
its hop limit expires, instead of being dropped at once. No assigned address is affected.

### 2.3 Keeping the core quiet: floating statics

Before the distance-1 statics are removed, a copy of each at distance 250 is added
(`ipv6 route 2001:db8:10::/64 <switch> 250`, and the same for `:20::` and `:30::`). The static source then never
disappears: removing the distance-1 route is a best-path change to IS-IS (115) and the external LSA is not withdrawn.
The floating copies are removed once IS-IS owns the routes. cEOS keeps the distance-1 and distance-250 entries as
separate configuration lines, so `no ipv6 route <prefix> <next hop> 1` removes only the first.

This removes the 5 s withdrawal but does not make the boundary routers silent: see 2.4.

### 2.4 Core routers R3 and R4: kernel covers for the whole migration window

R3 and R4 are FRR 8.4.4. Their forwarding plane is the Linux kernel, zebra updates an IPv6 route there by deleting it
and adding it again (5 to 750 microseconds apart, measured), and the only less-specific route behind a client /64 is
the management default. Whenever R1 or R2 re-originates an external LSA, the core can replace the client route.

On the production-shaped sandbox the boundary routers did re-originate, sporadically and not only at the switchover:
after adding or removing a static route, after a redistribution change, and again tens of seconds later. In 20
forward and 20 rollback migrations the two cores replaced a client /64 84 times. No probe was lost, but at the probe
rates used the chance of a packet arriving inside such a gap is small, so that run does not prove the gap harmless.

A cover advertised by R1/R2 themselves (the /63 shield statics redistributed into OSPFv3) was tried and rejected:
it protected the switchover, but 51 of the 84 replacements happened outside it, several of them triggered by
withdrawing the cover itself.

The mechanism that is used instead is a temporary **kernel** route on each core router:

| Item | Value |
|---|---|
| Where | R3 and R4, in the kernel routing table (not FRR configuration; `staticd` is not running on them) |
| Routes | `2001:db8:10::/63`, `2001:db8:20::/63`, `2001:db8:30::/63` |
| Next hops | the two next hops the core's own client /64 is installed with at that moment: R1 and R2, by link-local address and interface |
| Command | `ip -6 route add 2001:db8:10::/63 nexthop via <R1 link-local> dev <if> nexthop via <R2 link-local> dev <if>` (and `:20::`, `:30::`) |
| Installed | before the first configuration change of the migration (before stage 1) |
| Removed | after the last change, and only once both cores have left every client /64 untouched for 120 s (`show ipv6 route <prefix>` uptime) |
| Rollback | `ip -6 route del 2001:db8:10::/63` (and `:20::`, `:30::`); a restart of the container also removes them |

Why this is valid: the cover sends a packet to the same two routers the /64 sends it to, and both forward the client
prefixes at all times (R1/R2 are themselves shielded). Why no loop: R1 and R2 never forward a client /64 back to the
core. Why management cannot become the data path: the /63 is more specific than `::/0` and is present for the whole
window. The cover is never redistributed: R3/R4 redistribute only BGP into OSPFv3 and announce the client prefixes to
R5 by exact `network` statements.

The workflow refuses a router transition unless every core router shows a cover for every protected prefix.

The covers are temporary transition guards, not topology intent. They never appear in the startup configuration of
R3/R4, in a Golden configuration, in NetBox route intent or in a final candidate. Their lifecycle is: capture the
prior state, install, verify, perform the protected migration, verify stable final forwarding, remove, verify absence,
verify the final intended state.

Production values (the boundary routers' link-local addresses on the core-facing VLANs, read from the running devices):

| Core | Prefixes | Next hop toward R1 | Next hop toward R2 |
|---|---|---|---|
| R3 | `2001:db8:10::/63`, `2001:db8:20::/63`, `2001:db8:30::/63` | `fe80::21c:73ff:fe20:ab82` on `Vlan101` | `fe80::21c:73ff:fe17:db73` on `Vlan103` |
| R4 | the same three | `fe80::21c:73ff:fe20:ab82` on `Vlan102` | `fe80::21c:73ff:fe17:db73` on `Vlan104` |

NMAS installs, verifies and removes them itself (`route_shield/core_cover.py`, section 8); the precheck refuses the
migration if a core's installed client /64 does not use exactly these next hops. **The design is approved; writing
these routes on production R3 and R4 is authorized (2026-10-12) only as temporary covers inside the NMAS migration
transaction.**

### 2.5 `set tag 6200` is dropped from the permanent design

The earlier permanent candidate tagged the IS-IS-sourced external LSAs with 6200. Nothing matches that tag, and it
changes the LSA at the moment of the switchover, which made an FRR core replace every client /64 at every switchover
(240 replacements per FRR router in 20 cycles). Without the tag the LSA content is the same before and after. The
permanent candidates in `docs/evidence/v2-route-shield/final/` do not set it.

## 3. Sequence

Forward, one side at a time (R1/S1 first, then R2/S2). Additive stages first; nothing is replaced in stages 1 to 4.

1. VLAN99 IPv6 addresses; IS-IS process and interfaces on all four devices.
2. Wait for the adjacencies R1-S1, R2-S2, S1-S2 (VLAN99).
3. Client SVIs passive in IS-IS; on the routers the northbound policy, the three `/32` anchor statics (before
   `distance ospf external 130`), static to IS-IS redistribution, IS-IS to OSPFv3 redistribution.
4. Verify IS-IS holds every prefix while the statics still own the routes.
5. Per side: install the switch shield (2.1) and the router shield (2.2); verify both.
6. Remove the switch static aggregate.
7. Add the floating statics; remove the distance-1 statics; wait until IS-IS owns the three client routes; remove the
   floating statics.
8. Remove the old `redistribute static` and `STATIC6-TO-OSPF`.
9. Verify the take-over next hops; remove the router shield, then the switch shield; verify no temporary line remains.

Before stage 1 the core covers (2.4) are installed and verified on R3 and R4. After stage 9 on the second side, and
after 120 s without a client-route change on either core, they are removed.

Rollback starts with the core covers, then per side in reverse order (R2/S2 first): shields; old route-map and
`redistribute static`; statics back; switch static back; remove the shields. Then the advertisements, IS-IS and the
VLAN99 IPv6 addresses are removed, and the core covers go after the same 120 s quiet period.
The configuration digest of each device must equal the digest taken before the migration.

## 4. IPv4

RIP is not changed. The client-VLAN `network` statements stay, no RIP adjacency is moved, nothing is de-preferred.
The permanent candidates carry today's `router rip` section unchanged.

## 5. Evidence

`docs/evidence/v2-route-shield/sandbox/` holds the scripts and device configurations, `results/` the summaries and
event logs of every run named below, `final/` the permanent candidates.

The sandbox is twelve disposable containers on their own Docker networks: R1, R2, S1, S2 as cEOS 4.36.2F with the
production routing configuration, two FRR 8.4.4 core routers in the forwarding path with ECMP toward R1 and R2 (as
R3/R4), an eBGP edge router (as R5), a web server, and hosts H1 to H4. The sandbox routers reach their switch on
Ethernet3 where production uses Ethernet2; nothing else differs in the migrated sections.

## 6. Results

### 6.1 What was measured

The production matrix, running through every change:

| Flow | Rate | Hosts |
|---|---|---|
| host to web server, IPv6 echo | 100 per second | H1, H2, H3, H4 |
| web server to host, IPv6 echo | 50 per second | H1, H2, H3, H4 |
| host to web server and back, IPv4 echo | 10 per second each | H1, H2, H3 (H4 is IPv6-only) |
| one long-lived TCP session per host and family | open for the whole run | H1 to H4 |
| a new HTTP request per host and family | every 250 ms | H1 to H4 |

H1 works in the sandbox and in production and is part of every figure. A missing sequence number counts as a lost
probe. Device-originated probes (from R1, R2, S1, S2 themselves) are reported separately as diagnostic. Two passive
monitors record every kernel route event for a client /64 on the two core routers and on the edge router.

A run passes only if all of these hold: no production probe lost, no TCP session broken, no HTTP request failed, the
running configuration after every rollback identical to the one before, and no client-route replacement on a core
router without a cover in place.

### 6.2 Baseline migration, 20 forward and 20 rollback

| Run | Core | Design | Probes lost | TCP / HTTP | Core replacements | Verdict |
|---|---|---|---|---|---|---|
| `proof20` | cEOS | switch /33, router /63, floating statics, `set tag 6200` | 0 of 2,699,249 | clean | hidden by cEOS; a passive FRR router saw 240 | superseded: core not production-shaped |
| `proof20frr` | FRR in path | as above without the tag, cover advertised by R1/R2 in OSPFv3 | 0 of 2,771,915 | clean | 84, of which 51 without a cover | **rejected** |
| `proof20kc` | FRR in path | switch /33, router /63, floating statics, kernel covers on the cores | **0 of 5,404,840** | clean | 24, **all covered** | **PASS** |

`proof20kc` in detail: 20 forward and 20 rollback migrations, 40 probe windows, none lost a probe; diagnostic probes
0 of 376,930 lost; seven TCP sessions open for the whole run without interruption; seven HTTP loops of about 39,000
requests each without a failure; the baseline configuration restored 20 times out of 20; the final configuration
identical in all 20 forward migrations; no client-route event at the edge router. The 24 core replacements followed
two kinds of step only: adding the floating statics on the second router (forward) and restoring the statics
(rollback).

Host conditions: nothing else ran on the host (the Challenge Console was stopped, no soak, no test run). The sandbox
itself keeps the 8-CPU host at a load of 15 to 29, with swap at 0. That is the quiet baseline of this test, not an
idle host, and it is a harsher condition than production, where the same devices run without the probe matrix.

### 6.3 Maintenance steering of R1 and R2 (run `drain20`)

With the sandbox in the IS-IS state, each cycle raised the IS-IS metric of S1's uplink to 1000 (R1 drained), restored
it to 10, then did the same on S2 (R2), each time under the switch shield of 2.1 pointing at the path about to carry
the traffic.

| Item | Result |
|---|---|
| R1 drains / restores | 20 / 20 |
| R2 drains / restores | 20 / 20 |
| Production probes | 0 of 1,018,183 lost |
| Diagnostic probes | 0 of 71,155 lost |
| TCP / HTTP | all sessions uninterrupted, all requests successful |
| Client-route replacements on the cores, events at the edge | 0, 0 (no core cover is needed for steering) |

**Limit of this proof.** The metric moves the northbound direction only (hosts toward the core). Southbound traffic
still reaches the hosts through the "drained" router, because the core keeps both routers as equal-cost next hops.
Taking R1 or R2 out of service with traffic flowing also needs the southbound direction moved (an OSPFv3 change on
that router, which makes the cores replace their client routes and so needs the covers of 2.4). That was not built
or measured. Maintenance Mode of R1/R2 with active traffic therefore stays `NOT_READY`; only the northbound steering
step is proven.

### 6.4 Locally originated traffic on S2

In an early trial, probes originated by a switch itself lost about half their packets for about 4 s after the first
metric change; transit traffic lost nothing. It did not recur: in `drain20` the switch-originated probes lost 0 of
71,155 through 40 drains and 40 restores, including the first one after the IS-IS state was created.

| Question | Answer |
|---|---|
| Which table | the switch's kernel routing table, used only by packets the switch originates; transit uses the forwarding plane and was never affected |
| Same path as transit | no |
| Production service originating on S1/S2 from that route | none: DHCP relay, logging, SNMP and RADIUS use the connected VLAN200, not the aggregate |
| Caused by the management default | not established; the early trial was not captured and the effect could not be reproduced |
| DHCP relay, VARP, control plane affected | no evidence of it: adjacencies stayed up and transit and relay-path addressing were unaffected in every run |

It is classified as a diagnostic-path effect that was not reproduced with the final shield, with no production
dependency. Its cause is not known.

### 6.5 Readiness

| Transition | State | Reason |
|---|---|---|
| Static IPv6 to IS-IS, and its automatic reverse path | `READY` | `proof20kc` passed; live changes on R1/R2/S1/S2 and the temporary kernel covers on R3/R4 explicitly authorized by the operator on 2026-10-12 |
| Operator-initiated revert of a completed migration (`ISIS_TO_STATIC_IPV6_REVERT`, section 10) | `PROVEN_NOT_AUTHORIZED` | `fc_revert` passed; not authorized |
| IS-IS metric steering (northbound) | `PROVEN_NOT_AUTHORIZED` | `drain20` passed; not authorized |
| R1/R2 Maintenance Mode with active traffic | `NOT_READY` | southbound direction not built or measured (6.3, 9) |

Baseline migration in three parts: forwarding mechanism **proven**; NMAS orchestration **implemented and proven on the
sandbox** (section 8); production execution **authorized by the operator on 2026-10-12**, through the NMAS lifecycle
only and subject to a fresh passing production precheck, healthy probes and host resource gate, and the live-window
authorization against the deployed commit.

`runner.execute` refuses every state other than `READY`; only `STATIC_IPV6_TO_ISIS` is `READY`.

## 7. NMAS workflow

`web/core/services/route_shield/` implements the two transitions of section 6.5 and nothing more general.

| Stage | What it does |
|---|---|
| Validation | the model refuses a malformed transition (for example a router cover longer than /64) |
| Planning | one configuration block per step: shield install, the replacement steps, shield removal, each with its exact inverse |
| Precheck | one fresh read of the device; any blocker of the list below stops the transition before a line is sent |
| Execution | the production cEOS executor, one block at a time |
| Read-back and postcheck | after every block: the shield is programmed toward the expected interface, the new owner holds the route, the take-over next hop is a resolved neighbour, no temporary line remains at the end |
| Compensation and restore | on any failure the applied blocks are undone in reverse order and the configuration digest must equal the one taken before the transition |

Blockers: expected old route absent, new path unavailable, alternate next hop unhealthy, route classification unknown,
production probes unhealthy, shield not confirmed, management route would forward, configuration baseline stale,
out-of-band change, host resource gate failed, core cover not confirmed, live evidence unavailable. Any lost
production probe during a transition aborts it, restores the last verified state and keeps the evidence.

`runner.execute` is the only service entry point and refuses every transition whose readiness is not `READY`; no
argument lifts that. No UI, API route or management command reaches the workflow. 34 unit tests cover the model, the
gates, the abort paths and the refusal.

### 7.1 Isolated pipeline proof

The workflow was run against the sandbox with the production executor over `docker exec`, on scratch Django
settings, with no NetBox, inventory or production database involved (`sandbox/nmas_pipeline.py`; it calls the
ungated internal entry after showing that `execute` refuses).

| Run | Content | Result |
|---|---|---|
| `nmas_mig2` | 1 forward and 1 rollback migration, 8 transitions | all stages passed; 0 of 525,694 probes lost; baseline restored; 2 core replacements, both covered |
| `nmas_abort` | a router transition without core covers; then a lost probe reported right after the statics were removed | first refused with `UPSTREAM_COVER_NOT_CONFIRMED` (and `NEW_PATH_UNAVAILABLE`, IS-IS not being prepared yet), nothing sent; second aborted with `PRODUCTION_PACKET_LOSS`, three blocks compensated, statics own the routes again, configuration identical to before; 0 of 198,809 real probes lost |
| `nmas_toisis`, `nmas_drain`, `nmas_tostatic` | forward migration, 4 drains and 4 restores, rollback | all stages passed; 0 lost of 265,980, 364,844 and 246,928; baseline restored |
| `nmas_mig` | 3 forward and 3 rollback migrations, 24 transitions | all stages passed and the baseline was restored 3 times, **but its loss figures are not evidence**: each half ran longer than the 16-bit sequence counter of the 100-per-second probes allows. It was repeated as `nmas_mig2` at 40 per second |

The workflow moves one device completely before the next (switch, then router), which is slower than the scripted
sequence of the 20+20 proof: about 14 minutes per direction on the loaded sandbox host. The 20+20 repetition was
done with the scripted sequence, not through the workflow.

### 7.2 What this per-device workflow did not cover

This section describes the first, per-device workflow (`runner.py`). It was not connected to Change, plan or approval
records, applied the additive IS-IS stages from the sandbox script, and only checked that the core covers existed.
Section 8 replaces it for the baseline migration: one transaction, all six devices, covers included. `runner.py`
remains for IS-IS metric steering (section 6.3).

## 8. One NMAS transaction across S1, S2, R1, R2, R3 and R4

The forwarding mechanism of sections 2 and 3 was accepted on 2026-10-11, including the temporary kernel covers on R3
and R4. This section describes how NMAS now owns the whole migration, covers included. Production execution was
authorized by the operator on 2026-10-12 (section 6.5) and has not been run.

### 8.1 Lifecycle

| Step | Record | Content |
|---|---|---|
| Change | `Change` with the six devices as targets | carries only the transition kind; the content is the approved design |
| Validation | `ChangeValidationRun` (immutable) | the plan against the approved design (cover inventory, cover window, every temporary statement removed again, exact inverses) and the managed inventory (R1/R2/S1/S2 are cEOS, R3/R4 are Ubuntu/FRR) |
| Plan | `ChangePlan` with 48 frozen `Configlet` rows | one row per operation in execution order, each marked `PERMANENT` or `TEMPORARY`, with its statements, its exact inverse and the checks before and after it |
| Precheck | `OperationalCheckRun` (precheck) | fresh reads of all six devices; section 8.3 |
| Approval | lifecycle event to `READY_TO_DEPLOY` | the Change id typed again and four explicit acknowledgements, bound to that plan and that precheck |
| Execution | `ChangeExecutionRun`, one `ConfigletExecutionResult` per operation and per undo | one lock on all six devices; section 8.4 |
| Postcheck | `OperationalCheckRun` (postcheck) | section 8.5 |
| Evidence | the run report, audit events, lifecycle events | stages, probes per flow, digests before and after, what was temporary, what remains |

The operator entry point is `python manage.py nmas_isis_migration create | validate | plan | precheck | approve |
execute | show`. No shell script runs beside it. The general execution engine refuses a transition Change
(`TRANSITION_CHANGE_NOT_GENERIC`): applying its rows as a plain list would skip the waits and checks between them.

### 8.2 Permanent intent and temporary transition state

| Kind | Operations | In the final desired configuration |
|---|---|---|
| Permanent, 24 operations | VLAN99 IPv6 addresses; IS-IS process and interfaces; client SVIs passive; boundary policy and anchors; removal of the superseded static aggregate, client statics and static redistribution | yes |
| Temporary, 24 operations | 6 cover installs and 6 cover removals on R3/R4; 4 shield installs and 4 removals on S1/S2/R1/R2; 2 floating-static additions and 2 removals on R1/R2 | no |

The plan summary lists the two sets separately (`permanent_intent`, `temporary`). Validation blocks a plan in which a
temporary statement is never removed, or is declared as permanent intent. The run report lists what temporary state
was installed, what was removed, and what remains (read from the devices, not from the run's own records). Nothing
permanent is ever planned on R3 or R4.

### 8.3 Prechecks

Before the first write, on every run and again inside the lock:

| Scope | Must hold |
|---|---|
| R3, R4, per cover | the target is R3 or R4; the prefix is the /63 of a client /64; the client /64 is installed toward exactly the approved two next hops and FRR holds it with both active; no route exists for the /63 (a route that exists is never overwritten); nothing else lies inside the /63; both next-hop interfaces are up; each next hop is a Full OSPFv3 neighbour with that link-local address on that interface; neither interface is the one the default route uses |
| S1, S2, R1, R2 | the statics own the aggregate and the client routes; the shield next hop is directly connected, up and answers; no shield route exists; no statement the plan adds is already configured; every statement the plan removes is present |
| All | the host gate; the production probes answer on every flow with no loss; every device unchanged since the approved precheck (configuration digests, non-dynamic kernel routes, FRR configuration, OSPF adjacencies) |

### 8.4 Execution, read-back and compensation

Every operation is assessed against the current device state, applied, read back (the device must report it as in
place), verified by its own checks and followed by a probe read. After the six covers are installed, each is read
back from the kernel (exact route, both next hops), a lookup under it must leave toward a boundary router, and the
core's OSPF adjacencies must be unchanged; no access device is touched before that.

| Failure | Behaviour |
|---|---|
| Before any write | `BLOCKED`, nothing sent |
| While installing covers | the covers already installed are removed, absence verified |
| During the migration | the covers stay; every applied operation is undone newest first, each by its exact inverse, each read back, with the configuration digest of the device compared to the one taken before that operation; then the covers are removed once the cores are quiet |
| A cover cannot be removed, or removing it is not provably safe | the run ends `FAILED_COMPENSATION_INCOMPLETE`, the report names every route and statement still present, and the Change cannot be executed again |

A run is reported as restored only if every undo was verified, no temporary statement or cover remains on any device,
and the digests of all six devices equal the precheck's.

### 8.5 Postcheck

Nothing temporary on any access device; every permanent statement present and every superseded one gone; IS-IS owns
the aggregate on S1/S2 and the client routes on R1/R2 with adjacencies up; no cover on R3/R4; R3/R4 non-dynamic
kernel routes and FRR configuration equal to the precheck's, adjacencies unchanged; no probe lost. The final
configuration digests of R1, R2, S1 and S2 are stored as the new baseline. The startup configuration is not written:
NMAS executes on the running configuration and persistence belongs to the Golden step.

### 8.6 Isolated full-pipeline proof

The complete lifecycle was run on the rebuilt disposable sandbox (section 5) with an isolated SQLite database and the
six sandbox containers as inventory. Nothing read NetBox, `inventory.yml` or the production database
(`sandbox/nmas_lifecycle.py`). The probe source was the workflow's own (`route_shield/probes.py`): 14 flows, H1 to H4
toward the service and back, IPv6 at 100 and 50 per second, IPv4 at 10 per second.

| Run | Content | Outcome | Evidence |
|---|---|---|---|
| `lc_forward` | Change, validation, plan, precheck, approval, execution of all 48 operations, postcheck | `SUCCEEDED`, Change `DEPLOYED`, postcheck `PASS` | 0 of 659,579 probes lost on 14 flows; 7 TCP sessions uninterrupted; 7 HTTP loops without a failure; 12 temporary installs and 12 removals, nothing remaining; no cover left on either core; final configuration digests identical to the final state of `proof20kc`; 2 client-route replacements on the cores, both covered; none at the edge router; 18 minutes |
| `lc_abort2` | the same, with a failure injected after R2's client statics were removed (side R1/S1 already fully migrated, side R2/S2 in mid-switchover; 38 operations applied) | `FAILED_ROLLED_BACK`, Change `ROLLED_BACK` | 38 of 38 operations compensated; configuration digests of all four access devices equal to the start; no shield, floating static or cover remaining; 0 of 779,185 probes lost; TCP and HTTP clean; no client-route replacement on the cores or the edge; 22 minutes |
| `lc_abort1` | the same, failure injected after R1's client statics were removed (29 operations applied) | `FAILED_ROLLED_BACK` | 29 of 29 compensated; digests restored; nothing temporary remaining; 0 of 1,206,280 probes lost; TCP and HTTP clean; no client-route replacement on the cores or the edge |

Gates shown in each run before execution: the general execution engine refused the Change; execution before approval
was `BLOCKED`; approval without acknowledgements was refused; the service entry point refused. In two earlier
attempts the precheck itself blocked the run, correctly: the freshly built sandbox was not forwarding IPv4 (its edge
router had rejected `ip routing` at boot), and one core's next hops were not yet proven reachable.

Limits of these runs:

- One forward run and two abort runs, not a repetition series.
- `lc_abort1` was a first complete run made while the workflow was still being adjusted: covers were removed 120 s
  apart instead of together, which is slower and not less safe. `lc_abort2` ran before two later additions (the check
  that core adjacencies are unchanged after the covers are installed, and a provenance field of the plan record).
  `lc_forward` ran the final code. The reverse path on the final code is covered by unit tests on a simulated
  network, not by a further sandbox run.
- Host load was 15 to 27 on 8 CPUs during the runs, produced by the sandbox itself.

The 20+20 forwarding proof was not repeated: prefixes, next hops, statements and their order are the ones of
`proof20kc`. What differs is pace: the workflow reads back and verifies after every operation, so shields and covers
are held longer than in the scripted run.

### 8.7 What is still open

- Production execution has not been run. `STATIC_IPV6_TO_ISIS` is `READY` (operator authorization of 2026-10-12);
  `execute` still refuses without the approved Change, a fresh passing precheck, healthy probes and the host gate.
- There is no web page for the lifecycle; the operator entry point is the management command. The Change, its plan
  rows and its runs are ordinary records.
- The items this list held before (production wiring never exercised, no revert of a completed migration, startup
  configuration not written) are closed in section 10.

## 9. Maintenance of R1/R2 with traffic flowing: next step, not built

Section 6.3 proved the northbound half only. Taking R1 or R2 out of both forwarding directions needs, in this order:

| Direction | Mechanism (existing protocols only) | State |
|---|---|---|
| Northbound, hosts toward the core | IS-IS metric on the access side, under the switch shield | proven (section 6.3) |
| Southbound, core toward the hosts | OSPFv3 path selection on the core side, so that R3/R4 stop choosing the target router; every such change makes the cores replace client routes, so the covers of 2.4 are needed | not designed, not built, not measured |
| Verification | neither direction uses the target router; production probes lose nothing | not done |

No new routing protocol is introduced. Production OSPFv3 was not changed. R1/R2 active-traffic maintenance stays
`NOT_READY`. IPv4 maintenance is a separate, later problem; RIP is unchanged.

## 10. Live-window readiness closure

Closes the operational gaps that remained before a live-window decision. The forwarding design and the R3/R4 cover
mechanism are unchanged. Nothing was written to a production device; production was read (section 10.3).

### 10.1 Locked R3/R4 cover inventory

`core_cover.APPROVED_COVERS` is a constant: `2001:db8:10::/63`, `:20::/63`, `:30::/63` on R3 toward
`fe80::21c:73ff:fe20:ab82` on `Vlan101` and `fe80::21c:73ff:fe17:db73` on `Vlan103`, and the same three on R4 toward
the same addresses on `Vlan102` and `Vlan104`. The production executor is built without any other inventory and
refuses (assess `REFUSE`, nothing sent) any route that is not one of these six, including a well-formed /63 with
another prefix, next hop or interface, or an approved cover addressed to the other core. A different inventory can
only be handed to an executor whose container is not the managed production container (the sandbox cores, whose
next hops are measured); for the production container that is refused at connect. Validation blocks a production
plan whose covers are not exactly the inventory (`COVER_INVENTORY_MISMATCH`).

### 10.2 Persistence stage

After the final validation, and before the run can be `SUCCEEDED`:

| Device | What happens | Verified |
|---|---|---|
| R1, R2, S1, S2 | the running configuration must still be the digest the final validation recorded; `copy running-config startup-config`; `show startup-config` is read back | startup, running and intended digests equal; no temporary statement in the startup configuration; every permanent addition present and every superseded statement absent |
| R3, R4 | nothing is written | `/etc/frr/frr.conf`, the FRR running configuration and the non-dynamic kernel routes equal to the pre-run state |

The precheck requires startup equal to running on the four access devices before anything starts
(`STARTUP_NOT_IN_SYNC`): otherwise the persistence stage would also persist somebody else's unsaved change, and the
recovery below could not reproduce the previous startup configuration.

Recovery when persistence cannot be verified: the run fails closed (`PERSISTENCE_NOT_VERIFIED`), the postcheck run
keeps the evidence, the whole migration is undone by the reverse path, and every device whose startup configuration
was already written gets the restored running configuration written again; its startup digest must equal the pre-run
one. Outcome `POSTCHECK_FAILED_ROLLED_BACK`, or `POSTCHECK_FAILED_COMPENSATION_INCOMPLETE` with the device named when
a startup configuration cannot be written back.

### 10.3 Read-only production dry run and precheck snapshot

`nmas_isis_migration dry-run` builds the production environment the live command builds (`production.environment()`:
inventory, credential lookup, SSH sessions to R1/R2/S1/S2, `docker exec` to R3/R4, probe flows inside H1 to H4 and the
web server), wraps every executor and session in a guard that refuses and counts each write-capable call, and then
runs the real precheck, every read-back the live run is gated on, and the probes. It needs no Change and records
nothing.

Run on 2026-10-12 (UTC) against production, with the PR code and the deployed runtime's credential store, inventory
and database, the database opened read-only (`closure/prod_ro_settings.py`; PR #51 is not deployed). Report:
`docs/evidence/v2-route-shield/closure/production_dry_run.json`.

| Check | Result |
|---|---|
| six managed devices resolve with the expected platform | PASS |
| credentials resolve for R1, R2, S1, S2 | PASS |
| transport connects to all six | PASS |
| device identity matches the inventory name; cEOS / FRRouting detected | PASS |
| running and startup configuration of R1, R2, S1, S2 read | PASS |
| R3/R4 kernel routes, FRR and boot configuration read | PASS |
| IS-IS, RIP and OSPFv3 preconditions evaluated (the precheck reached a verdict) | PASS |
| probe sources start; 14 flows answer, 0 lost | PASS |
| route state read on all six | PASS |
| evidence targets resolve | PASS |
| every postcheck reader functions | PASS |
| no write method invoked (0 attempts) | PASS |

`PRODUCTION_READ_ONLY_DRY_RUN = PASS`

`PRODUCTION_PRECHECK = BLOCKED`, by one blocker:

| Blocker | Device | Cause |
|---|---|---|
| `STARTUP_NOT_IN_SYNC` | R1 | the running configuration holds `interface Loopback105` (`FOR-SOAK-TESTING`, the probation object of SOAK-000001, due 2026-10-13) that is not in the startup configuration |

It is a real condition of production, not a defect of the check: the migration must not persist the soak's object,
and it is not this workflow's to remove. The precheck passes once the soak has ended and Loopback105 is either
removed or saved by its own workflow.

What the snapshot recorded otherwise: R2, S1 and S2 startup equal to running; the expected static IPv6 routes
installed by static on all four (S1/S2 aggregate, R1/R2 three client prefixes each); the six approved covers absent
on R3 and R4, no conflicting route, both boundary routers Full OSPFv3 neighbours on the approved interfaces; no
temporary statement on any access device; no transition Change, pending or unresolved, in the database; NetBox holds
`2001:db8:110:3::/64` on VLAN 99 and, as intended before activation, no address inside it; the four tracked templates
are `PRE_MIGRATION`; the quiet-host gate passed.

The first dry run found a defect that the sandbox could not: FRR prints the age of a route older than a day as
`4d21h45m`, the code read only `HH:MM:SS`, and the precheck therefore reported the production client routes as not
installed. Fixed (`core_cover.uptime_seconds`) and covered by a test; the report above is the run after the fix.

### 10.4 Resource window

Measured on this host with the Challenge Console stopped, no disposable lab and no test run
(`closure/host_baseline.json`, 8 minutes settled): 1-minute load 3.3 to 6.06, CPU 41 to 49 % busy, swap 0. With only
the 14 dedicated probe flows added (`closure/host_probes.json`): CPU 80 to 84 %, load above 17 and still rising after
three minutes, 0 of 112,445 probes lost.

The gate follows the measurement. Before the probes start: console stopped, no `isisbx-*` or capability-validation
container, no test run, swap 0, CPU below the project's CPU warning threshold (70 %), 1-minute and 5-minute load at or
below 9.09 (the measured quiet maximum times 1.5). With the probes running: the same structural conditions, CPU below
the critical threshold (90 %), load recorded and not judged. A command that did not measure the quiet host first is
refused.

**Open point for the window decision.** "Host CPU below the warning state" cannot hold while the probes run at the
proven rates: the probes themselves are the load. The alternatives are to accept that (the sandbox proofs ran with
the same probes on a busier host and lost nothing) or to lower the probe rates for the live window, which lowers the
resolution of the loss measurement. The rates were not changed here.

### 10.5 Permanent source of truth

`source_of_truth.py` derives the post-migration content of the tracked templates from the plan: PERMANENT additions
are added, the statements a PERMANENT removal supersedes are removed, and no TEMPORARY statement can appear. The
reviewed copies are in `docs/evidence/v2-route-shield/intent/templates/`; a test keeps them equal to what the plan
derives and checks that the `router rip` section is untouched. The tracked `templates/` were not changed: until the
migration has succeeded they must stay `PRE_MIGRATION`. The updates that follow a `SUCCEEDED` run, each with its
verification, are listed in the runbook, section 7 (templates, the two `Vlan99` interface addresses in NetBox and
`netbox/ipam.yml`, a new Golden bundle). R3 and R4 have no entry: covers are execution evidence only.

### 10.6 Revert of a completed migration

`create-revert --migration-run <run id>` creates a Change of kind `REVERT_COMPLETED_BASELINE_MIGRATION`. It is not a
general rollback engine: its plan is the migration's 48 operations in the opposite order, each replaced by its exact
inverse and gated by the checks the automatic reverse path uses.

| Requirement | Implementation |
|---|---|
| references the successful run | only a `SUCCEEDED` migration run with verified persistence is accepted; once reverted it cannot be reverted again |
| uses the captured pre-migration baseline | the digests come from the immutable run record, never from the Change |
| fresh validation and precheck | its own validation, plan, precheck; the precheck requires the devices to be exactly what the migration left (`REVERT_BASIS_DRIFTED`) |
| explicit confirmation | its own approval with the Change id and the four acknowledgements; its own readiness key `ISIS_TO_STATIC_IPV6_REVERT`, `PROVEN_NOT_AUTHORIZED` |
| same shielding, R3/R4 covers | covers in first, out last; shields back before the statics return under them |
| IS-IS removed only when protected | IS-IS policy and process are removed after the statics own the routes again |
| zero observed loss | the same probes; a lost probe returns the devices to the migrated state |
| restores startup persistence | the same persistence stage; running and startup must equal the pre-migration digests |
| immutable evidence | the same run, result, postcheck and audit records |

### 10.7 Sandbox proofs on the closure code

All four runs used the code of commit `a5ebd01` (the working tree under `web/` was clean), the rebuilt disposable
sandbox, an isolated SQLite database and the sandbox containers as inventory. Evidence:
`docs/evidence/v2-route-shield/closure/`.

| Run | Content | Outcome | Evidence |
|---|---|---|---|
| `fc_abort` | the migration with a failure injected after R2's client statics were removed: six covers installed, side R1/S1 fully migrated, side R2/S2 in mid-switchover, 38 operations applied | `FAILED_ROLLED_BACK`, Change `ROLLED_BACK` | 38 of 38 operations compensated; running digests of R1, R2, S1, S2 equal to the start; startup equal to running and unchanged; no shield, floating static or cover remaining; core boot configuration unchanged; 0 of 811,820 probes lost on 14 flows; 7 TCP sessions with every message echoed; 7 HTTP loops without a failure; no client-route replacement on the cores, no event at the edge router; 22 minutes |
| `fc_forward` | the complete migration including the persistence stage | `SUCCEEDED`, Change `DEPLOYED`, persistence `VERIFIED` | 48 operations; startup written on R1, R2, S1, S2, each startup digest equal to the running and the intended digest; core boot configuration unchanged, no cover left; 0 of 708,663 probes lost; TCP and HTTP clean; no client-route replacement on the cores; 20 minutes |
| `fc_revert` | `REVERT_COMPLETED_BASELINE_MIGRATION` of the `fc_forward` run: own Change, validation, plan, precheck, approval | `SUCCEEDED`, Change `DEPLOYED`, persistence `VERIFIED` | 48 inverse operations; running and startup digests of all four access devices equal to the digests captured before `fc_forward`; no cover left, core boot configuration unchanged; 0 of 579,860 probes lost; TCP and HTTP clean; no client-route replacement on the cores; a revert that names an unknown run was refused (`REVERT_SOURCE_NOT_SUCCEEDED`); 16 minutes |
| `fc_abort_persist` | the migration with a failure injected after the startup configuration of R1 and R2 had been written and before S1 and S2 | `FAILED_ROLLED_BACK`, Change `ROLLED_BACK`, persistence `RECOVERED` | 48 of 48 operations compensated; R1 and R2 startup written back (`STARTUP_RESTORED`); running and startup digests of all four equal to the start; nothing temporary remaining; 0 of 959,936 probes lost; TCP and HTTP clean; no client-route replacement on the cores; 27 minutes |

`fc_abort` is the late-stage abort proof on the closure code. In each run the gates were shown before execution: the
general execution engine refused the Change, execution before approval was `BLOCKED`, approval without
acknowledgements was refused, the service entry point refused. A first attempt at `fc_abort`
(`closure/fc_abort_blocked1`) was blocked by the precheck with `STARTUP_NOT_IN_SYNC` on all four devices: the sandbox
shell wrapper prefixed the startup configuration with the echoed command line. The wrapper was corrected
(`sandbox/nmas_lifecycle.py`); the product code was not changed. Host load during the runs was 20 to 31 on 8 CPUs.

`readiness.py` records `ISIS_TO_STATIC_IPV6_REVERT` as `PROVEN_NOT_AUTHORIZED`; `fc_revert` is its evidence. The
comment in that file cites sections 6 and 8 only: it was left as it is so that the product code in the final commit
is byte-identical to the code these runs executed. Between `a5ebd01` and the final commit the only change under
`web/` is one test file, `core/tests/test_contracts.py`.

That change is a decision to review. The execution-boundary contract forbade any `startup-config` command string in
the execution package, and the hosted Tier-3 run of `1e7f00e` failed on it (2 failures of 718 tests): the persistence
stage needs `copy running-config startup-config` and `show startup-config` in the cEOS executor. The contract now
allows exactly these two strings in that one module and gains a test that no module of the general engine refers to
`save_startup`, and that `route_shield/lifecycle.py` is its only caller anywhere in the services.

### 10.8 Limits

- One run of each kind, not a repetition series. The 20+20 forwarding proof was not repeated; prefixes, next hops,
  statements and order are those of `proof20kc`.
- The production wiring was exercised read-only. The write path over SSH, including
  `copy running-config startup-config`, and a cover installed by `docker exec` on the production R3/R4 have never run
  on production. The sandbox executes the same executor classes over a different transport (`docker exec` and `Cli`).
- The dry run executed the PR code against the deployed runtime's credential store, inventory and database, because
  PR #51 is not deployed. A live window needs the code deployed, and the dry run repeated from the deployment.
- The sandbox cores use measured next hops through the sandbox-only inventory; the six production covers were
  checked for absence and conflict on production, never installed.
- The revert was proven directly after the migration it reverts. A revert days later depends on its precheck: any
  drift from the state the migration left blocks it, and is then a manual decision.
- Probes at the proven rates load this host beyond the CPU warning threshold (section 10.4); that decision is open.
- Template, NetBox and Golden updates are defined (runbook, section 7) and not applied.
- No web page; the operator entry point is the management command.
- R1/R2 maintenance with traffic flowing (section 9) is not part of this closure.

## 11. Production activation gate

Not executed. `PRODUCTION MIGRATION = BLOCKED` while any item is false. The table is the state at the end of the
closure pass; section 12 records what changed afterwards.

| # | Item | State | Basis |
|---|---|---|---|
| 1 | PR #51 final code Tier-3 green | recorded in the PR | must be the hosted run on the head commit of PR #51; a file cannot record the run of its own commit, so the run id is in the PR description |
| 2 | final-code late-stage abort | TRUE | `fc_abort`, section 10.7 |
| 3 | production read-only dry run | TRUE | `PRODUCTION_READ_ONLY_DRY_RUN = PASS`, section 10.3 |
| 4 | production precheck | **FALSE** | `PRODUCTION_PRECHECK = BLOCKED`: `STARTUP_NOT_IN_SYNC` on R1 (Loopback105 of SOAK-000001) |
| 5 | approved covers absent on R3/R4 | TRUE | dry-run snapshot |
| 6 | startup persistence implemented and tested | TRUE | section 10.2, `fc_forward`, `fc_abort_persist` |
| 7 | source-of-truth path defined | TRUE | section 10.5; runbook section 7 |
| 8 | reversion workflow available | TRUE | section 10.6, `fc_revert` |
| 9 | runbook matches code | TRUE | `docs/V2_ISIS_LIVE_MIGRATION_RUNBOOK.md`, rewritten against this code |
| 10 | production probes healthy | TRUE at the dry run | 14 flows, 0 lost; measured again by the precheck of the window |
| 11 | host resource gate available | TRUE | section 10.4; passed in quiet state at the dry run |
| 12 | no unresolved temporary state | TRUE | dry-run snapshot: no temporary statement, no cover, no transition Change |

Item 4 is false: **`PRODUCTION MIGRATION = BLOCKED`**. Independently of the list, execution needs an explicit
production authorization, which is a reviewed change of `readiness.py`, and the deployment of this code. Items 3, 4,
5, 10, 11 and 12 describe production at one moment and are evaluated again by the precheck of the live command.

## 12. Go/no-go preparation (2026-10-12)

Nothing of the migration was executed. No cover was installed.

### 12.1 SOAK-000001 and Loopback105

Read from the production records: SOAK-000001 is `COMPLETED` / `FAIL`, reason `RESOURCE_CRITICAL_SUSTAINED`
(R1 CPU high on three consecutive samples), started 2026-10-06T10:56:22Z, required end 2026-10-13T10:56:22Z, finished
2026-10-10T00:45:43Z by the collector; 344 samples; no Golden decision. Section 10.3 described the soak as still in
probation: that was wrong, it had ended two days earlier.

The soak lifecycle has no cleanup action (`docs/PROBATION_SOAK_AND_PROMOTION.md`: nothing is repaired or rolled back
after a failure). The operator decided to remove the probation object through an ordinary NMAS Remove Configuration
Change:

| Step | Record |
|---|---|
| read-only capture of R1 | snapshot `36c001d6-3669-4ea3-a86e-f377c9432b73` |
| Change | `CHG-20261012-0001`, one Configlet: `no interface Loopback105` |
| validation, plan | `0065226c` `PASS`; plan `205beada` |
| precheck | `7fa4f0ef` `PASS` (10 of 10), after a first one with a CPU warning while the Challenge Console was polling |
| execution | run `564d4863-d74a-428a-805f-4eb9e8648f91`, general engine, `SUCCEEDED`, 1 applied; postcheck `b232fdf1` `PASS` |
| R1 afterwards | `show running-config diffs` empty (running equals startup, nothing was saved); OSPF and OSPFv3 neighbours Full; route counts unchanged except the two connected /32 and /128 |

Evidence: `docs/evidence/v2-route-shield/gonogo/r1_loopback105/`. Consequence: `BND-PROB-000001` describes a
configuration that is no longer running and cannot be soaked again; the next soak needs a new lifecycle.

### 12.2 Startup-configuration contract, reviewed

| Criterion | Where it holds |
|---|---|
| limited to the route-shield lifecycle | the two command strings exist in the cEOS executor only; `save_startup` is called from `route_shield/lifecycle.py` only. The contract test now scans the whole application (views, commands, services), not only the services |
| no generic Configlet or raw path can write startup | no module of the general engine refers to `save_startup`; the engine refuses a transition Change |
| tests fail on a new user | `test_startup_persistence_is_never_reached_from_the_general_engine` |
| only after the final validation | `final_validation()` calls `persist()` only when `final_checks()` returned nothing |
| nothing temporary before the save | the final checks require every temporary statement and cover absent; `persist()` refuses a device whose running digest is not the one just validated, and checks the saved text for temporary paths |
| read-back mandatory; three digests equal | `persist()`: startup, running and intended digest per device |
| failure after persistence restores startup | `restore_startup()`; sandbox run `fc_abort_persist` |

Other startup writers that existed before this work (credential and MFA rollout) are outside the execution package
and unchanged.

### 12.3 Abort before the next stage

Added after the closure pass. Before every stage and before the final validation the run evaluates the host gate
again and asks the probe source whether every flow kept delivering samples.

- Host: the PROBED gate of section 10.4. It must fail `consecutive_samples` (3, from the CPU policy) samples in a row.
  The abort threshold is the policy's critical level, 90 %: the warning level, 70 %, is below what the probes
  themselves cause. Blocker `WINDOW_CONDITION_LOST`.
- Probes: a flow that delivered fewer than half of the samples its rate calls for since the previous judged reading
  is unreliable timing. Blocker `PROBE_TIMING_UNRELIABLE`. On the loaded sandbox the flows deliver 79 to 90 % of
  nominal.
- Either one stops the run before the next stage and takes the reverse path. Probe rates are unchanged.

Sandbox run `gn_window` on commit `030b842` (rebuilt sandbox, isolated database): the host gate was made to report
an injected critical condition after R2's client statics were removed. The run finished the stage it was in (40
operations applied), took three failed samples, stopped before `SHIELD_REMOVE` with `WINDOW_CONDITION_LOST`, and
compensated 40 of 40. Running and startup digests of the four access devices equal to the start; no cover, shield or
floating static left; 0 of 908,917 probes lost on 14 flows; 7 TCP sessions with every message echoed; 7 HTTP loops
without a failure; 3 client-route replacements on the cores, all under a cover. The guard passed at all nine earlier
stage boundaries with the real probes at host load 24 to 31. Evidence: `docs/evidence/v2-route-shield/gonogo/gn_window/`.

Limits: one run. The injected condition is a reported gate failure, not a host that is really at 90 %. A stalled
probe flow is covered by unit tests, not by a sandbox run.

### 12.4 What follows the merge

The read-only dry run and the precheck are repeated from the deployed code; their result and the 16-item
authorization checklist are in the go/no-go report and the pull request, since a file cannot record the state of a
deployment made from its own commit.

