# V2 Phase 9 (D): IPv6 admission

A device that routes IPv6 with OSPFv3 can now be isolated behind a cEOS trusted upstream, commissioned and admitted to
production. Admission checks the OSPFv3 adjacency, the IPv6 routes learned through the released port and IPv6
reachability. Before this change, isolation refused any upstream port that ran OSPFv3 (`ISOLATION_ROUTING_UNSUPPORTED`).
Admission could check IPv6 routes and IPv6 pings, but had no OSPFv3 adjacency check.

## What changed

| Area | Change | Where |
|---|---|---|
| Isolation read-back | `ipv6 ospf N area A` on the port records the process. An `ipv6 router ospf N` block of that process (same VRF) is suppressible. `passive-interface default` and an explicit `passive-interface <port>` count as already passive. `no passive-interface <port>` under `passive-interface default` is refused, and so is any other OSPFv3 form (for example `router ospfv3`, or a port process with no block). | `isolation/eos.py` `interface_facts`, `routing_facts` |
| Isolation plan | One `ospf6-passive-N` operation: `ipv6 router ospf N` / `passive-interface <port>`, undone with `default passive-interface <port>`. Released after the OSPFv2 passive operation. The OSPFv3 keys appear in the intent only when the port runs OSPFv3, so an IPv4-only policy keeps its earlier intent hash. | `isolation/eos.py` `render_apply`, `RELEASE_ORDER`; `isolation/intent.py` |
| Isolation verification | The routing finding reads `show ipv6 ospf neighbor \| json`. Any OSPFv3 neighbour on the port is a leak (`ISOLATION_LEAK`), and an unreadable table is `ISOLATION_UPSTREAM_UNREADABLE`. cEOS answers `{"vrfs": {}}` when no OSPFv3 process runs, which counts as an empty table. | `isolation/service.py` `routing_findings`; `eos.ospf6_neighbors_on` |
| Admission expectations | New `ospfv3_neighbors` (router IDs) and routing `OSPFV3` (IPv6-only routing). OSPFV3 needs OSPFv3 neighbours and no OSPF ones. Any OSPFv3 neighbour also needs at least one expected IPv6 route. OSPFv3 neighbours may accompany OSPF or RIP (dual stack). | `commissioning/admission.py` `validate_expectations` |
| Admission verification | `ospfv3_adjacency`: each expected router ID must be Full on the released port. The monitoring hand-off lists the check. | `admission.failures`; `commissioning/outbox.py` |
| Commissioning a ZTP-onboarded cEOS | An OSPFv3 or RIPng process carries `ipv6 unicast-routing`, the same way an IPv4 process already carried `ip routing`. | `planning/configlet_factory.py` `_routing_prerequisite` |

## Platform behaviour this relies on (observed live, cEOS 4.36.2F)

`docs/evidence/v2-phase9-closure/ipv6-admission/platform-probe/` holds a disposable probe between the fixture upstream and a
ZTP-onboarded cEOS, set up with the fixture's out-of-band console (fixture only, not NMAS execution):

- `a-*`: the onboarded device boots with IPv6 routing off. `ipv6 router ospf 1` is accepted with the warning
  `IPv6 routing not enabled in VRF default`, and no OSPFv3 adjacency forms within 90 s.
- `b-*`: after `ipv6 unicast-routing` on the device only, the adjacency is Full within seconds. `b-up-nbr.json` is the
  `ospf3NeighborEntries` shape that `ospf6_neighbors_on` parses (`routerId`, `adjacencyState: "full"`, `interfaceName`).
- `c-*`: both loopbacks are learned as `O3` through Ethernet1, and the loopback-to-loopback ping succeeds.
  `eos.routes_via` / `eos.ospf6_neighbors_on` on these live outputs return the device loopback and the Full neighbour.
- OSPFv3 formed Full through the upstream's isolation ACLs (`deny ipv6 any any` on the port). cEOS port ACLs do not filter
  routing control traffic, which is why isolation suppresses OSPFv3 with `passive-interface`, exactly as for OSPFv2.

## Live proof

Harness `core.tests.live_ipv6_admission_fixture` (the Phases 5 + 6 harness with NEW1's intent and admission expectations made
dual-stack) on `labs/isolation-commissioning-isolated` started with `NMAS_ISO_FX_OSPF6=on`. UP1 and CORE run OSPFv3 next to
OSPFv2, and UP1 runs it on bootstrap port A. Every NMAS write is the governed isolation transaction or the generic execution
engine through CeosExecutor over SSH (pinned host key, key-only service account); the fixture console only observes. Evidence is
in `docs/evidence/v2-phase9-closure/ipv6-admission/live/`:

| File | What it shows |
|---|---|
| `10-isolation-before-device.json` | The isolation plan for the port includes `ospf6-passive-1` (`ipv6 router ospf 1` / `passive-interface Ethernet1`). It is applied, read back and verified against the hostile probe before any device exists. |
| `20-ztp.json`, `30-onboard.json` | Native ZTP and onboarding of the factory-default NEW1 behind the enforced policy, as in Phases 5 + 6. |
| `v6-40-commission-ipv6-configlets.json` | NEW1's Device Builder intent renders the IPv6 addresses and the OSPFv3 process, and `ipv6 unicast-routing` is the first line of the OSPFv3 process configlet. |
| `v6-45-isolated-ospfv3-suppressed.json` | NEW1 runs OSPFv3 on its uplink with IPv6 routing on. UP1 has no OSPFv3 neighbour on Ethernet1 and no route to NEW1's IPv6 loopback, and isolation re-verifies (routing finding with the OSPFv3 table, traffic matrix). |
| `50-admission-injected-failure.json`, `v6-50-restored-ospfv3-passive.json` | A dual-stack admission that also expects `2001:db8:254:250::/64`, which NEW1 never advertises. The only failure is `routes_v6: 2001:db8:254:250::/64 not learned through Ethernet1`: the OSPF and OSPFv3 adjacencies, the real IPv6 route and IPv4/IPv6 reachability all held. Every removed statement is restored byte for byte (`upstream_restored_byte_identical`), the OSPFv3 passive interface is back, the adjacency is gone, and isolation re-verifies. |
| `60-admission.json`, `v6-60-admitted-ipv6-reachability.json` | The dual-stack admission is `ADMITTED`; NEW1 is `IN_SERVICE`. UP1 has NEW1 (10.254.255.11) Full over OSPFv3 on Ethernet1. CORE learns `2001:db8:254:255::11/128` as `O3` through UP1, and the production host reaches NEW1's IPv6 loopback and uplink. |

## Tests

`core.tests.test_ipv6_admission`, positive and negative for each function:
- render and release of the OSPFv3 passive operation;
- the already-passive and refused forms;
- the neighbour parser on the cEOS shape, including the not-running and unreadable answers;
- expectation validation;
- admission failures (absent, unfinished, unreadable adjacency; missing IPv6 route; unreachable IPv6 address);
- the isolation routing finding;
- end to end, for IPv6-only and dual-stack upstreams: isolate, admit (the upstream returns byte for byte to its prior
  configuration), and a failed verification that restores the passive interface.

`core.tests.test_tg_configlet_factory_units` covers the IPv6 routing prerequisite.

## Limits

- Only the cEOS OSPFv3 form NMAS renders (`ipv6 router ospf N` plus interface `ipv6 ospf N area A`) is suppressible. The
  address-family form `router ospfv3` is still refused, because no verified passive procedure for it exists here.
- RIPng and IS-IS on the port are still refused by isolation. RIPng admission is route-based (`routes_v6`).
- On an Ubuntu/FRR upstream (V2 Phase 9 FRR isolation), an `ospfv3_neighbors` expectation is read from ospf6d in the FRR snapshot. That path is unit-tested (`test_frr_isolation`) but was not part of this live run, which used a cEOS upstream.
- The OSPFv3 passive-interface suppression is cEOS-only. FRR isolation filters with nftables and is unchanged here.
