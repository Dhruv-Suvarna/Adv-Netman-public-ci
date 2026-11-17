# VM-local veth worker networking — discovery, design and evidence

Date: 2026-11-15 (UTC)

## Decision

**VM_LOCAL_NETWORKING_IMPLEMENTED_AND_TESTED — LIVE_APPROVAL_PENDING**

The requirement for additional externally allocated worker source addresses is
eliminated. Nothing was activated on VM1. This is not Gate B approval, not
institutional authorization and not live containment proof.

## Network architecture discovered (read-only)

| Item | Observation on VM1 | Consequence |
|---|---|---|
| `ens33` | `10.224.77.0/22`, DHCP, IPv4 default via `10.224.76.1`; no global IPv6 | Only public path; IPv4 only |
| `nmas-mgmt` | Host end of a veth into `mgmt_swt:eth9`; `192.168.200.100/24`, `2001:db8:200::100/64` plus RA-derived addresses; static routes to lab loopbacks | Not a bridge, so a worker veth cannot be bridged onto it; a routed attachment is required |
| IPv6 default route | Learned by RA from four lab routers on `nmas-mgmt` | A route exists but leads into the lab, not to the internet. Research IPv6 must stay disabled |
| Containerlab bridge | Docker network `clab`, `br-2c83d7955d69`, `172.20.20.0/24`, `3fff:172:20:20::/64`, 15 `clab-srlceos01-*` containers | Not used and not touched |
| Host forwarding | `net.ipv4.ip_forward=1`, `net.ipv6.conf.all.forwarding=1` (already on for Docker) | No sysctl change needed; controller refuses rather than enabling |
| `ip filter FORWARD` | iptables-nft, policy accept, Docker chains match only Docker bridges | Owned-veth IPv4 forwarding is not blocked by a foreign table |
| `ip6 filter FORWARD` | iptables-nft, **policy drop** | Forwarded IPv6 from a worker veth is dropped by Docker's chain; needs its owner's explicit admission or diagnostic IPv6 stays disabled |
| NAT | Docker/libvirt masquerade rules match only their own source subnets; `nmas_demo_mgmt` is output-hook, uid-scoped | No interaction with an owned, veth-scoped NAT rule |
| Other tables | `inet aiorch_fixtures` scoped to `aiofx*` | No interaction |
| Namespaces | 21 Containerlab/validation namespaces; none named `nmas-ts-*` | No name collision |
| Resolvers | `ens33` learns three campus resolvers by DHCP | Not copied into any template; resolver choice remains an approval input |
| Previous attachment | `ipvlan` L2 child of a parent interface with a new unique source address, gateway, return route and upstream ACL per namespace | Source of the external-address requirement |

No ESXi, vCenter, other VM or campus system was contacted. No scan was run.

## Connectivity implementation selected

One owned veth pair per worker, routed (never bridged), with an owned host nft
table per worker. Full description: `../namespace-activation.md`.

- Diagnostic: point-to-point link, one host route per approved target and no
  default route; host table admits only `ip . tcp port` tuples out of the
  management interface and source-NATs to the existing NMAS management address.
  No new address appears on the frozen management LAN.
- Research: point-to-point link, default route to the host end; host table
  admits approved resolvers, then drops private/special/operator-protected
  destinations, then admits public TCP/443 out of the external interface only,
  masqueraded behind VM1's existing address. IPv6 disabled.

Alternatives rejected: an `ipvlan` child of `nmas-mgmt` (adds an address to the
frozen management LAN and shares an RA-enabled segment); bridging (`nmas-mgmt`
is not a bridge, and bridging to Docker/Containerlab would create the forbidden
routing bridge); editing Docker's `ip6 filter` chain from the controller.

## Files changed

| File | Change |
|---|---|
| `deploy/sandbox/namespace_activation.py` | veth lifecycle, generated host table, exact-target routes, schema `/2` |
| `deploy/sandbox/diagnostic-namespace.env.in`, `research-namespace.env.in` | VM-local keys; external source/gateway/return-route/ACL keys removed |
| `deploy/sandbox/render_policy.py` | emits `diagnostic-targets.env` |
| `deploy/sandbox/test_namespace_activation.py` | rewritten disposable integration test |
| `web/core/tests/test_troubleshooting_sandbox_artifacts.py` | static checks for the veth design and host policy |
| `docs/troubleshooting/namespace-activation.md` and the validation documents that requested external addresses | updated |

Unchanged: nft namespace templates, systemd units, worker, broker, IPC,
credential and authorization code, migrations.

## Tests

`python3 deploy/sandbox/test_namespace_activation.py` — PASS, 18 groups. All
objects, including the VM1 stand-in, live in `nmas-test-*` namespaces with
synthetic addresses.

| # | Required test | Result |
|---|---|---|
| 1 | Diagnostic reaches approved simulated device, IPv4 and IPv6, seen from the existing management source | PASS |
| 2 | Diagnostic cannot reach the adjacent endpoint or an unapproved port | PASS |
| 3 | Diagnostic cannot reach simulated vCenter, student VM, internet or host services | PASS |
| 4 | Research reaches approved simulated public HTTPS and resolver, seen behind the host's existing address | PASS |
| 5 | Research cannot reach private, campus, Containerlab, host, non-HTTPS or operator-protected destinations | PASS |
| 6 | IPv4-mapped IPv6 denied at packet level; DNS rebinding, redirect and proxy denied by the broker (`test_troubleshooting_research`) | PASS |
| 7 | IPv4/IPv6 containment, including the lab-only IPv6 default route | PASS |
| 8 | Each namespace rolled back with the other byte-identical and still valid | PASS |
| 9 | Failure injected after every one of 19 diagnostic and 18 research steps cleans only owned resources | PASS |
| 10 | Repeated activation, deactivation, rollback and three full cycles | PASS |
| 11 | Simulated host restored exactly; real host addresses, links, routes, rules, firewall, forwarding, SSH configuration and namespaces identical before and after | PASS |
| 12 | Worker IPC, target authorization, credential handling (focused Django suites) | PASS |
| 13 | NMAS services and 15 Containerlab containers operational before and after | PASS |

Additional: return routes exist on both simulated neighbours, so every denial is
attributable to filtering; a namespace with its own policy flushed and a default
route added is still contained by the host table and reported as drift;
pre-existing unowned veth/table names are refused and left in place; a changed
ownership marker and a different activation ID both block rollback.

Defect found and fixed by the test: a namespace move resets IPv6 address
generation, which gave the host end an unintended link-local address.

## Package identity

New immutable compatibility package (this document is outside the payload):

- Path: `/home/student/Scripts/nmas-vm-local-veth-release-20261115T212420Z/package`
- Entries identity: `838514a6d92dc359a12558f5c4237f22305653fe731e01a2dd4246e96c7190c4`
- Manifest SHA-256: `0d339ae850567cf81cbaabe57135fe06f3252f2709c14e9e6ef4af766f91a944`
- Tool SHA-256: `46db050bd863183498203b796a21bb563026b97a829d1cdbe4678f0e5dd99a0e` (unchanged)
- 210 operations (201 ADD, 8 REPLACE, 1 MERGE), `problems: []`. Eight entries
  differ from the frozen package; no path added or removed; every production
  precondition hash is identical.

Checks: 210/210 payload hashes; preconditions 210/210 against unchanged
production (`129d3f0`); staged copy 210/210 postconditions; disposable apply
210/210, rollback (201 removed, 9 restored) and 210/210 preconditions again;
namespace test and focused Django suites pass from the staged copy. The frozen
package `5dab9de7…` (`47c98c1a…`) still verifies against its `SHA256SUMS`.

This package needs a focused review before it can replace the frozen one.

## Limits of this evidence

- Simulated, not live. Docker's real chains, `rp_filter`, conntrack state and
  campus-side filtering were inspected but not exercised.
- The foreign-chain check detects default-drop forward *policies*. It cannot
  detect an explicit drop rule in someone else's chain; that would fail closed
  (no connectivity), not open.
- `EXTRA_DENY_CIDRS` is only as complete as the list supplied. Without it,
  research can reach any public TCP/443 address, including institutional
  public-range hosts; the broker's hostname allowlist is the remaining control.
- Diagnostic source NAT means devices cannot distinguish worker sessions from
  other NMAS sessions by address. Attribution relies on NMAS audit records.
- While active, VM1 carries one extra interface, address and connected route
  per enabled family per worker. Existing entries are not altered.
