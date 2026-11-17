# Independent diagnostic and research namespace activation (VM-local veth)

## Scope and authorization boundary

`deploy/sandbox/namespace-activate.sh` is the only supported namespace lifecycle
entry point. It operates on exactly one of `diagnostic` or `research` per
invocation. It does not discover networks, gateways, resolvers or interfaces and
does not treat current host reachability as authorization.

The frozen 205- and 210-operation packages remain immutable. The 210-operation
package attached each namespace with an `ipvlan` child of an existing interface
and therefore needed an additional, externally allocated source address,
gateway, return route and upstream ACL per namespace. That attachment is
retired. Each namespace is now attached by one owned veth pair that exists only
inside VM1, so **no address outside VM1 is requested or used**.

This mechanism does not provide or imply institutional authorization. Creating
namespaces, a veth, forwarding and NAT rules on VM1 is still a host-networking
change that needs an attributable approval (see "Approvals that remain").

## Architecture

```text
 nmas-ts-diagnostic netns                    VM1 host netns                    Containerlab
 nmas-ts-diag0  <-- veth, /30 + /126 -->  nmas-ts-diagh0
   routes: one host route per approved      table inet nmas_host_diagnostic     mgmt_swt:eth9
   target, no default route                 forward: exact IP . TCP port  -->  nmas-mgmt (unchanged)
   table inet nmas_diagnostic (drop)        snat to the existing NMAS
                                            management address

 nmas-ts-research netns                      VM1 host netns                    campus / internet
 nmas-ts-res0   <-- veth, /30 ----------->  nmas-ts-resh0
   default route to the host end            table inet nmas_host_research
   table inet nmas_research (drop)          forward: exact resolver and   -->  ens33 (unchanged)
   IPv6 disabled unless separately          reviewed address:443 tuples
   is confirmed                             masquerade behind VM1's address
```

Properties enforced by the controller, not by convention:

- The veth is never enslaved to a bridge and never attached to Docker, the
  Containerlab bridge or `mgmt_swt`. `nmas-mgmt` is itself one end of a veth
  into `mgmt_swt`, not a bridge, so the diagnostic path is routed, not bridged.
- Link prefixes must be point-to-point (`/30`, `/31`, `/126`, `/127`) and
  VM-local (IPv4 link-local or private, IPv6 ULA). Preflight refuses a prefix
  that overlaps any address or route already on the host.
- Diagnostic devices see the existing NMAS management address (`IPV*_NAT`), so
  no new address appears on the frozen management LAN. `masquerade` is refused
  for diagnostics; the address must already be on `EGRESS_INTERFACE`.
- The diagnostic namespace has **no default route**: only one host route per
  approved target. The research namespace has a default route but can leave
  only through its own `EGRESS_INTERFACE`.
- Containment is enforced twice. The namespace table (reviewed file, exact
  SHA-256) is default-drop. The host table (generated from the approved config,
  digest journaled) drops everything entering or leaving the owned veth except
  the approved flows, including traffic to VM1's own addresses and services. A
  namespace that lost its own policy is still contained by the host table.
- The two namespaces cannot reach each other: each host table drops any packet
  on its veth whose other interface is not that namespace's egress interface.
- The controller never changes host forwarding sysctls, existing addresses,
  routes, rules, or any table it did not create. It adds exactly: one veth, one
  point-to-point address per enabled family on that veth (with its connected
  route), and one nft table. Preflight refuses if forwarding for an enabled
  family is not already on.
- A default-drop forward chain owned by someone else (Docker installs one for
  IPv6 on VM1) is never bypassed. Preflight refuses the affected family unless
  `IPV*_FOREIGN_FORWARD_APPROVAL_ID` records that the chain's owner admitted
  this exact path. The controller does not edit that chain.

## Configuration

Render one of `diagnostic-namespace.env.in` / `research-namespace.env.in` only
from the attributable change record. The file must be root-owned, a regular
non-symlink file and not group/world writable.

| Key | Meaning |
|---|---|
| `EGRESS_INTERFACE` | Existing interface traffic may leave by. Read, never modified. |
| `HOST_NETWORKING_APPROVAL_ID` | Approval for the veth, forwarding and NAT on VM1. |
| `FIREWALL_POLICY_APPROVAL_ID` | Approval for the namespace and host nft policies. |
| `NFT_POLICY`, `NFT_POLICY_SHA256` | Reviewed namespace policy and its exact digest. |
| `IPV4_MODE`, `IPV6_MODE` | Each explicitly `enabled` or `disabled`; a disabled family refuses stray values. |
| `IPV*_LINK_CIDR`, `IPV*_GATEWAY` | Namespace end and host end of the VM-local link. |
| `IPV*_NAT`, `IPV*_NAT_APPROVAL_ID` | Exact existing source address, or `masquerade` (research only). |
| `IPV*_FOREIGN_FORWARD_APPROVAL_ID` | Required only when a foreign default-drop forward chain governs the family. |
| `TARGETS` (diagnostic) | Exact `tcp:ADDR:PORT` / `tcp:[ADDR]:PORT` ManagementPath tuples. `render_policy.py` emits this line as `diagnostic-targets.env`; it must equal the sets in `diagnostic-egress.nft`, which `validate` checks. |
| `DNS_*` (research) | Literal resolver addresses, `udp,tcp`. Diagnostic DNS must be `disabled`. |
| `HTTPS_TARGETS` (research) | Exact `tcp:ADDR:443` tuples. They must equal the reviewed nft sets; no arbitrary-public fallback exists. |
| `RESEARCH_EGRESS_APPROVAL_ID` | Approval for public HTTPS research. |
| `EXTRA_DENY_CIDRS` (research) | Protected networks beyond the built-in private/special set, for example the institution's public ranges. |

`host-policy` prints the exact host table an activation would load, for review
before the window; it changes nothing:

```text
sudo deploy/sandbox/namespace-activate.sh host-policy research /etc/nmas/research-namespace.env
```

## Independent lifecycle

```text
sudo deploy/sandbox/namespace-activate.sh preflight diagnostic /etc/nmas/diagnostic-namespace.env
sudo deploy/sandbox/namespace-activate.sh activate  diagnostic /etc/nmas/diagnostic-namespace.env
sudo deploy/sandbox/namespace-activate.sh validate  diagnostic /etc/nmas/diagnostic-namespace.env

sudo deploy/sandbox/namespace-activate.sh preflight research /etc/nmas/research-namespace.env
sudo deploy/sandbox/namespace-activate.sh activate  research /etc/nmas/research-namespace.env
sudo deploy/sandbox/namespace-activate.sh validate  research /etc/nmas/research-namespace.env
```

`preflight` performs no filesystem or network mutation. It refuses missing or
inconsistent approvals and values, an absent egress interface, a NAT source that
is not on the egress interface, a link prefix that collides with the host,
disabled host forwarding, an unacknowledged foreign forward-drop chain, a policy
digest or syntax failure, and any namespace, veth or host table that already
exists without matching ownership state. It reports the host policy digest.

`activate` is idempotent for the same activation identity and config digest. It
journals each pending/completed step under
`/var/lib/nmas-ts-namespaces/<kind>.json`. Both nft policies are loaded before
any link exists. The veth pair is created and marked inside the owned namespace
and the host end enters the host namespace already carrying the ownership alias;
the host table is created atomically with its ownership comment. Any failed step
or handled interruption runs ownership-scoped cleanup; a repeated invocation
first reconciles an owned incomplete activation.

`validate` is read-only. It checks the ownership markers, veth types, that the
host end is not bridged, exact addresses on both ends, the exact route set, the
namespace sysctls, both nft tables, the exact diagnostic target sets on both
sides, exact research resolver and HTTPS sets on both sides, host forwarding
and the resolver file. Failure is a stop condition; it
never repairs or adopts drift.

To remove one namespace, stop and confirm exit of only its worker, then:

```text
sudo deploy/sandbox/namespace-activate.sh rollback   research   /etc/nmas/research-namespace.env
sudo deploy/sandbox/namespace-activate.sh deactivate diagnostic /etc/nmas/diagnostic-namespace.env
```

Both actions are idempotent, retain a state receipt, require the same activation
ID and config digest, and remove only that activation's veth, namespace, host
table and resolver file, each on an exact marker match. They refuse an unowned
or re-marked resource and never read or mutate the other namespace's state.

## Approvals that remain

Removed by this design: additional source addresses, parent interface/VLAN
attachment, per-namespace gateways, return routes and upstream ACLs on any
network outside VM1.

Still required before any live activation, and not inferable from the fact that
the mechanism works:

1. Host-networking approval for named namespaces, an owned veth, forwarding and
   NAT rules and owned nft tables on VM1 (`HOST_NETWORKING_APPROVAL_ID`,
   `FIREWALL_POLICY_APPROVAL_ID`).
2. Institutional decision on whether a university-assigned VM may source-NAT a
   worker namespace behind its assigned address for public HTTPS, plus resolver
   choice and any proxy requirement (`RESEARCH_EGRESS_APPROVAL_ID`,
   `IPV4_NAT_APPROVAL_ID`). Technically the traffic is indistinguishable from
   VM1's own HTTPS; that is not permission.
3. Any institution-specific public ranges that policy additionally requires in
   `EXTRA_DENY_CIDRS`. NMAS does not guess them. Their absence cannot broaden
   access because research egress is an exact destination-tuple allowlist; all
   other addresses already fail closed.
4. Per-device ManagementPath approval for every `TARGETS` tuple.
5. For diagnostic IPv6 on VM1 as currently configured: the Docker-managed
   `ip6 filter FORWARD` chain has policy drop, so forwarded IPv6 from the
   diagnostic veth is dropped there. Either leave diagnostic IPv6 disabled, or
   have that chain's owner admit the exact path and record
   `IPV6_FOREIGN_FORWARD_APPROVAL_ID`. This controller will not edit it.
6. Research IPv6 stays disabled on VM1 as currently configured: `ens33` has no
   global IPv6 address and the only IPv6 default route is learned from lab
   routers on `nmas-mgmt`. That route is not a public path.
7. Maintenance window, named operator/reviewer and console/OOB recovery.

## Recovery rules

If cleanup reports `activation-failed-cleanup-required`, or a marker or resolver
mismatch, do not perform broad deletion. Keep the other namespace running only
if its own validation and the host baseline still pass, preserve state and
evidence, and escalate through the OOB procedure. Never flush host nftables,
change a default route or forwarding sysctl, restart Docker, or
destroy/redeploy Containerlab.

## Disposable validation

```text
python3 deploy/sandbox/test_namespace_activation.py
```

The test builds a stand-in for VM1, a simulated management LAN and a simulated
campus/internet side entirely inside `nmas-test-*` namespaces with synthetic
addresses, and verifies before and after that the real host's addresses, links,
routes, rules, firewall, forwarding, SSH configuration and namespaces are
unchanged. Test-only flags are not production inputs. Evidence:
`validation/vm-local-veth-networking.md`.
