# University containment and authorization boundary

## What VM1 can establish

VM1 can establish facts about its own interfaces, routes, listeners, firewall rules, containers, namespaces, service identities, local inventory, NMAS lifecycle/identity records and exact Containerlab definitions. It can technically determine that certain destinations are routable.

It cannot establish ownership or authorization merely from:

- sudo/root access on VM1;
- a route, default gateway or directly connected subnet;
- RFC1918/ULA/global address class;
- ARP/ND/LLDP/DNS results;
- successful TCP/SSH/HTTPS response;
- shared vSphere placement;
- visibility in Docker/Containerlab tooling;
- a device discovered by monitoring or an AI model.

This work did not scan, ping-sweep, authenticate to, fingerprint or configure any neighboring/private/university address to infer boundaries.

## Locally authorized scope

The only eligible management target is a device that simultaneously has:

1. an exact tracked topology ID (`srlceos01` in the inspected inventory);
2. an authoritative NMAS inventory record and writable resolver scope;
3. a live ManagedDevice row;
4. verified identity;
5. in-service lifecycle and admitted production participation;
6. a current approved ManagementPath whose exact endpoint is also authoritative for that device;
7. a permitted fixed read-only operation and transport;
8. an authorized principal and unexpired, non-revoked authorization;
9. no protected-host or explicit exclusion match.

R5 is excluded even though it exists in the topology. R2 and R4 remain unverified and ineligible. R6/R7/R8/S5 have verified/admitted rows, but the inspected production database has no approved ManagementPath rows, so the new exact-target policy currently authorizes none of them for live diagnostics.

VM1's `ens33` management address, `nmas-mgmt` host addresses, other students' VMs/containers, ESXi/vCenter, university routers/switches/firewalls/DNS/DHCP/identity systems and unregistered discovered devices are not eligible targets.

Ordinary approved client use of university DNS/DHCP/default gateway is a dependency, not device-management authorization.

## Required university/infrastructure confirmations

An authorized university/infrastructure representative must confirm, in an attributable change record:

- VM1's assigned management subnet/address and whether any other address on that segment belongs to this project;
- the exact vSphere/ESXi/vCenter and infrastructure address ranges that must be protected, without requiring NMAS to probe them;
- whether the lab VLAN-200 IPv4/IPv6 prefixes are wholly local to this VM/topology or overlap/shared/bridged elsewhere;
- approved recursive DNS resolver addresses for the isolated research namespace;
- whether public TCP/443 from a dedicated namespace is permitted and whether an institutional proxy is mandatory;
- cgroup-BPF/systemd `IPAddressAllow` and network-namespace/nft policy support on the university VM;
- an approved management-connectivity recovery/out-of-band procedure for any host-level activation window;
- whether security monitoring requires additional egress/audit forwarding and retention.

No signature, approval or ownership statement was fabricated. Existing Gate B cannot be considered cleared while the university containment audit remains NO-GO/BLOCKED_EXTERNAL.

## Fail-closed response to unknown scope

- Do not add an address based on discovery or reachability.
- Do not create/approve a ManagementPath until identity, topology and ownership evidence is complete.
- Do not enable direct Python transport factories.
- Do not activate device worker cgroup allows beyond exact reviewed endpoints.
- Do not activate research hostnames before resolver/namespace approval.
- If an endpoint changes, expire the grant and regenerate/review the policy; do not follow DNS, redirects or alternate routes for device management.

## Current proof limit

Application policy and staged isolation artifacts demonstrate denial logic in local fixtures. They do not prove that the inactive production runtime is kernel-contained. Current root/Docker-capable components could bypass application policy if reused. Separate unprivileged identities and live kernel enforcement are therefore required before a production GO recommendation.

## Updated external prerequisites

VM1 now proves the required kernel mechanisms exist and rendered dual-stack rules work in disposable namespaces. It still cannot prove ownership of any address outside explicit project inventory. University/operator approval must allocate two non-host source addresses (diagnostic and research), approve their parent interfaces/gateways, approve exact recursive resolvers and confirm whether public 443 or an institutional proxy is required. A proxy requirement needs a separately reviewed pinned-proxy design; proxy environment variables are intentionally ignored.

The diagnostic namespace source/interface must be registered as an NMAS attachment and every target path must pass existing approval, topology, health, pin and credential checks. No path can be inferred from routing. The root gateway and Docker-capable web/orchestrator remain bypass-capable host components, but the staged Troubleshooter receives no grant to them. Institutional approval and live activation evidence remain separate from code completion and package review.
