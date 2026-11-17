# NMAS V2 infrastructure-owner authorization request

Prepared: 2026-11-14 (America/Denver); revised 2026-11-15 for VM-local veth
networking (`vm-local-veth-networking.md`). The earlier request for additional
namespace source addresses, parent attachments, gateways, return routes and
upstream ACLs is **withdrawn**: no address outside VM1 is needed.

Status: **REQUEST DRAFT — NO AUTHORIZATION GRANTED**

## Request and scope

NMAS requests the minimum information and permissions needed to prepare a
controlled production change on VM1. This request does not authorize a
deployment, service start, migration, namespace, firewall change, device
connection, research request, or remediation.

The proposed change is limited to:

- VM1, the existing NMAS application, and the already deployed Containerlab
  topology `srlceos01`;
- two dedicated, unprivileged worker identities and two isolated VM-local
  network namespaces, one for read-only diagnostics and one for public-document
  research;
- exact, individually governed Containerlab device management paths; and
- exact public HTTPS research destinations approved by hostname.

NMAS does **not** request unrestricted university-network access, permission to
scan or discover infrastructure, access to other students' VMs, or access to
ESXi, vCenter, vSphere management, university routers, switches, firewalls,
identity systems, metadata endpoints, or unregistered devices.

## Environment presented for review

- VM1 observed management interfaces are `ens33` and `nmas-mgmt`. Neither is
  modified. Worker traffic would leave through them only after VM-local source
  NAT behind the address VM1 already holds; observation of an interface is not
  evidence of ownership or authorization to do so.
- Project inventory identifies `nmas-mgmt` as the host attachment to the frozen
  Containerlab topology. No topology, Docker network, link, addressing, VLAN,
  route, or device configuration change is proposed.
- The diagnostic namespace is intended to reach only the exact IP and TCP port
  in each separately approved, current NMAS `ManagementPath`.
- The research namespace is intended to reach approved recursive DNS resolvers
  and public TCP/443 destinations, with application-layer exact-hostname,
  DNS-revalidation, redirect, TLS, media-type, size, and method restrictions.
- Existing VM1 SSH, NMAS services/timers, monitoring, Docker networks, and all
  15 Containerlab containers must remain unchanged.

## Information and decisions requested

Please provide an attributable change record containing each applicable answer.
An observed route, address, DNS response, or VM1 sudo capability will not be
treated as approval.

### VM1 and namespace connectivity

1. Confirm the authoritative VM1 management interfaces and the SSH endpoint
   that must remain reachable. No address, prefix, gateway or route on them is
   changed.
2. State whether two dedicated network namespaces, each attached by one veth
   pair that exists only inside VM1, are permitted. No additional address is
   requested on any network outside VM1.
3. State whether VM1 may forward and source-NAT traffic from the research
   namespace behind its existing assigned address for public TCP/443 and the
   approved resolvers only. This is a policy decision; the traffic is
   technically indistinguishable from VM1's own HTTPS.
4. Confirm that source-NATing diagnostic traffic to the existing NMAS
   management address towards the project-local Containerlab management LAN
   needs no approval beyond the project owner's, or name the approver.
5. Withdrawn (previously: `ipvlan` attachment and additional source
   addresses).

### Protected destinations and DNS

6. Provide the authoritative destination prefixes and exact assets that both
   namespaces must deny, including other students' networks, university
   infrastructure, ESXi/vCenter/vSphere management, metadata services, shared
   services, and any lab prefixes that are shared or bridged outside VM1.
7. Confirm whether the project inventory's lab VLAN-200 IPv4/IPv6 prefixes are
   wholly local to this VM/topology or overlap university/shared networks.
8. Identify the exact recursive DNS resolver IP addresses permitted from the
   research namespace, allowed transport (`UDP/53`, `TCP/53`, or both), return
   routing, ownership, and any logging/retention requirement.
9. State whether an institutional proxy is mandatory. The current broker
   intentionally ignores proxy environment variables; a required proxy needs a
   separately designed and reviewed pinned-proxy path.

### Research egress

10. State whether public HTTPS egress on TCP/443 is permitted from the dedicated
    research namespace.
11. Approve or reject each exact public research hostname supplied later by the
    project owner, together with privacy/data-handling constraints. Approval of
    public HTTPS does not permit private, reserved, metadata, IP-literal,
    arbitrary-port, upload, executable, or credential-bearing traffic.

### Host containment and recovery

12. Authorize or reject the VM-local creation of dedicated no-login users,
    root-owned environment/unit files, systemd hardening, cgroup-BPF
    `IPAddressDeny`/`IPAddressAllow`, named network namespaces, one owned veth
    pair and one owned, veth-scoped host nftables table (forward filter and
    source NAT) per namespace, namespace-local nftables tables, and
    namespace-specific resolver files. Host forwarding sysctls, existing
    addresses, routes and firewall tables are not changed.
13. Confirm that no vSphere, ESXi, vCenter, VM hardware, virtual-switch, or
    datastore change is required. If an infrastructure-side change is required,
    it must be a separately owned change and is outside this NMAS procedure.
14. Provide an approved maintenance window, named infrastructure operator and
    reviewer, required two-person control, expected user impact, and monitoring
    or audit-forwarding requirements.
15. Confirm working vSphere-console or equivalent out-of-band recovery access,
    the responsible operator, and the escalation path if VM1 SSH or management
    connectivity changes.

## Independently authorized stages

Record `APPROVED`, `DENIED`, or `NOT APPLICABLE` for each stage. Approval of one
stage does not approve any other stage.

| Stage | Requested decision | Current state |
|---|---|---|
| A. Application and migrations | Install the reviewed 210-operation application overlay and migrate only through `core.0039` in a separate application window | Not requested by this draft; production deployment remains blocked |
| B. Inactive worker artifacts | Create dedicated identities/directories and install reviewed units and secret references without enabling or starting them | Separate host-owner approval required |
| C. Host/namespace restrictions | Activate separately approved diagnostic and research namespace/veth/cgroup/nft controls | Host-networking and NAT approval required; no external address allocation required |
| D. Public research | Enable only the exact approved resolver and hostname set over public HTTPS | Infrastructure and project privacy approval required |
| E. Device diagnostics | Enable read-only diagnostics for each individually approved Containerlab `ManagementPath` | Per-device/path approval required; current production count is zero |
| F. Governed remediation | Permit proposals to enter the existing NMAS Change Engine; no Troubleshooter direct-write authority | Separate existing Change Engine approval remains required |

## Requested response artifacts

The response should include the attributable change/ticket identifier, named
approver and role, decision date, expiry/review date, exact approved values,
explicit exclusions, maintenance/recovery requirements, and the stage letters
authorized. NMAS will not create, sign, or infer this authorization.

