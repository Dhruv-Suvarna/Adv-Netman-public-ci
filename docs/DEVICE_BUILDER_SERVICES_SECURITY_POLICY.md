# Device Builder Services, Security, and Policy (Phase 12)

Phase 12 completes the major Device Builder catalogue before project-aware
validation. It extends the existing versioned structured-intent architecture;
it does not add a database model, migration, deployment path, NetBox write,
Configlet execution, Git operation, or device-access path.

> **Phase 20.5 continuation:** This document preserves the Phase-12 baseline.
> The current registry additionally has fixture-tested IPv4/IPv6 ACLs for SR
> Linux, IOS XR, and SONiC, plus DHCPv4/v6 relay for SR Linux and IOS XR. See
> `PHASE_20_5_PLATFORM_CAPABILITY_AUDIT.md`; none of these additions is live
> tested or runtime-enabled for deployment.

## 1. Architecture and ownership

The browser owns temporary typing state. Django owns Change, revision, and
accepted/draft workflow state. Python owns feature interpretation, Tier-1
validation, capabilities, and candidate rendering. NetBox remains passive
inventory/IPAM storage and is never queried or written by these Phase-12
editor, commit, or render paths.

`service_policy_intent_service.py` owns all Phase-12 collection mutation.
`field_registry.py` resolves strict owned paths. `field_commit_service.py`
preserves the one-field accept/rollback boundary. `candidate_renderer.py`
remains the single authoritative renderer and dispatches through
`platform_drivers.py`.

## 2. Namespace model

Phase-12 intent lives beside `interfaces` and `routing` in the same
`DeviceIntentRevision.sections` document:

```text
fhrp.instances.{fhrp_*}.virtual_ips.{vip_*}
nat.pools.{pool_*}
nat.rules.{nat_*}
services.dhcp.relays/clients.{dhcp_*}
services.dns.resolvers/search_domains.{dns_*}
services.monitoring
security.acls.{acl_*}.entries.{ace_*}
security.attachments.{attach_*}
policy.pbr.policies.{pbr_*}.sequences.{pbrseq_*}
policy.pbr.attachments.{attach_*}
```

Missing service namespaces are interpreted as `INHERIT`; opening the editor
does not materialize an override or rewrite a revision.

## 3. Stable identities and ordering

Every repeatable object has an opaque 16-hex stable ID with the prefix shown
above and an explicit sequence. Identity is independent of display order.
Rendering sorts by `(sequence, id)`. Removing one object does not renumber or
mutate siblings. Field paths always address owned IDs, never list indexes.

Lab-scale bounds are 32 FHRP instances, 16 VIPs per instance, 32 NAT pools,
128 NAT rules, 32 relays, 32 clients, 8 resolvers, 12 search domains, 32 ACLs,
128 ACEs per ACL, 64 ACL attachments, 16 PBR policies, 64 PBR sequences, and
32 PBR attachments.

## 4. Capability extension and evidence

`SERVICE_POLICY_CAPABILITIES` is independent of the existing interface and
routing matrices and uses the same exact statuses: `SUPPORTED`,
`NOT_IMPLEMENTED`, `UNSUPPORTED`, and `UNKNOWN`. Only `SUPPORTED` combinations
can create new intent. Platform changes preserve all existing objects and the
renderer emits an explicit incompatible-object comment when necessary.

Evidence is repository-local:

- cEOS: S1/S2 templates and logs prove Arista `ip virtual-router` (VARP-style)
  IPv4/IPv6 gateways and DHCPv4/DHCPv6 relay syntax. The monitoring ACL and
  historical backup lab ACL prove named IPv4 ACL syntax.
- Ubuntu/FRR: R3/R4 templates prove nftables stateful IPv4 source masquerade
  (`EDGE_PAT`) behavior.
- SR Linux, IOS XR, and SONiC have no approved live baseline. Phase 20.5 adds
  fixture-tested IPv4/IPv6 ACL rendering for all three and DHCPv4/v6 relay
  rendering for SR Linux and IOS XR from authoritative vendor models.
- No repository evidence proves HSRP, protocol VRRP, GLBP, vendor anycast
  gateway, NAT64/NAT66/NPTv6 rendering, DNS overrides, or PBR set actions.

## 5. FHRP vocabulary

The structured vocabulary is `HSRP`, `VRRP`, `VARP`, `GLBP`, and
`ANYCAST_GATEWAY`. An instance records a candidate-owned interface,
address-family, optional group/virtual-router ID, stable virtual-IP objects,
priority, preempt, optional advanced timers, optional virtual MAC, description,
and `auth_secret_ref`.

### HSRP

Representable but `NOT_IMPLEMENTED` everywhere because the repository has no
verified HSRP or HSRPv2 syntax. IPv6 does not silently select HSRPv2.

### VRRP

Representable but `NOT_IMPLEMENTED`. NetBox uses a `vrrp` address role as an
inventory label, but the live cEOS command is Arista `virtual-router`, not
evidence of protocol VRRP configuration. No interoperability is inferred.

### VARP

IPv4 and IPv6 are `SUPPORTED` on cEOS using the exact S1/S2 evidence:
`ip virtual-router mac-address`, `ip virtual-router address`, and
`ipv6 virtual-router address`. VARP remains distinct from VRRP.

### GLBP and anycast gateway

Both remain `NOT_IMPLEMENTED`; neither is treated as a synonym for VARP or
VRRP. No generic Cisco or EVPN syntax is fabricated.

### FHRP secrets

Only `auth_secret_ref` exists. A plaintext `password`/`authentication` path is
not registered, and the shared secret policy rejects secret-shaped data in
revision JSON. A reference is rendered only as an unresolved comment, never as
a password command.

## 6. NAT architecture

NAT separates translation family (`NAT44`, `NAT64`, `NAT66`, `NPTV6`,
`NAT_PT`) from rule behavior (`STATIC`, `DYNAMIC`, `PAT`, `STATEFUL`,
`TWICE_NAT`, `POLICY_NAT`). Rules are structured; there is no authoritative
raw `ip nat`/nft string field.

### Static, dynamic, PAT, and stateful NAT

Static and dynamic forms are represented but not selectable without verified
rendering. Ubuntu/FRR supports the repository-proven NAT44 `PAT`/`STATEFUL`
masquerade form only. It renders a candidate-only nftables IPv4 NAT table from
the structured original source prefix and stable outside-interface reference.
PAT is explicit and is not inferred merely from a dynamic rule.

### NAT44, NAT64, NAT66, and NPTv6

NAT44 is the only rendered family. NAT64 and NAT66 remain `NOT_IMPLEMENTED`.
NPTv6 is modeled as prefix translation, not stateful NAT66; Tier-1 validation
requires IPv6 prefixes and equal prefix lengths when both sides are present.
There is no invented DNS64 behavior.

### NAT-PT

`NAT_PT` is explicitly `UNSUPPORTED` and documented `DEPRECATED/obsolete` on
all platforms. It is never mapped to NAT64 and has no renderer.

### Twice NAT and policy NAT

Both remain typed rule modes but `NOT_IMPLEMENTED`; the project has no verified
syntax or safe structured renderer for them.

### NAT pools

Pools are independent stable objects with name, family, start/end, prefix
length, and description. Rules reference a candidate-owned `pool_*` ID. No
pool renderer is enabled because the repository evidence only proves interface
masquerade, not an address-pool syntax.

## 7. DHCP and DHCPv6

Default state is `INHERIT PROJECT DHCP DEFAULTS`. The current architecture is
unchanged: NetBox stores passive structured pool/reservation data; Python owns
pool logic/rendering; NMAS is primary; R2 is secondary with non-overlapping
pools. Opening the module creates no override and no reservation workflow.

cEOS has an explicit `OVERRIDE` mode for structured relay objects because
S1/S2 prove `ip helper-address` and `ipv6 dhcp relay destination`. Relay
destinations and candidate interface ownership receive Tier-1 validation.
Server reachability remains Phase 13.

DHCP/DHCPv6 client vocabulary exists but has no enabled platform renderer.
Local-device DHCP server override remains `NOT_IMPLEMENTED`; Device Builder
does not compete with NMAS/R2.

### VLAN 200 exclusion

Management/Vlan200 is always static. DHCP and DHCPv6 client creation is
server-side rejected even if a capability were accidentally enabled. The UI
does not offer a reservation workflow, and no MAC/DUID is used as delivery
identity.

## 8. DNS

Default state is `INHERIT PROJECT / HOST DEFAULTS`. The structured override
schema contains stable IPv4/IPv6 resolver objects, stable search-domain
objects, and an optional domain name. IP/domain syntax and bounds are Tier-1
validated. No platform has repository evidence for a safe override renderer,
so override creation is currently `NOT_IMPLEMENTED`. No authoritative-zone
feature exists and reachability is not claimed.

## 9. Monitoring inheritance

Monitoring is represented as `INHERIT` rather than duplicating the existing
SNMP, syslog, telemetry, receiver, database, or dashboard architecture.
Per-device monitoring override remains `NOT_IMPLEMENTED`.

## 10. ACL architecture

ACLs and ACEs are structured objects. An ACL records stable identity, name,
IPv4/IPv6 family, standard/extended class, description, and an independent
entry collection. An ACE records stable identity, explicit sequence,
permit/deny action, protocol, structured `ANY`/`HOST`/`PREFIX` source and
destination matches, numeric single/range ports, description, and logging
intent.

cEOS IPv4 standard and extended ACLs are supported from repository evidence.
IPv6 ACL rendering remains `NOT_IMPLEMENTED`. Port fields are accepted only
for TCP/UDP and are bounded to 0-65535.

ACL attachment is a separate stable relationship containing an ACL ID,
candidate-owned interface ID, and `IN`/`OUT` direction. The renderer defines
ACLs before attachments. This preserves the future DEFINE versus
ACTIVATE/ATTACH dependency boundary.

Phase 12 does not claim an ACL is safe. The UI and candidate say explicitly
that traffic-impact validation has not run. Management lockout, routing/DHCP
survival, application requirements, and control-plane effects wait for Phase
13. There is no raw security CLI field.

## 11. PBR architecture

The PBR schema has stable policy, sequence, and attachment IDs. Policies have
name/family/description; sequences can express source/destination prefix,
protocol, IPv4/IPv6 next hop, candidate-owned output interface, and sequence;
attachments are separate candidate-owned inbound relationships.

No platform has verified repository evidence for PBR forwarding syntax, so new
PBR intent is not selectable and no route-map syntax is fabricated. Preserved
PBR intent renders an incompatibility comment. Next-hop reachability,
dependency correctness, topology impact, and loop risk are Phase 13 checks.

## 12. Basic and Advanced synchronization

Basic and Advanced consume the same `DeviceIntentRevision`, stable objects,
and `IntentFieldState` rows. Basic exposes common fields; Advanced adds secret
references and detailed fields. There are no Basic/Advanced duplicate models.

## 13. Field commit and browser draft behavior

Ordinary input changes only JavaScript state and server-provided descriptor
slots. It never calls `fetch` or submits a form. Enter (or Ctrl/Cmd+Enter for a
textarea) explicitly commits one field. The server resolves a known namespace,
known object shape, stable owned ID, known field, validator, and renderer
descriptor. Invalid commits restore only that field; siblings remain intact.
Successful commits return the authoritative Python render.

Collection add/remove is explicit POST with CSRF, DRAFT-only checks, ownership,
bounds, and literal `REMOVE` confirmation. GET never mutates.

## 14. Candidate rendering

`candidate_renderer.render()` remains the one renderer. It hydrates accepted or
selected draft state for identity, interfaces, routing, FHRP, NAT, services,
security, and policy, then dispatches once through the platform driver.

Additive templates are:

- `templates/features/ceos/fhrp_varp.j2`
- `templates/features/ceos/acl_ipv4.j2`
- `templates/features/ubuntu_frr/nat_pat.j2`

Frozen Lab-1 per-device templates are untouched. JavaScript contains no vendor
CLI. Ordering is deterministic and repeated accepted renders are byte-identical.

## 15. Tier-1 validation and Phase-13 boundary

Implemented locally: enums, IP/prefix/domain syntax, family consistency,
port/range syntax, FHRP group/priority/timers, virtual IPs, MAC syntax,
candidate-owned interface/pool/ACL/policy references, ACE structure, NPTv6
equal prefix length, collection bounds, and obvious local exclusions.

Explicitly deferred: peer existence, virtual-IP uniqueness, NAT inside/outside
topology and symmetry, ACL traffic survival, DHCP overlap/reachability, DNS
reachability, PBR next-hop reachability/loops, NAT64 design, cross-device policy
references, service dependencies, and deployment safety. Accepted fields say
`SYNTAX ACCEPTED`; project validation is pending.

## 16. Future Configlet mapping and priority

No Configlet is created or executed. The intended Phase-14 mapping is:

| Object | Future operation | Likely priority |
|---|---|---|
| FHRP definition | DEFINE | higher-level service/basic forwarding |
| NAT pool | DEFINE | higher-level service |
| NAT rule | ACTIVATE | traffic-affecting policy |
| DHCP relay | ATTACH | higher-level service |
| DNS resolver override | DEFINE | higher-level service |
| ACL | DEFINE | policy definition |
| ACL attachment | ACTIVATE/ATTACH | traffic-affecting policy |
| PBR policy | DEFINE | policy definition |
| PBR attachment | ACTIVATE/ATTACH | traffic-affecting policy |

Dependency planning and final priority decisions remain Phase 14 work.

## 17. Security

No raw CLI input exists. Dynamic field paths use strict regexes plus owned-ID
lookups. Django autoescaping protects descriptions and names. The existing
secret denylist remains active; only `*_ref` references are allowed. No module
imports live-device, NetBox, Git, GitHub, or deployment clients. The Change
stays DRAFT.

## 18. Known limitations

- In addition to the original cEOS VARP/relay/IPv4 ACL and Ubuntu nftables
  NAT44 renderers, Phase 20.5 provides fixture-tested IPv4/IPv6 ACLs for SR
  Linux, IOS XR, and SONiC and DHCPv4/v6 relay for SR Linux and IOS XR.
- HSRP, protocol VRRP, GLBP, generic anycast gateway, cEOS IPv6 ACL, NAT
  pools, NAT64, NAT66, NPTv6 rendering, twice/policy NAT, DNS overrides,
  DHCP client, local DHCP server override, monitoring override, and PBR remain honestly
  unavailable for new intent.
- VARP global virtual-MAC coordination across multiple instances/devices is a
  project-level concern reserved for Phase 13.
- The UI is intentionally a lab-scale structured catalogue, not a vendor-
  complete firewall/NAT product.

## 19. Phase-13 handoff

Phase 13 can consume these stable objects and separate definition/attachment
relationships to perform cross-device, NetBox, topology, reachability, traffic-
safety, collision, and dependency analysis without changing the Phase-12
schema or inventing a second renderer.
