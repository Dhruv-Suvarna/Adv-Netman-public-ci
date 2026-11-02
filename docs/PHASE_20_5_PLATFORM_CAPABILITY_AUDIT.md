# Phase 20.5 Platform Capability Audit

> Historical implementation audit. Version 2 Phase 4 supersedes its
> operator-facing multi-state classifications with the fail-closed binary
> matrix documented in `V2_PHASE4_FULL_PLATFORM_CAPABILITY_MATRIX.md`.
> `UNKNOWN` below describes historical internal evidence only and is never a
> Version 2 Phase 4 terminal matrix state.

This audit separates five facts that must not be conflated:

1. the NOS/platform documents a feature;
2. the target image/version and exact model are verified;
3. NMAS can validate, compose, render, and import it;
4. writer software exists and is enabled; and
5. a live device accepted and read back the result.

`SUPPORTED` in `platform_drivers.py` means the NMAS canonical/rendering path
exists. It never means live-tested unless live evidence is stated separately.

## Evidence boundary

The approved live baseline contains cEOS 4.36.2F and Ubuntu 24.04 / FRR
8.4.4 only. No SR Linux, IOS XR, or SONiC node is deployed. Work for those
three platforms is therefore **IMPLEMENTED / FIXTURE TESTED / NOT LIVE
VERIFIED**. Missing nodes prevent live capture, live writes, capability
discovery, and readback; they do not prevent parsers, renderers, translators,
or mock tests.

## Canonical implementation matrix

| Platform | Interfaces/addressing | Routing | Services/policy | Structured import | Real executor |
|---|---|---|---|---|---|
| cEOS 4.36.2F | routed/access/trunk/subif/SVI/mgmt/loopback | static, RIPv2, OSPFv2/v3, BGPv4/v6 | IPv4 ACL, DHCPv4/v6 relay, VARP | live tested | SSH/Netmiko CLI |
| Ubuntu 24.04 / FRR 8.4.4 | routed/subif/SVI/mgmt/loopback | static, RIPv2/RIPng, OSPFv2/v3, BGPv4/v6 | nft NAT44 PAT/stateful | live tested | fixed lab-local `docker exec` argv |
| SR Linux | routed physical/subif/loopback/mgmt | static, OSPFv2/v3, BGPv4/v6 | IPv4/IPv6 ACL + attachment; DHCPv4/v6 relay | structured JSON fixture tested | none |
| IOS XR 8000v | routed physical/subif/loopback/mgmt | static, RIPv2, OSPFv2/v3, BGPv4/v6 | IPv4/IPv6 ACL + attachment; DHCPv4/v6 relay | running-config fixture tested | none |
| SONiC | routed physical/subif/loopback/mgmt plus access/trunk/SVI | static, BGPv4/v6 | IPv4/IPv6 ACL + attachment | config_db JSON fixture tested | none |

The three fixture importers call the same canonical apply service as live
cEOS/FRR import. SR Linux and IOS XR are semantic round trips. The supported
SONiC tables make a byte-equivalent JSON round trip after decoding. Unknown
tables/stanzas, inner fields, malformed entries, non-default VRFs, and
unresolved references are preserved as unmanaged configuration.

## Closed Phase 20.5 cells

### SR Linux

- Interfaces, addresses, network-instance membership, static route/
  next-hop-group indirection, OSPFv2/v3, BGP peer groups/neighbors, ACLs and
  attachments: **IMPLEMENTED / FIXTURE TESTED**.
- DHCPv4/v6 relay: **IMPLEMENTED / FIXTURE TESTED** using the documented
  subinterface `ipv4|ipv6 dhcp-relay server` leaf-list. Optional relay
  source/gi-address, options, and non-default network instances remain
  unmanaged because canonical relay intent has no corresponding fields.
- Structured JSON importer, including physical parents without index 0 and
  correct `parent.0` versus tagged-subinterface references: **IMPLEMENTED /
  FIXTURE TESTED**.

### IOS XR 8000v

- Routed interfaces/subinterfaces, dotted IPv4 masks, IPv6, static routes,
  OSPF/OSPFv3, BGP, and ACLs: **IMPLEMENTED / FIXTURE TESTED**.
- RIPv2: **IMPLEMENTED / FIXTURE TESTED** as `router rip`, nested
  `interface`, and optional `passive-interface`.
- DHCPv4/v6 relay: **IMPLEMENTED / FIXTURE TESTED** using documented
  `dhcp ipv4|ipv6`, named relay profiles, `helper-address vrf default`, and
  interface/profile attachments. Classic-IOS interface `ip helper-address`
  is deliberately not fabricated for IOS XR.
- Running-config importer covers the same implemented subset and preserves
  unsupported subcommands: **IMPLEMENTED / FIXTURE TESTED**.

RIPng remains **PLATFORM SUPPORTED / VERIFIED MODEL OR SCHEMA MISSING**:
Cisco documents it for Cisco 8000 from IOS XR 7.5.2 under `router rip / vrf
<name> / address-family ipv6`, but this project has no pinned IOS XR release
and canonical RIP has no VRF field. Rendering default-VRF RIPv2 syntax as
RIPng would be incorrect.

### SONiC

- Routed interfaces, subinterfaces, loopbacks, management interfaces,
  static routes, BGP, and ACLs: **IMPLEMENTED / FIXTURE TESTED**.
- ACCESS, TRUNK, and SVI: **IMPLEMENTED / FIXTURE TESTED** through `VLAN`,
  `VLAN_MEMBER`, and `VLAN_INTERFACE`.
- ConfigDB importer for every table rendered by NMAS: **IMPLEMENTED /
  FIXTURE TESTED**. Standalone VLANs, orphan neighbor-AFs, absent ACL ports,
  unknown tables, and unknown inner fields remain unmanaged rather than
  disappearing.

## Remaining capability cells

The following is an explicit re-audit of every still-missing family. A
registry `UNKNOWN` means precisely that the absent target/image or mapping
does not justify either a support or an unsupported claim.

### SR Linux

| Cells | Classification | Exact blocker |
|---|---|---|
| ACCESS, TRUNK, SVI | PLATFORM SUPPORTED / VERIFIED MODEL OR SCHEMA MISSING | SR Linux uses MAC-VRF/IRB/network-instance relationships; canonical flat VLAN/SVI intent does not identify MAC-VRF, IRB, or routed attachment ownership. |
| LAG | PLATFORM SUPPORTED / VERIFIED MODEL OR SCHEMA MISSING | The platform aggregate/member model is known, but canonical `LAG` has no member-interface collection or aggregation parameters. |
| MLAG, TUNNEL, GRE, VXLAN/VTEP, VIRTUAL, RADIO | PLATFORM/FEATURE CAPABILITY UNVERIFIED | No target-specific model mapping and no deployed 24.10 image evidence exists; the registry does not claim platform denial. |
| IS-IS | PLATFORM SUPPORTED / VERIFIED MODEL OR SCHEMA MISSING | The repository has no verified SR Linux instance/interface/level mapping for the canonical IS-IS fields. |
| RIP/RIPng; EIGRP | PLATFORM UNSUPPORTED | SR Linux documents no RIP implementation; EIGRP is not an SR Linux protocol. |
| FHRP variants, NAT variants, DHCP client/server, DNS/monitoring override, PBR | PLATFORM/FEATURE CAPABILITY UNVERIFIED | Feature-specific 24.10 model applicability and canonical attachment semantics have not been verified. They are `UNKNOWN`, not falsely labeled unsupported or implemented. |
| NAT-PT | PLATFORM UNSUPPORTED | Deprecated NAT-PT is intentionally not mapped to NAT64. |
| Linux BOND/BRIDGE kinds | PLATFORM UNSUPPORTED AS MODELED | These are Linux-specific canonical constructs, not SR Linux LAG/network-instance objects. |

### IOS XR 8000v

| Cells | Classification | Exact blocker |
|---|---|---|
| ACCESS, TRUNK, SVI | PLATFORM SUPPORTED / VERIFIED MODEL OR SCHEMA MISSING | IOS XR uses L2VPN bridge groups/domains and BVI objects; canonical flat switchport/SVI fields do not model those relationships. |
| LAG | PLATFORM SUPPORTED / VERIFIED MODEL OR SCHEMA MISSING | Bundle-Ether requires member relationships and bundle parameters absent from canonical `LAG`. |
| TUNNEL, GRE, VXLAN/VTEP | PLATFORM SUPPORTED / VERIFIED MODEL OR SCHEMA MISSING | Exact Cisco 8000v release/data-plane applicability and the required tunnel/overlay fields are unpinned. |
| MLAG, VIRTUAL, RADIO | PLATFORM/FEATURE CAPABILITY UNVERIFIED | No precise IOS XR 8000v object contract has been established. |
| RIPng | PLATFORM SUPPORTED / VERIFIED MODEL OR SCHEMA MISSING | Requires a pinned release and canonical VRF ownership, as described above. |
| IS-IS and EIGRP | PLATFORM SUPPORTED / VERIFIED MODEL OR SCHEMA MISSING | The registry records vendor support, but this repository lacks a release-pinned process/interface model mapping and renderer tests. |
| FHRP, NAT, DHCP client/server, DNS/monitoring override, PBR | PLATFORM/FEATURE CAPABILITY UNVERIFIED | Exact Cisco 8000v release/hardware applicability and required VRF/profile/policy fields are not verified. DHCP relay is the exception and is implemented. |
| NAT-PT; Linux BOND/BRIDGE kinds | PLATFORM UNSUPPORTED AS MODELED | NAT-PT is deprecated; Linux object kinds are not IOS XR interface objects. |

### SONiC

| Cells | Classification | Exact blocker |
|---|---|---|
| LAG | PLATFORM SUPPORTED / VERIFIED MODEL OR SCHEMA MISSING | ConfigDB PortChannel tables exist, but canonical `LAG` has no member collection; emitting an empty PortChannel would be misleading. |
| VXLAN/VTEP | PLATFORM SUPPORTED / VERIFIED MODEL OR SCHEMA MISSING | Canonical intent lacks VNI, tunnel source, VLAN/VRF maps, and EVPN ownership needed by SONiC tables. |
| MLAG, TUNNEL, GRE, VIRTUAL, RADIO | PLATFORM/IMAGE CAPABILITY UNVERIFIED | These are distribution, ASIC, and image dependent; no intended SONiC image/version is pinned. |
| RIP/RIPng, OSPFv2/v3, IS-IS | PLATFORM SUPPORTED / VERIFIED MODEL OR SCHEMA MISSING | The routing stack may support them, but no stable target config_db schema was verified. Direct FRR/vtysh configuration is not silently mixed into a config_db candidate. |
| EIGRP | PLATFORM UNSUPPORTED | EIGRP is not a SONiC/FRR platform protocol in this project. |
| FHRP, NAT, DHCP, DNS/monitoring override, PBR | PLATFORM/IMAGE CAPABILITY UNVERIFIED | Upstream designs exist for some distributions, but table availability, schema version, services, and restart/apply behavior depend on the absent target image. |
| NAT-PT; Linux BOND/BRIDGE kinds | PLATFORM UNSUPPORTED AS MODELED | NAT-PT is deprecated; Linux object kinds are not exposed as SONiC candidate objects. |

These blockers are feature-specific. They are not a blanket “no live node,
therefore no software” exception.

## NETCONF, gNMI, and runtime enablement

`execution/transport_capability.py` distinguishes `NOT_IMPLEMENTED`,
`IMPLEMENTED_NOT_LIVE_VERIFIED`, `IMPLEMENTED_DISABLED`, `AVAILABLE`,
`READ_ONLY`, and `PLATFORM_CAPABILITY_UNVERIFIED`. Only `AVAILABLE` is
selectable. Candidate rendering never implies execution.

| Platform | NETCONF writer | gNMI writer | Runtime/UI | Evidence and blocker |
|---|---|---|---|---|
| cEOS live | NOT_IMPLEMENTED; monitoring session READ_ONLY | NOT_IMPLEMENTED; monitoring session READ_ONLY | disabled | Existing credential is read-only; CLI candidates are not YANG paths; live NETCONF lacks the requested confirmed-commit/validate/rollback safety. No write probe was sent. |
| Ubuntu/FRR live | no endpoint/writer | no endpoint/writer | existing Docker executor only | Approved containers expose no NETCONF or gNMI target. |
| SR Linux | NOT_IMPLEMENTED | IMPLEMENTED_DISABLED | absent from executor registry and UI | CLI-origin gNMI Set translation is fixture/mock tested as one atomic private-candidate request. No node, credential, commit-confirmed client support, or post-write readback exists. |
| IOS XR | NOT_IMPLEMENTED | NOT_IMPLEMENTED | disabled | Device protocols are documented, but no release-pinned native-YANG/per-feature path translator or mock corpus exists. CLI text is not passed off as YANG. |
| SONiC | PLATFORM_CAPABILITY_UNVERIFIED | PLATFORM_CAPABILITY_UNVERIFIED | disabled | Protocol availability and schema are image-dependent. ConfigDB rendering exists, but no verified safe deployment adapter exists for an unpinned image. |

The SR Linux writer rejects placeholders, composition conflicts, unsupported
object markers, comments, and non-SR-Linux statements. Its `apply()` method
defaults to disabled, and production code never enables or registers it.

No live model-driven write, credential change, topology lifecycle action, or
automatic candidate deployment is part of this work.
