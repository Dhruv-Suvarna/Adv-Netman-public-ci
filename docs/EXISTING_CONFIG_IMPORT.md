# Existing-Device Configuration Import (Phase 20.5 Objective 1)

Status: live, read-only import is implemented for the approved deployed
baseline (Arista cEOS 4.36.2F and Ubuntu 24.04 / FRR 8.4.4). Fixture import
software is also implemented for Nokia SR Linux, Cisco IOS XR 8000v, and
SONiC. Those three platforms have no deployed node or inventory capture
transport, so their evidence is **IMPLEMENTED / FIXTURE TESTED / NOT LIVE
VERIFIED**.

## One canonical workflow

```text
live sanitized capture OR explicit test fixture
  -> platform parser
  -> transient vendor-neutral parsed records
  -> canonical Device Builder mutation + field-commit services
  -> candidate composition
  -> platform renderer
```

`config_import/schema.py` is an import boundary, not a second intent model.
Both live and fixture entry points call the same `_apply_parsed_config()`
pipeline. Rendering never executes a change. `import_from_fixture()` is test
support only and is not wired to the operator's live-import action; it also
refuses a fixture whose platform does not match the candidate.

## Acquisition and provenance

Live import is POST-only, CSRF protected, and available only for an
`EXISTING_DEVICE` draft. It reuses `bootstrap.capture` and
`health.live.read_device_with_raw`; no browser-supplied command is accepted.

| Platform | Source | Parser | Evidence |
|---|---|---|---|
| cEOS | fixed read-only `show running-config` | `parser_ceos.py` (`ceos-2.0`) | live tested |
| Ubuntu/FRR | fixed read-only FRR config, `ip -j addr`, nft ruleset | `parser_frr.py` (`ubuntu-frr-1.0`) | live tested |
| SR Linux | structured JSON matching the rendered model/path tree | `parser_srlinux.py` (`srlinux-json-1.0`) | fixture tested only |
| IOS XR | documented IOS XR running-config syntax | `parser_iosxr.py` (`iosxr-1.0`) | fixture tested only |
| SONiC | config_db JSON | `parser_sonic.py` (`sonic-configdb-1.0`) | fixture tested only |

Live imports record device, platform, transport, credential *reference*,
capture timestamp, SHA-256 digest of sanitized sources, and parser version.
Secrets are redacted before parsing or persistence. Fixture provenance says
`fixture` and `none (fixture)` explicitly; it never masquerades as live
evidence. A failed read or platform mismatch applies nothing.

## Structured coverage

- cEOS: hostname; supported interfaces and addressing; access/trunk VLANs;
  static routes; RIPv2; OSPFv2/v3; BGP; IPv4 ACLs; DHCP relays; VARP.
- Ubuntu/FRR: hostname; Linux interfaces/address state; static routes;
  RIPv2/RIPng; OSPFv2/v3; BGP; recognized nft NAT44 PAT.
- SR Linux: system name; physical, index-0 and tagged routed
  subinterfaces; IPv4/IPv6; static route/next-hop-group pairs; OSPFv2/v3;
  BGP groups/neighbors; IPv4/IPv6 ACLs and attachments; DHCPv4/v6 relay.
- IOS XR: hostname; routed interfaces/subinterfaces; IPv4 dotted masks and
  IPv6 prefixes; static routes; default-VRF RIPv2; OSPF/OSPFv3; BGP; IPv4/
  IPv6 ACLs and attachments; DHCPv4/v6 relay profiles and attachments.
- SONiC: `DEVICE_METADATA`, `INTERFACE`, `LOOPBACK_INTERFACE`,
  `MGMT_INTERFACE`, `VLAN`, `VLAN_MEMBER`, `VLAN_INTERFACE`, `STATIC_ROUTE`,
  `BGP_GLOBALS`, `BGP_NEIGHBOR`, `BGP_NEIGHBOR_AF`, `ACL_TABLE`, and
  `ACL_RULE`.

Only syntax that maps unambiguously to the canonical model is parsed. For
example, an FRR prefix-form RIP `network` remains opaque because canonical
RIP activation is an interface binding. IOS XR RIPng remains opaque because
the documented Cisco 8000 form is version- and VRF-dependent while canonical
RIP has no VRF field.

## Lossless unmanaged preservation

Unknown top-level tables/stanzas, unsupported subcommands, unknown fields
inside known structured tables, malformed entries, non-default VRFs,
unmodeled multipath constructs, and unresolved cross-object references are
stored in `revision.sections["_import"]["unmanaged"]`. Examples include a
SONiC standalone VLAN, an orphan BGP neighbor-AF, an ACL attachment to a
missing port, and an SR Linux OSPF reference to an absent interface.

Opaque source is retained for planning/audit continuity but is never injected
into executable CLI. A later explicit re-import replaces only object IDs
owned by the prior import; operator-created draft objects remain untouched.

## Round-trip evidence

The live-baseline tests exercise the real capture and sanitization pipeline.
`test_config_import_new_platforms.py` exercises the fixture entry point and
the same canonical apply pipeline:

- SR Linux structured fixture -> parser -> canonical intent -> composition
  -> SR Linux renderer, including index-0 and tagged-parent reference rules.
- IOS XR running-config fixture -> parser -> canonical intent -> composition
  -> IOS XR renderer, including RIPv2.
- SONiC config_db fixture -> parser -> canonical intent -> composition ->
  byte-identical supported config_db JSON.

Comparison is semantic except for the SONiC supported-table test, which is
byte-equivalent after JSON decoding. NOS defaults and source ordering need
not be retained when they do not change meaning.

## Boundaries

- Fixture import does not create a live capture transport or enable an
  execution transport.
- Unsupported source remains preserved metadata and is not auto-deployed.
- Import is not synchronization. It runs only on explicit operator action.
- Adding a live node still requires a fixed read-only acquisition contract,
  credential scope, sanitization, and live evidence before the UI may claim
  live import support.
