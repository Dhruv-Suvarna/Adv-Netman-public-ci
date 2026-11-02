# Phase 10 — Device Builder Interfaces, Addressing, and WAN Metadata

Status: implemented and verified 2026-09-20. This phase extends the Phase-9
Device Builder without adding a model migration, deployment path, or second
renderer. It is an intent editor and Tier-1 syntax-acceptance surface only.

> **Phase 20.5 continuation:** This document preserves the Phase-10 evidence
> snapshot. Its statements that SR Linux, IOS XR, and SONiC lack renderers are
> historical. The current registry implements routed interfaces for all three
> and SONiC ACCESS/TRUNK/SVI through config_db. See
> `PHASE_20_5_PLATFORM_CAPABILITY_AUDIT.md` for the current per-cell status.

## 1. Ownership and architecture

The ownership boundary remains:

```text
browser typing state
        |
        | explicit Enter/Commit or collection POST
        v
Django workflow state (DeviceIntentRevision + IntentFieldState)
        |
        v
Python validation and candidate rendering

NetBox: passive read-only prefix storage for an explicit Refresh Prefixes action
Live devices: never contacted by an editor/render/commit request
Git/GitHub: never contacted by an editor/render/commit request
```

`core/services/interface_intent_service.py` owns structured collection
mutation. `field_registry.py` resolves only allowlisted, candidate-owned paths.
`field_commit_service.py` retains Phase 9's one-field commit and rollback
contract. `candidate_renderer.py` remains the authoritative renderer and
dispatches through `platform_drivers.py`.

## 2. Interface intent schema

Interface intent lives in the existing versioned
`DeviceIntentRevision.sections["interfaces"]` mapping. A representative
object is:

```json
{
  "if_0123456789abcdef": {
    "id": "if_0123456789abcdef",
    "sequence": 1,
    "name": "Ethernet1",
    "kind": "ROUTED_PHYSICAL",
    "mode": "ROUTED",
    "description": "WAN handoff",
    "admin_state": "ENABLED",
    "mtu": 1500,
    "access_vlan": null,
    "trunk_allowed_vlans": [],
    "native_vlan": null,
    "parent_id": "",
    "encapsulation_vlan": null,
    "vlan_id": null,
    "role": "",
    "operational_description": "",
    "addresses": {},
    "wan": {}
  }
}
```

The mapping key and embedded `id` must agree. Identity never depends on a
list index or mutable interface name. `sequence` supplies explicit ordering;
the stable ID/name are deterministic tie-breakers. A candidate is bounded to
64 interfaces.

## 3. Stable interface and address IDs

Interfaces receive server-generated `if_<16 lowercase hex>` IDs. Addresses
receive `addr_<16 lowercase hex>` IDs. IDs are opaque and stable for the life
of that revision object. Address identity is similarly independent of its
position in the interface's address collection. An interface is bounded to 16
addresses.

Dynamic field paths bind to those IDs, for example:

```text
interfaces.if_0123456789abcdef.name
interfaces.if_0123456789abcdef.addresses.addr_0123456789abcdef.cidr
interfaces.if_0123456789abcdef.wan.provider_name
```

The registry uses strict ID/path regexes and then verifies each ID inside the
current revision. It is not a generic JSON-path mutator.

## 4. Collection mutation and security

Add Interface, Remove Interface, Add Address, Remove Address, and Refresh
Prefixes are POST-only and use Django CSRF protection. Collection mutation is
DRAFT-only. Every Change/Intent/Revision relationship and every interface or
address ID is resolved against the current candidate. Removal requires the
literal `REMOVE` confirmation. A parent cannot be removed while a child still
references it. Cross-candidate and stale identifiers are rejected.

There is no per-keystroke backend request. Normal field typing only changes
browser state and the preview. The only JavaScript requests are an explicit
field commit and an explicit prefix refresh.

## 5. Canonical interface vocabulary

The registry can represent:

- routed physical, access, trunk, subinterface, SVI, management/OOB, loopback;
- LAG/Port-Channel, MLAG, Linux bond, Linux bridge;
- tunnel, GRE, VXLAN/VTEP, virtual, and radio/WLAN.

Representation in the vocabulary does not imply implementation. The
capability registry decides whether a platform/type combination is selectable.

## 6. Capability status model

Four distinct project statuses exist:

| Status | Meaning |
|---|---|
| `SUPPORTED` | The project can edit and render the combination safely now. |
| `NOT_IMPLEMENTED` | The platform may support it, but this project has no approved renderer. |
| `UNSUPPORTED` | The combination is a known mismatch or known unsuitable. |
| `UNKNOWN` | Repository/live evidence is insufficient. |

Only `SUPPORTED` combinations appear for new objects. Existing incompatible
objects remain present, appear in the selector as preserved, produce a visible
warning, and render an explicit unsupported-candidate comment rather than fake
CLI.

## 7. Platform evidence and capability registry

### Arista cEOS

Evidence: frozen Lab-1 templates and live cEOS 4.36.2F. Phase 10 supports
routed physical, access, trunk, subinterface, SVI, management/OOB, and
loopback. LAG/MLAG/tunnel/GRE/VXLAN are `NOT_IMPLEMENTED`; Linux bond/bridge
and radio are `UNSUPPORTED`; virtual is `UNKNOWN`.

The additive candidate syntax was parsed in an isolated live EOS configuration
session. It was never committed; running configuration marker checks were
empty and the session was deleted. One expected semantic warning was observed
for a native VLAN absent from R1; that is deliberately outside Tier-1 and is
not represented as project validation.

### Nokia SR Linux

Phase 20.5 implements routed physical, subinterface, loopback, management,
and IPv4/IPv6 address rendering against the SR Linux 24.10 model. Evidence is
fixture-only because no SR Linux node exists. ACCESS/TRUNK/SVI need a
MAC-VRF/IRB canonical relationship; LAG lacks member intent; other unverified
concepts remain `UNKNOWN` rather than being called unsupported.

### Ubuntu / FRR

Evidence: tracked R3/R4 Ubuntu 24.04 scripts and live iproute2 6.1.0 behavior.
Phase 10 supports routed physical, VLAN subinterface, Linux bridge represented
as SVI, management/OOB, loopback, IPv4/IPv6 addressing, MTU, and admin state.
FRR routing is not generated. Access/trunk/bond/bridge-as-a-standalone-feature,
tunnel/GRE/VXLAN/virtual/radio are `NOT_IMPLEMENTED`; LAG is `UNSUPPORTED` in
favor of the separate Linux-bond concept; MLAG is `UNKNOWN`.

Live evidence used only disposable `p10parent`, `p10parent.3999`, and `p10svi`
links with documentation ranges. A shell cleanup trap removed every object.

### Cisco IOS 8000v

Phase 20.5 implements fixture-tested IOS XR routed physical, subinterface,
loopback, management, and IPv4/IPv6 address rendering. No live node exists.
Bridge-domain/BVI and Bundle-Ether relationships are not represented by the
current flat switching/LAG intent, and no classic-IOS syntax is substituted.

### SONiC

Phase 20.5 implements fixture-tested config_db JSON for routed physical,
subinterface, loopback, management, ACCESS, TRUNK, and SVI intent using
`INTERFACE`, `VLAN`, `VLAN_MEMBER`, and `VLAN_INTERFACE`. No fake line CLI is
emitted and no live SONiC image is claimed.

## 8. Basic and Advanced editors

Basic and Advanced are two projections of the same `DeviceIntent`, revision,
interface IDs, address IDs, and `IntentFieldState` rows. They do not copy or
translate intent. Basic exposes common interface creation/selection and core
fields. Advanced exposes detailed address objects and WAN metadata. Switching
Basic → Advanced → Basic preserves the exact object identities and accepted
values.

**Phase 20.5**: Basic also exposes manual IPv4/IPv6 addressing for the
selected interface -- add, display, edit, and remove -- using the exact same
`interface_intent_service.add_address()`/`remove_address()` endpoints and
the exact same `interfaces.<id>.addresses.<id>.cidr` field path Advanced
edits. There is no second/parallel addressing model: an address created in
Basic (always `source="MANUAL"`; Basic's simplified add-form never offers
AUTO) is immediately a normal address object visible and fully editable in
Advanced (family, source, role, IPAM prefix), and an address edited in
Advanced is immediately reflected in Basic's simplified view. An
AUTO-sourced address created in Advanced still appears in Basic (so nothing
is hidden), but read-only there with a "manage from Advanced" note --
Basic's own add-form cannot create one, keeping VLAN 200's static-only
addressing guarantee (Section 6) enforced identically regardless of which
editor created the request. See `core/templates/core/device_builder/
editor.html`'s `{% if mode == 'advanced' %}...{% else %}...{% endif %}`
addressing block and `test_editor_views.BasicAddressingTests`.

Input updates browser state and the descriptor-based preview. Enter commits a
single-line field; Ctrl/Cmd+Enter or the explicit button commits a textarea.
An invalid commit returns the accepted value for only that field; sibling
interface/address/WAN values remain unchanged.

## 9. Interface types implemented

### Routed physical

Name, description, admin state, optional MTU, and multiple address objects.
cEOS emits `no switchport`; Ubuntu uses iproute2 link/address commands.

### Access

cEOS only in Phase 10. Stores a numeric VLAN ID and renders access-switchport
syntax. It is not selectable for Ubuntu/FRR.

### Trunk

cEOS only in Phase 10. Stores allowed VLANs as a semantic sorted list of
integers, not a vendor command string. Optional native VLAN is separate.

### Subinterface

cEOS and Ubuntu/FRR. Stores its own stable ID, name, candidate-local stable
parent ID, 802.1Q tag, optional MTU/description, admin state, and addresses.
The parent must exist in the same revision; another Change's ID is rejected.

### SVI

cEOS renders VLAN plus SVI syntax. Ubuntu represents the supported behavior as
a Linux bridge, matching the tracked R3/R4 pattern. VLAN ID, description,
admin state, MTU, and addresses are supported. FHRP is not generated.

### Management/OOB

Explicitly represented and marked `MANAGEMENT / STATIC`. AUTO and DHCP-like
behavior are unavailable. `Vlan200` receives VLAN ID 200 and the management
role at creation.

### Loopback

cEOS and Ubuntu/FRR. Name, description, admin/MTU where applicable, IPv4, and
IPv6 are supported. Prefixes are never forced to `/32` or `/128`; the entered
host CIDR is preserved.

## 10. Address schema

Each interface has an address mapping:

```json
{
  "addr_0123456789abcdef": {
    "id": "addr_0123456789abcdef",
    "sequence": 1,
    "family": "IPV4",
    "cidr": "192.0.2.1/31",
    "source": "MANUAL",
    "role": "PRIMARY",
    "ipam_prefix": ""
  }
}
```

Families are `IPV4`/`IPV6`; source modes are `MANUAL`/`AUTO`; roles are
`PRIMARY`/`SECONDARY`. IPv4-only, IPv6-only, dual-stack, and multiple addresses
per family are representable. `ipaddress.ip_interface()` validates canonical
host CIDRs while preserving host bits (`192.0.2.1/31` remains that host, not
`192.0.2.0/31`). Family mismatch is rejected locally.

## 11. MANUAL and AUTO

`MANUAL` stores an explicit host CIDR and receives Tier-1 syntax acceptance.
It does not imply collision freedom.

`AUTO` means IPAM-assisted candidate intent. It is not DHCP, does not select a
free host, does not allocate, does not reserve, and makes no future-availability
promise. It stores at most a selected existing prefix and renders:

```text
allocation unresolved and unreserved
```

The UI also states `UNRESOLVED / UNRESERVED` and “Project validation pending.”

## 12. Explicit NetBox read path

`device_builder_ipam_service.py` calls the existing
`modules.netbox_ipam.list_all_prefix_cidrs()` only from the explicit
POST `.../ipam-prefixes/` endpoint. Prefixes are family-filtered and sorted
deterministically. Editor load, typing, candidate rendering, ordinary field
commit, Copy, Download, and Diff never query NetBox. Errors are returned as a
generic unavailable message. The module has no create/update/save/delete or
reconciliation call.

## 13. VLAN 200 guarantee

VLAN 200 remains `MANAGEMENT / STATIC`:

- the Advanced UI omits AUTO for management/Vlan200 address objects;
- collection creation rejects AUTO server-side;
- changing an existing address source to AUTO is rejected server-side;
- changing an interface into management/Vlan200 while AUTO addresses exist is
  rejected;
- no DHCP, DHCPv6, allocation, or reservation endpoint exists.

Both UI hiding and server-side rejection are tested and were verified live.

## 14. Trunk VLAN normalization

Input such as `10,20,30-32` is parsed into a sorted unique integer list.
Duplicates and overlapping ranges collapse deterministically. Reversed ranges,
empty tokens, non-integers, and values outside 1–4094 are rejected. The cEOS
renderer compresses the semantic list back to deterministic range syntax.

## 15. WAN metadata

Every interface carries optional WAN metadata:

- enabled/disabled state;
- provider name and peer label;
- peer IPv4/IPv6 host addresses;
- gateway/next-hop IPv4/IPv6 host addresses;
- WAN MTU and description.

When enabled, the candidate prints comments headed “WAN metadata only.” It
does not emit static routes, BGP, route maps, NAT, GRE, IPsec, or any other
routing/tunneling configuration.

## 16. Tier-1 validation boundary

Implemented validation includes interface-name syntax, known/selectable type,
description bounds, admin/source/family/role enums, MTU 576–9216, VLAN 1–4094,
trunk-set normalization, IPv4/IPv6 host CIDR syntax, local family consistency,
candidate-local parent identity, WAN host IP syntax, and bounded labels.

Phase 10 does **not** claim duplicate-address detection, collision freedom,
prefix non-overlap, peer consistency, topology validity, NetBox availability at
deployment time, route/VRF validity, feature dependencies, or complete project
validity. Those belong to Phase 13. The UI says `SYNTAX ACCEPTED`, never overall
`VALIDATED`.

## 17. Feature templates and rendering

Reusable additive Jinja templates live under:

```text
templates/features/ceos/
templates/features/ubuntu_frr/
```

Frozen Lab-1 per-device templates were not rewritten. Jinja renders unique
field markers, and `feature_template_renderer.py` converts them to the same
descriptor contract Phase 9 established. Browser JavaScript substitutes draft
values into server-provided descriptors; it contains no vendor CLI syntax.

`candidate_renderer.py` hydrates a deep copy of revision sections with either
accepted or selected draft `IntentFieldState` values, sorts by explicit
sequence plus stable ID/name, dispatches by platform, and joins the descriptors.
Repeated accepted renders are byte-identical. Its header states:

```text
Not deployed. Tier-1 syntax acceptance only; project validation is pending.
```

## 18. Draft, accepted, Copy, Download, and Diff

Phase-9 behavior is preserved. Every successful commit promotes one field;
every invalid commit restores that field's draft to its accepted value. The
Change remains DRAFT and no Configlet is created or executed. Copy uses the
visible browser preview, including local draft. Download returns the
server-authoritative accepted candidate. Diff compares persisted accepted
against persisted last-attempt draft renders. No operation contacts a device.

## 19. Platform changes

Changing `device.platform` preserves sections, stable IDs, addresses, and WAN
metadata. Existing incompatible objects remain visible and are flagged. The
new-interface selector is refreshed to only the new platform's `SUPPORTED`
types. No object is pruned or rewritten.

## 20. Verification summary

- 138 dedicated Phase-10 Django tests cover collections, fields,
  capabilities, rendering, views, IPAM, JavaScript, and architecture.
- Full Django suite: 541 tests pass.
- Existing monitoring suite: 446 tests pass.
- `manage.py check` and migration drift checks pass; Phase 10 has no migration.
- All 12 feature templates parse with Jinja `StrictUndefined` metadata checks.
- Headless Firefox verified local typing, one-request commit, field-local
  rollback, Basic/Advanced synchronization, platform warning/filtering,
  VLAN-200 UI behavior, Copy, Download, Diff, and all four themes.
- One explicit NetBox refresh returned prefixes as unresolved/unreserved;
  `populate_netbox.py --check` remained `UNCHANGED=318`.
- cEOS and Ubuntu syntax evidence was gathered without committing or retaining
  live configuration artifacts.

## 21. Known limitations

- AUTO host selection/reservation and collision checks wait for Phase 13.
- SR Linux, IOS XR, and SONiC gained the fixture-tested Phase-20.5 renderers
  summarized above; none has live-device evidence.
- Ubuntu support is selected iproute2 interface/address behavior; no FRR
  routing is generated.
- cEOS has the broadest Phase-10 interface-type support.
- LAG, MLAG, bond, standalone bridge, tunnel, GRE, VXLAN/VTEP, virtual, and
  radio/WLAN remain honestly classified but unimplemented where noted.
- No FHRP, routing protocol, static route, NAT, security, deployment, Golden,
  Probation, or rollback automation is introduced.
- JavaScript syntax could not be checked with Node.js because Node is absent;
  static contract tests and real headless-Firefox execution cover the browser
  code instead.

## 22. Phase-11 handoff

Phase 11 can add structured routing modules behind the same revision schema,
dynamic allowlist, one-field commit boundary, platform capability model,
feature-template layer, and Python renderer. Static routing, RIP, OSPF,
IS-IS, EIGRP, and BGP must remain separate feature namespaces with the same
truthful capability/evidence rules. WAN metadata must not silently become a
routing generator; any relationship must be an explicit Phase-11 intent field
and renderer decision.
