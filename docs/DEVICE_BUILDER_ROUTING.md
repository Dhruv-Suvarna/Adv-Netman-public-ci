# Device Builder Routing (Phase 11)

Phase 11 adds structured routing intent -- static routing, RIPv2/RIPng,
OSPFv2/OSPFv3, IS-IS, EIGRP, and BGP -- to the Device Builder established in
Phases 8-10. It reuses every Phase-10 pattern exactly (stable opaque IDs,
Tier-1 syntax-only validation, a four-state evidence-backed capability
matrix, browser-local draft typing, one authoritative Python renderer) and
adds no new Django model, no migration, and no second renderer. Nothing in
this phase deploys anything to a device, NetBox, or Git.

> **Phase 20.5 continuation:** This document preserves the Phase-11 baseline;
> its original per-platform matrices are historical. SR Linux, IOS XR, and
> SONiC now have fixture-tested routing renderers/importers for the subsets in
> `PHASE_20_5_PLATFORM_CAPABILITY_AUDIT.md`; IOS XR RIPv2 and FRR RIPv2/RIPng
> are implemented. No new platform is live-tested.

## 1. Routing architecture

Routing intent lives inside the existing `DeviceIntentRevision.sections`
JSON, in a `routing` key that sits alongside the Phase-10 `interfaces` key.
The `FeatureNamespace.ROUTING` enum value has been reserved since Phase 8;
Phase 11 is the first phase to populate it. There is no `RoutingIntent`
model, no `RoutingRevision` model -- only more structured data inside the
one existing `sections` JSONField, exactly as `interfaces`/`addresses`/`wan`
already work.

Service boundary: `core/services/routing_intent_service.py` owns every
mutation (add/remove instance, add/remove interface binding, add/remove BGP
neighbor/network), following `interface_intent_service.py`'s shape
precisely -- `require_draft()` gate, `@transaction.atomic`,
ownership-checked lookups (`get_static_route`, `get_protocol_instance`,
`get_interface_binding`, `get_bgp_neighbor`, `get_bgp_network`, all raising
`CollectionOwnershipError` rather than `KeyError`), `MAX_*` bounds, and one
`editor_routing_summary()` presentation builder consumed by both Basic and
Advanced templates.

## 2. Routing namespace schema

```
sections["routing"] = {
    "static_routes": {"route_<id>": {...}},
    "rip":   {"rip_<id>":   {..., "interfaces": {"bind_<id>": {...}}}},
    "ospf":  {"ospf_<id>":  {..., "interfaces": {"bind_<id>": {...}}}},
    "isis":  {"isis_<id>":  {..., "interfaces": {"bind_<id>": {...}}}},
    "eigrp": {"eigrp_<id>": {..., "interfaces": {"bind_<id>": {...}}}},
    "bgp":   {"bgp_<id>":   {..., "neighbors": {"peer_<id>": {...}},
                                   "networks":  {"net_<id>": {...}}}},
}
```

Full per-object field lists are defined in `routing_intent_service.py`:
`STATIC_ROUTE_FIELDS`, `INSTANCE_FIELDS[family]`, `BINDING_FIELDS[family]`,
`BGP_NEIGHBOR_FIELDS`, `BGP_NETWORK_FIELDS`. `_routing_sections()` guarantees
all six sub-namespaces exist as dicts on every read, without disturbing
`interfaces` or any other top-level key already in `sections`.

## 3. Stable routing object IDs

Every repeatable object gets an opaque `uuid4().hex[:16]`-suffixed ID, never
a list index:

| Object | Prefix | Example |
|---|---|---|
| Static route | `route_` | `route_a1b2c3d4e5f60718` |
| RIP instance | `rip_` | `rip_a1b2c3d4e5f60718` |
| OSPF instance | `ospf_` | `ospf_a1b2c3d4e5f60718` |
| IS-IS instance | `isis_` | `isis_a1b2c3d4e5f60718` |
| EIGRP instance | `eigrp_` | `eigrp_a1b2c3d4e5f60718` |
| BGP instance | `bgp_` | `bgp_a1b2c3d4e5f60718` |
| Interface binding (RIP/OSPF/IS-IS/EIGRP) | `bind_` | `bind_a1b2c3d4e5f60718` |
| BGP neighbor | `peer_` | `peer_a1b2c3d4e5f60718` |
| BGP network advertisement | `net_` | `net_a1b2c3d4e5f60718` |

Field-commit paths address objects by these IDs
(`routing.ospf.ospf_x.interfaces.bind_y.area`), so renaming or reordering
never breaks a bound field path, and cross-candidate IDs are always
rejected by the ownership lookups above.

## 4. Deterministic ordering

Every collection (`ordered_static_routes`, `ordered_instances`, per-instance
`interfaces`/`neighbors`/`networks`) sorts by `(int(sequence), id)`, the
same helper shape `ordered_interfaces()` already used. `sequence` is
assigned once at creation (`max(existing) + 1`) and never renumbered on
removal, so accepted-state renders of unchanged intent are byte-identical
across repeated calls -- verified by
`test_phase11_routing_service.DeterministicOrderingTests`.

## 5. Capability registry extension

`platform_drivers.py` gains a second, independent capability dimension:

```
class RoutingProtocol(StrEnum):
    STATIC_IPV4, STATIC_IPV6, RIPV2, RIPNG, OSPFV2, OSPFV3, ISIS,
    EIGRP_IPV4, EIGRP_IPV6, BGP_IPV4, BGP_IPV6

ROUTING_CAPABILITIES: dict[platform][RoutingProtocol] -> PlatformCapability
```

This is a parallel dict to the Phase-10 `PLATFORM_CAPABILITIES` (interfaces)
-- neither is touched by the other, and `capabilities.html` now renders two
independent tables. The same `CapabilityStatus` four states apply:
`SUPPORTED` / `NOT_IMPLEMENTED` / `UNSUPPORTED` / `UNKNOWN`. Only
`SUPPORTED` combinations are selectable for **new** objects
(`is_routing_protocol_selectable()`); existing objects on a since-switched
incompatible platform are preserved and rendered with an explicit
`UNSUPPORTED CANDIDATE OBJECT` comment, never silently dropped.

## 6. Capability evidence model

Every cell in `ROUTING_CAPABILITIES` carries an `evidence` string. Evidence
comes from grepping this repository's own tracked, live-applied
configuration (`templates/*.cfg.j2` cross-checked against `logs/*.log`), not
from generic vendor documentation:

- cEOS: `router rip`, `router ospf 10`, `ipv6 router ospf 10`, `ip ospf
  area`, `router bgp 65005` (R1/R2/S1/S2/R5 templates and logs).
- Ubuntu/FRR: `router ospf` / `ospf router-id`, `router ospf6` / `ospf6
  router-id`, `router bgp 65003` with `address-family ipv4/ipv6 unicast` +
  `exit-address-family` (R3/R4 templates and logs).
- SR Linux, IOS XR 8000v, and SONiC now use authoritative vendor model/CLI/
  ConfigDB documentation and fixture tests, never live claims. Their exact
  implemented subsets are listed below and in the Phase-20.5 audit.
- RIPng is implemented for Ubuntu/FRR. IOS XR RIPng remains model-blocked by
  its documented release/VRF form; SR Linux lacks RIP; SONiC has no verified
  config_db RIP schema. IS-IS remains unimplemented/model-unverified.
- EIGRP is classified `UNSUPPORTED` (not `NOT_IMPLEMENTED`) on cEOS, SR
  Linux, and SONiC -- it is a Cisco-proprietary protocol, a genuine vendor
  mismatch, not merely an unimplemented renderer. On Ubuntu/FRR and IOS
  8000v it is `NOT_IMPLEMENTED` (no eigrpd/EIGRP evidence in this project).
- Static routing on Ubuntu/FRR is marked `SUPPORTED` using standard FRR
  staticd `ip route`/`ipv6 route` syntax (applied via the same `vtysh` path
  this repo's own verified OSPF/BGP FRR config uses) even though R3/R4's
  own tracked templates carry no static route (they only run dynamic
  protocols) -- the evidence string says this explicitly rather than
  overclaiming repository proof it doesn't have.

## 7-8. Static IPv4/IPv6 routes

Model: `family`, `destination` (network syntax, host bits rejected via
`validate_prefix`), `next_hop_type` (`ADDRESS` or `INTERFACE` -- `NULL`/
blackhole is intentionally not modeled; no verified Null0/blackhole syntax
exists in this repository), `next_hop_address` (`validate_ip_host`,
family-matched), `next_hop_interface_id` (candidate-owned, via
`interface_intent_service.get_interface`), `distance` (1-255, optional),
`description`, `tag` (optional), `enabled` (disabling preserves intent
without rendering it). Rendered identically on cEOS and Ubuntu/FRR as
`ip route <dest> <next-hop> [<distance>] [tag <tag>]` /
`ipv6 route ...` -- genuinely the same CLI on both platforms for this
project's evidence, so one shared Python renderer function and one shared
`routing_static_route.j2` template file (present under both
`templates/features/ceos/` and `templates/features/ubuntu_frr/`) back both
drivers.

## 9-10. RIPv2 / RIPng

One `rip` namespace, disambiguated only by `address_family` (`IPV4` =>
RIPv2, `IPV6` => RIPng) -- there is deliberately no `version` field at all,
so RIPv1 cannot be silently enabled even by accident. Interface
participation is a candidate-owned binding (`interface_id` + `passive`).
RIPv2 is supported on cEOS, Ubuntu/FRR, and IOS XR; RIPng is supported on
Ubuntu/FRR. cEOS derives `network <connected-subnet>` from the bound
interface. FRR uses interface activation. IOS XR uses `router rip`, nested
`interface <name>`, and optional nested `passive-interface`. The SR Linux,
IOS XR RIPng, and SONiC blockers are platform/model-specific and documented
in the Phase-20.5 audit.

## 11-13. OSPFv2 / OSPFv3 / interface-area abstraction

One `ospf` namespace per instance, disambiguated by `version`
(`OSPFV2`/`OSPFV3`). Fields: `process_id` (cEOS only -- FRR's `router
ospf`/`router ospf6` take no process number, matching R3/R4 evidence
exactly), `router_id`, `reference_bandwidth`. Interface participation is
**always** modeled as a candidate-owned interface binding
(`interface_id` + `area` + `passive` + `cost` + `network_type` + timers),
never a network statement, per the interface-oriented abstraction the
Phase-10 handoff document required -- renaming a bound interface never
breaks the binding. `area` accepts `0`, dotted-decimal, or 0-4294967295
integer, normalized to canonical dotted-decimal
(`field_validators.validate_area_id`). cEOS renders interface-native
`ip ospf area <area>` / `ipv6 ospf <process> area <area>` (matching R1/R2
evidence exactly); FRR renders the equivalent `ip ospf area <area>` /
`ipv6 ospf6 area <area>` inside its own `interface <name>` vtysh stanza
(distinct from the Linux `ip link`/`ip addr` stanza Phase 10 already
renders for the same interface).

## 14. IS-IS

Modeled structurally (`net`, `level` enum, `address_family_ipv4`/`_ipv6`
booleans, interface bindings with `passive`/`metric`) because zero
repository evidence exists for IS-IS on any platform. `NET` gets real
Tier-1 syntax validation (`validate_isis_net`: dot-separated hex groups,
8-20 bytes total) but no network-wide uniqueness claim. IS-IS is
`NOT_IMPLEMENTED` on every platform today -- structurally representable,
never fabricated.

## 15. EIGRP

Modeled structurally (`asn`, `router_id`, `address_family`, interface
bindings with `passive`) but classified honestly: `UNSUPPORTED` on cEOS/SR
Linux/SONiC (Cisco-proprietary, a genuine vendor mismatch), `NOT_IMPLEMENTED`
on Ubuntu/FRR and IOS 8000v (no eigrpd/EIGRP evidence in this project). No
stub/authentication/variance/redistribution fields are modeled.

## 16-22. BGP architecture, instances, neighbors, address families, advertisements, Basic/Advanced editors

One `bgp` namespace per instance (`local_asn`, `router_id`), each holding
two nested collections: `neighbors` (`peer_address`, `family` derived from
the address and kept consistent with it on every commit, `remote_asn`,
`description`, `activate_ipv4`/`activate_ipv6`,
`update_source_interface_id` (candidate-owned), `ebgp_multihop`,
`next_hop_self`, `route_reflector_client`, `shutdown`, `password_ref`) and
`networks` (`family`, `cidr`). Basic exposes local ASN, router ID, peer
address, remote ASN, IPv4/IPv6 activation, description, and advertised
networks; Advanced adds update-source, eBGP multihop, next-hop-self,
route-reflector-client, and shutdown -- all on the exact same underlying
objects (`editor_routing_summary()` builds one presentation view consumed
by both templates; nothing is duplicated per mode).

Rendering: cEOS emits `address-family ipv4`/`ipv6` (no `unicast` keyword,
matching R5 evidence exactly); Ubuntu/FRR emits `address-family ipv4/ipv6
unicast` closed with `exit-address-family` (matching R3/R4 evidence
exactly) -- genuinely different, real CLI, never blurred into one shared
template.

## 23. Secret-reference policy

BGP neighbor authentication is modeled as `password_ref` only -- there is
no `password` field anywhere in `BGP_NEIGHBOR_FIELDS`, so a raw secret
cannot even be committed through this object. `password_ref` is validated
by `field_validators.validate_secret_ref` (a bounded, safe-character
label, same shape as `validate_bounded_label`) and its `_ref` suffix means
`secret_policy.py`'s existing denylist-with-`*_ref`-exemption already
treats it correctly with no code change needed there. The renderer never
prints the reference as though it were a password command -- it emits an
honest comment (`! neighbor <peer> authentication reference present
(<ref>); unresolved for deployment`).

## 24. Basic/Advanced synchronization

Basic and Advanced both call the same `_editor_view()` ->
`routing_intent_service.editor_routing_summary()` -> same `sections["routing"]`
data -- there is no `AdvancedBGP`/`AdvancedOSPF` model or copy of state. A
field committed in Advanced is immediately visible in Basic and vice versa,
proven by `test_phase11_ospf.OspfServiceTests.test_basic_and_advanced_share_same_instance`.

## 25. Candidate rendering

`candidate_renderer.py` gains `_routing_from_sections()`, structurally
identical to the Phase-10 `_interfaces_from_sections()` -- it deep-copies
`sections["routing"]` and overlays draft/accepted `IntentFieldState` values
by path, so accepted and draft renders share one object model.
`PlatformDriver.render_candidate()` now calls `self.render_routing(field_values,
routing, interfaces)` after interfaces and before the (still Phase-12+)
Services/Security "not configured" lines. There is exactly one authoritative
renderer -- no `routing_preview_renderer` or any second renderer exists
anywhere, and the JS contract tests prove `device_builder.js` contains no
routing CLI keywords at all.

## 26. Reusable routing feature templates

Additive files only, following the exact `templates/features/<platform>/<feature>.j2`
naming convention Phase 10 established:

```
templates/features/ceos/routing_static_route.j2
templates/features/ceos/routing_rip.j2
templates/features/ceos/routing_ospfv2.j2
templates/features/ceos/routing_ospfv3.j2
templates/features/ceos/routing_bgp.j2
templates/features/ubuntu_frr/routing_static_route.j2
templates/features/ubuntu_frr/routing_ospfv2.j2
templates/features/ubuntu_frr/routing_ospfv3.j2
templates/features/ubuntu_frr/routing_bgp.j2
```

Each template renders only the protocol-instance **header** (the scalar
fields with real cross-cutting reusability -- `router ospf`/`router bgp`
lines, `router-id`), via the unchanged `feature_template_renderer.py`
marker-substitution mechanism. Repeatable nested rows (interface bindings,
BGP neighbors, BGP networks) are built as direct Python descriptor lists,
the same approach `_address_descriptors()`/`_wan_descriptors()` already use
instead of Jinja for naturally tabular per-row data -- each row needs its
own field-path marker for live per-row preview binding, which one Jinja
loop cannot express through the single-marker-per-line contract
`feature_template_renderer.render_descriptors()` enforces. Unimplemented
families still have no renderer; SR Linux, IOS XR, and SONiC now have
platform-specific fixture-tested renderers for the subsets below.

## 27. Platform support matrix

See the table in section 6 above and the live matrix at
`/device-builder/capabilities/` (second table, "Routing Protocol
Capabilities").

## 28-32. Per-platform status

- **cEOS**: SUPPORTED for static IPv4/IPv6, RIPv2, OSPFv2, OSPFv3, BGP
  IPv4/IPv6, and IS-IS (process plus interface bindings; see
  `docs/V2_IPV6_ISIS_ACCESS_REDUNDANCY.md`). NOT_IMPLEMENTED for RIPng.
  UNSUPPORTED for EIGRP.
- **Ubuntu/FRR**: SUPPORTED for static IPv4/IPv6, RIPv2, RIPng, OSPFv2,
  OSPFv3, and BGP IPv4/IPv6. IS-IS/EIGRP remain unimplemented.
- **SR Linux**: fixture-tested static IPv4/IPv6, OSPFv2/v3, and BGPv4/v6;
  RIP/EIGRP unsupported and IS-IS model mapping unverified. Not live tested.
- **IOS XR 8000v**: fixture-tested static IPv4/IPv6, RIPv2, OSPFv2/v3, and
  BGPv4/v6. RIPng/IS-IS/EIGRP remain model/release blocked. Not live tested.
- **SONiC**: fixture-tested config_db static IPv4/IPv6 and BGPv4/v6. RIP,
  OSPF, and IS-IS lack a verified target config_db schema; EIGRP is
  unsupported. Not live tested.

## 33. Tier-1 validation

Every routing validator in `field_validators.py`
(`validate_as_number`, `validate_router_id`, `validate_area_id`,
`validate_isis_net`, `validate_distance`, `validate_metric`,
`validate_secret_ref`, plus reused `validate_ip_host`/`validate_prefix`/
`validate_bool`) answers only "is this value structurally/syntactically
possible," exactly like every Phase-9 validator. Every accepted value's
message says "Syntax accepted; project validation pending" (or an
equivalent honest qualifier) -- never "validated configuration."

## 34. Explicit Phase-13 validation boundary

Not implemented, and not claimed, in Phase 11: peer-device existence,
remote-AS/peer consistency, next-hop reachability, network-statement-to-
connected-prefix matching, OSPF adjacency formation or area-design
validity, duplicate router-ID detection, route collision/loop analysis,
VRF relationship validity, topology-wide protocol support, or
project-wide policy-reference validity. All of that is explicitly reserved
for Phase 13.

## 35. No redistribution / route-policy overclaim

No redistribution intent is modeled at all in Phase 11 (Option A from the
spec: not exposed yet, rather than a half-built, loop-risking structure).
No route-map/prefix-list/route-policy object exists anywhere in the schema,
validators, or renderer; `test_phase11_bgp.BgpRenderingTests.test_no_route_policy_fabrication`
asserts none of that text ever appears in rendered output.

## 36. Interface stable-ID references

Every routing-to-interface reference (`next_hop_interface_id`, every
binding's `interface_id`, `update_source_interface_id`) stores the
candidate-owned interface's stable `if_*` ID and is checked against
`interface_intent_service.get_interface(revision, id)` at validation time.
Binding `interface_id` is set once at creation (removing and re-adding the
binding is how you change it, mirroring how WAN metadata is scoped to one
interface for its lifetime) -- every other referencing field remains
editable and re-validated on every commit.

## 37. Future Configlet mapping

Phase 8's `Configlet` model is untouched; Phase 11 creates none. The
likely future (Phase 14+) mapping, informational only:

| Routing object | Future Configlet action |
|---|---|
| Static route | DEFINE |
| RIP/OSPF/IS-IS/EIGRP instance | DEFINE |
| Protocol interface binding | ACTIVATE/ATTACH |
| BGP instance | DEFINE |
| BGP neighbor | DEFINE |
| BGP address-family activation | ACTIVATE |
| BGP network advertisement | DEFINE |

## 38. No deployment

No Netmiko/Paramiko/SSH/subprocess call exists anywhere in
`routing_intent_service.py`, `field_registry.py`, `field_validators.py`,
`platform_drivers.py`, `candidate_renderer.py`, `feature_template_renderer.py`,
or the new routing views -- enforced by
`test_phase11_architecture.Phase11ArchitectureTests.test_routing_modules_have_no_live_device_or_git_imports`.
The Change never leaves `DRAFT` (`test_change_stays_draft_and_no_configlet_created`).

## 39. Security

- Every collection mutation is `@require_POST`, CSRF-protected (Django's
  standard `{% csrf_token %}` + `X-CSRFToken` contract, unchanged), and
  DRAFT-only (`require_draft()`).
- Every routing field path is resolved through six families of strict,
  anchored regexes in `field_registry.py` (`_ROUTE_PATH_RE`,
  `_RIP_INSTANCE_PATH_RE`/`_RIP_BINDING_PATH_RE`, similarly for
  ospf/isis/eigrp, `_BGP_INSTANCE_PATH_RE`/`_BGP_NEIGHBOR_PATH_RE`/
  `_BGP_NETWORK_PATH_RE`) -- never a generic JSON-path mutator, never
  `eval()`, never `setattr` from a browser-supplied attribute name.
- Every extracted object ID is looked up inside the *specific* revision the
  request resolved to; an ID from another candidate is always rejected
  with `CollectionOwnershipError` -> HTTP 403.
- All strings are bounded (`validate_bounded_label`, `validate_secret_ref`);
  Django's template auto-escaping (unchanged) prevents stored-XSS through
  any routing description/label field.
- No plaintext routing authentication secret can be persisted -- see
  section 23.

## 40. Known limitations

- Static routes model `ADDRESS`/`INTERFACE` next hops only; `NULL`/
  blackhole routes are not modeled (no verified syntax evidence).
- RIP exposes no redistribution or authentication.
- OSPF authentication is not modeled at all (deferred to a later security
  phase, as the original spec explicitly allows).
- IS-IS and EIGRP are structurally complete but unimplemented on every
  current platform -- purely honest classification, not a gap to "fix"
  without new evidence.
- BGP models one flat set of Basic/Advanced fields; no route-reflector
  topology inference, no policy objects, no VRF-scoped BGP.
- `MAX_PROTOCOL_INSTANCES_PER_FAMILY = 4`, `MAX_INTERFACE_BINDINGS_PER_INSTANCE = 64`,
  `MAX_BGP_NEIGHBORS_PER_INSTANCE = 32`, `MAX_BGP_NETWORKS_PER_INSTANCE = 64`,
  `MAX_STATIC_ROUTES_PER_REVISION = 64` are lab-scale bounds, documented
  here as the authoritative limits.

## 41. Phase-12 handoff

Routing intent now exists end-to-end (schema, capability matrix, Tier-1
validation, one-renderer dispatch, Basic/Advanced UI) for static routing,
RIPv2/RIPng, OSPFv2/OSPFv3, IS-IS, EIGRP, and BGP. Services and Security
remain the two still-locked Device Builder modules. Phase 12 should reuse
this exact pattern (structured `sections` sub-namespace, stable IDs,
capability matrix, Tier-1 validators, one renderer, additive feature
templates) rather than inventing new architecture, exactly as Phase 11
reused Phase 10's.
