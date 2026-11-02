# Phase 13 — Tier-2 Project-Aware Change Validation and Semantic Dependencies

This document describes the Python-owned **Tier-2 project-aware validation
engine** introduced in Phase 13. It validates an entire structured Change
against the broader project state and produces machine-readable findings,
derived facts, and a semantic dependency graph for Phase 14. It does **not**
deploy, plan execution, write NetBox, write Git, run CI, create Configlets,
or contact any device.

Contents: 1 Tier-1 vs Tier-2 · 2 Architecture · 3 Whole-Change scope ·
4 Accepted-only snapshot · 5 Run model · 6 Result vocabulary · 7 Stale
semantics · 8 Finding schema · 9 Finding codes · 10 Provenance · 11 Input
hashing · 12 Source hashing · 13–16 Sources · 17 Source failure ·
18–22 Addressing · 23–24 AUTO · 25–27 Links · 28–31 Routing ·
32 FHRP · 33 NAT · 34 DHCP/DNS · 35 ACL · 36 PBR · 37–40 Dependency graph ·
41 Derived facts · 42 Determinism · 43–45 UI/history/report · 46 Audit ·
47 Security · 48–49 No device access / no deployment · 50 Phase-14 handoff ·
Known limitations.

## 1. Tier-1 versus Tier-2

| | Tier 1 (Phases 9–12) | Tier 2 (this phase) |
|---|---|---|
| Question | "Is this individual field syntactically acceptable?" | "Given this whole Change and the authoritative project state available now, is the accepted intent internally and project-wide coherent enough to proceed to deployment planning?" |
| Unit | one field | the **entire Change** (all DeviceIntents together) |
| When | on explicit field commit (Enter) | only on the explicit operator action **Run Change Validation** — an explicit POST with CSRF (never on keypress, field commit, editor load, a timer, a NetBox change, or a topology refresh) |
| Evidence | the value itself | accepted intent + NetBox + topology + inventory + the capability registry |
| Owner | `field_validators.py` | `core/services/validation/` |

Tier 2 does **not** answer "will deployment definitely succeed?". No device is
contacted, no running configuration is read, and a `PASS` is a statement about
project-level coherence of committed intent — nothing more.

## 2. Architecture

```
                    Change
                      |
                      v
          Accepted DeviceIntent State   (candidate_renderer.hydrate_state, use_draft=False)
                      |
                      v
             Python Tier-2 Engine        core/services/validation/engine.py
          /        |        |        \
     NetBox     Topology  Inventory  Capabilities
   READ ONLY    READ ONLY  READ ONLY  SAME REGISTRY (platform_drivers.py)
          \        |        |        /
                      v
   ChangeValidationRun (append-only): findings, derived facts, dependency graph
                      |
                      v
                 Django UI  ->  Phase 14 planner
```

**NetBox is passive storage only.** It never validates, decides collisions,
reconciles, allocates, approves, or triggers anything. All intelligence is
Python. The package layout (one concern per module):

| Module | Concern |
|---|---|
| `findings.py` | vocabulary, stable codes, `Finding`, bounded/redacted serialization, status derivation |
| `snapshot.py` | deterministic accepted-intent snapshot, SHA-256, revision map |
| `sources.py` | read-only NetBox/topology/inventory/capability adapters + fingerprints |
| `context.py` | parsed project model shared by every validator |
| `capabilities.py` | capability + renderer-consistency + platform-identity validation |
| `addressing.py` | duplicates, NetBox collisions, DHCP pools, reservations, VLAN 200, AUTO derivation |
| `topology.py` | link / VLAN / MTU cross-endpoint checks |
| `routing.py` | static / OSPF / RIP / BGP / router-ID |
| `composition.py` | normalized-scope merge conflicts before planning |
| `fhrp.py` | FHRP / VARP domain checks |
| `services_policy.py` | NAT / DHCP relay / DNS / PBR |
| `acl.py` | conservative ACL first-match traffic-impact analysis |
| `dependency_graph.py` | semantic dependency graph, missing edges, cycles |
| `engine.py` | orchestration, isolation, status, determinism |

`core/services/change_validation_service.py` is the reusable API
(`build_change_snapshot`, `build_source_snapshot`, `validate_change`,
`get_validation_currency`, `get_latest_validation`, `serialize_validation_run`,
plus `get_validation_run`, `list_validation_runs`, `filter_findings`,
`dependency_rows`). Phase 14 calls this module directly, without HTTP.
Django views resolve the Change, call the service, and render — no collision
loop, BGP matching, ACL evaluation, or graph construction lives in a view.

## 3. Whole-Change scope

A Change may contain several DeviceIntents (R1, R2, S1, S2 ...). They are
validated **together**. Cross-device analysis is essential for duplicate IPs,
point-to-point addressing, VLAN/link consistency, OSPF relationships, BGP peer
pairing, FHRP domains, DHCP conflicts, and dependencies.

## 4. Accepted-only snapshot

Validation uses **committed/accepted intent only**. The snapshot is built from
`candidate_renderer.hydrate_state(intent, revision, use_draft=False)` — the
*same* hydration the one Python renderer uses — so the renderer and the
validator can never disagree about what "accepted" means. Browser
`draftValue`s and uncommitted `IntentFieldState.draft_value`s are excluded.
The validation page says so explicitly: *"Project validation uses
committed/accepted intent only."* Keystrokes are never persisted to work
around this.

Canonicalization: devices ordered by name; stable object IDs kept; dictionary
key order irrelevant; the display-only `sequence` is dropped **except** where
order is semantic (ACL entries, PBR sequences); VLAN sets are sorted. Secret-
shaped keys (not `*_ref` references) are replaced by `[REDACTED]`, so a manual
database edit cannot leak a value into a snapshot or report. `*_ref` keys are
kept as safe references.

## 5. Validation run model

One new model, `ChangeValidationRun` (migration `0003_phase13_change_validation_run`,
one `CreateModel`, plus a label-only `AuditEvent.event_type` choices update):

`run_id` (UUID), `change` (FK), `status`, `engine_version`, `input_hash`,
`source_hash`, `repository_head`, `created_at`, `created_by`, `summary`,
`report`, `derived_facts`, `dependency_graph`, `intent_revision_map`,
`source_provenance` (all sanitized JSON on **one immutable row** — there is no
per-finding table).

Runs are **append-only**: created finished, never modified
(`_forbid_row_mutation`), and the status vocabulary is enforced in `save()`.
A later intent edit, a NetBox change, or an operator re-run creates a **new**
run; old evidence remains historical. Validation status and Change lifecycle
are separate: a run never changes `Change.lifecycle_state` or
`Change.validation_state`, never sets `VALIDATED`/`READY_TO_DEPLOY`, and
publishes no notification.

## 6. Result vocabulary

| Result | Meaning |
|---|---|
| `PASS` | every required check completed; no blocking finding; no warning |
| `PASS_WITH_WARNINGS` | all required evidence available; no blocking finding; ≥ 1 non-blocking warning |
| `BLOCKED` | ≥ 1 concrete finding means the Change must not proceed to planning as represented |
| `INCOMPLETE` | required authoritative evidence was unavailable, unverifiable, or insufficient |

Derivation is purely from findings: `BLOCKED` > `INCOMPLETE` >
`PASS_WITH_WARNINGS` > `PASS`. INFO findings never prevent `PASS`. A source
failure or an unexpected validator exception can **never** surface as `PASS`.
When a Change is both blocked and has an evidence gap the result is `BLOCKED`
and the gap is still listed (`summary.incomplete_findings`).

## 7. Stale semantics

`STALE` is a **currency state**, not a fifth result.

| Currency | Meaning |
|---|---|
| `NEVER_RUN` | no run exists |
| `CURRENT` | the accepted-snapshot SHA-256 equals the latest run's (and, if checked, no consumed source changed) |
| `STALE` | accepted intent changed, or a consumed source changed / became unverifiable, or the engine version changed |

Example display: *Validation state: STALE · Last completed result: PASS ·
Re-run required.* A stale `PASS` is **not** current authorization. Intent
staleness is always evaluated (cheap, local). External-source staleness reads
NetBox/topology, so it runs only on request (`?check_sources=1`, a read-only
GET that persists nothing) or when a `sources` bundle is passed to the
service. A draft-only edit never makes a run stale.

## 8. Finding schema

Every finding is machine-readable:

`finding_id` (stable hash), `code`, `severity` (`ERROR`/`WARNING`/`INFO`),
`category`, `message`, `blocking`, `incomplete` (an evidence gap that keeps the
result from being `PASS`), `device`, `object_type`, `object_id`, `field_path`,
`related_devices`, `related_objects`, `source`, `evidence` (bounded, redacted
JSON), `remediation`. Categories: `SOURCE INTERNAL PLATFORM ADDRESSING
INTERFACE TOPOLOGY ROUTING FHRP NAT DHCP DNS ACL PBR DEPENDENCY`. Strings are
clipped to 400 characters, lists to 40 items, nesting to 4 levels, the list of
findings to 400 (with an explicit `REPORT_TRUNCATED`), and secret-shaped
evidence keys are `[REDACTED]`.

## 9. Finding codes

Codes are stable constants (`findings.CODE_CATALOG`); an unknown code is
rejected at construction. Severity may be softened per finding (an `ERROR`
code softened to `WARNING` is never blocking).

| Code | Category | Default severity | Blocking | Evidence gap | Meaning |
|---|---|---|---|---|---|
| `SOURCE_NETBOX_UNAVAILABLE` | SOURCE | ERROR | no | yes | NetBox could not be read; NetBox-dependent evidence is missing. |
| `SOURCE_TOPOLOGY_UNAVAILABLE` | SOURCE | ERROR | no | yes | Topology metadata could not be read; link adjacency was not evaluated. |
| `SOURCE_INVENTORY_UNAVAILABLE` | SOURCE | ERROR | no | yes | The fixed project inventory could not be read. |
| `PLATFORM_FEATURE_UNSUPPORTED` | PLATFORM | ERROR | yes | no | Registry: the platform cannot implement this object (known limitation). |
| `PLATFORM_FEATURE_NOT_IMPLEMENTED` | PLATFORM | ERROR | yes | no | Registry: the platform supports it but the project has no authoritative renderer. |
| `PLATFORM_FEATURE_UNKNOWN` | PLATFORM | ERROR | no | yes | Registry: capability is unverified; planning must not proceed. |
| `PLATFORM_RENDERER_INCONSISTENT` | PLATFORM | ERROR | yes | no | Registry and authoritative renderer disagree about an object. |
| `PLATFORM_INVENTORY_MISMATCH` | PLATFORM | ERROR | yes | no | Intent platform differs from the fixed project inventory platform. |
| `DEVICE_NOT_IN_INVENTORY` | PLATFORM | WARNING | no | no | Existing-device intent names a device unknown to inventory/topology. |
| `INTENT_REVISION_MISSING` | INTERNAL | ERROR | yes | no | A DeviceIntent has no candidate revision, so nothing accepted exists to validate. |
| `IP_DUPLICATE` | ADDRESSING | ERROR | yes | no | The same host address is assigned to more than one candidate interface. |
| `IP_NETBOX_COLLISION` | ADDRESSING | ERROR | yes | no | A candidate host address is already assigned to another NetBox object. |
| `IP_DHCP_POOL_CONFLICT` | ADDRESSING | ERROR | yes | no | A static candidate address falls inside an active dynamic DHCP pool. |
| `IP_RESERVATION_CONFLICT` | ADDRESSING | ERROR | yes | no | A candidate address conflicts with a reservation owned by another identity. |
| `AUTO_IP_UNRESOLVED` | ADDRESSING | ERROR | yes | no | An AUTO address has no resolvable NetBox prefix. |
| `AUTO_IP_NO_AVAILABLE_ADDRESS` | ADDRESSING | ERROR | yes | no | No free host address remains in the selected prefix. |
| `ADDRESS_INVALID` | ADDRESSING | ERROR | yes | no | A persisted candidate address is not a valid interface address. |
| `ADDRESS_FAMILY_MISMATCH` | ADDRESSING | ERROR | yes | no | A persisted address family does not match its address literal. |
| `LINK_PREFIX_MISMATCH` | TOPOLOGY | ERROR | yes | no | The two ends of a direct routed link do not share a subnet. |
| `LINK_MODE_MISMATCH` | TOPOLOGY | WARNING | no | no | The two ends of a link use modes whose compatibility is ambiguous. |
| `LINK_ACCESS_VLAN_MISMATCH` | TOPOLOGY | ERROR | yes | no | Two access ports of one link carry different VLANs. |
| `LINK_NATIVE_VLAN_MISMATCH` | TOPOLOGY | ERROR | yes | no | Two trunk ports of one link use different native VLANs. |
| `LINK_TRUNK_VLAN_MISSING` | TOPOLOGY | ERROR | yes | no | A trunk link does not carry a VLAN the design concretely requires. |
| `LINK_MTU_MISMATCH` | TOPOLOGY | WARNING | no | no | The two ends of a direct link use different MTUs. |
| `VLAN_NOT_IN_NETBOX` | INTERFACE | WARNING | no | no | A referenced VLAN ID is not modeled in NetBox. |
| `TOPOLOGY_DEVICE_UNKNOWN` | TOPOLOGY | WARNING | no | no | A Change device is not present in the topology source. |
| `ROUTER_ID_DUPLICATE` | ROUTING | ERROR | yes | no | Two devices use the same router ID where uniqueness is required. |
| `BGP_PEER_UNRESOLVED` | ROUTING | WARNING | no | no | A BGP neighbor address maps to no project-known interface. |
| `BGP_REMOTE_AS_MISMATCH` | ROUTING | ERROR | yes | no | Configured remote ASN differs from the peer's local ASN. |
| `BGP_AF_MISMATCH` | ROUTING | ERROR | yes | no | Both BGP peers are candidate-controlled but share no address family. |
| `BGP_PEER_NO_RECIPROCAL` | ROUTING | WARNING | no | no | The resolved peer device has no neighbor pointing back. |
| `BGP_NETWORK_NO_EVIDENCE` | ROUTING | WARNING | no | no | An advertised prefix has no matching connected/static evidence. |
| `OSPF_AREA_MISMATCH` | ROUTING | ERROR | yes | no | Both ends of a link run OSPF in different areas. |
| `OSPF_VERSION_MISMATCH` | ROUTING | ERROR | yes | no | The two ends of a link run different OSPF versions. |
| `OSPF_NETWORK_TYPE_MISMATCH` | ROUTING | WARNING | no | no | Both ends set different OSPF network types. |
| `OSPF_ONE_SIDED` | ROUTING | INFO | no | no | Only one end of a link participates in OSPF. |
| `OSPF_PROCESS_ID_REQUIRED` | ROUTING | ERROR | yes | no | A cEOS OSPF candidate is missing its required process ID. |
| `ROUTING_INTERFACE_NO_ADDRESS` | ROUTING | WARNING | no | no | A routing interface binding has no address of the needed family. |
| `RIP_FAMILY_MISMATCH` | ROUTING | WARNING | no | no | Both ends of a link run RIP for different address families. |
| `ROUTE_FAMILY_MISMATCH` | ROUTING | ERROR | yes | no | A static route mixes address families. |
| `ROUTE_NEXT_HOP_SELF` | ROUTING | ERROR | yes | no | A static route's next hop is the device's own address. |
| `ROUTE_NEXT_HOP_UNRESOLVED` | ROUTING | WARNING | no | no | A static route next hop is not in a known connected network. |
| `ROUTE_EXIT_INTERFACE_IMPLAUSIBLE` | ROUTING | WARNING | no | no | A static route exits through a layer-2-only interface. |
| `FHRP_VIP_CONFLICT` | FHRP | ERROR | yes | no | A virtual IP collides with another FHRP domain or an ordinary address. |
| `FHRP_GROUP_MISMATCH` | FHRP | ERROR | yes | no | Peers of one intended FHRP domain disagree on group or VIP set. |
| `FHRP_VIRTUAL_MAC_MISMATCH` | FHRP | ERROR | yes | no | Virtual MAC differs inside one shared VARP domain. |
| `FHRP_PRIORITY_DUPLICATE` | FHRP | WARNING | no | no | Peers of one FHRP domain use the same priority. |
| `FHRP_VIP_OFF_SUBNET` | FHRP | WARNING | no | no | A VIP is outside every candidate subnet of its interface. |
| `NAT_INTERFACE_ROLE_CONFLICT` | NAT | ERROR | yes | no | A NAT rule uses one interface as both inside and outside. |
| `NAT_POOL_CONFLICT` | NAT | ERROR | yes | no | A NAT pool is family-incompatible, overlapping, or holds protected addresses. |
| `NAT_FAMILY_MISMATCH` | NAT | ERROR | yes | no | A NAT rule mixes address families. |
| `NAT_ROLE_UNVERIFIED` | NAT | INFO | no | no | Inside/outside directionality could not be proven from topology metadata. |
| `DHCP_VLAN200_FORBIDDEN` | DHCP | ERROR | yes | no | VLAN 200 management addressing must remain static. |
| `DHCP_POOL_OVERLAP` | DHCP | WARNING | no | no | NetBox DHCP pool state has a pre-existing safety problem. |
| `DHCP_RELAY_UNRESOLVED` | DHCP | WARNING | no | no | A DHCP relay destination is not a project-known service address. |
| `DHCP_RELAY_FAMILY_MISMATCH` | DHCP | ERROR | yes | no | A DHCP relay destination family differs from the relay family. |
| `DNS_RESOLVER_UNRESOLVED` | DNS | WARNING | no | no | A DNS resolver address is not a project-known service address. |
| `ACL_REQUIRED_FLOW_DENIED` | ACL | ERROR | yes | no | An explicit ACL deny provably blocks a required flow. |
| `ACL_EFFECT_UNKNOWN` | ACL | WARNING | no | no | The ACL effect on a required flow cannot be proven. |
| `ACL_ENTRY_SHADOWED` | ACL | WARNING | no | no | An ACL entry can never match because an earlier entry covers it. |
| `ACL_DUPLICATE_ATTACHMENT` | ACL | WARNING | no | no | More than one ACL is attached to one interface/direction/family. |
| `PBR_NEXT_HOP_UNRESOLVED` | PBR | WARNING | no | no | A PBR next hop is not in a known connected network. |
| `RAW_TARGET_UNKNOWN` | RAW | ERROR | yes | no | A Raw Configlet targets a device that has no Device Intent in this Change. |
| `RAW_PLATFORM_MISMATCH` | RAW | ERROR | yes | no | The target device's platform differs from the platform the Raw Configlet revision was authored and verified for. |
| `RAW_VERIFIER_UNAVAILABLE` | RAW | ERROR | yes | no | The platform has no supported raw verification path. |
| `RAW_NOT_VERIFIED` | RAW | ERROR | yes | no | The Raw Configlet revision has never been verified. |
| `RAW_VERIFICATION_STALE` | RAW | ERROR | yes | no | The Raw Configlet verification is STALE (content, platform, policy, verifier or backend changed). |
| `RAW_VERIFICATION_BLOCKED` | RAW | ERROR | yes | no | The Raw Configlet verification is BLOCKED (static policy or the platform parser rejected it). |
| `RAW_VERIFICATION_INCOMPLETE` | RAW | ERROR | no | yes | The Raw Configlet verification is INCOMPLETE (the sandbox could not complete it); nothing was verified. |
| `RAW_VERIFICATION_WARNINGS` | RAW | WARNING | no | no | The Raw Configlet verification passed with warnings. |
| `RAW_PRIORITY_INVALID` | RAW | ERROR | yes | no | A Raw Configlet priority is not one of the nine canonical deployment priorities. |
| `RAW_DEPENDENCY_SELF` | RAW | ERROR | yes | no | A Raw Configlet declares a dependency on itself. |
| `RAW_EXECUTION_NOT_SUPPORTED` | RAW | WARNING | no | no | The platform can verify but not execute Raw Configlets; a plan containing it cannot be executed. |
| `REMOVAL_TARGET_UNKNOWN` | REMOVAL | ERROR | yes | no | A removal targets a device that is not a target of this Change. |
| `REMOVAL_EMPTY` | REMOVAL | ERROR | yes | no | A removal selection resolves to nothing. |
| `REMOVAL_BLOCKED` | REMOVAL | ERROR | yes | no | Partial context, a protected object, or a dependency that stays (re-derived from the persisted snapshot). |
| `REMOVAL_NOT_EXECUTABLE` | REMOVAL | ERROR | yes | no | The removal form is fixture-only / not implemented on the platform; previewable, never executable. |
| `REMOVAL_NOT_RESTORABLE` | REMOVAL | WARNING | no | no | A removed object carries redacted values; exact compensation is not provable, so Complete mode refuses it. |
| `REMOVAL_POLICY_CHANGES` | REMOVAL | WARNING | no | no | One entry of a still-referenced ACL / prefix-list / route-map is removed. |
| `REMOVAL_PROPOSAL_AVAILABLE` | REMOVAL | INFO | no | no | The removal leaves an object unused; it is proposed, never added automatically. |
| `MGMT_VRF_PLATFORM_UNSUPPORTED` | MANAGEMENT | ERROR | yes | no | No management-VRF renderer exists for this platform; select a supported platform or remove the intent. |
| `MGMT_VRF_REFERENCE_INVALID` | MANAGEMENT | ERROR | yes | no | A binding, route or service refers to a missing VRF; correct its candidate-local reference. |
| `MGMT_INTERFACE_REFERENCE_INVALID` | MANAGEMENT | ERROR | yes | no | A management object refers to a missing interface; select an interface in this candidate revision. |
| `MGMT_BINDING_INVALID` | MANAGEMENT | ERROR | yes | no | The binding targets a non-L3 interface; use an eligible routed interface, SVI, subinterface, loopback or management interface. |
| `MGMT_BINDING_NO_ADDRESS` | MANAGEMENT | ERROR | yes | no | A bound interface has no address; supply an authorized management address before planning. |
| `MGMT_VRF_UNBOUND` | MANAGEMENT | ERROR | yes | no | The VRF has no interface; bind an eligible addressed interface. |
| `MGMT_VRF_NO_ACCESS_SERVICE` | MANAGEMENT | ERROR | yes | no | No SSH/API access service is enabled in the VRF; add a platform-supported management service. |
| `MGMT_ROUTE_NEXT_HOP_UNREACHABLE` | MANAGEMENT | ERROR | yes | no | The route's next hop is outside every bound interface subnet; correct the on-link next hop or binding/address intent. |
| `MGMT_VRF_FEATURE_UNSUPPORTED` | MANAGEMENT | ERROR | yes | no | The platform cannot render this specific management object; remove it or use an evidenced renderer. |
| `MGMT_VRF_MOVES_MANAGEMENT_ADDRESS` | MANAGEMENT | ERROR | yes | no | Binding the current management address would cut the existing session; first establish and verify an independent management path, then use a later governed Change. |
| `MGMT_VRF_EXECUTION_NOT_IMPLEMENTED` | MANAGEMENT | WARNING | no | no | Rendering and validation exist but execution does not; planning is possible, while the execution capability gate still refuses application. |
| `DEPENDENCY_MISSING` | DEPENDENCY | ERROR | yes | no | An object references a stable ID that does not exist. |
| `DEPENDENCY_CYCLE` | DEPENDENCY | ERROR | yes | no | The semantic dependency graph contains a cycle. |
| `CANDIDATE_COMPOSITION_CONFLICT` | DEPENDENCY | ERROR | yes | no | Incompatible contributions claim one single-valued configuration-scope property. |
| `INTERNAL_VALIDATION_ERROR` | INTERNAL | ERROR | no | yes | A validator failed unexpectedly; its checks did not complete. |
| `REPORT_TRUNCATED` | INTERNAL | WARNING | no | no | The finding list exceeded the report bound and was truncated. |

The catalogue includes Raw Configlet and management-VRF findings. See `docs/RAW_CONFIGLETS_AND_SANDBOX.md` and
`docs/evidence/v2-phase4-management/README.md` for their evidence boundaries. Management validation reads accepted intent
and fixed source data; it does not probe a device, prove reachability or authorize a new physical/routed path. Those
requirements remain with approved attachment evidence and the management-path verifier. A render/validate-only warning
never promotes a platform or service to live execution support.

## 10. Provenance

Every run records: repository HEAD (read-only, via the existing `nsot_git`
adapter; provenance only), NetBox fingerprint, topology fingerprint, inventory
fingerprint, capability-registry fingerprint, engine version, report schema
version, snapshot schema version, the accepted-snapshot `input_hash`, the
`source_hash`, a per-device intent revision map, and a `semantic_digest` of the
result. No credential is ever hashed into provenance.

## 11. Input hashing

`input_hash` = SHA-256 over the canonical JSON of the accepted snapshot. The
same accepted intent always yields the same hash; a different accepted intent
yields a different hash. `updated_at` is deliberately **not** used. Only the
**content** is hashed: the Change ID and revision *numbers* are provenance, so
a new revision with identical content does not stale a validation.

## 12. Source hashing

`source_hash` = SHA-256 over `{engine version, netbox, topology, inventory,
capability}` fingerprints. Repository HEAD is excluded (an unrelated commit
must not invalidate a validation). An unavailable source has the distinct
fingerprint `UNAVAILABLE`. The topology fingerprint covers only nodes and link
endpoints (MAC/management-address noise from a redeploy is ignored).

## 13. NetBox source

Read-only. `nsot_netbox.project_facts()` (added to the existing Phase-7
adapter — no second client or auth path) gathers, with **six batched list
queries**, normalized facts: tagged IP assignments (device/interface/role),
prefixes (VLAN, `dhcp_relay_targets`), VLAN IDs, DHCP ranges, interface
assignment-mode custom fields (reservation state), and device names. The
heavier `ipam_context.get_address_reservations()` / `get_dhcp_pool_context()`
were measured at about 49 s and 20 s against the live instance (per-interface
round trips) and are not used; the batched read takes about one second. No URL,
token, or free-text description is carried. Only tagged (`csci5840-iac`)
objects are visible, so an untagged foreign record is not seen.

## 14. Topology source

The fixed `runtime_metadata` path named in `monitoring/config/topology.yml` is
read as a bounded JSON file (no subprocess, no `containerlab`, never written).
Nodes, kinds, and link endpoints are normalized (`ethN` → `EthernetN` for cEOS
nodes, mirroring `modules.topology`); host attachments are excluded. Where the
source is unavailable, adjacency is **never guessed**.

## 15. Inventory source

The fixed repository file `inventory.yml`, read with a **whitelist**: management
service addresses, per-device platform and monitoring address, host names.
Usernames, passwords, and SNMP material are never read into a report. Used for
platform cross-checks and for project-known service addresses (NMAS, R2).

## 16. Capability source

The **same** three registries the UI and renderer use
(`PLATFORM_CAPABILITIES`, `ROUTING_CAPABILITIES`,
`SERVICE_POLICY_CAPABILITIES`). Validation holds no capability table of its own;
it enumerates accepted objects and looks each up through the registry's public
functions.

| Registry status | Planning effect |
|---|---|
| `SUPPORTED` | continue |
| `NOT_IMPLEMENTED` | `PLATFORM_FEATURE_NOT_IMPLEMENTED` — **blocking** (no authoritative renderer) |
| `UNSUPPORTED` | `PLATFORM_FEATURE_UNSUPPORTED` — **blocking** |
| `UNKNOWN` | `PLATFORM_FEATURE_UNKNOWN` — evidence gap → `INCOMPLETE` |

Incompatible intent preserved by a platform switch is surfaced explicitly.

**Renderer consistency.** For every enumerated object, the driver's own
descriptor API is probed with a one-object slice (delta against a baseline):
registry `SUPPORTED` but the renderer raises / emits the unsupported-object
marker / emits nothing → `PLATFORM_RENDERER_INCONSISTENT` (blocking);
registry not supported but deployable-looking (non-comment) output emitted →
the same. No CLI text is parsed beyond the comment/marker convention.

## 17. Source-failure semantics

Best-effort across independent validators: a NetBox outage does not stop the
topology or dependency checks. An outage is a fixed, sanitized finding
(`SOURCE_*_UNAVAILABLE`, no exception text, host, or token) and marks the
result `INCOMPLETE` only when the Change **requires** that source: NetBox for
addresses/FHRP/DHCP/NAT, topology for interfaces, inventory for existing-device
intents. An unneeded source outage is only a WARNING. An unexpected exception
inside one validator is caught at the engine boundary, logged server-side by
class name only, and reported as `INTERNAL_VALIDATION_ERROR` (evidence gap →
`INCOMPLETE`); the other validators still run.

## 18. Addressing collision validation

Exact host identity via `ipaddress` — never mere prefix overlap. Two addresses
in the same subnet are different hosts and never collide.

* candidate-vs-candidate duplicate (`IP_DUPLICATE`), reporting both objects;
  link-local/loopback addresses are exempt;
* candidate-vs-NetBox (`IP_NETBOX_COLLISION`): assigned to another object →
  blocking; an unassigned record or an address *released by the same Change* →
  WARNING; a shared-role (`vrrp`…) record used as an ordinary address →
  blocking. Same device but different interface is still a collision.
* persisted-but-malformed addresses (`ADDRESS_INVALID`, `ADDRESS_FAMILY_MISMATCH`).

## 19. Existing-device self-match

An `EXISTING_DEVICE` intent that reproduces the assignment NetBox already holds
is **not** a collision. Ownership matching is explicit: same **device**, same
**interface**, same **host**. Same device name alone is never exempt.

## 20. DHCP conflict validation

A static candidate address (or FHRP VIP) inside an active dynamic pool from
NetBox → `IP_DHCP_POOL_CONFLICT`. No exclusion is invented. Pre-existing pool
model problems (found by reusing `ipam_context.validate_dhcp_pool_safety`) are
non-blocking `DHCP_POOL_OVERLAP` warnings: project state, not caused by the
Change.

## 21. Reservation conflict validation

Reservation state is read from the NetBox assignment-mode custom fields
(`dhcp-reserved` / `dhcpv6-reserved`). `IP_RESERVATION_CONFLICT`: a candidate
address reserved to another identity, or a reserved identity given a different
static address. Nothing is created.

## 22. VLAN 200 defense in depth

Even though Phase 12 already blocks it, malformed persisted intent that gives
a VLAN 200 / management interface a DHCP or DHCPv6 client, a DHCP relay, an AUTO
address, or a NetBox reservation is blocked (`DHCP_VLAN200_FORBIDDEN`). VLAN 200
remains `STATIC` / `MANAGEMENT`.

## 23. AUTO address derivation

Phase 10 left AUTO as unresolved/unreserved. Phase 13 derives a deterministic
**proposal** (validation output only): resolve the selected NetBox prefix →
enumerate hosts (network/broadcast excluded; bounded at 4096 candidates) →
exclude NetBox-assigned hosts, other candidate MANUAL addresses, earlier
derived AUTO picks in the same run, FHRP VIPs, dynamic DHCP ranges,
reservations owned by others, and project-owned service addresses (inventory /
relay targets) → choose the **lowest free host**. Devices/interfaces are
processed in a stable order; there is no randomness. The result is a derived
fact:

`object_id, device, interface, family, selected_prefix, proposed_address,
source, algorithm (lowest-free-host/v1), reserved=false, status=PROPOSED,
note`. The UI states **PROPOSED · NOT RESERVED · Must be rechecked immediately
before deployment**. Failure modes: `AUTO_IP_UNRESOLVED` (no/invalid/unknown
prefix; an evidence gap if NetBox is down) and `AUTO_IP_NO_AVAILABLE_ADDRESS`.
Accepted intent is never modified; NetBox is never written; no reservation is
created.

## 24. AUTO race limitations

A read-only allocation can race: another actor may take the proposed address
after validation. A Phase-13 proposal is **not a lease and not a reservation**.
Real deployment (Phase 14/15) **must** perform final freshness and
revalidation immediately before use. No stronger guarantee is claimed.

## 25. Link validation

Only links whose ends can be correlated (topology link + candidate interface
at each end) are judged.

* **Direct routed links:** each address family that **both** ends carry must
  share a subnet (`LINK_PREFIX_MISMATCH`, blocking candidate-vs-candidate);
  single-family links are legitimate; `/31` and `/127` pairs must be a valid
  pair (same block, different host); larger prefixes are legitimate. When the
  far end is outside the Change the comparison uses NetBox evidence and is
  only a WARNING.
* **Missing references:** a dangling stable reference is `DEPENDENCY_MISSING`.
* **Unknown VLAN / device:** `VLAN_NOT_IN_NETBOX`, `TOPOLOGY_DEVICE_UNKNOWN`.

## 26. Access / trunk validation

* access/access: both VLANs set and different → `LINK_ACCESS_VLAN_MISMATCH`
  (blocking); only one set → WARNING.
* trunk/trunk: native VLAN mismatch (default native = 1) → blocking; allowed-
  VLAN sets that share nothing → blocking. A side that legitimately carries
  additional VLANs is **not** demanded to match. A VLAN both switches use
  locally (access/SVI) but missing from a non-empty allowed list is a WARNING
  (`LINK_TRUNK_VLAN_MISSING`) — concrete evidence of use, not proof of intent.
* access↔trunk: compatible when the access VLAN equals the trunk native VLAN
  (silent); otherwise ambiguous → WARNING `LINK_MODE_MISMATCH`, never a block.
* routed↔trunk/access: a subinterface tag not allowed on the trunk is blocking;
  a routed port without subinterfaces facing a trunk is a WARNING.

## 27. MTU semantics

Direct-link MTU mismatch is a WARNING (`LINK_MTU_MISMATCH`), called out
specifically when OSPF runs on the link. It is never escalated to a block:
nothing in the project proves an MTU mismatch fatal.

## 28. Static routing validation

Beyond Tier 1: family consistency, next hop equal to the device's own address
(blocking), next hop reachable through a connected network known from the
candidate or NetBox (otherwise a WARNING — reachability not established), and a
layer-2 exit interface (WARNING). No routing simulation.

## 29. OSPF validation

When **both** ends of a topology link are candidate OSPF participants: version
mismatch and area mismatch are blocking; network-type mismatch is a WARNING;
areas compare numerically (`0` = `0.0.0.0`). One-sided participation is INFO
only (the other side may be intentionally non-OSPF). Router IDs must be unique
per version (`ROUTER_ID_DUPLICATE`). An OSPFv2 interface without any IPv4
address is a WARNING (OSPFv3/RIPng use link-local so are not judged).
On cEOS, an OSPF instance without `process_id` is a blocking
`OSPF_PROCESS_ID_REQUIRED` finding. The draft preview retains the explicit
`<process-id-required>` placeholder, while validation and planning prevent it
from becoming deployable configuration.

## 30. BGP validation

A neighbor's peer address is resolved against candidate addresses, then NetBox.
For a candidate-controlled peer: configured remote ASN must equal the peer's
local ASN (`BGP_REMOTE_AS_MISMATCH`, blocking, checked from each side's own
neighbor); both sides must activate a common address family
(`BGP_AF_MISMATCH`, blocking); a missing reciprocal neighbor is a WARNING.
An unresolvable peer is `BGP_PEER_UNRESOLVED` — a **WARNING** (it may be an
external provider; the model has no peer-scope field, so none is invented; the
evidence records the inferred EBGP/IBGP type). Advertised networks without
connected/static evidence are WARNINGs. Duplicate BGP router IDs block only for
the same ASN or resolved peers; otherwise WARNING. Identical router IDs across
unrelated protocol families are not a conflict.

## 31. RIP and other routing handling

RIP: family disagreement across a link is a WARNING. IS-IS/EIGRP/RIPng and any
other preserved intent are first capability-checked; deeper checks run only
where a renderer actually exists. No adjacency state is inferred.

## 32. FHRP validation

Peers are correlated into **domains** (same protocol and family, and a shared
VIP or the same VLAN context and group). Shared VIPs inside one domain are
intended and are **not** ordinary duplicates. Checks: group-ID agreement
(HSRP/VRRP/GLBP), identical VIP sets (`FHRP_GROUP_MISMATCH`), VARP virtual-MAC
agreement and one global MAC per cEOS device (`FHRP_VIRTUAL_MAC_MISMATCH`;
a MAC set on only some peers is a WARNING), duplicate priorities (WARNING; VARP
has no priority so none is demanded), VIP off the interface subnet (WARNING).
`FHRP_VIP_CONFLICT` (blocking): a VIP shared by two unrelated domains or equal
to an ordinary candidate interface address. A VIP equal to a NetBox
*shared-role* record is accepted; equal to an ordinary NetBox assignment it
collides; inside a dynamic pool it conflicts.

## 33. NAT validation

Not a NAT simulator. Provable relationships only: referenced interfaces/pools
exist (dynamic rules require a pool), a rule's addresses match its family,
pool/rule family compatibility, pool boundaries, no overlapping pools, no pool
covering an interface or management/service address
(`NAT_POOL_CONFLICT`), and one interface never both inside and outside
(`NAT_INTERFACE_ROLE_CONFLICT`). WAN metadata reversed → WARNING. Topology has
no role metadata, so directionality is never fabricated — it is reported once
per device as INFO `NAT_ROLE_UNVERIFIED`. Unsupported NAT is blocked by
capability; NPTv6/NAT-PT get no deep semantics.

## 34. DHCP and DNS validation

Relay destinations are matched against project-known addresses (inventory
NMAS/R2, NetBox relay targets, candidate/NetBox addresses); known → derived
fact, unknown → `DHCP_RELAY_UNRESOLVED` WARNING (never pinged); wrong family
blocks. DNS resolvers are matched the same way (`DNS_RESOLVER_UNRESOLVED`);
**no name is ever resolved and no query is ever sent**. Explicit DNS override
is `NOT_IMPLEMENTED` and therefore blocked through the capability check. NMAS/R2
configuration is never modified.

## 35. ACL safety analysis

Conservative — not a firewall theorem prover. Only the structured entries
(action, protocol IP/IPV6/TCP/UDP/ICMP/ICMPV6, ANY/HOST/PREFIX, port/range)
are evaluated; **no raw CLI is parsed**. Matching is three-valued
(MATCH / NO_MATCH / MAYBE) and follows first-match order: a later permit never
rescues an earlier matching deny; a later deny never matters after a
definitive earlier permit. Required flows come from a small catalogue with
concrete endpoints: management SSH/SNMP/gNMI/NETCONF and syslog to/from the
inventory NMAS address on a management interface; OSPF hellos on an OSPF-bound
interface; BGP TCP/179 for a candidate peer; DHCP relay client/server UDP.

* explicit definitive deny of a required flow → `ACL_REQUIRED_FLOW_DENIED` (blocking);
* anything uncertain — unknown attributes, a MAYBE entry that could flip the
  outcome, or reaching the implicit end-of-list deny — is `ACL_EFFECT_UNKNOWN`
  (WARNING), never fabricated certainty;
* shadowed entries (`ACL_ENTRY_SHADOWED`) and multiple ACLs on one
  interface/direction/family (`ACL_DUPLICATE_ATTACHMENT`) are WARNINGs.

## 36. PBR validation

PBR currently has no rendering support on any platform, so preserved PBR intent
is blocked by capability. Reference integrity (policy/interface/output
interface) is still checked through the dependency graph. Next-hop
reachability (`PBR_NEXT_HOP_UNRESOLVED`) is evaluated **only** for a platform
whose registry actually SUPPORTS PBR; no reachability is simulated for an
undeployable feature.

## 37. Dependency graph

A semantic graph of accepted intent, **not** the Phase-14 plan. Nodes are stable
objects: interface, address, static route, routing instance / binding, BGP
neighbor / network, FHRP instance, NAT pool / rule, DHCP relay / client, ACL /
ACL attachment, PBR policy / sequence / attachment. Node id =
`<device>/<type>/<object id>`. Output is sorted and serialized
deterministically.

## 38. Dependency edge types

`REQUIRES` (address→interface, binding→instance, neighbor→instance) ·
`PARENT_BEFORE_CHILD` (subinterface→parent) · `INTERFACE_BEFORE_SERVICE`
(binding/update-source/FHRP/NAT/DHCP/ACL/PBR→interface) · `DEFINE_BEFORE_ATTACH`
(ACL attachment→ACL, NAT rule→pool, PBR attachment→policy) ·
`ADDRESS_BEFORE_ROUTING` (binding/static route/neighbor→a candidate address it
relies on) · `REFERENCES` (soft: PBR output interface). An edge `A → B` reads
"A depends on B". Each edge has a status (`RESOLVED` / `MISSING`).

## 39. Missing dependencies

A reference to a missing object is kept as an edge with status `MISSING` and
becomes `DEPENDENCY_MISSING` (blocking) — never silently dropped. It defends
against historical data, manual database edits, migration bugs, and stale
intent even though Phase 10–12 mutation guards make it unlikely.

## 40. Cycle detection

Iterative, deterministic DFS over resolved edges; each cycle is reported once
with full evidence (`A -> B -> ... -> A`) as blocking `DEPENDENCY_CYCLE`. The
only cycle the current model can express is an interface parent loop.

## 41. Derived facts

Kept strictly separate from findings and from accepted intent. Types:
`AUTO_ADDRESS`, `BGP_PEER_RESOLVED`, `STATIC_ROUTE_NEXT_HOP`,
`DHCP_RELAY_DESTINATION`, `FHRP_DOMAIN`. Deriving a fact never modifies a
DeviceIntent.

## 42. Deterministic output

Same accepted intent + same source snapshots + same engine version ⇒ same
status, findings (order and IDs), derived facts, dependency graph, and hashes.
Timestamps and run IDs are ignored when comparing (`semantic_digest`).

## 43. Validation UI

`/device-builder/changes/<change_id>/validation/` (GET, read-only) shows
currency (`CURRENT` / `STALE` / `NEVER RUN`), the latest result, run
timestamp, short input fingerprint, source provenance, the summary (errors,
warnings, info, devices, objects, sources available), filterable findings
(severity, category, device, blocking-only; bookmarkable GET), derived facts
(AUTO shown as PROPOSED / NOT RESERVED), a readable dependency summary
(object → depends on → edge type → status, cycles highlighted), and the
limitations of the result. `…/validation/run/` (POST + CSRF) is the only action
that persists anything and ignores every POST field — sources, paths and URLs
are fixed server-side. Everything is auto-escaped; `|safe` is not used.

## 44. History

`…/validation/runs/<run_id>/` opens a historical run read-only (POST → 405).
A run is only addressed **through its Change**; a run of another Change is a
404. History lists the most recent 25 runs, newest first.

## 45. JSON / machine-readable report

`…/validation/runs/<run_id>/report.json` — sanitized, bounded, structured
provenance, status, summary, findings, derived facts, dependency graph. Fixed
filename `<CHANGE_ID>-validation-<first 8 of run id>.json`, `attachment`,
`nosniff`. No credentials. Intended for Phase 14 and Phase 16.

## 46. Audit

Each run appends one `AuditEvent` (`VALIDATION_RECORDED`) with actor, Change,
run ID, result, and input hash — never the snapshot. No Slack/notification is
produced for an ordinary validation run.

## 47. Security

POST + CSRF for the run; Change → run relationship resolution; fixed source
paths (no browser-supplied URL/host/path/query); no shell, `eval`, or dynamic
import (asserted by AST tests); bounded report, evidence, and finding counts;
XSS-escaped output; secret-shaped keys rejected/redacted; sanitized source
errors and logs (class names only); no credentials in provenance; no
running-config retrieval.

## 48. No device access

Tier 2 uses intent, NetBox, inventory, topology, and project data. It performs
no Netmiko/Paramiko/SSH, no `show`, no ping/traceroute, no DNS query. Live
health belongs to Phase 15. Tests run a full validation with `socket`,
`subprocess`, and `urllib` disabled.

## 49. No deployment

No `configure terminal`, FRR reload, SR Linux/EOS commit, `write memory`, or
Containerlab deploy/destroy exists on any Phase-13 path. No NetBox write, no
Git write, no GitHub Action, no Configlet, no lifecycle transition.

## 50. Phase-14 handoff

Phase 14 consumes, without HTTP:

* `change_validation_service.get_latest_validation(change)` and
  `get_validation_currency(change, check_sources=True)` — plan only from a
  `CURRENT` run whose result is acceptable;
* `serialize_validation_run(run)` — findings, derived facts, and the semantic
  dependency graph (nodes with stable IDs, typed edges);
* derived `AUTO_ADDRESS` proposals, which are **unreserved** and **must be
  rechecked immediately before deployment**;
* the same capability registry and the single `candidate_renderer`.

Phase 14 builds the unified priority/dependency plan and deterministic
Configlet generation; it must not treat the graph as an execution order, and
deployment must perform its own final freshness check.

## Known limitations

* Only `csci5840-iac`-tagged NetBox objects are visible.
* Topology comes from the runtime metadata file; it carries no port roles, so
  NAT directionality and peer scope are not inferable.
* No routing/NAT/ACL simulation; ACL analysis covers the fixed flow catalogue
  and the structured ACE subset only (implicit-deny outcomes are WARNINGs).
* BGP peer-type is inferred from ASNs only; an external provider peer is a
  WARNING, not proof.
* AUTO derivation is a race-prone read-only proposal.
* R3/R4 are Linux/FRR whose interface names are `ethN`, so link correlation for
  them depends on the intent using those names.
* Source freshness is checked on request, not continuously.
