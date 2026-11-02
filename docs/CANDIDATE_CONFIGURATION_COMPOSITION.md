# Candidate Configuration Composition

Candidate configuration is rendered from one normalized, scope-aware model. The
persisted `DeviceIntentRevision.sections` JSON remains the feature-editing
source of truth; `candidate_renderer.hydrate_state()` selects accepted or draft
values, then `candidate_composition.compose()` projects those feature objects
into their actual configuration scopes before a platform driver emits the
platform's real representation -- CLI text for cEOS/FRR/SR Linix/IOS XR, or a
config_db JSON document for SONiC (see `platform_drivers.SonicDriver`, which is
the one driver that overrides `render_composed` directly rather than using the
shared line/field-marker CLI renderer, because SONiC's authoritative
configuration surface is a structured datastore, not a CLI). `compose()` itself
is fully platform-agnostic either way; only the final rendering step differs.

```text
UI / persisted feature intent
          |
          v
accepted-or-draft hydration
          |
          v
normalized scope composition
  device/global
  interface
  routing process
  static route
  named policy/object
  services/other global
          |
          v
platform-specific rendering
```

Every logical interface has one authoritative normalized object. Base interface
properties and addresses are joined with interface-owned OSPF, FHRP, ACL, DHCP,
PBR, and NAT-role contributions. The platform driver renders the interface once
in a deterministic order. Feature code must extend this normalized object; it
must not append another `interface <name>` fragment to the final candidate.

Scope ownership follows the target NOS syntax. OSPF area/cost/network type, ACL
and PBR attachments, relay/helper commands, FHRP virtual addresses, and any
platform interface role belong to the interface scope. OSPF/BGP/RIP processes,
static routes, ACL definitions, NAT rules/pools, and other named/global objects
remain separate scopes. VLAN definitions and global VARP MAC configuration are
deduplicated globally even though their related interface objects are edited in
the same UI modules.

Composition is deterministic: stable sequence and object IDs determine input
order, identical repeated contributions are idempotent, and single-valued slots
never use last-writer-wins. Incompatible contributions create a structured
composition conflict, appear as a draft-preview conflict comment, and produce a
blocking `CANDIDATE_COMPOSITION_CONFLICT` project-validation finding.

Draft interface removal deletes interface-owned routing bindings and service or
policy attachments, while preserving named definitions and routing processes.
NAT rules are retained but references to the deleted interface are cleared.
Global objects such as static routes, BGP update sources, FHRP instances, or PBR
next-hop references must be explicitly detached first; they are not cascaded.

Draft previews may contain required-value placeholders so the operator can see
incomplete work. Project validation must report the missing dependency, and the
planner independently rejects any surviving placeholder. A candidate becomes
deployable only after committed intent passes project validation and the normal
plan/execution eligibility gates.
