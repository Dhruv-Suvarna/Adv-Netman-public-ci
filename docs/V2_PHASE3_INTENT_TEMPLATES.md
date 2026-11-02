# Version 2 Phase 3: intent-based configuration templates and portable exchange

A template is **reusable semantic intent**, never a CLI blob. It is the same vendor-neutral, name-keyed structure the
configuration importers already produce, stored as YAML-safe data with typed `{{ parameter }}` placeholders. A template
never renders configuration itself and is never pushed: using it clones it into an ordinary Device Builder Change, which
is then rendered by the existing Jinja2 feature templates and goes through the unchanged Phase 2 lifecycle.

```
running configuration ──(read-only capture, sanitized)──► importer (config_import parsers)
        ──► vendor-neutral semantic intent ──► normalize / parameterize ──► immutable template version (YAML)
        ──► clone ──► Change / DeviceIntentRevision (Device Builder services, Tier-1 field validation)
        ──► Jinja2 feature renderer (templates/features/<platform>/*.j2)
        ──► network-config validation ──► Tier-2 validation ──► plan ──► precheck ──► approval
        ──► execution ──► postcheck ──► live network-config validation ──► evidence
```

There is no second configuration system: extraction reuses `config_import`, cloning reuses
`config_import.service.apply_parsed_config` (the Device Builder apply pipeline), rendering reuses
`candidate_renderer`, and the incremental path reuses the Configuration Changes contribution baseline.

Code: `web/core/services/config_templates/` (`schema`, `normalize`, `combine`, `features`, `secrets`, `package`,
`service`, `clone`, `working_intent`, `baselines`). Models and migration `core.0021`. Pages under `/template-library/`.

## Data model

`ConfigurationTemplate` is the identity: stable `template_id`, name, role/family, origin (`BASELINE`, `EXTRACTED`,
`DERIVED`, `IMPORTED`), description, creator, creation time, retirement. `template_id`, family and origin are immutable.

`ConfigurationTemplateVersion` is one numbered revision:

| field | meaning |
| --- | --- |
| `version`, `schema_version`, `status` | numbered, `DRAFT` or `PUBLISHED` |
| `intent` | the semantic intent (see below) |
| `parameters`, `parameter_sets` | typed parameter definitions; the values of each source device |
| `platforms`, `required_features`, `constraints` | compatibility, derived from the intent and the Phase 1 capability registries |
| `provenance` | source devices, running-config snapshot ids and digests, extraction time, platforms, repository HEAD, differences, derivation |
| `exclusions` | what was deliberately left out, and why (labels only) |
| `digest` | SHA-256 of the canonical content |
| `source_version` | lineage |

A draft can only be **published or discarded**; a published version never changes (`save`, `delete`, bulk `update` and
bulk `delete` all refuse). Modification is always a new version or a cloned working intent.

### Intent schema (schema version 1)

```yaml
device:        {hostname}
interfaces:    [{name, kind, description, mtu, admin_state, access_vlan, trunk_allowed_vlans, native_vlan, parent_name,
                 encapsulation_vlan, vlan_id, addresses[], dhcp_relays[], fhrp[], acl_attachments[]}]
static_routes: [{family, destination, next_hop_address, next_hop_interface, distance, tag}]
routing:       [{family, fields{}, bindings[], neighbors[], networks[]}]
acls:          [{name, family, acl_type, entries[]}]
nat_rules:     [{family, mode, original_source, outside_interface}]
host:          {...}        # end-device profile only
```

It mirrors `config_import.schema.ParsedConfig` field for field. Objects are identified by **name**, never by a database
id, so a template does not depend on one NMAS instance. Raw CLI (`preserved_lines`, unmanaged blocks) is never carried.

A string may be exactly `{{ name }}` (replaced by the typed parameter value) or contain such placeholders (rendered by
a sandboxed Jinja2 environment with `StrictUndefined`). **No other Jinja2 syntax is accepted**, so neither a template
nor an imported package can carry template logic. Any object may carry `_when: <boolean parameter>`.

### Parameters

Types: `hostname`, `interface_name`, `ipv4_interface`, `ipv6_interface`, `ip_interface`, `ipv4_address`,
`ipv6_address`, `ip_address`, `ip_prefix`, `vlan_id`, `vlan_list`, `asn`, `integer`, `boolean`, `string`. Every value is
validated against its type before the intent is resolved, and again by the Tier-1 field validators when the clone is
applied. Parameters used only inside a disabled `_when` object are not required.

## Extraction, normalization and parameterization

`normalize.clean` removes what must not be reused, recording each removal as an exclusion:

- Containerlab-assigned management plumbing (`Management0`, Linux `eth0`) and static routes through it;
- link-local addresses (derived from the interface MAC);
- secret-shaped keys and values (credential references are blanked: they are instance-local);
- an access VLAN with no layer-3 addressing is normalized to an `ACCESS` port (EOS omits its default switchport mode).

`normalize.generalize` turns the intent of one or more source devices of the same role into one template:

- **identity-class values always become parameters**: hostname, the static VLAN 200 management addresses
  (`mgmt_ipv4`, `mgmt_ipv6`), loopback addresses, router ids, the BGP AS, BGP peers, descriptions naming the device;
- any other value that **differs between the sources** becomes a typed parameter;
- a value the sources **share stays a literal baseline default** — nothing is parameterized blindly;
- an object only some sources have is kept behind a boolean `_when` parameter and listed under
  `provenance.differences` — role-specific behaviour is documented, not erased.

Each source's own values are kept as a named parameter set, and resolving the template with a source's set reproduces
that source's intent exactly (tested).

Live extraction is implemented for the platforms with a read-only capture transport and a parser: **Arista cEOS** and
**Ubuntu/FRR**. Other platforms are not claimed; exhaustive platform support is Version 2 Phase 4. Extraction is
strictly read-only and is refused for anything outside the NetBox-authoritative management scope.

## Baseline families

Generated by `manage.py nmas_templates generate-baselines` (`--live` for a fresh read-only capture; default: the newest
stored sanitized snapshot of each source). Baseline ids are fixed; regeneration is idempotent and a changed source
publishes the next immutable version.

| family | template id | source |
| --- | --- | --- |
| Access Layer Switch | `TPL-BASELINE-ACCESS-SWITCH` | S1 + S2, generalized |
| Default Gateway Router | `TPL-BASELINE-GATEWAY-ROUTER` | R1 + R2, generalized |
| Multilayer Switch | `TPL-BASELINE-MULTILAYER-SWITCH` | semantic combination of the two above |
| Spine Device | `TPL-BASELINE-SPINE` | S3 + S4, generalized |
| Internet Uplink Device | `TPL-BASELINE-INTERNET-UPLINK` | R3 + R4 (Ubuntu/FRR), generalized |
| End Device | `TPL-BASELINE-END-DEVICE` | H1–H4, from the repository's lab definition |

The tracked packages live in `templates/baselines/*.nmas-template.yaml`; `manage.py nmas_templates load-baselines`
registers them on any instance (validated like any import, idempotent).

### Multilayer Switch

`combine.combine` builds it semantically from the Access and Gateway template intents — it never touches CLI. Every
collision is decided by an explicit rule and recorded under `provenance.conflicts`:

| code | rule |
| --- | --- |
| `DUPLICATE_MANAGEMENT` | one management SVI, one management access port, one hostname |
| `DUPLICATE_INTERFACE` | the access role keeps the port; the gateway role's port moves to the next free port and every reference (routing bindings, next-hop interfaces, parameters) follows it |
| `OVERLAPPING_ADDRESSING` | the access role (the VLAN's gateway) keeps its addressing |
| `LOOPBACK_ROUTER_ID` | one loopback carrying both roles' address families; router ids reference it |
| `ROUTING_PROCESS_COLLISION` | the same protocol in both roles becomes one process |
| `DEFAULT_GATEWAY_ROLE` | the same static destination via different next hops: the gateway role's route wins |
| `VLAN_WITHOUT_SVI`, `SVI_WITHOUT_PORT` | VLAN / SVI relationship findings, reported rather than silently repaired |
| `PARAMETER_COLLISION` | same name, different meaning: the gateway role's parameter is renamed `gw_*` |

### End Device

H1–H4 are outside NMAS management and stay unmanaged. The template is derived from `inventory.yml` (`hosts`), the
topology file and `hostserv.configure_host`; the hosts are not logged into. It is marked `deployable: false`,
`managed_scope: false`, has no platform, and **cannot be cloned into a working intent** — it exists for lab generation,
testing, workload reuse and exchange.

## Use Template (clone into Device Builder)

Choose a published version, a target device and platform, a parameter set / values, and a new or existing Draft Change.
The clone is a new `DeviceIntentRevision` built through the Device Builder services; its metadata records the template
id, version, digest and parameter values. The template is only read.

- **Full** — the whole resolved intent becomes the working intent.
- **Incremental** — for an existing running device: its running configuration is captured and imported as context
  (the Configuration Changes contribution baseline, guarded by the snapshot digest at execution), and only what the
  template **adds** becomes the Change. Objects the device already has are context and are not re-deployed; a value
  that differs on an existing object is reported and **not** overwritten.

The working copy is edited like any Device Builder draft (remove OSPF, drop VLANs, change a description). "Save working
intent as template draft" creates the next version of an extracted/derived template; a clone of a baseline or imported
template becomes a **new** derived template, so a baseline is never altered.

## Portable package

One deterministic YAML document (`*.nmas-template.yaml`): `kind`, `schema_version`, `manifest` (id, name, family,
origin, version, creator, sha256 digest), `compatibility`, `provenance`, `parameters`, `parameter_sets`, `intent`,
`exclusions`, `notes`, and `rendering` (references to the project-owned Jinja2 feature templates). The same version
always exports the same bytes. A single document has no archive members, so there are no member paths to traverse.

Import validates untrusted input completely before anything is stored: size limit, strict YAML (no aliases, no custom
tags), kind, schema version, structure, placeholder integrity, secret scan, template-reference safety
(`<platform>/<name>.j2` only) and the digest. Rejections carry a stable code (`MALFORMED_PACKAGE`,
`UNSUPPORTED_SCHEMA_VERSION`, `INVALID_PACKAGE`, `SECRET_MATERIAL_REFUSED`, `UNSAFE_TEMPLATE_REFERENCE`,
`DIGEST_MISMATCH`, `PACKAGE_TOO_LARGE`, …) and are audited without content. An imported version is immutable from the
start, keeps its original provenance, and is never executed: import means register → inspect → clone → validate →
explicit execution later. A version number that already exists locally with different content never overwrites; the
package is registered under a new local identity.

## Security

Templates, exports and audit records never contain passwords, password hashes, TOTP seeds or codes, private keys,
RADIUS secrets, API tokens, credential-provider contents, Cloudflare credentials or session secrets. Extraction works on
the already-sanitized capture and additionally redacts secret-shaped keys and values; publication and import reject
them. Audit metadata names identifiers, digests and parameter **names** only.

## Authorization and audit

Viewing needs `nmas_view`; extracting, importing, cloning, discarding a draft and saving a working intent need
`nmas_edit`; **publishing and retiring need `nmas_approve`**; pushing a cloned Change is still `nmas_execute` on the
Change's own Execute page. Export is an audited sensitive read. Domain events: `TEMPLATE_EXTRACTED`,
`TEMPLATE_CREATED`, `TEMPLATE_VERSION_CREATED`, `TEMPLATE_PUBLISHED`, `TEMPLATE_DRAFT_DISCARDED`, `TEMPLATE_EXPORTED`,
`TEMPLATE_IMPORTED`, `TEMPLATE_IMPORT_REJECTED`, `TEMPLATE_CLONED`, `TEMPLATE_PUSH_RECORDED`, `TEMPLATE_RETIRED` — each
attributed to the authenticated website user through the Phase 1 request context.

## Capability evidence

Recorded through the Phase 1 framework (no redesign): `PARSER_IMPORT` and `LIVE_READ` for every feature extracted from
a live device (`template-extraction`); `RENDERER` when a cloned intent renders (`template-render`); `LIVE_WRITE` and
post-write validation for a template-derived push are recorded by the existing Phase 2 live validation, plus one
`TEMPLATE_PUSH_RECORDED` audit event linking the push to the template version.

## Validation boundaries

Tier-3 (`tier3.py`, subsystem `config_templates`) validates the NMAS source. Template-derived **network configuration**
is validated by the network-config validation system on the cloned Change, exactly like any other Change. The only
template-specific validation is package/schema integrity.

## Deferred to Version 2 Phase 4

Exhaustive per-platform capability status; live extraction and push for C8000V, SONiC and SR Linux; new-device
provisioning from a template; in-place modification of an existing object by an incremental clone (today it is reported,
and Remove Configuration + a new contribution is the path).

## Live validation evidence (2026-10-03)

Run from the Phase 3 worktree against a copy of the deployment database (migrated to `core.0021`; the production
database is not migrated from an unmerged branch), actor `v2-phase3-live-validation`. Every device contact other than the
two approved executions was the existing read-only capture.

| step | result |
| --- | --- |
| Baselines | Six families generated from live read-only captures of R1, R2, R3, R4, S1, S2, S3, S4 (H1–H4 not contacted) and exported to `templates/baselines/` |
| A. Pull | `TPL-B9133C4AB268@v1` extracted from the running R1 (cEOS, netmiko privileged EXEC `show` only); running-config digest `23460f93ef43ccee…`; published |
| B. Clone | Full clone into `CHG-20261003-0001` (working copy, archived, never executed); a `Loopback103` added in Device Builder; saved as `TPL-B9133C4AB268@v2` (v1 digest unchanged) |
| B. Clone (incremental) | v2 cloned onto running R1 as `CHG-20261003-0002`: 13 existing objects are context, exactly 1 new interface |
| C. Modify | Working copy edited: `Loopback103` description → `NMAS-V2P3-TEMPLATE-PUSH-TEST` (Tier-1 `VALID`) |
| D. Validate | network-config `CANDIDATE` WARNING (pre-existing: Containerlab `Management0` addresses are outside NetBox pools); Tier-2 `PASS`; plan = one configlet (`interface Loopback103` + description); precheck `PASS` |
| E. Push | execution `fe91ef15-ac78-4a01-bdae-812edc1ea4db`, Complete mode, `SUCCEEDED`; postcheck `PASS`; network-config `POST_PUSH` `PASS`; `TEMPLATE_PUSH_RECORDED` audit event against `TPL-B9133C4AB268@v2` |
| F. Live verify | fresh read-only capture: `interface Loopback103` / `description NMAS-V2P3-TEMPLATE-PUSH-TEST`; digest `7b4061ece7523e06…` |
| G. Revert | Remove Configuration `CHG-20261003-0003` (`no interface Loopback103`): `REMOVAL_PRECHECK` `PASS`, Tier-2 `PASS`, precheck `PASS_WITH_WARNINGS` (the two link events of the test loopback itself), execution `310a9b16-a991-4ebe-b485-9dbeb69e4619` `SUCCEEDED`, `POST_REMOVAL` `PASS` |
| H. Restoration | fresh capture digest `23460f93ef43ccee…` — identical to the pre-test digest; `Loopback103` absent |

Capability evidence recorded: `LIVE_READ` / `PARSER_IMPORT` `VERIFIED` for cEOS and Ubuntu/FRR (`template-extraction`),
`RENDERER` `VERIFIED` for cEOS (`template-render`), and the Phase 2 live-write / post-write rows for the push.
VLAN 200 was not touched; R5, WebServer and H1–H4 have no intent, snapshot or template-derived Change.
