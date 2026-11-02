# Automation Configuration Workflows — Configuration Changes and Remove Configuration

Status (2026-09-27): **implemented and tested offline (fixtures + the real lifecycle on fake device sessions).**
No new workflow has sent configuration to any live device.

Live execution uses the existing approval-gated Execute page. It still needs a
separate operator authorization per the project safety rules; the Phase-22
live-write authorization does not cover these workflows.

## 1. Four distinct workflows

| Workflow | Purpose | Page |
|---|---|---|
| **Device Builder** | Build substantial or complete desired state (a new device, a full composed candidate). | `/device-builder/…` |
| **Configuration Changes** | Small CREATE / UPDATE / ATTACH changes to an already-running device, as an incremental patch. | `/automation/configuration-changes/` |
| **Remove Configuration** | Intentional REMOVE / DETACH / DELETE of selected configuration from a running device. | `/automation/remove-configuration/` |
| **Rollback / Recovery** | Restore a prior known-good state after a bad deployment. **Not implemented as a page** (still an honest shell). Not the same thing as removal. | shell |

The Automation cards route accordingly:

* "Configuration Changes" opens the incremental page. It no longer points at
  Device Builder's Changes list.
* "Remove Configuration" opens the real removal page. It is no longer the
  "View shell" placeholder.
* Fleet Health, Per-Device Health, Soak Management, Initial Golden Bootstrap,
  Change History, Troubleshooting and Device Credentials are unchanged.

## 2. Shared split layout

Both pages extend one template, `core/automation/workbench/base.html`. They
differ only in the left block.

```
+------------------------------------------------------------------+
| Device | platform badge | snapshot digest | Refresh running config |
+----------------------------------+-------------------------------+
| LEFT  (what I want to change /   | RIGHT (what exists right now) |
|        remove)                   |  _running_config.html         |
|  mode tabs · widgets / CLI /     |  read-only · line-numbered ·  |
|  line range / object navigator   |  sanitized · digest ·         |
|  preview · blockers · proposals  |  timestamp · highlighted      |
|  Validate · Save Draft ·         |  affected lines               |
|  Push/Execute… · Cancel          |                               |
+----------------------------------+-------------------------------+
```

Shared parts:

* the device bar
* the platform badge
* the refresh POST
* the running-config component
* the Change panel (`_change_panel.html`: validation status, the exact plan
  patch, Validate & plan / Precheck / **Push / Execute…** / history)
* the styles (token-only CSS, so every theme works)
* `static/core/js/workbench.js` (DOM-only; it makes no network request)

## 3. Running configuration and snapshots

* **Acquisition.** Snapshots use the one existing read-only path,
  `config_import.service.fetch_running_config_outcome`: the legacy-bootstrap
  / Phase-15 transport plus `bundles.legacy_sanitize`. There is no second
  retrieval mechanism. Both pages post to the same `workbench_snapshot` view,
  which calls the same `snapshots.capture`.
* **Device scope.** `config_workbench.scope` is the only selectable-device
  scope, and both pages use it for the dropdown and for every POST. A device
  qualifies when NetBox marks it IaC-managed (`netbox_ipam.get_managed_devices`,
  where the `managed` tag and `iac_managed` must agree) **and** `inventory.yml`
  gives it a capturable platform. Today that means R1–R4, S1–S4 and
  `mgmt_swt`. R5 is NetBox-unmanaged, so it is never offered, and a crafted
  POST for it is refused with HTTP 400 `DEVICE_OUT_OF_SCOPE`. No device name
  is hard-coded. If NetBox cannot be read, the scope fails closed: nothing is
  selectable, and a capture returns `MANAGEMENT_SCOPE_UNAVAILABLE`. The
  legacy-bootstrap/Golden capture scope (`bootstrap.capture.managed_scope`)
  deliberately still includes R5.
* **Transport and credentials.** cEOS devices go through `health.live.EosSession`
  and the device-aware `nsot_live.get_live_target` resolver. That means
  the dedicated `nmas-automation` reference declared for each managed device;
  a missing device profile fails closed and never falls back to a shared account.
  The GUI never chooses an account. Ubuntu/FRR
  (R3/R4) goes through `LinuxSession` (`docker exec`, fixed argv), and no EOS
  command is ever sent to it.
* **Error taxonomy.** Every refusal has a stable code and a fixed message with
  no secrets in it (`snapshots.CAPTURE_ERRORS`):
  - `DEVICE_OUT_OF_SCOPE`, `DEVICE_NOT_FOUND`, `UNSUPPORTED_PLATFORM`: the
    request itself is refused with HTTP 400 and the device is never contacted.
  - `MANAGEMENT_SCOPE_UNAVAILABLE`, `ACCESS_TARGET_NOT_CONFIGURED`,
    `CREDENTIAL_NOT_CONFIGURED`, `AUTHENTICATION_FAILED`, `CONNECTION_FAILED`,
    `RETRIEVAL_FAILED`, `SNAPSHOT_DATABASE_UNAVAILABLE`: the page shows the
    code.
  - `SNAPSHOT_STALE`: returned by `recheck`.

  The database is checked before the device is contacted.
* **Canonical runtime.** The GUI on port 8001 must run from the deployment
  checkout `/home/student/Scripts/clab_dualstack_lab-deploy` (`web/`), with
  its migrated `web/db.sqlite3` and its gitignored runtime credential store
  `monitoring/runtime/device-credentials/store.json`. A development worktree
  has neither. Running the GUI from one produces exactly two symptoms:
  - cEOS capture fails with `CREDENTIAL_NOT_CONFIGURED`. It was reported as
    `NOT_CONFIGURED` before this code existed.
  - Ubuntu capture fails with `SNAPSHOT_DATABASE_UNAVAILABLE`. Previously this
    was an unhandled `no such table: core_runningconfigsnapshot`.
* **When a device is read.** Only on the explicit POST "Refresh running
  configuration". A GET never contacts a device, and a test enforces this.
* **Storage.** Each snapshot is stored as an immutable `RunningConfigSnapshot`
  holding sanitized text, the digest, a timestamp, the source transport and the
  redacted-line count. Secret values are redacted (`<REDACTED>`) and never
  rendered.
* **Digest.** It uses the same formula as the import provenance
  (`running_config_digest`). A Change built from a snapshot carries
  `workflow_snapshot = {device, digest, snapshot_id}`.
* **Stale-snapshot guard.** The execution engine's PREPARE phase re-reads the
  device through the run's own session, recomputes the digest, and blocks with
  `SNAPSHOT_STALE` before any mutation if it differs (or
  `SNAPSHOT_UNVERIFIABLE` if it cannot re-read). Line-based removals therefore
  never run against stale line numbers.
* **Limitation (inherited from the sanitizer).** A change to only a redacted
  secret value does not change the digest.

## 4. Configuration Changes (incremental patch)

**Direct CLI mode ("Push configs into CLI directly").** Recognised lines are
normalized onto the same structured operations the widgets produce:

* `ip|ipv6 route`
* under `interface X`: `ip|ipv6 address … [secondary]`, `ip helper-address`,
  `ip ospf area`
* `interface LoopbackN` creation
* under the existing `router bgp N`: `neighbor X remote-as Y` and `network P`

Everything else is rejected with a reason and never sent:

* `no …` / `default …` → `REMOVAL_BELONGS_IN_REMOVE_CONFIGURATION`
* secret-bearing lines → `SECRET_MATERIAL_REFUSED` (the line is withheld)
* unknown syntax → `UNRECOGNISED_STATEMENT`
* unknown interface or BGP context → `INTERFACE_NOT_ON_DEVICE` /
  `BGP_PROCESS_NOT_ON_DEVICE`

Device Builder's Raw Configlet path (Phase 18) remains the route for opaque
CLI.

**Structured mode ("Push supporting configs").** The widgets are driven by the
execution capability registry:

| Widget | cEOS execution | Ubuntu/FRR |
|---|---|---|
| Static route | Complete or Partial | not executable |
| Address on an existing interface | Complete or Partial | Complete or Partial (iproute2) |
| New loopback interface | Complete or Partial | Complete or Partial (iproute2) |
| BGP neighbor (existing process) | Partial (UAT) only | not executable |
| BGP network (existing process) | Partial (UAT) only | not executable |
| OSPF interface attachment | Partial (UAT) only | not executable |
| DHCP relay | Partial (UAT) only | not executable |

Unsupported options are shown disabled with the capability note.

**Incremental semantics.** "Save Draft" does the following in one transaction;
any failure persists nothing:

1. Creates a normal `Change` (category `CONFIGURATION_CHANGE`, workflow
   `CONFIGURATION_CHANGES`), a target, and an EXISTING_DEVICE intent.
2. Imports the live running configuration through the Phase-20.5 importer as
   **context**. The import's provenance digest must equal the snapshot digest,
   or the draft is refused as stale.
3. Records every imported object id as `contribution_baseline`. This is part of
   the hashed validation input.
4. Applies each operation through the ordinary intent services and Tier-1 field
   commits. An INVALID value aborts.
5. Runs the existing Phase-13 validation and the Phase-14 planner.

The planner drops every baseline object
(`planning.builder._exclude_contribution_context`, plan warning
`CONTRIBUTION_CONTEXT_EXCLUDED`). The plan is therefore exactly the
contribution. For example, a secondary address produces only
`interface Ethernet2` + `ip address … secondary`. It is never a replacement
configuration, and nothing outside the requested patch is sent (a test
asserts the unrelated lines are absent).

The preview in the left pane is the plan's own Configlets: the rendered CLI, the
operation, and the validation findings and dependencies.

## 5. Remove Configuration

### 5.1 Model and first-class operations

* `ConfigletOperationType` gains `DEACTIVATE_DETACH` (an attachment or
  activation: ACL on an interface, secondary address, BGP AF activation…) and
  `REMOVE_DELETE` (a defined object: VLAN, SVI, neighbor, ACL…).
* `ConfigletOrigin` gains `REMOVAL`.
* `ConfigRemoval` stores one device's selection per Change.
* Migration: `0013_automation_config_workflows`.

Removal flows through the same lifecycle as everything else:

| Stage | Removal-specific behavior |
|---|---|
| Change snapshot | `config_removals` (the key exists only when present, so historical input hashes are unchanged). It carries the sanitized snapshot text. |
| Validation | `validation/removals.py` **re-derives** the analysis from that text. The page's copy is presentation, never authority. |
| Graph | One `config_removal` node per item. A referrer is removed first (`REQUIRES`). |
| Plan | Configlets with the parser-validated removal CLI; metadata carries the restore lines and verification paths. |
| Precheck / postcheck | Requirement `CONFIG_REMOVED` → check `CONFIG_OBJECT_ABSENT`. Evidence group `config_paths` holds header-qualified signatures of the sanitized running config, taken from the `show running-config` already read. |
| Execution (`CeosExecutor`) | Assess: present → APPLY; absent → SKIP; partial → REFUSE `REMOVAL_TARGET_DRIFTED`. Apply: the removal lines. Complete-mode compensation re-adds the captured original lines and verifies them by read-back. |

An object with redacted values is **not restorable**, so Complete mode refuses
it (Partial/UAT only).

This is **not** failure compensation. Compensation remains the engine's
internal undo of a failed Complete run, and it is also what protects a failed
removal.

### 5.2 Line-range removal

The operator enters *From* / *Through*, or clicks a line number (shift-click
extends the range). The selection resolves to:

* whole semantic objects whose every line is selected (a selected parent
  implies its children), and
* individually removable child lines (attributes), each rendered as
  `no <line>` inside its own block headers.

It is **blocked** when:

* a line opens an object that is not wholly selected (`PARTIAL_CONTEXT_SELECTED`,
  with the lines needed);
* the line is an identity line (for example `neighbor X remote-as Y` alone);
* the line is negated (`no shutdown`);
* the line holds a redacted value;
* the line is unrecognised or unmanaged;
* removing the line would **widen** behavior: removing a
  `switchport trunk allowed vlan` list would allow **all** VLANs.

Text is never simply deleted.

### 5.3 Smart / semantic removal

The object navigator lists every recognised object, with removability and
support status. Objects are granular:

* one BGP neighbor or peer group, one AF activation, one network statement,
  one redistribution
* one OSPF / RIP network statement or interface attachment, a whole routing
  process
* one secondary or IPv6 address, one primary address (only when it has no
  secondaries)
* one static route
* one VLAN (also from a `vlan 101-102` range), one SVI, loopback,
  sub-interface or port-channel
* one ACL, or one ACL sequence
* one route-map sequence, one prefix-list sequence
* one PBR policy, sequence, class-map or attachment
* one DHCP relay, one VARP VIP, one VRRP group, one access-VLAN membership

Physical interfaces are never deleted (`PHYSICAL_INTERFACE_NOT_DELETABLE`).

### 5.4 Dependency model

References come from:

* SVI → VLAN
* access port / trunk allowed-list / native VLAN → VLAN (a trunk with **no**
  allowed-list carries **every** VLAN)
* neighbor → route-map / prefix-list / peer group / update-source interface
* route-map → prefix-list / ACL
* interface → ACL / PBR policy
* PBR sequence → class-map → ACL
* VIP / VRRP → the interface's address
* OSPF interface attachment → OSPF process
* redistribution → route-map
* NAT → ACL / pool
* any unmanaged line that names an ACL, route-map or prefix-list (SNMP,
  management APIs…)

A redacted `snmp-server community` line may hide an ACL name, so its presence
blocks every ACL removal on that device (fail-safe).

Rules:

* Removing something still referenced by configuration that **stays** is
  **BLOCKED** (`STILL_REFERENCED`, listing every referrer and its lines),
  unless the referrers are part of the same removal.
* Removing one entry of a still-referenced ACL, prefix-list or route-map is
  allowed with a `POLICY_CHANGES` warning. Removing the **last** entry of a
  referenced list is blocked.
* Named objects that the removal leaves unused are **proposed**, never added.
  The operator ticks them explicitly, and both operations are then shown.
* Items are ordered referrer-first: detach before delete, and the SVI before
  its VLAN.

### 5.5 The SVI / VLAN rule (tested exactly)

* Remove `interface VlanX` where nothing else uses VLAN X → the SVI removal is
  READY and `vlan X` is **proposed**. Once accepted, the order is
  `no interface VlanX`, then `no vlan X`.
* Remove `interface VlanX` while VLAN X is still on an access port, a trunk, or
  another reference → only the SVI is removed, the VLAN is preserved, and
  nothing is proposed.
* Remove `vlan X` while it is still referenced → BLOCKED.

### 5.6 Management-plane protection

The following are PROTECTED and never removable here:

* `Management*` interfaces, `interface Vlan200` and their addresses
* VLAN 200 and VLAN 1
* static routes towards the management networks — 192.168.200.0/24,
  2001:db8:200::/64, **and the subnets of the management interfaces
  themselves** (for example the Containerlab `Management0` network that the
  default route uses)
* every unmanaged top-level stanza (users, AAA, management APIs, SNMP,
  logging…)
* entries of an ACL that such a stanza uses (for example `NMAS_SNMP`)

## 6. Syntax evidence and platform support

"Do not generate fake delete syntax" is enforced by an evidence class per form
(`config_workbench.removal`):

| Class | Meaning | Executable |
|---|---|---|
| `PARSER_VALIDATED` | Accepted by the **live cEOS 4.36.2F parser** inside a configuration session that was aborted or deleted **uncommitted**. The running-config SHA-256 was identical before and after on R1 and S1, and no probe session was left behind. | cEOS: yes (the live run still needs authorization) |
| `FIXTURE_ONLY` | Rendered and unit-tested; syntax not proven on a device. | no (validation `REMOVAL_NOT_EXECUTABLE`) |
| `NOT_IMPLEMENTED` | No renderer for the platform. | no |

Parser-validated on cEOS 4.36.2F (2026-09-27):

* **Interfaces:** `no interface Vlan99 | Loopback250 | Ethernet2.250 | Port-Channel250`
* **VLAN:** `no vlan 30`
* **Static route:** `no ipv6 route …`
* **Interface children:**
  * `no ip address … secondary`
  * `no ip address …`
  * `no ipv6 address …`
  * `no switchport access vlan`
  * `no ip access-group X in`
  * `no ip helper-address …`
  * `no ip virtual-router address …`
  * `no vrrp N`
  * `no ip ospf area …`
  * `no ipv6 ospf 10 area …`
* **Routing:**
  * `no redistribute rip route-map …`
  * RIP / OSPF `no network …`
  * `no router ospf 10`, `no ipv6 router ospf 10`, `no router rip`, `no router bgp N`
  * BGP `no neighbor X`, `no neighbor PG peer group`, AF `no neighbor X activate`, `no network …`
* **ACL / lists / route-maps:**
  * `no ip access-list [standard] X`
  * ACL `no 20`
  * `no route-map X deny 10`
  * prefix-list `no seq 30`
  * `no ip prefix-list X`
* **PBR:**
  * `no class-map type pbr match-any X`
  * `no policy-map type pbr X`
  * policy-map `no 10`
  * `no service-policy type pbr input X`
* **Attribute lines:**
  * `no description …`
  * `no mtu …`
  * `no switchport trunk native vlan`
  * `no neighbor X route-map … in`
  * `no passive-interface …`
  * `no ip ospf cost …`
  * route-map `no match …`

**Rejected by the parser (so never executable):** `no ip nat pool X` (the
rendered NAT-pool form). **Not probed (so FIXTURE_ONLY):** NAT rules and
`ip rip` interface attributes.

| Platform | Analysis / preview | Removal execution | Configuration Changes |
|---|---|---|---|
| Arista cEOS 4.36.2F | yes | PARSER_VALIDATED forms only | per the capability matrix (§4) |
| Ubuntu/FRR (R3/R4) | yes (`exit`-terminated blocks, 1-space indentation) | FIXTURE_ONLY: no incremental FRR apply path is proven | address/interface via iproute2 only |
| SR Linux, IOS XR, SONiC | not implemented | not implemented | not executable |

## 7. Execution safety

* Rendering, preview, validation and planning never deploy, and no workbench
  view executes anything.
* "Push / Execute…" opens the Change's own Execute page. That is the single
  execution route: CSRF-protected POST, explicit mode confirmation, UAT
  acknowledgements, a CURRENT validation and plan, and a recent precheck.
* The browser never supplies a device address or credential. Devices come from
  the server-side inventory list, a snapshot for another device is ignored, and
  every selection is re-derived on the server.
* Every removal and contribution Change is re-read and digest-checked before
  its first mutation.

## 8. Known limitations

* Nothing in these workflows is **live-verified**; only the parser syntax
  evidence (§6) touched a device, in uncommitted sessions.
* The semantic index is conservative. Unrecognised lines are unmanaged and
  protected, and an over-reported reference blocks rather than permits.
* Removal verification checks the removed statements' header-qualified
  signatures. It proves the statements are absent, not the downstream
  protocol effect. Use Health / IP-connectivity checks around a real run.
* Direct CLI recognises a deliberately small vocabulary. Anything else stays in
  Device Builder / Raw Configlets.
* The digest ignores redacted-only changes (a sanitizer limitation).
