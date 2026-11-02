# Phase 8 — Device Intent / Change / Configlet Data Model

This document describes the structured control-plane data model and service
contracts introduced in Phase 8. It is structure only: no configuration
generation, no network-semantic validation, no deployment, no Golden/
Probation/UAT behavior, no NetBox write. Those are later phases' scope, and
this document says explicitly where each boundary sits so Phase 9+ does not
have to re-derive it.

## 1. Model architecture / ownership boundaries

Five distinct data domains exist in this project, and Phase 8 deliberately
keeps them separate rather than collapsing them into one JSON blob:

| Domain | Owner | Notes |
|---|---|---|
| Device Intent (what the operator wants) | **Django** (this phase) | `DeviceIntent` + `DeviceIntentRevision` + `IntentFieldState` |
| Change / workflow state | **Django** (this phase) | `Change`, `ChangeTarget`, `Configlet`, lifecycle/audit models |
| Device observed state (live facts) | **Live device / NSOT** (`core/services/nsot_live.py`, Phase 7) | Never copied into DeviceIntent as authoritative |
| NetBox state (passive inventory/IPAM) | **NetBox** (`modules/netbox_ipam.py`, Phase 1-7) | Referenced by external name string only, never an FK |
| Git state (source/version/recovery) | **Git** | Only reference fields (`git_branch_ref`, `git_commit_ref`) exist on `Change`/`Configlet` in Phase 8; nothing is serialized to Git yet |

Persistence decision: all Phase 8 models are plain Django ORM models in the
existing `core` app (`web/core/models.py`), migrated normally
(`core/migrations/0002_phase8_device_intent_change_model.py`). Per the
non-negotiable rule for this phase, none of this data lives in NetBox (no
plugin, no custom field), in `topology-data.json`, or in InfluxDB. NetBox
stays passive storage; Django is the human control plane; Python (the
service layer, not NetBox, not views) owns all decision logic.

Primary keys are plain auto-incrementing integers, matching every existing
model in this project (`Notification` included) rather than introducing a
second PK convention. Every object also carries a stable, human-meaningful,
*immutable* external identifier where one is needed for later addressing
(`Change.change_id`, `Configlet.cfg_id`).

## 2. Change model

`Change` (`web/core/models.py`) is one controlled, operator-approved unit of
work.

**Identifier**: `change_id`, format `CHG-YYYYMMDD-NNNN` (e.g.
`CHG-20260920-0001`), generated server-side by
`core/services/change_service.py::create_change()`. It is:

- unique (DB `UNIQUE` constraint, plus a race-safe allocation loop — see
  "Concurrency" below),
- human-readable and URL/log/Git-metadata safe,
- **immutable after creation** — `Change.save()` raises `ValueError` if
  `change_id` differs from what is already persisted for that row (enforced
  in code, not just convention; proven by
  `test_phase8_models.ChangeIdentifierTests.test_change_id_is_immutable`).

The integer `id` primary key is an internal implementation detail; nothing
external should address a Change by it.

**Execution mode**: `ExecutionMode` (`COMPLETE` / `PARTIAL_UAT`), displayed
to the operator as exactly **"Complete"** / **"Partial (UAT)"**. Default is
`COMPLETE`. Phase 8 stores this distinction but implements **no** deployment
semantics for either value — creating a `PARTIAL_UAT` Change has zero side
effects beyond the field itself being set (proven by
`GoldenProbationSoakNotImplementedTests.test_partial_uat_execution_mode_has_no_deployment_side_effect`).

**Partial (UAT) acknowledgement**: five explicit boolean fields
(`uat_ack_target_is_authorized_nonprod`,
`uat_ack_partial_success_may_remain_applied`,
`uat_ack_dependent_stages_may_stop`,
`uat_ack_adjacent_traffic_may_be_affected`,
`uat_ack_operator_accepts_risk`) plus `uat_acknowledged_by`/
`uat_acknowledged_at`. All default `False`/blank/null. Nothing in Phase 8
ever sets them to `True` automatically — there is no acknowledgement
service action yet, only the fields to record one in Phase 9+.

**Targets / affected devices**: a separate `ChangeTarget` model
(`change`, `device_name`, optional `netbox_device_ref`, `site`), not a bare
list column, so each target can carry its own metadata and be queried
independently. `device_name` is a plain external string (see §22).

**Metadata / future references**: `git_branch_ref`, `git_commit_ref`,
`github_actions_run_ref`, `deployment_reference`, `candidate_revision`
(overall bundle-level counter) are all nullable/blank and are never
populated with placeholder values in this phase. `metadata` is a `JSONField`
policed by the shared secret policy (§21) before it can be saved.

**Category / validation state**: `ChangeCategory` (configuration change, new
device provisioning, decommission, rollback, other) and `ValidationState`
(`PENDING`/`PASSED`/`FAILED`) are structural fields only — nothing in Phase 8
ever sets `ValidationState` to `PASSED`/`FAILED` (that requires a real
validator, Phase 13).

## 3. Device Intent

`DeviceIntent` (one per `(change, device_name)`) captures *what* is wanted,
distinct from `DeviceIntentRevision` (the *versioned payload* of that want)
and `IntentFieldState` (the *per-field draft/accepted state* within one
revision).

- **Existing vs new device**: `DeviceIntentTargetType.EXISTING_DEVICE` /
  `NEW_DEVICE`. New-device intent may carry `image_reference` (a name/tag
  string only — see §16) and use a proposed `device_name` rather than one
  that exists in NetBox today.
- **Platform**: `Platform` enum with six stable identifiers —
  `arista_ceos`, `nokia_srlinux`, `ubuntu_frr`, `cisco_c8000v_iosxe`,
  `cisco_iosxr`, `sonic` —
  matching the intended Device Builder platform catalogue. An unsupported
  string is rejected by `intent_service.create_or_get_device_intent()`
  before it ever reaches the database.
- **Schema version**: every `DeviceIntentRevision.sections` payload carries
  `schema_version` (`PositiveIntegerField`, defaults to `1`, validated
  `>= 1`). This lives on the *revision*, not the parent `DeviceIntent`,
  since the versioned thing is the payload, and different revisions of the
  same intent could in principle be written under different schema versions
  as Phase 10+ evolves the schema.
- **Feature namespace**: `sections` is a single `JSONField` holding the
  modular structure described in the Phase 8 brief — top-level keys
  `interfaces` / `routing` / `nat` / `fhrp` / `services` / `security` (see
  `FeatureNamespace` for the matching Configlet-side enum). Phase 8
  guarantees the *namespace contract* only; Phase 10+ populates real
  per-feature schemas.
- **Candidate revisions**: `DeviceIntentRevision.revision` is a positive
  integer starting at 1. `intent_service.create_candidate_revision()`
  always creates a **new row** — it never overwrites
  `sections`/`metadata` on a prior revision. `revision` and the parent FK
  are immutable after creation (same `save()`-guard pattern as
  `Change.change_id`). Uniqueness of `(device_intent, revision)` is a real
  DB constraint, not just a convention — see "Concurrency" below.

## 4. Draft / accepted field state — the Phase-9 contract

This is the part every future Device Builder interaction depends on, so
Phase 8 gets the *representation* exactly right even though it implements
none of the interactive behavior yet.

`IntentFieldState` is one row per `(revision, path)`:

| Field | Meaning |
|---|---|
| `path` | Dotted namespace path, e.g. `interfaces.Ethernet1.ipv4_address` |
| `draft_value` | What the operator is currently typing/previewing |
| `accepted_value` | The last value that passed field-level commit validation |
| `dirty` | `draft_value != accepted_value` |
| `last_committed_at` | Set only when `accepted_value` is updated |
| `validation_state` / `validation_message` | Set by a future Phase-9 validator; Phase 8 leaves this `UNVALIDATED` |

**Mutation behavior**, all in `core/services/intent_service.py`:

- `set_draft_field(revision, path, draft_value)` — creates the row on first
  use (draft == accepted, matching the "initial state" contract) or updates
  only `draft_value`/`dirty` on an existing row. `accepted_value` is never
  touched by this call.
- `accept_field_value(revision, path)` — promotes `draft_value` into
  `accepted_value`, clears `dirty`, stamps `last_committed_at`. No semantic
  validation happens here — Phase 8 has no validator to run.
- `rollback_draft_to_accepted(revision, path)` — reverts `draft_value` back
  to `accepted_value` for exactly this field. This models the Phase 9
  "invalid commit rolls back" behavior without an actual validator.

Because every field is its own row, mutating one field is structurally
incapable of mutating a sibling field — there is no shared JSON document
where an edit to one key could accidentally touch another. This is proven
directly by
`test_phase8_services.DraftAcceptedFieldStateTests.test_reverting_one_field_preserves_sibling_fields`.

**Why keystrokes are not persisted here**: `set_draft_field()` is a durable,
server-side write — appropriate for "operator committed a value" moments,
not for "operator pressed a key." Phase 9's browser-side editor will hold
live typing state itself (e.g. in a JS model / local component state) and
call `set_draft_field()` only at meaningful commit boundaries (blur, Enter,
explicit save), never per keystroke. This keeps `IntentFieldState` a
small, meaningful table instead of a keystroke log.

**Phase-9 handoff contract**: on Enter/commit, Phase 9's field validator
runs; on failure, it calls the equivalent of `rollback_draft_to_accepted()`
for *that field only* and sets `validation_state=INVALID` with a message;
on success it calls `accept_field_value()` and sets
`validation_state=VALID`. Phase 8 provides every hook needed for that except
the validator itself.

## 5. Configlets

`Configlet` is one atomic-ish deployable configuration unit inside a
`Change`.

- **Identifier**: `cfg_id` (e.g. `CFG-004`), derived from `sequence`
  (`f"CFG-{sequence:03d}"`) by `configlet_service.create_configlet()`,
  unique within its `Change` and immutable after creation (same guard
  pattern as `Change.change_id`). Human representation is
  `"{change.change_id} / {cfg_id}"` (`Configlet.full_identifier`), so an
  operator can eventually say "rollback CFG-004 but leave CFG-001/CFG-002"
  unambiguously.
- **Target device**: plain external device-name string (§22), optionally
  linked to a `DeviceIntent` via FK when one exists for that device in the
  same Change.
- **Feature namespace**: `FeatureNamespace`, the same vocabulary as intent
  sections.
- **Operation type**: `ConfigletOperationType.CREATE_DEFINE` vs
  `ACTIVATE_ATTACH` — e.g. defining an ACL is `CREATE_DEFINE`; applying it
  to an interface (traffic-affecting) is `ACTIVATE_ATTACH`. The future
  deployment engine (Phase 13+) is expected to treat these very
  differently; Phase 8 only records the distinction.
- **Deployment priority**: `DeploymentPriority` — a 9-tier
  `IntegerChoices` taxonomy (foundation/access -> ... -> persistence)
  matching the unified deployment order in the Phase 8 brief. Stored, not
  executed; the dependency graph (Phase 13+) may override simple numeric
  ordering where necessary.
- **State/config fields**: `previous_state_ref` / `desired_state_ref`
  (JSON *references*, never raw secrets — §21), `rendered_config` /
  `rollback_config` (both empty strings in Phase 8 — no renderer exists
  yet), `verification_spec` (JSON, empty by default),
  `execution_status` (`PENDING` by default; nothing in Phase 8 ever
  transitions it to `DEPLOYED`).
- **Dependencies**: `ConfigletDependency(configlet, depends_on)` is a real
  relational edge (FK pair with a `UniqueConstraint` and a
  `CheckConstraint` forbidding `configlet == depends_on`), not a
  comma-separated string. `configlet_service.add_configlet_dependency()`
  additionally rejects self-dependency and cross-Change dependency with a
  clear `ValueError` (same-Change dependencies are the only kind supported
  in Phase 8, per the brief) and translates a duplicate-edge
  `IntegrityError` into `ValueError`. Full cycle detection is Phase 13's
  dependency-planner job; Phase 8 only guarantees the edges themselves are
  well-formed.

## 6. Lifecycle model

`ChangeLifecycleState` vocabulary (on `Change.lifecycle_state`):

```
DRAFT -> VALIDATED -> CI_PENDING -> CI_FAILED -> READY_TO_DEPLOY ->
DEPLOYING -> DEPLOYED -> UAT -> PROBATION -> GOLDEN
                                  \-> FAILED -> ROLLED_BACK -> SUPERSEDED
```

(Not a strict linear chain — this lists the states, not a transition
graph; Phase 8 implements no transition graph at all.)

**Mapping onto `Notification.EventType`'s reserved producer values** (Phase
4 already reserved these but never wired a producer): a future
`DEPLOYED` transition would eventually call `publish_event(event_type=
DEPLOYMENT_SUCCEEDED, ...)`; `FAILED`/`ROLLED_BACK` map to
`DEPLOYMENT_FAILED`/`ROLLBACK_FAILED`/`ROLLBACK_SUCCEEDED`; entering `UAT`
maps to `UAT_PARTIAL`; a blocked `GOLDEN` promotion maps to
`GOLDEN_PROMOTION_BLOCKED`; a `PROBATION` regression maps to
`SOAK_REGRESSION`/`SOAK_COMPLETE`. **None of these calls exist yet** —
Phase 8 does not publish a single Notification for lifecycle changes, by
design (see "Notification integration" in the Phase 8 brief: don't spam
notifications for structural CRUD). This mapping is documented so Phase 13+
does not have to invent new EventType values for something Phase 4 already
reserved.

**History**: `ChangeLifecycleEvent(change, from_state, to_state, reason,
actor, occurred_at, metadata)` is append-only —
`lifecycle_service.record_lifecycle_event()` is the only way to create one,
and the model's `save()` raises `ValueError` on any attempt to modify an
already-persisted row. `record_lifecycle_event()` also updates
`Change.lifecycle_state` in the same transaction, so the "current state"
field and the "history" table can never disagree.

**Explicitly NOT implemented in Phase 8** (all confirmed by
`GoldenProbationSoakNotImplementedTests`):

- No automatic lifecycle transition of any kind — every row is one explicit
  `record_lifecycle_event()` call.
- No Golden bundle model/artifact exists (`hasattr(models, "GoldenBundle")`
  is `False`).
- No soak timer model/mechanism exists.
- No UAT deployment is ever executed — setting `execution_mode=
  PARTIAL_UAT` has zero device-facing effect.
- Reaching lifecycle state `GOLDEN`/`PROBATION` is just an enum value being
  set; it carries no promotion/soak semantics whatsoever until a much later
  phase builds them.

### 6a. Draft deletion (Phase 20.5)

Rendering a candidate never deploys it, and an operator must be able to
discard a draft they no longer want to continue -- `change_service.
delete_draft_change()` (called from the "Delete Draft" action on the
Changes list and the Change detail page, `views.
device_builder_delete_change`) permanently removes one Change's
application state: the `Change` row itself and everything that legitimately
cascades from it (`DeviceIntent`, `DeviceIntentRevision`, `IntentFieldState`,
`ChangeTarget`, `Configlet`, `ChangeLifecycleEvent`). It can never touch a
device, NetBox, or a Golden/Probation/UAT bundle.

Because Section 6 above is true -- `lifecycle_state` never advances
automatically -- a Change can carry real validation/plan/precheck/execution
history while its `lifecycle_state` still literally reads `DRAFT`.
Deletion eligibility is therefore never decided by `lifecycle_state` alone.
`change_service.can_delete_draft()` / the internal `_draft_deletion_blockers()`
check, independently:

- `lifecycle_state == DRAFT` (a Change that was ever explicitly advanced
  carries real history and is refused);
- no `ChangeExecutionRun` exists for the Change (execution history);
- no `OperationalCheckRun` exists for the Change (precheck/postcheck
  history);
- no `ConfigurationBundle` exists for the Change (a UAT/Probation/Golden
  bundle) -- also independently enforced by the database itself, since
  `ConfigurationBundle.change` is `on_delete=PROTECT`, so this specific
  guard could be bypassed entirely and the delete would still fail rather
  than silently removing a Golden-lineage bundle.

Any one of these blocks the delete with a specific message, and the SAME
check decides whether the "Delete Draft" control is even shown, so the UI
and the enforcement can never disagree. A separate explicit `DELETE`
confirmation (a required checkbox, matching every other collection-removal
control in Device Builder) is checked before any of the above.

`AuditEvent(event_type=DRAFT_CHANGE_DELETED, ...)` is written in the same
transaction as the delete; since `AuditEvent.change` is `on_delete=SET_NULL`
(Section 7), this audit row survives the Change it describes -- the fact
that a draft existed and was deliberately discarded remains in the audit
trail even though the Change row itself is gone. See `test_draft_deletion.py`.

## 7. Audit model

`AuditEvent(event_type, change, object_type, object_id, actor, summary,
metadata, created_at)` is the general-purpose, append-only trail for
control-plane mutations other than lifecycle transitions (which get the
more structured `ChangeLifecycleEvent` instead). Phase 8 populates it for:
`CHANGE_CREATED`, `INTENT_CREATED`, `INTENT_REVISED`, `CONFIGLET_CREATED`,
`LIFECYCLE_CHANGED`, `FIELD_ACCEPTED`. `VALIDATION_RECORDED`,
`DEPLOYMENT_RECORDED`, `ROLLBACK_RECORDED` are reserved `AuditEventType`
values, unused until those phases exist — same "reserve the enum value
now, wire the producer later" pattern as `Notification.EventType`.
Immutability is enforced the same way as `ChangeLifecycleEvent`.

## 8. Secret handling

**Policy**: `core/services/secret_policy.py` is the *one* reusable
denylist/rejection helper, generalized from Phase 4's
`notification_service._validate_metadata` (which now delegates to it
rather than keeping a second, drifting copy). Any dict key containing
`password`, `passwd`, `secret`, `token`, `webhook`, `credential`,
`apikey`/`api_key`, `private_key`/`priv_key`, `auth_key`, or `community`
(case-insensitive substring match, checked recursively through nested
dicts/lists) raises `ValueError` — hard rejection, never silent stripping.
A key ending in `_ref` (e.g. `secret_ref`, `credential_ref`) is exempt: it
names a reference to a secret held elsewhere, not the secret itself.

**Enforcement points**: every Phase 8 service function that accepts a JSON
payload (`Change.metadata`, `DeviceIntent.metadata`,
`DeviceIntentRevision.sections`/`metadata`, `Configlet.metadata`/
`previous_state_ref`/`desired_state_ref`/`verification_spec`,
`ChangeLifecycleEvent.metadata`) runs it through
`secret_policy.assert_no_secret_shaped_keys()` *before* any database write
is attempted — proven by
`test_phase8_models.SecretHandlingModelTests` (a raw `password`/`api_token`
value never reaches the database; a `*_ref` value does).

**Later credential remediation**: Phase 23 removed current-tree device password
values and replaced them with protected runtime references. Phase 24 adds a
per-device cEOS automation profile while preserving the fleet default. The
Phase 8 models still never copy or persist secret values; their `*_ref`
convention remains metadata, not a secret store. Historical plaintext exposure
still requires separately authorized credential rotation.

## 9. Service layer

Four new modules under `core/services/`, all pure Django-ORM CRUD — no
Netmiko/Paramiko/pynetbox/InfluxDB import anywhere (enforced by
`test_phase8_models.NoForbiddenImportsTests`, the same AST-based rule
`test_architecture.py` already applies to `views.py`):

- **`change_service.py`** — `create_change()` (allocates `change_id`,
  creates the initial `DRAFT` lifecycle event and `CHANGE_CREATED` audit
  row, all in one `transaction.atomic()` block), `add_target()`,
  `get_change_or_404()`, `list_changes()`.
- **`intent_service.py`** — `create_or_get_device_intent()`,
  `create_candidate_revision()`, `set_draft_field()`,
  `accept_field_value()`, `rollback_draft_to_accepted()`.
- **`configlet_service.py`** — `create_configlet()` (allocates `sequence`/
  `cfg_id`), `add_configlet_dependency()`.
- **`lifecycle_service.py`** — `record_lifecycle_event()`,
  `list_lifecycle_history()`.

Views call these services exactly the way every existing view calls
`monitoring_service`/`nsot_service`/etc. — one service call, one render.

## 10. Migrations

One new migration: `core/migrations/0002_phase8_device_intent_change_model.py`
(`core/migrations/0001_notification.py` is untouched). It creates 9 new
tables (`Change`, `ChangeTarget`, `DeviceIntent`, `DeviceIntentRevision`,
`IntentFieldState`, `Configlet`, `ConfigletDependency`,
`ChangeLifecycleEvent`, `AuditEvent`), their indexes, and their
`UniqueConstraint`/`CheckConstraint` declarations. Verified:

- `manage.py migrate` applies cleanly from the Phase 1-5 baseline.
- Re-running `manage.py migrate` reports "No migrations to apply."
  (idempotent).
- `manage.py makemigrations --check --dry-run` reports "No changes
  detected" after the migration exists (model/migration are in sync).
- `manage.py check` reports no issues.

## 11. Concurrency

Two places allocate a "next number" that must stay unique under concurrent
writers: `Change.change_id`'s daily sequence, and `Configlet.sequence`/
`DeviceIntentRevision.revision` within their parent. All three follow the
same pattern instead of "read max, blindly insert max+1":

1. Read the current max inside the service function.
2. Attempt to create the row with the computed next value **inside
   `transaction.atomic()`**.
3. Rely on a **real DB `UniqueConstraint`** to reject a racing duplicate
   with `IntegrityError`.
4. Catch that `IntegrityError` outside the (already-rolled-back) atomic
   block and retry with a freshly recomputed next value, bounded to a
   small number of attempts.

This does not use `select_for_update()` because the project's database is
SQLite, which does not support row-level locking — relying on it here
would either silently no-op or raise, depending on Django version. The
constraint-plus-retry pattern is correct under SQLite today and remains
correct if the project ever moves to a database that *does* support
`SELECT ... FOR UPDATE`.

## 12. Immutability

Enforced in code, not just documentation, via two small helpers in
`models.py`:

- `_forbid_field_mutation(instance, field_name)` — used by `Change.save()`
  (`change_id`), `Configlet.save()` (`cfg_id`), and
  `DeviceIntentRevision.save()` (`revision`, `device_intent_id`). Raises
  `ValueError` if the field differs from what is already persisted.
- `_forbid_row_mutation(instance)` — used by `ChangeLifecycleEvent.save()`
  and `AuditEvent.save()`. Raises `ValueError` if the row already exists at
  all (full append-only semantics). The admin registrations for both
  models additionally disable add/change/delete permissions, so there is
  no UI path that could look like it rewrites history either.

## 13. Device references

No Phase 8 model has a Django `ForeignKey` into any NetBox-mirroring table.
`ChangeTarget.device_name`, `DeviceIntent.device_name`, and
`Configlet.target_device` are all plain `CharField`s validated against
`DEVICE_NAME_VALIDATOR` (`^[A-Za-z0-9_-]{1,64}$`), the same external-identity
pattern `core/services/nsot_service.py` already enforces for device-detail
lookups. An optional `netbox_device_ref` field on `ChangeTarget`/
`DeviceIntent` exists purely as a *read-only lookup hint* (e.g. NetBox's own
device name) for a future page to resolve through
`core/services/nsot_netbox.py` — never a joined/enforced relationship.
Reconciliation between a Phase 8 device name and live NetBox state is
expected to happen the same way Phase 7's NSOT pages already do it: a
read-time lookup through `nsot_netbox.py`, not a stored foreign key.

## 14. Existing vs new device / platform / image reference

`DeviceIntentTargetType.EXISTING_DEVICE` targets a device NetBox/topology
already knows about; `NEW_DEVICE` represents a proposed device that does not
exist yet (infrastructure-level change). `Platform` is a closed enum of six
identifiers (`arista_ceos`, `nokia_srlinux`, `ubuntu_frr`,
`cisco_c8000v_iosxe`, `cisco_iosxr`, `sonic`). Catalyst 8000V uses IOS XE;
IOS XR is a separate platform and neither identity aliases the other.
`DeviceIntent.image_reference` stores a name/tag/reference **string only** —
there is no `FileField`/`BinaryField` anywhere in this model (proven by
`test_phase8_models.DeviceIntentTests.test_no_image_binary_field_exists`).
Vendor images stay local on NMAS; Git/Django would only ever store a
reference to one, never the binary itself.

## 15. Read-only UI

Two new routes under the existing Device Builder section, both `GET`-only
(`@require_GET`, so a `POST` gets HTTP 405 automatically rather than
needing a bespoke check):

- `/device-builder/changes/` — list of recorded Changes.
- `/device-builder/changes/<change_id>/` — one Change's targets, device
  intents (with latest revision number), configlets (with their
  dependencies), and full lifecycle history.

Neither page has a form, a Push/Deploy button, or any element that could be
mistaken for a mutation control — there is no HTTP endpoint in Phase 8 that
writes to any of these models at all; all writes so far happen only through
direct service-layer calls (tests, management shell, a future management
command), never through a browser-reachable POST. The existing Device
Builder landing page (`/device-builder/`) keeps its honest
`not_integrated` summary (the guided intent-capture/candidate-generation
*engine* is still Phase 9+ scope) and adds one link out to the new
inspection page. All Phase 8 templates rely on Django's default
autoescaping — no `|safe` filter is used anywhere on Change/Configlet
content, so operator-supplied text (titles, descriptions) cannot inject
HTML. Django admin registrations exist for every new model for local
development convenience only; the lifecycle/audit admin pages are
explicitly view-only (no add/change/delete), and no admin `list_display`
names a secret-shaped field (nor could it — no model field ever holds a raw
secret).

## 16. Known limitations

- No cycle detection on `ConfigletDependency` beyond same-Change/no-self
  checks — full dependency-graph validation is Phase 13's job.
- `Change.candidate_revision` is a bare counter with no service action
  wired to it yet (no "redo the whole bundle" flow exists) — the field
  exists so Phase 9+ does not need a migration to add it later.
- `IntentFieldState.validation_state` can only ever be `UNVALIDATED` in
  Phase 8 — there is no validator to set `VALID`/`INVALID`.
- No notification is published for any Phase 8 CRUD action, by design
  (avoids spamming Slack/in-app notifications for structural changes); the
  lifecycle-state -> `Notification.EventType` mapping in §6 is documented
  for Phase 13+ to wire up, not implemented here.
- Field-level values (`draft_value`/`accepted_value`) are stored as
  `JSONField`, so they can hold any JSON-serializable value; Phase 8 does
  not constrain their shape per-namespace (Phase 10+ feature modules will
  define what "valid shape" means per field).

## 17. Phase-9 handoff

Phase 9 (Device Builder shell: split-screen intent editing, instant
candidate preview, draft/accepted field commit behavior) can build directly
on:

- `intent_service.set_draft_field()` / `accept_field_value()` /
  `rollback_draft_to_accepted()` as the exact server-side calls a
  keypress-vs-Enter frontend needs — call `set_draft_field()` on each
  commit-worthy moment (not every keystroke), `accept_field_value()` after
  a real field validator (which Phase 9 must add) passes, and
  `rollback_draft_to_accepted()` when it fails.
- `change_service.create_change()` / `add_target()` and
  `intent_service.create_or_get_device_intent()` /
  `create_candidate_revision()` as the exact calls a "New Change" /
  "Add device" flow needs.
- `configlet_service.create_configlet()` / `add_configlet_dependency()` once
  Phase 9/10 starts generating real configlets from accepted intent.
- `/device-builder/changes/<change_id>/` as the read-only reference for
  what a real Device Builder detail page needs to eventually render live
  (targets, intents, configlets, dependencies, lifecycle history all
  already queryable in one place).
