# Phase 9 — Device Builder Foundation

This document describes the Phase 9 interactive Device Builder editing
shell: split-screen layout, browser-owned draft typing, the explicit
Enter/Commit boundary, Tier-1 field validation, field-local rollback, and
the one authoritative Python candidate-rendering contract. It builds
directly on the Phase 8 data model (`docs/DEVICE_INTENT_CHANGE_MODEL.md`)
without changing it — no migration was needed for this phase.

## 1. Device Builder architecture

```
Browser (device_builder.js)
   |
   | input/keypress -> mutates ONLY local JS state + preview
   | Enter / Ctrl+Enter / Commit button -> POST fields/commit/
   v
Django view (device_builder_field_commit)
   |
   v
field_commit_service.commit_field()
   |
   +--> intent_service.set_draft_field()          (Phase 8, unchanged)
   +--> field_validators.validate_*()              (Tier-1 only)
   +--> intent_service.accept_field_value() /
        intent_service.rollback_draft_to_accepted() (Phase 8, unchanged)
   +--> candidate_renderer.render()                 (authoritative)
```

Ownership stays exactly where Phase 8 established it: NetBox is passive
storage and is never touched by any Phase 9 code path; Python (this
service stack) owns all validation/rendering intelligence; Django owns
durable control-plane state (Change/DeviceIntent/DeviceIntentRevision/
IntentFieldState, all from Phase 8 -- no new model exists); the browser
owns only ephemeral, per-viewer draft typing state.

## 2. Split-screen model

`/device-builder/changes/<change_id>/intent/<intent_id>/` (Basic) and its
`/advanced/` sibling both render `core/device_builder/editor.html`:

- **Left** (`device-builder-editor__left`, ~42% width): the module
  catalogue -- Device Identity, Platform, and (Advanced only) Image /
  Deployment Metadata as editable `module-card`s, plus Interfaces/Routing/
  Services/Security rendered as `module-card--locked` with the honest label
  "Available in Phase 10+" -- no fake controls exist for them.
- **Right** (`device-builder-editor__right`, sticky on desktop up to
  900px, `overflow-y:auto` bounded so it can never produce unusable
  scrolling): the candidate preview panel, Copy/Download/Diff actions.
- Below 900px both stack to a single column (`.device-builder-editor`'s
  `@media (max-width: 900px)` rule in `base.css`), matching the existing
  sidebar breakpoint.

## 3. Browser draft state

`static/core/js/device_builder.js` keeps one JS object,
`state[path] = {draftValue, acceptedValue, dirty, validationState,
validationMessage}`, seeded from a `json_script`-embedded bootstrap blob
(`#device-builder-bootstrap`) built server-side in
`views.py::_editor_bootstrap()`. An `input` event
(`handleFieldInput`) updates only `draftValue`/`dirty` and re-renders the
preview by substituting the draft value into the server-provided
descriptor slots (see §7) -- it never calls `fetch()`, never submits a
form, and nothing is written to the database. `test_phase9_js_contract.py`
enforces this structurally (asserts `fetch(` appears exactly once in the
whole file, inside `commitField`, and is absent from `handleFieldInput`).

### 3a. Non-refresh editing model (Phase 20.5)

Two independent mutation mechanisms exist on this page, and both must avoid
a full browser navigation:

1. **Single-field edits** (`data-field-path` inputs) already worked this way
   from Phase 9: `handleFieldInput`/`commitField` above.
2. **Collection mutations** (Add/Remove Interface, Address, Static Route,
   BGP/OSPF/RIP/IS-IS/EIGRP instance or binding, FHRP/NAT/ACL/PBR/DHCP
   object, service mode) are ordinary server-rendered Django
   `<form method="post" class="collection-form">` elements -- there is no
   second client-side copy of their behavior or a duplicate endpoint set.
   Before Phase 20.5, submitting one of these (by button click, or by
   pressing Enter in a plain input with no `data-field-path`, which the
   browser's native "submit the nearest form" behavior turns into exactly
   this) caused a full page navigation, and the server-side redirect target
   (`views._collection_redirect`) was hardcoded to Basic mode with no
   interface/routing selection carried forward -- an operator working in
   Advanced, or with a routing instance selected, was silently dropped back
   to Basic with nothing selected.

The fix has two parts, both required:

- **Server**: `views._collection_redirect()` now reads the same-origin
  `Referer` header (the editor page that rendered the form) to recover
  which mode (Basic/Advanced path) and which `interface`/`routing_family`/
  `routing_instance` query parameters the operator was viewing, and
  redirects back to that same mode/selection. A newly created object
  (a new interface, a new routing instance) is explicitly selected via an
  override; a just-removed object's own selection is explicitly cleared
  (`clear=(...)`) rather than carried forward stale. This makes the
  *fetched* page already reflect the correct state, whether or not
  JavaScript is involved.
- **Browser**: `device_builder.js`'s `handleCollectionFormSubmit` (delegated
  `submit` listener on the editor root, so it also catches the Enter-key
  case) intercepts every `.collection-form` submission, sends it with
  `fetch()`, and replaces `root.innerHTML` with the fetched page's own
  `[data-device-builder-root]` fragment instead of letting the browser
  navigate. It then re-reads the fresh `#device-builder-bootstrap` JSON
  (`readBootstrap()`) and re-runs the same field-status/preview
  initialization every page load already does (`initializeView()`), updates
  the address bar via `history.replaceState` (no navigation triggered), and
  restores scroll position. A `.catch()` falls back to a real
  `form.submit()` if the network request fails, so the feature still works
  without JavaScript or on a transient error -- it degrades to the
  pre-Phase-20.5 (still now mode/selection-correct) behavior, not to a dead
  page. `test_js_contract.py` and `test_editor_views.
  CollectionRedirectPreservesEditorStateTests` cover this structurally and
  end-to-end.

Everything rendered inside `root` is reached through *delegated* listeners
on `root` itself (`input`/`keydown`/`click`/`submit`), never a one-time
`querySelector` + `addEventListener` on a specific descendant node -- a
descendant-bound listener would silently stop working the first time
`root.innerHTML` is replaced. `test_js_contract.py.
test_copy_candidate_survives_a_collection_form_dom_swap` guards this for the
Copy Candidate button specifically, since it was the one control still using
the old (broken-after-a-swap) pattern.

## 4. Durable accepted state

Durable state is exactly the Phase 8 `IntentFieldState` row set -- Phase 9
adds no new model. `field_commit_service.seed_device_identity_field_states()`
is called once, right after a `DeviceIntentRevision` is created, populating
`device.hostname` / `device.description` / `device.target_type` /
`device.platform` / `device.image_reference` rows (draft == accepted == the
intent's creation-time value) so the first page load has real state instead
of an empty revision.

## 5. Field commit contract

`POST /device-builder/changes/<change_id>/intent/<intent_id>/fields/commit/`
(JSON body: `path`, `value`, `revisionId`) is the **only** mutation
endpoint Phase 9 adds. `field_commit_service.commit_field()`:

1. Verifies `intent.change == change` and `revision.device_intent == intent`
   -- a browser-supplied `intent_id`/`revision_id` can never select an
   unrelated record (`RecordOwnershipError` / a revision-id mismatch
   returns HTTP 409 "stale revision -- reload the page").
2. Rejects any `path` not in `field_registry.FIELD_REGISTRY` --
   `UnknownFieldPathError` -> HTTP 400. There is no dynamic `eval`/`setattr`
   from a browser-supplied name; `mirrors_to` values are validated against a
   fixed allowlist (`_ALLOWED_MIRROR_FIELDS`) at import time.
3. Calls Phase 8's unchanged `intent_service.set_draft_field()`.
4. Runs the field's Tier-1 validator (see §6).
5. Valid -> normalizes if needed, calls the unchanged
   `intent_service.accept_field_value()`, sets
   `validation_state=VALID`, and mirrors the value onto the matching
   `DeviceIntent` column when one exists (`platform`, `target_type`,
   `image_reference` -- **not** `device_name`; see §20).
6. Invalid -> calls the unchanged `intent_service.rollback_draft_to_accepted()`,
   sets `validation_state=INVALID` with a message. Only this one
   `IntentFieldState` row changes; every sibling row is a separate row by
   construction (the Phase 8 invariant this module builds on, not
   redesigns).

The endpoint always returns the authoritative Python render (§7) so the
browser can reconcile itself after every commit.

## 6. Enter / commit behavior

- Single-line fields (hostname, platform select, target-type select,
  image reference): **Enter commits**.
- The multiline field (description): **Ctrl+Enter (or Cmd+Enter) commits**;
  plain Enter inserts a newline, exactly as the operator requested, because
  a textarea needs Enter for its ordinary job. An explicit **Commit**
  button is always available next to the description field for users who
  don't use the keyboard shortcut.
- Blur/focus-loss never commits anything -- only Enter/Ctrl+Enter/the
  Commit button does.

## 7. Tier-1 field validation

`core/services/field_validators.py` -- five validators, each
`(raw_value) -> (ok, normalized_value, message)`, syntax-only:

| Path | Rule |
|---|---|
| `device.hostname` | non-empty, ≤64 chars, `[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?`, trimmed |
| `device.description` | ≤500 chars, trimmed, empty allowed |
| `device.platform` | must be one of the 5 `Platform` enum values |
| `device.target_type` | must be `EXISTING_DEVICE` or `NEW_DEVICE` |
| `device.image_reference` | ≤255 chars, `[A-Za-z0-9][A-Za-z0-9._:/-]*`, empty always allowed |

**Explicit Tier-2 exclusion**: nothing here checks duplicate IPs, NetBox
collisions, prefix overlap, peer consistency, routing/VRF dependency, DHCP
conflict, topology impact, or platform cross-feature validity -- that is
Phase 13's job. No validator here calls NetBox, Git, GitHub, or a live
device. Whether `image_reference` is *required* for a `NEW_DEVICE` intent
is treated as a UI hint, not a Tier-1 rule (empty is always syntactically
valid) -- requiring it would be a cross-field rule, which is out of Tier-1's
scope by definition.

## 8. Field-local rollback

Proven both by unit tests
(`test_phase9_field_commit_service.py::HostnameCommitTests`) and live
verification (§16): committing an invalid hostname after two other fields
were already committed leaves those two fields' `accepted_value` completely
unchanged. There is no sibling reset, no whole-form refresh, and no
candidate-revision destruction -- an invalid commit is a single-row
`UPDATE`, nothing more.

## 9. CandidateRevision behavior

Phase 9 never creates a new `DeviceIntentRevision` per keystroke or per
field commit. `field_commit_service.resolve_active_revision()` always reuses
`intent.latest_revision()` -- the one active revision for the whole editing
session. Creating a genuinely new revision remains a distinct, explicit
service action (`intent_service.create_candidate_revision()`, unchanged from
Phase 8) that Phase 9's UI does not expose; that is reserved for a later
phase's probation-reset semantics.

## 10. Basic/Advanced synchronization

Basic and Advanced are two templates (well: one shared template,
`editor.html`, rendered with `mode="basic"`/`mode="advanced"`) pointed at
the **same** `DeviceIntent` and `DeviceIntentRevision` rows -- there is no
`AdvancedIntent` model or any second copy of state. Basic renders only
`device.target_type`, `device.hostname`, and `device.platform` inline;
Advanced adds `device.description` and `device.image_reference`. Because
both read the same `IntentFieldState` rows via `_editor_bootstrap()`, a
commit made on either page is immediately visible on the other on next
load -- proven by `test_phase9_views.py::BasicAdvancedSyncTests`.

## 11. Renderer architecture

`core/services/candidate_renderer.py::render(intent, revision,
field_overrides=None, use_draft=False)` is the **one** authoritative Python
rendering contract, reused by the editor preview today and intended for
deployment planning, deployment, Golden comparison, and rollback
preparation once those phases exist -- there must never be a second,
unrelated renderer. It reads only already-persisted `DeviceIntent`/
`IntentFieldState` values; it never queries NetBox, Git, GitHub, or a live
device.

`modules/eos_render.py` (`render()`/`eos_commands()`, Jinja2 +
`StrictUndefined`) was evaluated for reuse and deliberately **not** used
here: it requires every referenced template variable to be present
(`StrictUndefined`), which fights a payload that is often only partially
filled (draft mode, a `NEW_DEVICE` with no image yet). Its two functions
remain untouched and reserved for `master.py`'s frozen Lab-1 `.cfg.j2`
templates; Phase 9's renderer uses plain Python string construction instead
of Jinja for a five-line identity render. A future phase may switch to
Jinja once the interface/routing/service catalogue (Phase 10+) makes the
tradeoff worthwhile.

## 12. Platform renderer registry

`core/services/platform_drivers.py::PLATFORM_DRIVERS` maps each of the
six `Platform` identifiers to a `PlatformDriver` instance
(`CeosDriver`, `SrLinuxDriver`, `UbuntuFrrDriver`, `C8000vIosXeDriver`,
`IosXrDriver`, `SonicDriver`), each exposing `render_candidate(field_values)` and
`supported_feature_names()`. `candidate_renderer.render()` looks the driver
up by `intent.platform` (`platform_drivers.get_driver()`) -- there is no
`if hostname == "R1"` or `if platform == "..."` branching anywhere;
`test_phase9_candidate_renderer.py::test_no_hostname_conditionals_in_driver_or_renderer_source`
asserts this structurally.

## 13. Python-authoritative render contract

Every successful field commit's HTTP response includes the fresh
`candidate_renderer.render()` output; the browser calls
`setAuthoritativeCandidate()` to replace its locally-substituted preview
with that exact server output, closing the loop and guaranteeing the
visible preview and the server-authoritative render never permanently
diverge after a commit.

## 14. Browser preview strategy

Each driver returns a list of **descriptors**, not pre-joined strings:

```python
{"kind": "field", "path": "device.hostname", "template": "hostname {value}", "value": "R1", "omit_if_empty": True}
{"kind": "static", "text": "! Interfaces: not configured in current candidate"}
```

The initial page load embeds these descriptors (plus `header_lines`) in the
bootstrap JSON. `device_builder.js::renderPreviewFromDraft()` substitutes
the current **draft** value into each `field` descriptor's `template` and
re-joins the lines -- it never invents vendor syntax itself, including the
two-line disclaimer banner, which always comes from
`candidate.header_lines` rather than a hardcoded string in JS
(`test_phase9_js_contract.py::test_header_lines_never_hardcoded_only_from_server_candidate`).
This is exactly pattern (A)/(B) hybrid the Phase 9 brief called for: Python
renders the authoritative accepted candidate and hands the browser a
structured preview model; JavaScript only substitutes into known slots.

## 15. Copy Candidate

Client-side only (`data-copy-candidate` button): copies whatever text is
currently in the preview `<pre>` element, draft or accepted, via
`navigator.clipboard.writeText()` with an `execCommand("copy")` fallback
for browsers/contexts without the async Clipboard API. No claim of
validity is made or implied by copying.

## 16. Download Candidate

`GET /device-builder/changes/<change_id>/intent/<intent_id>/candidate/download/`
returns the server-generated **authoritative accepted candidate only** as a
`text/plain` attachment. Phase 9 deliberately does not offer a draft
download: the server cannot know true live-browser keystroke state without
a request per keystroke, which this project explicitly forbids, so any
"draft download" could only ever reflect the last *committed attempt* per
field, not what the operator is currently looking at -- Copy Candidate
already covers "copy exactly what I see, including live draft" client-side
without that ambiguity. Filename is `f"{safe(device_name)}-candidate.txt"`
where `safe()` maps every character outside `[A-Za-z0-9_-]` to `_` -- there
is no way to influence the response's file path or read another file; the
handler ignores any other query parameters entirely.

## 17. Draft-vs-accepted diff

`GET .../candidate/diff/` renders `candidate_renderer.diff_accepted_vs_draft()`
(a `difflib.unified_diff` between the accepted and draft renders) as a
static page using the existing `.diff-add`/`.diff-remove` CSS classes.
Both sides are built from **already-persisted** field state (the last
commit attempt, valid or invalid) -- this is computed only when the page is
explicitly requested, never automatically while typing, and never against
live running configuration. A future "Candidate vs Running" comparison
(Phase 7's live-read capability) is out of scope here and is not silently
fetched.

## 18. Existing vs New Device

`DeviceIntentTargetType.EXISTING_DEVICE` / `NEW_DEVICE` (Phase 8 enum,
unchanged) is editable via `device.target_type` like any other field.
Neither the create-Change form, the add-intent form, nor any field commit
performs a NetBox write, a topology change, or a Containerlab action for
either target type -- a `NEW_DEVICE` intent record existing does not imply
anything was provisioned.

## 19. Image-reference handling

`device.image_reference` stores a name/tag/reference string only (Phase 8's
`DeviceIntent.image_reference`, a `CharField`, unchanged) -- there is no
`FileField`/`BinaryField` anywhere and Phase 9 adds none. The Advanced
editor's image-reference row is always present in the DOM (so
`data-field-path="device.image_reference"` is inspectable/testable
regardless of target type) but is only *meaningful* for `NEW_DEVICE`; a
local image-existence check was considered and skipped as unnecessary
read-only complexity for this phase.

## 20. Field allowlist / security

`core/services/field_registry.py::FIELD_REGISTRY` is the only source of
truth for which paths a browser can commit to. Five entries exist today;
Phase 10+ adds interface/routing/service/security paths here, not before
those feature modules are real. Each entry's `mirrors_to` (the
`DeviceIntent` column a successful commit also updates) is checked against
a fixed set (`_ALLOWED_MIRROR_FIELDS = {"target_type", "platform",
"image_reference"}`) at import time -- a typo in the registry cannot open a
new attribute-write target. `device.hostname` deliberately does **not**
mirror to `DeviceIntent.device_name`: `device_name` is the external
identity key used in URLs, `ChangeTarget`, and `Configlet.target_device`
routing, and renaming it mid-edit would require cascading renames this
phase does not implement -- editing the candidate hostname is intentionally
decoupled from renaming the intent's identity. This is a deliberate design
choice, documented here as a known limitation (§26), not an oversight.

## 21. No-per-keystroke-server-call rule

Enforced in three independent ways: (1) `device_builder.js`'s
`handleFieldInput` structurally contains no `fetch(`
(`test_phase9_js_contract.py`); (2) the only server endpoint capable of
mutating field state is the explicit commit endpoint, which requires a POST
with a JSON body -- there is no GET-based or implicit mutation path; (3)
`beforeunload` only warns, it never force-persists anything.

## 22. No NetBox / device / GitHub / Git behavior

No Phase 9 module (`field_validators.py`, `field_registry.py`,
`platform_drivers.py`, `candidate_renderer.py`, `field_commit_service.py`,
or the new `views.py` functions) imports `netmiko`, `paramiko`, `pynetbox`,
`subprocess`, `influxdb`, or the Phase 7 live-device/NetBox adapters
(`nsot_live`, `nsot_netbox`, `netbox_ipam`) -- enforced by
`test_phase9_architecture.py`'s AST-based import check, the same technique
`test_architecture.py` already applies to `views.py`. Creating a Change or
DeviceIntent is application state only: no NetBox object, no topology
change, no CI trigger, no Git commit.

## 23. Theme behavior

No new theme/context is introduced. Every new Device Builder route
(`changes`, `change_detail`, `edit`, `advanced`, `candidate_diff`,
`capabilities`) is added to `context_processors.PAGE_URL_NAMES` mapped to
`page_key="device_builder"` (the read-only Changes/Change-detail pages from
Phase 8 were missing this mapping and have been fixed here too). The
existing `PAGE_THEME_CONTEXT["device_builder"]` entries already resolve
Dark Angels to **Core** and Adeptus Mechanicus to **Forge** for this
page_key (set up in Phase 3) -- Phase 9 needed no theme_registry change.
Candidate/config panels reuse the existing `.code-panel`/`--code-bg`/
`--code-text`/`--code-border` tokens verbatim (defined in exactly the same
4 theme blocks `test_architecture.py` already checks) so they stay
high-contrast and legible in every theme without a 5th override.

## 24. Known limitations

- `device.hostname` intentionally does not rename `DeviceIntent.device_name`
  (see §20) -- editing the candidate hostname and the intent's external
  identity are decoupled by design in Phase 9.
- Diff and Download reflect the **last committed attempt** per field, not
  literally the current unsaved browser keystrokes (impossible without a
  request-per-keystroke, which this project forbids) -- documented on both
  pages.
- No Selenium/Playwright browser automation exists in this repository
  (confirmed by search); Phase 5/6's "geckodriver" mention was a one-off
  manual verification step, not a reusable script. Phase 9 relies on Django
  test-client HTTP/JSON contract tests plus static JS-source contract tests
  and manual `curl`/shell live verification instead of adding a new
  browser-automation dependency for one phase's UI (see §16 Safe Live
  Verification in the final report for what was actually exercised).
- The Basic view does not inline the description field (it's Advanced-only)
  even though the underlying state is fully shared -- an intentional "Basic
  exposes minimum fields" reading of the brief, not a sync bug.
- No cross-platform capability filtering exists yet: switching platform
  never deletes `sections`, but nothing yet warns which of an intent's
  fields might not apply to the new platform (Phase 10+ scope, per the
  brief).

## 25. Phase-10 handoff

Phase 10 (interfaces, addressing, WAN modules) can build directly on:

- `FIELD_REGISTRY`: add new `interfaces.<name>.<attr>` entries here, each
  with its own Tier-1 validator, following the exact same shape.
- `PlatformDriver.render_candidate()`: extend each driver to emit interface
  descriptors once real interface state exists on `DeviceIntentRevision.sections`
  or new `IntentFieldState` rows -- keep using the descriptor pattern so the
  browser preview strategy keeps working unchanged.
- `field_commit_service.commit_field()`: unchanged contract; Phase 10 fields
  commit through the exact same endpoint.
- The Basic/Advanced split and the locked-module-card pattern in
  `editor.html`: unlock "Interfaces" by giving it real inline (Basic) and
  dedicated (Advanced) fields the same way Device Identity/Platform work
  today.
