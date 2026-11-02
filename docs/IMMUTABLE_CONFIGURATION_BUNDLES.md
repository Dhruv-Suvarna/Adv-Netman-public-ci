# Phase 19 — Immutable configuration bundles (UAT → Probation → Golden foundations)

A bundle is **evidence**. It is not a mutable "current configuration" record: it is an immutable, content-addressed artifact that freezes
exactly what a historical Partial (UAT) execution applied, together with its provenance. Phase 19 provides the artifacts and the safe
transition foundations; the probation soak and the Golden decision are **Phase 20**.

It is a reusable Python service (`web/core/services/bundles/`, facade `bundle_service.py`); Django views are thin adapters. It builds **no**
planner, executor, raw verifier, postcheck engine, Git deployment engine or NetBox controller: Phase 17 stays the only mutating engine and
Phase 18 the only raw verifier. Creating, deriving, verifying or exporting a bundle **never configures a device**.

Contents: 1 Lifecycle and the Phase-20 boundary · 2 Data model · 3 Manifest · 4 Canonicalization and digests · 5 Immutability · 6 Lineage ·
7 UAT eligibility · 8 Partial prefix semantics · 9 Raw Configlets · 10 UNVERIFIED and warnings · 11 Probation derivation · 12 Golden foundation ·
13 Integrity verification · 14 Export · 15 Security and secrets · 16 UI workflow · 17 Concurrency and idempotency · 18 Audit · 19 Tier-3 and tests ·
20 Local database · 21 Known limitations.

## 1. Lifecycle and the Phase-20 boundary

```
finished Partial (UAT) execution run
        │  explicit POST "Create UAT bundle"
        v
   UAT bundle A            "this exact immutable scope is the UAT artifact"
        │  explicit, confirmed POST "Create Probation bundle"
        v
   Probation bundle B      "this exact same artifact is the candidate ENTERING probation"
        │  Phase 20 only (soak + evidence + explicit operator decision)
        v
   Golden bundle C         "after the required evidence and an explicit decision, this artifact is the approved known-good configuration"
```

A remains UAT forever, B remains Probation forever, C will remain Golden forever. **A transition never edits a row**: it creates a NEW bundle
whose `parent` is the previous one. Bundle **kind** (UAT / PROBATION / GOLDEN) and **soak state** are different concepts; no soak state exists in Phase 19.

| Phase 19 | Phase 20 |
|---|---|
| creates the immutable UAT bundle from an eligible finished Partial (UAT) run | starts / records / evaluates the required soak |
| explicitly derives an eligible, verified UAT bundle into a Probation candidate | tracks the seven-day observation window and collects operational evidence |
| defines what a Golden bundle **is** (model, lineage, digests, display, integrity) | handles the operator's final Golden decision |
| provides the integrity / provenance foundation and the Golden **service seam** | creates the Golden descendant when eligibility is met |

**Probation is not soak success.** Creating a Probation bundle means only that the candidate has entered the probation lifecycle boundary. It does not
mean any time has passed, that anything is healthy, that a soak passed, or that it is Golden. There is no timer, no scheduler, no telemetry query and no
`soak_*` field in Phase 19. **No Phase-19 action creates a Golden bundle** (§12); nothing infers Golden from "tests passed", "currently deployed", "no errors
observed" or a successful Complete execution. The `Change` lifecycle is not touched by any bundle action.

## 2. Data model (migration `0008_phase19_configuration_bundles`)

| Model | Role |
|---|---|
| `ConfigurationBundle` | The artifact. `bundle_id` (`BND-UAT-000001`, `BND-PROB-000001`, `BND-GOLD-000001`; per-kind counter; the stable operator identity, **not** part of any digest), explicit `kind` enum, `schema_version`, `builder_version`, `payload_digest`, `bundle_digest`, `manifest` (JSON), `parent` / `source_uat` (self, PROTECT), and PROTECT foreign keys to the pinned `change`, `plan`, `validation_run`, `execution_run`, `postcheck_run`. `created_at` / `created_by` are immutable creation metadata. |
| `ConfigurationBundleItem` | One ordered Configlet: a normalized projection of `manifest.payload.items[i]` (the full canonical `record`, `payload`, `payload_hash`, `item_digest`, order, device, platform, origin, operation, priority) plus PROTECT pins to the plan Configlet, the exact `RawConfigletRevision` and `RawConfigletVerificationRun` (raw only) and the `ConfigletExecutionResult`. |
| `AuditEventType` | `UAT_BUNDLE_CREATED`, `PROBATION_BUNDLE_CREATED`, `BUNDLE_INTEGRITY_FAILED`. |

There is deliberately no bundle-device table (devices are in the manifest and derivable from the items), no `DRAFT_GOLDEN` / `SOAKING` / `PROMOTED` kind, no
`soak_*` field, no admin registration and no edit form. The models are named so the Phase-8 absence guard (`GoldenBundle`, `ProbationRecord`, `SoakTimer`) still holds.

## 3. Manifest (schema version 1)

The stored `manifest` is `{"manifest_schema_version", "kind", "lineage", "payload"}`; digests are stored **beside** it, never inside it.

```
lineage:  {parent_bundle_digest, source_uat_bundle_digest}          ("" for a UAT root)
payload:  payload_schema_version
          source:        change_id · validation{run_id,status,input_hash,source_hash} · plan{plan_id,plan_hash,planner_version}
                         · execution{run_id,mode,outcome,plan_hash,precheck_run_id} · git{repository_head | "UNKNOWN"}
                         · engines{validation,planner,execution,postcheck}
          scope:         mode · through_cfg_id · requested (exact ordered prefix) · plan_order · out_of_scope (ids only) · devices
          verification:  state VERIFIED|UNVERIFIED · execution_outcome · postcheck{run_id,result,engine_version,counts,cfg_ids}
                         · unverified[{cfg_id,code,requirement}] · unverified_count · raw_cfg_ids · execution_warning_codes
          items[]:       order · cfg_id · plan_sequence · device · platform · origin STRUCTURED|RAW · operation · namespace · priority · description
                         · source{node_id,object_type,object_id} · payload · payload_hash · depends_on · expected_state (verification descriptors)
                         · raw{raw_id,revision,revision_content_hash,assertions,priority,verification{run_id,result,policy_version,verifier,backend,
                           scope:"SYNTAX_ONLY",semantics_verified:false}} · execution{phase,status,error_code,partial_effects,lines_sent}
          dependencies[] edges inside the scope only
```

Only what was **persisted historically** is read: the plan Configlet's frozen fields (`Configlet.PLAN_FROZEN_FIELDS`) and its dependency edge rows. Fields the
execution engine rewrites afterwards (`previous_state_ref`, `execution_status`, `metadata`) are never part of a payload, so later execution history cannot change a
bundle. `git.repository_head` is the value the validation run persisted, not today's HEAD; if it was never recorded it is `UNKNOWN`, never guessed.

## 4. Canonicalization and digests

* Canonical JSON: keys sorted, compact separators, ASCII-escaped, `NaN` refused, **no `default` hook** (a datetime, set or object raises instead of being silently
  stringified); `repr()` is never hashed. The same payload hashes identically regardless of dict insertion order, query ordering, whitespace or row order; **Configlet order
  does matter**.
* SHA-256 over a **domain-tagged** envelope `{"domain","schema","value"}`, so a payload digest can never equal a bundle / item / export digest of the same bytes.

| Digest | Covers | Does **not** cover |
|---|---|---|
| **payload digest** | the whole `payload` (source provenance, exact ordered scope, items with payload text / hash / dependencies / raw pins / execution results / expected-state descriptors, verification quality) | bundle id, database primary key, `created_at`, `created_by`, builder version, kind, lineage |
| **bundle digest** | payload digest + kind + schema version + parent / source-UAT bundle digests — the **tamper / provenance identity** | bundle id, `created_at`, `created_by`, builder version |
| item digest | one canonical item record | — |
| export digest | the whole exported document (creation metadata included) minus the digest field | — |

A Probation bundle sealed from a UAT bundle therefore has the **same payload digest** (configuration equivalence, enforced by the model) and a **different bundle digest**
(kind and lineage differ). Fixed test vectors pin the canonicalization (`test_bundles.CanonicalizationTests`).

## 5. Immutability

Layered; none of them is "the button is disabled":

1. Creation only through `bundle_service` (atomic: bundle + items + audit in one transaction; a failure leaves nothing that looks valid).
2. Model: a persisted row cannot be saved again, an instance cannot be deleted, and the manager's queryset refuses `update` / `bulk_update` / `delete`.
3. Every foreign key to history is PROTECT/RESTRICT: nothing a bundle pins (Change, plan, validation, execution run, postcheck, Configlet, raw revision / verification, result)
   can be deleted from under it. (Deleting a Change is refused while it has bundles.)
4. Database constraints: kind/parent shape, per-kind sequence, one UAT bundle per execution, one Probation per UAT, one Golden per Probation.
5. No admin registration, no form, no edit or delete route.
6. `verify_bundle_integrity` recomputes everything from the stored contents on demand (§13); a stored "integrity_ok" flag would be trusted forever, so none exists.

## 6. Lineage

`UAT (root) → PROBATION → GOLDEN`, nothing else: a UAT bundle has no parent bundle (it derives from an execution); Probation's parent is a UAT bundle; Golden's parent is a Probation bundle;
`source_uat` is always the root. No UAT → Golden, no Golden → Probation, no arbitrary parent, no payload change along the chain, and a derived bundle pins the same historical sources as its
parent. Enforced by the model on write, by database constraints, and re-verified by the integrity check.

## 7. UAT eligibility (server-enforced; every blocker has a stable code, message and remediation)

A UAT bundle is created only from a **terminal Partial (UAT)** run that applied its whole requested scope. Bundle creation is an explicit POST — never automatic, never from GET.

| Code | Blocks when |
|---|---|
| `RUN_NOT_FINISHED` / `ACTIVE_EXECUTION` | the run is RUNNING / another execution of the Change or of one of its devices is active |
| `MODE_NOT_PARTIAL_UAT` | Complete is a deployment mode; it is never reinterpreted as UAT. A `SUCCEEDED` Complete run has its own root, the Deployed bundle (V2 Phase 5, `V2_PHASE5_PROVISIONING_TRAFFIC_SOAK.md` §3), and no Golden shortcut |
| `OUTCOME_NOT_BUNDLEABLE` | anything but `UAT_SCOPE_APPLIED` or (explicitly) `UAT_SCOPE_APPLIED_UNVERIFIED`: failed, interrupted, blocked, postcheck-failed, compensation-incomplete, unknown |
| `SCOPE_UNKNOWN` | the recorded scope is missing / not an ordered plan prefix / disagrees with the run's devices |
| `PLAN_PROVENANCE_INVALID` / `PLAN_HASH_MISSING` / `VALIDATION_NOT_PASSING` | run, plan and validation no longer agree on the pinned provenance, or the validation did not pass |
| `PLAN_CONFIGLETS_MISSING` / `DEPENDENCY_SCOPE_INCONSISTENT` | a scope Configlet no longer resolves in its historical plan / a prerequisite is outside the prefix or out of order |
| `RESULT_MISSING` / `RESULT_NOT_APPLIED` / `RESULT_OUT_OF_SCOPE` | a requested Configlet has no APPLY result / did not finish applied (or already satisfied) / an applied result exists outside the scope |
| `POSTCHECK_EVIDENCE_INVALID` | the pinned postcheck is missing or contradicts the outcome |
| `RAW_PROVENANCE_MISSING` / `RAW_REVISION_INTEGRITY` / `RAW_VERIFICATION_INVALID` | §9 |
| `SECRET_SHAPED_PAYLOAD` | §15 |
| `BUNDLE_TOO_LARGE` | more than 500 items or 2 MiB of manifest |

Everything is reconstructed from the run's **pinned historical records**; the current Change state is never consulted. The current validation / plan / precheck currency is deliberately **not** required
(a bundle is a historical artifact; a newer edit must not prevent bundling what was actually executed).

## 8. Partial (UAT) prefix semantics

Phase 17 defined Partial (UAT) as a dependency-safe **ordered prefix** through a selected Configlet. A UAT bundle preserves that exactly: it contains **precisely the selected, successfully applied prefix**
(in the persisted order — never re-derived from priority). It never contains the unapplied remainder, out-of-scope future Configlets, a failed Configlet, or anything added to the plan later. The
remainder's **ids** (not payloads) are recorded as `out_of_scope` so the artifact says honestly that it is a prefix of a larger plan.

## 9. Raw Configlets

A Raw Configlet enters a bundle only through the **exact Phase-18 immutable revision** the executed plan pinned: `RawConfiglet` id, `RawConfigletRevision` (content hash re-verified against the stored text),
the `RawConfigletVerificationRun` (must be finished, acceptable, and for that exact revision), its policy / verifier / backend provenance and the declared assertions. The plan copy, the run report and the plan's
desired-state must all agree on those pins. Nothing loads "latest", nothing is re-verified, no sandbox is started, and no browser text is ever accepted (the creation API takes only the run and the actor).
The verification is recorded as `scope: SYNTAX_ONLY`, `semantics_verified: false`: **a syntax PASS is never operational verification.** A verification that is no longer CURRENT (a later policy or backend
change) does not rewrite history and does not block bundling of what was executed.

## 10. UNVERIFIED and warnings

`UAT_SCOPE_APPLIED_UNVERIFIED` is a legitimate terminal outcome (for example a Raw Configlet with no declared assertion). The bundle is created and records `verification.state = UNVERIFIED` together with the
Configlets the postcheck could not confirm; **it is never labelled verified and can never enter Probation** (`SOURCE_UNVERIFIED`). No score exists.

| Warning / condition | UAT bundle | Probation |
|---|---|---|
| execution-gate warnings (for example `TOUCHES_MANAGEMENT_INTERFACE`, `AUTO_ADDRESS_NOT_RECORDED_IN_NETBOX`) | allowed; recorded as codes | allowed; stays visible |
| postcheck `PASS_WITH_WARNINGS` | allowed | allowed |
| UNVERIFIED scope (postcheck `INCOMPLETE`) | allowed; recorded honestly | **blocked** (`SOURCE_UNVERIFIED`, `POSTCHECK_NOT_ACCEPTABLE`) |
| any non-applied included result | blocked | blocked (`RESULT_NOT_APPLIED`) |

## 11. Probation derivation

An explicit, **confirmed** POST creates a NEW Probation bundle from an eligible UAT bundle: a deep copy of the parent's payload (so the payload digest is equal), new kind and lineage (so the bundle digest differs), the same
item pins. It requires: the source is a UAT bundle, its integrity verifies, its scope is VERIFIED with an acceptable postcheck, every included result is applied, and no Probation child exists (idempotent). It never re-runs
a deployment, a plan or a postcheck; it never touches the UAT bundle; it starts **no** timer and changes **no** lifecycle. If the source fails integrity the derivation is refused and one bounded `BUNDLE_INTEGRITY_FAILED` audit
event is written. If the payload would change, that is a new UAT candidate — never "the same artifact promoted".

## 12. Golden foundation

Structurally a Golden bundle is a `GOLDEN` `ConfigurationBundle` whose parent is a Probation bundle: immutable, content-addressed, lineage-backed, historically readable, displayable and verifiable (test fixtures build one
structurally). **Phase 19 provides no way to create one**: `check_golden_eligibility` / `create_golden_bundle` always refuse with `PHASE20_EVIDENCE_REQUIRED`; because Phase 19 recognises no soak-evidence type, anything passed
as evidence is refused as `PHASE20_NOT_AVAILABLE`, never interpreted. No route, view, form field, query parameter or flag can create Golden; a contract test scans every non-test source file. **Phase-20 seam:** replace the
evidence check in `bundles/golden.py` with the Phase-20 soak / decision model, then call `persistence.seal_bundle(kind=GOLDEN, parent=<probation>, ...)` — the model and the database already enforce the lineage; nothing else in
Phase 19 changes. Phase 20 also owns the soak run / window, health samples, the soak result and the operator's decision; none of that is modelled here.

## 13. Integrity verification

`verify_bundle_integrity(bundle)` is read-only and recomputes: schema support; the payload digest; the bundle digest; kind and lineage rules (recursively through at most two ancestors); parent digest and payload
equivalence; item rows against the manifest (count, contiguous order, canonical record, item digest, payload hash, pinned Configlet, raw revision / verification pins and revision text hash); the pinned source references
(change, plan, validation, execution, postcheck vs the manifest); and secret hygiene. Findings carry stable codes (`PAYLOAD_DIGEST_MISMATCH`, `BUNDLE_DIGEST_MISMATCH`, `ITEMS_MISMATCH`, `ITEM_RECORD_MISMATCH`,
`ITEM_DIGEST_MISMATCH`, `ITEM_PAYLOAD_HASH_MISMATCH`, `LINEAGE_INVALID`, `PARENT_DIGEST_MISMATCH`, `PAYLOAD_NOT_EQUIVALENT`, `ANCESTOR_INTEGRITY_FAILED`, `SOURCE_PIN_MISMATCH`, `SOURCE_REFERENCE_INVALID`,
`RAW_PIN_MISMATCH`, `SCHEMA_UNSUPPORTED`, `MANIFEST_MALFORMED`, `KIND_MISMATCH`, `SECRET_SHAPED_CONTENT`). A failing bundle is shown prominently, is never repaired, can never be derived from and can never feed a Golden
decision. The bundle **list** never verifies per row; the detail page verifies the one bundle being opened.

## 14. Export

`/device-builder/bundles/<id>/manifest.json` is a deterministic, read-only JSON attachment: schema versions, identity, kind, both digests, lineage ids, source ids and the whole canonical manifest plus an `export_digest`.
It is a pure function of stored immutable data (no live integrity result, no children), so the same bundle always exports the same bytes. `verify_export` verifies a document **without the database**. It carries no
credentials, resolved secrets, command output or logs, and is re-scanned for secret-shaped content before release (HTTP 409 if it fails). It writes nothing: no file, Git commit, tag, push or release.

## 15. Security and secrets

Bundle immutability is not a reason to persist secrets. Nothing is resolved (no credential lookup exists in the package). Every payload line is scanned again at creation with the project's shared detector
(`raw_configlets.static_gate.secret_patterns`: credential formats, keyword-with-value, SNMPv3 key material) and every descriptor key with `secret_policy`; a hit **blocks** creation — nothing is silently redacted and
then presented as the executed configuration. Findings carry pattern names and line numbers, never the matched text. Audit metadata is a fixed bounded key set (ids, digests, counts, result): never the manifest.
Boundaries proved by contract tests: no import of Netmiko / subprocess / socket / requests / Git / NetBox / execution / notification / lifecycle modules, no dynamic execution or shell, no update or delete call anywhere in the
package, only its own rows and one audit event are ever created, and the engine's entry-point name never appears in it.

## 16. UI workflow

Inside Device Builder (the sidebar is unchanged): Change → *Open Configuration Bundles*; Device Builder landing → *View Configuration Bundles*; finished Partial (UAT) run → **Create UAT bundle**
(POST + CSRF, shown only when eligible, blockers listed otherwise; the server re-checks regardless; an existing bundle is linked instead).

| Route | Method | Effect |
|---|---|---|
| `/device-builder/bundles/` | GET | list, filter by kind / Change (no per-row integrity) |
| `/device-builder/bundles/<id>/` | GET | identity, digests, sources, **integrity (recomputed)**, lineage, scope, verification quality, ordered items with frozen payloads and raw pins, action panel |
| `/device-builder/bundles/<id>/manifest.json` | GET | export (§14) |
| `/device-builder/changes/<change>/executions/<run>/bundle/` | POST | create the UAT bundle (idempotent) |
| `/device-builder/bundles/<id>/probation/` | POST | Create Probation bundle — needs the confirmation checkbox: "the configuration payload will not change" and "the seven-day soak is NOT part of this action" |

The browser supplies only a confirmation and an id in the URL; never a payload, digest, kind or parent. Probation pages say "Golden promotion requires the Phase-20 soak and the operator's Golden decision".

## 17. Concurrency and idempotency

One UAT bundle per execution run, one Probation bundle per UAT bundle, one Golden bundle per Probation bundle — **database unique constraints**, not the button. A racing request that loses the constraint re-reads and returns the
winner's artifact; a lost race on the per-kind sequence retries with the next number; creation locks the run row where the database supports `SELECT … FOR UPDATE` (no-op on SQLite; uniqueness still holds).

## 18. Audit

`UAT_BUNDLE_CREATED`, `PROBATION_BUNDLE_CREATED` (operator, bundle id, kind, digests, parent, source execution, verification state, item count, result) and `BUNDLE_INTEGRITY_FAILED` (bounded finding codes, when an explicit
action was refused because a bundle failed verification). Written in the same transaction as the bundle. No notifications are sent (§21).

## 19. Tier-3 and tests

Tier-3 has a `bundles` subsystem (paths `web/core/services/bundles/**`, `bundle_service.py`), impact edges `models_schema` / `execution` / `planning` / `health` / `raw_configlets` → `bundles`, and selects `bundles`, `bundle_views`,
`contracts`; templates select Django tests only (no lab verifier). Tests: `test_bundles` (canonicalization vectors, immutability, lineage, eligibility over real engine runs, prefix, Probation, Golden boundary, raw provenance, tamper matrix, export,
side-effect audit), `test_bundle_views` (HTTP), `BundleBoundaryContractTests` in `test_contracts`, shared fixtures in `tests/helpers/bundles.py`. Every bundle in the tests is built from a **real run of the production engine on the simulated network**.

## 20. Local development database

`web/db.sqlite3` is not part of Git. Phase 19 adds migration `0008`; the normal `python web/manage.py migrate` applies it (schema maintenance, not a network action). Tests use throwaway databases and never need it.

## 21. Known limitations (deliberate unless marked)

* **A digest is not a signature.** The integrity check detects any inconsistent, partial or accidental change. An actor with database write access who rewrites the manifest, the item rows **and** recomputes every digest
  consistently is not detectable from the database alone; there is no signing key and no external anchor. Anchoring exports (for example in Git) is Phase 22's reproducibility concern and is deliberately not done here (no Git writes from bundle code).
* The plan's own `plan_hash` is pinned **by value** and cross-checked against the run, plan and validation; it is not recomputed from Configlet rows because the planner's node keys are not persisted on them.
* Verification quality is a run-level fact (postcheck result + the Configlets it listed as unverifiable); it is not asserted per Configlet, so a bundle never claims more than the postcheck established.
* **Running configuration only.** A bundle records what a Partial (UAT) run applied to the running configuration. Phases 17–18 say startup-config persistence "belongs to the Golden / Probation phases"; Phase 19 forbids any device
  action, so persistence remains undecided and is a **Phase-20 / later** design question.
* One Probation bundle per UAT bundle. How an iteration after a failed soak is represented is Phase 20's; the constraint would be revisited there, never worked around.
* Active-execution blocking is conservative: an expired-lease RUNNING run stays "active" until the engine reaps it on its next attempt.
* No notification is published for bundle events (the reserved event vocabulary has no bundle event; adding one is optional and deferred). The bundle list shows the newest 100.
* Bundles have no admin registration by design. Nothing here has been applied to a real device; live UAT acceptance is still not part of this project's approved test set.

## 22. Phase-20 extension: the soak-backed Golden bundle

Sections 1 – 21 describe the Phase-19 artifacts and remain accurate for UAT and Probation bundles. Phase 20 (see `docs/PROBATION_SOAK_AND_PROMOTION.md`) fills the seam §12 deliberately left open:

* **Golden is now creatable — by exactly one path.** `bundles/golden.py::create_golden_bundle` accepts only a technically passed `ProbationSoakRun` (anything else is refused with `PHASE20_EVIDENCE_REQUIRED` / `EVIDENCE_TYPE_UNSUPPORTED`; the old `PHASE20_NOT_AVAILABLE` code is replaced by real evidence checks). It is called by the operator's explicit APPROVE (`soak.decision.decide`) and nothing else: not the collector, not a view. Immediately before sealing it re-checks integrity, soak identity and digest, the soak's own reproducible evidence, the duration, the decision window and later interference.
* **Same payload, new identity.** The Golden payload is a deep copy of the Probation payload (equal payload digest); kind, lineage and promotion differ (different bundle digest). Nothing is re-rendered or re-loaded.
* **Promotion provenance.** A Golden manifest carries `lineage.promotion` (soak id, policy version, observation start / required end / completion, evidence digest, Probation digest, decision, decider, decision time). The bundle digest covers it **only when present**, so every UAT and Probation digest is unchanged from Phase 19. Integrity cross-checks it against the stored `GoldenDecision` and `ProbationSoakRun` (`PROMOTION_MISSING`, `PROMOTION_MISMATCH`); a GOLDEN bundle without a well-formed promotion no longer verifies, and a non-Golden bundle must not carry one.
* **New audit / model additions:** `GOLDEN_APPROVED` (written with the bundle), the `ProbationSoakRun` / `ProbationSoakSample` / `GoldenDecision` models, migration `0009`. `golden_builder_version` is `20.0.0`.
* **Still true:** a bundle carries no soak state; nothing infers Golden from "tests passed", "currently deployed" or "no errors observed"; approval sends nothing to a device; startup-config persistence remains undecided (`PROBATION_SOAK_AND_PROMOTION.md` §16).
* One Probation per UAT is unchanged: a soak retry is a new **soak run** on the same Probation bundle, never a new bundle.
