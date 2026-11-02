# Phase 14 — Unified Priority / Dependency Plan Builder and Configlets

Phase 14 converts a **CURRENT, passing Phase-13 validation** into a deterministic,
granular, ordered **plan of Configlets**. It consumes Phase 13's stored results
(derived facts, semantic dependency graph, status, hashes) rather than recreating
them, renders every snippet through the **same platform drivers** as the Device
Builder preview, and stops there: nothing is deployed, executed, persisted to a
device, written to NetBox/Git, or verified. Test-suite rationalization (Stage 0)
is documented in `docs/TEST_SUITE_RATIONALIZATION.md`.

Contents: 1 Architecture · 2 Relationship to Phase 13 · 3 Eligibility ·
4 Validation-run pinning · 5 Staleness · 6 Configlet reuse / model · 7 Granularity ·
8 CFG identity · 9 Nine priority classes · 10 Dependency over priority ·
11 DEFINE vs ACTIVATE/ATTACH · 12 Interfaces · 13 Addressing · 14 AUTO addresses ·
15 Static routes · 16 Dynamic routing · 17 BGP decomposition · 18 FHRP / services ·
19 NAT · 20 ACL · 21 PBR · 22 DHCP / DNS · 23 Dependency mapping · 24 Cross-device ·
25 Ordering · 26 Cycle defense · 27 Idempotency · 28 History · 29 Transactionality ·
30 Previous state · 31 Verification placeholders · 32 Machine-readable plan · 33 UI ·
34 Security · 35 Secrets · 36 No device access · 37 No NetBox writes · 38 No Git/GitHub ·
39 No deployment · 40 Phase-15 handoff · Errors and warnings · Known limitations.

## 1. Plan-builder architecture

```
 Change ── accepted intent ─────────────┐
 Latest ChangeValidationRun (CURRENT,   │
   PASS / PASS_WITH_WARNINGS) ──────────┤  derived_facts, dependency_graph,
                                        v  status, hashes
                          core/services/change_plan_service.py   (public API)
                                        │
        core/services/planning/  ───────┘
          priorities.py          object type -> (priority, operation, namespace)  [the one catalogue]
          snippets.py            driver-based snippet extraction (slice + positional diff)
          configlet_factory.py   graph node -> Configlet spec(s)
          dependency_mapping.py  Phase-13 typed edges -> Configlet dependencies
          ordering.py            deterministic, cycle-safe topological order
          builder.py             eligibility · compute_plan (pure) · persist_plan (atomic) · currency
          serialization.py       sanitized machine-readable report
          errors.py              PlanGenerationError + stable codes
                                        │
                                        v
   ChangePlan (append-only) ── Configlets (existing model, frozen) ── ConfigletDependency
```

`compute_plan(change, run)` is **pure** (no writes, no network); `persist_plan`
is the only writer and runs in one `transaction.atomic()`. Views
(`core/views.py`, "Phase 14" section) resolve the Change, call
`change_plan_service`, and render.

## 2. Relationship to Phase 13

Phase 14 never re-validates and never derives cross-device semantics itself. It
reads, from the pinned run: `status`, `input_hash`, `source_hash`,
`engine_version`, `derived_facts` (AUTO addresses) and `dependency_graph`
(typed edges between stable objects). It performs only *defensive integrity*
checks (input hash re-computed, graph not truncated, no MISSING/unknown edge,
no cycle) and contains no validator function (asserted by a contract test).

## 3. Plan eligibility

A plan may be built only when the latest validation is **CURRENT** *and* its
result is `PASS` or `PASS_WITH_WARNINGS`.

| Validation | Result | Code |
|---|---|---|
| never run | — | `VALIDATION_NEVER_RUN` |
| STALE | any | `VALIDATION_STALE` |
| CURRENT | `BLOCKED` | `VALIDATION_BLOCKED` |
| CURRENT | `INCOMPLETE` | `VALIDATION_INCOMPLETE` |
| CURRENT | `PASS` / `PASS_WITH_WARNINGS` | allowed |

Validation is **never** re-run implicitly; a refusal persists nothing.
`PASS_WITH_WARNINGS` carries the run ID, warning count and warning finding codes
into the plan (`VALIDATION_WARNINGS_CARRIED_FORWARD`). No execution acknowledgement
exists (Phase 17).

## 4. Validation-run pinning

Every `ChangePlan` stores a `RESTRICT` foreign key to the exact
`ChangeValidationRun` plus copies of `input_hash`, `source_hash` and
`engine_version`, and a `plan_hash` (SHA-256 of the canonical semantic plan:
planner version, input/source hash, engine version, ordered Configlets and their
dependencies — **not** run IDs or timestamps). `RESTRICT` (not `PROTECT`) means a
pinned run cannot be deleted alone, yet a whole Change (plans, Configlets, runs)
can still be deleted — regression-tested.

## 5. Plan staleness

Currency is computed, never stored. A plan is **CURRENT** only while its pinned
run is still the latest run **and** Phase-13 currency of the Change is CURRENT.

| Reason | Meaning |
|---|---|
| `VALIDATION_SUPERSEDED` | a newer validation run exists (even with identical input) |
| `ACCEPTED_INTENT_CHANGED` | accepted intent no longer hashes to the run's input hash |
| `SOURCE_CHANGED:<X>` / `SOURCE_UNVERIFIABLE:<X>` | a consumed source changed / cannot be verified |
| `ENGINE_VERSION_CHANGED`, `PLANNER_VERSION_CHANGED` | tooling changed |

Intent staleness is always evaluated; source staleness on request
(`?check_sources=1`, read-only) and always at **Build Plan** (see §33). A stale
plan is never regenerated automatically: re-run validation, then rebuild.

## 6. Configlet reuse and model

The Phase-8 `Configlet` / `ConfigletDependency` are reused; no competing unit
exists. The minimum schema change is migration `0004_phase14_change_plan`:

* new **`ChangePlan`** (`plan_id`, `change`, `validation_run`, `planner_version`,
  pinned hashes, `plan_hash`, `created_at/by`, JSON `summary`/`warnings`/`provenance`);
  append-only; unique per `(validation_run, planner_version)`;
* nullable **`Configlet.plan`**; `cfg_id`/`sequence` uniqueness became **per plan**
  (conditional unique constraints); the original per-Change constraints remain for
  plan-less (Phase 8) Configlets, so their behavior is unchanged;
* `AuditEventType.PLAN_BUILT` (label-only).

Frozen after creation for a plan-owned Configlet: `plan`, `cfg_id`, `sequence`,
`target_device`, `feature_namespace`, `operation_type`, `deployment_priority`,
`rendered_config`, `desired_state_ref`, `verification_spec`, `description`. Execution
fields (`execution_status`, `previous_state_ref`, `rollback_config`, `git_reference`,
`metadata`) stay writable for the phases that own them. JSON fields pass the shared
`secret_policy`.

## 7. Configlet granularity

One Configlet per meaningful atomic object — not one per device, not one per CLI
line: interface, address assignment, static route, routing process, routing
interface attachment, BGP neighbor definition, BGP address-family activation, BGP
network advertisement, FHRP definition, DHCP relay attachment, ACL definition, ACL
attachment, NAT rule activation, (and NAT pool / PBR policy / PBR attachment if a
platform ever supports them).

## 8. CFG identity

`CFG-001`, `CFG-002`, … assigned **in final plan order** (never from database
IDs), unique per plan generation. The same accepted input yields the same IDs, so
identical plans in different generations share IDs while remaining separate rows.

## 9. The nine priority classes (canonical `DeploymentPriority`)

| # | Class | Populated by |
|---|---|---|
| 1 | Foundation / access | a hostname **rename** only (accepted hostname ≠ device name) |
| 2 | Interface construction | interface definitions |
| 3 | Addressing | address assignments (incl. derived AUTO) |
| 4 | Basic forwarding | static routes |
| 5 | Dynamic routing | RIP/OSPF/IS-IS/EIGRP/BGP processes, bindings, neighbors, AF activation, networks |
| 6 | Higher-level services | FHRP, DHCP relay, and the *definitions* of ACL / NAT pool / PBR policy |
| 7 | Traffic-affecting policy | NAT rule activation, ACL attachment, PBR attachment |
| 8 | Monitoring / mirroring | **empty** — monitoring is inherited project infrastructure |
| 9 | Persistence | **empty** — saving is the execution system's job; no `write memory` step exists |

Empty stages are normal and shown as such.

## 10. Dependency over priority

Priority is a coarse class, **not** the ordering mechanism. If Configlet A depends
on B and B's priority is numerically greater, B is ordered first and the plan
records `PRIORITY_DEPENDENCY_INVERSION` (on the plan and on A). Priorities are
never rewritten to hide it. (The current Phase-13 graph produces none; it is
tested with an injected edge.)

## 11. DEFINE vs ACTIVATE / ATTACH

| `CREATE_DEFINE` | `ACTIVATE_ATTACH` |
|---|---|
| interface, address, static route, routing process, BGP neighbor definition, FHRP, ACL definition, NAT pool, PBR policy, hostname | routing interface binding, BGP AF activation, BGP network advertisement, DHCP relay, NAT rule, ACL attachment, PBR attachment |

Definition and attachment are never collapsed.

## 12–13. Interface and addressing Configlets

An interface Configlet is the interface block **without** addresses (a subinterface
renders with its parent for name resolution); each address is a separate priority-3
Configlet that depends on its interface (`REQUIRES`). Vendor syntax
(`interface Ethernet1 / no switchport`, `ip address …`, `ip addr replace … dev …`)
comes from the platform driver.

## 14. AUTO derived addressing

An AUTO address uses the Phase-13 `AUTO_ADDRESS` fact (`proposed_address`),
substituted on an in-memory **copy**; accepted intent and NetBox are untouched.
Configlet metadata: `source=VALIDATION_DERIVED`, `proposed_address`,
`selected_prefix`, `algorithm`, `reserved=false`, `recheck_required=true`; plan
warning `AUTO_ADDRESS_RECHECK_REQUIRED`. Missing fact → `AUTO_VALUE_MISSING`.

## 15. Static routes

One Configlet per enabled route (priority 4), depending on the address it relies on
(`ADDRESS_BEFORE_ROUTING`) or its exit interface. A route that renders no
deployable configuration (e.g. disabled) is skipped with `NO_DEPLOYABLE_CONFIG`.

## 16. Dynamic-routing Configlets

Process definition (DEFINE) + per-interface binding (ATTACH) for RIP/OSPF (v2/v3),
plus BGP below. IS-IS/EIGRP/RIPng have no renderer on any platform, so validation
blocks them; the planner would refuse them with `UNSUPPORTED_OBJECT`.

## 17. BGP decomposition

`router bgp` process → **neighbor definition** (remote-as, description,
update-source, multihop, auth *reference* comment, shutdown) → one **address-family
activation** per activated family (`address-family …`, `neighbor … activate`,
`next-hop-self`, `route-reflector-client`, and FRR's `exit-address-family`) →
**network advertisement**. Each snippet is self-contained (enclosing block headers
included) and the activation depends on its neighbor definition.

## 18. FHRP and service Configlets

FHRP (cEOS VARP): one definition Configlet per instance including its VIPs,
depending on its interface.

## 19. NAT

Ubuntu/FRR NAT44/PAT: one rule Configlet per rule (priority 7, ATTACH), depending
on its inside/outside interfaces. The nftables block is emitted by the driver; see
Known limitations for multi-rule devices. NAT pools are `NOT_IMPLEMENTED` today.

## 20. ACL definition and attachment

Definition (priority 6, DEFINE) and attachment (priority 7, ATTACH,
`DEFINE_BEFORE_ATTACH` on the definition, `INTERFACE_BEFORE_SERVICE` on the
interface) are separate Configlets; the attachment snippet contains only
`interface … / ip access-group NAME dir`.

## 21. PBR

No platform supports PBR; validation blocks it. If a PBR object ever reached the
planner it maps to `pbr_policy` (DEFINE, 6) and `pbr_attachment` (ATTACH, 7), sequences
folded into the policy, and is refused while the driver reports it unsupported.

## 22. DHCP / DNS

DHCP relay (priority 6, ATTACH) depends on its interface. DHCP/DNS *inherit*
defaults generate no Configlet ("do not invent configuration"); DNS override is
`NOT_IMPLEMENTED` and blocked by validation. DHCP clients are capability-blocked.

## 23. Dependency mapping

Every RESOLVED Phase-13 edge `A → B` becomes "A's Configlet depends on B's" with the
typed relationships kept on the Configlet (`metadata.dependencies[].edge_types`):
`REQUIRES`, `REFERENCES`, `DEFINE_BEFORE_ATTACH`, `PARENT_BEFORE_CHILD`,
`ADDRESS_BEFORE_ROUTING`, `INTERFACE_BEFORE_SERVICE`. Duplicate edges merge; edges
inside one Configlet are dropped; a `MISSING`/unknown edge fails the plan
(`DEPENDENCY_MISSING`). All edges stay inside one plan (DB-enforced same-Change, no
self-dependency, no duplicates).

## 24. Cross-device dependencies

Nothing restricts a `ConfigletDependency` to one device; the ordering interleaves
devices rather than finishing R1 first. The current Phase-13 graph is per-device, so
this is exercised with an injected cross-device edge (an R2 Configlet ordered before
an R1 Configlet that depends on it).

## 25. Deterministic topological ordering

Kahn's algorithm with a min-heap; among dependency-ready Configlets the next is the
smallest by `(priority, device name, operation class, source identity)` where the
source identity is `<device>/<type>/<object id>` (never a primary key), DEFINE before
ATTACH within a class. NetworkX order is not relied on. Same input ⇒ same order.

## 26. Cycle defense

Phase 13 already blocks cycles; the planner checks again. Never-ready Configlets
raise `CONFIGLET_CYCLE` with one deterministic cycle path — no ambiguous order is
produced and nothing is persisted.

## 27. Idempotent generation

A plan is unique per `(validation run, planner version)`. Repeating **Build Plan**
returns the existing plan (`created=False`), adds no Configlet, no audit event; a
concurrent duplicate is caught by the unique constraint. Identical accepted input
under a *new* validation run produces the **same `plan_hash`** and CFG numbering.

## 28. Historical plan preservation

A new validation run ⇒ the old plan becomes STALE (`VALIDATION_SUPERSEDED`) and a new
plan generation is created; the old plan's Configlets are frozen and never rewritten.
Change detail lists only Phase-8 (plan-less) Configlets; plan Configlets live on the
plan page.

## 29. Plan transactionality

Everything is computed first (pure); persistence is one `transaction.atomic()`
(plan, Configlets, dependencies, audit). An injected failure mid-persist leaves no
plan, Configlet, dependency or audit row (tested).

## 30. Previous-state limitation

No live retrieval exists, so `previous_state_ref = {"status": "UNKNOWN_DEFERRED"}`
and `rollback_config = ""` — no rollback text is fabricated. Warning
`PREVIOUS_STATE_DEFERRED`. Phase 17 captures real pre-change state.

## 31. Verification-requirement placeholders

Each Configlet carries declarative descriptors (`INTERFACE_PRESENT`,
`ADDRESS_PRESENT`, `ROUTE_INTENDED`, `BGP_PEER_INTENDED`, `ACL_ATTACHMENT_INTENDED`, …)
with `status=DEFERRED`, `owner=PHASE_15`. Nothing is checked. Warning
`VERIFICATION_REQUIREMENT_DEFERRED`.

## 32. Machine-readable plan

`GET …/plan/<plan_id>/report.json` — `attachment`, `nosniff`, filename
`<CHANGE_ID>-plan-<first 8 of plan id>.json` (derived only from server-side IDs; any
query string is ignored). Contains plan identity/currency, validation provenance,
summary, the nine stages, ordered Configlets (snippet, source, operation, priority,
dependencies with edge types, verification, previous-state marker, derived-value
metadata), flat dependencies, warnings and limitations. Built from persisted rows and
passed through the shared secret-key redaction; deterministic.

## 33. Django UI

* `/device-builder/changes/<change_id>/plan/` (GET, read-only): header (Change ID,
  lifecycle, validation state/run, plan currency, generated, Configlet / device /
  dependency / warning counts), provenance, warnings, the nine stages (empty ones
  marked), per-stage Configlet cards (CFG ID, device, DEFINE / ACTIVATE-ATTACH,
  source object, `requires:` list with typed edges, snippet, verification, previous
  state, AUTO banner), a dependency table, limitations, plan history.
* `…/plan/build/` (**POST + CSRF**): ignores every POST field; runs eligibility with a
  read-only source-freshness check, then builds; refusals redirect to
  `?refused=<CODE>` where the code is looked up in a fixed allowlist (nothing from the
  query string is echoed).
* `…/plan/<plan_id>/` (historical, read-only) and `…/report.json`.
Configlets are shown, never editable (no form fields); to change one, edit the Device
Intent → re-validate → rebuild. No copy/download-per-Configlet controls were added.

## 34. Security

POST + CSRF for the only action; plans are addressed only through their Change (foreign
or unknown plan/Change ⇒ 404); fixed filename; no browser-supplied path, template,
object ID, source URL or CLI; all output auto-escaped (no `|safe`); contracts assert no
forbidden imports, no `eval`/`exec`/shell, no vendor syntax and no device-name
literals anywhere in `planning/`.

## 35. Secrets

Only `*_ref` references ever appear (a BGP `password_ref` renders as an
"authentication reference present" comment). JSON fields are checked by
`secret_policy`; the report is redacted; a manually injected `password` key in
intent never reaches a plan (tested).

## 36–39. No device access, NetBox writes, Git/GitHub, or deployment

Plan building is tested with `socket`, `subprocess`, `urllib` and the NetBox client
disabled: it adds exactly one `ChangePlan`, its Configlets/dependencies and one audit
event, leaves the Change `DRAFT`, `git_commit_ref`/`github_actions_run_ref`/
`deployment_reference` empty, accepted intent byte-identical, and every Configlet
`PENDING`. Nothing named `configure terminal`, `write memory`, `commit confirmed`,
`vtysh`, `netmiko` or a Containerlab lifecycle command exists in the planning code. No
notification is sent.

## 40. Phase-15 handoff

Phase 15 (fleet / per-device health, change-aware prechecks/postchecks) reads
`Configlet.verification_spec.requirements` (declarative, `DEFERRED`), the plan's
`plan_hash` and validation provenance, and may capture real previous state. It must
re-check AUTO addresses immediately before use. Deployment, transactional execution,
rollback and Complete/Partial(UAT) acknowledgement remain Phase 17.

## Errors and warnings

Errors (`PlanGenerationError.code`; fixed operator messages, nothing persisted):
`VALIDATION_NEVER_RUN`, `VALIDATION_STALE`, `VALIDATION_BLOCKED`, `VALIDATION_INCOMPLETE`,
`INPUT_HASH_MISMATCH`, `GRAPH_TRUNCATED`, `DEPENDENCY_MISSING`, `CONFIGLET_CYCLE`,
`RENDERER_INCONSISTENT`, `UNSUPPORTED_OBJECT`, `UNRESOLVED_PLACEHOLDER` (a `<…-required>`
renderer placeholder would appear in a Configlet), `AUTO_VALUE_MISSING`,
`UNKNOWN_OBJECT_TYPE`.

Warnings (small vocabulary; Phase-13 findings are not recreated):
`PRIORITY_DEPENDENCY_INVERSION`, `AUTO_ADDRESS_RECHECK_REQUIRED`,
`VALIDATION_WARNINGS_CARRIED_FORWARD`, `PREVIOUS_STATE_DEFERRED`,
`VERIFICATION_REQUIREMENT_DEFERRED`, `NO_DEPLOYABLE_CONFIG`.

## Known limitations

* The plan renders the **whole accepted intent**; with no live/previous state it cannot
  tell which objects already exist on a device.
* Snippet extraction is a positional diff of two driver renderings of small slices
  (no renderer refactor). Every snippet line is a line the full candidate would emit
  (tested), except the derived AUTO address, which the candidate shows as a comment.
* Ubuntu/FRR NAT: each rule's snippet contains the shared `table ip DEVICE_BUILDER_PAT`
  block, so several PAT rules on one device repeat that table header; merging is an
  execution-phase concern.
* Foundation (priority 1) is emitted only for a hostname rename; priorities 8 and 9
  are always empty.
* Graph labels for some objects include opaque IDs (from the Phase-13 graph).
* **Build Plan** performs a read-only source-freshness check; if NetBox cannot be read
  the sources are unverifiable, the plan is refused as `VALIDATION_STALE`, and
  validation would also be INCOMPLETE.
* Phase 13's graph contains no cross-device edges today; cross-device support is
  mapping-level and tested synthetically.
* Live verification used documentation-range addresses on synthetic Changes.
