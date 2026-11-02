> **Version 2 Phase 5 (2026-10-05) -- IN PROGRESS, after session 2:** new-device provisioning, the traffic / test workbench and the
> probation baseline are implemented and tested (`web/core/services/provisioning/`, `traffic/`, `soak/baseline.py`, `soak/config_state.py`,
> `soak/overview.py`; migrations `0024`-`0027`). Provisioning was **proven live** against a disposable FRR node and the real NetBox, and
> the workbench was **proven live** between H1-H4 (evidence under `docs/evidence/v2-phase5/`). There is ONE execution entry point: a
> provisioning Change runs through the ordinary execute route, whose gate enforces the provisioning approval. A verified Complete
> provisioning run seals a `DEPLOYED` bundle that can enter probation. A soak now pins per-device configuration digests at start and is
> invalidated by drift. Collector systemd units exist in `deploy/systemd/` and are **not installed**. **Not done:** the traffic workbench
> cannot run from the deployed web service as built (`NoNewPrivileges`), Tier-3, the PR, the deployment promotion and the real 7-day
> soak. Production untouched (15/15). See `docs/V2_PHASE5_PROVISIONING_TRAFFIC_SOAK.md`.
>
> **Phase-25 continuation (2026-09-28):** R1 Microsoft Authenticator MFA and
> post-pilot closure are complete. Generic one-device-at-a-time cEOS rollout
> source, per-device credential routing, protected RADIUS-client rendering and
> the evidence lifecycle are documented in
> `docs/PHASE_25_CEOS_MFA_FLEET_ROLLOUT.md`. Remaining eligible targets are R2,
> S1-S4 and `mgmt_swt`; none is live-migrated without its own approval.
>
> **Legacy baseline bootstrap update (2026-09-22) -- ONE-TIME, REAL:** the operator-approved one-time exception between Phase 20 and Phase 21
> (`web/core/services/bootstrap/`, facade `bootstrap_service.py`; the candidate/Golden seam in `bundles/legacy.py`; migration `0010`;
> `docs/LEGACY_BASELINE_BOOTSTRAP.md`; `docs/CHECKPOINT_04_MANIFEST.md`) was **actually executed against the real lab**, not merely implemented.
> Read-only readiness probe (READY, 10/10 devices) -> read-only sanitized capture of every managed device's running configuration into an immutable
> candidate (`BND-LEGACY-000001`; 32 secret-bearing lines redacted before storage; digest `71ae6edf...d6f634`) -> a REAL, wall-clock **30-minute**
> observation (`BOOT-000001`, `started_at` 2026-09-21T23:58:08Z, `required_end_at`/`finished_at` 2026-09-22T00:28:08Z/00:28:10Z, 7 samples all PASS,
> 100% coverage, max gap 300s, no drift, no interference) driven by `python manage.py legacy_bootstrap observe` (bounded waits, never a busy loop;
> no device was configured at any point) -> the operator's explicit approval (`legacy_bootstrap approve --confirm`; the server re-read every
> device's configuration immediately before sealing and would have refused on any difference) -> the **initial Golden bundle**
> `BND-GOLD-000001` (provenance `LEGACY_BOOTSTRAP`, integrity `INTACT`, export self-verifies). No Change, plan, validation run, execution run,
> UAT bundle, Probation bundle or `ProbationSoakRun` was fabricated (a database count immediately after approval showed zero of each). The
> shortcut is now **permanently locked out** (`LEGACY_BOOTSTRAP_ALREADY_COMPLETED`, enforced by a DB unique constraint, survives a restart); a
> second capture was attempted immediately afterward and correctly refused. The **normal seven-day probation policy is unchanged**
> (`soak_service.current_policy().duration_seconds == 604800`, confirmed read from the running application after the bootstrap). This initial
> Golden did **not** pass a seven-day soak and is never described as having done so. `bundle_service.known_good_baseline()` now reports a valid
> Phase-21 entry with `source = LEGACY_BOOTSTRAP`. Checkpoint 4 is created (`docs/CHECKPOINT_04_MANIFEST.md`); **Phase 21 may now begin.**
> Implementation: 1169 Django tests pass (1085 + 84 new); eighteen targeted mutations were all caught by tests; hosted Tier-3 `SUCCESS` on PR #6
> (merged as `984ac0f`); a real defect fixed along the way -- R5's Containerlab-assigned ("auto") management address had no SSH target, so the
> health engine's live read returned `NOT_CONFIGURED` for it, fixed with a credential-free `docker exec ... Cli -p 15 -c "<show command>"`
> session (the same read pattern the repository already uses for R2's DHCP verification), reusing the same fixed read-only allowlist.

> **Phase 20 update (2026-09-21) -- 20A IMPLEMENTATION ONLY:** **probation soak + operator Golden decision** (`web/core/services/soak/`, facade `soak_service.py`, promotion in `bundles/golden.py`; migration `0009`; `docs/PROBATION_SOAK_AND_PROMOTION.md`). An explicit
> POST starts a soak of one exact immutable Probation bundle; the **server** pins the start, the required end and the policy (production duration `timedelta(days=7)` = 168 elapsed hours, UTC; the environment can only raise it, never shorten it; a browser can supply none of it).
> A scheduler-safe, idempotent, restartable management command (`probation_soak_tick`, every 5 min recommended; no scheduler is installed by the repository) takes one read-only evidence sample per 900 s interval: bundle integrity + later-execution interference (persisted Phase-17 history;
> no lock, session or transaction is held for the window), the **Phase-15 postcheck engine** over the pinned descriptors of the executed prefix (fixed read-only allowlists) and the **existing gNMI-fed topology telemetry** (freshness, CPU, memory, events) -- no second monitoring stack, Grafana is never
> read, and nothing is refreshed. Explicit rules, no score: a demonstrated intended-state failure ends the soak at once; critical CPU / memory only after the project's `consecutive_samples`; stale / missing telemetry is **INCOMPLETE, never PASS**; PASS also needs >= 90 % interval coverage and no gap over 2 h.
> State (`RUNNING` / `COMPLETED` / `INVALIDATED` / `CANCELLED`) and result (`PASS` / `FAIL` / `INCOMPLETE`) are separate; a technical PASS only makes the run **ready** -- **there is no automatic promotion**. The operator's explicit APPROVE re-checks integrity, digest, reproducible soak evidence, duration, decision window and
> interference inside the creating transaction, then seals a NEW immutable Golden bundle (identical payload; `lineage.promotion` pins the soak, evidence digest and decision inside the bundle digest and is cross-checked by integrity); REJECT is immutable and a retry is a new soak. Approval never contacts a device;
> **startup-config persistence remains undecided and is not implemented.** UI under Device Builder (`/device-builder/soaks/`); audit `PROBATION_SOAK_*` / `GOLDEN_*`; notifications through the existing service. Tier-3 gained `probation_soak`. **1085** Django tests pass (1007 + 78); 446 monitoring; eleven targeted mutations were all
> caught by tests; read-only verifiers: topology / NetBox 392/392 / populate UNCHANGED=318 / reservations READY / DHCP / NMAS 20/20 pass and Grafana fails only the known SNMP-poll `Latest polled CPU` panel (the streamed telemetry the soak reads was measured FRESH on all ten devices). **No real device was configured and no
> real soak has been started: Phase 20B (168 real hours + the operator's decision) has NOT happened, so there is no real Golden bundle and Checkpoint 4 is NOT created.** See the runbook in `docs/PROBATION_SOAK_AND_PROMOTION.md` section 17.

> **Phase 19 update (2026-09-21):** **immutable configuration bundles -- UAT -> Probation -> Golden foundations** (`web/core/services/bundles/`, facade `bundle_service.py`; migration `0008`). A bundle is *evidence*: an immutable,
> content-addressed artifact (`ConfigurationBundle` + ordered `ConfigurationBundleItem`; ids `BND-UAT-000001` / `BND-PROB-` / `BND-GOLD-`; explicit `UAT` / `PROBATION` / `GOLDEN` kind) with a versioned canonical manifest and two SHA-256 digests
> (a **payload digest** over the frozen configuration + source provenance, and a **bundle digest** that adds kind and lineage). A **UAT bundle** is created only by an explicit POST from a finished, eligible **Partial (UAT)** run and freezes exactly the
> successfully applied ordered prefix from the run's *pinned historical records* (never the current Change state); failed / interrupted / blocked / Complete runs are refused with stable codes. Raw Configlets are pinned to their exact Phase-18 revision and
> verification run and recorded as `SYNTAX_ONLY`. An explicitly `UNVERIFIED` scope may be bundled but can **never** enter Probation. A **Probation bundle** is a NEW artifact sealed from an eligible, verified UAT bundle (same payload digest, different bundle
> digest, explicit confirmed POST, UAT untouched). **Probation is not soak success**: no timer, soak state, scheduler or lifecycle change exists. The **Golden** bundle is defined structurally (model, lineage, integrity, display) but **no Phase-19 action creates one**:
> the service seam always refuses with `PHASE20_EVIDENCE_REQUIRED` (soak, evidence and the operator decision are Phase 20). Immutability is layered (write-once rows, refusing querysets, PROTECT FKs, DB constraints, no admin/edit route) and integrity is
> *recomputed* on demand (`verify_bundle_integrity`), never a stored flag; a deterministic, self-verifying manifest export exists. Creation is atomic and idempotent (DB unique constraints; races return the winner). Bundle actions are DB + audit only
> (`UAT_BUNDLE_CREATED`, `PROBATION_BUNDLE_CREATED`, `BUNDLE_INTEGRITY_FAILED`): no device, NetBox, Git, notification, credential or shell. UI under Device Builder (`/device-builder/bundles/`). Tier-3 gained a `bundles` subsystem. **1007** Django tests pass
> (950 + 57); 446 monitoring; the full local Tier-3 ran with the real read-only verifiers: six of seven pass, and the Grafana verifier fails only the known `Latest polled CPU` panel (on-demand SNMP data older than its fixed 24 h window; unrelated to Phase 19).
> Fifteen targeted mutations were all caught by existing tests. **No real device was configured.** A digest is not a signature (see the doc's limitations). No Golden, no soak, no Checkpoint 4. See `docs/IMMUTABLE_CONFIGURATION_BUNDLES.md`.

> **Developer workflow update (2026-09-21):** **phase integration helper** (`tools/phase_integrate.py`; `docs/PHASE_INTEGRATION_WORKFLOW.md`) -- *not* a phase and not part of the application: it automates the repetitive Git/GitHub
> source-integration steps (`start` a `phase<N>-<slug>` branch, `prepare` = derive source candidates from Git status, refuse suspicious files, validate with local Tier-3, stage explicit paths only, verify the staged manifest, commit, push,
> open/reuse the PR; `status`; `merge` = merge commit only after the hosted `Tier-3 validation` check succeeded, then `git pull --ff-only`). `Run_Logs.log` and `logs/R2.log` are the only permitted dirty runtime artifacts and are never
> staged; no add-all / commit-all / force-push / reset / clean / stash exists in its command allowlist; `prepare` never merges (the operator's `merge` is the approval boundary). Source-control tooling only: no device, NetBox, `master.py`
> or Containerlab operation. Tier-3 classifies `tools/**` as `dev_tooling` (selects `core.tests.test_phase_integrate`). No functional change to any phase.

> **Phase 18 update (2026-09-21):** **Raw Configlets + isolated verifier / sandbox** (`web/core/services/raw_configlets/`, facade `raw_configlet_service.py`; migration `0007`). An explicit, *separate* escape hatch from the
> structured Device Builder (no CLI field was added to any structured section): operator-authored network **configuration statements** for one device, as `RawConfiglet` (stable `RAW-NNN`) -> **immutable**
> `RawConfigletRevision` (text + content hash + target / platform / declared priority / explicit dependencies / optional assertions) -> append-only `RawConfigletVerificationRun`. A deterministic **static gate** (size 32 KiB /
> 500 lines / 512 chars, ASCII only, no NUL / control chars, no prompts / mode control / host shell / exec-mode / `event-handler`-style constructs, **secret-shaped content refused before persistence**) runs at save and again at verify.
> Verification runs **only in a disposable, network-less sandbox, never on a managed device**: Ubuntu/FRR via `vtysh --dryrun` (unprivileged, read-only, all caps dropped, local image built from the R3/R4 FRR version) and cEOS via an
> always-aborted `configure session` (needs `--privileged`, so **off by default**, `RAW_VERIFIER_ALLOW_PRIVILEGED=1`); syntax only, never semantics; the one process boundary is a `docker` argv list, `shell=False`, stdin-only payload, allowlisted env,
> cleanup confirmed in `finally`; every failure is `INCOMPLETE`, never PASS. Results PASS / PASS_WITH_WARNINGS / BLOCKED / INCOMPLETE; currency NEVER_RUN / CURRENT / STALE (content, platform, policy, verifier, adapter, backend). Raw input joins the Change
> snapshot **only when present** (historical hashes unchanged), so any add / edit / retarget / reorder / remove / re-verify makes validation and plan STALE; validation treats raw as opaque verified artifacts (`RAW_*` codes), dependencies are
> explicit graph edges, priority is declared, and verified raw becomes an opaque Configlet (`origin=RAW`, pinned revision + verification) in the SAME plan. Execution is the SAME Phase-17 engine: payload re-read from the pinned revision, **Complete is
> always refused (`RAW_COMPLETE_FORBIDDEN`)**, Partial (UAT) keeps all five acknowledgements and ordered-prefix semantics; postcheck = declared closed-catalogue assertions or honestly UNVERIFIED. Raw execution is SUPPORTED on cEOS only; FRR is
> verifiable but execution NOT_IMPLEMENTED; SR Linux UNSUPPORTED; IOS 8000v / SONiC NOT_IMPLEMENTED. UI: `/device-builder/changes/<id>/raw/` (editor, read-only revision + verification history). **915** Django tests pass (860 + 55); 446 monitoring;
> Tier-3 full PASS_WITH_WARNINGS (documented hygiene bound). The real sandboxes were exercised (`manage.py raw_verifier_selftest`: FRR and cEOS valid -> PASS, invalid -> BLOCKED, cleanup proven). Six of the seven existing real lab verifiers pass; the
> Grafana verifier fails one panel (`Latest polled CPU`) because the ON-DEMAND SNMP poll data is older than its fixed 24 h window (data exists at 24-48 h; unrelated to Phase 18). **No Raw Configlet was applied to a real device.** No commit.
> See `docs/RAW_CONFIGLETS_AND_SANDBOX.md`.

> **Phase 17 update (2026-09-21):** **structured execution -- Complete and Partial (UAT)** (`web/core/services/execution/`, facade `execution_service.py`;
> migration `0006`). A reusable Python engine, called only by the explicit CSRF POST `/device-builder/changes/<id>/execute/run/`, executes the CURRENT plan's structured
> Configlets in plan order. An eligibility gate (lifecycle, CURRENT validation + plan, a permitting **recent precheck for this plan**, managed/platform-consistent devices, supported
> apply paths, Complete-only compensation/verifiability proof, five UAT acknowledgements + explicit prefix scope, VLAN 200, no concurrent run) blocks with stable codes and never refreshes
> anything silently. Preparation (connect, read-only AUTO-address recheck -- **no NetBox write**, assess every Configlet's previous state from the Phase-15 evidence groups) precedes the
> first mutation. **Complete** = application-level transaction: apply, stop at first failure, Phase-15 postcheck must confirm (missing evidence is never PASS), otherwise reverse-order,
> read-back-verified compensation of what THIS run applied -- additive Configlets only (address, static route, newly created interface); everything else is refused for Complete before any
> change. **Partial (UAT)** = ordered prefix, stops at first failure, **preserves** the applied prefix, never rolls back, records applied/failed/unapplied/out-of-scope, postchecks only the
> executed scope. Executors: cEOS via Netmiko config mode (`master.py::push_eos` pattern); Ubuntu/FRR interface/address via credential-free `docker exec` argv with a strict grammar; FRR
> routing/static routes/NAT, SR Linux, IOS 8000v, SONiC are NOT_IMPLEMENTED/UNSUPPORTED. Append-only `ChangeExecutionRun` / `ConfigletExecutionResult` (+ transient DB-unique device locks:
> one active run per Change, one run per device), audit (`DEPLOYMENT_RECORDED`/`ROLLBACK_RECORDED`), notifications (persist first). Running configuration only (no `write memory`); lifecycle
> untouched; no Golden/Probation/soak. **860** Django tests pass (809 + 51); 446 monitoring; Tier-3 full PASS_WITH_WARNINGS (documented hygiene bound); the seven real read-only lab verifiers pass.
> **No real device configuration was executed** (no approved live mutation exists): live mutating acceptance was not performed. No commit. See `docs/STRUCTURED_EXECUTION_COMPLETE_PARTIAL_UAT.md`.

> **Phase 16 update (2026-09-21):** **Tier-3 change-effect, integration and regression validation** -- a reusable pure-Python service
> (`web/core/services/ci/`, facade `ci_service.py`, launcher `tier3.py`; no Django configuration needed) plus one thin GitHub workflow
> (`.github/workflows/tier3-validation.yml`: checkout, install, one `python tier3.py --from-github` call, artifact upload;
> `permissions: contents: read`, no secrets, no `pull_request_target`, no self-hosted runner). For an explicit base/head comparison
> (merge-base for PRs, direct for pushes, working-tree for local use; a base CI cannot use broadens to full, never skips) it collects
> changed files through a read-only git allowlist, classifies each path against ONE declarative rule table (`rules.py`; unknown paths force
> the full gate), expands curated cross-subsystem impact (validation -> planning -> health, renderer -> Device Builder -> validation ...), and
> selects checks with a stated reason for each: baseline static gates (hygiene, syntax, `manage.py check`, migration drift), the affected
> Django test modules or the whole `core` suite, the monitoring suite and Grafana drift check. `--mode full` runs the whole regression
> surface. The seven real lab verifiers are a separate opt-in `--lab` gate; when not run they are `NOT_RUN`, never PASS. Results are
> PASS / PASS_WITH_WARNINGS / FAIL / INCOMPLETE (exit 0/0/1/3; 2 = usage); a crash, timeout or zero-test run is INCOMPLETE. The report is
> bounded, redacted, deterministic JSON plus a job summary; nothing is persisted (no model, no migration). No deployment, device or NetBox
> write, Configlet execution, lifecycle change, Containerlab command or rollback. **809** Django tests pass (770 + 39, order-independent;
> also with outbound TCP blocked); the 446-test monitoring suite and the real Grafana, topology, NetBox, reservation, DHCP and NMAS
> verifiers also pass. Offline (CI) viability was proven; the workflow itself has not run on GitHub. No commit.
> See `docs/GITHUB_ACTIONS_TIER3_VALIDATION.md`.

> **Phase 15 update (2026-09-21):** read-only **operational health, prechecks and a reusable postcheck engine**
> (`web/core/services/health/`, facade `health_service.py`). *Fleet Quick* summarizes the whole managed fleet from the
> EXISTING topology / InfluxDB telemetry (freshness FRESH <= 60 s < STALE <= 120 s < EXPIRED, CPU 70/90 %, memory 75/90 %, all
> read from the existing monitoring config; a missing metric is UNKNOWN, never 0) with no device access. *Deep Health* is an
> explicit, one-device, read-only query from fixed server-owned allowlists (cEOS via Netmiko `show ... | json`; Ubuntu/FRR via
> `docker exec` of fixed `ip -j` / `vtysh show` / `nft list` argv; live-verified on R1 and R3). The *precheck* consumes the CURRENT
> passing validation and CURRENT plan (never re-running or rebuilding either), judges only the plan-derived affected scope, and
> treats future-state requirements as not-yet-required before deployment; the *postcheck* engine
> (`evaluate_plan_requirements(plan, phase, evidence)`) evaluates the plan's Phase-14 verification descriptors, which gained an
> optional secret-free `expected` block (descriptor schema 2, no migration for it). Missing evidence is UNKNOWN / INCOMPLETE, never PASS;
> unverifiable requirements are reported honestly. One append-only `OperationalCheckRun` model (migration `0005`) + one audit event
> per explicit run. UI: sidebar **Health**, `/health/`, `/health/device/<device>/`, `/device-builder/changes/<id>/precheck/`.
> No deployment, device mutation, NetBox/Git write, notification, lifecycle change or rollback. **770** Django tests pass (717 + 53);
> the 446-test monitoring suite and the Grafana, topology, NetBox, DHCP and NMAS verifiers also pass. No commit.
> See `docs/HEALTH_PRECHECK_POSTCHECK.md` and `docs/CHECKPOINT_03_MANIFEST.md`.

> **Phase 14 update (2026-09-20/21):** *Stage 0* rationalized the Django suite
> (1075 -> **682** tests, -36.6 %; wall clock 106.5 s -> 34.8 s; behavioral coverage
> not reduced -- see `docs/TEST_SUITE_RATIONALIZATION.md`, including one real
> Phase-12 HTTP-500 defect fixed and a 43 s unmocked-NetBox wait removed).
> *Stage 1* adds the unified priority / dependency **plan builder**: from the latest
> CURRENT `PASS` / `PASS_WITH_WARNINGS` validation (never re-run implicitly) it builds
> granular Configlets on the existing Phase-8 `Configlet` / `ConfigletDependency`
> models, pinned to the exact validation run (input/source hash, engine version),
> ordered by a deterministic dependency-first topological sort over the nine canonical
> priority classes, DEFINE kept distinct from ACTIVATE/ATTACH, snippets rendered by the
> same platform drivers as the Device Builder preview, AUTO addresses taken from
> Phase-13 derived facts (unreserved, recheck required), previous state explicitly
> `UNKNOWN_DEFERRED`, verification as declarative Phase-15 placeholders. Persistence is
> one minimal append-only `ChangePlan` (migration `0004`) built atomically and
> idempotently per validation run; a plan is CURRENT only while its pinned validation is.
> UI: `/device-builder/changes/<change_id>/plan/` (GET read-only; explicit CSRF POST
> *Build Plan*; stages, Configlets, typed dependencies, history, JSON report). No
> deployment, device access, NetBox/Git write, notification or lifecycle change; the
> Change stays `DRAFT`. **717** Django tests pass (682 optimized baseline + 35); the
> 446-test monitoring suite and the Grafana, topology, NetBox, DHCP and NMAS verifiers
> also pass; a live walkthrough against the real read-only sources left no synthetic
> rows. No commit. See `docs/CHANGE_PLAN_AND_CONFIGLETS.md`.

> **Phase 13 update (2026-09-20):** a Python-owned Tier-2 project-aware Change
> validation engine now validates a WHOLE Change's committed/accepted intent
> against NetBox (read-only), the runtime topology metadata, the fixed project
> inventory, and the SAME capability registries the renderer uses. It produces a
> deterministic accepted-intent snapshot with a SHA-256 input hash, source
> provenance/fingerprints, stale detection (NEVER_RUN/CURRENT/STALE -- STALE is
> a currency state, not a result), stable machine-readable finding codes, derived
> facts (including read-only PROPOSED/NOT-RESERVED AUTO addresses), and a
> semantic dependency graph with typed edges, missing-reference and cycle
> detection. Results are PASS / PASS_WITH_WARNINGS / BLOCKED / INCOMPLETE and a
> source outage or validator exception never becomes PASS. One append-only
> `ChangeValidationRun` model (migration 0003) keeps the history; validation runs
> only on an explicit POST, never advances the lifecycle, and performs no
> deployment, NetBox/Git write, device access, or Configlet creation. UI:
> `/device-builder/changes/<change_id>/validation/`. Phase 14 consumes the
> validated objects and dependency graph to build the unified plan.
> 335 new focused tests pass (1075-test Django suite, up from 740); the
> unchanged 446-test monitoring suite and the safe Grafana, topology, NetBox,
> DHCP and NMAS verifiers also pass. A live `127.0.0.1` walkthrough (real
> read-only NetBox/topology/inventory; PASS, duplicate/NetBox-collision BLOCKED,
> BGP remote-AS BLOCKED, mocked-outage INCOMPLETE, STALE after an accepted edit,
> append-only re-run, JSON report) left no synthetic rows behind. No commit.
> See `docs/CHANGE_VALIDATION_AND_DEPENDENCIES.md`.

> **Phase 12 update (2026-09-20):** the Device Builder major catalogue now
> includes structured FHRP, NAT, DHCP/DHCPv6 and DNS inheritance, ACL, and PBR
> foundations in the existing versioned revision schema. Stable IDs, strict
> owned field paths, browser-local typing, Tier-1 validation, field-local
> rollback, four-state capability filtering, platform-preserved incompatible
> intent, and the single Python candidate renderer extend the Phase-10/11
> contracts without a model migration. Repository evidence enables cEOS VARP,
> cEOS DHCPv4/DHCPv6 relay, cEOS IPv4 ACL, and Ubuntu nftables NAT44/PAT;
> unevidenced features remain honestly unavailable. DHCP defaults still inherit
> NMAS primary/R2 secondary architecture, VLAN 200 remains static, NAT-PT is
> explicitly deprecated, and no deployment/NetBox/Git/Configlet action exists.
> The 40 Phase-12 focused tests and full 740-test Django suite pass; the
> unchanged 446-test monitoring suite and safe Grafana, topology, NetBox, and
> DHCP verifiers also pass.
> See `docs/DEVICE_BUILDER_SERVICES_SECURITY_POLICY.md`.

> **Phase 11 update (2026-09-20, continuation session):** structured routing
> intent -- static routing, RIPv2/RIPng, OSPFv2/OSPFv3, IS-IS, EIGRP, and
> BGP -- is now live in the Device Builder, in the same `sections["routing"]`
> namespace/stable-ID/Tier-1-validator/one-renderer pattern Phase 10
> established for interfaces (no new model, no migration). A second,
> independent, evidence-backed capability matrix
> (`platform_drivers.ROUTING_CAPABILITIES`) filters selectable new protocol
> objects per platform while preserving and flagging incompatible existing
> intent exactly like the Phase-10 interface matrix does; cEOS and
> Ubuntu/FRR get real, evidence-backed syntax (verified against tracked
> R1-R5 configs and logs), SR Linux/IOS 8000v/SONiC/IS-IS/RIPng/EIGRP stay
> honestly `NOT_IMPLEMENTED`/`UNSUPPORTED`. BGP neighbor authentication is
> `password_ref`-only -- no plaintext secret can be persisted. 159 new
> focused tests pass (700-test Django suite total, up from 541); the
> unchanged 446-test monitoring suite, the 7-dashboard/62-panel Grafana
> verifier, the 19-check topology verifier, `verify_netbox_model.py`
> (392/392), `populate_netbox.py --check` (318 unchanged), and
> `verify_reservations.py` (READY) were all re-run and still pass. A live
> `127.0.0.1` walkthrough (static routes, OSPF, BGP instance/neighbor/
> network, invalid-then-valid commit, platform switch preserving
> now-unsupported intent) was exercised against a real running server and
> the synthetic Change was deleted afterward. No commit occurred. Full
> schema, capability, security, evidence, limitations, and Phase-12
> handoff details are in `docs/DEVICE_BUILDER_ROUTING.md`.

> **Phase 10 update (2026-09-20, continuation session):** the in-progress
> Device Builder interface/address/WAN implementation is complete and
> verified. Stable `if_*`/`addr_*` objects live in versioned revision sections;
> Basic/Advanced edit the same state; four-state, evidence-backed platform
> capabilities filter only project-supported new objects while preserving and
> flagging incompatible existing intent; cEOS and selected Ubuntu/iproute2
> feature templates feed the one Python renderer; MANUAL dual-stack and
> explicit-read-only AUTO prefix intent are supported; AUTO remains
> unresolved/unreserved and is not DHCP; VLAN 200 is UI-hidden and
> server-rejected for AUTO; WAN remains metadata-only. 138 focused tests and
> the 541-test Django suite pass, along with the unchanged 446-test monitoring
> suite and all safe Checkpoint-2 live verifiers. Full schema, capability,
> security, evidence, limitations, and Phase-11 handoff details are in
> `docs/DEVICE_BUILDER_INTERFACES_ADDRESSING_WAN.md`.

> **Phase 9 update (2026-09-20, later session):** the Device Builder is now
> a real interactive split-screen editor at `/device-builder/changes/
> <change_id>/intent/<id>/` (Basic) and `.../advanced/` (Advanced) --
> both operate on the exact same Phase-8 `DeviceIntent`/
> `DeviceIntentRevision`/`IntentFieldState` rows (no new model; this phase
> needed zero migrations). Browser-owned draft typing
> (`static/core/js/device_builder.js`) never calls the server on keypress
> -- only an explicit Enter (Ctrl+Enter for the multiline description, or a
> Commit button) POSTs to the one new mutation endpoint,
> `.../fields/commit/`, which runs a Tier-1 syntax-only validator
> (`core/services/field_validators.py`) against a fixed field allowlist
> (`core/services/field_registry.py`) and either accepts+normalizes or
> rolls back exactly the one field that failed -- proven not to touch
> siblings. A new one-authoritative-renderer contract
> (`core/services/candidate_renderer.py`) with a five-platform driver
> registry (`platform_drivers.py`, cEOS/SR Linux/Ubuntu-FRR/IOS
> 8000v/SONiC, looked up by platform, never by hostname conditional)
> produces a truthful minimal "Candidate Configuration" (hostname-only
> today; unimplemented sections say so honestly instead of fabricating
> vendor CLI); the browser substitutes live draft values into the same
> descriptor slots the Python renderer emits, so there is exactly one CLI
> renderer, not two. Copy Candidate (client-side Clipboard API), Download
> Candidate (server-generated, accepted-only, safe filename), and an
> accepted-vs-draft Diff page are all implemented; none of it deploys
> anything, calls NetBox/GitHub/Git, or opens a live device connection.
> `device_builder_service` graduates out of the `not_integrated`
> placeholder list in this phase (Device Identity editing is real now),
> matching monitoring's Phase 6 and NSOT's Phase 7 graduation. 108 new
> Django tests pass (403 total, up from 294 -- 295 after one small
> `test_services.py` graduation-test addition); the existing 446-test
> monitoring suite, the 7-dashboard/62-panel Grafana verifier, the
> 19-check topology verifier, and `verify_netbox_model.py` (392/392) were
> all re-run unchanged and still pass. No commit occurred. Full
> architecture, the Tier-1 validation boundary, the browser-preview
> contract, and the Phase-10 handoff are in
> `docs/DEVICE_BUILDER_FOUNDATION.md`.

> **Phase 8 update (2026-09-20, later session):** the structured Device
> Intent / Change / Configlet control-plane data model now exists —
> `Change` (stable `CHG-YYYYMMDD-NNNN` id, immutable after creation,
> Complete/Partial (UAT) execution mode, append-only lifecycle history via
> `ChangeLifecycleEvent`), `ChangeTarget`, `DeviceIntent` +
> `DeviceIntentRevision` (versioned, namespaced `sections` JSON,
> `schema_version`), `IntentFieldState` (the exact draft_value/
> accepted_value-per-field contract Phase 9's Device Builder needs),
> `Configlet` (stable `CFG-NNN` id, deployment-priority taxonomy, create-
> vs-activate/attach distinction) + `ConfigletDependency` (same-Change
> directed edges, self/duplicate/cross-Change rejected), and a
> general-purpose append-only `AuditEvent` trail. A new
> `core/services/secret_policy.py` generalizes Phase 4's notification
> metadata-secret denylist into one shared policy both subsystems now use;
> no Phase 8 model can persist a raw password/token/etc., only a `*_ref`
> reference. Structure only, per this phase's explicit scope: no config
> rendering, no network-semantic validation, no deployment, no NetBox
> write, no Golden/Probation/soak/rollback behavior. Two new read-only
> routes (`/device-builder/changes/`, `/device-builder/changes/<id>/`)
> exist purely for inspection; the existing Device Builder landing page's
> honest `not_integrated` summary is unchanged. 81 new Django tests pass
> (293 total, up from 212); the existing 446-test monitoring suite, the
> 7-dashboard/62-panel Grafana verifier, the 19-check topology verifier,
> and `verify_netbox_model.py` (392/392) were all re-run unchanged and
> still pass. No commit occurred (per this phase's instructions — next
> checkpoint is after Phase 10). Full architecture, ownership boundaries,
> and the Phase-9 handoff contract are in
> `docs/DEVICE_INTENT_CHANGE_MODEL.md`.

> **Phase 7 update (2026-09-20, later session):** the Django NSOT page is now
> a real, read-only, multi-source aggregation surface (Overview, Devices,
> Device detail, Interfaces, IPAM, VLANs, Routing/ASN, Platforms,
> Templates/Code, Drift/Consistency) reading through new adapters
> `core/services/nsot_netbox.py` (existing `modules/netbox_ipam.py`/
> `modules/ipam_context.py` client, never a second one), `core/services/
> nsot_git.py` (the only module that shells out to `git`; fixed argument
> arrays, allowlisted file catalogue), and `core/services/nsot_live.py`
> (bounded, explicit, redacted `show running-config` retrieval, cEOS only,
> reusing `master.py::verify_eos()`'s own enable-mode pattern; R3/R4 Linux/
> FRR honestly report `not_supported`). NetBox remains passive storage --
> Django never writes to it. Live-verified end-to-end against the real
> NetBox instance and a real cEOS device (R1): 43 new Django tests pass, the
> existing 212-test Django suite (up from 169) passes, and a real secret
> leak this phase's own testing caught -- SNMPv3 localized auth/priv key
> material on a live `show running-config` response was not covered by the
> initial redaction keyword list -- was found and fixed before shipping
> (see `docs/DJANGO_NSOT_INTEGRATION.md` "Redaction"). `verify_netbox_model.py`
> (392/392), `populate_netbox.py --check` (UNCHANGED=318), and
> `verify_reservations.py` (READY, 0 reservation targets) are all unchanged
> from the Phase 1-6 baseline -- no NetBox write occurred. Full architecture,
> source-ownership matrix, security model, and known limitations are in
> `docs/DJANGO_NSOT_INTEGRATION.md`.

> **Phase 6 update (2026-09-20; iframe hotfix 2026-09-27):** all three Django
> Monitoring shells are operational read-only Grafana control surfaces. They
> use canonical `nmas-resources`, `nmas-link-events`, and
> `nmas-link-state-traffic` UIDs; validate bookmarkable GET filters and fixed
> time ranges; and keep Grafana authoritative for rendering. Grafana remains
> loopback-only, authenticated, and anonymous-disabled, while tracked Compose
> desired state permits framing. Django now verifies both health and the live
> XFO/CSP framing policy before rendering an authenticated iframe; prohibited
> framing retains the secure full-dashboard fallback. Real Chromium acceptance
> rendered all three dashboards and preserved Resources filters across reload.
> Full architecture, security, filters, theme behavior, and limitations are in
> `docs/DJANGO_MONITORING_INTEGRATION.md`.

> **Phase 3 update (2026-09-20, later session):** a Django UI foundation
> now exists at `web/` (project `config`, app `core`) — a human-control-plane
> shell with sidebar (Home/Monitoring/Device Builder/NSOT/Automation),
> top-right Notifications/Profile, a four-theme framework (Basic Minimal,
> Dark Mode, Dark Angels, Adeptus Mechanicus, the latter two each with
> contextual variants), and an explicit `core/services/` boundary that
> returns honest `not_integrated` placeholders — no view performs
> Netmiko/pynetbox/subprocess/InfluxDB access. The ten operator-supplied
> artwork assets were not present in this session's filesystem; the theme/
> asset framework and CSS fallback were still built, with exact drop-in
> locations documented. 50 new Django tests pass; the existing 446-test
> regression suite and the Grafana verifier were re-run unchanged and both
> still pass. Full detail in `docs/DJANGO_UI_FOUNDATION.md`. Everything
> below this notice is the Phase 1/2 baseline and is unaffected by Phase 3.

> **Phase 4 update (2026-09-20, later session):** the notification/event
> backbone now exists — `core/models.py::Notification` (one model, one
> migration), a single reusable publisher API
> (`core/services/notification_service.py::publish_event()`), a Slack
> Incoming Webhook adapter (`core/services/slack_service.py`, stdlib
> `urllib`, no new dependency, webhook read only from `SLACK_WEBHOOK_URL` at
> send time and never persisted/logged/templated), a real header dropdown
> (max 4, newest first, unread badge capped at "9+"), a full Notification
> Center with filters/pagination, a per-notification detail page,
> CSRF-protected mark-read/mark-all-read, and a safe
> `manage.py send_test_notification` / `cleanup_test_notifications` tool
> pair. Slack was not configured in this environment
> (`SLACK_WEBHOOK_URL` unset) — delivery behavior was proven with mocked
> HTTP tests plus a live `NOT_CONFIGURED` run, not a real Slack send. This
> phase also fixed a pre-existing artwork-resolver bug (three of the ten
> slot path strings pointed one directory level too deep) discovered while
> verifying the ten watermark files the operator added after Phase 3; all
> ten now resolve and serve HTTP 200 — no artwork file was altered. 117
> Django tests pass (up from 50 at Phase 3); the existing 446-test
> monitoring regression suite and the 7-dashboard Grafana verifier were
> re-run unchanged and both still pass. Full detail in
> `docs/NOTIFICATION_AND_SLACK_ARCHITECTURE.md`. Everything below this
> notice is the Phase 1/2 baseline and is unaffected by Phase 4.

> **Phase 5 update (2026-09-20, later session):** Django Home now renders
> the existing read-only NetworkX topology through a validated server-side
> adapter and same-origin GET-only `/api/topology/` endpoint. The existing
> graph service remains authoritative; Django performs no discovery or graph
> construction. The Home SVG supports pan, zoom, presentation-only node
> dragging/reset, address visibility, node/link details, and 20-second
> refresh while preserving browser display state. Upstream failures produce
> a clear usable degraded Home rather than fake data or a crash. The upstream
> 10-second cache is reused; Django adds no second cache. Full architecture,
> schema, security, read-only evidence, and Phase-6 handoff are documented in
> `docs/DJANGO_TOPOLOGY_INTEGRATION.md`.

# Current State — Phase 1 Baseline (Labs 4/5)

Established: 2026-09-20, via independent live re-verification of the repository at
`/home/student/Scripts/clab_dualstack_lab`. This document is the authoritative
handoff for all subsequent Labs 4/5 Codex phases. It supersedes casual assumptions
carried over from prior conversations; every figure below was reproduced live in
this session, not copied from an older report.

> **Phase 2 update (2026-09-20, same day, later session):** the Grafana
> finding in §5/§6/§13/§15 below (the CPU-alert-panel verifier gap) has been
> resolved. Grafana now has 7 dashboards (62 panels, 23 variables, 79
> queries; the 4 original dashboards are unchanged and retained as legacy,
> plus 3 new canonical dashboards: `nmas-resources`, `nmas-link-events`,
> `nmas-link-state-traffic`). Full detail, design rationale, and the Django
> integration contract are in `docs/GRAFANA_MONITORING_TAXONOMY.md`. The
> rest of this document (NetBox/IPAM, SNMP, syslog, telemetry, topology,
> template/render architecture) is unaffected by Phase 2 and remains
> accurate as the Phase 1 baseline below describes it.

## 1. Repository / Git baseline

- Path: `/home/student/Scripts/clab_dualstack_lab`, confirmed via `git rev-parse
  --show-toplevel`.
- Branch: `main`. HEAD: `7a26dee` ("Complete final Labs 2 and 3 report"). 15 commits
  total, all from the original Lab 1/Labs 2-3 monitoring build-out.
- Working tree is **intentionally not clean**: the entire NetBox/IPAM/DHCP
  migration sits uncommitted (modified: `.gitignore`, `Run_Logs.log`,
  `dhcp/dhcpd.conf.j2`, `dhcp/dhcpd6.conf.j2`, `logs/R2.log`, `master.py`,
  `monitoring/requirements.txt`, `monitoring/scripts/install_python_dependencies.sh`,
  `templates/R2.cfg.j2`; untracked: `docs/NETBOX_IPAM.md`, `modules/eos_render.py`,
  `modules/ipam_context.py`, `modules/netbox_ipam.py`, 7 new test files, all of
  `netbox/`, `templates/R2_dhcp_server.cfg.j2`). This matches the project's
  standing convention (see `AGENTS.md`): the human reviews and commits phases
  separately. **This phase made no edits to any of those files and did not stage
  or commit anything** — the only change introduced by Phase 1 is this new file.

## 2. Architecture overview

Layered IaC: `inventory.yml` (declarative toggles/addressing) → `master.py` (thin
orchestrator) → `modules/*.py` (one module per subsystem) → Jinja templates →
Netmiko (EOS) / Paramiko-SSH (Linux) for push, plus a parallel, additive NetBox
layer (`modules/netbox_ipam.py`, `modules/ipam_context.py`) supplying DHCP pool
structure to the render path. Labs 2/3 monitoring (SNMP/syslog/gNMI/NETCONF/CPU
alerting/InfluxDB/Grafana/NetworkX) is a second additive layer wired in via
`master.py`'s `ensure_*_infrastructure()` chain. Lab 1 (routing/VLANs/addressing)
is frozen per `AGENTS.md` and was not touched.

## 3. master.py / module ownership

`master.py` (414 lines) remains thin: it owns orchestration order and
connection/push mechanics only. It delegates: NetBox DHCP-context building and
pool-safety validation to `modules/ipam_context.py`; Jinja rendering and EOS
command flattening to `modules/eos_render.py`; all monitoring provisioning to
`modules/{nmas,snmp,syslog,telemetry,grafana,topology}.py` via their
`ensure_*_infrastructure()` entry points, called once at the end of `main()` in
that fixed order (nmas → snmp → syslog → telemetry → grafana → topology). It
still never calls `containerlab deploy/destroy` — confirmed absent from the file.

## 4. NetBox / IPAM / DHCP — verified live this session

- **NetBox is passive**: `netbox/configuration/configuration.py` has
  `PLUGINS = []`, untouched; all decision logic lives in
  `modules/netbox_ipam.py` (pure reads via pynetbox) and
  `modules/ipam_context.py` (fail-closed `build_and_validate_*_dhcp_context()`
  gates). No plugin/webhook code exists inside NetBox itself.
- **NetBox is the runtime-authoritative structured source for DHCP pool
  data.** `netbox/ipam.yml` is confirmed bootstrap/recovery-seed-only: consumed
  solely by `populate_netbox.py --apply` and a test fixture, never read by
  `master.py`/`ipam_context.py` at render time.
- **Drift check (live, `populate_netbox.py --check`, dry-run):**
  `Summary: UNCHANGED=318` — the live NetBox instance and the seed manifest are
  in sync, zero drift.
- **VLAN 200 status (live, `verify_reservations.py`):** all 9 managed devices'
  Vlan200 interfaces (R1, R2, R3, R4, S1, S2, S3, S4, `mgmt_swt`) show
  `IPv4 MODE=static`, `IPv6 MODE=static`, `READINESS=STATIC/NONE`. **Reservation
  targets checked: 0.** VLAN 200 is fully static and structurally excluded from
  DHCP/DHCPv6 on every device — confirmed, not assumed.
- **Primary/secondary DHCP health (live, `test_verify_dhcp_servers`-style check
  and `populate_netbox.py --check` output inspected):** NMAS (primary, ISC)
  reports active/active for IPv4/IPv6; R2 (secondary, EOS/Kea) reports
  active/active. No competing literal pool boundaries were found in either
  active render path (`dhcp/dhcpd.conf.j2`, `dhcp/dhcpd6.conf.j2`,
  `templates/R2.cfg.j2` + `R2_dhcp_server.cfg.j2` — all NetBox-context-driven).
- **NetBox model validation (live, `verify_netbox_model.py`):**
  `392/392 checks passed.` — unchanged from the last reported figure.
- **`pin_stable_identities.py` / `sync_interface_macs.py`**: unchanged from prior
  assessment — self-guarding, currently no-op for pinning (no
  `dhcp-reserved`/`dhcpv6-reserved` interfaces exist to act on), retained for a
  genuinely future dynamic-assignment target.

## 5. Monitoring — verified live this session

| Subsystem | Result | Notes |
|---|---|---|
| SNMPv3 polling/auth (`verify_snmp.py`) | **PASS, all 10 devices** | AGENT/AUTH/SYSNAME/UPTIME/CPU/IFSTATUS/STORAGE all PASS |
| SNMP trap ingestion | **PASS** | Verified via R1 test notification → InfluxDB |
| Syslog (`verify_syslog.py`) | **PASS, all 10 devices** | CONFIG/CRITICAL/RAWLOG/STORAGE all PASS |
| CPU alerting | **Collector-side only, confirmed** | `modules/cpu_alerts.py` writes measurement `collector_alert`, distinct from `snmp_trap`; **no native device CPU SNMP trap exists on either platform** — this was true before and remains true |
| gNMI/NETCONF (`verify_telemetry.py`) | **PASS, all 10 devices** | GNMI/STREAM/INFLUX/NETCONF/NC-GET all PASS; R3/R4 explicitly via the documented read-only lab adapter, not native FRR |
| InfluxDB | **Healthy** | `monitoring-influxdb-1`, 2.7.11, 30-day retention confirmed by `verify_nmas_infrastructure.sh` |
| Grafana | **PASS with one live finding** | See below |
| NMAS infrastructure (`verify_nmas_infrastructure.sh`) | **PASS 20/20** | rsyslog, snmptrapd, SNMP/NETCONF/gNMI client tooling, InfluxDB, Grafana, logrotate, synthetic write/query all PASS |

**New live finding (not previously documented as a known state): `verify_grafana.py`
currently fails on one panel** — `nmas-snmp-monitoring: panel "NMAS Collector CPU
Alerts" returned no recent real data`. Root-cause analysis: this panel queries the
`collector_alert` measurement over the verifier's default 24h window
(`modules/grafana.py:execute_flux`, `hours=24`); the panel is **not** in the
script's `ALLOW_EMPTY` set. `docs/FINAL_COMPLIANCE_AUDIT.md` records that this
panel legitimately had data on 2026-09-07 (presumably from a test/synthetic CPU
alert injected while `modules/cpu_alerts.py` was being built and verified). No
real CPU threshold breach has occurred since, so the panel is currently, honestly
empty — this reflects normal fleet health (CPU never exceeded the warning/critical
threshold), not a collector defect. **This is a real, current gap in the
verification script's tolerance, not a functional regression**, and is flagged
for Phase 2 (Grafana reconciliation) to either add this panel to `ALLOW_EMPTY` or
otherwise handle legitimate quiescence. Not fixed in this phase (out of scope).

## 6. Grafana baseline (inventory only — not restructured)

- 4 dashboards, file-provisioned from
  `monitoring/grafana/provisioning/dashboards/json/*.json`, generated/checked by
  `monitoring/scripts/build_grafana_dashboards.py --check` (drift-proof against
  hand-editing).
- **39 panels** (confirmed by live `verify_grafana.py` output and by direct
  inspection of `modules/grafana.py`'s `EXPECTED` dict): `nmas-fleet-overview`=12,
  `nmas-streaming-telemetry`=11, `nmas-snmp-monitoring`=10 (includes the CPU
  Alerts panel above), `nmas-critical-syslog`=6.
- 8 template variables across the 4 dashboards; single datasource
  `nmas-influxdb` (InfluxDB, UID-pinned, no secrets embedded — enforced by a
  regex/substring check in `modules/grafana.py`).
- Provisioning mechanism: file provisioning + API reload
  (`/api/admin/provisioning/dashboards/reload`), not one-shot dashboard creation
  via `/api/dashboards/db`.
- Mapping to the future Django taxonomy (for Phase 2, not decided here):
  Resources ≈ fleet-overview + relevant snmp-monitoring panels; Link Events ≈
  snmp-monitoring traps + critical-syslog + streaming-telemetry state-change
  panels; Link State & Traffic ≈ streaming-telemetry. The 4-dashboard split does
  not map 1:1 onto the required 3-page taxonomy — this is Phase 2's job, not
  Phase 1's.

## 7. NetworkX topology — verified live this session

`verify_topology.py`: **19/19 checks PASS**. Live snapshot:
`nodes=15 edges=23` (`SERVICE_HEALTH`, `NETWORKX_GRAPH`, `ACTIVE_TOPOLOGY` all
agree), matching every prior report exactly. Graph source: `topology-data.json`
reconciled against a live, read-only `containerlab inspect` call
(`modules/topology.py`), overlaid with real InfluxDB health evidence
(`modules/topology_graph.py`). Service: `monitoring/scripts/topology_server.py`,
a stdlib `http.server.ThreadingHTTPServer` bound to `127.0.0.1:8050`, GET-only
endpoints (`/`, `/api/topology`, `/healthz`) — confirmed no mutation endpoint
exists. `REAL_NODE_R1`/`REAL_NODE_R3` checks confirm live cross-source agreement
(native cEOS gNMI and the Linux adapter respectively). `SAFE_DEMO` confirms the
"safe-link-down" demo mode only overlays a synthetic status in the JSON response
and never touches a real device. **Reuse recommendation**: a future Django Home
page should call the existing `/api/topology` endpoint directly — no new graph
engine is warranted or justified.

## 8. Configuration / template / rendering state

- 13 device `.cfg.j2` templates. Of these, only `R2.cfg.j2` and
  `R2_dhcp_server.cfg.j2` (both added by the NetBox migration) use real Jinja
  control flow/includes; the other 11 (`R1.cfg.j2`, `R3.cfg.j2`, `R4.cfg.j2`,
  `S1-S4.cfg.j2`, `mgmt_swt.cfg.j2`, etc.) are flat/hardcoded per-device text
  with little or no `{% %}` logic. **This is a finding, not something this
  phase changed or was asked to change** — the frozen Lab 1 templates were not
  touched.
- `modules/eos_render.py` provides the two reusable primitives
  (`render()`, `eos_commands()`) extracted from `master.py`; both are used
  identically by `master.py` and by the NetBox-only render/verify scripts.
- Config push: `master.py:push_eos()` (Netmiko) / `push_linux_router()`
  (Paramiko SSH + `bash -n` syntax check before execution) — unchanged.
- Idempotency: SNMP/syslog-cEOS/gNMI all use hash-of-desired-vs-actual compares
  before reconfiguring (`modules/snmp.py:126`, `modules/syslog.py:67`,
  `modules/gnmi.py:112`); topology service provisioning uses a "changed" flag
  gate. This phase did not need to (and did not) modify any of this.

## 9. Tests and verification — exact results, this session

| Command | Result |
|---|---|
| `.venv/bin/python -m unittest discover -s monitoring/tests -p 'test_*.py'` | **Ran 429 tests in 1.058s — OK** (exit 0) |
| `.venv/bin/python netbox/scripts/verify_netbox_model.py` | **392/392 checks passed.** |
| `.venv/bin/python netbox/scripts/populate_netbox.py --check` | **Summary: UNCHANGED=318** (dry-run only, no `--apply`) |
| `.venv/bin/python netbox/scripts/verify_reservations.py` | **35 rows checked, 0 reservation targets, Overall: READY** |
| `.venv/bin/python monitoring/tests/verify_snmp.py` | **PASS, all 10 devices + trap ingestion PASS** |
| `.venv/bin/python monitoring/tests/verify_syslog.py` | **PASS, all 10 devices** |
| `.venv/bin/python monitoring/tests/verify_grafana.py` | **FAIL** on one panel (see §5); all other dashboards/panels/variables/queries/data PASS |
| `bash monitoring/tests/verify_nmas_infrastructure.sh` | **SUMMARY: PASS=20 FAIL=0** |
| `.venv/bin/python monitoring/tests/verify_topology.py` | **19/19 PASS**, nodes=15 edges=23 |
| `.venv/bin/python monitoring/tests/verify_telemetry.py` | **PASS, all 10 devices**, gNMI+STREAM+INFLUX+NETCONF+NC-GET |

All counts exactly match or (Grafana) narrowly explain a divergence from the
last-reported baseline (429/429, 392/392 both reproduced exactly). The Python
test environment is `/home/student/Scripts/.venv` (NOT the bare system
`python3`, which lacks `pynetbox`/`pygnmi`/`ncclient` — this trips up a naive
`python3 script.py` invocation; future phases must use
`$NMAS_VENV/bin/python` or `monitoring/scripts/common.sh`'s convention).

## 10. Runtime / source-of-truth ownership matrix

| Data category | Owner | Notes |
|---|---|---|
| Frozen Lab 1 topology, links, routing, VLANs | **Git** (`.clab.yml`, `templates/*.cfg.j2`) | Immutable per `AGENTS.md` |
| DHCP pool boundaries/reservations (VLAN10/20/30) | **NetBox** (live) | `netbox/ipam.yml` is bootstrap-seed only |
| VLAN 200 management addressing | **Git** (static, in device templates) | Never NetBox-managed, never DHCP |
| Device/interface/VLAN/prefix inventory | **NetBox** (live) | Read via `modules/netbox_ipam.py` |
| Monitoring credentials (SNMPv3, InfluxDB token, Grafana admin) | **`monitoring/runtime/`** (gitignored, mode 600) | Not read or echoed this session |
| NetBox stack credentials | **`netbox/.env`** (gitignored) | Not read this session |
| Topology identity/state | **`topology-data.json`** + live `containerlab inspect` (read-only reconciliation) | Never rewritten by the topology service |
| Runtime telemetry/events | **InfluxDB** (`network-monitoring` bucket, 30-day retention) | Sole time-series store |
| Candidate/shadow DHCP renders | **`netbox/runtime/`** (gitignored) | Never applied to a device |

No duplicate active runtime source was found for any NetBox-owned category.

## 11. Reusable components for Labs 4/5

`modules/netbox_ipam.py`, `modules/ipam_context.py`, `modules/eos_render.py`
(render/rollout primitives); `modules/snmp.py`, `syslog.py`, `gnmi.py`,
`netconf.py`, `cpu_alerts.py`, `grafana.py`, `topology.py`, `topology_graph.py`
(all monitoring/visualization, all idempotent, all tested); the InfluxDB/Grafana/
NetBox docker-compose stacks; `monitoring/scripts/topology_server.py`'s
`/api/topology` read endpoint (for a future Home page); the existing
`verify_*.py` scripts as the pattern for any future health-check framework.

## 12. Known platform limitations (unchanged, re-confirmed)

- No native CPU SNMP threshold trap on cEOS or Ubuntu/FRR — collector-side
  alerting only (`collector_alert` measurement).
- R3/R4 gNMI/NETCONF is a repository-owned read-only lab adapter, not native
  FRR support; `Set()`/NETCONF config RPCs are explicitly unimplemented.
- cEOS-lab engineering-build `rsyslog.service` defect (documented previously);
  mitigated by a supplementary forwarder, unchanged.
- SR Linux is not part of the approved live baseline.

## 13. Actual remaining technical debt (genuine, current)

- **Flat/hardcoded device templates** (11 of 13) are the opposite of a
  "generic reusable template" model — a real future migration cost, not
  addressed in this phase.
- **`verify_grafana.py`'s CPU-alert panel check has no tolerance for
  legitimate alert-free quiescence** (§5) — a real, live-discovered gap in
  the verification script, not the collector itself.
- **Large uncommitted NetBox/IPAM diff** persists in the working tree by
  design; still a real orientation risk for future sessions until the human
  chooses to commit it.
- No `.github/` CI workflows exist yet (expected — out of scope for Labs 2/3
  and for this phase).

## 14. H1 → WebServer status — independently verified live, this session

**Not outstanding. Independently tested live and found fully functional.**
Ran `curl` HTTP GET from inside all four host containers (H1, H2, H3, H4) to the
WebServer's documented service addresses, both IPv4 (`172.30.50.10`, where
applicable — H4 is IPv4-less by design) and IPv6 (`2001:db8:3050::10`):

- H1 → WebServer: **HTTP 200**, body `Hello world`, IPv4 and IPv6, repeated 3×
  consistently (~20-30ms response time).
- H2, H3 → WebServer: **HTTP 200** IPv4 and IPv6.
- H4 → WebServer: **HTTP 200** IPv6 (no IPv4 configured on H4 by design).

This directly contradicts prior documentation (`AGENTS.md`, `GAP_ANALYSIS.md`,
`docs/FINAL_COMPLIANCE_AUDIT.md`, `docs/LABS_2_3_FINAL_REPORT.md`, and even the
newest untracked `docs/NETBOX_IPAM.md`), all of which describe this as an open,
pre-existing, application-layer issue. No code fix for this was found anywhere
in `git log` history, and this phase made no change that could have fixed it —
so the most defensible conclusion is that the original issue was either
environment/timing-dependent at the time it was documented, or has resolved
itself as a side effect of container uptime/state rather than an intentional
fix. **Per this phase's independent live verification, H1 → WebServer
connectivity is not outstanding technical debt and must not be reported as such
going forward**, without this being represented as a knowingly-applied fix.
The historical documentation above was intentionally NOT edited in this phase
(each is a dated, phase-scoped implementation report — see §15) — this
document is the current, authoritative statement.

## 15. Risks / constraints for future phases

- The **frozen-baseline-vs.-future-Device-Builder tension** flagged in the
  original planning pass still stands: any future phase capable of pushing
  structured configuration must not silently target R1-R5/S1-S4/`mgmt_swt`
  without explicit operator authorization, since `AGENTS.md` still freezes
  exactly the categories (routing/VLANs/BGP/NAT/DHCP/addressing) such a system
  would touch.
- H1→WebServer working *today* is not a guarantee it will remain so — it was
  never root-caused. Do not build anything that assumes it is permanently
  fixed at a root-cause level; treat it as "not currently reproducible," not
  "provably fixed."
- Use `/home/student/Scripts/.venv/bin/python` (or `$NMAS_VENV`) for any
  Python invocation touching NetBox/gNMI/NETCONF — bare `python3` lacks the
  required packages and fails misleadingly.
- The Grafana CPU-alert panel gap (§5/§13) should be resolved as part of
  Phase 2, not worked around ad hoc later.

## 16. Phase-2 readiness statement

All Phase 1 acceptance criteria are met: repository state reconstructed and
verified live; Git state documented accurately; NetBox/IPAM/DHCP ownership is
unambiguous and live-confirmed; VLAN 200 static-management behavior is
live-confirmed (0 reservation targets across all 9 devices); monitoring
architecture reconciled against live verifier output (one new, narrow,
non-blocking Grafana finding documented); Grafana and NetworkX baselines
documented without restructuring; configuration/render/push architecture
documented; all repository-supported safe verifiers re-run with results
recorded; no live network configuration was changed; no Containerlab lifecycle
command was executed; no Labs 4/5 functionality was implemented; this document
exists and is accurate; the working tree contains no unexplained changes.

**The repository is ready for Phase 2: Grafana monitoring taxonomy
reconciliation**, with the CPU-alert panel tolerance gap (§5) as an explicit
input to that phase's scope.
