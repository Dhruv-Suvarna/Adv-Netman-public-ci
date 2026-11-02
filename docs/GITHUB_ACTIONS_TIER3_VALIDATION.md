# Phase 16 — GitHub Actions Tier-3 change-effect, integration and regression validation

Tier 3 answers a question the two earlier tiers do not: **"what did this repository change touch, and did the checks that
protect those things still pass?"** It is a reusable, deterministic Python service; GitHub Actions is only one thin caller.

```
GitHub Actions ──▶ tier3.py ──▶ core.services.ci  ──▶ change collection ─▶ classification ─▶ impact expansion
   (checkout,         (launcher)  (pure Python,                                                   │
    install, run,                  no Django)              structured report ◀─ execution ◀─ check selection
    upload)
```

Validation only. Tier 3 never deploys, never touches a device, never writes NetBox / Git / topology, never executes a
Configlet, never advances a Change lifecycle, never runs Containerlab, and persists nothing (no model, no migration).

Contents: 1 Tiers compared · 2 Architecture · 3 Base/head semantics · 4 Change-effect model · 5 Impact expansion ·
6 Check selection · 7 Gates: offline vs lab-backed · 8 Result semantics and exit codes · 9 Report · 10 Local use ·
11 GitHub workflow · 12 Security · 13 Side-effect audit · 14 Tests · 15 Known limitations · 16 Phase-17 handoff.

## 1. Tier 1, Tier 2 and Tier 3

| | Tier 1 | Tier 2 | **Tier 3** |
|---|---|---|---|
| Question | is this *field* well-formed? | is this whole *Change's* accepted intent consistent with NetBox / topology / inventory? | did this *repository change* break a subsystem or contract it can reach? |
| Where | Device Builder commit (`field_validators`) | `change_validation_service` → `ChangeValidationRun` | `ci_service` → JSON report / job summary |
| Input | one field value | one `Change` in the database | a git comparison (base → head) |
| Persistence | draft/accepted field state | append-only run row | **none** (report artifact only) |
| Needs the lab? | no | reads NetBox/topology read-only | **no** (offline by default) |

Tier 3 is not a duplicate of Tier 2. It never validates, creates or replays a production `Change`, `ChangeValidationRun`,
`ChangePlan`, Configlet or `OperationalCheckRun`; it runs the *tests that protect* those subsystems (all faked) when their
code changes. `STALE` remains a Phase-13 *currency*, not a result, and Tier 3 does not touch it.

## 2. Architecture

Pure standard-library Python in `web/core/services/ci/` (plus the project's own `secret_policy`), importable **without
configuring Django** — the validator must still run when the code it validates is broken. Facade: `core/services/ci_service.py`.
Launcher: `tier3.py` at the repository root.

| Module | Concern |
|---|---|
| `constants.py` | vocabulary (modes, gates, statuses, results, exit codes), versions, output bounds |
| `gitio.py` | **the only git access**: read-only verb allowlist (`rev-parse merge-base diff ls-files ls-tree`), fixed argv, no shell, revision-name validation |
| `changes.py` | change detection: `ChangedFile` / `ChangeSet`, range strategies, added-line source for the hygiene scan |
| `github_context.py` | derive base/head/mode from GitHub event data (pure; reads one JSON file) |
| `rules.py` | **the declarative mapping**: subsystems, path rules, impact edges, check selections, lab verifiers |
| `classify.py` | path → subsystem(s); transitive impact expansion |
| `planner.py` | change set → structured validation plan with a reason for every selected check |
| `catalog.py` | **every command Tier 3 can run**, by id, with a fixed argv |
| `static_checks.py` | in-process syntax and hygiene checks (parse only, never execute) |
| `runner.py` | subprocess execution (allowlisted environment, bounded, redacted); with `gitio.py` the only `subprocess` user |
| `execute.py` | run the plan; map outcomes to truthful statuses |
| `report.py` | overall result, stable JSON, text and Markdown presentation |
| `service.py` / `cli.py` | orchestration (`run_tier3`, `plan_change_effect`) and the command line |

The intelligence is in Python and in **one** table module (`rules.py`). The workflow file holds none of it.

## 3. Base / head semantics

A comparison is always explicit: a *base* and a *head* revision (or, for the working tree, a base only).

| Strategy | Diff | Used for |
|---|---|---|
| `merge-base` | `merge-base(base, head)..head` | pull requests, local default: exactly what the branch introduces, unaffected by later movement of `base` |
| `direct` | `base..head` | pushes (`--no-merge-base`): exactly what the push introduced |
| `working-tree` | `base` ↔ working tree (staged + unstaged + untracked) | `--working-tree`: validate uncommitted work before committing |
| `all-tracked` | every tracked file at `head` treated as *added* | no usable base: new branch, unresolvable force-push, manual full run |

Renames are detected (git default similarity) and classify **both** the old and the new path; deletions classify by their old
path. `HEAD^` is never assumed. Resolution from GitHub events (`--from-github`, done in Python, not YAML):

| Event | Base → head | Mode |
|---|---|---|
| `pull_request` | PR base SHA → PR head SHA, `merge-base` | targeted |
| `push` | `before` → `after`, `direct` | **full on the default branch**, targeted elsewhere; all-zero `before` (new branch) → no base → full |
| `workflow_dispatch` | `inputs.base` → checked-out SHA if given, else **no base** | targeted with a base (or `inputs.mode=full`); **full without a base** |
| anything else | none | full |

If a CI-derived base cannot be used (force-push, shallow checkout), Tier 3 **broadens to full** and reports a `BASE_FALLBACK`
warning rather than skipping validation. An explicit `--base` that does not resolve is a usage error (exit 2).

## 4. Change-effect model

Every changed path is classified against the ordered rules in `rules.PATH_RULES`. A path may belong to several subsystems
(`netbox/scripts/render_r2_dhcp.py` is `netbox_ipam` **and** `dhcp`). Subsystems: `models_schema`, `migrations`, `shared_core`,
`django_project`, `dependencies`, `control_plane`, `device_builder`, `candidate_rendering`, `platform_drivers`, `validation`,
`planning`, `health`, `execution` (Phase 17), `netbox_ipam`, `dhcp`, `nsot`, `monitoring`, `topology`, `notifications`, `django_views_api`,
`ui_presentation`, `lab_config` (frozen Lab 1), `core_automation`, `dev_tooling` (`tools/**`, the phase-integration helper), `challenge_console` (`challenge_console/**`, the standalone read-only Tkinter console and its launcher), `lab_verifiers`, the test subsystems (`tests_django`,
`tests_support`, `tests_monitoring`), `ci_engine`, `ci_workflow`, `documentation`, `repo_meta`, `runtime_artifacts`.

**Unknown paths never mean "nothing to test."** A path matching no rule is `unclassified`: the plan becomes `full` and a
`UNCLASSIFIED_PATH` warning asks for a rule. A repository-wide contract test fails if any file in the checkout is unclassified,
so the fallback stays an exception.

Path-level warnings (never blocking, never emitted for a synthetic no-base comparison): `FROZEN_LAB_PATH_CHANGED` (a frozen Lab-1
template / inventory / `.clab.yml` changed — needs explicit authorization), `RUNTIME_ARTIFACT_CHANGED` (a runtime log or cache
is in the diff), `MIGRATION_HISTORY_MODIFIED` (an existing migration was edited, deleted or renamed away; migrations are append-only).

## 5. Impact expansion

`rules.IMPACT_EDGES` is a **curated** consumer map (not a source-level import graph): if A changes, B consumes A's output, so B's
regression surface is also required. Expansion is transitive and the shortest chain is reported with the reason for its last hop.

```
models_schema ─▶ control_plane, validation, planning, health, notifications, django_views_api      migrations ─▶ models_schema
platform_drivers ─▶ candidate_rendering, validation, planning        candidate_rendering ─▶ device_builder, planning
control_plane ─▶ device_builder, validation                          device_builder ─▶ validation
validation ─▶ planning ─▶ health                                     netbox_ipam ─▶ validation, nsot, dhcp
dhcp ─▶ validation, health                                           topology ─▶ validation, nsot, health
monitoring ─▶ health                                                 lab_config ─▶ validation, health, topology
```

`shared_core`, `django_project`, `dependencies` and `tests_support` are **foundational**: they imply the whole Django surface
(one `core` run) but do **not** propagate onward into monitoring or lab verifiers.

## 6. Check selection

Each subsystem requires (`rules.SELECTIONS`): Django test modules under `core.tests`, the whole `core` suite (broad gate), the
monitoring suite, the Grafana drift check and/or lab verifiers. Every selected check carries its reasons, e.g.
`Tier-2 validation engine changed [web/core/services/validation/engine.py]` or
`plan builder / Configlet code changed … affected via validation -> planning: plan eligibility and pinning derive from the validation run`.

| Always (baseline, any change) | Gate |
|---|---|
| `static.hygiene` — credential *formats*, conflict markers, credential-store file names in **added** content | static |
| `static.syntax` — Python / JSON / YAML / Jinja (`.j2`) / shell (`bash -n`) parsing of changed files (all tracked files in full mode) | static |
| `django.check` — `manage.py check` | static |
| `django.migrations` — `makemigrations --check --dry-run` | static |

| Conditional | Gate |
|---|---|
| `django.tests` — the selected `core.tests.test_*` modules, or `core` when a foundational subsystem changed / full | repository |
| `monitoring.unit` — `unittest discover -s monitoring/tests` (446 tests, ~2 s) | repository |
| `grafana.drift` — `build_grafana_dashboards.py --check` (generated JSON must match) | repository |
| `lab.*` — the seven real verifiers (Grafana, topology, NetBox model, NetBox seed drift `--check`, reservations, DHCP, NMAS) | **lab** |

Examples: docs-only → baseline only (plus the one test module that reads a given document, for the few documents tests assert on); `web/core/models.py` or a new
migration → baseline + full `core`; validation engine → the Phase-13 modules + planning and health consumers + contracts;
platform renderer → renderer, Device Builder, validation and planning consumers; a changed test module → that module.
A changed test module is itself always selected. Selection is deduplicated, sorted and independent of input order; the plan
carries a `plan_hash` (over *what* is validated, not over SHAs).

`--mode full` (or an unclassified path / no base) requires the whole repository regression surface: baseline + full `core` +
monitoring suite + Grafana drift, syntax over every tracked file.

## 7. Gates: offline vs lab-backed

| Gate | Needs | Default | Meaning |
|---|---|---|---|
| **static** | Python + repo | runs | syntax, hygiene, Django check, migration drift |
| **repository** | Python + project dependencies | runs | unit / contract / view-boundary suites — **all external systems faked** |
| **lab** | the real lab, on the operator's machine | **not run** | the existing external verifiers, only with `--lab` |

The offline gates never receive the caller's environment: subprocesses get a fixed allowlist (`PATH HOME LANG LC_* TZ TMPDIR
VIRTUAL_ENV`, and `DISPLAY XAUTHORITY` -- an X display name and cookie-file path, no secret value -- for the Tk console tests) plus `DJANGO_DEBUG=true` (the settings' own fake development key) and `PYTHONDONTWRITEBYTECODE=1`, so no token,
webhook, credential or lab address can reach a test process. **Lab verifiers that were not run are reported `NOT_RUN` and the
coverage block says `lab: NOT_RUN` — absence is never converted into PASS.** With `--lab`, the selected verifiers run through
their existing entry points with the operator's environment (they need docker / NetBox / monitoring runtime context); a verifier
that fails is `FAIL`, one that cannot start or times out is `ERROR` → `INCOMPLETE`. The report cannot tell an unreachable lab from
a broken one — the redacted output tail shows which. Unit-test simulated success (fakes) and real-verifier success are different
evidence; only `--lab` produces the latter. Note `lab.nmas` (`verify_nmas_infrastructure.sh`) writes one **synthetic InfluxDB
point**, as it always has; every other lab verifier is read-only (`populate_netbox.py --check` is the dry run).

There is deliberately **no self-hosted lab-runner job** in the workflow: running untrusted pull-request code on a machine with lab
access is a security risk, and the lab gate needs no CI wiring to be useful (`python tier3.py --mode full --lab` on the lab host).

## 8. Result semantics and exit codes

Per check: `PASS`, `WARN`, `FAIL`, `ERROR` (could not be executed reliably: crash, timeout, tool missing, **exit 0 but zero tests ran**),
`NOT_RUN` (policy; optional only). Overall (project vocabulary):

| Result | Rule | Exit |
|---|---|---|
| `PASS` | every required check passed, no warnings | 0 |
| `PASS_WITH_WARNINGS` | passed; a check `WARN` or a plan warning exists (non-blocking) | 0 |
| `FAIL` | a required check failed (wins over `INCOMPLETE`) | 1 |
| `INCOMPLETE` | a required check could not be executed; never a pass | 3 |
| *(usage)* | bad arguments, unresolvable explicit revision, not a git repository | 2 |

Unknown, not-executed, missing evidence and a tool crash are never `PASS`. The GitHub job fails on 1, 2 and 3.

## 9. Report

`--json PATH` writes the machine-readable report (schema v1, engine `16.0.0`), bounded (<= 512 KiB, tool output <= 40 lines /
4 KB per check, redacted). Fields: `result`, `exit_code`, `blocking_checks`, `provenance` (`base_sha`, `compare_from_sha`, `head_sha`,
`strategy`, event / ref / repository / run id / checkout SHA, Python version, engine version), `coverage` per gate, `summary`
counts, `changed_files` (path, status, old path, subsystems), `affected_subsystems` (direct + impacted with chains), `mode`
(requested, effective, reasons), `plan` (hash, required / optional checks with reasons, per-module test selection), `warnings`,
`checks` (status, summary, counts, findings, duration, output tail). `Tier3Report.semantic_digest()` excludes durations and tool
output, so equal inputs give equal digests. Findings carry a path, line and stable code — **never file content or a matched value**.
`--summary-md PATH` **appends** a Markdown job summary (safe for a shared `$GITHUB_STEP_SUMMARY`).

## 10. Local use

Run with the project interpreter (`/home/student/Scripts/.venv/bin/python`); no Django settings, database or network needed.

```bash
python tier3.py --base origin/main                      # targeted, merge-base(origin/main, HEAD)..HEAD
python tier3.py --base <sha> --head <sha>               # explicit comparison
python tier3.py --base HEAD --working-tree              # uncommitted + untracked work, before committing
python tier3.py --base origin/main --plan-only          # print the change-effect plan; execute nothing
python tier3.py --mode full                             # whole regression surface (~1 min)
python tier3.py --mode full --lab                       # ... plus the real lab verifiers (lab-connected host only)
python tier3.py --base <sha> --json out.json --format json
```

`echo $?` gives the exit status of section 8. `--no-merge-base` diffs `base..head` directly. The same logic is callable from Python:
`core.services.ci_service.run_tier3(Tier3Request(repo, base, head))`.

## 11. GitHub workflow

`.github/workflows/tier3-validation.yml` — about 60 lines: checkout (`fetch-depth: 0`, `persist-credentials: false`), setup-python 3.12
with pip cache, install the three requirements files, a virtual display (Xvfb; installed only if missing, and the step fails loudly if
Tk cannot open it), **one** invocation `xvfb-run -a python tier3.py --from-github --json tier3-report.json
--summary-md "$GITHUB_STEP_SUMMARY"`, upload `tier3-report.json` (14 days). Events: `pull_request`, `push` to `main`,
`workflow_dispatch` (inputs `base`, `mode`). No schedule, no deployment trigger. Workflow-level `permissions: contents: read`; nothing
else. **No secrets are referenced**, no `pull_request_target`, no self-hosted runner, and no event data is interpolated into a shell:
Python reads `GITHUB_EVENT_PATH` itself and validates every revision. A PR gets a targeted run; a push to `main` and a manual run
without a base get the deliberate full regression (post-merge safety net, not a duplicate of the PR run). Runs are cancelled only for
superseded PR pushes. `Run_Logs.log` and `logs/*.log` are never uploaded.

## 12. Security

* Least privilege (`contents: read`); untrusted PR code receives no secret because none exists in the workflow.
* Offline subprocesses get an allowlisted environment (section 7); git gets a minimal one (`GIT_OPTIONAL_LOCKS=0`, no credentials).
* Only catalogue commands run; the sole variable input is a Django test-module label validated as `core` or `core.tests.test_<[a-z0-9_]+>`.
* Hygiene scans **added lines** for high-confidence credential formats (private-key blocks, Slack webhook URLs / tokens, GitHub tokens,
  AWS key ids), merge-conflict markers and credential-store file names (`.env` except `.env.example`, `*.pem`, `*.key`, `id_*`,
  `monitoring/runtime/*` except `.gitkeep`). It is deliberately **not** a generic `password =` scan: historical lab credentials in old
  source are out of scope and Tier 3 neither spreads nor re-flags them. It reports a name and a location, never the value.
* Captured tool output is redacted with the project-wide `secret_policy` key denylist (`*_ref` references allowed) and credential
  formats, then bounded. Report keys are asserted to satisfy the same denylist.

## 13. Side-effect audit

Contract tests (`test_tier3_execution`) prove: a full run with every check faked leaves HEAD, refs, index/working-tree status and file
contents identical; only allowlisted read-only git verbs are used (`add commit reset clean stash checkout push fetch restore rm config gc`
are refused); only catalogue argv is executed; the package imports no device / NetBox / HTTP / Django / socket library, uses `subprocess`
only in `gitio.py` and `runner.py`, never `shell=True`, writes to disk only from the CLI's report artifacts, and contains no
deployment / rollback / Golden text. Tier 3 has no Phase-17 execution path, no Phase-18 raw-CLI surface and no Phase-19/20 bundle or soak logic.

## 14. Tests

Three subsystem-named modules, 39 methods (matrices with labelled `subTest`): `test_tier3_changes` (12: range semantics, revision safety,
read-only git, GitHub event resolution, base fallback), `test_tier3_selection` (15: classification matrix, drift guard over every repository
file, rule-table consistency, impact matrix, selection / full / fallback / determinism / warnings), `test_tier3_execution` (12: status
mapping, aggregation, static checks, hygiene, offline environment + catalogue, report / redaction / digest, lab gate, CLI exit codes,
GitHub launcher, side-effect and boundary contracts, workflow contract). Shared fixtures: `helpers/tier3.py` (a temporary git repository and
a scriptable command runner). No test starts Django, the monitoring suite, a verifier or a device connection. The suite passes with outbound
sockets blocked and under a scrubbed environment (section 15 notes what that does and does not prove).

## 15. Known limitations

* The impact map is **curated**, not derived from imports; a new cross-subsystem dependency needs an edge in `rules.py`. The
  classification drift test catches unclassified files, not missing edges.
* Test selection is file-level: a module's *content* dependencies beyond the table are not analysed. Foundational changes and unknown
  paths therefore broaden to the whole `core` suite (the safety net), and `--mode full` is always available.
* The existing Django and monitoring suites are hermetic in outcome but **not in behavior**: they attempt loopback connections to
  `127.0.0.1:3000` (Grafana), `:8050` (topology service) and `:8000` and tolerate the failure. Verified by running both suites with all
  outbound TCP blocked (770 and 446 pass). On a developer machine those attempts may reach a real local service; Tier 3 does not add
  network isolation beyond the environment allowlist.
* `manage.py check` runs in `DJANGO_DEBUG=true` (not `check --deploy`): production-settings hardening is not exercised.
* Fresh checkouts create the ignored `web/db.sqlite3` (a side effect of `makemigrations --check` opening the database).
* GitHub actions are pinned by major version tag (`@v4`, `@v5`), not by commit SHA; pinning by SHA is a recommended hardening.
* The lab gate cannot distinguish "lab unreachable" from "verifier failed" beyond exit status and the redacted output tail; `lab.nmas`
  writes one synthetic InfluxDB point (existing verifier behavior).
* Hygiene is a lightweight format scan, not a replacement for a dedicated secret scanner; history is not scanned.
* Rename detection uses git's default similarity; a heavily edited rename is reported as delete + add (both paths still classify).
* Phase-15 limitations (Fleet Quick has no routing telemetry, some postcheck families are UNKNOWN, …) are unchanged and not addressed here.

## 16. Phase-17 handoff

Tier 3 is ready as the pre-deployment repository gate. Phase 17 (structured deployment, Complete / Partial-UAT execution, rollback
handling) should run `python tier3.py` in CI for its own source, keep device-facing checks behind the explicit runtime verifiers, and add
`rules.py` entries (subsystems, edges, selections, and an `execution` `PathRule`) for the code it introduces so the classification drift
test keeps passing. Nothing in Phase 16 executes, schedules or approves a deployment.

## Lab 7 test governance checks (engine 16.1.0)

Tier-3 also runs the Lab 7 unit-test / code-coverage governance (full description: `docs/UNIT_TEST_AND_CODE_COVERAGE.md`):

| Check | Gate | When |
|---|---|---|
| `governance.catalog` | static | every change -- `manage.py nmas_test_governance validate-catalog --ci` (artifact classification, `@case` declarations, references, baseline locks) |
| `quality.pylint` | static | targeted: changed deployed Python files; full: every deployed Python artifact (`.pylintrc`; critical messages or growth above `baseline.json` fail) |
| `django.tests`, `monitoring.unit` | repository | full mode runs them **traced (direct-invocation tracer) under coverage.py**: one run yields the regression result and the evidence |
| `governance.report` | repository | full mode -- combines coverage, builds `tier3-governance/test-governance-report.json`, validates its schema and evaluates the closure gate |

The workflow uploads the `test-governance` artifact (report + `coverage.xml`); NMAS's Unit Test Matrix / Code Coverage
pages accept it through **Refresh** only after verifying its schema, hash, run id and commit. The coverage toolchain is
pinned in `requirements-ci.txt` (installed by the workflow only, never on the web server). Targeted pull-request runs
never claim global coverage; full evidence comes from push-to-`main` and manual full runs.
