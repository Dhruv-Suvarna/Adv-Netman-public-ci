# Unit Testing and Code Coverage (Lab 7) -- NMAS test governance

NMAS already had thousands of tests. Lab 7 turns them into a **systematic, auditable** framework that answers two
questions from repository-owned data, in the NMAS website, without anyone reading test source, CLI output or coverage.py
HTML:

1. **Which** automation tools / modules / functions / platform-feature cells are covered by unit tests, and by **which** tests?
2. **How much** of each piece of automation code is covered -- explicit positive cases, explicit negative cases, functions
   explicitly tested ("3 of 6 functions tested"), statements and branches?

The measured numbers are generated, never typed: see [`docs/evidence/lab7/RESULTS.md`](evidence/lab7/RESULTS.md)
(final, with the baseline column) and [`docs/evidence/lab7/BASELINE.md`](evidence/lab7/BASELINE.md) (the gap
assessment made before any Lab 7 test was written). The baseline report is bundled as
`docs/evidence/lab7/baseline-report.json.gz` and re-renders with
`manage.py nmas_test_governance summarize ../docs/evidence/lab7/baseline-report.json.gz --gap`. Its one failing test
(`test_tier3_selection ... test_every_repository_file_has_a_classification_rule`) was caused by a Lab 7 fixture file
created while the baseline run was in progress, before its classification rule was added; it is not a pre-existing
defect and passes in the final run.

| | |
|---|---|
| Code | `web/core/services/test_governance/` (one canonical service), `web/core/management/commands/nmas_test_governance.py` |
| Pages | Automation -> **Unit Test Matrix** (`/automation/quality/unit-tests/`), Automation -> **Code Coverage** (`/automation/quality/coverage/`) |
| Tier-3 | `.github/workflows/tier3-validation.yml` -> `tier3.py` (checks `governance.catalog`, `quality.pylint`, traced `django.tests` / `monitoring.unit`, `governance.report`) |
| Configuration | `.coveragerc`, `.pylintrc`, `requirements-ci.txt`, `web/core/services/test_governance/policy.yml`, `.../baseline.json` |
| Evidence | `docs/evidence/lab7/test-governance-report.json` (bundled, hash-verified), Tier-3 artifact `test-governance` |

---

## 1. Lab 7 requirement mapping

| Lab 7 requirement | Where it is met |
|---|---|
| Unit tests for **all** network-automation code (IP validation, IP connectivity, file existence, template from YAML ...) | Every deployed artifact is discovered and gets required cases (section 3-5). The Lab 7 examples are mapped to the real NMAS functions in `policy.yml` (`assignment_examples`) and shown on the Unit Test Matrix ("Lab 7 assignment examples"): `field_validators.validate_cidr / validate_ip_host`, `health/live.norm_cidr / validate_ping_destination` (IP validation); `health/live.parse_ping_output`, `health/connectivity.ping_targets / run_connectivity` (IP connectivity); `cpu_alerts.load_policy`, `device_credentials.FileSecretProvider.current`, `topology.load_config` (file / artifact existence); `eos_render.render`, `feature_template_renderer.render_descriptors`, `master.load_inventory` (template from YAML); `health/live.parse_eos_ospf / parse_eos_bgp / parse_eos_rip_neighbors / parse_frr_bgp` (neighbor status); `cpu_alerts.classify / evaluate_cpu_threshold` (CPU status); `candidate_renderer.render`, `PlatformDriver.render_candidate`, `ipam_context.render_candidate_config` (configuration / routing generation). |
| Integrate into CI/CD (Jenkins -> here GitHub Actions / Tier-3) | Section 9: the existing Tier-3 workflow runs the catalog gate and Pylint on every change, and on push to `main` / manual full runs the suites run traced under coverage.py and the closure gate evaluates the report. |
| Appropriate documentation | This document, `RESULTS.md`, `BASELINE.md`, inline module docstrings. |
| Coverage tool: **which** modules are covered | Unit Test Matrix: one row per deployed artifact with its Negative and Positive cases (expandable, each case with its exact test id and evidence basis). |
| Coverage tool: **how much** of each module ("3 of 6 functions tested -> ~50%") | Per artifact: `Functions x / y`, statements %, branches %; per symbol on the artifact detail page; per capability cell and per control-plane group on the Code Coverage page. |

---

## 2. Design in one picture

```
 repository (Git)                      Tier-3 (GitHub Actions) / nmas_test_governance run           NMAS website (read-only)
 ─────────────────                     ─────────────────────────────────────────────────           ────────────────────────
 policy.yml ─┐                         django.tests  ── traced (sys.monitoring) + coverage.py ─┐
 ledger ─────┼─> inventory ─> symbols  monitoring.unit── traced + coverage.py ────────────────┤
 code ───────┘   (artifacts)  (AST,    quality.pylint ── .pylintrc json2 ─────────────────────┤
                              disposition)                                                     v
                     │                 governance.report: catalog(required cases) x evidence ──> test-governance-report.json
                     └──────────────────────────────────────────────> closure gate (baseline.json)   (schema + sha256)
                                                                                                    │ artifact / bundled copy
                                                                                                    v
                                                                       evidence store (accept: schema + hash) ─> pages
```

Heavy work (tests, coverage, Pylint, AST) happens only in Tier-3 or the management command. A page view reads one
accepted, verified report (cached per file version) and computes nothing else; the only GitHub call is the explicit
**Refresh** button.

---

## 3. Deployed artifact inventory (`inventory.py`)

* **Discovery, not a hand-written list**: `git ls-files --cached --others --exclude-standard` -- tracked plus
  untracked-not-ignored files, so a brand-new module is seen before it is committed.
* **Type by extension**: `PY`, `JINJA`, `YAML`, `JSON`, `SH`, `SYSTEMD` (`.service/.timer/.socket`), `CONF`, `DOCKER`.
* **Exclusions with reasons** (`policy.yml exclude`): documentation and evidence, test code, logs, caches, runtime
  state and the secret store, collectstatic output, the website presentation templates / static assets, the
  disposable proof-lab topology.
* **Stable artifact id** = `<TYPE>:<repository path>`, e.g. `PY:web/core/services/health/live.py`,
  `JINJA:templates/features/ceos/routing_ospfv2.j2`, `YAML:monitoring/config/cpu_threshold_policy.yml`.
* **Classification** (one canonical place each, nothing duplicated):
  * subsystem -- the existing Tier-3 path table (`ci/rules.py` via `ci/classify.py`); a path no rule matches is an
    `UNCLASSIFIED_ARTIFACT` catalog error, so new code cannot appear unclassified;
  * generic group (Health, Validation, Execution, Config Import, NetBox, Credentials, Monitoring, Maintenance, CI,
    Provisioning, Removal/lifecycle, Website permissions, Workers/console ...) -- `policy.yml generic_groups`;
  * deploy / runtime role -- `inventory.ROLE_RULES`;
  * platform / feature -- `policy.yml platform_dirs`, `platform_artifacts`, `template_features`;
  * **current scope** -- `CURRENT`, `NOT_CURRENT_SCOPE` (a platform-specific artifact whose platform has no SUPPORTED
    capability cell, a feature template whose cells are all UNSUPPORTED, or a template no deployed producer references,
    e.g. `templates/R3_backup.cfg.j2`) or `EXEMPT` (migrations, live lab verifiers, generated Grafana dashboards,
    container recipes -- each with its reason).
* **Source fingerprint** = sha256 over every deployed artifact + every test file + policy / baseline / ledger /
  `.pylintrc` / `.coveragerc`: the identity of the evidence inputs (used for CURRENT / STALE, section 11).

## 4. Function / symbol inventory and dispositions (`symbols.py`)

Every function and method of every deployed Python artifact is inventoried from the AST (qualified name, line range,
public / private, parameters). Its **disposition** -- what it requires -- is decided by fixed rules, never by whether a
test exists:

| Rule | Symbol | Disposition |
|---|---|---|
| R1 | declared in `policy.yml symbol_exemptions` (with reason) | EXEMPT |
| R2 | private helper `_name` | INTERNAL -- proven through its public boundary; its own line / branch coverage is shown |
| R3 | presentation / protocol dunder (`__str__`, `__eq__` ...) | EXEMPT |
| R4 | abstract / interface declaration (`pass`, `...`, `NotImplementedError`, `@abstractmethod`) | EXEMPT |
| R5 | trivial initializer (only stores its arguments) | EXEMPT |
| R6 | pure accessor (no arguments, single `return` of a name / attribute / constant) | EXEMPT |
| R7 | framework declaration hook (`add_arguments`, `ready`) | POSITIVE |
| R8 | public callable **with inputs** (an exposed boundary) | POSITIVE **and** NEGATIVE |
| R9 | public callable without inputs | POSITIVE |
| R10 | public callable whose body never reads its parameters (added in the closure sprint, commit 36fa2e8) | POSITIVE only -- no input can change its behaviour, so no negative case can exist |

R10 is a **denominator rule change** and is reported as one (section 6.4): it removed the NEGATIVE requirement from
callables that ignore their inputs (e.g. a read-only admin `has_change_permission` that always returns False, an
immutable model's `delete` that always raises). It is computed from the AST, never from whether a test exists, and it
never removes the POSITIVE requirement. Its one **counting change** (`catalog.py`): for an R10 symbol a direct test of
either intent proves the single required case, because a function that cannot read its input has one behaviour.
No `symbol_exemptions` entry was added in the sprint.

Exemptions are displayed as EXEMPT (never TESTED, never MISSING) and excluded from the denominator. Nested functions are
part of their enclosing function.

## 5. The required test catalog (`catalog.py`) -- why "X / Y" is real

**Y comes from the code and the capability matrix; X counts a case only when its test RAN in the evidence run and
PASSED.** Five written tests can therefore never display as "5 / 5" when ten cases are required.

| Case id | Required for |
|---|---|
| `SYM:<path>::<qualname>:POSITIVE` / `:NEGATIVE` | every symbol whose disposition requires it |
| `TPL:<path>:RENDER:POSITIVE` | every CURRENT network Jinja template |
| `TPL:<path>:STRICT_UNDEFINED:NEGATIVE` | every CURRENT template that references a variable (a static template is EXEMPT: nothing can be undefined) |
| `CFG:<path>:LOAD:POSITIVE` / `:MALFORMED:NEGATIVE` | every CURRENT YAML / JSON artifact (MALFORMED is EXEMPT for files only an external tool reads -- docker compose, Grafana, GitHub Actions, containerlab) |
| `EXE:<path>:STATIC:POSITIVE` | every CURRENT shell script, systemd unit and service configuration |
| `CELL:<platform>:<feature>:<stage>:POSITIVE` / `:NEGATIVE` | every lifecycle stage the capability evidence says is implemented, for every SUPPORTED platform x feature cell |
| any `@case(...)` id | an explicit declaration on a test (locked by the baseline once declared) |

### 5.1 How a test proves a symbol case: the direct-invocation tracer (`tracer.py`)

"A line executed" is not "the behavior was tested". During the evidence run a Python 3.12 `sys.monitoring` tracer
(its own tool id, so it coexists with coverage.py) records a link `(test, symbol)` **only when the symbol was invoked
from the test method's own dynamic extent with no other deployed code in between** (library frames such as the Django
test client, `mock` and unittest are transparent; so are request middleware and closures). Calls made from `setUp` /
`setUpTestData` are not links (fixture construction is not a test). Per link it counts direct starts and direct
exception unwinds, and the intent of the active test / sub-test:

| Basis (shown next to every test in the UI) | Counts as |
|---|---|
| `DECLARED` -- an `@case` on the test names the symbol | the declared polarity |
| `DIRECT_RETURN` -- the direct call returned in a positive / neutral context | POSITIVE |
| `DIRECT_RAISE` -- the direct call raised, and the test passed | NEGATIVE |
| `DIRECT_REFUSAL` -- the direct call returned inside a test / `subTest` whose stated intent is a refusal / invalid input | NEGATIVE |

The tracer is behavior-neutral (proven by `TracerTests` and by the full suite passing identically traced and untraced);
it never returns `DISABLE` from the global `PY_UNWIND` event (doing so would change the exception the code under test sees
-- caught while building it).

### 5.2 Declared cases (`cases.py`)

```python
from core.services.test_governance.cases import NEGATIVE, case

@case("F1_DESCRIPTION_LINE_BREAK_REFUSED_AT_TIER1", target="web/core/services/field_validators.py::validate_interface_description",
      polarity=NEGATIVE, condition="a description with CR / LF / NUL", expected="INVALID at Tier-1",
      requirement="Lab 7 finding F1")
def test_control_characters_are_refused(self): ...
```

The decorator only attaches metadata. Fields: case id, target artifact / symbol, polarity, condition, expected result,
requirement / risk, platform, feature, stage. The static validator (`catalog_check.py`, Tier-3 `governance.catalog`)
checks every declaration: unique id, real artifact, real symbol, real capability cell, real generated requirement; the
baseline locks declared ids, so deleting the proving test makes the case `BROKEN_REFERENCE`.

### 5.3 Case states

`PASS` (test exists, ran, passed) · `FAIL` (its test failed / errored) · `MISSING` (nothing proves it; shown with the
reason, e.g. *KNOWN DEFECT ... expected failure* or *skipped in the evidence run*) · `BROKEN_REFERENCE` · `EXEMPT` (with
reason) · `NOT_CURRENT_SCOPE`.

## 6. Positive and negative tests written in this phase

Generated suites (methods generated from the inventory / ledger, so new artifacts get cases automatically):

| Module | What it proves |
|---|---|
| `test_tg_templates.py` | every CURRENT template rendered through its **real producer** (Lab-1 configs via `eos_render.render` + tracked inventory, monitoring templates via `modules.snmp/syslog/gnmi.render`, DHCP templates, feature templates via the platform drivers for every SUPPORTED cell); output equals a reviewed golden digest and is deterministic; each referenced variable removed in turn raises `UndefinedError` (a deliberately optional variable must fail on malformed structure instead) |
| `test_tg_artifacts.py` | every YAML / JSON artifact through its real loader (positive) and a malformed copy refused by that loader (negative); every shell script (`bash -n`, shebang, strict mode), systemd unit and service configuration statically verified -- nothing on the host is modified |
| `test_tg_cells.py` | 46 SUPPORTED cells x implemented stages x {POSITIVE, NEGATIVE} through the real Phase-4 probe paths in rolled-back transactions with fake devices (table in the module docstring) |
| `test_tg_health_parsers.py` | every `health/live.py parse_*` parser of untrusted device output: malformed / wrong-shaped output never crashes a device read (UNAVAILABLE `PARSE_ERROR` group) and text parsers produce no phantom facts |
| `test_tg_field_validators.py` | every Tier-1 field validator: exact positive; wrong JSON types, boundary values and malformed text refused, never an exception |
| `test_tg_automation_modules.py` | Labs 1-3 automation (`master.py`, `cpu_alerts`, `topology_graph`, `device_credentials`, `eos_render`, `grafana`): exact positives, fail-closed negatives, subprocess faked |
| `test_tg_view_route_sweep.py` | every argument-taking `core:` route (unknown object ids, GET and POST, as operator and anonymous): refused or answered, never 5xx, and no process / socket / HTTP call for an unknown object (local read-only `git` allowed; the one documented source lookup is blocked and must degrade) |
| `test_tg_linux_executor_units.py` | Ubuntu/FRR executor device-read, digest and NAT helpers, `connect`, `compensate`: every read fails closed (`PREVIOUS_STATE_UNAVAILABLE`) on timeout / non-zero exit / unparsable output; `subprocess.run` is always faked |
| `test_tg_execution_persistence_units.py` | execution history: secret-shaped keys refused before storage (run left RUNNING), unknown run ids resolve to nothing, a failing notifier never changes the committed run, secret values redacted from the JSON download |
| `test_tg_configlet_factory_units.py` | planning Configlet factory: fixed-code refusals (AUTO value missing, unknown node type, missing device, unpinned Raw node, undeclared priority); a line break in a description never becomes a line |
| `test_tg_identity_mfa_units.py` | website TOTP MFA: enrollment / verification / replay / wrong-length / key-changed / reset, positive and negative |
| `test_tg_template_filters.py` | every registered template filter: exact known values; unknown / wrong-type / hostile values fall back, never green |
| `test_tg_governance_units.py` | every public helper of the governance package and every management subcommand, called directly |
| `test_test_governance*.py` | the governance framework itself (section 14) |

**Current-scope closure sprint** (82 new `test_tg_*` modules after the first closure at `e398cd2`; every test calls the
deployed function directly, asserts exact values, and fakes every device, NetBox, SSH, Docker, socket and subprocess
boundary). They are listed in the order of the sprint's risk priority:

| Priority / area | Modules (`web/core/tests/` unless noted) | What they prove |
|---|---|---|
| 1 Device write | `test_tg_execution_closure`, `test_tg_raw_closure`, `test_tg_automation_scripts_closure` (`master.py` / `hostserv.py` / `address_report.py` with fake SSH / netmiko / Docker), `test_tg_maintenance_executor_closure` | a refused or failed push never reports success; a script syntax failure never executes; the password goes only on stdin, never on argv / logs |
| 2 Rollback | `test_tg_execution_closure` (compensation), `test_tg_route_shield_*_closure` (fake kernel), `test_tg_workbench_removal_closure` | compensation is planned from captured state; an unreadable prior state refuses instead of guessing |
| 3 Auth / MFA / RBAC | `test_tg_security_closure`, `test_tg_identity_mfa_units` (extended), `test_tg_credentials_*_closure` (7 modules), `test_tg_web_helpers_closure` (MFA admin reset) | wrong codes / replays / unprivileged users refused; no secret value in any output |
| 4 Validation | `test_tg_validators_closure`, `test_tg_validation_context_closure`, `test_tg_validation_service_closure`, `test_tg_config_validation_closure` | exact verdicts; missing evidence BLOCKS (F3) |
| 5 Config import | `test_tg_config_import_closure`, `test_tg_srlinux_model_closure` | parser positives and malformed input refusals |
| 6 Rendering | `test_tg_platform_drivers_closure`, `test_tg_routing_interface_intent_closure`, `test_tg_service_policy_closure`, `test_tg_config_template_*_closure` (5), `test_tg_workbench_semantics_closure`, `test_tg_configuration_facade_closure` | exact rendered lines; capability-gated contributions withheld (F2) |
| 7 Planning | `test_tg_planning_closure` | plan steps and refusals with fixed codes |
| 8 Locking / lifecycle | `test_tg_model_rows_closure` (immutable rows, append-only evidence), `test_tg_bundles_lifecycle_closure`, `test_tg_bootstrap_lifecycle_closure`, `test_tg_soak_lifecycle_closure`, `test_tg_lifecycle_pure_closure`, `test_tg_legacy_bootstrap_command_closure` | immutable rows refuse edits; lifecycle steps refuse out-of-order transitions |
| 9 Maintenance | `test_tg_maintenance_closure`, `_policy_`, `_service_`, `_state_`, `_views_closure` | every guard refuses unsafe entry / drain; nothing is executed against a device |
| 10 Credentials | `test_tg_credentials_core_closure`, `_ceos_`, `_linux_`, `_linux_runner_`, `_runner_`, `_pilot_`, `_commands_closure` | rotation and provider paths with placeholder secrets only |
| 11 NetBox / IPAM | `test_tg_nsot_closure`, `test_tg_nsot_sources_closure`, `test_tg_reconciliation_closure`, `test_tg_provisioning_closure`, `monitoring/tests/test_tg_netbox_*`, `test_tg_populate_netbox_closure`, `test_tg_ipam_context_closure` | read-only fake client (fails on anything but reads); no NetBox write |
| 12 Health | `test_tg_health_core_closure`, `_fleet_`, `_live_`, `_runs_closure` | parsers, gates and run records; unreachable devices are UNAVAILABLE, never PASS |
| 13 Topology | `monitoring/tests/test_tg_topology_closure` | snapshot / builder / server helpers |
| 14 Monitoring | `monitoring/tests/test_tg_snmp_module_`, `_syslog_module_`, `_gnmi_module_`, `_gnmi_collector_`, `_grafana_builder_`, `_linux_gnmi_server_`, `_linux_netconf_server_`, `_syslog_ingest_daemon_`, `_monitoring_modules_`, `_monitoring_scripts_`, `_provision_scripts_closure`; `test_tg_monitoring_service_closure` | the deployed scripts stay byte-identical; their functions are imported and called, never executed as programs |
| 15 CI / governance | `test_tg_ci_governance_closure`, `test_tg_phase_integrate_closure`, `test_test_governance` (extended) | Tier-3 engine, validation script and governance helpers called directly |
| 16 Helpers / UI adapters | `test_tg_web_views_closure` (RequestFactory, render recorded), `test_tg_web_helpers_closure`, `test_tg_traffic_closure` (spawn-free, fake sockets), `test_tg_capability_*_closure`, `test_tg_residual_closure` (history-row delete guards, template-version queryset, offline capability probe helpers, schema loader), `test_tg_raw_selftest_closure`, `challenge_console/tests/test_tg_core_closure`, `challenge_console/tests/test_tg_adapters_closure`, `challenge_console/tests/test_tg_ui_closure` (Tk widgets, views, bridge, close dialog, `run`, `live_proof`; needs a display), `test_tg_defect_regressions` | exact contexts / values; the traffic and device-write-script modules were also run under a socket / subprocess interceptor: 0 attempts |

### 6.1 Defects found and fixed by this phase

| # | Finding | Found by | Fix |
|---|---|---|---|
| F1 | **CLI injection**: a line break in any description field (interface, routing, BGP neighbor, ACL, device) passed Tier-1 and was rendered as an extra top-level configuration line (e.g. `username ... privilege 15`) on cEOS and FRR | systematic negative cases on the validators | `validate_description` refuses control characters; the candidate renderer withholds any multi-line field value with a visible refusal marker (defence in depth for stored / imported values) |
| F4 | a non-text JSON value (`{"value": 5}`) at the Device Builder commit endpoint raised `AttributeError` (HTTP 500) in 14 text validators | wrong-type contract cases | `_text_input` guard: non-text -> `(False, value, message)`; endpoint now answers 200 / INVALID |
| F5 | a provisioning plan-builder refusal raised `TypeError` (`code` passed twice to `blocker()`) instead of recording `PLAN_NOT_CURRENT` | Pylint `redundant-keyword-arg` | detail renamed `plan_code`; regression case `PROVISIONING_PLAN_BUILDER_REFUSAL_IS_A_BLOCKER` |
| F6 | FRR PAT / stateful NAT was rendered by a hard-coded platform flag, outside the capability registry | cell RENDER negative | the registry gates it like every other feature (SUPPORTED cells unchanged) |
| F7 | the Linux executor accepted a Configlet with no statements (every other executor refuses it) | cell EXECUTE negative | refused with `PLATFORM_EXECUTION_UNSUPPORTED` |
| F2 | *(first closure: expected failure; fixed in the sprint, 36fa2e8)* with a feature NOT_IMPLEMENTED in the capability registry, **per-interface contributions** (`ip ospf ...`, IS-IS bindings, `ip helper-address`, `ip access-group`, VARP lines, an SVI's `vlan`, the cEOS virtual-router MAC) were not separately gated | cell RENDER negative (cEOS SVI, OSPFv2, OSPFv3, ACL attach v4, DHCP relay v4/v6, VARP v4/v6; FRR OSPFv2/v3) | every contribution is gated by the capability registry like its object; production renders unchanged (golden digests identical); regression tests in `test_tg_defect_regressions.py` |
| F3 | *(first closure: expected failure; fixed in the sprint, 36fa2e8)* an L2 access / trunk candidate reached network-configuration validation WARNING with NetBox unavailable | cell VALIDATE negative (cEOS ACCESS, TRUNK) | with NetBox unavailable the managed-scope check BLOCKS (fail closed, as import already did) |
| F8 | `nsot_netbox.list_ip_addresses(prefix)` compared string prefixes, so an address inside the requested network (`10.0.0.1/31` in `10.0.0.0/24`) was dropped (13fa9cc) | NSOT adapter negative / positive cases | network containment via `ipaddress`; an invalid prefix degrades to unavailable. No production caller passed a prefix, so no page output changed |
| F9 | **governance tracer**: the direct-call caches were keyed by the bare code object; CPython code equality ignores `co_filename`, so two identical functions at the same first line in different files (the `provision_*.py` `run()` helpers) shared one entry and a call was credited to whichever file was seen first (6b48470; that commit message calls it "F5", renumbered here because F5 was already taken) | evidence attribution | caches keyed by `(code, co_filename)`; regression meta-test `TracerTests.test_identical_functions_in_different_files_are_credited_to_their_own_file` fails on the old tracer |

### 6.2 Known defects reproduced, not hidden (expected failures)

**None at the sprint's final run.** The first closure carried F2 and F3 as 12 `expectedFailure` cell cases (tracked
debt, never PASS); both were fixed at the root and the `KNOWN_DEFECTS` table in `test_tg_cells.py` is now empty, so
an expected failure can no longer hide a supported feature. The first-closure record is preserved in
[`RESULTS-first-closure-e398cd2.md`](evidence/lab7/RESULTS-first-closure-e398cd2.md).

Observations from the first closure, all **resolved in the sprint** (36fa2e8):

* O1 `gnmi_paths.yml` / `snmp_oids.yml` were loaded verbatim -> validating loaders in `modules/monitoring_config.py`,
  used by `modules.snmp` / `modules.gnmi`; their MALFORMED cases are now proven.
* O2 `cpu_alerts.classify` classified a NaN sample as normal -> NaN, +/-inf, None, bools and strings classify as
  `invalid` and never change alert state.
* O3 `identity/mfa.provisioning_uri` did not validate its seed -> it validates the seed (32 base32 characters) and the
  user; errors never echo the seed.
* O4 `nsot_device_detail` resolved an unknown device through the topology service before answering 404 -> an unknown
  device triggers no drift / inventory / git / topology lookup; the route sweep no longer needs an exemption.

New observations recorded in the sprint (**left unchanged**: changing behaviour is outside this test-only phase; none
can produce a false PASS, a device write or a NetBox write):

* O5 (P2, hardening) `views.notification_mark_all_read` / `notification_retry_slack` redirect to `request.POST["next"]`
  without `url_has_allowed_host_and_scheme`. The request needs login, MFA, POST and CSRF, which limits exposure; a
  candidate for a small hardening change.
* O6 (P2, operations console) `challenge_console/adapters/endpoints.py::ping` maps a source-container error to
  `SOURCE_CONTAINER_NOT_RUNNING` only when the exit code is not 0 / 1; `docker exec` on a stopped container exits 1, so
  the reason reads `TIMEOUT`. The verdict is still FAIL (never a false pass).
* O7 (P2, cosmetic) "SR Linix" typo in `config_import/parser_srlinux.py` docstrings and
  `docs/CANDIDATE_CONFIGURATION_COMPOSITION.md` (text only; no behaviour).

## 7. Pylint (`.pylintrc`, `pylint_data.py`)

Deliberate configuration: **everything disabled, then only chosen checks enabled** -- all `E` (error) and `F` (fatal)
messages; correctness (`dangerous-default-value`, `unreachable`, `duplicate-key`, `lost-exception`, `return-in-finally`,
`self-assigning-variable`, `undefined-loop-variable`, `cell-var-from-loop`, `using-constant-test`, `pointless-statement`,
`expression-not-assigned`); exception quality (`bare-except`, `broad-exception-caught`, `broad-exception-raised`,
`raise-missing-from`, `try-except-raise`); unused / redundant code; complexity outliers (`too-many-branches` > 30,
`too-many-statements` > 150, `too-many-nested-blocks` > 6, `inconsistent-return-statements`). Cosmetic conventions
are off on purpose (no style refactor of ~90k lines). `pylint-django` resolves Django models.

* **Critical** (gate fails on any): every E/F message plus the correctness set in `CRITICAL_SYMBOLS`.
* **Non-critical**: tracked per artifact in `baseline.json`; WARN while within the baseline, FAIL above it.
* Two dynamic patterns are configured explicitly (`findings.Code` attributes set with `setattr`; collaborators injected
  through fields annotated `object`). Other proven false positives are annotated inline with their reason; the two files
  that must stay byte-identical because they are copied onto devices (`ceos_syslog_forward.py`, `linux_gnmi_server.py`)
  have their false positives listed in `policy.yml pylint_false_positives`.
* Baseline triage (measured): the baseline run reported **230 critical messages**; the final run reports **0**. They were
  cleared by the two configured dynamic patterns above, the two device-copied files in `policy.yml`, **19 reasoned inline
  annotations in deployed code** (each `# pylint: disable=<symbol>  # <reason>`; list them with
  `git diff origin/main...HEAD -U0 | grep "pylint: disable"`), **one real defect fixed (F5)** and one mutable default
  argument removed (`credentials/r1_pilot.py::mfa_infrastructure_healthy`, read-only use, behaviour unchanged).
* Closure sprint: **23 verified-unused imports removed** from deployed code (dc9b74a, Pylint `unused-import` W0611;
  each checked across the repository for re-exports, attribute access and `mock.patch` targets before removal;
  side-effect imports and every file copied verbatim onto devices were deliberately kept); critical stays **0**.

## 8. coverage.py (`.coveragerc`, `coverage_data.py`)

Statement **and branch** coverage, `source` = repository root, omitting tests, migrations, documentation, virtual
environments and runtime output. Both suites write their own data file (`.coverage.django`, `.coverage.monitoring`);
they are combined and exported as JSON (consumed by NMAS -- never HTML) and XML (CI artifact). A file no test imported is
still counted: its statements / branches come from coverage.py's own parser, all uncovered. Per symbol, the statements
and branches inside its line range are reported next to its case states. **Line / branch coverage is shown separately
from case coverage and never substitutes for it.**

## 9. Tier-3 integration

The existing workflow and engine are extended, not replaced (`ci/catalog.py`, `ci/planner.py`, engine 16.1.0):

| Check | Gate | When | What |
|---|---|---|---|
| `governance.catalog` | static | every change | `nmas_test_governance validate-catalog --ci`: classification, declarations, references, baseline locks; lists NEW required symbols |
| `quality.pylint` | static | targeted: the changed deployed Python files; full: all | critical messages and baseline excess fail |
| `django.tests` / `monitoring.unit` | repository | full mode | the same suites, **traced and under coverage.py** (one run gives both the regression result and the evidence) |
| `governance.report` | repository | full mode | combine coverage, assemble the report, validate its schema, evaluate the closure gate; non-secret GitHub provenance (run id, repository, ref, SHA) is recorded |

Full mode = push to `main`, a manual run without a base, an unusable base or an unclassified path. The workflow uploads
`test-governance` (report + coverage.xml) next to `tier3-report`. **A path-scoped targeted run never claims global
coverage**; it validates the catalog and lints what changed.

**Evidence must be host-independent.** The first hosted full run failed the gate although every test passed: two cases
were proven only by evidence that does not exist on a GitHub runner -- `render_nmas_dhcp.main`'s happy path only by
tests that need the `dhcpd` binary (skipped there), and `cases.case()` only by a test that happened to be the first to
import a test module. The gate caught both (`CASE_MISSING_NEW`, `CLOSED_REGRESSION`); each now has a hermetic test.
A case whose only proof is a host-dependent `skipUnless` test is therefore never "closed" in Tier-3 -- add a test that
fakes the host dependency. The closure sprint's first hosted full run (39314819864 at e8b29bf) failed the gate the
same way, on one case: `ceos_syslog_forward.py::tail` POSITIVE. Its test closed the generator in the test body, and
the runner's CPython 3.12.15 traced that close's `GeneratorExit` unwind (counted as a raise) where the local 3.12.3 did
not; the close now happens in `addCleanup`, outside the test method (4f6ea28).

**A display is part of the evidence environment.** The Tk console tests need one. Both environment allowlists (Tier-3
`ci/runner.py`, governance `runner.py`) forward `DISPLAY` / `XAUTHORITY` (a display name and a cookie-file path, no
secret value); the workflow installs Xvfb if missing, fails the step if Tk cannot open a window, and runs `tier3.py`
under `xvfb-run -a`; local evidence runs use the same wrapper. A run without a display leaves the UI cases MISSING, and
because the baseline records them closed, the gate fails (`CLOSED_REGRESSION`) instead of passing quietly. The bundled `docs/evidence/lab7/test-governance-report.json` is the **hosted** full-run
report (provenance: run id, repository, SHA), verified by its payload hash.

### Closure gate (`gate.py`) -- fails on

`CASE_FAILED`, `CASE_MISSING_NEW` (a required case missing that is not recorded debt -- new uncovered code or a new
SUPPORTED cell cannot add silent debt), `BROKEN_REFERENCE`, `CATALOG_ERROR`, `ARTIFACT_DISAPPEARED`,
`CLOSED_REGRESSION` (an artifact / cell the baseline records as closed), `PYLINT_CRITICAL`, `PYLINT_NEW_DEBT`,
`NO_TESTS`, `NO_COVERAGE`. It warns with `KNOWN_DEBT` (exact count) and `DEBT_RESOLVED` (tighten the baseline).

### Tracked baseline (`baseline.json`) -- the ratchet

`manage.py nmas_test_governance baseline --from <report> --write` records today's measured state: known missing cases,
closed artifacts / cells, locked declared cases, artifact ids and per-file Pylint counts. Debt can only shrink from there.
No percentage threshold was invented: the gate is "no new debt, no regression, nothing failing", which is stricter than
a fixed number and cannot be met by adding meaningless tests.

## 10. Evidence format (`report.py`, `report.schema.json`)

`test-governance-report.json`, schema version 1, generator version: provenance (repository SHA, Tier-3 run id,
repository, ref, event, Python version, mode), source fingerprint, summary, every artifact (classification, cases
tally, functions, coverage incl. uncovered lines / branches, Pylint, symbols), every case (state, evidence with basis),
every test (id, outcome, file:line, intent, declared ids), capability cells, generic groups, Lab 7 examples, catalog
errors, the gate, input file digests, and `payload_sha256` over the canonical payload (timestamps and run ids excluded:
same source + tests + environment -> same hash). `schema.py` validates it without third-party packages.

## 11. NMAS pages

* **Unit Test Matrix** -- summary cards (positive X / Y, negative X / Y, artifacts closed, functions, statements, branches,
  capability cells, Pylint, tests, debt), the closure-gate findings, the Lab 7 example mapping, filters (group /
  subsystem, artifact type, platform, feature, status incl. *incomplete*, positive missing, negative missing, Pylint,
  current scope / all, path search) and the table **Deployed file / artifact | Negative test cases | Positive test
  cases**; each cell expands to every required case with its state, reason and exact test identifiers.
* **Artifact detail** -- path, type, role, subsystem / group, platform / feature, scope reason, Pylint messages,
  statements / branches with uncovered lines and branches, every symbol (lines, disposition + rule, negative / positive
  state, per-symbol coverage), every case with its proving tests (file:line, basis), the capability cells using it. Read
  only: there is no editor.
* **Code Coverage** -- the platform x feature grid in the capability-matrix design: each SUPPORTED cell shows cases %,
  `POS x / y`, `NEG x / y`, `FUNC x / y`, `LINES %`; NOT_IMPLEMENTED / UNSUPPORTED cells are grey and never counted; the
  generic / control-plane table (artifacts closed, functions, positive, negative, statements, branches per group).
* **Cell detail** -- every lifecycle stage with its negative and positive case (condition -> expected, tests), stages not
  implemented for the cell shown as NOT_CURRENT_SCOPE, and the cell's source artifacts with their coverage.
* **Evidence banner** on every page: CURRENT / STALE / UNKNOWN / NO_EVIDENCE, tested SHA vs deployed SHA, whether the
  source fingerprint is identical, generation time, source (bundled / accepted / GitHub run with link), payload hash,
  closure-gate result, and **Refresh from Tier-3**.

**CURRENT** = the report's SHA is the deployed SHA, or the deployed source fingerprint (code + tests + governance
inputs) is identical (a documentation-only commit does not stale evidence). Otherwise **STALE** with the reason --
old coverage is never presented as current.

**Refresh** (POST, `VALIDATE` permission) polls GitHub for the newest completed Tier-3 run of the deployed SHA, downloads
its `test-governance` artifact (the token is never forwarded to the signed storage URL), and accepts it only if the
schema and hash verify **and** it names that run id and commit. Viewing never depends on GitHub; no callback exists;
nothing is accepted from a browser upload.

Access: the ordinary NMAS boundary (authenticated + website MFA). Pages are `READ_ROUTES` (VIEW); a POST on them is
refused by the middleware (405). No secret, token or credential value is ever in the report (contexts in tests are
fake values; the tracer records test ids and symbol ids only).

## 12. Current closure vs final closure

**CURRENT TEST CLOSURE** covers the deployed backend, the currently implemented features and the currently SUPPORTED
platform x feature cells (46 of 396 in the capability ledger). Its status is in `RESULTS.md` and section 16: **46 / 46
SUPPORTED cells closed (276 / 276 positive, 276 / 276 negative), 0 expected failures**, with 112 tracked
symbol cases still open (section 16.4). The UI shows every one of them with its reason.

**FINAL TEST CLOSURE** follows **Platform x Feature Capability Closure**: every cell moved to SUPPORTED adds its stage
cases to current scope automatically (the catalog is derived from the ledger), and every new renderer / validator /
executor / postcheck / compensation function appears as a new required symbol with no disposition -> MISSING ->
`CASE_MISSING_NEW` until it is tested.

## 13. How to ...

* **add a deployed module** -- nothing to register: it is discovered; add a Tier-3 path rule if `governance.catalog`
  reports it UNCLASSIFIED; write tests that call its public functions directly (positive + negative); run
  `xvfb-run -a manage.py nmas_test_governance run --out /tmp/tg` to see its row (the virtual display lets the Tk console tests run,
  exactly as in Tier-3; without one their cases stay MISSING and the gate says so).
* **add a platform feature** -- regenerate the capability ledger when the cell becomes SUPPORTED; its cases appear in
  `test_tg_cells.py` automatically (a feature without a probe sample fails visibly); add its template to
  `policy.yml template_features`.
* **add test metadata** -- decorate the test with `@case(...)` (section 5.2); `validate-catalog` checks it.
* **exempt something** -- `policy.yml` (`artifact_exemptions` / `symbol_exemptions` / `external_consumers`), always with
  a reason; it is shown as EXEMPT.
* **read evidence** -- the pages, or `manage.py nmas_test_governance status [--json]`; `summarize REPORT --baseline B`
  renders Markdown.
* **update the baseline after closing gaps** -- `run`, then `baseline --from <report> --write`, review the diff (debt must
  only shrink), commit.

Commands: `inventory`, `validate-catalog`, `run`, `report`, `pylint`, `status`, `accept`, `baseline`, `summarize`,
`refresh` (`manage.py nmas_test_governance <command> --help`).

## 14. Testing the testing system

`test_test_governance.py` and `test_test_governance_views.py` prove discovery and classification, AST symbol detection,
every disposition rule, policy and ledger validation, positive / negative counting, missing and failing cases, broken
references, the coverage and Pylint parsers, cell and group aggregation, schema validation, deterministic hashing, the
evidence store (write-once, tamper refusal, stale / current), the GitHub refresh (only the run's own report), the tracer
(direct vs indirect, setUp exclusion, raise vs return, sub-test intent, outcome capture, behavior neutrality) and the
pages (rendering, filters, expansion, drill-down, stale banner, refresh outcomes, RBAC / read-only). Fixture proofs:
a new uncovered file and a new uncovered function become MISSING and fail the gate; a missing negative lowers X while Y
stays fixed; a failing test is never PASS; evidence for other source is STALE; NOT_IMPLEMENTED cells never count; a cell
moving to SUPPORTED creates 12 required cases at once.

## 15. Lab 7 video walkthrough (exact examples)

Start on the Automation landing page: the two read-only sections; explain discovery -> required catalog -> evidence ->
pages (section 2). The evidence banner must read **CURRENT** (tested SHA or source fingerprint = deployed) with the
hosted run link.

| | Show | Exactly where |
|---|---|---|
| A | **Unit Test Matrix, one strong artifact** | Unit Test Matrix, search `field_validators.py` -> row `PY:web/core/services/field_validators.py`: Negative x / y and Positive x / y (all PASS); expand both columns -- each case names its function (`validate_cidr`, `validate_ip_host`, `validate_interface_description` ...) and the exact test id with its basis (`DIRECT_RETURN` / `DIRECT_RAISE` / `DECLARED`); open the artifact detail page: every symbol, disposition rule, per-symbol lines / branches |
| B | **Negative robustness** | the declared case `F1_DESCRIPTION_LINE_BREAK_REFUSED_AT_TIER1` on `validate_interface_description` (a description containing CR / LF / NUL is INVALID at Tier-1, so it can never become an injected `username ... privilege 15` line); alternatively `health/live.py` parsers: malformed device output -> UNAVAILABLE `PARSE_ERROR`, never a crash or a phantom neighbor |
| C | **Code Coverage Matrix, cEOS routing** | Code Coverage -> cell `arista_ceos · routing.OSPFV2`: CLOSED, POS 6 / 6, NEG 6 / 6; open it: every lifecycle stage with its negative and positive case; the RENDER negative that was the F2 known defect in the first closure is now PASS (contributions gated, section 6.1) |
| D | **Generic coverage** | Code Coverage -> generic / control-plane table, row **Health** (18 / 18 artifacts, 127 / 127 functions, 128 / 128 positive, 126 / 126 negative) or **Validation** (23 / 23, 148 / 148, 148 / 148, 110 / 110) |
| E | **Pylint 0 critical** | Unit Test Matrix summary card *Pylint: WARN (0 critical)*; a detail page's Pylint section; section 7 of this document |
| F | **GitHub final full Tier-3 PASS** | the hosted `workflow_dispatch` full run [39331725853](https://github.com/Dhruv-Suvarna/Adv-Netman/actions/runs/39331725853) (Tier-3 PASS_WITH_WARNINGS, closure gate PASS_WITH_DEBT) (jobs `governance.catalog`, `quality.pylint`, traced `django.tests` / `monitoring.unit`, `governance.report`, artifact `test-governance`); back in NMAS the banner's run link |
| G | **Documentation / requirement mapping** | section 1 of this document (Lab 7 requirement -> where it is met) and the "Lab 7 assignment examples" table on the Unit Test Matrix / in `RESULTS.md` |

## 16. Current-scope closure sprint: before / after

Three evidence points, all generated by `nmas_test_governance` and hash-verified:

* **Baseline** -- deployed code before any Lab 7 test (18d7972): [`BASELINE.md`](evidence/lab7/BASELINE.md), unchanged.
* **First closure** -- hosted full Tier-3 run at e398cd2: preserved unchanged as
  [`RESULTS-first-closure-e398cd2.md`](evidence/lab7/RESULTS-first-closure-e398cd2.md).
* **Final** -- this sprint: hosted full Tier-3 run
  [39331725853](https://github.com/Dhruv-Suvarna/Adv-Netman/actions/runs/39331725853) at 9ba6cd8 (`workflow_dispatch`,
  mode full, CPython 3.12.15, under `xvfb-run`): Tier-3 **PASS_WITH_WARNINGS** (the only warning is the no-base hygiene scan's line bound;
  lab-backed verifiers are NOT_RUN offline by design), closure gate **PASS_WITH_DEBT**, payload sha256
  `b5559a2b5c6f3a1bc13aacc6d45558fb193f33576c70586d8c5ec9b2dbb6b888`. The report is bundled as
  `docs/evidence/lab7/test-governance-report.json`; [`RESULTS.md`](evidence/lab7/RESULTS.md) is generated from it.

### 16.1 Headline figures

| Metric | Baseline (18d7972) | First closure (e398cd2, hosted) | Final (9ba6cd8, hosted) |
|---|---|---|---|
| Positive cases PASS / required | 1160 / 2930 | 1553 / 3134 | **3068 / 3140** |
| Negative cases PASS / required | 826 / 2304 | 1247 / 2515 | **2433 / 2473** |
| Functions explicitly tested / required | 1354 / 2832 | 1612 / 2978 | **2913 / 2984** |
| Artifacts closed / counted | 39 / 478 | 151 / 503 | **493 / 504** |
| SUPPORTED cells closed | 0 / 46 | 34 / 46 | **46 / 46** |
| Cell negative cases | 0 / 276 | 264 / 276 (12 expected failures) | **276 / 276** |
| Statements | 76.81 % | 78.20 % | **87.80 %** |
| Branches | 68.41 % | 71.09 % | **81.18 %** |
| Pylint | 230 critical | 0 critical, 288 tracked | **0 critical, 263 tracked** |
| Tests | 3108 (1 fail) | 4239 (12 expected failures) | **6327: 6319 pass, 8 skip, 0 fail, 0 expected failures** |
| Tracked case debt (`baseline.json`) | -- | 2862 | **112** |

The final column is the **hosted** run. Its 8 skips are one opt-in live Docker smoke test
(`test_traffic_runner.LiveRuntimeSmokeTests`) and 7 tests that need the `dhcpd` binary or the live lab topology file,
absent on a GitHub runner (each of their cases is also proven by a hermetic test, section 9). The Tk console tests run
under the virtual display (section 9). The final **local** full run (`xvfb-run -a`, report SHA ceb80c0, identical code and
tests; the following commit only tightened `baseline.json`) gave the same case, cell and function figures with 6327 tests:
6326 pass, 1 skip, 0 fail. Before the display was added, the sprint's previous hosted run
([39320066484](https://github.com/Dhruv-Suvarna/Adv-Netman/actions/runs/39320066484), ee0c58c) measured 3037 / 3140,
2420 / 2473 and 156 tracked cases, the difference being exactly the 44 Tk UI cases.

### 16.2 Denominator audit (first closure -> final), every change explained

Computed by comparing the required case sets of the two reports case id by case id:

| Change | Positive | Negative | Functions | Reason |
|---|---|---|---|---|
| New deployed module `modules/monitoring_config.py` (O1 fix: validating loaders) | +4 | +4 | +4 | new code, new required cases |
| New public functions `cpu_alerts.is_valid_sample` (O2), `identity/mfa.validate_seed` (O3) | +2 | +2 | +2 | new code, new required cases |
| Rule **R10** (section 4): 50 symbols R8 -> R10 | 0 | **-48** | 0 | callables that never read their inputs cannot have a negative input case; 48 negative requirements removed (27 of them were MISSING, 21 PASS; the other 2 symbols are in the EXEMPT live verifier `netbox/scripts/verify_netbox_model.py` and had no case) |
| **Total** | 3134 -> **3140** | 2515 -> **2473** | 2978 -> **2984** | |

No symbol or artifact was removed, no scope changed, no `symbol_exemptions` / `artifact_exemptions` were added, and
the EXEMPT count is unchanged (100 positive, 17 negative). R10 lowered the debt by 27 cases through the denominator;
that is the only debt reduction not made by a test. The cell denominator is unchanged (276 + 276).

### 16.3 Defects

F2 and F3 (the 12 expected failures of the first closure) were fixed at the root; F8 and F9 were found and fixed in
the sprint; O1-O4 were resolved; O5-O7 are recorded and left unchanged (section 6.1 / 6.2).

### 16.4 Remaining current-scope debt (112 cases, each listed in the UI with its reason)

The 44 Tk console UI cases that were still open at ee0c58c are closed: the evidence environment now has a virtual
display (section 9, d11e38b) and `challenge_console/tests/test_tg_ui_closure.py` calls every UI entry point directly
(ceb80c0). The challenge-console group is 34 / 34 artifacts and 176 / 176 functions.

| Cases | Where | Why it remains |
|---|---|---|
| 108 | `capabilities/isolated_live.py`, `batch_live.py`, `batch_frr_routing.py`, `batch_iosxe.py`, `batch_srlinux.py`, `batch_ceos_interfaces.py`, `batch_frr_nat.py` | **Deferred to Platform x Feature capability closure.** These are the live probes that drive the disposable `nmas-cap-validation` container lab to promote a cell; every remaining function starts, execs into or tears down containers (lab classes, `probe_*`, `verify_*`, the docker-exec EOS connection). A hermetic test would only re-assert a fake. They are exercised by the capability workstream, which this phase does not start. Their offline helpers are closed: `probe_cases`, `assessment`, and the IOS XE / SR Linux `plan` / `imported` (render, then parse). |
| 1 | `models.py::_ImmutableQuerySet.delete` | **Structural.** No inputs and an unconditional raise: rule R9 requires a POSITIVE case and no call can return. Its refusal is tested (`test_bundles.py` / `test_bootstrap.py` queryset-delete cases). |
| 2 | `monitoring/scripts/linux_netconf_server.py::main`, `syslog_ingest_daemon.py::main` | **Structural.** Daemon entry points that end in `while True` (bind a listening socket / tail a log file forever); the deployed scripts are kept byte-identical, so no exit hook can be added. Every other function in both files is closed (20 / 21 and 7 / 8 functions). |
| 1 | `raw_verifier_selftest.py::Command.handle` (POSITIVE) | **Structural.** The command always ends with `SystemExit` (0 on success, 1 / 2 otherwise), and the tracer counts every raise as NEGATIVE, so no call can be a positive return. Its NEGATIVE case is PASS. |
