# Phase 21 — DevOps pipeline (Part 2, Objective 2)

Status: complete. The hosted evidence in section 6 proves the required automatic
code/configuration PASS/FAIL behavior; the final Phase-21 branch remains subject
to the same hosted check before merge.

## 1. Assignment requirement and selected platform

The assignment requires a DevOps pipeline in which both a code change and a
configuration change automatically trigger a meaningful test and produce an
observable PASS/FAIL result. Jenkins is the assignment's example. This project
uses GitHub Actions because the repository, pull requests, and existing Tier-3
validation are already hosted on GitHub; installing a second CI controller would
duplicate the established pipeline without improving the required behavior.

The completion claim requires four hosted observations, not merely a workflow
file: a passing code-change run, a separate passing configuration-change run, a
controlled invalid change that fails for the intended reason, and a correction
that automatically runs and passes.

## 2. Existing Tier-3 architecture

`.github/workflows/tier3-validation.yml` is a deliberately thin GitHub Actions
caller. It checks out the complete history, installs the three pinned project
requirement sets, runs `python tier3.py --from-github`, publishes a Markdown job
summary, and uploads the bounded `tier3-report.json` artifact. The implementation
lives under `web/core/services/ci/`:

1. GitHub event metadata determines the comparison range.
2. Changed paths are classified by the ordered rules in `rules.py`.
3. Consumer impacts are expanded transitively.
4. The planner selects baseline and subsystem-specific checks.
5. Checks execute from a fixed catalogue and produce a structured PASS, FAIL, or
   INCOMPLETE result.

Tier 3 is validation-only. Hosted CI has `contents: read`, receives no project
secrets, does not use a self-hosted runner, and has no device, NetBox write, or
Containerlab lifecycle path.

## 3. Automatic triggers

| GitHub event | Scope | Automatic behavior |
|---|---|---|
| `pull_request` | Every PR; no path filters | Opening a PR and every pushed PR update run targeted Tier-3 validation automatically. |
| `push` | `main` only; no path filters | Every merge/direct push to the default branch runs full Tier-3 regression automatically. |
| `workflow_dispatch` | Manual utility | Optional manual full/targeted validation; not accepted as Phase-21 trigger evidence. |

There are no `paths:` or `paths-ignore:` filters. GitHub therefore cannot discard
a tracked configuration change before Tier 3 sees it. A feature-branch push with
no open PR does not trigger this workflow; the normal integration contract is an
active pull request. Neither `tools/phase_integrate.py` nor a manual `tier3.py`
invocation is required to schedule the hosted PR check.

The visible workflow and job/check name are both `Tier-3 validation`. GitHub posts
that check to the pull request and its conclusion follows the Tier-3 process exit
status.

## 4. Evidence-based code and configuration classification

Classification is path/ownership based, not inferred only from a suffix. A path
can belong to more than one subsystem; for example
`templates/R2_dhcp_server.cfg.j2` is both frozen `lab_config` and `dhcp`.

### Code

The project's implementation code includes:

| Paths | Tier-3 ownership |
|---|---|
| `master.py`, `hostserv.py`, `address_report.py`, `modules/*.py` | core automation or the relevant monitoring/topology/NetBox subsystem |
| `web/core/services/**/*.py`, `web/core/views.py`, `web/core/urls.py`, `web/config/**` | Django control plane, renderers, drivers, validation, planning, health, execution, views/API, or Django project configuration |
| `monitoring/scripts/**`, `netbox/scripts/**` | monitoring, topology, NetBox/IPAM, DHCP, or lab verifiers according to the exact path |
| `tools/**`, `tier3.py`, `web/core/services/ci/**` | developer tooling or CI engine/workflow support |
| `web/core/templates/**`, `web/core/static/**` | frontend/UI implementation (`ui_presentation`) |

Tests (`web/core/tests/test_*.py`, helpers, and `monitoring/tests/test_*.py`) and
Django migrations have separate Tier-3 classifications so changes select their
own regression surface or the full Django suite instead of being treated as
generic Python.

### Configuration

The authoritative declarative configuration families are:

| Paths | Tier-3 ownership | Meaningful validation selected |
|---|---|---|
| `templates/features/**` | `candidate_rendering` | Jinja parse plus renderer, platform, Device Builder, validation, planning, and downstream tests |
| `dhcp/**`, `templates/R2_dhcp_server.cfg.j2` | `dhcp` (and `lab_config` for the R2 template) | Jinja/YAML parse, DHCP/service-policy and health tests, monitoring/NetBox unit suite |
| `templates/monitoring/**`, `monitoring/config/**`, `monitoring/docker-compose.yml` | `monitoring` | YAML/Jinja parse where applicable, monitoring consumers, full monitoring unit suite, Grafana drift check |
| `monitoring/grafana/**` | `monitoring` | JSON/YAML parse, monitoring integration tests, full monitoring unit suite, deterministic generated-dashboard drift check |
| `netbox/ipam.yml`, `netbox/docker-compose.yml` | `netbox_ipam` | YAML parse, IPAM/NSOT/address-validation consumers, monitoring/NetBox unit suite |
| `inventory.yml`, `srlceos01.clab.yml`, `templates/*.cfg.j2` | frozen `lab_config` | YAML/Jinja parse, inventory/topology/health/DHCP consumers, monitoring unit suite, plus a frozen-baseline warning |
| `.github/workflows/**` | `ci_workflow` | YAML parse and the workflow security/trigger contract test |

Every change also receives credential/conflict hygiene, changed-file syntax
validation, `manage.py check`, and migration-drift validation. An unknown path
broadens to the full offline regression rather than silently selecting no tests.

## 5. Representative trigger and change-effect matrix

| Representative tracked path | Direct classification | Effective relevant checks |
|---|---|---|
| `web/core/services/validation/engine.py` | `validation` | Python syntax; Tier-2 validation, planning, health, execution, bundle/soak, and contract tests |
| `web/core/templates/core/base.html` | `ui_presentation` | UI/theme/navigation/view-boundary regression tests |
| `web/core/static/core/js/app.js` | `ui_presentation` | UI and JavaScript contract/regression tests |
| `templates/features/ceos/routing_bgp.j2` | `candidate_rendering` | Jinja parse and candidate/routing renderer plus downstream consumer tests |
| `monitoring/config/topology.yml` | `monitoring` | YAML parse, monitoring/health/topology/soak consumers, monitoring unit suite, Grafana drift |
| `monitoring/grafana/provisioning/dashboards/json/fleet-overview.json` | `monitoring` | JSON parse, monitoring integration/unit tests, generated-dashboard drift |
| `web/core/tests/test_health_engine.py` | `tests_django` | The changed test module itself |
| `web/core/migrations/0005_phase15_operational_check_run.py` | `migrations` | Migration parse/drift plus full Django regression; modification also warns because history is append-only |
| `.github/workflows/tier3-validation.yml` | `ci_workflow` | YAML parse and `test_tier3_execution` workflow contract |

`test_tier3_selection.py` pins these classifications and check-selection
relationships. A repository-wide drift contract also requires every tracked file
to match at least one Tier-3 path rule.

## 6. Hosted evidence

All four runs below were scheduled by GitHub's `pull_request` event after a push
or PR creation. None used `workflow_dispatch`, the GitHub **Run workflow** button,
or a manual `tier3.py` invocation as hosted evidence.

| Proof | Branch / PR | Commit | Event | Run ID | Classification / relevant check | Conclusion |
|---|---|---|---|---|---|---|
| Code change | `phase21-objective2-devops-pipeline`, PR #11 | `f249d1ec63216529e086d1c62f8fccd6f644aaa0` | `pull_request` | `36328970722` | Direct `tests_django`, `ci_engine`, `documentation`; baseline checks and 74 Tier-3 contract tests | **SUCCESS / PASS** |
| Configuration change (`monitoring/config/topology.yml`) | `phase21-objective2-devops-pipeline`, PR #11 | `ef48829a6e3cee2765c1f252a14e4338a6f68ced` | `pull_request` | `36329360790` | Direct `monitoring`; YAML parse, 467 downstream Django tests, 446 monitoring tests, Grafana drift | **SUCCESS / PASS** |
| Controlled invalid configuration | `phase21-ci-failure-evidence`, disposable PR #12 | `4b0a3cde40ddab87f9882fc30c00a670d0d2e899` | `pull_request` | `36329557115` | Direct `monitoring`; `static.syntax` found `SYNTAX_YAML` at `monitoring/config/topology.yml:14` (`expected the node content, but found '<stream end>'`) | **FAILURE / FAIL as expected** |
| Corrected configuration | `phase21-ci-failure-evidence`, disposable PR #12 | `7d493ac9ed39730797150208b45f0017e61f88f9` | `pull_request` | `36329655097` | Correction restored the tree exactly to the PR base, so the net PR diff was empty; all four mandatory baseline gates passed | **SUCCESS / PASS** |

Run `36329360790` compared the complete PR against `main`, so its report contains
the earlier code/doc files as well as `monitoring/config/topology.yml`. The commit
that scheduled it was configuration-only, and the newly selected `monitoring`
classification and three configuration-relevant repository checks are explicit
in the report. The independent disposable PR compared only the configuration
file against the Phase-21 branch, which proves both its direct classification and
its deterministic failure behavior without the code/doc changes in scope.

The controlled change was the single line
`phase21_controlled_invalid_yaml: [`. It contained no credential, made no runtime
or device change, and failed at YAML parsing before it could be consumed. The
next commit deleted only that line. PR #12 was then closed without merge and its
remote/local evidence branch was deleted; the commits and Actions runs remain in
GitHub's audit history.

Textual evidence was captured with `gh run view ... --json`, `gh run view ...
--log`, and `gh pr checks`. The relevant workflow job was named `Tier-3
validation` in every run and its visible PR check conclusion matched the Tier-3
report result.

## 7. Branch-protection audit

The repository is private and the authenticated owner has `ADMIN` permission.
GitHub's branch-protection and repository-ruleset APIs both return HTTP 403 with
the message that GitHub Pro or a public repository is required. The Tier-3 check
exists and is visible on pull requests, but required-check enforcement cannot be
inspected or configured on the repository's current plan. No repository setting
was changed.

## 8. Limitations and completion gate

- Hosted GitHub Actions exercises offline static/repository gates only. Real lab
  verifiers remain explicit local `--lab` checks so untrusted PR code never runs
  on a lab-connected self-hosted runner.
- A feature branch must have an open PR to receive automatic pre-merge validation;
  default-branch pushes receive the separate automatic full regression.
- The Phase-21 evidence branch will use only harmless repository configuration;
  it will not contact devices or modify live lab state.

The four mandatory evidence rows now contain real commit SHAs, automatic
`pull_request` run IDs, relevant check output, and final conclusions. PR #11 is
the final Phase-21 PR and is intentionally not merged without explicit user
approval.

**Phase 21 / Part 2 Objective 2: COMPLETE.**
