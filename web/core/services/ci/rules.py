"""Declarative Tier-3 change-effect rules -- the ONE inspectable source-to-check mapping.

Nothing here executes anything.  Three tables drive everything, and the classifier/planner
are generic over them:

1. ``SUBSYSTEMS`` / ``PATH_RULES``   which logical project subsystem(s) a path belongs to.
                                     A path may match several (a migration is ``migrations``;
                                     a DHCP renderer under ``netbox/`` is ``netbox_ipam`` AND ``dhcp``).
2. ``IMPACT_EDGES``                  curated cross-subsystem consumers.  If A changes, B consumes
                                     A's output, so B's regression surface is also required.
                                     Expansion is transitive; the chain is reported.
3. ``SELECTIONS``                    what each subsystem directly requires (Django test modules,
                                     the monitoring suite, the Grafana drift check, lab verifiers).

Anything that matches no rule is ``UNCLASSIFIED`` and forces the conservative full gate.
Django test names are relative to ``core.tests``; a contract test proves each one exists.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache


# --- subsystems -------------------------------------------------------------------------------

SOURCE, TEST, DOC, CI, RUNTIME, META = "source", "test", "doc", "ci", "runtime", "meta"


@dataclass(frozen=True)
class Subsystem:
    id: str
    title: str
    kind: str
    frozen: bool = False  # part of the frozen Lab-1 baseline: a change is surfaced as a warning


SUBSYSTEM_LIST = (
    Subsystem("models_schema", "Django models / schema", SOURCE),
    Subsystem("migrations", "Django migrations", SOURCE),
    Subsystem("shared_core", "shared Django core utilities", SOURCE),
    Subsystem("django_project", "Django project configuration", SOURCE),
    Subsystem("dependencies", "Python dependency manifests", SOURCE),
    Subsystem("control_plane", "Change / intent control plane", SOURCE),
    Subsystem("device_builder", "Device Builder (Tier-1 validators, intent services)", SOURCE),
    Subsystem("candidate_rendering", "candidate rendering / feature templates", SOURCE),
    Subsystem("platform_drivers", "platform drivers and capability matrices", SOURCE),
    Subsystem("validation", "Tier-2 Change validation engine", SOURCE),
    Subsystem("network_config_validation", "Network-device configuration validation", SOURCE),
    Subsystem("planning", "plan builder / Configlets", SOURCE),
    Subsystem("health", "health / precheck / postcheck", SOURCE),
    Subsystem("execution", "structured execution engine (Complete / Partial UAT)", SOURCE),
    Subsystem("raw_configlets", "Raw Configlets + isolated verifier / sandbox", SOURCE),
    Subsystem("bundles", "immutable configuration bundles (UAT / Probation artifacts and their integrity)", SOURCE),
    Subsystem("probation_soak", "probation soak: evidence collection, evaluation, scheduler command and the operator decision", SOURCE),
    Subsystem("legacy_bootstrap", "one-time legacy baseline bootstrap: read-only capture, 30-minute observation, initial baseline approval and its lockout", SOURCE),
    Subsystem("config_workbench", "Configuration Changes / Remove Configuration workbench: snapshots, line index, semantic removal analysis", SOURCE),
    Subsystem("config_templates", "Intent-based configuration templates: extraction, parameterization, baselines, portable packages, clone", SOURCE),
    Subsystem("traffic", "traffic / test workbench: endpoint catalogue, hard limits, the runner (IPC + the one process boundary), parsers, run evidence", SOURCE),
    Subsystem("provisioning", "new-device provisioning: staged request, bootstrap classification, capability gate, IPAM reservation, registry", SOURCE),
    Subsystem("device_lifecycle", "managed-device identity / lifecycle / expected attachments / bootstrap authorization and the one managed-device resolver", SOURCE),
    Subsystem("device_ztp", "native ZTP: platform adapters, isolated DHCP providers (ISC / Kea), trusted discovery, bootstrap artifacts / delivery, management verification", SOURCE),
    Subsystem("device_management", "management multihoming: NMAS attachments, management paths, L1-L6 probes, the selector / resolver and bootstrap credential retirement", SOURCE),
    Subsystem("device_commissioning", "trusted-upstream isolation, governed commissioning, dependency ordering, production admission and the lifecycle outbox", SOURCE),
    Subsystem("management_vrf", "management VRF intent, per-platform rendering, validation, Configlets, cEOS execution inverse and import", SOURCE),
    Subsystem("device_secrets", "protected runtime device-secret provider consumed by every device session", SOURCE),
    Subsystem("credentials", "managed-device credential metadata, rotation policy / engine / scheduler and device-login 2FA policy", SOURCE),
    Subsystem("identity_security", "NMAS website authentication / RBAC / website MFA / request audit middleware", SOURCE),
    Subsystem("capability_framework", "capability evidence framework (aggregation over the capability registries + empirical evidence)", SOURCE),
    Subsystem("web_deployment", "website hosting templates: Gunicorn / systemd / Apache / cloudflared (website only)", SOURCE),
    Subsystem("netbox_ipam", "NetBox / IPAM integration", SOURCE),
    Subsystem("dhcp", "DHCP (NMAS primary / R2 secondary)", SOURCE),
    Subsystem("nsot", "NSOT aggregation", SOURCE),
    Subsystem("monitoring", "monitoring (SNMP / syslog / telemetry / Grafana)", SOURCE),
    Subsystem("topology", "topology (NetworkX / topology service)", SOURCE),
    Subsystem("notifications", "notifications / Slack", SOURCE),
    Subsystem("django_views_api", "Django views / routes / API boundary", SOURCE),
    Subsystem("ui_presentation", "templates / static / themes", SOURCE),
    Subsystem("lab_config", "frozen Lab-1 configuration and inventory", SOURCE, frozen=True),
    Subsystem("core_automation", "core automation / orchestrator", SOURCE),
    Subsystem("dev_tooling", "developer workflow tooling (phase integration helper; source control only)", SOURCE),
    Subsystem("test_governance", "Lab 7 test governance: deployed-artifact inventory, test catalog, direct-invocation tracer, coverage.py, Pylint, evidence pages", SOURCE),
    Subsystem("challenge_console", "standalone read-only Tkinter operations console (not part of the website; its own collectors, adapters and tests)", SOURCE),
    Subsystem("lab_verifiers", "live lab verifier scripts", TEST),
    Subsystem("tests_django", "Django tests", TEST),
    Subsystem("tests_support", "shared Django test helpers", TEST),
    Subsystem("tests_monitoring", "monitoring / NetBox unit tests", TEST),
    Subsystem("ci_engine", "Tier-3 validation engine", CI),
    Subsystem("ci_workflow", "GitHub Actions workflow / launcher", CI),
    Subsystem("documentation", "documentation and project policy", DOC),
    Subsystem("repo_meta", "repository metadata", META),
    Subsystem("runtime_artifacts", "runtime logs / caches / local state", RUNTIME),
)
SUBSYSTEMS: dict[str, Subsystem] = {s.id: s for s in SUBSYSTEM_LIST}
UNCLASSIFIED = "unclassified"

_SVC = "web/core/services"


@dataclass(frozen=True)
class PathRule:
    subsystem: str
    patterns: tuple[str, ...]


def _svc(*names: str) -> tuple[str, ...]:
    return tuple(f"{_SVC}/{n}.py" for n in names)


PATH_RULES: tuple[PathRule, ...] = (
    PathRule("models_schema", ("web/core/models.py",)),
    PathRule("migrations", ("web/core/migrations/**",)),
    PathRule("shared_core", ("web/core/__init__.py", "web/core/apps.py", *_svc("__init__", "base", "secret_policy"))),
    PathRule("django_project", ("web/config/**", "web/manage.py")),
    PathRule("dependencies", ("requirements.txt", "monitoring/requirements.txt", "web/requirements.txt")),
    PathRule("control_plane", _svc("change_service", "intent_service", "lifecycle_service")),
    PathRule("device_builder", (*_svc(
        "field_registry", "field_validators", "field_commit_service", "device_builder_service",
        "interface_intent_service", "routing_intent_service", "service_policy_intent_service"),
        f"{_SVC}/config_import/**")),
    PathRule("candidate_rendering", (*_svc("candidate_renderer", "candidate_composition", "feature_template_renderer"), "templates/features/**")),
    PathRule("platform_drivers", _svc("platform_drivers", "srlinux_model")),
    PathRule("validation", (f"{_SVC}/validation/**", f"{_SVC}/configuration_validation/**", *_svc("change_validation_service"),
                             "web/core/management/commands/nmas_configuration_validation.py")),
    PathRule("network_config_validation", _svc("network_config_validation")),
    PathRule("planning", (f"{_SVC}/planning/**", *_svc("change_plan_service", "configlet_service"))),
    PathRule("health", (f"{_SVC}/health/**", *_svc("health_service"))),
    PathRule("execution", (f"{_SVC}/execution/**", f"{_SVC}/route_shield/**", f"{_SVC}/maintenance_mode/**", *_svc("execution_service"),
                           "web/core/management/commands/nmas_isis_migration.py",
                           # live proof of exact cEOS compensation (run in the commissioning fixture) and its evidence
                           "web/core/tests/live_ceos_compensation_fixture.py", "docs/evidence/ceos-exact-compensation/**",
                           # V2 Maintenance Mode: its pages, its operator command and its worker (with the worker's timer units)
                           "web/core/maintenance_views.py", "web/core/templates/core/maintenance/**",
                           "web/core/management/commands/nmas_maintenance.py", "web/core/management/commands/maintenance_tick.py",
                           "deploy/systemd/nmas-maintenance-tick.*", "deploy/scripts/install_maintenance_timer.sh")),
    PathRule("raw_configlets", (f"{_SVC}/raw_configlets/**", *_svc("raw_configlet_service"), "web/core/management/commands/raw_verifier_selftest.py")),
    PathRule("bundles", (f"{_SVC}/bundles/**", *_svc("bundle_service"))),
    PathRule("probation_soak", (f"{_SVC}/soak/**", *_svc("soak_service"), "web/core/management/commands/probation_soak_*.py")),
    PathRule("legacy_bootstrap", (f"{_SVC}/bootstrap/**", *_svc("bootstrap_service"), "web/core/management/commands/legacy_bootstrap.py")),
    PathRule("config_workbench", (f"{_SVC}/config_workbench/**", "web/core/templates/core/automation/workbench/**",
                                  *_svc("workbench_service"))),
    PathRule("traffic", (f"{_SVC}/traffic/**", *_svc("traffic_service"), "web/core/templates/core/traffic/**",
                         "web/core/management/commands/traffic_reconcile.py", "web/core/management/commands/traffic_runner_config.py",
                         "deploy/traffic-tools/**", "deploy/systemd/nmas-traffic-runner.*", "deploy/scripts/install_traffic_runner.sh")),
    PathRule("provisioning", (f"{_SVC}/provisioning/**", *_svc("provisioning_service"), "web/core/templates/core/provisioning/**",
                              # PR #69 live acceptance: the NMAS-active managed scope against a disposable NetBox
                              "web/core/tests/live_managed_scope_fixture.py", "labs/managed-scope-isolated/**",
                              "docs/evidence/pr69-managed-scope/**")),
    PathRule("device_lifecycle", (f"{_SVC}/devices/**", "web/core/lifecycle_views.py", "web/core/management/commands/nmas_devices.py")),
    PathRule("device_ztp", (f"{_SVC}/ztp/**", "web/core/ztp_views.py", "web/core/management/commands/nmas_ztp.py",
                            "web/core/templates/core/provisioning/_ztp_panel.html", "web/core/templates/core/provisioning/ztp_networks.html",
                            "labs/ztp-isolated/**", "web/core/tests/fixtures/ztp/**", "docs/evidence/v2-phase3-ztp/**",
                            # V2 Phase 9: governed DHCP relay option 82 and its live proof (relay -> downstream native ZTP)
                            "web/core/tests/live_option82_ztp_fixture.py", "docs/evidence/v2-phase9-closure/option82/**")),
    PathRule("device_commissioning", (f"{_SVC}/isolation/**", f"{_SVC}/commissioning/**", "web/core/commissioning_views.py",
                                      "web/core/templates/core/provisioning/commissioning_device.html",
                                      "web/core/templates/core/provisioning/commissioning_overview.html",
                                      "web/core/tests/live_isolation_commissioning_fixture.py",
                                      "labs/isolation-commissioning-isolated/**", "docs/evidence/v2-phase5-6-isolation-commissioning/**",
                                      # V2 Phase 9: IPv6 admission (OSPFv3 isolation and dual-stack admission) and its live proof
                                      "web/core/tests/live_ipv6_admission_fixture.py", "docs/evidence/v2-phase9-closure/ipv6-admission/**",
                                      # V2 Phase 7 decommission / restoration and Phase 8 outbox consumers (NSOT, topology, monitoring)
                                      f"{_SVC}/decommission/**", "web/core/decommission_views.py",
                                      "web/core/templates/core/provisioning/decommission_device.html",
                                      "web/core/templates/core/provisioning/decommission_overview.html",
                                      "web/core/tests/live_decommission_fixture.py", "labs/decommission-isolated/**",
                                      "docs/evidence/v2-phase7-9/phase7/**",
                                      f"{_SVC}/infrastructure/**", "web/core/infrastructure_views.py",
                                      "web/core/templates/core/infrastructure/**", "web/core/management/commands/nmas_infrastructure.py",
                                      "docs/evidence/v2-phase7-9/phase8/**",
                                      # V2 Phase 9: Ubuntu/FRR trusted-upstream isolation (nftables) and its live proof
                                      "web/core/tests/live_frr_isolation_fixture.py", "labs/frr-isolation-isolated/**",
                                      "docs/evidence/v2-phase9-closure/frr-isolation/**",
                                      # V2 Phase 8 closure: disposable-NetBox reconciliation and path-aware telemetry live proofs
                                      "web/core/tests/live_netbox_reconcile_fixture.py", "web/core/tests/live_dynamic_telemetry_fixture.py",
                                      "docs/evidence/v2-phase8-closure/**")),
    PathRule("management_vrf", (f"{_SVC}/management/vrf.py", f"{_SVC}/management/capability_evidence.py", f"{_SVC}/validation/management_vrf.py")),
    PathRule("device_management", (f"{_SVC}/management/**", "web/core/management_views.py", "web/core/management/commands/nmas_management.py",
                                   "web/core/templates/core/provisioning/management_device.html",
                                   "web/core/templates/core/provisioning/management_overview.html",
                                   "web/core/tests/live_management_fixture.py",
                                   "labs/mgmt-multihoming-isolated/**", "docs/evidence/v2-phase4-management/**")),
    PathRule("config_templates", (f"{_SVC}/config_templates/**", "web/core/templates/core/templates_library/**", "templates/baselines/**",
                                  "web/core/management/commands/nmas_templates.py")),
    PathRule("device_secrets", ("modules/device_credentials.py",)),
    PathRule("credentials", (
        f"{_SVC}/credentials/**", *_svc("credential_service"),
        "web/core/management/commands/rotate_due_credentials.py", "web/core/management/commands/import_device_credential.py",
        "web/core/management/commands/reconcile_device_credential.py", "web/core/management/commands/enroll_service_ssh_key.py",
        "web/core/management/commands/register_operator_ssh_key.py", "web/core/management/commands/render_device_mfa_candidate.py",
        "web/core/management/commands/verify_device_mfa.py", "web/core/management/commands/prepare_r1_mfa_rollout_metadata.py",
        "web/core/management/commands/prepare_ceos_mfa_rollout_metadata.py",
        "web/core/management/commands/prepare_linux_mfa_rollout_metadata.py",
        "web/core/management/commands/r1_mfa_pilot.py", "web/core/management/commands/ceos_mfa_rollout.py",
        "web/core/management/commands/linux_mfa_rollout.py",
        "web/core/templates/core/automation/credentials.html", "monitoring/config/nmas-credential-rotation.*",
        "monitoring/scripts/install_credential_rotation_timer.sh", "monitoring/human_mfa/**",
    )),
    PathRule("identity_security", (
        "web/core/middleware.py", "web/core/signals.py", "web/core/auth_views.py", f"{_SVC}/identity/**",
        "web/core/templates/core/auth/**", "web/core/management/commands/nmas_app_mfa_reset.py",
        "web/core/management/commands/nmas_grant_roles.py",
    )),
    PathRule("capability_framework", (
        f"{_SVC}/capabilities/**", "web/core/management/commands/nmas_capabilities.py",
        # V2 Phase 9 capability closure: the ledger command and the option-82 relay admission gate with its isolated fixture
        "web/core/management/commands/nmas_phase9_ledger.py", *_svc("dhcp_relay_option82"), "labs/phase9-option82-isolated/**",
        "labs/phase9-ceos-isis-isolated/**", "docs/evidence/v2-phase9-closure/ceos-isis/**",
        "labs/phase9-ceos-acl6-isolated/**", "docs/evidence/v2-phase9-closure/ceos-acl6/**",
        "labs/phase9-srlinux-isolated/**", "docs/evidence/v2-phase9-closure/srlinux/**",
        "labs/phase9-frr-isis-isolated/**", "docs/evidence/v2-phase9-closure/frr-isis/**",
        "labs/phase9-frr-nat44-static-isolated/**", "docs/evidence/v2-phase9-closure/frr-nat44-static/**",
        "docs/evidence/v2-phase7-9/phase9/**",
        # V2 Phase 9: a RIP instance disabled in intent, live on cEOS (runs in the decommission fixture's NMAS namespace)
        "web/core/tests/live_disabled_rip_fixture.py", "docs/evidence/v2-phase9-closure/disabled-rip/**",
    )),
    PathRule("web_deployment", ("deploy/**",)),
    PathRule("netbox_ipam", ("modules/netbox_ipam.py", "modules/ipam_context.py", "modules/ipam_evidence.py", "netbox/**", *_svc("nsot_netbox", "device_builder_ipam_service"))),
    PathRule("dhcp", ("dhcp/**", "templates/R2_dhcp_server.cfg.j2", "netbox/scripts/render_nmas_dhcp.py", "netbox/scripts/render_r2_dhcp.py", "netbox/scripts/verify_dhcp_servers.py")),
    PathRule("nsot", (*_svc("nsot_service", "nsot_git", "nsot_live", "nsot_netbox"),
                      # state reconciliation: accepted current state vs NMAS's previous expectation, and its explicit NetBox status projection
                      *_svc("reconciliation_service"), "web/core/management/commands/nmas_reconcile.py")),
    PathRule("monitoring", (
        "monitoring/config/**", "monitoring/grafana/**", "monitoring/scripts/**", "monitoring/docker-compose.yml", "templates/monitoring/**",
        "modules/snmp.py", "modules/syslog.py", "modules/gnmi.py", "modules/netconf.py", "modules/telemetry.py", "modules/cpu_alerts.py",
        "modules/monitoring_config.py",
        "modules/grafana.py", "modules/nmas.py", "modules/linux_telemetry_adapter.py", *_svc("monitoring_service"))),
    PathRule("topology", ("modules/topology.py", "modules/topology_graph.py", "monitoring/scripts/topology_server.py", "monitoring/scripts/provision_topology.py", *_svc("topology_service"))),
    PathRule("notifications", (*_svc("notification_service", "slack_service"), "web/core/management/__init__.py", "web/core/management/commands/__init__.py",
                               "web/core/management/commands/send_test_notification.py", "web/core/management/commands/cleanup_test_notifications.py")),
    PathRule("django_views_api", ("web/core/views.py", "web/core/urls.py", "web/core/context_processors.py", "web/core/admin.py", "web/core/templatetags/**", *_svc("automation_service"))),
    PathRule("ui_presentation", ("web/core/templates/**", "web/core/static/**", "web/core/theme_assets.py", "web/core/theme_registry.py")),
    PathRule("lab_config", ("templates/*.cfg.j2", "inventory.yml", "srlceos01.clab.yml")),
    PathRule("core_automation", ("master.py", "hostserv.py", "address_report.py", "address_report.csv", "modules/__init__.py", "modules/eos_render.py")),
    PathRule("dev_tooling", ("tools/**",)),
    PathRule("test_governance", (f"{_SVC}/test_governance/**", "web/core/management/commands/nmas_test_governance.py", "web/core/test_governance_views.py",
                                 "web/core/templates/core/quality/**", ".coveragerc", ".pylintrc", "requirements-ci.txt",
                                 "web/core/tests/fixtures/test_governance/**")),
    PathRule("challenge_console", ("challenge_console/**", "scripts/run_challenge_console.sh", "web/core/tests/test_challenge_console.py")),
    PathRule("lab_verifiers", ("monitoring/tests/verify_*", "netbox/scripts/verify_*", "netbox/scripts/compare_live_state.py")),
    PathRule("tests_django", ("web/core/tests/test_*.py",)),
    PathRule("tests_support", ("web/core/tests/helpers/**", "web/core/tests/__init__.py", "web/core/tests/runner.py")),
    PathRule("tests_monitoring", ("monitoring/tests/test_*.py",)),
    PathRule("ci_engine", (f"{_SVC}/ci/**", *_svc("ci_service"), "web/core/tests/test_tier3_*.py")),
    PathRule("ci_workflow", (
        ".github/**", "tier3.py", "scripts/ci/**",
        ".gitleaks.toml", ".gitleaksignore", ".pre-commit-config.yaml",
        "PUBLIC_CI_SNAPSHOT.json",
    )),
    PathRule("documentation", ("docs/**", "*.md")),
    PathRule("repo_meta", (".gitignore", ".gitattributes")),
    PathRule("runtime_artifacts", ("Run_Logs.log", "logs/**", "**/__pycache__/**", "__pycache__/**", "**/*.pyc", "monitoring/runtime/**", "web/db.sqlite3", "web/staticfiles/**")),
)


@lru_cache(maxsize=None)
def _regex(pattern: str) -> re.Pattern:
    """Glob -> regex: ``**`` spans directories, ``*`` and ``?`` never cross ``/``."""
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("".join(out) + r"\Z")


def glob_match(pattern: str, path: str) -> bool:
    return bool(_regex(pattern).match(path))


# --- cross-subsystem impact (curated, direct edges; expansion is transitive) ------------------

@dataclass(frozen=True)
class Edge:
    source: str
    consumer: str
    reason: str


IMPACT_EDGES: tuple[Edge, ...] = (
    Edge("models_schema", "control_plane", "Change / intent persistence is model-backed"),
    Edge("models_schema", "validation", "validation reads accepted intent and persists ChangeValidationRun"),
    Edge("models_schema", "network_config_validation", "network configuration evidence is model-backed"),
    Edge("models_schema", "planning", "ChangePlan / Configlet persistence is model-backed"),
    Edge("models_schema", "health", "OperationalCheckRun persistence is model-backed"),
    Edge("models_schema", "execution", "ChangeExecutionRun / ConfigletExecutionResult / device-lock persistence is model-backed"),
    Edge("models_schema", "raw_configlets", "Raw Configlet / revision / verification-run persistence is model-backed"),
    Edge("models_schema", "bundles", "ConfigurationBundle / item persistence, constraints and immutability guards are model-backed"),
    Edge("models_schema", "notifications", "Notification persistence is model-backed"),
    Edge("models_schema", "django_views_api", "views and admin query the models"),
    Edge("migrations", "models_schema", "a migration must stay consistent with the model definitions"),
    Edge("platform_drivers", "candidate_rendering", "snippets are rendered through the platform drivers"),
    Edge("platform_drivers", "validation", "the capability registries are validation sources"),
    Edge("platform_drivers", "network_config_validation", "configuration syntax and feature support are platform-specific"),
    Edge("platform_drivers", "planning", "plan snippets use the same drivers as the Device Builder preview"),
    Edge("platform_drivers", "health", "SR Linux gNMI state reads decode through the shared SR Linux set-path model"),
    Edge("platform_drivers", "execution", "the SR Linux executor derives its Set and its inverse from the shared SR Linux set-path model"),
    Edge("candidate_rendering", "device_builder", "the Device Builder preview and download consume the one renderer"),
    Edge("candidate_rendering", "planning", "plan snippets reuse the candidate renderer"),
    Edge("control_plane", "device_builder", "the editor operates on Change / DeviceIntent state"),
    Edge("control_plane", "validation", "validation snapshots the accepted intent of a Change"),
    Edge("device_builder", "validation", "validation snapshots the accepted intent the Device Builder commits"),
    Edge("validation", "planning", "plan eligibility and pinning derive from the validation run"),
    Edge("planning", "health", "precheck / postcheck requirements derive from the plan descriptors"),
    Edge("planning", "execution", "execution runs the plan's Configlets in the plan's own order and reads their frozen descriptors"),
    Edge("health", "execution", "execution requires a permitting precheck and verifies with the Phase-15 postcheck engine and live reads"),
    Edge("validation", "execution", "the AUTO-address recheck reuses the Phase-13 addressing derivation and validation currency"),
    Edge("network_config_validation", "execution", "execution requires current passing network-configuration evidence and records live validation"),
    Edge("raw_configlets", "validation", "validation snapshots the effective raw input and verification status and validates raw metadata"),
    Edge("raw_configlets", "planning", "the plan pins exact raw revisions and verification runs and builds opaque Configlets from them"),
    Edge("raw_configlets", "execution", "execution re-reads the pinned raw revision, re-checks its verification and forbids Complete for raw"),
    Edge("execution", "bundles", "a UAT bundle is sealed from a finished Partial (UAT) run, its results, scope and recorded outcome"),
    Edge("planning", "bundles", "a bundle pins the historical plan's frozen Configlets and dependency edges"),
    Edge("health", "bundles", "a bundle pins the postcheck evidence and verification quality of the run"),
    Edge("raw_configlets", "bundles", "a bundle pins exact raw revisions and verification runs and reuses the static gate's secret detector"),
    Edge("models_schema", "probation_soak", "soak run / sample / decision persistence, constraints and immutability guards are model-backed"),
    Edge("bundles", "probation_soak", "a soak observes an immutable Probation bundle and re-verifies its integrity on every tick"),
    Edge("probation_soak", "bundles", "the evidence-checked promotion in the bundle package reads the soak's evidence and digest"),
    Edge("health", "probation_soak", "samples reuse the Phase-15 collector, postcheck engine and telemetry checks"),
    Edge("execution", "probation_soak", "interference is detected from the persisted execution history"),
    Edge("notifications", "probation_soak", "soak lifecycle events are published through the notification service"),
    Edge("models_schema", "legacy_bootstrap", "bootstrap run / sample / decision persistence and the provenance constraints are model-backed"),
    Edge("bundles", "legacy_bootstrap", "the baseline candidate and the initial baseline bundle are immutable bundles verified by the bundle integrity check"),
    Edge("legacy_bootstrap", "bundles", "the initial-baseline creation path reads the bootstrap observation's evidence, digest and interference"),
    Edge("probation_soak", "legacy_bootstrap", "the observation reuses the pure soak evaluator, coverage rules, assessment and interference detection"),
    Edge("health", "legacy_bootstrap", "samples reuse the read-only live sessions, Deep-Health checks, evaluators and telemetry"),
    Edge("execution", "legacy_bootstrap", "interference is detected from the persisted execution history"),
    Edge("notifications", "legacy_bootstrap", "bootstrap lifecycle events are published through the notification service"),
    Edge("models_schema", "credentials", "credential policy and rotation audit persistence are model-backed"),
    Edge("config_workbench", "validation", "the removal validator re-derives every removal from the snapshot text"),
    Edge("config_workbench", "network_config_validation", "candidate, removal and running snapshots receive network-configuration validation"),
    Edge("config_workbench", "planning", "removal Configlets are rendered from the re-derived analysis"),
    Edge("config_workbench", "execution", "cEOS removal assessment / compensation and the snapshot guard use the line index"),
    Edge("config_workbench", "health", "the config_paths evidence group verifies removals"),
    Edge("models_schema", "config_templates", "templates and their immutable versions are model-backed"),
    Edge("device_builder", "config_templates", "templates are extracted by the importers and cloned through the intent services"),
    Edge("config_workbench", "config_templates", "extraction and incremental clones use the one read-only capture and the contribution baseline"),
    Edge("candidate_rendering", "config_templates", "a cloned template is rendered by the one Jinja2 candidate renderer"),
    Edge("platform_drivers", "config_templates", "template platform compatibility is derived from the capability registries"),
    Edge("device_secrets", "credentials", "rotation stages / promotes / discards through the protected provider"),
    Edge("device_secrets", "execution", "cEOS execution resolves managed-device passwords through the protected provider"),
    Edge("device_secrets", "health", "cEOS health sessions resolve the same current/pending recovery candidates"),
    Edge("device_secrets", "nsot", "NSOT live reads resolve the same protected credential reference"),
    Edge("netbox_ipam", "validation", "validation reads NetBox for collisions and pool facts"),
    Edge("netbox_ipam", "network_config_validation", "network configuration validation checks IPAM allocation and prefix relationships"),
    Edge("netbox_ipam", "nsot", "NSOT aggregates NetBox read-only"),
    Edge("netbox_ipam", "dhcp", "DHCP pool structure is NetBox-driven"),
    Edge("dhcp", "validation", "validation checks DHCP pool / reservation conflicts"),
    Edge("dhcp", "health", "DHCP service health reuses the DHCP verifier"),
    Edge("topology", "validation", "validation reads the runtime topology metadata"),
    Edge("topology", "nsot", "NSOT consumes topology relationships"),
    Edge("topology", "health", "Fleet Quick reads the topology service"),
    Edge("monitoring", "health", "health thresholds and telemetry come from the monitoring configuration"),
    Edge("lab_config", "validation", "validation reads the fixed project inventory"),
    Edge("lab_config", "health", "the managed device inventory drives health scope"),
    Edge("lab_config", "topology", "topology is reconciled against the deployed lab definition"),
    Edge("models_schema", "identity_security", "website MFA / audit request fields / role permissions are model-backed"),
    Edge("identity_security", "django_views_api", "every view runs behind the access middleware and attributes actions through it"),
    Edge("models_schema", "capability_framework", "empirical capability evidence is model-backed"),
    Edge("platform_drivers", "capability_framework", "renderer / Device Builder axes are read from the platform drivers"),
    Edge("execution", "capability_framework", "live write / post-write / compensation axes are read from the execution registries"),
    Edge("device_builder", "capability_framework", "the parser axis is read from config_import"),
    Edge("models_schema", "device_lifecycle", "managed devices, attachments, observations, authorizations and the event chain are model-backed"),
    Edge("lab_config", "device_lifecycle", "the resolver and adoption read the tracked inventory and topology"),
    Edge("provisioning", "device_lifecycle", "name collisions and the resolver read the provisioning registry"),
    Edge("netbox_ipam", "device_lifecycle", "the read-only NetBox device / cable reader and projection"),
    Edge("capability_framework", "device_lifecycle", "lifecycle capabilities use the capability vocabulary"),
    Edge("device_lifecycle", "device_ztp", "ZTP correlates into observations, consumes bootstrap authorizations and drives the BOOTSTRAP edge"),
    Edge("models_schema", "device_ztp", "bootstrap networks, sessions, artifacts, deliveries, leases and DHCP applications are model-backed"),
    Edge("device_secrets", "device_ztp", "the per-session enrollment key is held by the protected device-secret provider"),
    Edge("identity_security", "device_ztp", "every ZTP route and command carries an RBAC permission"),
    Edge("device_lifecycle", "device_management", "paths belong to managed devices, use their attachments and the shared resolver"),
    Edge("device_ztp", "device_management", "bootstrap credential retirement replaces the ZTP enrollment credential"),
    Edge("models_schema", "device_management", "attachments, paths, probes, transitions, state and credential transitions are model-backed"),
    Edge("device_secrets", "device_management", "probes and credential retirement read / retire provider-held keys"),
    Edge("identity_security", "device_management", "every management route and command carries an RBAC permission"),
    Edge("device_lifecycle", "device_commissioning", "isolation, commissioning and admission drive the ISOLATE / COMMISSION* lifecycle edges"),
    Edge("device_ztp", "device_commissioning", "native ZTP is gated on a verified isolation policy and commissioning reads the ZTP session"),
    Edge("device_management", "device_commissioning", "commissioning requires a completed bootstrap credential retirement and uses the pinned transport"),
    Edge("provisioning", "device_commissioning", "production configuration is an ordinary provisioning run (Device Builder candidate, execution engine)"),
    Edge("execution", "device_commissioning", "isolation is applied and released through the cEOS executor's governed transaction"),
    Edge("models_schema", "device_commissioning", "policies, checks, dependencies, commissioning records, admissions and outbox events are model-backed"),
    Edge("identity_security", "device_commissioning", "every isolation / commissioning / admission route carries an RBAC permission"),
    Edge("models_schema", "traffic", "the immutable run evidence and the one-active-run constraint are model-backed"),
    Edge("health", "traffic", "the endpoint catalogue reads the tracked inventory and the ICMP bounds / ping parser are the health engine's"),
    Edge("models_schema", "provisioning", "the request, its append-only stage events and the device registry are model-backed"),
    Edge("capability_framework", "provisioning", "provisioning is gated on the terminal Phase-4 capability status of every planned feature"),
    Edge("control_plane", "provisioning", "the candidate is an ordinary Change with a NEW_DEVICE intent"),
    Edge("validation", "provisioning", "the candidate must pass Change validation"),
    Edge("network_config_validation", "provisioning", "the candidate must pass network-configuration validation"),
    Edge("planning", "provisioning", "the provisioning plan is the ordinary Change plan"),
    Edge("health", "provisioning", "precheck and postcheck are the Phase-15 engine"),
    Edge("execution", "provisioning", "the approved plan runs through the execution engine"),
    Edge("bundles", "provisioning", "a provisioned scope is sealed into UAT / Probation bundles"),
    Edge("probation_soak", "provisioning", "a provisioned device enters the normal probation soak"),
    Edge("models_schema", "challenge_console", "the console's read-only automation transport names model tables and columns"),
    Edge("migrations", "challenge_console", "a migration can rename or drop a column the console's fixed SELECT statements read"),
    Edge("probation_soak", "challenge_console", "the console reports soak collector freshness and eligibility with the soak overview's own rules"),
    Edge("health", "challenge_console", "the console classifies telemetry freshness with the health engine's thresholds"),
    Edge("lab_config", "challenge_console", "the probed endpoints and the managed-device list are read from the tracked inventory"),
)

# A change here can affect every Django-side subsystem: the impact is "django-wide", not chain-shaped.
BROADENING = ("shared_core", "django_project", "dependencies", "tests_support")
DJANGO_WIDE_CONSUMERS = (
    "control_plane", "device_builder", "candidate_rendering", "platform_drivers", "validation", "network_config_validation", "planning", "health", "execution", "raw_configlets",
    "bundles", "probation_soak", "legacy_bootstrap", "credentials", "config_workbench", "config_templates", "netbox_ipam", "nsot", "topology", "notifications", "django_views_api", "ui_presentation",
    "identity_security", "capability_framework", "provisioning", "traffic", "device_lifecycle", "device_ztp", "device_management", "management_vrf",
    "device_commissioning",
)


# --- what each subsystem directly requires -----------------------------------------------------

@dataclass(frozen=True)
class Selection:
    django: tuple[str, ...] = ()   # test modules under core.tests
    full_django: bool = False      # broad gate: the whole ``core`` suite
    monitoring_unit: bool = False  # monitoring/tests + NetBox script unit tests (offline)
    grafana_drift: bool = False    # generated Grafana JSON drift check (offline)
    lab: tuple[str, ...] = ()      # lab verifier ids (optional unless --lab)
    reason: str = ""


P13 = ("phase13_addressing", "phase13_architecture", "phase13_capabilities", "phase13_dependencies", "phase13_engine", "phase13_routing",
       "phase13_services_policy", "phase13_snapshot", "phase13_sources", "phase13_topology", "phase13_validation_runs", "phase13_views")
RENDERERS = ("candidate_renderer", "interface_renderer", "routing_renderer", "phase12_service_policy")
VIEW_SET = ("view_boundaries", "routes", "navigation", "services", "admin_surface", "editor_views", "change_plan_views", "health_views",
            "execution_views", "raw_views", "bundle_views", "soak_views", "bootstrap_views", "phase13_views", "notification_views")

SELECTIONS: dict[str, Selection] = {
    "models_schema": Selection(full_django=True, reason="models are foundational: model, migration and every consumer contract"),
    "migrations": Selection(full_django=True, reason="a migration changes the schema every consumer relies on"),
    "shared_core": Selection(full_django=True, reason="shared core utility used across the Django services"),
    "django_project": Selection(full_django=True, reason="Django project configuration affects the whole application"),
    "dependencies": Selection(full_django=True, monitoring_unit=True, reason="a dependency manifest can change behavior anywhere"),
    "tests_support": Selection(full_django=True, reason="shared test helpers are used by most Django test modules"),
    "control_plane": Selection(django=("control_plane", "field_commit", "contracts", "view_boundaries"), reason="Change / intent control plane changed"),
    "device_builder": Selection(
        django=("field_validators", "field_commit", "interface_service", "routing_service", "phase12_service_policy", "capabilities",
                "editor_views", "js_contract", "view_boundaries", "contracts"),
        reason="Device Builder intent / validator code changed"),
    "candidate_rendering": Selection(django=(*RENDERERS, "contracts"), reason="candidate renderer or feature template changed"),
    "platform_drivers": Selection(django=("capabilities", *RENDERERS, "phase13_capabilities", "contracts"), reason="platform driver / capability matrix changed"),
    "validation": Selection(django=(*P13, "configuration_validation", "execution_engine", "raw_integration", "contracts"),
                            reason="Tier-2 validation engine changed"),
    "network_config_validation": Selection(
        django=("network_config_validation", "phase2_ospf_networks", "config_workflows", "execution_engine", "phase13_addressing", "phase13_routing", "contracts"),
        reason="network-device configuration validation or live validation evidence changed",
    ),
    "planning": Selection(django=("change_plan_service", "change_plan_views", "change_precheck", "control_plane", "raw_integration", "contracts"),
                          reason="plan builder / Configlet code changed"),
    "health": Selection(django=("health_engine", "health_sources", "health_views", "change_precheck", "change_plan_service", "contracts"),
                        reason="health / precheck / postcheck code changed"),
    "execution": Selection(django=("execution_engine", "execution_executors", "execution_views", "change_precheck", "raw_integration", "contracts",
                                   "maintenance_mode", "maintenance_live", "maintenance_web", "maintenance_sandbox"),
                           reason="structured execution engine / executors / Maintenance Mode changed"),
    "raw_configlets": Selection(django=("raw_configlets", "raw_sandbox", "raw_integration", "raw_views", "contracts"),
                                reason="Raw Configlet models / static gate / verifier / sandbox adapters / integration changed"),
    "bundles": Selection(django=("bundles", "bundle_views", "soak", "soak_decision", "contracts"), reason="immutable configuration bundle service / integrity / export changed"),
    "probation_soak": Selection(django=("soak", "soak_decision", "soak_views", "bundles", "bundle_views", "health_engine", "contracts"),
                                reason="probation soak evidence / evaluator / collector / operator decision changed"),
    "legacy_bootstrap": Selection(django=("bootstrap", "bootstrap_views", "bundles", "bundle_views", "soak", "health_engine", "health_sources", "contracts"),
                                  reason="one-time legacy baseline bootstrap capture / observation / approval changed"),
    "traffic": Selection(django=("traffic", "traffic_runner", "traffic_views", "web_deployment", "contracts"),
                         reason="traffic workbench validation / bounds / runner IPC / process boundary / parsers / run evidence changed"),
    "provisioning": Selection(
        # its own suites drive the real validation / plan / precheck / execution / bundle / soak services end to end, so an upstream
        # change that reaches provisioning is proven here without re-selecting each upstream suite
        django=("provisioning", "provisioning_views", "contracts"),
        reason="new-device provisioning workflow / capability gate / IPAM reservation / device registry changed",
    ),
    "device_lifecycle": Selection(
        django=("lifecycle_identity", "lifecycle_service", "lifecycle_authorization", "lifecycle_resolver", "lifecycle_views",
                "lifecycle_capability_vocabulary", "contracts"),
        reason="managed-device identity / lifecycle / attachments / bootstrap authorization / resolver changed",
    ),
    "device_ztp": Selection(
        django=("ztp_adapters", "ztp_dhcp", "ztp_discovery", "ztp_artifacts", "ztp_workflow", "ztp_views", "lifecycle_service",
                "lifecycle_authorization", "lifecycle_views", "lifecycle_capability_vocabulary", "contracts"),
        reason="native ZTP adapters / isolated DHCP providers / discovery / artifact delivery / management verification changed",
    ),
    "device_management": Selection(
        # the resolver's consumers (nsot_live, health live sessions, execution PREPARE) are exercised by management_paths'
        # own integration cases: impact edges to them would make every lifecycle change pull the execution suites
        django=("management_paths", "management_views", "bootstrap_retirement", "lifecycle_capability_vocabulary", "contracts"),
        reason="management paths / probes / selector / resolver / bootstrap credential retirement changed",
    ),
    "device_commissioning": Selection(
        django=("isolation_eos", "isolation_service", "commissioning", "commissioning_dependencies", "commissioning_views",
                "tg_isolation_closure", "tg_commissioning_closure", "tg_commissioning_views_closure", "tg_phase56_platform_fixes",
                "provisioning", "lifecycle_service", "lifecycle_capability_vocabulary", "ztp_workflow", "bootstrap_retirement", "contracts",
                "decommission_service", "tg_phase7_closure", "tg_phase7_views_closure", "tg_phase79_gap_closure", "tg_phase9_live_runner_closure",
                "infrastructure_fixtures", "infrastructure_flow", "tg_phase8_closure"),
        reason="trusted-upstream isolation / commissioning / decommission / restoration / dependency graph / admission / outbox changed",
    ),
    "management_vrf": Selection(
        django=("management_vrf", "management_views", "candidate_renderer", "configuration_validation", "change_plan_service",
                "execution_executors", "config_import", "lifecycle_capability_vocabulary", "contracts"),
        reason="management VRF intent / rendering / validation / Configlets / cEOS inverse / import changed",
    ),
    "config_templates": Selection(
        django=("config_templates", "config_templates_views", "config_import", "config_workflows", "capability_framework", "contracts"),
        reason="template extraction / parameterization / baselines / package exchange / clone changed",
    ),
    "config_workbench": Selection(
        django=("config_workbench", "config_workflows", "execution_executors", "execution_engine", "health_engine", "change_plan_service"),
        reason="Configuration Changes / Remove Configuration analysis, snapshots or workbench pages changed",
    ),
    "device_secrets": Selection(
        django=("credential_rotation", "device_mfa", "r1_mfa_pilot", "ceos_mfa_rollout", "linux_mfa_rollout",
                "execution_executors", "health_sources", "nsot"),
        monitoring_unit=True,
        reason="protected runtime device-secret provider changed",
    ),
    "credentials": Selection(
        django=("credential_rotation", "device_mfa", "r1_mfa_pilot", "ceos_mfa_rollout", "linux_mfa_rollout",
                "routes", "admin_surface", "contracts"),
        reason="managed-device credential metadata / rotation policy / engine / scheduler / 2FA policy changed",
    ),
    "identity_security": Selection(full_django=True, reason="the access middleware / identity layer sits in front of every view"),
    "capability_framework": Selection(django=("capability_framework", "capabilities", "transport_capability", "contracts",
                                              "phase9_option82", "tg_phase9_closure", "tg_phase9_live_runner_closure"),
                                      reason="capability evidence aggregation / Phase 9 ledger / option-82 admission changed"),
    "web_deployment": Selection(django=("web_deployment",), reason="website hosting templates changed (static safety checks + deploy check)"),
    "netbox_ipam": Selection(django=("nsot", "ipam_refresh", "phase13_sources", "phase13_addressing", "contracts"), monitoring_unit=True,
                             lab=("netbox_model", "netbox_populate", "reservations"), reason="NetBox / IPAM integration changed"),
    "dhcp": Selection(django=("phase13_services_policy", "health_sources"), monitoring_unit=True, lab=("dhcp", "reservations"), reason="DHCP rendering / verification changed"),
    "nsot": Selection(django=("nsot", "contracts"), reason="NSOT aggregation changed"),
    "monitoring": Selection(django=("monitoring_integration", "topology_integration", "health_sources"), monitoring_unit=True, grafana_drift=True,
                            lab=("grafana", "nmas"), reason="monitoring code / configuration changed"),
    "topology": Selection(django=("topology_integration", "phase13_topology", "health_sources", "topology_source"), monitoring_unit=True, lab=("topology",), reason="topology code changed"),
    "notifications": Selection(django=("notifications", "notification_views", "notification_commands", "notification_model", "slack_service", "secret_policy"),
                               reason="notification / Slack code changed"),
    "django_views_api": Selection(django=(*VIEW_SET, "contracts"), reason="Django route / view boundary changed"),
    "ui_presentation": Selection(
        django=("themes", "artwork", "navigation", "js_contract", "routes", "view_boundaries", "editor_views", "topology_integration",
                "monitoring_integration", "notification_views", "change_plan_views", "health_views", "execution_views", "raw_views", "bundle_views", "soak_views", "bootstrap_views", "phase13_views", "nsot"),
        reason="template / static / theme asset changed"),
    "lab_config": Selection(django=("phase13_sources", "phase13_topology", "health_sources", "topology_source", "contracts"), monitoring_unit=True,
                            lab=("topology", "dhcp"), reason="frozen Lab-1 configuration / inventory changed"),
    "core_automation": Selection(monitoring_unit=True, reason="core automation / orchestrator changed"),
    "dev_tooling": Selection(django=("phase_integrate",), reason="developer phase-integration tooling changed (its own contract / safety tests)"),
    "test_governance": Selection(django=("test_governance", "tg_templates", "tg_artifacts", "tier3_execution", "tier3_selection"), reason="Lab 7 test governance (catalog / tracer / coverage / Pylint / evidence pages) changed"),
    "challenge_console": Selection(django=("challenge_console",),
                                   reason="standalone challenge console changed (its own suite plus the schema / vocabulary contract with the website)"),
    "tests_monitoring": Selection(monitoring_unit=True, reason="a monitoring / NetBox unit test changed"),
    "lab_verifiers": Selection(reason="a live lab verifier script changed (syntax-checked; it only runs against the real lab)"),
    "ci_engine": Selection(django=("tier3_changes", "tier3_selection", "tier3_execution", "contracts"), reason="Tier-3 validation engine changed"),
    "ci_workflow": Selection(django=("tier3_execution",), reason="GitHub workflow / launcher changed (workflow contract test)"),
}

# Specific files that tests read as fixtures.  ``(pattern, django test module, reason)``.
PATH_SELECTIONS: tuple[tuple[str, str, str], ...] = (
    # Lab 7: every deployed template / structured / executable artifact has generated cases in these suites
    ("templates/**", "tg_templates", "a network template's generated render / StrictUndefined cases"),
    ("dhcp/*.j2", "tg_templates", "a DHCP template's generated render / StrictUndefined cases"),
    ("inventory.yml", "tg_templates", "the Lab-1 templates render from the tracked inventory"),
    ("inventory.yml", "tg_artifacts", "the inventory's loader cases"),
    ("inventory.yml", "lifecycle_resolver", "the managed-device resolver's scope / candidate cases read the tracked inventory"),
    ("web/core/services/health/inventory.py", "lifecycle_resolver", "the resolver builds on the health inventory loaders"),
    ("web/core/services/devices/resolver.py", "health_sources", "health inventory managed_devices() resolves through the shared resolver"),
    ("web/core/services/devices/resolver.py", "nsot", "live NSOT target metadata resolves through the shared resolver"),
    ("web/core/services/capabilities/**", "lifecycle_capability_vocabulary", "the four-value vocabulary is derived from the ledger"),
    ("web/core/services/ztp/adapters/**", "lifecycle_capability_vocabulary", "per-platform ZTP capability rows derive from adapter evidence"),
    ("docs/evidence/v2-phase3-ztp/**", "lifecycle_capability_vocabulary", "a SUPPORTED native-ZTP row requires its committed live evidence file"),
    ("monitoring/config/**", "tg_artifacts", "a monitoring policy's loader cases"),
    ("netbox/ipam.yml", "tg_artifacts", "the NetBox manifest's loader cases"),
    ("templates/baselines/**", "tg_artifacts", "a baseline package's loader cases"),
    ("deploy/**", "tg_artifacts", "a deployment script / unit's static cases"),
    ("**/*.sh", "tg_artifacts", "a shell script's static cases"),
    ("**/docker-compose.yml", "tg_artifacts", "a stack definition's structure case"),
    ("docs/CHANGE_VALIDATION_AND_DEPENDENCIES.md", "phase13_architecture", "a test asserts this document's content"),
    ("docs/CURRENT_STATE.md", "phase13_architecture", "a test asserts this document's Phase-13 note"),
    ("docs/GITHUB_ACTIONS_TIER3_VALIDATION.md", "tier3_execution", "a test asserts this document's content"),
    ("docs/RAW_CONFIGLETS_AND_SANDBOX.md", "raw_configlets", "a test asserts this document's content"),
    ("docs/IMMUTABLE_CONFIGURATION_BUNDLES.md", "bundles", "a test asserts this document's content"),
    ("docs/PROBATION_SOAK_AND_PROMOTION.md", "soak", "a test asserts this document's content"),
    ("docs/PHASE_INTEGRATION_WORKFLOW.md", "phase_integrate", "a test asserts this document's content"),
)

# Lab verifiers: id -> (title, relative script, extra argv, interpreter).  Real external systems; explicit opt-in.
LAB_VERIFIERS: dict[str, tuple[str, str, tuple[str, ...], str]] = {
    "grafana": ("Grafana dashboards / datasource / queries", "monitoring/tests/verify_grafana.py", ("--verbose",), "python"),
    "topology": ("NetworkX topology service", "monitoring/tests/verify_topology.py", (), "python"),
    "netbox_model": ("NetBox model", "netbox/scripts/verify_netbox_model.py", (), "python"),
    "netbox_populate": ("NetBox seed drift (dry run)", "netbox/scripts/populate_netbox.py", ("--check",), "python"),
    "reservations": ("DHCP reservations / VLAN 200 static", "netbox/scripts/verify_reservations.py", (), "python"),
    "dhcp": ("DHCP servers (NMAS / R2)", "netbox/scripts/verify_dhcp_servers.py", (), "python"),
    "nmas": ("NMAS monitoring infrastructure", "monitoring/tests/verify_nmas_infrastructure.sh", (), "bash"),
}

# Path-level warnings derived from the diff status (never for a synthetic all-tracked change set).
WARN_FROZEN = "FROZEN_LAB_PATH_CHANGED"
WARN_RUNTIME = "RUNTIME_ARTIFACT_CHANGED"
WARN_MIGRATION = "MIGRATION_HISTORY_MODIFIED"
WARN_UNCLASSIFIED = "UNCLASSIFIED_PATH"
WARN_BASE_FALLBACK = "BASE_FALLBACK"
