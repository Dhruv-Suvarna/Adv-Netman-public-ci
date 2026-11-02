"""Tier-3 change-effect analysis: classification, impact expansion and check selection.

The mapping tables live in ``core.services.ci.rules``; these tests pin the *behavior* they must produce.
Add a row to a matrix here rather than a new method (docs/TEST_SUITE_RATIONALIZATION.md, section 16).
"""

from __future__ import annotations

import random
from pathlib import Path

from django.test import SimpleTestCase

from core.services.ci import catalog, classify, gitio, planner, rules
from core.services.ci.constants import Gate, Mode
from core.tests.helpers.tier3 import change_set

WEB_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = WEB_ROOT.parent
BASELINE = {"static.hygiene", "static.syntax", "django.check", "django.migrations", "governance.catalog"}  # Lab 7: the catalog gate runs for every change
T = "core.tests.test_"


def plan_for(*files, mode=Mode.TARGETED, include_lab=False, strategy="merge-base"):
    return planner.build_plan(change_set(*files, strategy=strategy), mode=mode, include_lab=include_lab)


def required_ids(plan) -> set[str]:
    return {c.id for c in plan.required}


def labels_of(plan) -> set[str]:
    return set(next((c.params["labels"] for c in plan.required if c.id == "django.tests"), []))


class ClassificationTests(SimpleTestCase):
    def test_path_classification_matrix(self):
        rows = [
            ("web/core/models.py", {"models_schema"}),
            ("web/core/migrations/0005_phase15_operational_check_run.py", {"migrations"}),
            ("web/core/services/validation/engine.py", {"validation"}),
            ("web/core/services/change_validation_service.py", {"validation"}),
            ("web/core/services/planning/builder.py", {"planning"}),
            ("web/core/services/health/evaluators.py", {"health"}),
            ("web/core/services/platform_drivers.py", {"platform_drivers"}),
            ("templates/features/ceos/routing_bgp.j2", {"candidate_rendering"}),
            ("dhcp/dhcpd.conf.j2", {"dhcp"}),
            ("monitoring/config/topology.yml", {"monitoring"}),
            ("monitoring/config/rsyslog-lab-monitoring.conf", {"monitoring"}),
            ("monitoring/human_mfa/docker-compose.yml", {"credentials"}),
            ("monitoring/grafana/provisioning/dashboards/json/fleet-overview.json", {"monitoring"}),
            ("netbox/ipam.yml", {"netbox_ipam"}),
            ("templates/R1.cfg.j2", {"lab_config"}),
            ("templates/R2_dhcp_server.cfg.j2", {"lab_config", "dhcp"}),  # one path, two subsystems
            ("netbox/scripts/render_r2_dhcp.py", {"netbox_ipam", "dhcp"}),
            ("netbox/scripts/verify_netbox_model.py", {"netbox_ipam", "lab_verifiers"}),
            ("modules/topology.py", {"topology"}),
            ("monitoring/scripts/topology_server.py", {"monitoring", "topology"}),
            ("web/core/views.py", {"django_views_api"}),
            ("web/core/templates/core/base.html", {"ui_presentation"}),
            ("web/core/static/core/js/device_builder.js", {"ui_presentation"}),
            ("modules/device_credentials.py", {"device_secrets"}),
            ("web/core/services/credentials/mfa.py", {"credentials"}),
            ("web/core/management/commands/verify_device_mfa.py", {"credentials"}),
            ("web/core/management/commands/nmas_capabilities.py", {"capability_framework"}),
            ("modules/ipam_evidence.py", {"netbox_ipam"}),
            ("web/core/tests/test_health_engine.py", {"tests_django"}),
            ("web/core/tests/helpers/validation.py", {"tests_support"}),
            ("monitoring/tests/test_grafana.py", {"tests_monitoring"}),
            ("monitoring/tests/verify_topology.py", {"lab_verifiers"}),  # a lab verifier is not monitoring source
            ("web/core/tests/test_tier3_selection.py", {"tests_django", "ci_engine"}),
            ("web/core/services/ci/rules.py", {"ci_engine"}),
            (".github/workflows/tier3-validation.yml", {"ci_workflow"}),
            ("PUBLIC_CI_SNAPSHOT.json", {"ci_workflow"}),
            ("tier3.py", {"ci_workflow"}),
            ("docs/CURRENT_STATE.md", {"documentation"}),
            ("README.md", {"documentation"}),
            ("Run_Logs.log", {"runtime_artifacts"}),
            ("logs/R2.log", {"runtime_artifacts"}),
            ("web/core/services/__pycache__/x.cpython-312.pyc", {"runtime_artifacts"}),
            ("master.py", {"core_automation"}),
            ("tools/phase_integrate.py", {"dev_tooling"}),
            ("challenge_console/collectors/connectivity.py", {"challenge_console"}),
            ("challenge_console/tests/test_core.py", {"challenge_console"}),
            ("scripts/run_challenge_console.sh", {"challenge_console"}),
            ("web/core/tests/test_challenge_console.py", {"tests_django", "challenge_console"}),
            ("requirements.txt", {"dependencies"}),
            ("totally/unknown/file.bin", {rules.UNCLASSIFIED}),
            ("web/core/services/brand_new_service.py", {rules.UNCLASSIFIED}),  # a new module nobody classified is never "nothing to test"
        ]
        for path, expected in rows:
            with self.subTest(path=path):
                self.assertEqual(set(classify.classify_path(path)), expected)

    def test_glob_semantics(self):
        rows = [("a/*.py", "a/x.py", True), ("a/*.py", "a/b/x.py", False), ("a/**", "a/b/c/x.py", True), ("**/x.pyc", "x.pyc", True),
                ("**/x.pyc", "a/b/x.pyc", True), ("a?.py", "ab.py", True), ("a?.py", "a/.py", False), ("docs/**", "docs2/x", False), ("*.md", "docs/x.md", False)]
        for pattern, path, expected in rows:
            with self.subTest(pattern=pattern, path=path):
                self.assertEqual(rules.glob_match(pattern, path), expected)

    def test_every_repository_file_has_a_classification_rule(self):
        # Drift guard: a new top-level area must get a rule (or it silently forces the full gate forever).
        try:
            raw = gitio.run_git(REPO_ROOT, ["ls-files", "-co", "--exclude-standard", "-z"])
        except gitio.GitError:
            self.skipTest("not a git checkout")
        unclassified = [p for p in raw.split("\0") if p and classify.classify_path(p) == (rules.UNCLASSIFIED,)]
        self.assertEqual(unclassified, [], "add a PathRule in core/services/ci/rules.py for these paths")

    def test_rule_tables_are_consistent_and_point_at_real_things(self):
        ids = set(rules.SUBSYSTEMS)
        self.assertTrue({r.subsystem for r in rules.PATH_RULES} <= ids)
        self.assertTrue(set(rules.SELECTIONS) <= ids)
        for edge in rules.IMPACT_EDGES:
            with self.subTest(edge=f"{edge.source}->{edge.consumer}"):
                self.assertIn(edge.source, ids)
                self.assertIn(edge.consumer, ids)
                self.assertTrue(edge.reason)
        for sub in rules.SUBSYSTEM_LIST:
            if sub.kind == rules.SOURCE:
                with self.subTest(source_subsystem=sub.id):
                    self.assertIn(sub.id, rules.SELECTIONS, "a source subsystem must always require something")
        modules = {name for sel in rules.SELECTIONS.values() for name in sel.django} | {name for _p, name, _r in rules.PATH_SELECTIONS}
        for name in sorted(modules):
            with self.subTest(test_module=name):
                self.assertTrue(catalog.valid_test_module(f"test_{name}"))
                self.assertTrue((WEB_ROOT / "core" / "tests" / f"test_{name}.py").is_file(), f"core.tests.test_{name} does not exist")
        for key, (_title, script, _extra, interpreter) in rules.LAB_VERIFIERS.items():
            with self.subTest(lab=key):
                self.assertTrue((REPO_ROOT / script).is_file())
                self.assertIn(f"lab.{key}", catalog.CHECKS)
                self.assertIn(interpreter, ("python", "bash"))
        for sel in rules.SELECTIONS.values():
            self.assertTrue(set(sel.lab) <= set(rules.LAB_VERIFIERS))
        self.assertEqual({c.gate for c in catalog.CHECK_LIST} - set(Gate.ALL), set())


class ImpactExpansionTests(SimpleTestCase):
    def test_impact_matrix(self):
        rows = [
            # (directly changed, must be impacted, must NOT be impacted)
            ({"validation"}, {"planning", "health"}, {"models_schema", "device_builder", "topology"}),
            ({"planning"}, {"health"}, {"validation", "device_builder"}),
            ({"health"}, set(), {"planning", "validation"}),
            ({"candidate_rendering"}, {"device_builder", "planning", "validation", "health"}, {"platform_drivers", "topology"}),
            ({"platform_drivers"}, {"candidate_rendering", "device_builder", "validation", "planning", "health"}, {"topology"}),
            ({"models_schema"}, {"validation", "planning", "health", "control_plane", "django_views_api"}, {"topology", "nsot"}),
            ({"migrations"}, {"models_schema", "validation", "planning", "health"}, {"topology"}),
            ({"topology"}, {"validation", "nsot", "health", "planning"}, {"monitoring", "models_schema"}),
            ({"netbox_ipam"}, {"validation", "nsot", "dhcp", "health"}, {"topology"}),
            ({"shared_core"}, set(rules.DJANGO_WIDE_CONSUMERS), {"documentation", "monitoring"}),
            ({"documentation"}, set(), set(rules.SUBSYSTEMS) - {"documentation"}),
            ({"notifications"}, set(), {"validation", "health"}),
            ({"execution"}, {"bundles"}, {"planning", "validation", "models_schema"}),
            ({"raw_configlets"}, {"bundles", "execution"}, {"models_schema", "device_builder"}),
            ({"models_schema"}, {"bundles"}, {"topology", "nsot"}),
            # Phase 23: the provider reaches every device-session consumer; the
            # Django rotation/2FA layer reaches none of them.
            ({"device_secrets"}, {"credentials", "execution", "health", "nsot"}, {"models_schema", "topology"}),
            ({"credentials"}, set(), {"execution", "health", "nsot", "device_secrets"}),
            ({"models_schema"}, {"credentials"}, {"nsot", "device_secrets"}),
            ({"bundles"}, set(), {"execution", "planning", "health", "raw_configlets", "validation", "django_views_api", "notifications"}),
        ]
        for direct, expected, excluded in rows:
            with self.subTest(direct=sorted(direct)):
                impacted = set(classify.expand_impact(direct))
                self.assertTrue(expected <= impacted, f"missing {expected - impacted}")
                self.assertFalse(excluded & impacted, f"unexpected {excluded & impacted}")
                self.assertFalse(direct & impacted)  # a directly changed subsystem is not also "impacted"

    def test_chains_explain_why_and_order_is_stable(self):
        impact = classify.expand_impact({"validation"})
        self.assertEqual(impact["health"].via, ("validation", "planning", "health"))
        self.assertIn("plan descriptors", impact["health"].reason)
        self.assertEqual(list(impact), [s for s in classify.subsystem_order() if s in impact])
        self.assertEqual(classify.expand_impact({"validation", "planning"}), classify.expand_impact({"planning", "validation"}))


class TargetedSelectionTests(SimpleTestCase):
    def test_configuration_change_selection_matrix(self):
        """Real declarative inputs select checks that consume their configuration family."""
        rows = [
            # case, path, direct subsystem, extra checks, meaningful Django consumers
            ("network feature Jinja", "templates/features/ceos/routing_bgp.j2", "candidate_rendering", set(),
             {T + "candidate_renderer", T + "routing_renderer", T + "phase13_routing"}),
            ("DHCP Jinja", "dhcp/dhcpd.conf.j2", "dhcp", {"monitoring.unit"},
             {T + "phase13_services_policy", T + "health_sources"}),
            ("monitoring YAML", "monitoring/config/topology.yml", "monitoring", {"monitoring.unit", "grafana.drift"},
             {T + "monitoring_integration", T + "health_engine", T + "soak"}),
            ("Grafana JSON", "monitoring/grafana/provisioning/dashboards/json/fleet-overview.json", "monitoring",
             {"monitoring.unit", "grafana.drift"}, {T + "monitoring_integration"}),
            ("NetBox desired state", "netbox/ipam.yml", "netbox_ipam", {"monitoring.unit"},
             {T + "ipam_refresh", T + "nsot", T + "phase13_addressing"}),
            ("workflow YAML", ".github/workflows/tier3-validation.yml", "ci_workflow", set(),
             {T + "tier3_execution"}),
        ]
        for case, path, direct, extra, consumers in rows:
            with self.subTest(case=case, path=path):
                plan = plan_for(("modified", path))
                self.assertEqual(plan.direct, [direct])
                self.assertEqual(required_ids(plan) - {"django.tests"}, BASELINE | extra)
                self.assertTrue(consumers <= labels_of(plan), f"missing {consumers - labels_of(plan)}")

    def test_selection_matrix(self):
        rows = [
            # case, changed files, extra required checks, labels (None = no django.tests, "core" = whole suite), labels present / absent
            ("docs only", [("modified", "docs/HEALTH_PRECHECK_POSTCHECK.md")], set(), None, set(), set()),
            ("doc read by a test", [("modified", "docs/CURRENT_STATE.md")], set(), {T + "phase13_architecture"}, set(), set()),
            ("test module only", [("modified", "web/core/tests/test_health_engine.py")], set(), {T + "health_engine"}, set(), set()),
            ("validation engine", [("modified", "web/core/services/validation/engine.py")], set(), "targeted",
             {T + "phase13_engine", T + "change_plan_service", T + "health_engine", T + "contracts"}, {T + "notifications", T + "routes"}),
            ("planning", [("modified", "web/core/services/planning/builder.py")], set(), "targeted",
             {T + "change_plan_service", T + "change_precheck", T + "health_engine"}, {T + "phase13_engine"}),
            ("health", [("modified", "web/core/services/health/evaluators.py")], set(), "targeted",
             {T + "health_engine", T + "change_precheck", T + "change_plan_service"}, {T + "phase13_engine", T + "notifications"}),
            ("platform renderer", [("modified", "web/core/services/candidate_renderer.py")], set(), "targeted",
             {T + "interface_renderer", T + "field_validators", T + "phase13_engine", T + "change_plan_service"}, {T + "notifications"}),
            ("models", [("modified", "web/core/models.py")], set(), "core", set(), set()),
            ("new migration", [("added", "web/core/migrations/0006_next.py")], set(), "core", set(), set()),
            ("shared utility", [("modified", "web/core/services/secret_policy.py")], set(), "core", set(), set()),
            ("test helper", [("modified", "web/core/tests/helpers/candidates.py")], set(), "core", set(), set()),
            ("views", [("modified", "web/core/views.py")], set(), "targeted", {T + "view_boundaries", T + "routes"}, {T + "phase13_engine"}),
            ("monitoring", [("modified", "monitoring/scripts/ingest_snmp_trap.py")], {"monitoring.unit", "grafana.drift"}, "targeted",
             {T + "monitoring_integration"}, {T + "phase13_engine"}),
            ("credential rotation installer", [("modified", "monitoring/scripts/install_credential_rotation_timer.sh")],
             {"monitoring.unit", "grafana.drift"}, "targeted",
             {T + "credential_rotation", T + "device_mfa", T + "monitoring_integration"}, {T + "phase13_engine"}),
            ("bundle service", [("modified", "web/core/services/bundles/integrity.py")], set(), "targeted",
             {T + "bundles", T + "bundle_views", T + "contracts"}, {T + "phase13_engine", T + "execution_engine", T + "notifications"}),
            ("bundle facade", [("modified", "web/core/services/bundle_service.py")], set(), "targeted", {T + "bundles", T + "bundle_views"}, {T + "phase13_engine"}),
            ("bundle template (no lab verifier, no monitoring)", [("modified", "web/core/templates/core/device_builder/bundle_detail.html")], set(), "targeted",
             {T + "bundle_views", T + "execution_views"}, {T + "phase13_engine", T + "notifications"}),
            ("execution engine reaches its consumers", [("modified", "web/core/services/execution/engine.py")], set(), "targeted",
             {T + "execution_engine", T + "bundles", T + "bundle_views"}, {T + "phase13_engine"}),
            ("bundle test module only", [("modified", "web/core/tests/test_bundles.py")], set(), {T + "bundles"}, set(), set()),
            ("bundle doc read by a test", [("modified", "docs/IMMUTABLE_CONFIGURATION_BUNDLES.md")], set(), {T + "bundles"}, set(), set()),
            ("probation soak evaluator", [("modified", "web/core/services/soak/evaluator.py")], set(), "targeted",
             {T + "soak", T + "soak_decision", T + "soak_views", T + "bundles", T + "health_engine", T + "contracts"}, {T + "phase13_engine", T + "notifications", T + "execution_engine"}),
            ("probation soak scheduler command", [("modified", "web/core/management/commands/probation_soak_tick.py")], set(), "targeted",
             {T + "soak", T + "soak_views"}, {T + "phase13_engine", T + "notifications"}),
            ("soak template (no lab verifier, no monitoring)", [("modified", "web/core/templates/core/device_builder/soak_detail.html")], set(), "targeted",
             {T + "soak_views", T + "bundle_views"}, {T + "phase13_engine", T + "notifications"}),
            ("soak test module only", [("modified", "web/core/tests/test_soak.py")], set(), {T + "soak"}, set(), set()),
            ("soak doc read by a test", [("modified", "docs/PROBATION_SOAK_AND_PROMOTION.md")], set(), {T + "soak"}, set(), set()),
            ("execution engine reaches the soak (interference)", [("modified", "web/core/services/execution/engine.py")], set(), "targeted",
             {T + "soak", T + "soak_decision"}, {T + "phase13_engine"}),
            ("workflow", [("modified", ".github/workflows/tier3-validation.yml")], set(), {T + "tier3_execution"}, set(), set()),
            ("orchestrator", [("modified", "master.py")], {"monitoring.unit"}, None, set(), set()),
        ]
        for case, files, extra, labels, present, absent in rows:
            with self.subTest(case=case):
                plan = plan_for(*files)
                self.assertEqual(plan.mode_effective, Mode.TARGETED)
                # Lab 7: a changed deployed Python file is always Pylint-checked (targeted to the changed files)
                lint = {"quality.pylint"} if any(p.endswith(".py") and not p.startswith(("web/core/tests/", "monitoring/tests/", "docs/"))
                                                  and s != "deleted" for s, p in files) else set()
                self.assertEqual(required_ids(plan) - {"django.tests"}, BASELINE | extra | lint)
                got = labels_of(plan)
                if labels is None:
                    self.assertNotIn("django.tests", required_ids(plan))
                elif labels == "core":
                    self.assertEqual(got, {"core"})
                elif labels != "targeted":
                    self.assertEqual(got, labels)
                self.assertTrue(present <= got, f"missing {present - got}")
                self.assertFalse(absent & got, f"unexpected {absent & got}")

    def test_every_selected_check_and_test_carries_a_reason(self):
        plan = plan_for(("modified", "web/core/services/validation/engine.py"), ("modified", "monitoring/scripts/ingest_snmp_trap.py"),
                        ("modified", "templates/R1.cfg.j2"), ("modified", "docs/CURRENT_STATE.md"))
        for check in (*plan.required, *plan.optional):
            with self.subTest(check=check.id):
                self.assertTrue(check.reasons and all(r.strip() for r in check.reasons))
        for label, reasons in plan.test_selection.items():
            with self.subTest(label=label):
                self.assertTrue(reasons)
        rendered = plan.to_dict()
        joined = " ".join(r for c in rendered["required_checks"] for r in c["reasons"])
        self.assertIn("Tier-2 validation engine changed", joined)  # the reason names the change, not "running full tests"
        only_validation = plan_for(("modified", "web/core/services/validation/engine.py"))
        self.assertIn("affected via validation -> planning -> health", " ".join(only_validation.test_selection[T + "health_engine"]))

    def test_lab_verifiers_are_optional_unless_explicitly_requested(self):
        files = [("modified", "monitoring/scripts/ingest_snmp_trap.py")]
        default = plan_for(*files)
        self.assertEqual({c.id for c in default.optional}, {"lab.grafana", "lab.nmas"})
        self.assertTrue(all(c.gate == Gate.LAB and not c.required for c in default.optional))
        self.assertFalse(any(c.gate == Gate.LAB for c in default.required))
        lab = plan_for(*files, include_lab=True)
        self.assertEqual({c.id for c in lab.required if c.gate == Gate.LAB}, {"lab.grafana", "lab.nmas"})
        self.assertEqual(lab.optional, [])

    def test_empty_change_runs_only_the_baseline(self):
        plan = plan_for()
        self.assertEqual(required_ids(plan), BASELINE)
        self.assertTrue(plan.empty_change)
        self.assertEqual(plan.mode_effective, Mode.TARGETED)


class FullAndFallbackTests(SimpleTestCase):
    def test_full_mode_requires_the_whole_regression_surface(self):
        plan = plan_for(("modified", "docs/CURRENT_STATE.md"), mode=Mode.FULL)
        self.assertEqual(plan.mode_effective, Mode.FULL)
        self.assertEqual(required_ids(plan), BASELINE | {"django.tests", "monitoring.unit", "grafana.drift", "quality.pylint", "governance.report"})
        self.assertEqual(labels_of(plan), {"core"})
        self.assertEqual({c.id for c in plan.optional}, {f"lab.{k}" for k in rules.LAB_VERIFIERS})
        # Lab 7: full mode runs the same suites traced under coverage.py (one run) and gates the evidence report
        params = {c.id: c.params for c in plan.required}
        self.assertTrue(params["django.tests"]["governance"] and params["monitoring.unit"]["governance"])
        self.assertEqual(params["quality.pylint"], {})

    def test_unknown_significant_path_and_missing_base_broaden_never_shrink(self):
        for case, plan in (
            ("unclassified path", plan_for(("added", "brand/new/thing.bin"), ("modified", "docs/CURRENT_STATE.md"))),
            ("no comparison base", plan_for(("added", "docs/CURRENT_STATE.md"), strategy="all-tracked")),
        ):
            with self.subTest(case=case):
                self.assertEqual(plan.mode_effective, Mode.FULL)
                self.assertEqual(labels_of(plan), {"core"})
                self.assertIn("monitoring.unit", required_ids(plan))
        self.assertIn("UNCLASSIFIED_PATH", [w.code for w in plan_for(("added", "brand/new/thing.bin")).warnings])

    def test_unknown_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            planner.build_plan(change_set(), mode="fast")


class DeterminismAndWarningTests(SimpleTestCase):
    def test_plan_is_independent_of_file_order_and_duplicates(self):
        files = [("modified", "web/core/services/validation/engine.py"), ("modified", "web/core/services/health/codes.py"),
                 ("added", "web/core/tests/test_health_engine.py"), ("modified", "docs/CURRENT_STATE.md"), ("modified", "monitoring/config/x.yml")]
        reference = plan_for(*files).to_dict()
        for seed in range(6):
            shuffled = list(files) + [files[0]]  # a duplicate entry must not duplicate a label
            random.Random(seed).shuffle(shuffled)
            with self.subTest(seed=seed):
                candidate = planner.build_plan(change_set(*sorted(set(shuffled))), mode=Mode.TARGETED).to_dict()
                self.assertEqual(candidate["plan_hash"], reference["plan_hash"])
                labels = next(c for c in candidate["required_checks"] if c["id"] == "django.tests")["params"]["labels"]
                self.assertEqual(labels, sorted(set(labels)))
        self.assertEqual(plan_for(*files).plan_hash(), plan_for(*reversed(files)).plan_hash())

    def test_path_warning_matrix(self):
        rows = [
            ("frozen lab template", [("modified", "templates/R1.cfg.j2")], {"FROZEN_LAB_PATH_CHANGED"}),
            ("inventory", [("modified", "inventory.yml")], {"FROZEN_LAB_PATH_CHANGED"}),
            ("runtime log", [("modified", "Run_Logs.log"), ("modified", "logs/R2.log")], {"RUNTIME_ARTIFACT_CHANGED"}),
            ("migration edited", [("modified", "web/core/migrations/0003_phase13_change_validation_run.py")], {"MIGRATION_HISTORY_MODIFIED"}),
            ("migration deleted", [("deleted", "web/core/migrations/0004_phase14_change_plan.py")], {"MIGRATION_HISTORY_MODIFIED"}),
            ("migration renamed away", [("renamed", "web/core/migrations/0009_b.py", "web/core/migrations/0008_a.py")], {"MIGRATION_HISTORY_MODIFIED"}),
            ("migration appended", [("added", "web/core/migrations/0006_next.py")], set()),
            ("ordinary source", [("modified", "web/core/services/health/codes.py")], set()),
        ]
        for case, files, expected in rows:
            with self.subTest(case=case):
                self.assertEqual({w.code for w in plan_for(*files).warnings}, expected)
        # a synthetic "everything added" comparison (no base) must not warn about tracked logs / templates
        self.assertEqual(plan_for(("added", "Run_Logs.log"), ("added", "templates/R1.cfg.j2"), strategy="all-tracked").warnings, [])
