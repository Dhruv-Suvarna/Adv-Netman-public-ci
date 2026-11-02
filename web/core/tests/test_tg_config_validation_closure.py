"""Lab 7 closure -- Configuration Validation (Tier-3 dispatch) building blocks, each called directly: the static check
categories, the bundle codec, the service status helpers, the GitHub client (its HTTP call replaced; no network) and
the dependency graph.

POSITIVE: a bundle NMAS really produced passes each category; digests, hashes and features are exact.  NEGATIVE: a
tampered fragment, an unknown platform / feature / edge type, control characters, a secret-shaped value, an edited
Change, a non-passing or exempt run and a failed GitHub step each fail closed with the exact reason.
"""

from __future__ import annotations

import copy
from unittest import mock

from django.test import SimpleTestCase

from core import models
from core.services.configuration_validation import bundle as bundle_module
from core.services.configuration_validation import checks, github, service
from core.services.validation import context as vc
from core.services.validation import dependency_graph as dg
from core.tests import test_configuration_validation as cvt
from core.tests.helpers import validation as vh
from core.tests.helpers.validation import simple_pass_change, validate


@cvt.ENABLED
class BundleChecksTests(cvt.Base):
    def setUp(self):
        super().setUp()
        self.f = simple_pass_change()
        self.f.r1.static_route("10.9.0.0/24", next_hop="192.0.2.1")
        self.run = validate(self.f.change, self.f.sources)
        self.good, self.payload = self.bundle()

    def statuses(self, category):
        return {check["name"]: check["status"] for check in category.checks}

    def test_category_add_records_a_bounded_check(self):
        category = checks.Category("Z", "Example")
        self.assertTrue(category.add("holds", True, "x" * 400))
        self.assertEqual((category.key, category.title, category.checks[0]["status"], len(category.checks[0]["detail"])), ("Z", "Example", checks.PASS, 300))

    def test_category_add_of_a_failed_check_is_false(self):
        category = checks.Category("Z", "Example")
        self.assertFalse(category.add("breaks", False, "why"))
        self.assertEqual(category.checks, [{"name": "breaks", "status": checks.FAIL, "detail": "why"}])

    def test_each_category_holds_for_the_real_candidate(self):
        for name, category in (("integrity", checks.integrity(self.good, self.payload)), ("rendering", checks.rendering(self.good)),
                               ("platform", checks.platform_support(self.good)), ("intent", checks.intent_checks(self.good, repo_root=cvt.ROOT)),
                               ("syntax", checks.syntax(self.good))):
            with self.subTest(case=f"holds {name}"):
                self.assertEqual(set(self.statuses(category).values()), {checks.PASS}, category.checks)

    def test_each_category_refuses_a_tampered_bundle(self):
        altered = copy.deepcopy(self.good)
        altered["devices"][0]["candidate"] += "\n% Invalid input\nip address 300.1.1.1/24\t\n"
        unknown = copy.deepcopy(self.good)
        unknown["devices"][0]["platform"] = "junos"
        incomplete = {k: v for k, v in self.good.items() if k != "candidate_hash"}
        stray = copy.deepcopy(self.good)
        stray["devices"].append({**stray["devices"][0], "device": "R5"})
        for label, category in (("integrity of an altered fragment", checks.integrity(altered)), ("integrity of a bundle missing a field", checks.integrity(incomplete)),
                                ("rendering on an unknown platform", checks.rendering(unknown)), ("platform support on an unknown platform", checks.platform_support(unknown)),
                                ("intent with a device outside the Change", checks.intent_checks(stray, repo_root=cvt.ROOT)), ("syntax of device error text", checks.syntax(altered))):
            with self.subTest(case=f"failure {label}"):
                self.assertIn(checks.FAIL, self.statuses(category).values(), category.checks)

    def test_matrix_status_reads_the_repository_verdict(self):
        self.assertEqual(checks.matrix_status("arista_ceos", "routing.STATIC_IPV4"), "SUPPORTED")

    def test_select_tests_lists_only_existing_modules_and_ignores_unknown_platforms(self):
        found = checks.select_tests(self.good, repo_root=cvt.ROOT)
        self.assertEqual(found[:2], ["core.tests.test_configuration_validation", "core.tests.test_network_config_validation"])
        self.assertIn("core.tests.test_candidate_renderer", found)
        self.assertEqual(len(found), len(set(found)))
        unknown = checks.select_tests({"devices": [{"platform": "junos", "features": ["nothing.KNOWN"]}]}, repo_root=cvt.ROOT)
        self.assertEqual(unknown, ["core.tests.test_configuration_validation", "core.tests.test_network_config_validation"])

    def test_build_bundle_of_the_validated_change(self):
        found = service.build_bundle(self.f.change, self.run, "corr-1")
        self.assertEqual((found["correlation_id"], found["snapshot_hash"]), ("corr-1", self.run.input_hash))
        self.assertEqual(found["candidate_hash"], bundle_module.candidate_hash(found["devices"], found["removals"]))

    def test_build_bundle_refuses_a_change_edited_after_validation(self):
        self.f.r1.address(self.f.r1.iface("Ethernet2"), "198.51.100.1/31")
        with self.assertRaises(bundle_module.BundleError) as caught:
            service.build_bundle(self.f.change, self.run, "corr-2")
        self.assertEqual(caught.exception.code, "CONFIG_VALIDATION_SNAPSHOT_CHANGED")

    def test_encode_refuses_a_secret_shaped_value(self):
        leaky = copy.deepcopy(self.good)
        leaky["devices"][0]["candidate"] += "\n-----BEGIN " "OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
        with self.assertRaises(bundle_module.BundleError):
            bundle_module.encode(leaky)
        with self.assertRaises(bundle_module.BundleError):
            bundle_module.assert_safe(leaky)

    def test_encode_and_assert_safe_of_the_real_bundle(self):
        self.assertIsNone(bundle_module.assert_safe(self.good))
        encoded = bundle_module.encode(self.good)
        self.assertEqual(bundle_module.decode(encoded), self.good)
        self.assertEqual(encoded["bundle_sha256"], bundle_module.digest(bundle_module.canonical(self.good)))

    def test_on_validation_never_dispatches_an_exempt_run(self):
        self.f.change.metadata = {"transition": {"kind": "ISIS_MIGRATION"}}
        self.f.change.save(update_fields=["metadata"])
        self.assertIsNone(service.on_validation(self.run))
        self.assertEqual(service.exempt(self.f.change), "routing transition ISIS_MIGRATION: validated and executed by its own workflow")

    def test_effective_status_and_reconciling_of_a_dispatched_row(self):
        row = models.ConfigurationValidationRun.objects.filter(change=self.f.change).latest("created_at")
        self.assertEqual(service.effective_status(row), row.status)
        self.assertTrue(service.needs_reconciling(row))
        panel = service.panel(self.f.change)
        self.assertEqual((panel["row"], panel["status"], panel["exempt"]), (row, service.effective_status(row), ""))

    def test_panel_of_a_never_validated_change_has_no_row_and_is_not_triggered(self):
        panel = service.panel(vh.new_change("never validated"))
        self.assertEqual((panel["row"], panel["status"], panel["stale_note"], panel["demonstration"], panel["history"]),
                         (None, models.ConfigurationValidationStatus.NOT_TRIGGERED, "", None, []))

    def test_effective_status_stale_and_no_reconciling_once_the_change_moved_on(self):
        row = models.ConfigurationValidationRun.objects.filter(change=self.f.change).latest("created_at")
        self.f.r1.address(self.f.r1.iface("Ethernet3"), "198.51.100.3/31")
        self.assertEqual(service.effective_status(row), models.ConfigurationValidationStatus.STALE)
        row.status, row.triggered_at, row.completed_at = models.ConfigurationValidationStatus.STALE, None, None
        self.assertFalse(service.needs_reconciling(row))


class BundleValueTests(SimpleTestCase):
    def test_canonical_and_digest_are_order_independent(self):
        self.assertEqual(bundle_module.canonical({"b": 1, "a": [2]}), '{"a":[2],"b":1}')
        self.assertEqual(bundle_module.digest({"b": 1, "a": 2}), bundle_module.digest({"a": 2, "b": 1}))
        self.assertEqual(bundle_module.digest("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_canonical_of_a_tampered_value_differs(self):
        self.assertNotEqual(bundle_module.canonical({"a": 1}), bundle_module.canonical({"a": 2}))

    def test_candidate_hash_covers_devices_and_removals(self):
        devices = [{"device": "R1", "platform": "arista_ceos", "candidate_sha256": "a"}]
        self.assertNotEqual(bundle_module.candidate_hash(devices, []), bundle_module.candidate_hash(devices, [{"device": "R1", "platform": "arista_ceos", "content_hash": "c"}]))

    def test_routing_leaves_for_known_and_unknown_values(self):
        self.assertEqual(bundle_module.routing_leaves("isis", {}), {"ISIS"})
        unknown = bundle_module.routing_leaves("rip", {"version": "IPX"})
        self.assertTrue(all(":" in leaf for leaf in unknown))
        self.assertEqual(bundle_module.routing_leaves("bgp", {"neighbors": {"n": {"family": "X25"}}}), {"BGP:X25"})

    def test_features_of_lists_interface_kinds_and_routes(self):
        found = bundle_module.features_of({"interfaces": {"i": {"kind": "SVI"}}, "routing": {"static_routes": {"r": {"family": "IPV6"}}}})
        self.assertEqual(found, ["interface.SVI", "routing.STATIC_IPV6"])


class ServiceSettingsTests(SimpleTestCase):
    def test_enabled_follows_the_setting(self):
        with self.settings(NMAS_CONFIGURATION_VALIDATION_ENABLED=True):
            self.assertTrue(service.enabled())

    def test_exempt_is_blank_for_a_change_without_a_transition(self):
        self.assertEqual(service.exempt(mock.Mock(metadata={})), "")
        self.assertEqual(service.exempt(mock.Mock(metadata=None)), "")


class GitHubClientTests(SimpleTestCase):
    def test_is_configured_and_repository_from_settings(self):
        with self.settings(NMAS_GITHUB_REPOSITORY="example/nmas", NMAS_GITHUB_TOKEN_ENV="NMAS_TEST_TOKEN"), mock.patch.dict("os.environ", {"NMAS_TEST_TOKEN": "t"}):
            self.assertEqual((github.is_configured(), github.repository()), (True, "example/nmas"))

    def run_row(self, **overrides):
        return {"id": 7, "path": github.WORKFLOW_PATH, "event": github.DISPATCH_EVENT, "display_title": "NMAS Configuration Validation | CHG | corr-9", **overrides}

    def test_github_reads_dispatch_runs_matching_runs_one_run_and_step_conclusions(self):
        answers = {f"/actions/runs?event={github.DISPATCH_EVENT}&per_page=100": {"workflow_runs": [self.run_row(), self.run_row(id=8, event="push")]},
                   "/actions/runs/7": {"id": 7, "status": "completed"},
                   "/actions/runs/7/jobs?per_page=20": {"jobs": [{"name": "Configuration Validation", "steps": [{"name": "Lint", "conclusion": "success"},
                                                                                                             {"name": "Validate", "conclusion": "failure"}]}]}}
        with mock.patch.object(github, "_call", side_effect=lambda method, path, body=None: answers[path]), mock.patch.object(github, "is_validation_run", side_effect=lambda run: run.get("event") == github.DISPATCH_EVENT):
            self.assertEqual([run["id"] for run in github.dispatch_runs()], [7])
            self.assertEqual([run["id"] for run in github.find_runs("corr-9")], [7])
            self.assertEqual(github.get_run("7"), {"id": 7, "status": "completed"})
            self.assertEqual(github.failed_steps(7), ["Configuration Validation: Validate"])

    def test_find_runs_for_an_unknown_correlation_and_failed_steps_of_a_clean_run_are_empty(self):
        self.assertEqual(github.find_runs("corr-unknown", [self.run_row()]), [])
        with mock.patch.object(github, "_call", return_value={"jobs": [{"name": "J", "steps": [{"name": "s", "conclusion": "success"}]}]}):
            self.assertEqual(github.failed_steps(7), [])

    def test_get_run_refuses_a_non_numeric_id_and_reports_an_unconfigured_client(self):
        with self.assertRaises(ValueError):
            github.get_run("seven")
        with self.settings(NMAS_GITHUB_TOKEN_ENV="NMAS_ABSENT_TOKEN"), mock.patch.dict("os.environ", {}, clear=True), self.assertRaises(github.GitHubError):
            github.get_run(7)


def project():
    device = {"device_name": "R1", "platform": "arista_ceos", "target_type": "device",
              "interfaces": {"i1": {"id": "i1", "name": "Ethernet1", "kind": "ROUTED_PHYSICAL", "addresses": {"a1": {"id": "a1", "cidr": "192.0.2.0/31"}}}},
              "routing": {"ospf": {"o1": {"id": "o1", "router_id": "10.0.0.1", "bindings": {"b1": {"id": "b1", "interface_id": "missing-iface"}}}}}}
    return vc.ProjectModel({"devices": [device]})


class DependencyGraphTests(SimpleTestCase):
    def test_node_ids_and_builder_nodes_and_edges(self):
        self.assertEqual(dg.node_id("R1", "INTERFACE", "i1"), "R1/INTERFACE/i1")
        builder = dg.GraphBuilder()
        a = builder.node("R1", "INTERFACE", "i1", "Ethernet1")
        self.assertEqual(builder.node("R1", "INTERFACE", "i1", "renamed"), a)                    # first label kept
        b = builder.node("R1", "ADDRESS", "a1", "192.0.2.0/31")
        edge_type = sorted(dg.EDGE_TYPES)[0]
        builder.edge(b, a, edge_type)
        self.assertEqual(builder.edges[(b, a, edge_type)], {"from": b, "to": a, "type": edge_type, "status": "RESOLVED", "reason": ""})

    def test_builder_refuses_an_unknown_edge_type(self):
        builder = dg.GraphBuilder()
        with self.assertRaises(ValueError):
            builder.edge("a", "b", "NOT_AN_EDGE")
        self.assertEqual(builder.edges, {})
        self.assertEqual(builder.node("", "X", "", ""), "/X/")

    def test_build_graph_links_addresses_to_interfaces(self):
        graph = dg.build_graph(project())
        self.assertEqual({node["id"] for node in graph["nodes"]}, {"R1/interface/i1", "R1/address/a1", "R1/routing_ospf/o1"})
        self.assertIn(("R1/address/a1", "R1/interface/i1", "RESOLVED"), {(e["from"], e["to"], e["status"]) for e in graph["edges"]})

    def test_build_graph_of_an_empty_project_has_no_nodes(self):
        graph = dg.build_graph(vc.ProjectModel({"devices": []}))
        self.assertEqual((graph["nodes"], graph["edges"]), ([], []))

    def test_removal_node_object_id_is_stable_and_path_safe(self):
        found = dg.removal_node_object_id("interface Ethernet1 / ip address")
        self.assertRegex(found, r"^RM-[0-9a-f]{12}$")
        self.assertEqual(found, dg.removal_node_object_id("interface Ethernet1 / ip address"))

    def test_removal_node_object_id_of_a_distinct_item_never_collides(self):
        self.assertNotEqual(dg.removal_node_object_id("a"), dg.removal_node_object_id("b"))

    def test_validate_dependencies_stores_the_graph(self):
        ctx = vc.ValidationContext(snapshot={}, model=vc.ProjectModel({"devices": []}), sources=None)
        dg.validate_dependencies(ctx)
        self.assertEqual((ctx.graph["nodes"], ctx.findings), ([], []))

    def test_validate_dependencies_reports_a_missing_binding_target(self):
        ctx = vc.ValidationContext(snapshot={}, model=project(), sources=None)
        dg.validate_dependencies(ctx)
        missing = [edge for edge in ctx.graph["edges"] if edge["status"] == "MISSING"]
        self.assertEqual(len([f for f in ctx.findings if f.code == "DEPENDENCY_MISSING"]), len(missing))
