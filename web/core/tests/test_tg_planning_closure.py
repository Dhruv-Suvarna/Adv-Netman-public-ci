"""Lab 7 closure -- deployment planning: snippet extraction, ordering, dependency mapping, persistence and the plan
service, each public function called directly.

POSITIVE: the lines an object adds, the stage table, a deterministic topological order, the mapped edges, the persisted
plan and its lookups are exactly what the validated Change implies.  NEGATIVE: a self, missing or circular dependency,
an unresolved graph edge, an unknown error code, a malformed or foreign plan id and a line-breaking value are refused
with a fixed code or yield nothing -- a plan is never guessed.  Everything is in-memory or the test database: no device.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

from django.test import SimpleTestCase, TestCase

from core import models
from core.services import change_plan_service as cps
from core.services import platform_drivers
from core.services.planning import builder, configlet_factory as cf, dependency_mapping, ordering, priorities, serialization, snippets
from core.services.planning.errors import ERROR_MESSAGES, PlanGenerationError
from core.tests.helpers.validation import new_change, simple_pass_change, validate

MARK = platform_drivers.UNSUPPORTED_OBJECT_MARKER


def static(text):
    return {"kind": "static", "text": text}


class FakeDriver:
    def __init__(self, descriptors):
        self.descriptors, self.calls = descriptors, []

    def render_candidate(self, **kwargs):
        self.calls.append(kwargs)
        return self.descriptors


class SnippetTests(SimpleTestCase):
    def test_render_lines_keeps_each_rendered_line_in_order(self):
        driver = FakeDriver([static("hostname R1"), static("interface Ethernet1   "), static("   description up")])
        self.assertEqual(snippets.render_lines(driver, {"device.hostname": "R1"}), ["hostname R1", "interface Ethernet1", "   description up"])
        self.assertEqual(driver.calls, [{"field_values": {"device.hostname": "R1"}, "interfaces": [], "routing": {}, "phase12": {}}])

    def test_render_lines_never_keeps_blank_or_omitted_lines_or_a_line_break(self):
        driver = FakeDriver([static(""), static("   "), {"kind": "field", "value": "", "omit_if_empty": True, "template": "x {value}"},
                             {"kind": "field", "value": "a\nb", "path": "device.description", "template": "description {value}"}])
        with self.subTest(case="blank omitted and line-break values refused"):
            self.assertEqual(snippets.render_lines(driver, {}), [f"{MARK} device.description contains a line break; value withheld"])

    def test_added_lines_returns_the_new_line_under_its_headers(self):
        before = ["router bgp 65001", "   neighbor 10.0.0.1 remote-as 1", "!"]
        after = ["router bgp 65001", "   neighbor 10.0.0.1 remote-as 1", "   neighbor 10.0.0.2 remote-as 2", "   ! peer two", "!"]
        self.assertEqual(snippets.added_lines(before, after), ["router bgp 65001", "   neighbor 10.0.0.2 remote-as 2", "   ! peer two"])

    def test_added_lines_of_identical_slices_or_a_bare_separator_is_empty(self):
        self.assertEqual(snippets.added_lines(["hostname R1"], ["hostname R1"]), [])
        self.assertEqual(snippets.added_lines(["hostname R1"], ["hostname R1", "!"]), [])

    def test_deployable_placeholders_and_marker_detection_of_real_lines(self):
        lines = ["interface Ethernet1", "   ip address <ipv4-address-required>", f"{MARK} pbr"]
        self.assertEqual(snippets.deployable(["! c", "", "interface Ethernet1", "# x"]), ["interface Ethernet1"])
        self.assertEqual(snippets.placeholders(lines), ["<ipv4-address-required>"])
        self.assertTrue(snippets.has_unsupported_marker(lines))

    def test_deployable_placeholders_and_marker_detection_are_empty_for_comment_only_or_clean_lines(self):
        self.assertEqual(snippets.deployable(["!", "# none", "  "]), [])
        self.assertEqual(snippets.placeholders(["interface Ethernet1", "   ip address 10.0.0.1/31", "<not-a-placeholder>"]), [])
        self.assertFalse(snippets.has_unsupported_marker(["interface Ethernet1", "! unsupported elsewhere"]))


class OrderingAndErrorTests(SimpleTestCase):
    KEYS = {"a": (1, "a"), "b": (2, "b"), "c": (0, "c")}

    def test_topological_order_respects_dependencies_then_sort_keys(self):
        self.assertEqual(ordering.topological_order(self.KEYS, [("c", "b")]), ["a", "b", "c"])
        self.assertEqual(ordering.topological_order(self.KEYS, []), ["c", "a", "b"])

    def test_topological_order_refuses_self_missing_and_circular_dependencies(self):
        for name, deps, code in (("self", [("a", "a")], "CONFIGLET_CYCLE"), ("missing", [("a", "zz")], "DEPENDENCY_MISSING"),
                                 ("cycle", [("a", "b"), ("b", "a")], "CONFIGLET_CYCLE")):
            with self.subTest(case=f"refused {name}"), self.assertRaises(PlanGenerationError) as caught:
                ordering.topological_order(self.KEYS, deps)
            self.assertEqual(caught.exception.code, code)

    def test_stage_table_lists_the_nine_canonical_stages(self):
        table = priorities.stage_table()
        self.assertEqual(len(table), 9)
        self.assertEqual([row["priority"] for row in table], sorted(row["priority"] for row in table))
        self.assertEqual(set(table[0]), {"priority", "key", "label"})

    def test_plan_generation_exception_returns_code_message_and_details(self):
        error = PlanGenerationError("CONFIGLET_CYCLE", cycle=["a", "b"])
        self.assertEqual(error.as_dict(), {"code": "CONFIGLET_CYCLE", "message": ERROR_MESSAGES["CONFIGLET_CYCLE"], "details": {"cycle": ["a", "b"]}})
        self.assertEqual(str(error), f"CONFIGLET_CYCLE: {ERROR_MESSAGES['CONFIGLET_CYCLE']}")

    def test_plan_generation_error_refuses_an_unknown_code(self):
        with self.assertRaises(ValueError):
            PlanGenerationError("NOT_A_PLAN_ERROR <script>")


class DependencyMappingTests(SimpleTestCase):
    GRAPH = {"nodes": [{"id": "n1"}, {"id": "n2"}, {"id": "n3"}],
             "edges": [{"from": "n2", "to": "n1", "type": "BINDS", "status": "RESOLVED", "reason": "on interface"},
                       {"from": "n3", "to": "n3", "type": "SELF", "status": "RESOLVED"}]}

    def test_map_dependencies_maps_edges_and_parent_keys(self):
        specs = [SimpleNamespace(key="k2", parent_key="k1"), SimpleNamespace(key="k1", parent_key=None)]
        found = dependency_mapping.map_dependencies(self.GRAPH, specs, {"n1": "k1", "n2": "k2", "n3": "k3"})
        self.assertEqual(found, {("k2", "k1"): {"edge_types": ["BINDS", "REQUIRES"],
                                                "reasons": ["address-family activation requires the neighbor definition", "on interface"]}})

    def test_map_dependencies_refuses_unresolved_unknown_or_unmapped_edges(self):
        cases = (("unresolved", {**self.GRAPH, "edges": [{"from": "n2", "to": "n1", "type": "BINDS", "status": "UNRESOLVED"}]}, {"n1": "k1", "n2": "k2"}),
                 ("unknown", {**self.GRAPH, "edges": [{"from": "n2", "to": "n9", "type": "BINDS", "status": "RESOLVED"}]}, {"n1": "k1", "n2": "k2"}),
                 ("unmapped", self.GRAPH, {"n1": "k1"}))
        for name, graph, mapping in cases:
            with self.subTest(case=f"refused {name}"), self.assertRaises(PlanGenerationError) as caught:
                dependency_mapping.map_dependencies(graph, [], mapping)
            self.assertEqual(caught.exception.code, "DEPENDENCY_MISSING")
        self.assertEqual(dependency_mapping.map_dependencies(self.GRAPH, [], {"n1": "k1"}, skipped_nodes={"n2", "n3"}), {})


class PlanPersistenceTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.f = simple_pass_change()
        cls.vrun = validate(cls.f.change, cls.f.sources)

    def test_persist_plan_writes_the_configlets_dependencies_and_audit_event(self):
        document = builder.compute_plan(self.f.change, self.vrun)
        plan = builder.persist_plan(self.f.change, self.vrun, document, actor="planner")
        self.assertEqual((plan.plan_hash, plan.created_by, plan.validation_input_hash), (document["plan_hash"], "planner", self.vrun.input_hash))
        self.assertEqual(list(plan.configlets.order_by("sequence").values_list("cfg_id", flat=True)), [r["cfg_id"] for r in document["configlets"]])
        self.assertEqual(models.ConfigletDependency.objects.filter(configlet__plan=plan).count(), len(document["dependencies"]))
        self.assertEqual(models.AuditEvent.objects.filter(event_type=models.AuditEventType.PLAN_BUILT, object_id=str(plan.plan_id)).count(), 1)
        self.assertEqual(builder.plan_for_run(self.vrun), plan)

    def test_persist_plan_of_a_secret_shaped_record_is_refused_and_rolls_back(self):
        document = builder.compute_plan(self.f.change, self.vrun)
        document["configlets"][0] = {**document["configlets"][0], "derived": {"password": "x"}}
        with self.assertRaisesRegex(ValueError, "Configlet metadata"):
            builder.persist_plan(self.f.change, self.vrun, document)
        self.assertEqual((models.ChangePlan.objects.filter(change=self.f.change).count(), models.Configlet.objects.filter(change=self.f.change).count()), (0, 0))
        self.assertIsNone(builder.plan_for_run(self.vrun))

    def test_get_plan_and_list_plans_through_the_change(self):
        plan, created = cps.build_change_plan(self.f.change, actor="planner", sources=self.f.sources)
        self.assertTrue(created)
        self.assertEqual((cps.get_plan(self.f.change, plan.plan_id), cps.get_plan(self.f.change, str(plan.plan_id))), (plan, plan))
        self.assertEqual(cps.list_plans(self.f.change), [plan])

    def test_get_plan_none_and_list_plans_empty_for_a_malformed_foreign_or_unknown_id(self):
        plan, _ = cps.build_change_plan(self.f.change, actor="planner", sources=self.f.sources)
        other = new_change("other")
        self.assertEqual((cps.get_plan(self.f.change, "not-a-uuid"), cps.get_plan(other, plan.plan_id), cps.get_plan(self.f.change, uuid.uuid4())), (None, None, None))
        self.assertEqual((cps.list_plans(other), cps.list_plans(self.f.change, limit=0)), ([], []))

    def test_serialize_plan_of_a_stale_plan_and_distinct_report_names(self):
        plan, _ = cps.build_change_plan(self.f.change, actor="planner", sources=self.f.sources)
        document = serialization.serialize_plan(plan, currency={"state": "STALE", "reasons": ["VALIDATION_SUPERSEDED"]})
        self.assertEqual((document["plan"]["currency"], document["plan"]["currency_reasons"]), ("STALE", ["VALIDATION_SUPERSEDED"]))
        self.assertEqual(serialization.serialize_plan(plan)["plan"]["currency"], None)
        self.assertNotEqual(serialization.plan_report_filename(plan), serialization.plan_report_filename(SimpleNamespace(change=plan.change, plan_id=uuid.uuid4())))


class DeviceContextRenderTests(TestCase):
    def test_render_and_added_of_an_empty_slice_are_empty_beyond_the_identity(self):
        f = simple_pass_change()
        ctx = cf.DeviceContext(f.r1.intent, f.r1.intent.latest_revision(), {})
        with self.subTest(case="empty slice never adds lines"):
            identity = ctx.render()
            self.assertEqual(ctx.added({}, {}), [])
            self.assertEqual(ctx.added({"interfaces": ctx.interfaces}, {"interfaces": ctx.interfaces}), [])
            self.assertNotIn("interface Ethernet1", identity)
