"""Unified priority / dependency plan builder (service level).

Table-driven where cases share an execution shape (eligibility by validation state, priority and operation
by object family, failure modes, snippet content); one method per genuinely distinct behavior otherwise.
HTTP behavior is in ``test_change_plan_views``; import / side-effect / vendor-syntax contracts are in
``test_contracts``.  Synthetic graphs are injected as NEW append-only validation runs (``clone_run``) --
a stored run is never mutated.
"""

from __future__ import annotations

import json
import socket
import subprocess
import urllib.request
from unittest import mock

from django.db import IntegrityError, transaction
from django.test import TestCase

from core import models
from core.services import candidate_renderer, change_plan_service as cps, change_validation_service as cvs, nsot_netbox
from core.services.planning import configlet_factory, priorities, snippets
from core.tests.helpers.validation import (
    change_in_state,
    clone_run,
    graph_node,
    graph_with_edges,
    make_sources,
    nb_ip,
    netbox_data,
    rich_change,
    simple_pass_change,
    validate,
)

DEFINE, ATTACH = models.ConfigletOperationType.CREATE_DEFINE, models.ConfigletOperationType.ACTIVATE_ATTACH


class _Rollback(Exception):
    pass


def counts():
    return {m.__name__: (m.domain if m is models.AuditEvent else m.objects).count() for m in (
        models.ChangePlan, models.Configlet, models.ConfigletDependency, models.ChangeValidationRun, models.AuditEvent,
        models.ChangeLifecycleEvent, models.Notification)}


def by_noun(doc, noun, *, device=None, contains=""):
    return next(c for c in doc["configlets"]
                if c["description"].startswith(noun) and (device is None or c["device"] == device) and contains in c["label"])


class PlanEligibilityTests(TestCase):
    def test_only_a_current_passing_validation_may_produce_a_plan(self):
        # (validation state, may plan?, refusal code)
        rows = [
            ("NEVER_RUN", False, "VALIDATION_NEVER_RUN"),
            ("PASS", True, ""),
            ("PASS_WITH_WARNINGS", True, ""),
            ("BLOCKED", False, "VALIDATION_BLOCKED"),
            ("INCOMPLETE", False, "VALIDATION_INCOMPLETE"),
            ("STALE", False, "VALIDATION_STALE"),
        ]
        for state, eligible, code in rows:
            with self.subTest(validation=state):
                change, _ = change_in_state(state)
                before = counts()
                runs_before = models.ChangeValidationRun.objects.filter(change=change).count()
                verdict = cps.check_eligibility(change)
                self.assertEqual((verdict["eligible"], verdict["code"]), (eligible, code))
                if eligible:
                    plan, created = cps.build_change_plan(change, actor="tester")
                    self.assertTrue(created)
                    self.assertEqual(plan.validation_run.status, state)
                    warned = "VALIDATION_WARNINGS_CARRIED_FORWARD" in {w["code"] for w in plan.warnings}
                    self.assertEqual(warned, state == "PASS_WITH_WARNINGS")
                else:
                    with self.assertRaises(cps.PlanGenerationError) as raised:
                        cps.build_change_plan(change, actor="tester")
                    self.assertEqual(raised.exception.code, code)
                    self.assertEqual(counts(), before, "a refused build persists nothing")
                self.assertEqual(models.ChangeValidationRun.objects.filter(change=change).count(), runs_before,
                                 "a plan build never silently re-runs validation")


class RichPlanTests(TestCase):
    """One rich, validated Change and its plan, built once for the whole class."""

    @classmethod
    def setUpTestData(cls):
        cls.f = rich_change()
        cls.vrun = validate(cls.f.change, cls.f.sources)
        cls.plan, _ = cps.build_change_plan(cls.f.change, actor="tester")
        cls.doc = cps.serialize_plan(cls.plan)

    def test_the_plan_pins_the_exact_validation_run_hashes_and_carries_its_warnings(self):
        plan, run, doc = self.plan, self.vrun, self.doc
        self.assertEqual(run.status, "PASS_WITH_WARNINGS")
        self.assertEqual(plan.validation_run_id, run.pk)
        self.assertEqual((plan.validation_input_hash, plan.validation_source_hash, plan.validation_engine_version),
                         (run.input_hash, run.source_hash, run.engine_version))
        validation = doc["validation"]
        self.assertEqual((validation["run_id"], validation["pinned_input_hash"]), (str(run.run_id), run.input_hash))
        self.assertGreater(validation["warning_count"], 0)
        self.assertEqual(validation["warning_codes"],
                         sorted({f["code"] for f in run.report["findings"] if f["severity"] == "WARNING"}))
        self.assertIn("VALIDATION_WARNINGS_CARRIED_FORWARD", {w["code"] for w in doc["warnings"]})

    def test_priority_and_operation_by_object_family_and_the_nine_stages(self):
        expected = {  # description prefix -> (deployment priority, operation)
            "interface definition": (2, DEFINE), "address assignment": (3, DEFINE), "static route": (4, DEFINE),
            "BGP process definition": (5, DEFINE), "OSPF process definition": (5, DEFINE),
            "routing interface attachment": (5, ATTACH), "BGP neighbor definition": (5, DEFINE),
            "BGP address-family activation": (5, ATTACH), "BGP network advertisement": (5, ATTACH),
            "FHRP definition": (6, DEFINE), "ACL definition": (6, DEFINE), "DHCP relay attachment": (6, ATTACH),
            "ACL attachment": (7, ATTACH), "NAT rule activation": (7, ATTACH),
        }
        seen = set()
        for configlet in self.doc["configlets"]:
            noun = next(n for n in expected if configlet["description"].startswith(n))
            with self.subTest(configlet=configlet["cfg_id"], noun=noun):
                self.assertEqual((configlet["priority"], configlet["operation"]), expected[noun])
                seen.add(noun)
        self.assertEqual(seen, set(expected), "every object family of the fixture produced a Configlet")

        stages = self.doc["stages"]
        self.assertEqual([s["priority"] for s in stages], list(range(1, 10)))
        self.assertEqual([s["label"] for s in stages], [p.label for p in models.DeploymentPriority])
        empty = {s["key"] for s in stages if not s["cfg_ids"]}
        self.assertEqual(empty, {"FOUNDATION_ACCESS", "MONITORING_MIRRORING", "PERSISTENCE"})  # nothing invented to fill stages

    def test_the_planner_knows_every_object_type_the_validation_graph_can_emit(self):
        graph_types = {"interface", "address", "static_route", "routing_rip", "routing_ospf", "routing_isis", "routing_eigrp",
                       "routing_binding", "routing_bgp", "bgp_neighbor", "bgp_network", "fhrp", "nat_pool", "nat_rule", "dhcp_relay",
                       "acl", "acl_attachment", "pbr_policy", "pbr_attachment", "pbr_sequence",  # dhcp_client is capability-blocked
                       "mgmt_vrf", "mgmt_vrf_binding", "mgmt_vrf_route", "mgmt_vrf_service"}     # V2 Phase 4 management VRF
        self.assertEqual(set(configlet_factory.HANDLERS) | set(priorities.FOLDED_NODE_TYPES), graph_types)
        for name, cls in priorities.CATALOGUE.items():
            with self.subTest(catalogue=name):
                self.assertIn(cls.priority, models.DeploymentPriority.values)
                self.assertIn(cls.operation, models.ConfigletOperationType.values)
                self.assertIn(cls.namespace, models.FeatureNamespace.values)

    def test_configlets_are_granular_and_their_syntax_comes_from_the_platform_driver(self):
        # (noun, device, label fragment, lines that must appear, text that must not appear)
        cases = [
            ("interface definition", "R1", "Ethernet1", ["interface Ethernet1", "no switchport"], ["ip address"]),
            ("address assignment", "R1", "192.0.2.0/31", ["interface Ethernet1", "ip address 192.0.2.0/31"], ["no switchport"]),
            ("static route", "R1", "10.9.0.0/24", ["ip route 10.9.0.0/24 192.0.2.1"], ["interface "]),
            ("BGP process definition", "R1", "AS65001", ["router bgp 65001", "router-id 10.0.0.1"], ["neighbor"]),
            ("BGP neighbor definition", "R1", "192.0.2.1", ["router bgp 65001", "neighbor 192.0.2.1 remote-as 65002"], ["activate"]),
            ("BGP address-family activation", "R1", "IPv4", ["address-family ipv4", "neighbor 192.0.2.1 activate",
                                                              "neighbor 192.0.2.1 next-hop-self"], ["remote-as"]),
            ("BGP network advertisement", "R1", "203.0.113.0/24", ["address-family ipv4", "network 203.0.113.0/24"], ["remote-as"]),
            ("routing interface attachment", "R1", "OSPF", ["interface Ethernet1", "ip ospf area 0.0.0.0"], ["router-id"]),
            ("FHRP definition", "R1", "VARP", ["interface Vlan10", "ip virtual-router address 192.168.10.1"], ["access-group"]),
            ("ACL definition", "R1", "EDGE-IN", ["ip access-list EDGE-IN", "10 permit ip any any"], ["access-group"]),
            ("ACL attachment", "R1", "attachment", ["interface Vlan10", "ip access-group EDGE-IN in"], ["10 permit"]),
            ("DHCP relay attachment", "R1", "relay", ["interface Vlan10", "ip helper-address 192.168.200.100"], ["access-group"]),
            ("NAT rule activation", "R3", "NAT rule", ['table ip DEVICE_BUILDER_PAT', 'oifname "eth2" ip saddr 10.0.0.0/8 masquerade'], ["ip route"]),
        ]
        for noun, device, fragment, required, forbidden in cases:
            with self.subTest(configlet=noun):
                text = by_noun(self.doc, noun, device=device, contains=fragment)["rendered_config"]
                for line in required:
                    self.assertIn(line, text)
                for line in forbidden:
                    self.assertNotIn(line, text)
        self.assertGreater(len(self.doc["configlets"]), 3 * len({c["device"] for c in self.doc["configlets"]}))  # not one blob per device

    def test_snippets_come_from_the_authoritative_renderer_and_together_cover_it(self):
        for intent in self.f.change.device_intents.all():
            revision = intent.latest_revision()
            candidate = {line for line in candidate_renderer.render(intent, revision)["lines"] if line.strip()}
            mine = [c for c in self.doc["configlets"] if c["device"] == intent.device_name]
            covered = set()
            for configlet in mine:
                lines = [ln for ln in configlet["rendered_config"].splitlines() if ln.strip()]
                if configlet["derived"]:
                    continue  # the AUTO address shows the derived value where the candidate only shows a comment
                with self.subTest(configlet=configlet["cfg_id"], claim="every snippet line is a line of the candidate render"):
                    self.assertLessEqual(set(lines), candidate)
                covered |= set(lines)
            deployable = {ln for ln in candidate if not ln.strip().startswith(("!", "#")) and not ln.startswith("hostname")}
            auto_lines = {ln for ln in deployable if "198.51.100" in ln}
            with self.subTest(device=intent.device_name, claim="every deployable candidate line is in some Configlet"):
                self.assertLessEqual(deployable - auto_lines - covered, set())

    def test_auto_address_uses_the_derived_value_without_mutating_intent_or_reserving_anything(self):
        auto = next(c for c in self.doc["configlets"] if c["derived"])
        self.assertIn("ip address 198.51.100.1/29", auto["rendered_config"])
        self.assertEqual(
            {k: auto["derived"][k] for k in ("source", "proposed_address", "reserved", "recheck_required")},
            {"source": "VALIDATION_DERIVED", "proposed_address": "198.51.100.1/29", "reserved": False, "recheck_required": True},
        )
        self.assertIn("AUTO_ADDRESS_RECHECK_REQUIRED", auto["warnings"])
        self.assertIn("AUTO_ADDRESS_RECHECK_REQUIRED", {w["code"] for w in self.doc["warnings"]})
        # accepted intent is untouched: it still hashes to exactly what was validated
        self.assertEqual(cvs.hash_snapshot(cvs.build_change_snapshot(self.f.change)), self.vrun.input_hash)
        auto_row = next(a for i in self.f.r1.refresh().sections["interfaces"].values() for a in i["addresses"].values() if a["source"] == "AUTO")
        self.assertEqual(auto_row["cidr"], "")

    def test_configlet_dependencies_mirror_the_validation_graph_with_typed_edges(self):
        cfg_of_node = {c["source"]["node_id"]: c["cfg_id"] for c in self.doc["configlets"]
                       if "address-family activation" not in c["description"]}
        persisted = {(d.configlet.cfg_id, d.depends_on.cfg_id)
                     for d in models.ConfigletDependency.objects.filter(configlet__plan=self.plan)}
        for edge in self.vrun.dependency_graph["edges"]:
            a, b = cfg_of_node.get(edge["from"]), cfg_of_node.get(edge["to"])
            if a and b and a != b:
                with self.subTest(edge=f"{edge['from']} -> {edge['to']}"):
                    self.assertIn((a, b), persisted)
        # representative typed relationships
        binding = by_noun(self.doc, "routing interface attachment", device="R1")
        kinds = {d["cfg_id"]: d["edge_types"] for d in binding["dependencies"]}
        self.assertEqual(kinds[by_noun(self.doc, "interface definition", device="R1", contains="Ethernet1")["cfg_id"]], ["INTERFACE_BEFORE_SERVICE"])
        self.assertEqual(kinds[by_noun(self.doc, "OSPF process definition")["cfg_id"]], ["REQUIRES"])
        attach = by_noun(self.doc, "ACL attachment")
        self.assertIn("DEFINE_BEFORE_ATTACH", {t for d in attach["dependencies"] for t in d["edge_types"]})
        activation = by_noun(self.doc, "BGP address-family activation")
        self.assertEqual([d["cfg_id"] for d in activation["dependencies"]], [by_noun(self.doc, "BGP neighbor definition")["cfg_id"]])
        # integrity: same plan, no self edge, none duplicated
        self.assertEqual(len(persisted), self.doc["summary"]["dependencies"])
        self.assertTrue(all(a != b for a, b in persisted))
        self.assertFalse(models.ConfigletDependency.objects.filter(configlet__plan=self.plan).exclude(depends_on__plan=self.plan).exists())

    def test_order_is_topological_deterministic_and_identified_by_position_not_database_id(self):
        configlets = self.doc["configlets"]
        self.assertEqual([c["cfg_id"] for c in configlets], [f"CFG-{i:03d}" for i in range(1, len(configlets) + 1)])
        position = {c["cfg_id"]: c["sequence"] for c in configlets}
        for edge in self.doc["dependencies"]:
            self.assertLess(position[edge["depends_on"]], position[edge["configlet"]])
        priorities_in_order = [c["priority"] for c in configlets]
        self.assertEqual(priorities_in_order, sorted(priorities_in_order), "no inversion in this Change, so classes are non-decreasing")
        self.assertEqual(cps.compute_plan(self.f.change, self.vrun), cps.compute_plan(self.f.change, self.vrun))
        first_pass = [c["cfg_id"] for c in cps.compute_plan(self.f.change, self.vrun)["configlets"]]
        self.assertEqual(first_pass, [c["cfg_id"] for c in configlets])

    def test_previous_state_and_verification_are_declarative_placeholders_only(self):
        for configlet in models.Configlet.objects.filter(plan=self.plan):
            with self.subTest(configlet=configlet.cfg_id):
                self.assertEqual(configlet.previous_state_ref["status"], "UNKNOWN_DEFERRED")
                self.assertEqual(configlet.rollback_config, "")
                self.assertEqual(configlet.execution_status, models.ConfigletExecutionStatus.PENDING)
                requirements = configlet.verification_spec["requirements"]
                self.assertTrue(requirements)
                self.assertTrue(all(r["status"] == "DEFERRED" and r["owner"] == "PHASE_15" for r in requirements))
        codes = {w["code"] for w in self.doc["warnings"]}
        self.assertLessEqual({"PREVIOUS_STATE_DEFERRED", "VERIFICATION_REQUIREMENT_DEFERRED"}, codes)


class PlanFailureAndGraphTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.f = rich_change()
        cls.vrun = validate(cls.f.change, cls.f.sources)

    def node(self, device, node_type, contains=""):
        return graph_node(self.vrun, device, node_type, contains)

    def test_a_cross_device_dependency_becomes_a_configlet_dependency_and_interleaves_devices(self):
        r1, r2 = self.node("R1", "interface", "Ethernet1"), self.node("R2", "interface", "Ethernet1")
        synthetic = clone_run(self.vrun, dependency_graph=graph_with_edges(self.vrun, (r1, r2, "REFERENCES")))
        doc = cps.compute_plan(self.f.change, synthetic)
        first, second = by_noun(doc, "interface definition", device="R1", contains="Ethernet1"), by_noun(doc, "interface definition", device="R2")
        self.assertIn(second["cfg_id"], [d["cfg_id"] for d in first["dependencies"]])
        self.assertEqual((first["device"], second["device"]), ("R1", "R2"))  # the dependency crosses devices
        self.assertLess(second["sequence"], first["sequence"], "R2's Configlet is ordered before R1's, not after all of R1")

    def test_a_dependency_overrides_priority_order_and_the_inversion_is_reported(self):
        address = self.node("R1", "address", "192.0.2.0/31")  # priority 3
        attachment = self.node("R1", "acl_attachment")         # priority 7
        synthetic = clone_run(self.vrun, dependency_graph=graph_with_edges(self.vrun, (address, attachment, "REQUIRES")))
        doc = cps.compute_plan(self.f.change, synthetic)
        dependent, dependency = by_noun(doc, "address assignment", contains="192.0.2.0/31"), by_noun(doc, "ACL attachment")
        self.assertLess(dependency["sequence"], dependent["sequence"])
        inversion = [w for w in doc["warnings"] if w["code"] == "PRIORITY_DEPENDENCY_INVERSION"]
        self.assertEqual([w["details"] for w in inversion], [{"configlet": dependent["cfg_id"], "depends_on": dependency["cfg_id"]}])
        self.assertIn("PRIORITY_DEPENDENCY_INVERSION", dependent["warnings"])
        self.assertEqual(dependency["priority"], 7, "priority is not rewritten to hide the inversion")

    def test_unsafe_graphs_and_renderer_failures_fail_safely_with_a_stable_code_and_persist_nothing(self):
        a, b = self.node("R1", "interface", "Ethernet1"), self.node("R1", "interface", "Ethernet2")
        good_run = self.vrun

        def truncated(run):
            graph = graph_with_edges(run)
            graph["summary"] = {**graph["summary"], "truncated": True}
            return {"dependency_graph": graph}

        def unknown_node(run):
            graph = graph_with_edges(run)
            graph["nodes"].append({"id": "R1/warp_drive/x", "device": "R1", "type": "warp_drive", "object_id": "x", "label": "x"})
            return {"dependency_graph": graph}

        # (label, expected code, validation-run overrides, patch context)
        cases = [
            ("dependency cycle", "CONFIGLET_CYCLE", {"dependency_graph": graph_with_edges(good_run, (a, b, "REQUIRES"), (b, a, "REQUIRES"))}, None),
            ("dependency marked MISSING", "DEPENDENCY_MISSING", {"dependency_graph": graph_with_edges(good_run, (a, b, "REQUIRES"), status="MISSING")}, None),
            ("edge to an unknown node", "DEPENDENCY_MISSING", {"dependency_graph": graph_with_edges(good_run, (a, "R1/interface/nope", "REQUIRES"))}, None),
            ("truncated graph", "GRAPH_TRUNCATED", truncated(good_run), None),
            ("unknown object type", "UNKNOWN_OBJECT_TYPE", unknown_node(good_run), None),
            ("AUTO value missing from the run", "AUTO_VALUE_MISSING", {"derived_facts": []}, None),
            ("accepted intent no longer matches the run", "INPUT_HASH_MISMATCH", {"input_hash": "0" * 64}, None),
            ("renderer reports the object unsupported", "UNSUPPORTED_OBJECT", {}, mock.patch.object(snippets, "has_unsupported_marker", return_value=True)),
            ("renderer emits nothing", "RENDERER_INCONSISTENT", {}, mock.patch.object(snippets, "added_lines", return_value=[])),
        ]
        for label, code, overrides, patch in cases:
            with self.subTest(case=label):
                try:
                    with transaction.atomic():  # each row is isolated: its cloned run must not become "latest" for the next row
                        before = counts()
                        run = clone_run(good_run, **overrides) if overrides else good_run
                        before_runs = counts()
                        with (patch or mock.MagicMock()):
                            with self.assertRaises(cps.PlanGenerationError) as raised:
                                if code == "INPUT_HASH_MISMATCH":  # a currency reason at the gate, so exercise it below the gate
                                    cps.compute_plan(self.f.change, run)
                                else:
                                    cps.build_change_plan(self.f.change, actor="tester")
                        self.assertEqual(raised.exception.code, code)
                        self.assertEqual(counts(), before_runs, "no partial plan is persisted")
                        raise _Rollback
                except _Rollback:
                    pass

    def test_a_self_edge_never_becomes_a_self_dependency(self):
        a = self.node("R1", "interface", "Ethernet1")
        doc = cps.compute_plan(self.f.change, clone_run(self.vrun, dependency_graph=graph_with_edges(self.vrun, (a, a, "REQUIRES"))))
        self.assertTrue(all(e["configlet"] != e["depends_on"] for e in doc["dependencies"]))

    def test_intent_with_an_unresolved_placeholder_is_refused_rather_than_planned(self):
        f = rich_change(ospf_process_id=False)
        run = validate(f.change, f.sources)
        self.assertEqual(run.status, "BLOCKED")
        self.assertIn("OSPF_PROCESS_ID_REQUIRED", {item["code"] for item in run.report["findings"]})
        with self.assertRaises(cps.PlanGenerationError) as raised:
            cps.build_change_plan(f.change)
        self.assertEqual(raised.exception.code, "VALIDATION_BLOCKED")
        # Defense in depth: even if eligibility were bypassed and the pure
        # planner were handed this run directly, the preview placeholder is
        # still not deployable.
        with self.assertRaises(cps.PlanGenerationError) as planner_error:
            cps.compute_plan(f.change, run)
        self.assertEqual(planner_error.exception.code, "UNRESOLVED_PLACEHOLDER")
        self.assertEqual(planner_error.exception.details["placeholders"], ["<process-id-required>"])
        self.assertFalse(models.ChangePlan.objects.filter(change=f.change).exists())

    def test_foundation_configlet_only_for_a_rename_and_disabled_objects_are_skipped_with_a_warning(self):
        f = simple_pass_change()
        f.r1.set("device.hostname", "R1-RENAMED")
        route = f.r1.static_route("10.9.0.0/24", next_hop="192.0.2.1")
        f.r1.set(f"routing.static_routes.{route['id']}.enabled", "false")
        validate(f.change, f.sources)
        doc = cps.serialize_plan(cps.build_change_plan(f.change)[0])
        foundation = doc["configlets"][0]
        self.assertEqual((foundation["priority"], foundation["stage"], foundation["rendered_config"]),
                         (1, "FOUNDATION_ACCESS", "hostname R1-RENAMED"))
        self.assertFalse([c for c in doc["configlets"] if c["description"].startswith("static route")])
        self.assertIn("NO_DEPLOYABLE_CONFIG", {w["code"] for w in doc["warnings"]})


class PlanPersistenceTests(TestCase):
    def test_generation_is_atomic(self):
        f = simple_pass_change()
        validate(f.change, f.sources)
        before = counts()
        with mock.patch.object(models.ConfigletDependency, "save", side_effect=RuntimeError("injected failure")):
            with self.assertRaises(RuntimeError):
                cps.build_change_plan(f.change)
        self.assertEqual(counts(), before, "an exception mid-generation leaves no plan, Configlet, dependency or audit row")

    def test_generation_is_idempotent_and_a_new_validation_run_creates_a_new_plan_without_touching_history(self):
        f = simple_pass_change()
        validate(f.change, f.sources)
        plan, created = cps.build_change_plan(f.change, actor="tester")
        again, created_again = cps.build_change_plan(f.change, actor="tester")
        self.assertEqual((created, created_again, again.pk), (True, False, plan.pk))
        self.assertEqual((models.ChangePlan.objects.count(), models.Configlet.objects.filter(change=f.change).count(),
                          models.AuditEvent.objects.filter(event_type=models.AuditEventType.PLAN_BUILT).count()),
                         (1, plan.configlets.count(), 1))
        snapshot = list(plan.configlets.order_by("sequence").values_list("cfg_id", "rendered_config", "created_at"))

        validate(f.change, f.sources)  # identical accepted intent, a NEW validation run
        self.assertEqual(cps.get_plan_currency(plan)["reasons"], ["VALIDATION_SUPERSEDED"])
        self.assertIsNone(cps.get_current_plan(f.change))
        second, second_created = cps.build_change_plan(f.change, actor="tester")
        self.assertTrue(second_created)
        self.assertNotEqual(second.pk, plan.pk)
        self.assertEqual(second.plan_hash, plan.plan_hash, "the same input yields the same semantic plan")
        self.assertEqual([r[:2] for r in snapshot], list(second.configlets.order_by("sequence").values_list("cfg_id", "rendered_config")))
        self.assertEqual(snapshot, list(plan.configlets.order_by("sequence").values_list("cfg_id", "rendered_config", "created_at")))
        self.assertEqual(models.ChangePlan.objects.filter(change=f.change).count(), 2)
        self.assertEqual(cps.get_current_plan(f.change), second)

    def test_a_plan_goes_stale_when_intent_or_a_consumed_source_changes_and_is_never_silently_rebuilt(self):
        f = simple_pass_change()
        validate(f.change, f.sources)
        plan, _ = cps.build_change_plan(f.change)
        self.assertEqual(cps.get_plan_currency(plan)["state"], "CURRENT")
        changed_source = make_sources(netbox=netbox_data(ip_addresses=[nb_ip("203.0.113.9/24", "H1", "eth0")]))
        self.assertIn("SOURCE_CHANGED:NETBOX", cps.get_plan_currency(plan, sources=changed_source)["reasons"])

        f.r1.set(f"interfaces.{f.a['id']}.description", "edited after planning")
        currency = cps.get_plan_currency(plan)
        self.assertEqual((currency["state"], currency["reasons"]), ("STALE", ["ACCEPTED_INTENT_CHANGED"]))
        self.assertIsNone(cps.get_current_plan(f.change))
        with self.assertRaises(cps.PlanGenerationError) as raised:
            cps.build_change_plan(f.change)
        self.assertEqual(raised.exception.code, "VALIDATION_STALE")
        self.assertEqual(models.ChangePlan.objects.filter(change=f.change).count(), 1)
        validate(f.change, f.sources)
        self.assertEqual(cps.build_change_plan(f.change)[0].pk, cps.get_current_plan(f.change).pk)

    def test_plans_and_their_configlets_are_immutable_history_with_per_plan_identity(self):
        f = simple_pass_change()
        validate(f.change, f.sources)
        plan, _ = cps.build_change_plan(f.change)
        configlet = plan.configlets.first()
        for field, value in (("rendered_config", "tampered"), ("operation_type", ATTACH), ("deployment_priority", 9),
                             ("target_device", "R9"), ("description", "x")):
            with self.subTest(field=field):
                stale = models.Configlet.objects.get(pk=configlet.pk)
                setattr(stale, field, value)
                with self.assertRaises(ValueError):
                    stale.save()
        configlet.execution_status = models.ConfigletExecutionStatus.RENDERED  # execution phases own this field
        configlet.save()
        plan.summary = {}
        with self.assertRaises(ValueError):
            plan.save()
        validate(f.change, f.sources)
        other, _ = cps.build_change_plan(f.change)
        self.assertEqual(other.configlets.first().cfg_id, configlet.cfg_id)  # CFG-001 may exist in every plan generation
        with self.assertRaises(IntegrityError), transaction.atomic():
            models.Configlet.objects.create(
                change=f.change, plan=plan, cfg_id="CFG-901", sequence=configlet.sequence, target_device="R1",
                feature_namespace="interfaces", operation_type=DEFINE, deployment_priority=2)
        legacy = models.Configlet.objects.create(
            change=f.change, cfg_id="CFG-001", sequence=1, target_device="R1", feature_namespace="interfaces",
            operation_type=DEFINE, deployment_priority=2)
        self.assertIsNone(legacy.plan_id, "a hand-created (plan-less) Configlet keeps its Phase-8 identity rules")

    def test_a_pinned_validation_run_cannot_be_deleted_alone_but_the_whole_change_can(self):
        f = simple_pass_change()
        run = validate(f.change, f.sources)
        cps.build_change_plan(f.change)
        with self.assertRaises(models.models.deletion.RestrictedError):
            run.delete()
        f.change.delete()  # plans, Configlets, dependencies and runs all go with their Change
        self.assertEqual((models.ChangePlan.objects.count(), models.ChangeValidationRun.objects.count(),
                          models.Configlet.objects.count()), (0, 0, 0))

    def test_the_phase14_schema_change_is_one_focused_migration(self):
        from pathlib import Path

        directory = Path(models.__file__).parent / "migrations"
        text = (directory / "0004_phase14_change_plan.py").read_text()
        self.assertEqual(text.count("CreateModel"), 1)
        self.assertIn("ChangePlan", text)
        self.assertNotIn("RunPython", text)
        self.assertEqual(sorted(p.name for p in directory.glob("0*.py"))[:4],
                         ["0001_notification.py", "0002_phase8_device_intent_change_model.py",
                          "0003_phase13_change_validation_run.py", "0004_phase14_change_plan.py"])


class PlanSideEffectAndReportTests(TestCase):
    def test_building_a_plan_touches_no_device_netbox_git_notification_or_lifecycle(self):
        f = simple_pass_change()
        validate(f.change, f.sources)
        sections = {i.pk: i.latest_revision().sections for i in f.change.device_intents.all()}
        before = counts()
        boom = AssertionError("plan building attempted an outward action")
        with mock.patch.object(socket, "socket", side_effect=boom), mock.patch.object(socket, "getaddrinfo", side_effect=boom), \
                mock.patch.object(subprocess, "run", side_effect=boom), mock.patch.object(subprocess, "Popen", side_effect=boom), \
                mock.patch.object(urllib.request, "urlopen", side_effect=boom), \
                mock.patch.object(nsot_netbox, "_client", side_effect=boom):
            plan, _ = cps.build_change_plan(f.change, actor="tester")
        after = counts()
        added = {k: after[k] - before[k] for k in after if after[k] != before[k]}
        self.assertEqual(added, {"ChangePlan": 1, "Configlet": plan.configlets.count(),
                                 "ConfigletDependency": models.ConfigletDependency.objects.filter(configlet__plan=plan).count(),
                                 "AuditEvent": 1})
        f.change.refresh_from_db()
        self.assertEqual(f.change.lifecycle_state, models.ChangeLifecycleState.DRAFT)
        self.assertEqual((f.change.git_commit_ref, f.change.github_actions_run_ref, f.change.deployment_reference), ("", "", ""))
        self.assertEqual({i.pk: i.latest_revision().sections for i in f.change.device_intents.all()}, sections)
        self.assertFalse(plan.configlets.exclude(execution_status=models.ConfigletExecutionStatus.PENDING).exists())

    def test_the_json_report_is_deterministic_structured_and_secret_free(self):
        f = rich_change()
        interface_id = next(iter(f.r1.refresh().sections["interfaces"]))
        f.r1.force(f"interfaces.{interface_id}.password", "hunter2-injected")  # a manual DB edit must not leak
        f.r1.set(f"routing.bgp.{f.bgp['id']}.neighbors.{f.neighbor['id']}.password_ref", "vault:bgp/r1-r2")
        validate(f.change, f.sources)
        plan, _ = cps.build_change_plan(f.change)
        first, second = cps.serialize_plan(plan), cps.serialize_plan(plan)
        blob = json.dumps(first, sort_keys=True)
        self.assertEqual(blob, json.dumps(second, sort_keys=True))
        for key in ("plan", "validation", "summary", "stages", "configlets", "dependencies", "warnings", "limitations"):
            self.assertIn(key, first)
        self.assertNotIn("hunter2", blob)
        self.assertNotRegex(blob.lower(), r'"(password|secret|token|community|webhook)"')
        neighbor_text = by_noun(first, "BGP neighbor definition")["rendered_config"]
        self.assertIn("authentication reference present", neighbor_text)
        self.assertNotIn("password ", neighbor_text)
        self.assertEqual(cps.plan_report_filename(plan), f"{f.change.change_id}-plan-{str(plan.plan_id)[:8]}.json")
