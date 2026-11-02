"""Plan-level precheck / postcheck / scope / run persistence, on REAL validated Changes and REAL plans.

Devices, telemetry, DHCP and NetBox are faked (``helpers.health``, ``helpers.validation.make_sources``): a test that
contacts anything external is a defect.  Evaluator semantics are in ``test_health_engine``; HTTP in ``test_health_views``.
"""

from __future__ import annotations

import json
import socket
import subprocess
import urllib.request
from unittest import mock

from django.test import TestCase

from core import models
from core.services import change_plan_service as cps, health_service as hs, nsot_netbox
from core.services.health import persistence, requirements as reqs
from core.services.health.codes import CheckStatus as S, Phase
from core.tests.helpers import health as h
from core.tests.helpers.validation import change_in_state, clone_run, graph_node, graph_with_edges, rich_change, simple_pass_change, validate


def eos_for(*names):
    return {n: h.eos_outputs() for n in names}


def factory(*names, fail=None):
    return h.session_factory({n: (h.linux_outputs() if n in ("R3", "R4") else h.eos_outputs()) for n in names}, fail=fail)


def precheck(change, sources, *, persist=False, session_factory=None, snapshot=None, **kwargs):
    return hs.run_change_precheck(change, actor="tester", sources=sources, snapshot=snapshot or h.snapshot(),
                                  session_factory=session_factory or factory("R1", "R2"), now=h.NOW, persist=persist, **kwargs)


def find(outcome, code, device=None):
    return [r for r in outcome.results if r.check_code == code and (device is None or r.device == device)]


class PrecheckGateTests(TestCase):
    def test_validation_and_plan_prerequisites_gate_every_precheck(self):
        # (label, build, expected result, codes that must appear).  A refused precheck touches NO device and never repairs anything.
        def with_plan(state):
            change, sources = change_in_state(state)
            if state in ("PASS", "PASS_WITH_WARNINGS"):
                cps.build_change_plan(change, actor="t", sources=sources)
            return change, sources

        def stale_plan():
            change, sources = change_in_state("PASS")
            cps.build_change_plan(change, actor="t", sources=sources)
            validate(change, sources)  # a NEWER run supersedes the plan's pinned validation
            return change, sources

        def stale_validation():
            f = simple_pass_change()
            validate(f.change, f.sources)
            cps.build_change_plan(f.change, actor="t", sources=f.sources)
            f.r1.set(f"interfaces.{f.a['id']}.description", "edited after validation")
            return f.change, f.sources

        rows = [
            ("never validated", lambda: change_in_state("NEVER_RUN"), "INCOMPLETE", {"VALIDATION_NOT_PASSING"}),
            ("validation BLOCKED", lambda: with_plan("BLOCKED"), "BLOCKED", {"VALIDATION_NOT_PASSING"}),
            ("validation INCOMPLETE", lambda: with_plan("INCOMPLETE"), "INCOMPLETE", {"VALIDATION_NOT_PASSING"}),
            ("validation STALE", stale_validation, "BLOCKED", {"PLAN_VALIDATION_STALE", "PLAN_STALE"}),
            ("validation passing, no plan", lambda: change_in_state("PASS"), "INCOMPLETE", {"PLAN_MISSING"}),
            ("plan superseded by a newer validation", stale_plan, "BLOCKED", {"PLAN_STALE"}),
            ("CURRENT validation + CURRENT plan is evaluated", lambda: with_plan("PASS"), "PASS", {"PLAN_VALIDATION_CURRENT", "PLAN_CURRENT"}),
            ("PASS_WITH_WARNINGS validation + CURRENT plan is evaluated", lambda: with_plan("PASS_WITH_WARNINGS"), "PASS", {"PLAN_CURRENT"}),
        ]
        for label, build, result, expected_codes in rows:
            with self.subTest(case=label):
                change, sources = build()
                before = {m.__name__: m.objects.count() for m in (models.ChangeValidationRun, models.ChangePlan, models.Configlet)}
                gated = result != "PASS"
                session = factory("R1", "R2")
                outcome = precheck(change, sources, session_factory=session)
                self.assertEqual(outcome.result, result)
                self.assertLessEqual(expected_codes, {r.check_code for r in outcome.results})
                self.assertEqual({m.__name__: m.objects.count() for m in (models.ChangeValidationRun, models.ChangePlan, models.Configlet)}, before,
                                 "a precheck never re-runs validation and never builds or edits a plan")
                if gated:
                    self.assertEqual((session.created, outcome.scope), ([], None), "a refused precheck touches no device")


class ScopeTests(TestCase):
    def test_scope_is_derived_from_the_plan_never_from_names(self):
        f = rich_change()
        run = validate(f.change, f.sources)
        plan, _ = cps.build_change_plan(f.change, actor="t", sources=f.sources)
        scope = hs.build_affected_scope(plan)
        self.assertEqual({n: d.role for n, d in scope.devices.items()}, {"R1": "TARGET", "R2": "TARGET", "R3": "TARGET"})
        self.assertNotIn("S4", scope.devices)
        self.assertEqual(scope.to_dict(), hs.build_affected_scope(plan).to_dict(), "deterministic")

        # validation-derived peers (BGP peer / FHRP member / a finding's related device) are PEERs; a target never is
        g = simple_pass_change()
        base = validate(g.change, g.sources)
        derived = [{"type": "BGP_PEER_RESOLVED", "device": "R1", "neighbor_id": "n", "peer_address": "192.0.2.9", "scope": "CANDIDATE", "peer_device": "S4"},
                   {"type": "BGP_PEER_RESOLVED", "device": "R1", "neighbor_id": "m", "peer_address": "192.0.2.1", "scope": "CANDIDATE", "peer_device": "R2"},
                   {"type": "FHRP_DOMAIN", "devices": ["R1", "S3"], "virtual_ips": [], "members": []},
                   {"type": "BGP_PEER_RESOLVED", "device": "S1", "peer_device": "S2"}]  # neither is a target: irrelevant to this change
        report = {**base.report, "findings": [{"code": "OSPF_ONE_SIDED", "device": "R1", "related_devices": ["mgmt_swt"], "severity": "WARNING"}]}
        clone_run(base, derived_facts=derived, report=report)
        peer_plan, _ = cps.build_change_plan(g.change, actor="t", sources=g.sources)
        peers = hs.build_affected_scope(peer_plan)
        self.assertEqual({n: d.role for n, d in peers.devices.items()},
                         {"R1": "TARGET", "R2": "TARGET", "S4": "PEER", "S3": "PEER", "mgmt_swt": "PEER"})
        self.assertIn("BGP_PEER_OF:R1", peers.devices["S4"].reasons)
        self.assertIn("FHRP_DOMAIN_MEMBER", peers.devices["S3"].reasons)

        # cross-device Configlet dependencies are recorded as reasons on the (already target) devices
        h1 = simple_pass_change()
        r = validate(h1.change, h1.sources)
        edge = (graph_node(r, "R2", "address"), graph_node(r, "R1", "interface", "Ethernet1"), "REQUIRES")
        clone_run(r, dependency_graph=graph_with_edges(r, edge))
        cross, _ = cps.build_change_plan(h1.change, actor="t", sources=h1.sources)
        scope2 = hs.build_affected_scope(cross)
        self.assertIn("DEPENDS_ON:R1", scope2.devices["R2"].reasons)
        self.assertIn("DEPENDED_ON_BY:R2", scope2.devices["R1"].reasons)


class PrecheckBlockingTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.f = simple_pass_change()
        validate(cls.f.change, cls.f.sources)
        cls.plan, _ = cps.build_change_plan(cls.f.change, actor="t", sources=cls.f.sources)
        g = simple_pass_change()
        base = validate(g.change, g.sources)
        clone_run(base, derived_facts=[{"type": "BGP_PEER_RESOLVED", "device": "R1", "neighbor_id": "n", "peer_address": "192.0.2.9", "scope": "CANDIDATE", "peer_device": "S4"}])
        cls.peer_change, cls.peer_sources = g.change, g.sources
        cps.build_change_plan(g.change, actor="t", sources=g.sources)

    def test_only_the_affected_scope_is_judged_and_blocking_follows_the_policy(self):
        timeout = {"R1": h.live.LiveError("TIMEOUT")}
        rows = [  # label, snapshot kwargs, precheck kwargs, expected result, a (code, status) that must be present
            ("everything healthy", {}, {}, "PASS", ("DEVICE_REACHABLE", S.PASS)),
            ("an UNRELATED device (S4) is expired", {"ages": {"S4": 900}}, {}, "PASS", None),
            ("an unrelated device is critical", {"cpu": {"S4": 99}, "ages": {"S3": 900}}, {}, "PASS", None),
            ("target telemetry expired but live proves it reachable", {"ages": {"R1": 900}}, {}, "PASS_WITH_WARNINGS", ("DEVICE_TELEMETRY_STALE", S.WARN)),
            ("target telemetry expired and no live read", {"ages": {"R1": 900}}, {"live_reads": False}, "BLOCKED", ("DEVICE_TELEMETRY_STALE", S.FAIL)),
            ("target unreachable live, telemetry fresh", {}, {"session_factory": factory("R1", "R2", fail=timeout)}, "INCOMPLETE", ("DEVICE_UNREACHABLE", S.UNKNOWN)),
            ("target unreachable live AND telemetry expired", {"ages": {"R1": 900}}, {"session_factory": factory("R1", "R2", fail=timeout)}, "BLOCKED", ("DEVICE_UNREACHABLE", S.FAIL)),
            ("target CPU critical", {"cpu": {"R2": 95}}, {}, "BLOCKED", ("CPU_HIGH", S.FAIL)),
            ("target CPU moderate", {"cpu": {"R2": 75}}, {}, "PASS_WITH_WARNINGS", ("CPU_HIGH", S.WARN)),
            ("target memory critical", {"memory": {"R1": 95}}, {}, "BLOCKED", ("MEMORY_HIGH", S.FAIL)),
            ("target link down only warns", {"links": [h.edge("R1", "S1", "DOWN")]}, {}, "PASS_WITH_WARNINGS", ("LINK_HEALTH_DEGRADED", S.FAIL)),
            ("monitoring down but every target is live-verifiable", {"summary": h.unavailable_topology()}, {}, "PASS_WITH_WARNINGS", ("MONITORING_PIPELINE_UNHEALTHY", S.WARN)),
            ("monitoring down and no live evidence", {"summary": h.unavailable_topology()}, {"live_reads": False}, "INCOMPLETE", ("DEVICE_TELEMETRY_UNAVAILABLE", S.UNKNOWN)),
        ]
        for label, snap, kwargs, result, expect in rows:
            with self.subTest(case=label):
                outcome = precheck(self.f.change, self.f.sources, snapshot=h.snapshot(**snap), **kwargs)
                self.assertEqual(outcome.result, result)
                if expect:
                    self.assertIn(expect, [(r.check_code, r.status) for r in outcome.results])
                if result == "BLOCKED":
                    self.assertTrue(find(outcome, "PLAN_HEALTH_PRECONDITION_FAILED") or find(outcome, "PLAN_VALIDATION_STALE"))
                judged = {r.device for r in outcome.results} - {"FLEET", self.f.change.change_id}
                self.assertEqual(judged, {"R1", "R2"}, "only the plan's affected devices are ever judged; S1/S3/S4/... never appear")

    def test_peer_devices_supply_evidence_but_never_block(self):
        rows = [
            ("a hot but reachable peer", {"cpu": {"S4": 99}}, {}, ("CPU_HIGH", S.FAIL)),
            ("an unreachable peer with expired telemetry", {"ages": {"S4": 900}}, {"fail": {"S4": h.live.LiveError("TIMEOUT")}}, ("DEVICE_UNREACHABLE", S.FAIL)),
        ]
        for label, snap, factory_kwargs, expect in rows:
            with self.subTest(case=label):
                outcome = precheck(self.peer_change, self.peer_sources, snapshot=h.snapshot(**snap), session_factory=factory("R1", "R2", "S4", **factory_kwargs))
                peer_results = [r for r in outcome.results if r.device == "S4"]
                self.assertIn(expect, [(r.check_code, r.status) for r in peer_results])
                self.assertTrue(all(r.role == "PEER" and not r.blocking for r in peer_results))
                self.assertEqual(outcome.result, "PASS_WITH_WARNINGS", "a failing peer is a warning, never a blocker")

    def test_a_relay_change_needs_the_dhcp_services_healthy(self):
        f = rich_change()
        validate(f.change, f.sources)
        cps.build_change_plan(f.change, actor="t", sources=f.sources)
        live_all = lambda: factory("R1", "R2", "R3")  # noqa: E731
        healthy = {"nmas": {"ipv4": "active", "ipv6": "active"}, "r2": {"ipv4": "active", "ipv6": "inactive"}, "error": ""}
        dead = {**healthy, "r2": {"ipv4": "inactive", "ipv6": "inactive"}}
        rows = [("both servers active", healthy, "PASS", S.PASS), ("a server with no active family", dead, "BLOCKED", S.FAIL),
                ("cannot inspect", {"nmas": None, "r2": None, "error": "INSPECTION_FAILED"}, "INCOMPLETE", S.UNKNOWN)]
        for label, state, result, status in rows:
            with self.subTest(case=label):
                outcome = precheck(f.change, f.sources, session_factory=live_all(), dhcp_state=state)
                self.assertEqual([r.status for r in find(outcome, "DHCP_SERVICE_UNHEALTHY")], [status])
                self.assertEqual(outcome.result, result)
        # a plan with no DHCP relay never inspects the servers
        with mock.patch("core.services.health.live.dhcp_service_state", side_effect=AssertionError("dhcp inspected")):
            precheck(self.f.change, self.f.sources)


class PrecheckVersusPostcheckTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.f = simple_pass_change()
        validate(cls.f.change, cls.f.sources)
        cls.plan, _ = cps.build_change_plan(cls.f.change, actor="t", sources=cls.f.sources)
        cls.requirements = reqs.normalize_plan(cls.plan)

    def test_future_state_absence_passes_the_precheck_but_fails_the_postcheck(self):
        # the live devices have NONE of the planned interfaces / addresses yet
        empty = {"R1": h.eos_outputs(interfaces={"Management0": ("connected", "up")}), "R2": h.eos_outputs(interfaces={"Management0": ("connected", "up")})}
        outcome = precheck(self.f.change, self.f.sources, session_factory=h.session_factory(empty))
        self.assertEqual(outcome.result, "PASS")
        future = [r for r in outcome.evaluation.results if r.requirement in ("INTERFACE_PRESENT", "ADDRESS_PRESENT")]
        self.assertTrue(future and all(r.status == S.NOT_APPLICABLE and not r.blocking for r in future))
        world = h.evidence_set(*[h.device_evidence(n, interfaces={"Management0": {"admin": "UP", "oper": "UP"}}, addresses={"Management0": []}) for n in ("R1", "R2")])
        evaluation, _ = hs.run_plan_postcheck(self.plan, evidence=world, persist=False)
        self.assertEqual(evaluation.result, "FAIL")
        self.assertIn("INTERFACE_MISSING", {r.check_code for r in evaluation.results})

    def test_postcheck_engine_passes_only_when_every_requirement_is_observed(self):
        world = h.satisfied_evidence(self.requirements)
        evaluation, run = hs.run_plan_postcheck(self.plan, actor="later-phase", evidence=world, persist=True)
        self.assertEqual((evaluation.result, run.mode, run.status), ("PASS", "CHANGE_POSTCHECK", "PASS"))
        self.assertEqual(evaluation.counts["FAIL"] + evaluation.counts["UNKNOWN"], 0)
        # one missing address -> FAIL naming that device; a device with no evidence -> INCOMPLETE (never PASS)
        r1 = world.device("R1")
        addresses = dict(r1.facts("addresses")); addresses.pop(next(iter(addresses)))
        r1.groups["addresses"] = h.ev.FactGroup(addresses, "LIVE", h.NOW)
        broken, _ = hs.run_plan_postcheck(self.plan, evidence=world, persist=False)
        self.assertEqual(broken.result, "FAIL")
        self.assertEqual({(r.device, r.check_code) for r in broken.results if r.status == S.FAIL}, {("R1", "ADDRESS_MISSING")})
        _, failed_run = hs.run_plan_postcheck(self.plan, actor="later-phase", evidence=world, persist=True)
        self.assertEqual(failed_run.status, "FAIL")
        summary = [r for r in failed_run.report["results"] if r["check_code"] == "POSTCHECK_REQUIREMENT_FAILED"]
        self.assertEqual([(r["status"], r["role"]) for r in summary], [("FAIL", "PLAN")])
        self.assertEqual(summary[0]["observed"]["failed"], [f"{r.cfg_id}:ADDRESS_MISSING" for r in broken.results if r.check_code == "ADDRESS_MISSING"])
        fresh = h.satisfied_evidence(self.requirements)
        del fresh.devices["R2"]  # no evidence at all for R2
        incomplete, _ = hs.run_plan_postcheck(self.plan, evidence=fresh, persist=False)
        self.assertEqual(incomplete.result, "INCOMPLETE")
        self.assertEqual({r.check_code for r in incomplete.results if r.status == S.UNKNOWN}, {"POSTCHECK_DATA_UNAVAILABLE"})
        self.assertEqual({r.device for r in incomplete.results if r.status == S.UNKNOWN}, {"R2"})

    def test_plans_built_before_expected_facts_existed_are_incomplete_not_guessed(self):
        f = simple_pass_change()
        validate(f.change, f.sources)
        plan, _ = cps.build_change_plan(f.change, actor="t", sources=f.sources)
        for configlet in plan.configlets.all():  # simulate a historical plan: descriptors without ``expected``
            spec = json.loads(json.dumps(configlet.verification_spec))
            for requirement in spec["requirements"]:
                requirement.pop("expected")
            models.Configlet.objects.filter(pk=configlet.pk).update(verification_spec=spec)
        world = h.evidence_set(*[h.device_evidence(n, interfaces={"Ethernet1": {"admin": "UP", "oper": "UP"}}, addresses={"Ethernet1": ["192.0.2.0/31"]})
                                 for n in ("R1", "R2")])
        evaluation, _ = hs.run_plan_postcheck(plan, evidence=world, persist=False)
        self.assertEqual(evaluation.result, "INCOMPLETE")
        self.assertEqual({r.check_code for r in evaluation.results}, {"REQUIREMENT_DESCRIPTOR_INCOMPLETE"})
        pre = precheck(f.change, f.sources)
        self.assertEqual(pre.result, "INCOMPLETE", "a precheck cannot trust a plan whose descriptors carry no expected facts")


class PlanDescriptorAndEngineTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.f = rich_change()
        validate(cls.f.change, cls.f.sources)
        cls.plan, _ = cps.build_change_plan(cls.f.change, actor="t", sources=cls.f.sources)

    def test_planner_descriptors_carry_the_expected_facts_of_every_object_family(self):
        by_kind = {}
        for configlet in self.plan.configlets.all():
            for descriptor in configlet.verification_spec["requirements"]:
                by_kind.setdefault((descriptor["requirement"], descriptor["device"]), []).append(descriptor)
                self.assertEqual((descriptor["schema_version"], descriptor["status"], descriptor["owner"]), (2, "DEFERRED", "PHASE_15"))
        # an INDEPENDENT oracle: what the rich_change fixture's accepted intent says, written down by hand
        oracle = {
            ("ADDRESS_PRESENT", "R1"): [{"interface": "Ethernet1", "address": "192.0.2.0/31", "family": 4},
                                        {"interface": "Ethernet2", "address": "198.51.100.1/29", "family": 4},  # AUTO: the validation-derived PROPOSED value
                                        {"interface": "Vlan10", "address": "192.168.10.11/24", "family": 4}],
            ("ROUTE_INTENDED", "R1"): [{"prefix": "10.9.0.0/24", "family": 4, "next_hop": "192.0.2.1", "exit_interface": ""}],
            ("ROUTING_INTERFACE_ENABLED", "R1"): [{"protocol": "ospf", "version": "OSPFV2", "interface": "Ethernet1", "area": "0.0.0.0", "passive": False}],
            ("BGP_PEER_INTENDED", "R1"): [{"peer": "192.0.2.1", "family": 4, "remote_asn": 65002, "local_asn": 65001, "shutdown": False}],
            ("FHRP_GROUP_INTENDED", "R1"): [{"interface": "Vlan10", "protocol": "VARP", "virtual_addresses": ["192.168.10.1"]}],
            ("DHCP_RELAY_INTENDED", "R1"): [{"interface": "Vlan10", "destination": "192.168.200.100", "family": 4}],
            ("ACL_DEFINED", "R1"): [{"name": "EDGE-IN", "family": "IPV4"}],
            ("ACL_ATTACHMENT_INTENDED", "R1"): [{"acl_name": "EDGE-IN", "interface": "Vlan10", "direction": "IN"}],
            ("NAT_RULE_INTENDED", "R3"): [{"inside_interface": "eth1", "outside_interface": "eth2", "mode": "PAT", "original_source": "10.0.0.0/8"}],
        }
        for key, expected in oracle.items():
            with self.subTest(requirement=key):
                self.assertEqual(sorted((d["expected"] for d in by_kind[key]), key=str), sorted(expected, key=str))
        self.assertEqual({d["expected"]["interface"] for d in by_kind[("INTERFACE_PRESENT", "R1")]}, {"Ethernet1", "Ethernet2", "Vlan10"})
        auto = next(d["expected"] for d in by_kind[("ADDRESS_PRESENT", "R1")] if d["expected"]["interface"] == "Ethernet2")
        self.assertRegex(auto["address"], r"^198\.51\.100\.\d+/29$", "an AUTO address expects the validation-derived PROPOSED value")

    def test_engine_evaluates_a_real_plan_and_reports_what_it_cannot_verify(self):
        requirements = reqs.normalize_plan(self.plan)
        world = h.satisfied_evidence(requirements)
        post = hs.evaluate_plan_requirements(self.plan, Phase.POSTCHECK, world)
        self.assertEqual(post.counts["FAIL"], 0)
        self.assertEqual(post.result, "INCOMPLETE", "the synthetic world carries no routing_config facts, so the routing configuration checks stay UNKNOWN")
        # Phase 4 gave the routing process / binding / BGP network requirements real evaluators: nothing is "not implemented" any more
        self.assertEqual(post.summary["unverified"], [])
        self.assertEqual({r.check_code for r in post.results if r.status == S.UNKNOWN}, {"POSTCHECK_DATA_UNAVAILABLE"})
        passed = {r.requirement for r in post.results if r.status == S.PASS}
        self.assertLessEqual({"INTERFACE_PRESENT", "ADDRESS_PRESENT", "STATIC_ROUTE_PRESENT", "OSPF_NEIGHBOR_EXPECTED", "BGP_NEIGHBOR_EXPECTED", "FHRP_VIRTUAL_ADDRESS_PRESENT",
                              "DHCP_RELAY_CONFIG_PRESENT", "ACL_DEFINITION_PRESENT", "ACL_ATTACHMENT_PRESENT", "NAT_RULE_PRESENT"}, passed)
        pre = hs.evaluate_plan_requirements(self.plan, Phase.PRECHECK, h.evidence_set(*[h.device_evidence(n) for n in ("R1", "R2", "R3")]))
        self.assertNotIn(pre.result, ("BLOCKED",), "future-state requirements never block a precheck")
        self.assertEqual(hs.evaluate_plan_requirements(self.plan, Phase.POSTCHECK, world).counts, post.counts, "deterministic")


class RunPersistenceAndSideEffectTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.f = simple_pass_change()
        validate(cls.f.change, cls.f.sources)
        cls.plan, _ = cps.build_change_plan(cls.f.change, actor="t", sources=cls.f.sources)

    def snapshot_state(self):
        change = models.Change.objects.get(pk=self.f.change.pk)
        return {
            "counts": {m.__name__: m.objects.count() for m in (models.Change, models.ChangeValidationRun, models.ChangePlan, models.Configlet,
                                                              models.ConfigletDependency, models.ChangeLifecycleEvent, models.Notification,
                                                              models.DeviceIntent, models.DeviceIntentRevision, models.IntentFieldState)},
            "change": (change.lifecycle_state, change.git_commit_ref, change.github_actions_run_ref, change.deployment_reference),
            "configlets": list(models.Configlet.objects.values_list("pk", "execution_status", "rendered_config", "verification_spec", "updated_at")),
            "plan": list(models.ChangePlan.objects.values_list("pk", "plan_hash", "created_at")),
        }

    def test_an_explicit_precheck_is_recorded_append_only_and_has_no_other_effect(self):
        before = self.snapshot_state()
        forbidden = AssertionError("external access during a precheck")
        with mock.patch.object(socket.socket, "connect", side_effect=forbidden), mock.patch.object(subprocess, "run", side_effect=forbidden), \
                mock.patch.object(subprocess, "Popen", side_effect=forbidden), mock.patch.object(urllib.request, "urlopen", side_effect=forbidden), \
                mock.patch.object(nsot_netbox, "_client", side_effect=forbidden), mock.patch("netmiko.ConnectHandler", side_effect=forbidden):
            outcome = precheck(self.f.change, self.f.sources, persist=True)
        after = self.snapshot_state()
        for key in ("change", "configlets", "plan"):
            self.assertEqual(after[key], before[key], f"{key} must be untouched")
        added = {k: after["counts"][k] - before["counts"][k] for k in before["counts"]}
        self.assertEqual({k: v for k, v in added.items() if v}, {}, "no model other than the run history and audit gains a row")
        self.assertEqual(after["change"][0], "DRAFT")
        run = outcome.run
        self.assertEqual((run.mode, run.status, run.change_id, run.plan_id, run.created_by), ("CHANGE_PRECHECK", "PASS", self.f.change.pk, self.plan.pk, "tester"))
        events = list(models.AuditEvent.objects.filter(event_type=models.AuditEventType.PRECHECK_RECORDED))
        self.assertEqual([(e.object_id, e.actor, e.metadata["status"]) for e in events], [(str(run.run_id), "tester", "PASS")])
        self.assertEqual(run.report["provenance"]["plan_hash"], self.plan.plan_hash)
        self.assertEqual(models.Configlet.objects.filter(plan=self.plan).exclude(execution_status="PENDING").count(), 0)
        with self.assertRaises(ValueError):
            run.status = "BLOCKED"
            run.save()

    def test_run_history_is_bounded_sanitized_and_vocabulary_checked(self):
        many = [hs.CheckResult("ROUTE_MISSING", S.FAIL, f"R{i % 5}", "m" * 900, "LIVE", observed={"password": "hunter2", "rows": list(range(500)), "deep": {"a": {"b": {"c": {"d": {"e": 1}}}}}},
                               subject=f"s{i}") for i in range(900)]
        run = persistence.record_run(mode="DEVICE_DEEP", status="UNHEALTHY", results=many, extra={"facts": {"x": "y" * 5000}}, actor="tester", device="R1")
        report = run.report
        self.assertLessEqual(len(json.dumps(report)), persistence.MAX_REPORT_BYTES)
        self.assertTrue(report["results_truncated"])
        self.assertLessEqual(len(report["results"]), 400)
        dump = json.dumps(persistence.serialize_health_run(run))
        self.assertNotIn("hunter2", dump)
        self.assertIn("[REDACTED]", dump)
        self.assertEqual([r.status for r in models.OperationalCheckRun.objects.all()], ["UNHEALTHY"])
        for mode, status in (("DEVICE_DEEP", "BLOCKED"), ("CHANGE_PRECHECK", "HEALTHY"), ("CHANGE_POSTCHECK", "BLOCKED"), ("NOT_A_MODE", "PASS")):
            with self.subTest(mode=mode, status=status):
                with self.assertRaises(ValueError):
                    persistence.record_run(mode=mode, status=status, results=[], actor="t")
        self.assertEqual(len(persistence.recent_runs(limit=10_000)), 1)
        self.assertIsNone(persistence.get_run("not-a-uuid"))
        # deleting a Change removes its runs but the plan's pinned validation is untouched by a run
        models.Change.objects.filter(pk=self.f.change.pk).delete()
        self.assertEqual(models.OperationalCheckRun.objects.filter(change__isnull=False).count(), 0)
