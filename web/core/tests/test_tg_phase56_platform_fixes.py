"""The fixes the V2 Phases 5 / 6 isolated cEOS acceptance run forced (docs/V2_TRUSTED_ISOLATION_COMMISSIONING.md, findings 14 and
17-21), each proven on its own: ``default passive-interface`` as the inverse of a passive binding, coexisting ``passive-interface``
lines, configuration-block inverses computed when a Configlet is APPLIED (not when the plan was assessed), OSPF areas compared in
one canonical form, and adjacencies on a port held by trusted isolation evaluated NOT_APPLICABLE until admission."""

from __future__ import annotations

from types import SimpleNamespace

from django.test import SimpleTestCase

from core.services.execution.executors.base import APPLY, ConfigletSpec
from core.services.execution.executors.ceos import CeosExecutor, child_negation, config_inverse
from core.services.health import evaluators
from core.services.health.codes import CheckStatus as S, Phase
from core.services.health.routing_config import normalized_area
from core.services.isolation import intent
from core.tests.helpers import isolation as I
from core.tests.helpers.health import device_evidence, evidence_set
from core.tests.test_commissioning import Base as CommissioningBase
from core.tests.test_health_engine import req, world

RUNNING = "hostname NEW1\ninterface Ethernet2\n   ip address 10.254.64.1/24\nrouter ospf 1\n   passive-interface Ethernet2\n"


def spec(cfg_id, *lines, kind="routing_ospf"):
    return ConfigletSpec(cfg_id, int(cfg_id[-1]), "NEW1", "arista_ceos", kind, "CREATE_DEFINE", tuple(lines), {})


def executor(text):
    session = I.FakeEosSession(text)
    found = CeosExecutor({"name": "NEW1"}, connection_factory=lambda device: session, reader=I._facts)
    found.connect()
    return found, session


class NegationTests(SimpleTestCase):
    def test_child_negation_returns_default_for_a_passive_interface_binding(self):
        self.assertEqual(child_negation("  passive-interface Loopback0 "), "default passive-interface Loopback0")

    def test_child_negation_never_defaults_an_ordinary_command(self):
        self.assertEqual(child_negation("router-id 10.254.255.11"), "no router-id 10.254.255.11")
        self.assertEqual(child_negation("network 10.0.0.0/8 area 0.0.0.0"), "no network 10.0.0.0/8 area 0.0.0.0")

    def test_config_inverse_accepts_coexisting_passive_interface_lines(self):
        self.assertEqual(config_inverse(["router ospf 1", "   passive-interface Loopback0"], RUNNING),
                         ["router ospf 1", "   default passive-interface Loopback0"])

    def test_config_inverse_still_refuses_a_replacement(self):
        self.assertIsNone(config_inverse(["router ospf 1", "   router-id 10.0.0.9"], RUNNING + "   router-id 10.0.0.1\n"))

    def test_isolation_passive_operation_returns_default_as_its_exact_inverse(self):
        net = SimpleNamespace(ipv4_prefix="10.254.30.0/24", gateway=I.GATEWAY, service_address=I.SERVICE, http_port=8080)
        _it, ops, problems, _facts = intent.build(device_id="DEV-000002", upstream="S1", interface=I.PORT, network=net,
                                                  config_text=I.upstream_config(), nmas_sources=["192.168.200.100"])
        self.assertEqual(problems, [])
        passive = next(op for op in ops if op["key"] == "ospf-passive-1")
        self.assertEqual(passive["inverse"], ["router ospf 1", f"   default passive-interface {I.PORT}"])
        session = I.FakeEosSession(I.upstream_config())
        baseline = session.config.text()
        session.send_config_set(passive["lines"])
        session.send_config_set(passive["inverse"])
        self.assertEqual(session.config.text(), baseline)


class ApplyTimeInverseTests(SimpleTestCase):
    def test_apply_returns_compensation_for_each_configlet_of_a_multi_configlet_plan(self):
        found, session = executor("hostname NEW1\n")
        baseline = session.config.text()
        first = spec("CFG-1", "router ospf 1", "   router-id 10.254.255.11")
        second = spec("CFG-2", "router ospf 1", "   passive-interface Loopback0")
        assessed = [found.assess(first), found.assess(second)]           # the engine assesses every Configlet before applying any
        self.assertEqual([a.action for a in assessed], [APPLY, APPLY])
        self.assertTrue(found.apply(first, assessed[0]).ok)
        after_first = session.config.text()
        self.assertTrue(found.apply(second, assessed[1]).ok)
        self.assertEqual(found.compensate(second, assessed[1]).status, "COMPENSATED")
        self.assertEqual(session.config.text(), after_first)              # only CFG-2 was undone, not the whole process
        self.assertEqual(found.compensate(first, assessed[0]).status, "COMPENSATED")
        self.assertEqual(session.config.text(), baseline)

    def test_apply_refuses_without_sending_when_no_inverse_is_provable_any_more(self):
        found, session = executor("hostname NEW1\ninterface Ethernet2\n   no switchport\n")
        relay = spec("CFG-1", "interface Ethernet2", "   ip helper-address 10.254.61.2", kind="dhcp_relay")
        assessed = found.assess(relay)
        self.assertEqual((assessed.action, assessed.restorable), (APPLY, True))
        session.config.apply(["interface Ethernet2", "ip helper-address 192.0.2.1"])      # an out-of-band change before the write
        outcome = found.apply(relay, assessed)
        self.assertEqual((outcome.ok, outcome.error_code), (False, "COMMAND_REJECTED"))
        self.assertEqual(session.sent, [])


class AreaTests(SimpleTestCase):
    def test_normalized_area_returns_the_integer_form_of_a_dotted_area(self):
        self.assertEqual((normalized_area("0.0.0.0"), normalized_area("0.0.0.10"), normalized_area(0)), ("0", "10", "0"))

    def test_normalized_area_never_rewrites_a_non_dotted_area(self):
        self.assertEqual((normalized_area("backbone"), normalized_area("49.0001")), ("backbone", "49.0001"))

    def test_binding_with_a_dotted_area_matches_the_running_configuration(self):
        requirement = req("ROUTING_INTERFACE_ENABLED", {"protocol": "ospf", "interface": "Ethernet1", "version": "OSPFV2", "area": "0.0.0.0"})
        results = evaluators.evaluate_requirements([requirement], Phase.POSTCHECK, world()).results
        self.assertEqual({r.status for r in results}, {S.PASS})


class IsolatedPortEvaluationTests(SimpleTestCase):
    OSPF = {"protocol": "ospf", "interface": "Ethernet1", "version": "OSPFV2"}

    def test_evaluate_requirements_accepts_an_isolated_port_as_not_applicable(self):
        evaluation = evaluators.evaluate_requirements([req("ROUTING_INTERFACE_ENABLED", self.OSPF)], Phase.POSTCHECK, world(ospf=[]),
                                                      isolated_ports={("R1", "Ethernet1")})
        first = evaluation.results[0]
        self.assertEqual((first.status, first.check_code), (S.NOT_APPLICABLE, "OSPF_EXPECTED_FULL"))
        self.assertTrue(first.expected["isolated_until_admission"])

    def test_evaluate_requirements_refuses_a_missing_adjacency_on_any_other_port(self):
        evaluation = evaluators.evaluate_requirements([req("ROUTING_INTERFACE_ENABLED", self.OSPF)], Phase.POSTCHECK, world(ospf=[]),
                                                      isolated_ports={("R1", "Ethernet2"), ("R2", "Ethernet1")})
        self.assertEqual((evaluation.results[0].status, evaluation.results[0].check_code), (S.FAIL, "OSPF_ADJACENCY_DOWN"))
        with self.assertRaises(ValueError):
            evaluators.evaluate_requirements([], "DURING", world(), isolated_ports={("R1", "Ethernet1")})

    def test_isis_and_rip_adjacencies_on_an_isolated_port_are_not_applicable(self):
        evidence = evidence_set(device_evidence("R1", isis=[], rip_neighbors=[]))
        for check_type, expected in (("ISIS_NEIGHBOR_EXPECTED", {"interface": "Ethernet1"}),
                                     ("RIP_NEIGHBOR_EXPECTED", {"interface": "Ethernet1", "present": True})):
            requirement = SimpleNamespace(device="R1", expected=expected, cfg_id="CFG-001", kind="X")
            evaluate = evaluators.EVALUATORS[check_type][0]
            with self.subTest(check_type):
                held = evaluate(requirement, evaluators.EvalContext(evidence=evidence, isolated_ports=frozenset({("R1", "Ethernet1")})))
                self.assertEqual(held.status, S.NOT_APPLICABLE)
                open_port = evaluate(requirement, evaluators.EvalContext(evidence=evidence))
                self.assertEqual(open_port.status, S.FAIL)


class IsolatedPortsOfAPlanTests(CommissioningBase):
    def test_isolated_ports_returns_the_commissioning_device_uplink(self):
        self.assessed()
        plan = self.record.provisioning_run.plan
        self.assertEqual(evaluators.isolated_ports(plan), frozenset({(self.device.name, self.flow.attachment.local_interface)}))
        evaluation = evaluators.evaluate_plan_requirements(plan, Phase.POSTCHECK, evidence_set())
        self.assertTrue(evaluation.results)

    def test_isolated_ports_is_empty_for_a_plan_without_an_isolated_device(self):
        self.ready()
        upstream_plan = self.flow.refresh().apply_change.plans.first()            # targets the trusted upstream S1, never isolated
        self.assertEqual(evaluators.isolated_ports(upstream_plan), frozenset())
        with self.assertRaises(ValueError):
            evaluators.evaluate_plan_requirements(upstream_plan, "DURING", evidence_set())
