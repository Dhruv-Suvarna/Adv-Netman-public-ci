"""V2 Phase 9 (D): IPv6 admission -- OSPFv3 on the bootstrap port is suppressed by isolation and verified by admission.

cEOS OSPFv3 in the form NMAS renders (``ipv6 router ospf N`` + ``ipv6 ospf N area A`` on the port) is isolated exactly like OSPFv2:
``passive-interface <port>`` under the process, undone with ``default passive-interface <port>``.  Isolation verification reads the
OSPFv3 neighbour table (``show ipv6 ospf neighbor | json``) and an admission may expect OSPFv3 adjacencies (``ospfv3_neighbors``)
together with the IPv6 routes learned through the released port and IPv6 reachability.  The live proof: docs/V2_IPV6_ADMISSION.md.
"""

from __future__ import annotations

from types import SimpleNamespace

from django.test import SimpleTestCase

from core import models
from core.services.commissioning import admission as A
from core.services.commissioning import outbox
from core.services.isolation import eos
from core.services.isolation import service as iso
from core.tests.helpers import isolation as I
from core.tests.helpers import lifecycle as L
from core.tests.test_commissioning import Base
from core.tests.test_isolation_eos import build, codes

V3 = "ipv6 router ospf 1\n   router-id 10.255.0.1"
V3_PORT = "ipv6 ospf 1 area 0.0.0.0"
DUAL = I.upstream_config(extra_port=V3_PORT, extra=V3)                  # OSPFv2 (network 10.0.0.0/8) and OSPFv3 on the port
V6_ONLY = I.upstream_config(ospf=False, extra_port=V3_PORT, extra=V3)
NEIGHBOR = "10.255.0.9"
V6_ROUTE, V6_HOST = "2001:db8:9::/48", "2001:db8:9::1"
EXPECT_V6 = {"routing": "OSPFV3", "ospfv3_neighbors": [NEIGHBOR], "routes_v6": [V6_ROUTE], "reachable": [V6_HOST]}


class OspfV3IsolationRenderTests(SimpleTestCase):
    def test_ospfv3_on_the_port_renders_a_passive_interface_with_its_exact_undo(self):
        it, ops, problems, _facts = build(V6_ONLY)
        self.assertEqual(problems, [])
        self.assertEqual(it["elements"]["CONTROL_PLANE"]["ospf6_passive"], [{"process": "1", "vrf": ""}])
        op = next(op for op in ops if op["key"] == "ospf6-passive-1")
        self.assertEqual(op["lines"], ["ipv6 router ospf 1", f"   passive-interface {I.PORT}"])
        self.assertEqual(op["inverse"], ["ipv6 router ospf 1", f"   default passive-interface {I.PORT}"])
        self.assertEqual(op["paths"], [f"ipv6 router ospf 1 > passive-interface {I.PORT}"])
        self.assertEqual(ops[-1]["key"], "ospf6-passive-1")

    def test_dual_stack_port_renders_both_passive_operations_and_release_order(self):
        it, ops, problems, _facts = build(DUAL)
        self.assertEqual(problems, [])
        self.assertEqual([op["key"] for op in ops][-2:], ["ospf-passive-1", "ospf6-passive-1"])
        released = [op["key"] for op in eos.render_release(it)]
        self.assertEqual(released[4:6], ["release-ospf-passive-1", "release-ospf6-passive-1"])
        restore = next(op for op in eos.render_release(it) if op["key"] == "release-ospf6-passive-1")
        self.assertEqual(restore["lines"], ["ipv6 router ospf 1", f"   default passive-interface {I.PORT}"])
        self.assertEqual(restore["kind"], "REMOVE")

    def test_ipv4_only_intent_keeps_its_earlier_shape(self):
        it, _ops, problems, _facts = build()
        self.assertEqual(problems, [])
        self.assertEqual(sorted(it["elements"]["CONTROL_PLANE"]), ["already_passive", "ospf_passive"])

    def test_ospfv3_already_passive_is_kept_and_renders_nothing(self):
        for extra in (V3 + f"\n   passive-interface {I.PORT}", V3 + "\n   passive-interface default"):
            with self.subTest(extra=extra):
                it, ops, problems, _facts = build(I.upstream_config(ospf=False, extra_port=V3_PORT, extra=extra))
                self.assertEqual(problems, [])
                self.assertEqual(it["elements"]["CONTROL_PLANE"]["already_passive6"], [{"process": "1", "vrf": ""}])
                self.assertNotIn("ospf6-passive-1", [op["key"] for op in ops])

    def test_ospfv3_forms_without_a_verified_procedure_are_refused(self):
        active = V3 + f"\n   passive-interface default\n   no passive-interface {I.PORT}"
        other_process = "ipv6 router ospf 2\n   router-id 10.255.0.1"
        for label, text in (("active under passive-interface default", I.upstream_config(ospf=False, extra_port=V3_PORT, extra=active)),
                            ("port in a process that is not configured", I.upstream_config(ospf=False, extra_port=V3_PORT, extra=other_process)),
                            ("router ospfv3 form", I.upstream_config(ospf=False, extra_port=V3_PORT, extra="router ospfv3\n   router-id 1.1.1.1")),
                            ("no process at all", I.upstream_config(ospf=False, extra_port=V3_PORT))):
            with self.subTest(label):
                self.assertIn("ISOLATION_ROUTING_UNSUPPORTED", codes(build(text)[2]))


class OspfV3NeighborParserTests(SimpleTestCase):
    def test_parser_returns_the_port_rows_of_every_instance(self):
        text = I.ospf6_neighbors((NEIGHBOR, "full", I.PORT), ("10.255.0.7", "full", "Ethernet1"), ("10.255.0.8", "init", I.PORT))
        self.assertEqual(eos.ospf6_neighbors_on(text, I.PORT), [{"neighbor": NEIGHBOR, "state": "full"}, {"neighbor": "10.255.0.8", "state": "init"}])
        self.assertEqual(eos.ospf6_neighbors_on(I.NO_OSPF6, I.PORT), [])            # cEOS with no OSPFv3 process
        self.assertEqual(eos.ospf6_neighbors_on(I.ospf6_neighbors(), I.PORT), [])

    def test_unreadable_neighbor_table_is_none_never_an_empty_answer(self):
        for text in ("", "% Invalid input", "[]", '{"vrfs": []}', None):
            with self.subTest(text=text):
                self.assertIsNone(eos.ospf6_neighbors_on(text, I.PORT))


class Upstream:
    """``executor.show`` / ``executor.reachable`` over fixed outputs (admission and isolation read nothing else)."""

    def __init__(self, outputs, pings=()):
        self.outputs, self.pings = outputs, set(pings)

    def show(self, command):
        return self.outputs.get(command, "")

    def reachable(self, address):
        return address in self.pings


POLICY = SimpleNamespace(upstream_interface=I.PORT, upstream_device="S1")


def admitted(*, state="full", neighbor_table=None):
    return Upstream({"show ipv6 ospf neighbor | json": neighbor_table if neighbor_table is not None else I.ospf6_neighbors((NEIGHBOR, state, I.PORT)),
                     "show ipv6 route | json": I.routes(V6_ROUTE)}, pings=[V6_HOST])


class OspfV3ExpectationTests(SimpleTestCase):
    def test_ospfv3_and_dual_stack_expectations_are_accepted(self):
        clean, problems = A.validate_expectations(EXPECT_V6)
        self.assertEqual(problems, [])
        self.assertEqual((clean["routing"], clean["ospfv3_neighbors"], clean["ospf_neighbors"]), ("OSPFV3", [NEIGHBOR], []))
        dual = {"routing": "OSPF", "ospf_neighbors": [NEIGHBOR], "ospfv3_neighbors": [NEIGHBOR], "routes_v4": ["10.9.0.0/16"],
                "routes_v6": [V6_ROUTE]}
        self.assertEqual(A.validate_expectations(dual)[1], [])
        self.assertEqual(A.validate_expectations({"routing": "RIP", "ospfv3_neighbors": [NEIGHBOR], "routes_v4": ["10.9.0.0/16"],
                                                  "routes_v6": [V6_ROUTE]})[1], [])

    def test_invalid_ospfv3_expectations_are_refused(self):
        for bad in ({"routing": "OSPFV3", "routes_v6": [V6_ROUTE]},                                      # no OSPFv3 neighbour
                    {"routing": "OSPFV3", "ospf_neighbors": [NEIGHBOR], "ospfv3_neighbors": [NEIGHBOR], "routes_v6": [V6_ROUTE]},
                    {"routing": "OSPFV3", "ospfv3_neighbors": [NEIGHBOR], "routes_v4": ["10.9.0.0/16"]},  # no IPv6 route
                    {"routing": "OSPF", "ospf_neighbors": [NEIGHBOR], "ospfv3_neighbors": [NEIGHBOR], "routes_v4": ["10.9.0.0/16"]},
                    {"routing": "OSPFV3", "ospfv3_neighbors": ["2001:db8::9"], "routes_v6": [V6_ROUTE]}):  # a router id is IPv4-formed
            with self.subTest(bad=bad):
                self.assertIn("ADMISSION_EXPECTATIONS_INVALID", [p["code"] for p in A.validate_expectations(bad)[1]])

    def test_failures_pass_when_ospfv3_is_full_with_the_ipv6_route_and_reachability(self):
        self.assertEqual(A.failures(admitted(), POLICY, A.validate_expectations(EXPECT_V6)[0]), [])

    def test_failures_report_an_absent_or_unfinished_ospfv3_adjacency(self):
        expectations = A.validate_expectations(EXPECT_V6)[0]
        for label, upstream, detail in (("absent", admitted(neighbor_table=I.ospf6_neighbors()), "absent"),
                                        ("not full", admitted(state="exStart"), "exStart"),
                                        ("unreadable", admitted(neighbor_table="% not json"), "unreadable")):
            with self.subTest(label):
                found = [row for row in A.failures(upstream, POLICY, expectations) if row["check"] == "ospfv3_adjacency"]
                self.assertEqual(len(found), 1)
                self.assertIn(detail, found[0]["detail"])

    def test_failures_report_a_missing_ipv6_route_and_unreachable_ipv6_address(self):
        upstream = Upstream({"show ipv6 ospf neighbor | json": I.ospf6_neighbors((NEIGHBOR, "full", I.PORT)),
                             "show ipv6 route | json": I.routes()})
        found = {row["check"] for row in A.failures(upstream, POLICY, A.validate_expectations(EXPECT_V6)[0])}
        self.assertEqual(found, {"routes_v6", "reachability"})

    def test_isolation_routing_findings_fail_while_an_ospfv3_adjacency_is_up(self):
        policy = SimpleNamespace(upstream_interface=I.PORT)
        isolated = I.FakeEosSession(V6_ONLY).config
        isolated.apply(["ipv6 router ospf 1", f"passive-interface {I.PORT}"])
        quiet = Upstream({"show ip route | json": I.routes(), "show ipv6 route | json": I.routes(),
                          "show ipv6 ospf neighbor | json": I.ospf6_neighbors()})
        self.assertTrue(iso.routing_findings(policy, quiet, isolated.text())[0])
        adjacent = Upstream({**quiet.outputs, "show ipv6 ospf neighbor | json": I.ospf6_neighbors((NEIGHBOR, "full", I.PORT))})
        ok, code, facts = iso.routing_findings(policy, adjacent, isolated.text())
        self.assertEqual((ok, code, facts["neighbors6"]), (False, "ISOLATION_LEAK", [{"neighbor": NEIGHBOR, "state": "full"}]))
        unreadable = Upstream({**quiet.outputs, "show ipv6 ospf neighbor | json": "% Error"})
        self.assertEqual(iso.routing_findings(policy, unreadable, isolated.text())[:2], (False, "ISOLATION_UPSTREAM_UNREADABLE"))
        active = Upstream(quiet.outputs)                                    # the port still active in the OSPFv3 process
        self.assertFalse(iso.routing_findings(policy, active, V6_ONLY)[0])


def v6_admitted_outputs(session, *, port=I.PORT):
    """The live upstream's behaviour: the OSPFv3 adjacency and the device's IPv6 routes appear only once the port is released."""
    def released(s):
        text = s.config.text()
        return f"passive-interface {port}" not in text and "access-group NMAS-ISO-" not in text

    session.outputs["show ipv6 ospf neighbor | json"] = lambda s: I.ospf6_neighbors((NEIGHBOR, "full", port)) if released(s) else I.ospf6_neighbors()
    session.outputs["show ipv6 route | json"] = lambda s: I.routes(V6_ROUTE) if released(s) else I.routes()
    session.pings[V6_HOST] = True


class Ipv6AdmissionTests(Base):
    upstream_text = V6_ONLY

    def ready(self):
        self.flow = I.Flow(self, text=self.upstream_text).ready_for_commissioning()
        self.device = self.flow.device
        return self.flow

    def test_ospfv3_isolation_enforces_the_passive_interface(self):
        self.ready()
        text = self.flow.session.config.text()
        self.assertIn(f"ipv6 router ospf 1\n   router-id 10.255.0.1\n   passive-interface {I.PORT}", text)
        self.assertEqual(self.flow.refresh().state, models.IsolationState.VERIFIED)

    def test_ipv6_admission_releases_ospfv3_and_admits(self):
        self.admission_approved(EXPECT_V6)
        v6_admitted_outputs(self.flow.session)
        result = A.execute(self.admission, actor=L.APPROVER, access=self.flow.access, gateway=self.lab.gateway)
        self.assertTrue(result.ok, result.codes)
        self.assertEqual(result.admission.state, models.AdmissionState.ADMITTED)
        self.assertEqual(self.flow.session.config.text(), I.FakeEosSession(self.upstream_text).config.text())    # exactly as before
        self.assertEqual(self.flow.refresh().state, models.IsolationState.RELEASED)
        target = models.LifecycleOutboxEvent.objects.get(topic=models.OutboxTopic.MONITORING_TARGET_ADMITTED)
        self.assertEqual(target.payload["checks"], ["reachability", "ospfv3_adjacency", "routes"])
        self.assertEqual(outbox.admission_payloads(result.admission)[models.OutboxTopic.MONITORING_TARGET_ADMITTED]["checks"],
                         ["reachability", "ospfv3_adjacency", "routes"])

    def test_failed_ospfv3_verification_restores_the_passive_interface(self):
        self.admission_approved(EXPECT_V6)
        enforced = self.flow.session.config.text()                                  # no OSPFv3 adjacency ever forms
        result = A.execute(self.admission, actor=L.APPROVER, access=self.flow.access, gateway=self.lab.gateway)
        self.assertFalse(result.ok)
        self.assertEqual((result.admission.state, result.codes), (models.AdmissionState.RESTORED, ["ADMISSION_VERIFICATION_FAILED"]))
        self.assertEqual(self.flow.session.config.text(), enforced)
        self.assertIn(f"passive-interface {I.PORT}", enforced)
        self.assertEqual(self.flow.refresh().state, models.IsolationState.ENFORCED)


class DualStackAdmissionTests(Ipv6AdmissionTests):
    upstream_text = DUAL

    def test_ipv6_admission_releases_ospfv3_and_admits(self):
        expectations = {**EXPECT_V6, "routing": "OSPF", "ospf_neighbors": [NEIGHBOR], "routes_v4": ["10.9.0.0/16"],
                        "reachable": [V6_HOST, "10.9.0.1"]}
        self.admission_approved(expectations)
        I.admitted_outputs(self.flow.session, neighbor=NEIGHBOR)
        v6_admitted_outputs(self.flow.session)
        result = A.execute(self.admission, actor=L.APPROVER, access=self.flow.access, gateway=self.lab.gateway)
        self.assertTrue(result.ok, result.codes)
        self.assertEqual(self.flow.session.config.text(), I.FakeEosSession(self.upstream_text).config.text())
        self.assertEqual(outbox.admission_payloads(result.admission)[models.OutboxTopic.MONITORING_TARGET_ADMITTED]["checks"],
                         ["reachability", "ospf_adjacency", "ospfv3_adjacency", "routes"])

    def test_failed_ospfv3_verification_restores_the_passive_interface(self):
        expectations = {**EXPECT_V6, "routing": "OSPF", "ospf_neighbors": [NEIGHBOR], "routes_v4": ["10.9.0.0/16"]}
        self.admission_approved(expectations)
        I.admitted_outputs(self.flow.session, neighbor=NEIGHBOR)                     # IPv4 comes up, OSPFv3 never does
        enforced = self.flow.session.config.text()
        result = A.execute(self.admission, actor=L.APPROVER, access=self.flow.access, gateway=self.lab.gateway)
        self.assertEqual((result.admission.state, result.codes), (models.AdmissionState.RESTORED, ["ADMISSION_VERIFICATION_FAILED"]))
        self.assertEqual(self.flow.session.config.text(), enforced)
