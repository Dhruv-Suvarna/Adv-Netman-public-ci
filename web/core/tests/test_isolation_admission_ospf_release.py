"""An OSPF admission releases the upstream port's explicit OSPF passive (made passive for the admission, outside the isolation intent)."""
from types import SimpleNamespace

from django.test import SimpleTestCase

from core.services.isolation import eos, service

CONFIG = """interface Ethernet4
   no switchport
   ip address 10.254.82.1/29
   ip ospf area 0.0.0.20
router ospf 10
   router-id 192.168.255.2
   passive-interface Ethernet4
router ospf 20
   passive-interface default
"""


def _policy(own=()):
    return SimpleNamespace(upstream_platform="arista_ceos", upstream_interface="Ethernet4", release_change=None,
                           intent={"upstream": {"interface": "Ethernet4"}, "elements": {"CONTROL_PLANE": {"ospf_passive": list(own)}}})


class AdmissionOspfReleaseTests(SimpleTestCase):
    def test_explicit_passive_on_the_port_is_released(self):
        self.assertEqual(service.admission_ospf_release(_policy(), CONFIG), [{"process": "10", "vrf": ""}])

    def test_a_process_the_isolation_intent_owns_is_not_duplicated(self):
        self.assertEqual(service.admission_ospf_release(_policy(own=[{"process": "10", "vrf": ""}]), CONFIG), [])

    def test_no_ospf_on_the_port_releases_nothing(self):
        self.assertEqual(service.admission_ospf_release(_policy(), CONFIG.replace("   ip ospf area 0.0.0.20\n", "")), [])

    def test_passive_default_is_never_touched(self):
        text = CONFIG.replace("router ospf 10\n   router-id 192.168.255.2\n   passive-interface Ethernet4\n", "").replace(
            "router ospf 20\n", "router ospf 20\n   router-id 1.1.1.1\n")
        self.assertEqual(service.admission_ospf_release(_policy(), text), [])

    def test_release_op_removes_with_default_and_restores_the_passive(self):
        (op,) = eos.render_admission_ospf_release([{"process": "10", "vrf": ""}], "Ethernet4")
        self.assertEqual(op["kind"], "REMOVE")
        self.assertEqual(op["lines"], ["router ospf 10", "   default passive-interface Ethernet4"])
        self.assertEqual(op["inverse"], ["router ospf 10", "   passive-interface Ethernet4"])
        self.assertEqual(op["paths"], ["router ospf 10 > passive-interface Ethernet4"])

    def test_release_ops_append_the_recorded_routing_release_after_the_filters(self):
        policy = _policy()
        policy.release_change = SimpleNamespace(metadata={"transition": {"ospf_release": [{"process": "10", "vrf": ""}]}})
        base = [{"key": "release-attach-v4"}]
        original = eos.render_release
        eos.render_release = lambda intent: list(base)
        try:
            ops = service.release_ops(policy)
        finally:
            eos.render_release = original
        self.assertEqual([op["key"] for op in ops], ["release-attach-v4", "release-admission-ospf-passive-10"])
