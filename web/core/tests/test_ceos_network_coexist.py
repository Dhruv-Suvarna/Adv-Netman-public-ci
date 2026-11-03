"""cEOS configuration-block inverse: ``network <prefix>`` lines under ``router rip`` / ``router bgp`` coexist.

Found live in Lab 8 (R7 commissioning, CHG-20261103-0001): the second RIP ``network`` Configlet was refused at apply time
because ``network 10.254.96.0/29`` was read as replacing ``network 10.254.10.0/24``.  cEOS 4.36.2F keeps both lines, and
``no network 10.254.96.0/29`` removes exactly that one (aborted configuration session on the isolated R7).
"""

from django.test import SimpleTestCase

from core.services.execution.executors.ceos import config_inverse

RIP_ONE = "router rip\n   network 10.254.10.0/24\n   no shutdown\n"


class CeosNetworkCoexistTests(SimpleTestCase):
    def test_second_rip_network_is_undone_by_its_own_negation(self):
        inverse = config_inverse(["router rip", "   network 10.254.96.0/29"], RIP_ONE)
        self.assertEqual(inverse, ["router rip", "   no network 10.254.96.0/29"])

    def test_rip_network_already_present_needs_no_inverse(self):
        self.assertEqual(config_inverse(["router rip", "   network 10.254.10.0/24"], RIP_ONE), [])

    def test_absent_rip_block_is_undone_by_removing_the_block(self):
        self.assertEqual(config_inverse(["router rip", "   network 10.254.96.0/29"], "hostname R7\n"), ["no router rip"])

    def test_bgp_network_lines_coexist(self):
        running = "router bgp 65000\n   network 10.0.0.0/24\n"
        self.assertEqual(config_inverse(["router bgp 65000", "   network 10.0.1.0/24"], running),
                         ["router bgp 65000", "   no network 10.0.1.0/24"])

    def test_ospf_network_for_the_same_prefix_in_another_area_is_still_unprovable(self):
        running = "router ospf 1\n   network 10.0.0.0/24 area 0.0.0.0\n"
        self.assertIsNone(config_inverse(["router ospf 1", "   network 10.0.0.0/24 area 0.0.0.1"], running))

    def test_ospf_network_for_a_new_prefix_is_undone_exactly(self):
        running = "router ospf 1\n   network 10.0.0.0/24 area 0.0.0.0\n"
        self.assertEqual(config_inverse(["router ospf 1", "   network 10.0.1.0/24 area 0.0.0.0"], running),
                         ["router ospf 1", "   no network 10.0.1.0/24 area 0.0.0.0"])

    def test_other_single_valued_children_keep_the_replacement_guard(self):
        running = "router ospf 1\n   router-id 1.1.1.1\n"
        self.assertIsNone(config_inverse(["router ospf 1", "   router-id 2.2.2.2"], running))

    def test_enabling_a_suspended_rip_process_is_undone_by_its_captured_shutdown(self):
        running = "router rip\n   network 10.254.96.0/29\n   shutdown\n"
        self.assertEqual(config_inverse(["router rip", "   no shutdown"], running), ["router rip", "   shutdown"])

    def test_suspending_a_running_rip_process_is_undone_by_its_captured_no_shutdown(self):
        running = "router rip\n   network 10.254.96.0/29\n   no shutdown\n"
        self.assertEqual(config_inverse(["router rip", "   shutdown"], running), ["router rip", "   no shutdown"])

    def test_no_shutdown_already_present_needs_no_inverse(self):
        running = "router rip\n   network 10.254.96.0/29\n   no shutdown\n"
        self.assertEqual(config_inverse(["router rip", "   no shutdown"], running), [])

    def test_no_shutdown_without_a_captured_partner_stays_unprovable(self):
        running = "router rip\n   network 10.254.96.0/29\n"
        self.assertIsNone(config_inverse(["router rip", "   no shutdown"], running))

    def test_other_negated_children_under_an_existing_block_stay_unprovable(self):
        running = "router ospf 1\n   passive-interface Ethernet2\n"
        self.assertIsNone(config_inverse(["router ospf 1", "   no passive-interface Ethernet2"], running))
