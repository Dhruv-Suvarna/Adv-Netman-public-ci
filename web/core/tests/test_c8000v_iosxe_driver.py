"""Catalyst 8000V is IOS XE; these fixtures must never use IOS XR syntax."""

from django.test import TestCase

from core import models
from core.services import candidate_renderer, platform_drivers
from core.services.config_import import parser_iosxe
from core.tests.helpers.candidates import add_interface, add_static_route, commit, make_candidate


class Catalyst8000vIosXeTests(TestCase):
    def candidate(self):
        return make_candidate(platform=models.Platform.CISCO_C8000V_IOSXE, device_name="C8KV1")

    def test_platform_identities_are_distinct(self):
        self.assertNotEqual(models.Platform.CISCO_C8000V_IOSXE, models.Platform.CISCO_IOSXR)
        self.assertEqual(platform_drivers.get_driver("cisco_c8000v_iosxe").display_name,
                         "Cisco Catalyst 8000V / IOS XE")
        self.assertEqual(platform_drivers.get_driver("cisco_iosxr").display_name, "Cisco IOS XR")

    def test_iosxe_interface_address_uses_ip_not_ipv4_keyword(self):
        change, intent, revision = self.candidate()
        iface = add_interface(revision, name="GigabitEthernet1")
        from core.services import interface_intent_service
        address = interface_intent_service.add_address(
            revision=revision, interface_id=iface["id"], family="IPV4", source="MANUAL",
        )
        commit(change, intent, revision, f"interfaces.{iface['id']}.addresses.{address['id']}.cidr", "192.0.2.1/31")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("ip address 192.0.2.1 255.255.255.254", text)
        self.assertNotIn("ipv4 address", text)

    def test_iosxe_static_route_is_global_not_router_static(self):
        change, intent, revision = self.candidate()
        route = add_static_route(revision)
        commit(change, intent, revision, f"routing.static_routes.{route['id']}.destination", "10.0.0.0/8")
        commit(change, intent, revision, f"routing.static_routes.{route['id']}.next_hop_address", "192.0.2.2")
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("ip route 10.0.0.0 255.0.0.0 192.0.2.2", text)
        self.assertNotIn("router static", text)

    def test_iosxe_parser_round_trips_verified_subset(self):
        parsed = parser_iosxe.parse("""hostname C8KV1
interface Loopback44
 ip address 198.51.100.44 255.255.255.255
 no shutdown
!
ip route 203.0.113.0 255.255.255.0 192.0.2.2 200
""")
        self.assertEqual(parsed.parser_version, "iosxe-1.2")
        self.assertEqual(parsed.interfaces[0].kind, "LOOPBACK")
        self.assertEqual(parsed.interfaces[0].addresses[0]["cidr"], "198.51.100.44/32")
        self.assertEqual(parsed.static_routes[0].destination, "203.0.113.0/24")
        self.assertEqual(parsed.static_routes[0].distance, 200)

    def test_iosxe_parser_preserves_xr_only_hierarchy(self):
        parsed = parser_iosxe.parse("router static\n address-family ipv4 unicast\n  10.0.0.0/8 192.0.2.2\n")
        self.assertFalse(parsed.static_routes)
        self.assertTrue(parsed.unmanaged_blocks)
