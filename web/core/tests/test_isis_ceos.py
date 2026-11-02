"""cEOS IS-IS: the narrow capability the IPv6 access-redundancy design needs, and nothing wider.

Every expected line here was accepted by a disposable cEOS 4.36.2F sandbox first (see
``docs/V2_IPV6_ISIS_ACCESS_REDUNDANCY.md``).  The RIP cases pin the sandbox-proven mechanism that makes VLAN99 the
deliberate S1<->S2 IPv4 transit: EOS has no RIP passive-interface, and a client SVI simply carries no ``network`` line.
"""

from __future__ import annotations

from django.test import TestCase

from core import models
from core.services import candidate_renderer, platform_drivers, routing_intent_service as service
from core.services.execution import capability as execution_capability
from core.services.execution.codes import Capability
from core.services.execution.executors.ceos import CONFIG_BLOCK_TYPES, config_inverse
from core.services.config_import import parser_ceos
from core.services.health import live, routing_config
from core.services.health.evaluators import EVALUATORS
from core.services.health.requirements import REQUIREMENT_MAP
from core.services.platform_drivers import CEOS_ISIS_TAG, CapabilityStatus, RoutingProtocol
from core.tests.helpers.candidates import add_binding, add_instance, add_interface, commit, make_candidate

NET = "49.0110.1921.6825.5011.00"


def _ipv6_only_instance(change, intent, revision):
    instance = add_instance(revision, family="isis")
    for field, value in (("net", NET), ("address_family_ipv4", False), ("address_family_ipv6", True)):
        commit(change, intent, revision, service._instance_path("isis", instance["id"], field), value)
    return instance


def _block(text: str, header: str) -> list[str]:
    lines, inside = [], False
    for line in text.splitlines():
        if not line.startswith(" "):
            inside = line.strip() == header
            continue
        if inside:
            lines.append(line.strip())
    return lines


class CeosIsisRenderTests(TestCase):
    def test_ipv6_only_process_keeps_ipv4_outside_the_address_family(self):
        change, intent, revision = make_candidate(device_name="S1")
        _ipv6_only_instance(change, intent, revision)
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertEqual(_block(text, f"router isis {CEOS_ISIS_TAG}"), [f"net {NET}", "is-type level-2", "address-family ipv6 unicast"])
        self.assertNotIn("address-family ipv4 unicast", text)

    def test_binding_is_rendered_inside_its_interface_once(self):
        change, intent, revision = make_candidate(device_name="S1")
        instance = _ipv6_only_instance(change, intent, revision)
        uplink = add_interface(revision, name="Ethernet1")
        binding = add_binding(revision, family="isis", instance_id=instance["id"], interface_id=uplink["id"])
        commit(change, intent, revision, service._binding_path("isis", instance["id"], binding["id"], "metric"), 10)
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertEqual(text.count("interface Ethernet1"), 1)
        block = _block(text, "interface Ethernet1")
        self.assertIn(f"isis enable {CEOS_ISIS_TAG}", block)
        self.assertIn("isis metric 10", block)
        self.assertNotIn("isis passive", block)
        self.assertNotIn("isis ipv6 metric 10", text)  # single topology: the sandbox showed this knob does not steer traffic

    def test_passive_binding_advertises_without_an_adjacency(self):
        change, intent, revision = make_candidate(device_name="S1")
        instance = _ipv6_only_instance(change, intent, revision)
        svi = add_interface(revision, kind="SVI", name="Vlan10")
        binding = add_binding(revision, family="isis", instance_id=instance["id"], interface_id=svi["id"])
        commit(change, intent, revision, service._binding_path("isis", instance["id"], binding["id"], "passive"), True)
        block = _block(candidate_renderer.render(intent, revision)["text"], "interface Vlan10")
        self.assertIn(f"isis enable {CEOS_ISIS_TAG}", block)
        self.assertIn("isis passive", block)

    def test_other_platforms_still_report_isis_honestly(self):
        self.assertEqual(platform_drivers.capability_for_routing("arista_ceos", RoutingProtocol.ISIS).status, CapabilityStatus.SUPPORTED)
        for platform in ("ubuntu_frr", "nokia_srlinux", "cisco_c8000v_iosxe", "cisco_iosxr", "sonic"):
            with self.subTest(platform=platform):
                self.assertEqual(platform_drivers.capability_for_routing(platform, RoutingProtocol.ISIS).status,
                                 CapabilityStatus.NOT_IMPLEMENTED)
        with self.assertRaises(service.CollectionMutationError):
            add_instance(make_candidate(platform=models.Platform.UBUNTU_FRR, device_name="R3")[2], family="isis")


class CeosIsisExecutionTests(TestCase):
    def test_apply_and_compensation_are_ceos_only(self):
        ceos = execution_capability.capability_for("arista_ceos", "routing_isis")
        self.assertEqual((ceos.apply, ceos.compensation), (Capability.SUPPORTED, Capability.SUPPORTED))
        self.assertIn("routing_isis", CONFIG_BLOCK_TYPES)
        for platform in ("ubuntu_frr", "nokia_srlinux", "cisco_c8000v_iosxe"):
            with self.subTest(platform=platform):
                self.assertEqual(execution_capability.capability_for(platform, "routing_isis").apply, Capability.NOT_IMPLEMENTED)

    def test_a_new_process_and_a_new_binding_have_an_exact_inverse(self):
        running = "interface Ethernet1\n   no switchport\n   ipv6 address 2001:db8:110:1::2/64\n"
        process = [f"router isis {CEOS_ISIS_TAG}", f"   net {NET}", "   is-type level-2", "   address-family ipv6 unicast"]
        self.assertEqual(config_inverse(process, running), [f"no router isis {CEOS_ISIS_TAG}"])
        binding = ["interface Ethernet1", f"   isis enable {CEOS_ISIS_TAG}", "   isis metric 10"]
        self.assertEqual(config_inverse(binding, running),
                         ["interface Ethernet1", "   no isis metric 10", f"   no isis enable {CEOS_ISIS_TAG}"])

    def test_changing_an_existing_metric_restores_the_captured_value(self):
        """The drain lever: the inverse of a metric change is the original metric line, proven byte-exact on cEOS 4.36.2F."""
        running = f"interface Ethernet1\n   isis enable {CEOS_ISIS_TAG}\n   isis metric 10\n"
        self.assertEqual(config_inverse(["interface Ethernet1", "   isis metric 1000"], running), ["interface Ethernet1", "   isis metric 10"])
        default = f"interface Ethernet1\n   isis enable {CEOS_ISIS_TAG}\n"
        self.assertEqual(config_inverse(["interface Ethernet1", "   isis metric 1000"], default), ["interface Ethernet1", "   no isis metric 1000"])

    def test_no_other_replacement_becomes_reversible(self):
        running = "interface Ethernet1\n   description uplink\n   ip ospf cost 10\n   isis metric 10\n   isis metric 20\n"
        for line in ("   description drained", "   ip ospf cost 500", "   isis metric 1000"):   # the last: two captured values, ambiguous
            with self.subTest(line=line):
                self.assertIsNone(config_inverse(["interface Ethernet1", line], running))


class CeosRipTransitTests(TestCase):
    """VLAN99 is the S1<->S2 RIP transit because the client SVIs carry no ``network`` statement."""

    def test_only_bound_interfaces_get_a_network_statement(self):
        change, intent, revision = make_candidate(device_name="S1")
        transit = add_interface(revision, kind="SVI", name="Vlan99")
        client = add_interface(revision, kind="SVI", name="Vlan10")
        for interface, cidr in ((transit, "192.168.110.4/31"), (client, "192.168.10.2/24")):
            address = service.interface_intent_service.add_address(revision=revision, interface_id=interface["id"], family="IPV4")
            commit(change, intent, revision, f"interfaces.{interface['id']}.addresses.{address['id']}.cidr", cidr)
        instance = add_instance(revision, family="rip", address_family="IPV4")
        add_binding(revision, family="rip", instance_id=instance["id"], interface_id=transit["id"])
        block = _block(candidate_renderer.render(intent, revision)["text"], "router rip")
        self.assertIn("network 192.168.110.4/31", block)
        self.assertNotIn("network 192.168.10.0/24", block)

    def test_rip_passive_is_still_reported_as_having_no_eos_command(self):
        change, intent, revision = make_candidate(device_name="S1")
        client = add_interface(revision, kind="SVI", name="Vlan10")
        instance = add_instance(revision, family="rip", address_family="IPV4")
        binding = add_binding(revision, family="rip", instance_id=instance["id"], interface_id=client["id"])
        commit(change, intent, revision, service._binding_path("rip", instance["id"], binding["id"], "passive"), True)
        text = candidate_renderer.render(intent, revision)["text"]
        self.assertIn("cEOS RIP passive binding on Vlan10 has no supported EOS command", text)
        self.assertNotIn("passive-interface", text)


# ``show isis neighbors | json`` exactly as cEOS 4.36.2F returned it in the sandbox (timers and BFD details trimmed).
NEIGHBORS_JSON = """{"vrfs": {"default": {"isisInstances": {"NMAS": {"neighbors": {"1921.6825.5002": {"adjacencies": [
  {"hostname": "jb", "circuitId": "jb.ab", "interfaceName": "Ethernet1", "state": "up", "snpa": "2:42:a:fb:9:3", "level": "level-2",
   "details": {"interfaceAddressFamily": "ipv6", "neighborAddressFamily": "ipv6", "areaIds": ["49.0110"]}, "routerIdV4": "0.0.0.0"}]}}}}}}}"""
RUNNING = f"""interface Ethernet1
   no switchport
   ipv6 address 2001:db8:110:1::2/64
   isis enable {CEOS_ISIS_TAG}
   isis metric 10
!
interface Vlan10
   ipv6 address 2001:db8:10::2/64
   isis enable {CEOS_ISIS_TAG}
   isis passive
!
interface Vlan200
   ipv6 address 2001:db8:200::11/64
!
router isis {CEOS_ISIS_TAG}
   net {NET}
   is-type level-2
   !
   address-family ipv6 unicast
      redistribute static route-map STATIC6-TO-ISIS6
"""


class CeosIsisReadTests(TestCase):
    def test_neighbor_read_parses_the_real_json_and_tolerates_no_instance(self):
        self.assertEqual(live.parse_eos_isis(NEIGHBORS_JSON), [{
            "instance": "NMAS", "system_id": "1921.6825.5002", "hostname": "jb", "interface": "Ethernet1", "level": "level-2", "state": "UP"}])
        self.assertEqual(live.parse_eos_isis('{"vrfs": {}}'), [])
        self.assertEqual(live.CEOS_COMMANDS["isis"], "show isis neighbors | json")

    def test_running_config_reads_back_the_process_and_bindings(self):
        (row,) = [r for r in routing_config.eos(RUNNING) if r["protocol"] == "isis"]
        bindings = {b["interface_name"]: (b["passive"], b["metric"]) for b in row["bindings"]}
        self.assertEqual(bindings, {"Ethernet1": (False, 10), "Vlan10": (True, None)})
        self.assertNotIn("Vlan200", bindings)
        parsed = next(i for i in parser_ceos.parse(RUNNING).routing_instances if i.family == "isis")
        self.assertEqual(parsed.fields, {"net": NET, "level": "LEVEL_2", "address_family_ipv4": False, "address_family_ipv6": True})
        self.assertEqual([line.strip() for line in parsed.preserved_lines], ["redistribute static route-map STATIC6-TO-ISIS6"])

    def test_a_process_under_another_tag_stays_unmanaged(self):
        parsed = parser_ceos.parse(RUNNING.replace(f"router isis {CEOS_ISIS_TAG}", "router isis OTHER"))
        self.assertFalse([i for i in parsed.routing_instances if i.family == "isis"])
        self.assertTrue(any(block.lines[0] == "router isis OTHER" for block in parsed.unmanaged_blocks))

    def test_an_isis_binding_is_postchecked_by_adjacency_and_by_configuration(self):
        checks = [check for match, check in REQUIREMENT_MAP["ROUTING_INTERFACE_ENABLED"] if match in ({}, {"protocol": "isis"})]
        self.assertEqual(checks, ["ISIS_NEIGHBOR_EXPECTED", "ROUTING_BINDING_CONFIG"])
        self.assertIn("ISIS_NEIGHBOR_EXPECTED", EVALUATORS)
