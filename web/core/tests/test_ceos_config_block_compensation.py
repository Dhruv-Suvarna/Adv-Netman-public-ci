"""cEOS config-snapshot compensation and the small fixes the isolated service-policy probes required."""

from django.test import SimpleTestCase

from core.services.config_import import parser_ceos
from core.services.execution import capability
from core.services.execution.codes import Capability
from core.services.execution.executors.base import APPLY, SKIP_SATISFIED, ConfigletSpec
from core.services.execution.executors.ceos import CeosExecutor, config_inverse
from core.services.health import live
from core.services.health.evidence import DeviceEvidence, FactGroup
from core.services import platform_drivers

RUNNING = """hostname ceos
interface Ethernet1
   no switchport
   ip address 198.18.0.1/24
interface Ethernet2
   ip helper-address 192.0.2.1
no ip routing
"""


class FakeSession:
    def __init__(self, text):
        self.text, self.sent = text, []

    def send_command(self, command, **_):
        return self.text

    def config_mode(self, **_):
        return None

    def check_config_mode(self):
        return False

    def send_config_set(self, commands, **_):
        self.sent.append(list(commands))
        lines = self.text.splitlines()
        if "no ip access-list CAP_ACL" in commands:
            start = lines.index("ip access-list CAP_ACL")
            del lines[start:start + 2]
        self.text = "\n".join(lines) + "\n"
        return ""

    def disconnect(self):
        return None


def _executor(session):
    facts = DeviceEvidence("ceos", "arista_ceos", {name: FactGroup(value, "SYNTHETIC") for name, value in
                                                    (("interfaces", {}), ("addresses", {}), ("routes", []))}, live_attempted=True)
    executor = CeosExecutor({"name": "ceos"}, connection_factory=lambda device: session, reader=lambda device: facts)
    executor.connect()
    return executor


def _spec(kind, *lines):
    return ConfigletSpec("CFG-1", 1, "ceos", "arista_ceos", kind, "CREATE_DEFINE", tuple(lines), {"interface": "Ethernet1"})


class ConfigInverseTests(SimpleTestCase):
    def test_new_block_is_removed_by_its_header(self):
        self.assertEqual(config_inverse(["ip access-list CAP_ACL", "   10 permit ip any any"], RUNNING), ["no ip access-list CAP_ACL"])

    def test_new_child_of_existing_block_is_negated_under_its_header(self):
        self.assertEqual(config_inverse(["interface Ethernet1", "   ip access-group CAP_ACL in"], RUNNING),
                         ["interface Ethernet1", "   no ip access-group CAP_ACL in"])

    def test_dependants_are_removed_first_and_present_lines_left_alone(self):
        lines = ["ip virtual-router mac-address 00:1c:73:00:00:44", "interface Ethernet1", "   no switchport",
                 "   ip virtual-router address 198.18.0.3"]
        self.assertEqual(config_inverse(lines, RUNNING), [
            "interface Ethernet1", "   no ip virtual-router address 198.18.0.3", "no ip virtual-router mac-address 00:1c:73:00:00:44"])
        self.assertEqual(config_inverse(["interface Ethernet2", "   ip helper-address 192.0.2.1"], RUNNING), [])

    def test_replacement_negation_and_nested_changes_are_not_provable(self):
        self.assertIsNone(config_inverse(["interface Ethernet1", "   ip address 198.18.9.1/24"], RUNNING))     # replaces the primary
        self.assertIsNone(config_inverse(["interface Ethernet1", "   no ip helper-address 192.0.2.1"], RUNNING))
        self.assertIsNone(config_inverse(["no ip access-list CAP_ACL"], RUNNING))
        self.assertIsNone(config_inverse(["ip virtual-router mac-address 00:1c:73:00:00:44"],
                                         RUNNING + "ip virtual-router mac-address 00:1c:73:00:00:01\n"))
        self.assertIsNone(config_inverse(["interface Ethernet1", "   ip ospf area 0", "      nested"], RUNNING))


class ConfigBlockExecutorTests(SimpleTestCase):
    def test_compensation_requires_identical_running_config(self):
        session = FakeSession(RUNNING)
        executor = _executor(session)
        spec = _spec("acl", "ip access-list CAP_ACL", "   10 permit ip any any")
        preflight = executor.assess(spec)
        self.assertEqual((preflight.action, preflight.restorable, preflight.previous_state["kind"]), (APPLY, True, "config_block"))
        self.assertNotIn("inverse", preflight.previous_state)            # only a digest is persisted
        session.text = RUNNING + "ip access-list CAP_ACL\n   10 permit ip any any\n"
        self.assertEqual(executor.compensate(spec, preflight).status, "COMPENSATED")
        self.assertEqual(session.sent[-1], ["no ip access-list CAP_ACL"])
        # The inverse is accepted but the configuration still differs from the capture: fail closed.
        session.text = RUNNING + "ip access-list CAP_ACL\n   10 permit ip any any\nip access-list OTHER\n"
        outcome = executor.compensate(spec, preflight)
        self.assertEqual((outcome.status, outcome.error_code), ("COMPENSATION_FAILED", "STATE_NOT_RESTORED"))

    def test_unprovable_and_satisfied_and_unmodelled_types(self):
        executor = _executor(FakeSession(RUNNING))
        replace = executor.assess(_spec("dhcp_relay", "interface Ethernet2", "   ip helper-address 192.0.2.9"))
        self.assertEqual((replace.action, replace.restorable), (APPLY, False))
        present = executor.assess(_spec("dhcp_relay", "interface Ethernet2", "   ip helper-address 192.0.2.1"))
        self.assertEqual((present.action, present.restorable), (SKIP_SATISFIED, True))
        process = executor.assess(_spec("routing_ospf", "router ospf 1", "   router-id 1.1.1.1"))
        self.assertEqual((process.action, process.restorable), (APPLY, True))
        fresh = _executor(FakeSession(RUNNING))                               # an inverse is never guessed by another run
        spec = _spec("acl", "ip access-list CAP_ACL", "   10 permit ip any any")
        preflight = executor.assess(spec)
        fresh._conn.text = RUNNING + "ip access-list CAP_ACL\n"
        self.assertEqual(fresh.compensate(spec, preflight).status, "COMPENSATION_FAILED")

    def test_capability_table_matches_executor(self):
        for kind in ("acl", "acl_attachment", "dhcp_relay", "fhrp"):
            self.assertEqual(capability.capability_for("arista_ceos", kind).compensation, Capability.SUPPORTED)
        for kind in ("routing_ospf", "routing_bgp", "routing_rip"):
            self.assertEqual(capability.capability_for("arista_ceos", kind).compensation, Capability.SUPPORTED)

    def test_routing_inverse_preserves_preexisting_unrelated_process_lines(self):
        from core.services.execution.executors.ceos import config_inverse

        original = "router bgp 65044\n   neighbor 192.0.2.1 remote-as 65001\n"
        touched = ["router bgp 65044", "   neighbor 192.0.2.2 remote-as 65002"]
        self.assertEqual(config_inverse(touched, original),
                         ["router bgp 65044", "   no neighbor 192.0.2.2 remote-as 65002"])
        self.assertIsNone(config_inverse(["router bgp 65044", "   neighbor 192.0.2.1 remote-as 65009"], original))
        self.assertEqual(config_inverse(["router ospf 44", "   router-id 198.18.44.1"], original),
                         ["no router ospf 44"])


class LiveFindingFixTests(SimpleTestCase):
    def test_standard_acl_renders_standard_list(self):
        acl = {"name": "CAP_ACL", "family": "IPV4", "acl_type": "STANDARD", "entries": {
            "a": {"id": "a", "sequence": 10, "action": "DENY", "source_type": "HOST", "source_value": "198.18.0.66"}}}
        self.assertEqual([row["text"] for row in platform_drivers._render_ceos_acl(acl)],
                         ["ip access-list standard CAP_ACL", "   10 deny host 198.18.0.66"])
        acl["acl_type"] = "EXTENDED"
        self.assertEqual(platform_drivers._render_ceos_acl(acl)[0]["text"], "ip access-list CAP_ACL")

    def test_acl_attachment_import_keeps_name_case(self):
        parsed = parser_ceos.parse("interface Ethernet1\n   no switchport\n   ip access-group CAP_ACL in\n")
        self.assertEqual(parsed.interfaces[0].acl_attachments, [{"family": "IPV4", "name": "CAP_ACL", "direction": "IN"}])

    def test_health_reader_sees_varp_addresses(self):
        text = "interface Ethernet1\n   ip virtual-router address 198.18.0.3\n   ipv6 virtual-router address 2001:DB8:44::3\ninterface Ethernet2\n"
        self.assertEqual(live.parse_eos_varp(text), {"Ethernet1": ["198.18.0.3", "2001:db8:44::3"]})
        self.assertEqual(live._merge_virtual({"Ethernet1": ["198.18.0.9"]}, live.parse_eos_varp(text)),
                         {"Ethernet1": ["198.18.0.3", "198.18.0.9", "2001:db8:44::3"]})
