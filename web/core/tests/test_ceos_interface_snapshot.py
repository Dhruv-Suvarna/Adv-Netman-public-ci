"""cEOS interface compensation from the captured section (one mechanism for routed, access, trunk, subinterface, SVI)."""

from django.test import SimpleTestCase

from core.services.config_import import parser_ceos
from core.services.execution.executors.base import APPLY, SKIP_SATISFIED, ConfigletSpec
from core.services.execution.executors.ceos import CeosExecutor, interface_snapshot_inverse
from core.services.health.evidence import DeviceEvidence, FactGroup

PRISTINE = "interface Ethernet2\n!\nno ip routing\n"
L2 = "vlan 45\n!\ninterface Ethernet2\n   description legacy uplink\n   load-interval 30\n   switchport access vlan 45\n!\n"
L3 = ("interface Ethernet2\n   description legacy uplink\n   load-interval 30\n   no switchport\n   ip address 198.18.7.1/24\n"
      "   ipv6 address 2001:db8:7::1/64\n!\n")
ROUTED = ("interface Ethernet2", "   description NMAS isolated assessment", "   no switchport", "   mtu 1500", "   no shutdown")
ACCESS = ("interface Ethernet2", "   description NMAS isolated assessment", "   switchport", "   switchport mode access",
          "   switchport access vlan 44", "   mtu 1500", "   no shutdown")
TRUNK = ("interface Ethernet2", "   switchport", "   switchport mode trunk", "   switchport trunk allowed vlan 44-45",
         "   switchport trunk native vlan 44")


class SnapshotInverseTests(SimpleTestCase):
    def test_pristine_port_is_returned_to_defaults_line_by_line_never_by_default_interface(self):
        inverse = interface_snapshot_inverse(ROUTED, PRISTINE)
        self.assertEqual(inverse, ["interface Ethernet2", "   default shutdown", "   default mtu 1500", "   default switchport",
                                   "   default description NMAS isolated assessment"])
        self.assertNotIn("default interface Ethernet2", inverse)

    def test_configured_port_restores_replaced_values_and_resends_every_captured_line(self):
        inverse = interface_snapshot_inverse(ROUTED, L2)
        # the description is REPLACED (captured value re-sent, no default); new settings are defaulted; then the whole
        # captured section follows verbatim, the unmodelled load-interval included
        self.assertEqual(inverse, ["interface Ethernet2", "   default shutdown", "   default mtu 1500", "   default switchport",
                                   "   description legacy uplink", "   load-interval 30", "   switchport access vlan 45"])
        inverse = interface_snapshot_inverse(ACCESS, L3)
        self.assertEqual(inverse[:5], ["interface Ethernet2", "   default shutdown", "   default mtu 1500",
                                       "   default switchport access vlan 44", "   default switchport mode access"])
        self.assertEqual(inverse[5:], ["   description legacy uplink", "   load-interval 30", "   no switchport",
                                       "   ip address 198.18.7.1/24", "   ipv6 address 2001:db8:7::1/64"])
        self.assertEqual(interface_snapshot_inverse(TRUNK, PRISTINE)[1:], [
            "   default switchport trunk native vlan 44", "   default switchport trunk allowed vlan 44-45",
            "   default switchport mode trunk", "   default switchport"])

    def test_addresses_primary_is_replaced_and_coexisting_addresses_are_removed(self):
        self.assertEqual(interface_snapshot_inverse(("interface Ethernet2", "   ip address 198.18.0.1/30"), L3)[:2],
                         ["interface Ethernet2", "   description legacy uplink"])       # old primary returns with the replay
        self.assertEqual(interface_snapshot_inverse(("interface Ethernet2", "   ipv6 address 2001:db8:44::1/64"), L3)[1],
                         "   no ipv6 address 2001:db8:44::1/64")
        self.assertEqual(interface_snapshot_inverse(("interface Ethernet2", "   ip address 198.18.0.1/30"), PRISTINE),
                         ["interface Ethernet2", "   default ip address 198.18.0.1/30"])

    def test_created_objects_are_removed_and_satisfied_or_unprovable_cases_are_explicit(self):
        svi = ("vlan 44", "interface Vlan44", "   description x", "   no shutdown")
        self.assertEqual(interface_snapshot_inverse(svi, PRISTINE), ["no interface Vlan44", "no vlan 44"])
        child = ("interface Ethernet2.44", "   encapsulation dot1q vlan 44")
        self.assertEqual(interface_snapshot_inverse(child, PRISTINE), ["no interface Ethernet2.44"])
        self.assertEqual(interface_snapshot_inverse(("interface Ethernet2", "   load-interval 30"), L2), [])
        secret = "interface Ethernet2\n   ip ospf authentication-key <REDACTED>\n"
        self.assertIsNone(interface_snapshot_inverse(ROUTED, secret), "a redacted captured line cannot be re-sent")
        nested = ("interface Ethernet2", "   no switchport", "      nested line")
        self.assertIsNone(interface_snapshot_inverse(nested, PRISTINE))


class FakeEos:
    """Applies exactly the command forms under test to a per-interface line list."""

    def __init__(self, text):
        self.text, self.sent = text, []

    def send_command(self, _command, **_kwargs):
        return self.text

    def config_mode(self, **_kwargs): pass
    def check_config_mode(self): return False
    def exit_config_mode(self): pass
    def disconnect(self): pass

    def send_config_set(self, commands, **_kwargs):
        self.sent.append(list(commands))
        lines = [line.strip() for line in self.text.splitlines() if line.startswith("   ")]
        for command in commands[1:]:
            if command == "exit":
                continue
            if command.startswith("default "):
                stem = command[8:].rsplit(" ", 1)[0] if " " in command[8:] and not command[8:].startswith("description") else command[8:].split()[0]
                lines = [line for line in lines if not line.removeprefix("no ").startswith(stem)]
            elif command.startswith("no ") and command[3:] in lines:
                lines.remove(command[3:])
            elif command not in lines:
                stem = command.rsplit(" ", 1)[0] + " " if " " in command and not command.startswith(("ipv6 address", "no ")) else None
                if command.startswith("description"):
                    stem = "description"
                lines = [line for line in lines if not (stem and line.startswith(stem))] + [command]
        self.text = "interface Ethernet2\n" + "".join(f"   {line}\n" for line in sorted(lines))   # EOS prints canonically
        return ""


class SnapshotExecutorTests(SimpleTestCase):
    def executor(self, conn):
        def read(_device):   # the Phase-15 read groups, derived from the same fake device the commands change
            addresses = [line.split()[2] for line in conn.text.splitlines() if " address " in line]
            return DeviceEvidence("ceos", "ceos", {n: FactGroup(v, "SYNTHETIC") for n, v in (
                ("interfaces", {"Ethernet2": {"admin": "UP", "oper": "UP"}}), ("addresses", {"Ethernet2": addresses}),
                ("routes", []))}, live_attempted=True)

        executor = CeosExecutor({"name": "ceos"}, connection_factory=lambda _d: conn, reader=read)
        executor.connect()
        return executor

    def test_plan_order_each_configlet_restores_the_state_it_found(self):
        start = "interface Ethernet2\n   description legacy uplink\n   load-interval 30\n"
        conn = FakeEos(start)
        executor = self.executor(conn)
        specs = [ConfigletSpec("if", 1, "ceos", "arista_ceos", "interface", "CREATE_DEFINE",
                               ("interface Ethernet2", "   description NMAS", "   mtu 1500"), {"interface": "Ethernet2"}),
                 ConfigletSpec("a6", 2, "ceos", "arista_ceos", "address", "CREATE_DEFINE",
                               ("interface Ethernet2", "   ipv6 address 2001:db8:44::1/64"),
                               {"interface": "Ethernet2", "address": "2001:db8:44::1/64", "family": 6})]
        preflights = [executor.assess(s) for s in specs]                   # engine order: every preflight first
        self.assertEqual([(p.action, p.restorable) for p in preflights], [(APPLY, True), (APPLY, True)])
        for s, p in zip(specs, preflights):
            self.assertTrue(executor.apply(s, p).ok)
        self.assertIn("ipv6 address 2001:db8:44::1/64", conn.text)
        self.assertEqual([executor.compensate(s, p).status for s, p in reversed(list(zip(specs, preflights)))], ["COMPENSATED"] * 2)
        self.assertEqual(conn.text, start)
        self.assertEqual(executor.assess(ConfigletSpec("x", 3, "ceos", "arista_ceos", "interface", "CREATE_DEFINE",
                                                       ("interface Ethernet2", "   load-interval 30"), {"interface": "Ethernet2"})).action,
                         SKIP_SATISFIED)

    def test_state_changed_by_someone_else_is_reported_not_hidden(self):
        conn = FakeEos("interface Ethernet2\n   description legacy uplink\n")
        executor = self.executor(conn)
        spec = ConfigletSpec("if", 1, "ceos", "arista_ceos", "interface", "CREATE_DEFINE",
                             ("interface Ethernet2", "   mtu 1500"), {"interface": "Ethernet2"})
        preflight = executor.assess(spec)
        executor.apply(spec, preflight)
        conn.text += "   storm-control broadcast level 5\n"
        outcome = executor.compensate(spec, preflight)
        self.assertEqual((outcome.status, outcome.error_code), ("COMPENSATION_FAILED", "STATE_NOT_RESTORED"))


class RoutedPortImportTests(SimpleTestCase):
    def test_dormant_switchport_lines_do_not_make_a_routed_port_an_access_port(self):
        text = ("interface Ethernet2\n   description x\n   switchport access vlan 45\n   no switchport\n   ip address 198.18.0.1/30\n!\n"
                "interface Ethernet3\n   switchport access vlan 45\n!\n")
        kinds = {i.name: i.kind for i in parser_ceos.parse(text).interfaces}
        self.assertEqual(kinds, {"Ethernet2": "ROUTED_PHYSICAL", "Ethernet3": "ACCESS"})
