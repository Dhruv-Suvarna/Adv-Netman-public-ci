"""IOS XE executor, captured running-config inverse and show-command state reader (no device: a small IOS config fake)."""

from __future__ import annotations

from django.test import SimpleTestCase

from core.services.capabilities import batch_iosxe
from core.services.execution import capability
from core.services.execution.executors import iosxe
from core.services.execution.executors.base import ConfigletSpec, ExecutorError
from core.services.health import live

BASE = """Building configuration...
Current configuration : 4242 bytes
!
! Last configuration change at 06:20:00 UTC Mon Oct 5 2026
hostname iosxe
ipv6 unicast-routing
interface GigabitEthernet1
 vrf forwarding clab-mgmt
 ip address 10.0.0.15 255.255.255.0
interface GigabitEthernet2
 no ip address
 shutdown
 negotiation auto
ip route vrf clab-mgmt 0.0.0.0 0.0.0.0 10.0.0.2
end
"""
SINGLE = ("description", "ip address", "mtu", "encapsulation")


class FakeIos:
    """Enough IOS configuration semantics to prove inverses: ordered blocks, single-valued lines, ``no`` forms."""

    def __init__(self, text=BASE):
        self.top, self.blocks, self.sent, self.reject = [], {}, [], ""
        for line in iosxe.stable_config(text).splitlines():
            if line.startswith(" "):
                self.blocks[self.top[-1]].append(line.strip())
            else:
                self.top.append(line)
                self.blocks[line] = []

    def send_command(self, command, **_kwargs):
        if command == "show tcp brief numeric":
            return "TCB       Local Address               Foreign Address             (state)\n7F1A2B3C  10.0.0.15.22               10.0.0.2.40122              ESTAB\n"
        assert command == "show running-config"
        return "Building configuration...\n" + "\n".join(
            part for head in sorted(self.top)        # IOS prints a canonical order, whatever order lines were entered in
            for part in (head, *(f" {child}" for child in sorted(self.blocks[head])))) + "\nend\n"

    def send_config_set(self, commands, **_kwargs):
        self.sent.append(list(commands))
        current = None
        for command in commands:
            if self.reject and self.reject in command:
                return "% Invalid input detected at '^' marker."
            if command.startswith("interface "):
                current = command
                if current not in self.blocks:
                    self.top.append(current)
                    self.blocks[current] = ["no ip address"]
            elif command.startswith("no interface "):
                self.top.remove(command[3:])
                self.blocks.pop(command[3:])
            elif command.startswith(("ip route ", "ipv6 route ")):
                current = None
                self.top.append(command) if command not in self.top else None
                self.blocks.setdefault(command, [])
            elif command.startswith(("no ip route ", "no ipv6 route ")):
                current = None
                self.top.remove(command[3:])
                self.blocks.pop(command[3:])
            else:
                self._child(self.blocks[current], command)
        return ""

    @staticmethod
    def _child(lines, command):
        negated, text = command.startswith("no "), command.removeprefix("no ")
        stem = next((s for s in SINGLE if text.startswith(s)), None)
        if text == "shutdown":
            lines[:] = [line for line in lines if line != "shutdown"] + ([] if negated else ["shutdown"])
        elif text == "ip address":                               # ``no ip address``: remove every IPv4 address
            lines[:] = [line for line in lines if "ip address" not in line] + ["no ip address"]
        elif negated:
            lines[:] = [line for line in lines if line.lower() != text.lower()]
            if stem == "ip address" and not any(line.startswith("ip address") for line in lines):
                lines[:] = [line for line in lines if line != "no ip address"] + ["no ip address"]
        else:
            if stem:
                lines[:] = [line for line in lines if not line.startswith(stem) and not (stem == "ip address" and line == "no ip address")]
            if text not in lines:
                lines.append(text.replace("2001:db8", "2001:DB8") if text.startswith("ipv6 address") else text)

    def disconnect(self):
        pass


def _spec(n, kind, lines, **kwargs):
    return ConfigletSpec(f"CFG-{n}", n, "iosxe", "cisco_c8000v_iosxe", kind, "CREATE_DEFINE", tuple(lines), **kwargs)


def _executor(node):
    executor = iosxe.IosXeExecutor({"name": "iosxe", "platform": "cisco_c8000v_iosxe"}, connection_factory=lambda _d: node)
    executor.connect()
    return executor


class InverseTests(SimpleTestCase):
    def test_new_blocks_are_removed_as_a_whole(self):
        text = iosxe.stable_config(BASE)
        self.assertEqual(iosxe.config_inverse(["interface Loopback44", " description x", " no shutdown"], text), ["no interface Loopback44"])
        self.assertEqual(iosxe.config_inverse(["ip route 203.0.113.0 255.255.255.0 198.18.0.2 200"], text),
                         ["no ip route 203.0.113.0 255.255.255.0 198.18.0.2 200"])
        self.assertEqual(iosxe.config_inverse(["ip route vrf clab-mgmt 0.0.0.0 0.0.0.0 10.0.0.2"], text), [])

    def test_existing_interface_is_restored_from_the_captured_section(self):
        text = iosxe.stable_config(BASE)
        inverse = iosxe.config_inverse(["interface GigabitEthernet2", " description NMAS", " no shutdown", " negotiation auto"], text)
        self.assertEqual(inverse, ["interface GigabitEthernet2", " shutdown", " no description NMAS",
                                   " no ip address", " shutdown", " negotiation auto"])
        up = text.replace(" shutdown\n", "")
        self.assertEqual(iosxe.config_inverse(["interface GigabitEthernet2", " no shutdown"], up), [])      # defaults are not displayed
        cased = up.replace(" negotiation auto", " negotiation auto\n ipv6 address 2001:DB8:44::1/64")
        self.assertEqual(iosxe.config_inverse(["interface GigabitEthernet2", " ipv6 address 2001:db8:44::1/64"], cased), [])

    def test_unprovable_inverses_fail_closed(self):
        text = iosxe.stable_config(BASE) + "\nip route 203.0.113.0 255.255.255.0 198.18.0.2 50"
        self.assertIsNone(iosxe.config_inverse(["ip route 203.0.113.0 255.255.255.0 198.18.0.2 200"], text))    # replaces a distance
        self.assertIsNone(iosxe.config_inverse(["no ip routing"], text))
        secret = text.replace(" negotiation auto", " negotiation auto\n ip ospf authentication-key <REDACTED>")
        self.assertIsNone(iosxe.config_inverse(["interface GigabitEthernet2", " description x"], secret))


class ExecutorTests(SimpleTestCase):
    def test_capability_is_iosxe_only(self):
        for kind in ("interface", "address", "static_route"):
            cap = capability.capability_for("cisco_c8000v_iosxe", kind)
            self.assertEqual((cap.apply, cap.compensation, cap.transport), ("SUPPORTED", "SUPPORTED", "netmiko-config-mode"))
        self.assertEqual(capability.capability_for("cisco_iosxr", "interface").apply, "NOT_IMPLEMENTED")

    def test_transaction_restores_the_exact_running_configuration(self):
        for seed in ((), ("interface GigabitEthernet2", "description legacy", "ip address 198.18.7.1 255.255.255.0", "no shutdown")):
            with self.subTest(seed=bool(seed)):
                node = FakeIos()
                node.send_config_set(list(seed)) if seed else None
                node.sent.clear()
                executor = _executor(node)
                before = executor.running_config_digest()
                specs = [_spec(1, "interface", ["interface GigabitEthernet2", " description NMAS", " mtu 1500", " no shutdown"]),
                         _spec(2, "address", ["interface GigabitEthernet2", " ip address 198.18.0.1 255.255.255.252"]),
                         _spec(3, "address", ["interface GigabitEthernet2", " ipv6 address 2001:db8:44::1/64"]),
                         _spec(4, "interface", ["interface Loopback44", " no shutdown"]),
                         _spec(5, "static_route", ["ip route 203.0.113.0 255.255.255.0 198.18.0.2 200"])]
                preflights = [executor.assess(spec) for spec in specs]
                self.assertEqual({(p.action, p.restorable) for p in preflights}, {("APPLY", True)})
                self.assertFalse(node.sent)
                for spec, preflight in zip(specs, preflights):
                    self.assertTrue(executor.apply(spec, preflight).ok)
                self.assertIn("ip address 198.18.0.1 255.255.255.252", node.blocks["interface GigabitEthernet2"])
                self.assertEqual(executor.assess(specs[2]).action, "SKIP_SATISFIED")          # device upper-cases IPv6
                statuses = [executor.compensate(s, p).status for s, p in reversed(list(zip(specs, preflights)))]
                self.assertEqual(statuses, ["COMPENSATED"] * 5)
                self.assertEqual(executor.running_config_digest(), before)

    def test_rejection_and_unrestored_state_are_reported(self):
        node = FakeIos()
        executor = _executor(node)
        spec = _spec(1, "interface", ["interface GigabitEthernet2", " description NMAS", " mtu 99999"])
        preflight = executor.assess(spec)
        node.reject = "mtu 99999"
        outcome = executor.apply(spec, preflight)
        self.assertEqual((outcome.ok, outcome.error_code, outcome.partial_effects), (False, "COMMAND_REJECTED", True))
        node.reject = ""
        self.assertEqual(executor.compensate(spec, preflight).status, "COMPENSATED")       # the partial line is undone
        self.assertNotIn("description NMAS", node.blocks["interface GigabitEthernet2"])
        preflight = executor.assess(spec)
        self.assertTrue(executor.apply(spec, preflight).ok)
        node.reject = "no description"
        self.assertEqual(executor.compensate(spec, preflight).status, "COMPENSATION_FAILED")

    def test_never_cuts_the_session_it_is_managed_through(self):
        node = FakeIos()
        executor = _executor(node)
        for lines in (["interface GigabitEthernet1", " ip address 198.18.0.1 255.255.255.252"], ["interface GigabitEthernet1", " shutdown"],
                      ["interface GigabitEthernet1", " no vrf forwarding clab-mgmt"], ["no interface GigabitEthernet1"]):
            found = executor.assess(_spec(1, "address", lines))
            self.assertEqual((found.action, found.restorable, found.reason), ("REFUSE", False, "MANAGEMENT_SESSION_AT_RISK"), lines)
        self.assertFalse(node.sent)
        for lines in (["interface GigabitEthernet1", " description uplink"], ["interface GigabitEthernet1", " ip address 198.18.0.1 255.255.255.252 secondary"],
                      ["interface GigabitEthernet2", " ip address 198.18.0.1 255.255.255.252"]):
            self.assertEqual(executor.assess(_spec(1, "address", lines)).action, "APPLY", lines)

    def test_refusals_and_unreadable_state(self):
        executor = _executor(FakeIos())
        for spec in (_spec(1, "routing_isis", ["router isis NMAS"]), _spec(2, "interface", ()),
                     _spec(3, "interface", ["interface Loopback44"], origin="RAW")):
            self.assertEqual(executor.assess(spec).action, "REFUSE")
        blank = iosxe.IosXeExecutor({"name": "iosxe"}, connection_factory=lambda _d: FakeIos("hostname x\n"))
        blank.connect()
        with self.assertRaises(ExecutorError):
            blank.assess(_spec(1, "interface", ["interface Loopback44"]))
        with self.assertRaises(ExecutorError):
            iosxe.netmiko_connection({"name": "not-in-inventory"})


V4 = """GigabitEthernet1 is up, line protocol is up
  Internet address is 10.0.0.15/24
  Broadcast address is 255.255.255.255
GigabitEthernet2 is up, line protocol is up
  Internet address is 198.18.0.1/30
  Secondary address 198.18.7.1/24
GigabitEthernet2.44 is deleted, line protocol is down
  Internet protocol processing disabled
GigabitEthernet3 is administratively down, line protocol is down
  Internet protocol processing disabled
"""
V6 = """GigabitEthernet2 is up, line protocol is up
  IPv6 is enabled, link-local address is FE80::A8C1:ABFF:FED4:A437
  Global unicast address(es):
    2001:DB8:44::1, subnet is 2001:DB8:44::/64
"""
R4 = """Gateway of last resort is not set

      10.0.0.0/24 is subnetted, 1 subnets
S        10.99.1.0 [1/0] via 198.18.0.2
      198.18.0.0/24 is variably subnetted, 2 subnets, 2 masks
C        198.18.0.0/30 is directly connected, GigabitEthernet2
L        198.18.0.1/32 is directly connected, GigabitEthernet2
S     203.0.113.0/24 [200/0] via 198.18.0.2
"""
R6 = """S   2001:DB8:113::/64 [200/0]
     via 2001:DB8:44::2
C   2001:DB8:44::/64 [0/0]
     via GigabitEthernet2, directly connected
"""


class StateReaderTests(SimpleTestCase):
    def test_interfaces_and_addresses(self):
        interfaces, addresses = live.parse_iosxe_interfaces(V4, V6)
        self.assertEqual(interfaces, {"GigabitEthernet1": {"admin": "UP", "oper": "UP"}, "GigabitEthernet2": {"admin": "UP", "oper": "UP"},
                                      "GigabitEthernet3": {"admin": "DOWN", "oper": "DOWN"}})       # a deleted subinterface is absent
        self.assertEqual(addresses["GigabitEthernet2"], ["198.18.0.1/30", "198.18.7.1/24", "2001:db8:44::1/64"])

    def test_routes_resolve_subnetted_masks_and_ipv6_next_hops(self):
        routes = {r["prefix"]: r for r in live.parse_iosxe_routes(R4, R6)}
        self.assertEqual(routes["10.99.1.0/24"], {"prefix": "10.99.1.0/24", "type": "static", "next_hops": ["198.18.0.2"], "interfaces": []})
        self.assertEqual(routes["203.0.113.0/24"]["next_hops"], ["198.18.0.2"])
        self.assertEqual((routes["198.18.0.0/30"]["type"], routes["198.18.0.0/30"]["interfaces"]), ("connected", ["GigabitEthernet2"]))
        self.assertEqual(routes["2001:db8:113::/64"], {"prefix": "2001:db8:113::/64", "type": "static",
                                                       "next_hops": ["2001:db8:44::2"], "interfaces": []})
        self.assertEqual(routes["2001:db8:44::/64"]["interfaces"], ["GigabitEthernet2"])

    def test_read_device_sends_only_allowlisted_show_commands(self):
        class Conn:
            sent = []

            def send_command(self, command, **_kwargs):
                self.sent.append(command)
                return {"show ip interface": V4, "show ipv6 interface": V6, "show ip route": R4, "show ipv6 route": R6}.get(command, "")

        conn = Conn()
        device = {"name": "iosxe", "platform": "cisco_c8000v_iosxe"}
        evidence = live.read_device(device, session_factory=lambda d: live.IosXeSession(d, conn=conn))
        self.assertTrue(evidence.live_reachable)
        self.assertEqual(set(conn.sent), set(live.IOSXE_COMMANDS.values()))
        self.assertTrue(all(command.startswith("show ") for command in conn.sent))
        with self.assertRaises(live.LiveError):
            live.IosXeSession(device, conn=conn).run("startup_config")
        self.assertEqual(live.read_device(device).live_error, "NOT_CONFIGURED")


class PlanTests(SimpleTestCase):
    def test_configlets_follow_the_planner_decomposition(self):
        _, specs, _, _ = batch_iosxe.plan("interface.LOOPBACK")
        self.assertEqual([list(s.lines) for s in specs], [
            ["interface Loopback44", " description NMAS isolated assessment", " no shutdown"],
            ["interface Loopback44", " ip address 198.18.0.1 255.255.255.252"],
            ["interface Loopback44", " ipv6 address 2001:db8:44::1/64"]])
        prerequisites, specs, _, _ = batch_iosxe.plan("routing.STATIC_IPV6")
        self.assertEqual(list(specs[0].lines), ["ipv6 route 2001:db8:113::/64 2001:db8:44::2 200"])
        self.assertEqual(prerequisites[0], "interface GigabitEthernet2")
