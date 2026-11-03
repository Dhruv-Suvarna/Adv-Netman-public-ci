"""cEOS IPv6 static routes that carry ``ipv6 unicast-routing`` (Lab 8 R6/R7: natively onboarded devices boot without it).

Such a Configlet is two top-level lines, so the one-leaf inverse of a static route cannot prove it; it is judged like a
configuration block instead: the inverse comes from the configuration captured right before apply, so the prerequisite is
removed again only by the Configlet that really added it, and compensation is proven by the captured configuration digest.
"""

from django.test import SimpleTestCase

from core.services.execution.executors.base import APPLY, ConfigletSpec
from core.services.execution.executors.ceos import CeosExecutor
from core.services.health.evidence import DeviceEvidence, FactGroup

START = "hostname R6\nip routing\n!\ninterface Ethernet1\n   no switchport\n   ip address 10.254.90.2/29\n!\n"


class FakeGlobalEos:
    """Applies global (top-level) statements and their ``no`` forms to a running configuration."""

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
        lines = self.text.splitlines()
        for command in commands:
            if command.startswith("no ") and command[3:] in lines:
                lines.remove(command[3:])
            elif not command.startswith("no ") and command not in lines:
                lines.append(command)
        self.text = "\n".join(lines) + "\n"
        return ""


def _route(cfg_id, destination, next_hop, *, prerequisite=True):
    lines = (("ipv6 unicast-routing",) if prerequisite else ()) + (f"ipv6 route {destination} {next_hop}",)
    return ConfigletSpec(cfg_id, int(cfg_id[-1]), "R6", "arista_ceos", "static_route", "CREATE_DEFINE", lines,
                         {"prefix": destination, "family": 6, "next_hop": next_hop, "exit_interface": ""})


class Ipv6StaticPrerequisiteTests(SimpleTestCase):
    def executor(self, conn):
        def read(_device):
            return DeviceEvidence("R6", "ceos", {n: FactGroup(v, "SYNTHETIC") for n, v in (
                ("interfaces", {}), ("addresses", {}), ("routes", []))}, live_attempted=True)

        executor = CeosExecutor({"name": "R6"}, connection_factory=lambda _d: conn, reader=read)
        executor.connect()
        return executor

    def test_two_routes_add_ipv6_routing_once_and_reverse_compensation_restores_the_captured_config(self):
        conn = FakeGlobalEos(START)
        executor = self.executor(conn)
        specs = [_route("CFG-7", "::/0", "2001:db8:254:90::1"), _route("CFG-8", "2001:db8:254:10::/64", "2001:db8:254:96::2")]
        preflights = [executor.assess(s) for s in specs]
        self.assertEqual([(p.action, p.restorable, p.reason) for p in preflights], [(APPLY, True, "")] * 2)
        for s, p in zip(specs, preflights):
            self.assertTrue(executor.apply(s, p).ok)
        self.assertEqual(conn.text.count("ipv6 unicast-routing"), 1)
        self.assertIn("ipv6 route ::/0 2001:db8:254:90::1", conn.text)
        outcomes = [executor.compensate(s, p) for s, p in reversed(list(zip(specs, preflights)))]
        self.assertEqual([o.status for o in outcomes], ["COMPENSATED"] * 2)
        self.assertEqual(conn.text, START)
        # the second route found IPv6 routing on: only the first Configlet removes it
        self.assertEqual(conn.sent[2], ["no ipv6 route 2001:db8:254:10::/64 2001:db8:254:96::2"])
        self.assertEqual(conn.sent[3], ["no ipv6 route ::/0 2001:db8:254:90::1", "no ipv6 unicast-routing"])

    def test_ipv6_routing_already_on_is_never_removed(self):
        conn = FakeGlobalEos(START + "ipv6 unicast-routing\n")
        executor = self.executor(conn)
        spec = _route("CFG-7", "::/0", "2001:db8:254:90::1")
        preflight = executor.assess(spec)
        self.assertTrue(executor.apply(spec, preflight).ok)
        self.assertEqual(executor.compensate(spec, preflight).status, "COMPENSATED")
        self.assertEqual(conn.sent[-1], ["no ipv6 route ::/0 2001:db8:254:90::1"])
        self.assertIn("ipv6 unicast-routing", conn.text)

    def test_a_single_line_route_keeps_its_leaf_inverse_and_an_unknown_extra_line_stays_unprovable(self):
        executor = self.executor(FakeGlobalEos(START))
        plain = executor.assess(_route("CFG-7", "::/0", "2001:db8:254:90::1", prerequisite=False))
        self.assertEqual((plain.action, plain.restorable), (APPLY, True))
        odd = ConfigletSpec("CFG-9", 9, "R6", "arista_ceos", "static_route", "CREATE_DEFINE",
                            ("ip routing vrf X", "ipv6 route ::/0 2001:db8:254:90::1"),
                            {"prefix": "::/0", "family": 6, "next_hop": "2001:db8:254:90::1", "exit_interface": ""})
        self.assertFalse(executor.assess(odd).restorable)
