"""Offline unit tests for modules/eos_render.py (Phase 3C extraction from
master.py -- see that module's docstring for why).

Regression coverage proves the extraction changed nothing about how the
9 real, managed device templates render/flatten (Step 8/15: "existing
primary NMAS behavior... existing routing/NAT/monitoring model remains
untouched"), and adds coverage for the new "dhcp server"/"subnet "/
"range " mode-start prefixes the Phase 3C DHCP template needs.
"""
from __future__ import annotations

import unittest

import yaml

from modules.eos_render import BASE, eos_commands, render

INVENTORY = yaml.safe_load((BASE / "inventory.yml").read_text())


class ExistingTemplatesRegressionTests(unittest.TestCase):
    """Every managed EOS device template must still render and flatten
    exactly as it did before eos_render.py was extracted from master.py --
    a pure refactor, not a behavior change."""

    def test_every_eos_template_renders_and_flattens(self):
        management = INVENTORY["management"]
        for node, meta in INVENTORY["network_devices"].items():
            if node in ("R3", "R4"):
                continue  # Linux/FRR, not rendered through this path
            with self.subTest(node=node):
                cfg = render(f"templates/{meta['template']}", {"management": management, "node": node})
                commands = eos_commands(cfg)
                self.assertTrue(commands)
                # No existing template contains a DHCP-server-mode line --
                # confirms the new MODE_STARTS entries are inert for them.
                self.assertFalse(any(c.startswith(("dhcp server", "subnet ", "range ")) for c in commands))

    def test_rerendering_is_deterministic(self):
        cfg1 = render("templates/R1.cfg.j2", {"management": INVENTORY["management"], "node": "R1"})
        cfg2 = render("templates/R1.cfg.j2", {"management": INVENTORY["management"], "node": "R1"})
        self.assertEqual(cfg1, cfg2)
        self.assertEqual(eos_commands(cfg1), eos_commands(cfg2))


class EosCommandsModeNestingTests(unittest.TestCase):
    """Unit coverage for the Phase 3C MODE_STARTS additions in isolation."""

    def test_interface_still_opens_and_closes_a_mode(self):
        text = "interface Vlan200\n   ip address 192.168.200.1/24\nvlan 10\n   name USERS10\n"
        self.assertEqual(
            eos_commands(text),
            ["interface Vlan200", "ip address 192.168.200.1/24", "exit", "vlan 10", "name USERS10", "exit"],
        )

    def test_dhcp_server_subnet_and_range_all_open_modes(self):
        text = (
            "dhcp server\n"
            "   subnet 192.168.10.0/24\n"
            "      name VLAN10-v4-secondary\n"
            "      range 192.168.10.200 192.168.10.220\n"
            "   subnet 192.168.20.0/24\n"
            "      range 192.168.20.200 192.168.20.220\n"
            "interface Vlan200\n"
            "   dhcp server ipv4\n"
        )
        commands = eos_commands(text)
        # Every subnet's range submode is closed before the next sibling
        # subnet is entered, and dhcp-server mode is closed before
        # "interface Vlan200" starts -- this is the exact nesting bug
        # (missing "range " in MODE_STARTS) this test class guards.
        self.assertEqual(
            commands,
            [
                "dhcp server",
                "subnet 192.168.10.0/24",
                "name VLAN10-v4-secondary",
                "range 192.168.10.200 192.168.10.220",
                "exit",  # closes range
                "exit",  # closes first subnet
                "subnet 192.168.20.0/24",
                "range 192.168.20.200 192.168.20.220",
                "exit",  # closes range
                "exit",  # closes second subnet
                "exit",  # closes dhcp server
                "interface Vlan200",
                "dhcp server ipv4",
                "exit",  # closes interface Vlan200 (trailing, no further sibling)
            ],
        )

    def test_blank_lines_and_bangs_are_ignored(self):
        text = "dhcp server\n\n   subnet 10.0.0.0/24\n!\n      range 10.0.0.10 10.0.0.20\n"
        commands = eos_commands(text)
        self.assertNotIn("", commands)
        self.assertNotIn("!", commands)


if __name__ == "__main__":
    unittest.main()
