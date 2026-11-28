"""The R4 -> R6 -> R7 Management VRF lab tool (labs/r4-r6-r7-demo/management_vrf.py): its plan is the reviewed change, and
multi-target writes are refused before any device is contacted."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.test import SimpleTestCase

TOOL = Path(settings.BASE_DIR).parent / "labs" / "r4-r6-r7-demo" / "management_vrf.py"


def load():
    spec = importlib.util.spec_from_file_location("lab_management_vrf", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ManagementVrfToolTests(SimpleTestCase):
    def setUp(self):
        self.tool = load()
        patcher = mock.patch.object(self.tool, "_run", side_effect=AssertionError("a device was contacted"))
        self.contacted = patcher.start()
        self.addCleanup(patcher.stop)

    def test_main_plan_lists_every_hop_and_contacts_nothing(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(self.tool.main(["plan", "all"]), 0)
        plan = {row["target"]: row["lines"] for row in json.loads(out.getvalue())}
        self.assertEqual(sorted(plan), ["R4", "R6", "R7", "host"])
        self.assertIn("interface Ethernet1.251", plan["R6"])
        self.assertIn("interface Ethernet2.251", plan["R6"])
        self.assertIn("   ip address 10.254.251.6/30", plan["R7"])
        self.assertIn("ip route vrf MGMT 192.168.200.100/32 10.254.251.5", plan["R7"])
        self.assertIn("pref 900 iif Vlan200 from 192.168.200.100/32 to 10.254.251.0/29 lookup 251", plan["R4"])
        self.assertFalse(any("Vlan200" in line for line in plan["R6"] + plan["R7"]))      # VLAN 200 never reaches the routed hops
        self.contacted.assert_not_called()

    def test_main_refuses_apply_or_confirm_for_all_targets_without_contacting_a_device(self):
        for action in ("apply", "confirm"):
            with self.subTest(action), self.assertRaises(SystemExit) as refused:
                self.tool.main([action, "all"])
            self.assertIn("one target at a time", str(refused.exception))
        self.contacted.assert_not_called()
