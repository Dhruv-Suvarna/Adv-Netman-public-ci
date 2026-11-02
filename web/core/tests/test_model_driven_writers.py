"""Software-only writer evidence; no live model-driven write is permitted."""

from __future__ import annotations

from unittest import mock

from django.test import SimpleTestCase

from core.services.execution.writers import srlinux_gnmi


class SrLinuxGnmiWriterTests(SimpleTestCase):
    CANDIDATE = """! Candidate Configuration
! Not deployed.
set system name host-name SRL1
set interface ethernet-1/1 admin-state enable
set interface ethernet-1/1 subinterface 0 ipv4 address 192.0.2.1/31
"""

    def test_builds_one_atomic_private_candidate_cli_origin_update(self):
        plan = srlinux_gnmi.build_set_plan(self.CANDIDATE)
        self.assertEqual(plan.origin, "cli")
        self.assertEqual(plan.encoding, "ascii")
        self.assertTrue(plan.atomic)
        self.assertTrue(plan.private_candidate)
        self.assertFalse(plan.live_verified)
        self.assertEqual(plan.update[0][0], "cli:")
        self.assertEqual(
            plan.update[0][1].splitlines(),
            [
                "/system name host-name SRL1",
                "/interface ethernet-1/1 admin-state enable",
                "/interface ethernet-1/1 subinterface 0 ipv4 address 192.0.2.1/31",
            ],
        )

    def test_runtime_is_disabled_by_default(self):
        client = mock.Mock()
        with self.assertRaises(srlinux_gnmi.WriterRuntimeDisabled):
            srlinux_gnmi.apply(client, srlinux_gnmi.build_set_plan(self.CANDIDATE))
        client.set.assert_not_called()

    def test_injected_mock_client_proves_exact_set_call(self):
        client = mock.Mock()
        client.set.return_value = {"timestamp": 1, "response": [{"op": "UPDATE"}]}
        plan = srlinux_gnmi.build_set_plan(self.CANDIDATE)
        result = srlinux_gnmi.apply(client, plan, runtime_enabled=True)
        client.set.assert_called_once_with(update=list(plan.update), encoding="ascii")
        self.assertEqual(result["timestamp"], 1)

    def test_refuses_unsupported_placeholder_or_foreign_cli(self):
        bad = (
            self.CANDIDATE + "! UNSUPPORTED CANDIDATE OBJECT: x\n",
            "set system name host-name <hostname-required>\n",
            "hostname not-srlinux\n",
        )
        for candidate in bad:
            with self.subTest(candidate=candidate):
                with self.assertRaises(srlinux_gnmi.WriterInputError):
                    srlinux_gnmi.build_set_plan(candidate)
