"""Lab 7 closure -- ``modules/ipam_context.py`` context/candidate writers and ``modules/ipam_evidence.py`` live evidence.

The in-memory fake NetBox fixtures of ``test_netbox_ipam`` / ``test_ipam_evidence`` are reused (read-only, no HTTP).
POSITIVE: a managed device's context carries its interfaces, management pair and shared VLAN gateways; a candidate
is written to the requested directory; a report without issues is READY.  NEGATIVE: an unmanaged device is refused
before any write, a BLOCKED / FAIL issue never reads READY, and live evidence with a non-static VLAN200, a missing
device or an unexpected address produces exact validation failures.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_ipam_evidence as evidence_base  # sibling fixture modules (discover -s monitoring/tests)
import test_netbox_ipam as base
from modules import ipam_context as ic
from modules import ipam_evidence
from modules import netbox_ipam as nb


def client_with_vlan20():
    client = base.FakeNetboxClient()
    client._vlans.append(base._Vlan(4, 20, "USERS20", "client"))
    return client


class DeviceContextTests(unittest.TestCase):
    def test_build_device_context_returns_interfaces_management_and_gateways(self):
        context = ic.build_device_context("S1", client_with_vlan20())
        self.assertEqual((context["device"], context["managed"], context["management"]["ipv4"]["cidr"], context["management"]["ipv6"]),
                         ("S1", True, "192.168.200.11/24", None))
        self.assertEqual(sorted(context["interfaces"]), ["Ethernet1", "Vlan10", "Vlan200", "Vlan30"])
        self.assertEqual(context["interfaces"]["Vlan30"]["ipv4"], None)
        self.assertEqual(context["interfaces"]["Vlan30"]["ipv6"]["cidr"], "2001:db8:30::2/64")
        self.assertEqual(context["client_vlan_gateways"][10]["ipv4"]["address"], "192.168.10.1")
        self.assertEqual((context["client_vlan_gateways"][20], context["client_vlan_gateways"][30]["ipv4"]),
                         ({"ipv4": None, "ipv6": None}, None))

    def test_write_candidate_config_returns_the_written_path(self):
        with tempfile.TemporaryDirectory() as root, patch.object(ic, "render_candidate_config", return_value="hostname S1\n") as render:
            path = ic.write_candidate_config("S1", client=object(), out_dir=Path(root, "shadow"))
            self.assertEqual((path, path.read_text()), (Path(root, "shadow", "S1.cfg"), "hostname S1\n"))
        render.assert_called_once()

    def test_write_candidate_config_for_an_unmanaged_device_is_refused_without_a_file(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(nb.NetboxModelError, "'R5' is not a managed device"):
                ic.write_candidate_config("R5", client=base.FakeNetboxClient(), out_dir=Path(root))
            self.assertEqual(list(Path(root).iterdir()), [])


class ReservationReportTests(unittest.TestCase):
    def test_overall_status_of_a_clean_report_is_ready(self):
        report = ic.ReservationReport(rows=[], readiness=[ic.ReservationReadiness("S1", "Vlan10", 4, ic.READINESS_READY, "ok")])
        self.assertEqual((report.ok, report.overall_status, report.readiness_counts), (True, "READY", {"READY": 1, "BLOCKED": 0, "FAIL": 0}))

    def test_overall_status_is_never_ready_with_a_blocked_or_failed_issue(self):
        blocked = ic.ReservationReport(rows=[], issues=[ic.ReservationIssue("identity-missing", "x", status=ic.READINESS_BLOCKED)])
        failed = ic.ReservationReport(rows=[], issues=[ic.ReservationIssue("a", "x", status=ic.READINESS_BLOCKED), ic.ReservationIssue("b", "y")])
        self.assertEqual([(r.ok, r.overall_status) for r in (blocked, failed)], [(False, "BLOCKED"), (False, "FAIL")])


class LiveEvidenceFailureTests(unittest.TestCase):
    def test_collect_live_evidence_reports_a_non_static_vlan200_and_validate_fails_it(self):
        manifest = ipam_evidence.load_manifest()
        live = ipam_evidence.collect_live_evidence(client=evidence_base._FakeNetBox(manifest, non_static_device="S2"), manifest=manifest)
        self.assertEqual((live["vlan200_policy"], live["reservation_targets"], live["management_static_count"]),
                         ("NOT_UNIFORMLY_STATIC", 1, len(ipam_evidence.MANAGED) - 1))
        self.assertEqual(ipam_evidence.validate(live), [f"VLAN200 static policy coverage: expected {len(ipam_evidence.MANAGED)}, found {len(ipam_evidence.MANAGED) - 1}",
                                                        "VLAN200 must remain static and absent from reservations"])

    def test_collect_live_evidence_counts_missing_devices_and_unexpected_addresses(self):
        manifest = ipam_evidence.load_manifest()
        client = evidence_base._FakeNetBox(manifest)
        client.dcim.devices._lookup.pop((("name", ipam_evidence.MANAGED[0]),))
        client.ipam.ip_addresses._rows.append(evidence_base._Row(address="198.51.100.9/32"))
        live = ipam_evidence.collect_live_evidence(client=client, manifest=manifest)
        self.assertEqual((live["unexpected_addresses"], live["missing_address_count"], live["management_dual_stack_count"]),
                         (["198.51.100.9/32"], 0, len(ipam_evidence.MANAGED) - 1))
        failures = ipam_evidence.validate(live)
        self.assertIn("unexpected_address_count: 1", failures)
        self.assertIn(f"IP address count: expected {live['total_address_count']}, found {live['total_address_count'] + 1}", failures)


if __name__ == "__main__":
    unittest.main()
