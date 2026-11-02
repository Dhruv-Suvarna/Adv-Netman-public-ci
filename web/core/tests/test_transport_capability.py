"""Phase 20.5 (spec section 14): deployment transport capability must be
capability-driven, never a fabricated NETCONF/gNMI write option. See
core/services/execution/transport_capability.py.
"""

from __future__ import annotations

from django.test import TestCase
from django.urls import reverse

from core import models
from core.services.execution import transport_capability as tc
from core.tests.helpers import execution as x
from core.tests.helpers.validation import simple_pass_change


class TransportMatrixTests(TestCase):
    def test_ceos_is_ssh_cli_and_model_driven_transports_are_read_only(self):
        rows = {row["transport"]: row for row in tc.deployment_transport_matrix(models.Platform.ARISTA_CEOS)}
        self.assertEqual(rows["SSH_CLI"]["status"], "AVAILABLE")
        self.assertEqual(rows["DOCKER_EXEC"]["status"], "NOT_IMPLEMENTED")
        self.assertEqual(rows["NETCONF"]["status"], "READ_ONLY")
        self.assertEqual(rows["GNMI_SET"]["status"], "READ_ONLY")
        self.assertEqual(tc.selected_transport(models.Platform.ARISTA_CEOS), "SSH_CLI")

    def test_ubuntu_frr_is_docker_exec_not_ssh(self):
        rows = {row["transport"]: row for row in tc.deployment_transport_matrix(models.Platform.UBUNTU_FRR)}
        self.assertEqual(rows["DOCKER_EXEC"]["status"], "AVAILABLE")
        self.assertEqual(rows["SSH_CLI"]["status"], "NOT_IMPLEMENTED")
        self.assertEqual(rows["NETCONF"]["status"], "READ_ONLY")
        self.assertEqual(rows["GNMI_SET"]["status"], "READ_ONLY")
        self.assertEqual(tc.selected_transport(models.Platform.UBUNTU_FRR), "DOCKER_EXEC")

    def test_platforms_with_no_executor_have_no_available_transport(self):
        for platform in (models.Platform.CISCO_IOSXR, models.Platform.SONIC):
            with self.subTest(platform=platform):
                rows = tc.deployment_transport_matrix(platform)
                self.assertTrue(all(row["status"] != "AVAILABLE" for row in rows))
                self.assertIsNone(tc.selected_transport(platform))

    def test_at_most_one_transport_is_ever_available_per_platform(self):
        for platform in models.Platform.values:
            with self.subTest(platform=platform):
                supported = [row for row in tc.deployment_transport_matrix(platform) if row["status"] == "AVAILABLE"]
                self.assertLessEqual(len(supported), 1)

    def test_iosxe_deploys_over_ssh_cli_and_iosxr_does_not_inherit_it(self):
        self.assertEqual(tc.selected_transport(models.Platform.CISCO_C8000V_IOSXE), "SSH_CLI")
        self.assertIsNone(tc.selected_transport(models.Platform.CISCO_IOSXR))

    def test_srlinux_deploys_over_gnmi_set_only(self):
        rows = {row["transport"]: row for row in tc.deployment_transport_matrix(models.Platform.NOKIA_SRLINUX)}
        self.assertEqual(rows["GNMI_SET"]["status"], "AVAILABLE")
        self.assertEqual(rows["NETCONF"]["status"], "NOT_IMPLEMENTED")
        self.assertEqual({rows["SSH_CLI"]["status"], rows["DOCKER_EXEC"]["status"]}, {"NOT_IMPLEMENTED"})
        self.assertEqual(tc.selected_transport(models.Platform.NOKIA_SRLINUX), "GNMI_SET")

    def test_sonic_protocol_capability_remains_image_unverified(self):
        rows = {row["transport"]: row for row in tc.deployment_transport_matrix(models.Platform.SONIC)}
        self.assertEqual(rows["NETCONF"]["status"], "PLATFORM_CAPABILITY_UNVERIFIED")
        self.assertEqual(rows["GNMI_SET"]["status"], "PLATFORM_CAPABILITY_UNVERIFIED")

    def test_device_capability_is_not_conflated_with_nmas_implementation(self):
        ceos = tc.device_protocol_capabilities(models.Platform.ARISTA_CEOS)
        self.assertTrue(ceos["NETCONF"]["writable"])
        self.assertTrue(ceos["NETCONF"]["candidate"])
        self.assertFalse(ceos["NETCONF"]["confirmed_commit"])
        self.assertFalse(ceos["NETCONF"]["nmas_write_suitable"])
        self.assertEqual(tc.selected_transport(models.Platform.ARISTA_CEOS), "SSH_CLI")

        srl = tc.device_protocol_capabilities(models.Platform.NOKIA_SRLINUX)
        self.assertTrue(srl["NETCONF"]["confirmed_commit"])
        self.assertTrue(srl["GNMI_SET"]["set"])
        self.assertFalse(srl["NETCONF"]["nmas_write_suitable"])
        self.assertTrue(srl["GNMI_SET"]["nmas_write_suitable"])
        self.assertIn("atomic CLI-origin Set", srl["GNMI_SET"]["suitability_reason"])

    def test_ceos_writer_blocker_names_the_telemetry_only_credential_gap(self):
        """Phase 20.5: modules/netconf.py and modules/gnmi.py both authenticate
        as the read-only nmas-telemetry identity -- a genuine, verified reason
        a writer can't safely reuse that session, beyond the pre-existing
        confirmed-commit gap. This guards that finding from silently
        disappearing from the evidence."""
        ceos = tc.device_protocol_capabilities(models.Platform.ARISTA_CEOS)
        self.assertIn("nmas-telemetry", ceos["NETCONF"]["suitability_reason"])
        self.assertIn("nmas-telemetry", ceos["GNMI_SET"]["suitability_reason"])

    def test_all_platforms_have_explicit_device_protocol_evidence(self):
        for platform in models.Platform.values:
            with self.subTest(platform=platform):
                protocols = tc.device_protocol_capabilities(platform)
                self.assertEqual(set(protocols), {"NETCONF", "GNMI_SET"})
                for facts in protocols.values():
                    self.assertTrue(facts["evidence"])
                    self.assertIn("nmas_write_suitable", facts)


class ExecutePageTransportDisclosureTests(TestCase):
    def test_execute_page_shows_the_real_transport_and_never_a_writable_netconf_or_gnmi_option(self):
        p = x.prepared(simple_pass_change())
        response = self.client.get(reverse("core:change_execute", args=[p.change.change_id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Deployment Transport")
        self.assertContains(response, "SSH CLI")
        html = response.content.decode()
        transport_block = html.split("Deployment Transport")[1].split("<h3>Execute</h3>")[0]
        self.assertIn("READ_ONLY", transport_block)
        # NETCONF/gNMI Set are disclosure rows only, never offered as a submittable option.
        self.assertNotIn('value="NETCONF"', transport_block)
        self.assertNotIn('value="GNMI_SET"', transport_block)
        self.assertNotIn("<select", transport_block)
