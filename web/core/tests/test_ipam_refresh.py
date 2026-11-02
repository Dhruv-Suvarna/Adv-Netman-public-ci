"""AUTO-address prefix refresh: an explicit, read-only NetBox lookup and nothing else.

POST-only / CSRF for the endpoint are in ``test_view_boundaries``; "the IPAM
service never writes NetBox" is in ``test_contracts``.
"""

from __future__ import annotations

from unittest import mock

from django.test import TestCase
from django.urls import reverse

from core.services import device_builder_ipam_service, interface_intent_service
from core.tests.helpers.candidates import add_interface, commit, make_candidate

LIST_PREFIXES = "core.services.device_builder_ipam_service.netbox_ipam.list_all_prefix_cidrs"


class ExplicitIpamReadTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change, cls.intent, cls.revision = make_candidate()
        cls.interface = add_interface(cls.revision)
        cls.address = interface_intent_service.add_address(
            revision=cls.revision, interface_id=cls.interface["id"], family="IPV4", source="AUTO"
        )
        cls.url = reverse(
            "core:device_builder_ipam_prefixes",
            args=[cls.change.change_id, cls.intent.pk, cls.interface["id"], cls.address["id"]],
        )

    @mock.patch(LIST_PREFIXES)
    def test_explicit_refresh_reads_and_sorts_only_matching_prefixes(self, list_prefixes):
        list_prefixes.return_value = {"2001:db8::/64", "198.51.100.0/24", "192.0.2.0/24"}
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["prefixes"], ["192.0.2.0/24", "198.51.100.0/24"])
        self.assertEqual(response.json()["allocationState"], "UNRESOLVED_UNRESERVED")
        list_prefixes.assert_called_once_with()

    @mock.patch(LIST_PREFIXES)
    def test_ordinary_rendering_and_committing_never_read_netbox(self, list_prefixes):
        editor = reverse("core:device_builder_advanced", args=[self.change.change_id, self.intent.pk])
        self.assertEqual(self.client.get(editor).status_code, 200)
        self.client.post(
            reverse("core:device_builder_field_commit", args=[self.change.change_id, self.intent.pk]),
            data='{"path":"device.hostname","value":"R1-new","revisionId":%d}' % self.revision.pk,
            content_type="application/json",
        )
        list_prefixes.assert_not_called()

    def test_a_manual_address_cannot_refresh_prefixes(self):
        manual = interface_intent_service.add_address(revision=self.revision, interface_id=self.interface["id"], source="MANUAL")
        url = reverse("core:device_builder_ipam_prefixes",
                      args=[self.change.change_id, self.intent.pk, self.interface["id"], manual["id"]])
        self.assertEqual(self.client.post(url).status_code, 400)

    @mock.patch(LIST_PREFIXES)
    def test_netbox_failures_and_malformed_data_are_sanitized(self, list_prefixes):
        cases = {
            "connection error": (
                {"side_effect": device_builder_ipam_service.netbox_ipam.NetboxConnectionError("secret endpoint detail")},
                "secret endpoint detail"),
            "malformed prefix": ({"return_value": {"not-a-prefix"}}, "not-a-prefix"),
        }
        for label, (behavior, leaked) in cases.items():
            with self.subTest(case=label):
                list_prefixes.reset_mock(side_effect=True, return_value=True)
                list_prefixes.configure_mock(**behavior)
                response = self.client.post(self.url)
                self.assertEqual(response.status_code, 503)
                self.assertNotContains(response, leaked, status_code=503)
                if label == "connection error":
                    self.assertContains(response, "currently unavailable", status_code=503)

    def test_auto_language_never_claims_dhcp_or_reservation(self):
        body = self.client.get(
            reverse("core:device_builder_advanced", args=[self.change.change_id, self.intent.pk])
        ).content.decode().lower()
        self.assertIn("unresolved", body)
        self.assertIn("no reservation exists", body)
        self.assertNotIn("dhcp client", body)


class Vlan200AutoTests(TestCase):
    def test_vlan200_can_never_be_auto_and_no_reservation_route_exists(self):
        _, _, revision = make_candidate()
        management = add_interface(revision, kind="MANAGEMENT", name="Vlan200")
        with self.assertRaises(interface_intent_service.CollectionMutationError):
            interface_intent_service.add_address(revision=revision, interface_id=management["id"], source="AUTO")

        change, intent, revision = make_candidate()
        svi = add_interface(revision, kind="SVI", name="Vlan200")
        address = interface_intent_service.add_address(revision=revision, interface_id=svi["id"], source="MANUAL")
        state = commit(change, intent, revision, f"interfaces.{svi['id']}.addresses.{address['id']}.source", "AUTO")
        self.assertEqual(state.accepted_value, "MANUAL")

        from core import urls

        route_text = "\n".join(str(pattern.pattern) for pattern in urls.urlpatterns).lower()
        self.assertNotIn("reserve", route_text)
        self.assertNotIn("dhcp", route_text)
