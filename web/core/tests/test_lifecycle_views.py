"""V2 Lifecycle Phase 2 pages and APIs: rendering, RBAC per step, CSRF, refusal codes, and the management command."""

from __future__ import annotations

from io import StringIO
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import Client, TestCase
from django.urls import reverse

from core import lifecycle_views, models
from core.services.devices import lifecycle
from core.services.identity import policy
from core.tests.helpers import lifecycle as L
from core.tests.runner import sign_in

MUTATIONS = {
    "managed_device_register": policy.Action.EDIT, "managed_device_identity": policy.Action.EDIT,
    "managed_device_withdraw": policy.Action.EDIT, "managed_device_attachment_add": policy.Action.EDIT,
    "managed_device_netbox_import": policy.Action.EDIT, "bootstrap_authorization_request": policy.Action.EDIT,
    "managed_device_adopt": policy.Action.APPROVE, "managed_device_attachment_approve": policy.Action.APPROVE,
    "managed_device_attachment_revoke": policy.Action.APPROVE, "managed_device_verify_identity": policy.Action.APPROVE,
    "bootstrap_authorization_approve": policy.Action.APPROVE, "bootstrap_authorization_revoke": policy.Action.APPROVE,
    "managed_device_netbox_compare": policy.Action.VALIDATE, "bootstrap_authorization_evaluate": policy.Action.VALIDATE,
}


def user_client(username, *roles, csrf=False):
    user = get_user_model().objects.create_user(username=username, password="correct-horse-battery-9")
    for role in roles:
        user.groups.add(Group.objects.get(name=role))
    client = Client(enforce_csrf_checks=csrf)
    sign_in(client, get_user_model().objects.get(pk=user.pk))
    return client


class PolicyClassificationTests(TestCase):
    def test_every_lifecycle_route_carries_the_permission_of_its_step(self):
        for name, action in MUTATIONS.items():
            with self.subTest(name):
                self.assertEqual(policy.MUTATION_ROUTES[name], action)
        for name in ("managed_devices", "managed_device_detail", "managed_devices_json", "managed_device_json"):
            self.assertIn(name, policy.READ_ROUTES)
        self.assertTrue({"managed_devices_json", "managed_device_json"} <= policy.SENSITIVE_READ_ROUTES)

    def test_no_commission_isolation_or_delivery_route_exists(self):
        names = set(policy.MUTATION_ROUTES) | set(policy.READ_ROUTES)
        self.assertFalse({n for n in names if n.startswith(("managed_device", "bootstrap_authorization"))
                          and any(word in n for word in ("commission", "isolat", "deliver", "admit", "bootstrap_run"))})


class PageTests(TestCase):
    def setUp(self):
        self.operator = user_client("olivia", "NMAS Operator")
        self.approver = user_client("arthur", "NMAS Approver")

    def test_list_page_renders_resolution_adoption_and_capabilities(self):
        response = self.operator.get(reverse("core:managed_devices"))
        self.assertContains(response, "Managed devices")
        self.assertContains(response, "OUT_OF_WRITABLE_SCOPE")         # R5
        self.assertContains(response, "lifecycle.ZTP")
        self.assertContains(response, "MANAGEMENT_ADDRESS_AUTO_REFUSED")
        self.assertNotContains(response, "commission/")          # the capability table names it; no control performs it
        self.assertNotContains(response, ">Commission<")
        self.assertNotContains(response, "172.20.20.")

    def test_list_page_shows_only_known_refusal_codes(self):
        response = self.operator.get(reverse("core:managed_devices") + "?codes=NAME_COLLISION,<script>,NOT_A_CODE")
        self.assertContains(response, "NAME_COLLISION")
        self.assertNotContains(response, "<script>")
        self.assertNotContains(response, "NOT_A_CODE")

    def test_register_and_detail_render(self):
        response = self.operator.post(reverse("core:managed_device_register"), {"name": "NEW1", "platform": "arista_ceos", "role": "router",
                                                                                 "expected_serial": L.SERIAL, "expected_base_mac": L.MAC})
        device = models.ManagedDevice.objects.get(name="NEW1")
        self.assertEqual(response.url, device.get_absolute_url())
        self.assertEqual(device.registered_by, "olivia")
        detail = self.operator.get(device.get_absolute_url())
        self.assertContains(detail, device.device_id)
        self.assertContains(detail, "DISCOVER &rarr; DISCOVERED: available")
        self.assertContains(detail, "intact")
        for word in ("Commission", "Isolate", "Deliver bootstrap", "Admit"):
            self.assertNotContains(detail, f">{word}")

    def test_register_refusal_redirects_with_codes_only(self):
        response = self.operator.post(reverse("core:managed_device_register"), {"name": "R1", "platform": "arista_ceos", "role": "router"})
        self.assertIn("codes=NAME_COLLISION", response.url)
        self.assertFalse(models.ManagedDevice.objects.exists())

    def test_unknown_device_and_authorization_are_404(self):
        self.assertEqual(self.operator.get(reverse("core:managed_device_detail", args=["DEV-999999"])).status_code, 404)
        device = L.register().device
        url = reverse("core:bootstrap_authorization_revoke", args=[device.device_id, "BAUTH-999999"])
        self.assertEqual(self.approver.post(url, {"reason": "x"}).status_code, 404)

    def test_mutating_routes_refuse_get(self):
        device = L.register().device
        for name, args in (("managed_device_register", []), ("managed_device_adopt", []), ("managed_device_withdraw", [device.device_id]),
                           ("managed_device_identity", [device.device_id])):
            with self.subTest(name):
                self.assertEqual(self.operator.get(reverse(f"core:{name}", args=args)).status_code, 405)

    def test_json_apis_return_resolution_and_device_state(self):
        device = L.adopt("R1", role="router").device
        listing = self.operator.get(reverse("core:managed_devices_json")).json()
        self.assertIn("R1", {t["name"] for t in listing["targets"]})
        one = self.operator.get(reverse("core:managed_device_json", args=[device.device_id])).json()
        self.assertEqual((one["lifecycle_state"], one["admission_state"], one["event_chain_intact"]), ("IN_SERVICE", "LEGACY_PREEXISTING", True))
        self.assertNotIn("password", str(one).lower())

    def test_managed_device_json_unknown_is_404(self):
        self.assertEqual(self.operator.get(reverse("core:managed_device_json", args=["DEV-0"])).status_code, 404)


class RbacAndCsrfTests(TestCase):
    def test_operator_cannot_adopt_or_approve_and_viewer_cannot_register(self):
        operator = user_client("olivia", "NMAS Operator")
        self.assertEqual(operator.post(reverse("core:managed_device_adopt"), {"name": "R1", "confirm_name": "R1", "role": "router"}).status_code, 403)
        viewer = user_client("vera", "NMAS Viewer")
        self.assertEqual(viewer.post(reverse("core:managed_device_register"), {"name": "NEW1"}).status_code, 403)
        self.assertEqual(viewer.get(reverse("core:managed_devices")).status_code, 200)
        self.assertFalse(models.ManagedDevice.objects.exists())

    def test_approver_adopts_with_confirmation(self):
        approver = user_client("arthur", "NMAS Approver")
        response = approver.post(reverse("core:managed_device_adopt"), {"name": "R1", "confirm_name": "R1", "role": "router"})
        device = models.ManagedDevice.objects.get(name="R1")
        self.assertEqual((response.url, device.registered_by), (device.get_absolute_url(), "arthur"))

    def test_adopt_refuses_missing_confirmation_and_out_of_scope(self):
        approver = user_client("arthur", "NMAS Approver")
        self.assertIn("AUTHORIZATION_CONFIRMATION_MISMATCH",
                      approver.post(reverse("core:managed_device_adopt"), {"name": "R1", "confirm_name": "R2", "role": "router"}).url)
        self.assertIn("OUT_OF_WRITABLE_SCOPE",
                      approver.post(reverse("core:managed_device_adopt"), {"name": "R5", "confirm_name": "R5", "role": "router"}).url)
        self.assertFalse(models.ManagedDevice.objects.exists())

    def test_post_without_csrf_token_is_forbidden(self):
        client = user_client("olivia", "NMAS Operator", csrf=True)
        response = client.post(reverse("core:managed_device_register"), {"name": "NEW1", "platform": "arista_ceos", "role": "router"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(models.ManagedDevice.objects.exists())


class WorkflowViewTests(TestCase):
    """The full Phase 2 workflow through the pages, with separate operator and approver sessions."""

    def setUp(self):
        self.operator = user_client("olivia", "NMAS Operator")
        self.approver = user_client("arthur", "NMAS Approver")
        lifecycle.adopt_existing("S1", role="switch", actor="arthur")
        self.device = lifecycle.register_device(name="NEW1", platform="arista_ceos", role="router", actor="olivia",
                                                expected_serial=L.SERIAL, expected_base_mac=L.MAC).device

    def url(self, name, *args):
        return reverse(f"core:{name}", args=[self.device.device_id, *args])

    def test_attachment_authorization_and_dry_run_workflow_succeeds(self):
        self.operator.post(self.url("managed_device_attachment_add"), {"upstream_device": "S1", "upstream_interface": "Ethernet7",
                                                                       "local_interface": "Ethernet1", "purpose": "PRODUCTION",
                                                                       "connectivity": "ACCESS", "vlan": "30"})
        attachment = self.device.attachments.get()
        self.approver.post(self.url("managed_device_attachment_approve", attachment.pk))
        self.operator.post(self.url("bootstrap_authorization_request"), {"attachment_id": attachment.pk, "scope": ["BOOTSTRAP_FETCH"],
                                                                         "duration_minutes": "60", "max_uses": "1", "reason": "first boot"})
        auth = self.device.bootstrap_authorizations.get()
        self.approver.post(self.url("bootstrap_authorization_approve", auth.auth_id), {"confirm_digest": auth.binding_digest})
        auth.refresh_from_db()
        self.assertEqual((attachment.__class__.objects.get(pk=attachment.pk).approval_state, auth.state), ("APPROVED", "APPROVED"))
        response = self.operator.post(self.url("bootstrap_authorization_evaluate", auth.auth_id), {
            "scope": "BOOTSTRAP_FETCH", "serial": L.SERIAL, "upstream_device": "S1", "upstream_interface": "Ethernet7",
            "attachment_source": "DHCP_RELAY_ATTACHMENT", "password": "ignored"})
        self.assertIn("decision=AUTHORIZED", response.url)
        self.assertContains(self.operator.get(response.url), "production admission: NO")
        auth.refresh_from_db()
        self.assertEqual(auth.use_count, 0)
        self.approver.post(self.url("bootstrap_authorization_revoke", auth.auth_id), {"reason": "rescheduled"})
        auth.refresh_from_db()
        self.assertEqual(auth.state, "REVOKED")
        self.approver.post(self.url("managed_device_attachment_revoke", attachment.pk), {"reason": "moved"})
        self.assertEqual(self.device.attachments.get().approval_state, "REVOKED")

    def test_every_workflow_view_refused_input_redirects_with_codes(self):
        bad = "BAUTH-999999"
        self.assertIn("codes=", self.operator.post(self.url("managed_device_identity"), {"expected_serial": "bad serial!", "expected_version": "1"}).url)
        self.assertIn("codes=", self.operator.post(self.url("managed_device_withdraw"), {"confirm_name": "NEW1", "reason": ""}).url)
        self.assertIn("codes=", self.approver.post(self.url("managed_device_verify_identity"), {"observation_id": "x"}).url)
        self.assertIn("codes=", self.operator.post(self.url("managed_device_attachment_add"), {"upstream_device": "NOPE9"}).url)
        self.assertIn("ATTACHMENT_NOT_FOUND", self.approver.post(self.url("managed_device_attachment_approve", 9999)).url)
        self.assertIn("ATTACHMENT_NOT_FOUND", self.approver.post(self.url("managed_device_attachment_revoke", 9999), {"reason": "x"}).url)
        self.assertIn("codes=", self.operator.post(self.url("bootstrap_authorization_request"), {"reason": ""}).url)
        L.attach(self.device)
        attachment = self.device.attachments.get()
        auth = L.request_auth(self.device, attachment).authorization
        self.assertIn("AUTHORIZATION_CONFIRMATION_MISMATCH",
                      self.approver.post(self.url("bootstrap_authorization_approve", auth.auth_id), {"confirm_digest": "wrong"}).url)
        self.assertIn("decision=PENDING_APPROVAL", self.operator.post(self.url("bootstrap_authorization_evaluate", auth.auth_id),
                                                                       {"scope": "BOOTSTRAP_FETCH"}).url)
        self.assertEqual(self.approver.post(self.url("bootstrap_authorization_approve", bad), {"confirm_digest": "x"}).status_code, 404)

    def test_workflow_refused_requests_redirect_with_codes(self):
        response = self.operator.post(self.url("managed_device_attachment_add"), {"upstream_device": "R5", "upstream_interface": "Ethernet1",
                                                                                  "purpose": "PRODUCTION", "connectivity": "ROUTED"})
        self.assertIn("UPSTREAM_NOT_TRUSTED", response.url)
        response = self.operator.post(self.url("bootstrap_authorization_request"), {"attachment_id": "", "scope": ["X"], "duration_minutes": "x",
                                                                                    "max_uses": "1", "reason": "r"})
        self.assertIn("AUTHORIZATION_WINDOW_INVALID", response.url)
        self.assertIn("codes=", self.approver.post(self.url("managed_device_verify_identity"), {"observation_id": "1"}).url)

    def test_authorization_request_view_rejects_malformed_window(self):
        attachment = L.attach(self.device).attachment
        for data in ({"duration_minutes": "9" * 30}, {"valid_from": "2026-13-45T00:00:00", "duration_minutes": "60"},
                     {"valid_from": "9999-12-31T23:59:00", "duration_minutes": "100000"}):
            response = self.operator.post(self.url("bootstrap_authorization_request"), {
                "attachment_id": attachment.pk, "scope": ["BOOTSTRAP_FETCH"], "max_uses": "1", "reason": "first boot", **data})
            self.assertEqual(response.status_code, 302, data)
            self.assertIn("AUTHORIZATION_WINDOW_INVALID", response.url)
        self.assertFalse(self.device.bootstrap_authorizations.exists())

    def test_identity_edit_and_withdraw_need_current_version_and_confirmation(self):
        response = self.operator.post(self.url("managed_device_identity"), {"expected_serial": "SN-B", "expected_version": "999"})
        self.assertIn("CONCURRENT_MODIFICATION", response.url)
        response = self.operator.post(self.url("managed_device_identity"), {"expected_serial": "SN-B", "expected_version": "x"})
        self.assertIn("CONCURRENT_MODIFICATION", response.url)
        self.device.refresh_from_db()
        response = self.operator.post(self.url("managed_device_identity"), {"expected_serial": "SN-B", "expected_version": self.device.version})
        self.assertNotIn("codes=", response.url)
        self.assertIn("AUTHORIZATION_CONFIRMATION_MISMATCH",
                      self.operator.post(self.url("managed_device_withdraw"), {"confirm_name": "nope", "reason": "x"}).url)
        self.device.refresh_from_db()
        self.operator.post(self.url("managed_device_withdraw"), {"confirm_name": "NEW1", "reason": "cancelled", "expected_version": self.device.version})
        self.device.refresh_from_db()
        self.assertEqual(self.device.lifecycle_state, "WITHDRAWN")

    def test_verify_identity_view_promotes_observed_identity(self):
        seen = lifecycle.record_observation(self.device, kind="IDENTITY", source="AUTHENTICATED_SESSION", actor="collector",
                                            claims={"serial": L.SERIAL, "base_mac": L.MAC, "host_key": L.HOST_KEY})
        self.device.refresh_from_db()
        response = self.approver.post(self.url("managed_device_verify_identity"), {"observation_id": seen.observation.pk,
                                                                                    "expected_version": self.device.version})
        self.assertNotIn("codes=", response.url)
        self.device.refresh_from_db()
        self.assertEqual(self.device.identity_state, "VERIFIED")

    def test_netbox_compare_and_import_views_read_only(self):
        reader = mock.Mock()
        reader.device.return_value = {"id": 3, "name": "NEW1", "status": "planned", "serial": ""}
        reader.cables.return_value = []
        with mock.patch.object(lifecycle_views.device_netbox, "NetboxDeviceReader", return_value=reader):
            self.assertNotIn("IPAM_UNAVAILABLE", self.operator.post(self.url("managed_device_netbox_compare")).url)
            self.assertEqual(self.approver.post(self.url("managed_device_netbox_compare")).status_code, 403)   # VALIDATE, not APPROVE
            self.operator.post(self.url("managed_device_netbox_import"))
        self.assertEqual(self.device.lifecycle_events.order_by("-sequence").first().action, "NETBOX_COMPARE")
        self.assertFalse([c for c in reader.mock_calls if "create" in str(c) or "update" in str(c) or "delete" in str(c)])

    def test_netbox_views_report_unavailable(self):
        from core.services.provisioning.ipam import IpamUnavailable

        reader = mock.Mock()
        reader.device.side_effect = IpamUnavailable()
        reader.cables.side_effect = IpamUnavailable()
        with mock.patch.object(lifecycle_views.device_netbox, "NetboxDeviceReader", return_value=reader):
            self.assertIn("IPAM_UNAVAILABLE", self.operator.post(self.url("managed_device_netbox_compare")).url)
            self.assertIn("IPAM_UNAVAILABLE", self.operator.post(self.url("managed_device_netbox_import")).url)


class ManagementCommandTests(TestCase):
    def run_command(self, *args):
        out = StringIO()
        call_command("nmas_devices", *args, stdout=out)
        return out.getvalue()

    def test_list_resolve_and_expire_return_output(self):
        self.assertIn("R5", self.run_command("list"))
        self.assertIn('"scope": "WRITABLE"', self.run_command("resolve", "--name", "R1"))
        self.assertIn("expired 0", self.run_command("expire-authorizations"))

    def test_adopt_accepts_approver_actor(self):
        user = get_user_model().objects.create_user(username="arthur")
        user.groups.add(Group.objects.get(name="NMAS Approver"))
        self.assertIn("adopted", self.run_command("adopt", "--name", "R2", "--role", "router", "--actor", "arthur", "--confirm", "R2"))
        self.assertIn("already adopted", self.run_command("adopt", "--name", "R2", "--role", "router", "--actor", "arthur", "--confirm", "R2"))

    def test_adopt_refuses_unknown_actor_bad_confirmation_unknown_name_and_r5(self):
        get_user_model().objects.create_user(username="olivia").groups.add(Group.objects.get(name="NMAS Operator"))
        approver = get_user_model().objects.create_user(username="arthur")
        approver.groups.add(Group.objects.get(name="NMAS Approver"))
        for args in (("--actor", "olivia", "--confirm", "R2", "--name", "R2"), ("--actor", "ghost", "--confirm", "R2", "--name", "R2"),
                     ("--actor", "arthur", "--confirm", "R3", "--name", "R2"), ("--actor", "arthur", "--confirm", "R5", "--name", "R5")):
            with self.subTest(args=args), self.assertRaises(CommandError):
                self.run_command("adopt", "--role", "router", *args)
        with self.assertRaises(CommandError):
            self.run_command("resolve", "--name", "H1")
        self.assertFalse(models.ManagedDevice.objects.exists())
