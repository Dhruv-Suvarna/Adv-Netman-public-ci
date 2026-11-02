"""V2 Phase 3: native-ZTP pages and actions -- RBAC per step, CSRF, refusal codes, evidence display and the absence of any
production-admission control.  No device or DHCP service is contacted (device contact is patched where a view would)."""

from __future__ import annotations

from unittest import mock

from django.test import TestCase
from django.urls import reverse

from core import models
from core.services.identity import policy
from core.services.ztp import dhcp, workflow
from core.tests.helpers import lifecycle as L
from core.tests.helpers import ztp as Z
from core.tests.test_lifecycle_views import user_client

MUTATIONS = {
    "ztp_session_open": policy.Action.EDIT, "ztp_network_create": policy.Action.APPROVE, "ztp_session_cancel": policy.Action.APPROVE,
    "ztp_session_enroll": policy.Action.APPROVE, "ztp_session_fail_device": policy.Action.APPROVE,
    "ztp_network_validate": policy.Action.VALIDATE, "ztp_network_ingest": policy.Action.VALIDATE, "ztp_session_contact": policy.Action.VALIDATE,
    "ztp_network_apply": policy.Action.EXECUTE, "ztp_network_rollback": policy.Action.EXECUTE, "ztp_session_verify": policy.Action.EXECUTE,
}


class PolicyTests(TestCase):
    def test_every_ztp_route_carries_the_permission_of_its_step(self):
        for name, action in MUTATIONS.items():
            with self.subTest(name):
                self.assertEqual(policy.MUTATION_ROUTES[name], action)
        self.assertTrue({"ztp_networks", "ztp_adapters_json", "ztp_session_json"} <= policy.READ_ROUTES)
        self.assertIn("ztp_session_json", policy.SENSITIVE_READ_ROUTES)

    def test_no_admission_or_commission_route_exists(self):
        names = set(policy.MUTATION_ROUTES) | set(policy.READ_ROUTES)
        self.assertFalse({n for n in names if n.startswith("ztp_") and any(w in n for w in ("admit", "commission", "in_service", "production"))})


class ViewTests(Z.ZtpTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.operator = user_client("olivia", "NMAS Operator")
        self.approver = user_client("arthur", "NMAS Approver")
        self.executor = user_client("erin", "NMAS Executor")
        self.viewer = user_client("vera", "NMAS Viewer")

    def session_url(self, name, session):
        return reverse(f"core:{name}", args=[session.device.device_id, session.session_id])

    def test_networks_page_and_adapter_report_are_read_only_views(self):
        L.adopt()
        self.network()
        response = self.viewer.get(reverse("core:ztp_networks"))
        self.assertContains(response, "ztp-test")
        self.assertContains(response, "SUPPORTED_AND_LIVE_VERIFIED")
        self.assertContains(response, "NOT_TESTED_NO_IMAGE")
        self.assertNotContains(response, "192.168.200.")
        adapters_json = self.viewer.get(reverse("core:ztp_adapters_json")).json()
        self.assertEqual({a["adapter"] for a in adapters_json["adapters"]} >= {"arista_eos", "cisco_iosxe"}, True)

    def test_network_create_needs_approve_and_reports_refusals(self):
        L.adopt()
        data = {**Z.NET, "trusted_relays": f"{Z.RELAY}=S1", "config_root": str(self.root / "dhcp"), "provider": "ISC_DHCP"}
        self.assertEqual(self.operator.post(reverse("core:ztp_network_create"), data).status_code, 403)
        response = self.approver.post(reverse("core:ztp_network_create"), {**data, "vlan": "200"})
        self.assertIn("codes=", response.url)
        self.assertIn("VLAN200_PURPOSE_FORBIDDEN", response.url)
        self.assertFalse(models.BootstrapNetwork.objects.exists())
        response = self.approver.post(reverse("core:ztp_network_create"), data)
        self.assertNotIn("codes=", response.url)
        self.assertTrue(models.BootstrapNetwork.objects.filter(name="ztp-test").exists())

    def test_device_page_shows_capability_dependencies_and_opens_a_session(self):
        device, _attachment, auth = L.ready_device()
        self.network()
        page = self.operator.get(device.get_absolute_url())
        self.assertContains(page, "Native zero-touch provisioning")
        self.assertContains(page, "arista_eos")
        self.assertContains(page, "upstream_ready")
        self.assertNotContains(page, "Admit to production")
        self.assertEqual(self.viewer.post(reverse("core:ztp_session_open", args=[device.device_id]),
                                          {"auth_id": auth.auth_id, "network": "ztp-test"}).status_code, 403)
        response = self.operator.post(reverse("core:ztp_session_open", args=[device.device_id]), {"auth_id": auth.auth_id, "network": "ztp-test"})
        self.assertNotIn("codes=", response.url)
        session = models.ZtpSession.objects.get()
        page = self.operator.get(device.get_absolute_url())
        self.assertContains(page, session.session_id)
        self.assertContains(page, "AWAITING_DISCOVERY")
        self.assertContains(page, "not available in bootstrap")
        self.assertNotContains(page, "PRIVATE KEY")
        response = self.operator.post(reverse("core:ztp_session_open", args=[device.device_id]), {"auth_id": auth.auth_id, "network": "ztp-test"})
        self.assertIn("ZTP_SESSION_OPEN_EXISTS", response.url)

    def test_dhcp_steps_have_their_own_permissions(self):
        session = self.open_session()
        name = session.network.name
        real = dhcp.for_network
        with mock.patch("core.services.ztp.dhcp.for_network", lambda network, runner=None: real(network, runner=Z.FakeRunner())):
            self.assertEqual(self.approver.post(reverse("core:ztp_network_validate", args=[name])).status_code, 403)
            self.assertEqual(self.operator.post(reverse("core:ztp_network_apply", args=[name])).status_code, 403)
            self.assertEqual(self.operator.post(reverse("core:ztp_network_validate", args=[name])).status_code, 302)
        self.assertEqual(session.network.applications.get().state, "VALIDATED")

    def test_session_actions_have_their_own_permissions(self):
        session = self.open_session()
        for client, name in ((self.operator, "ztp_session_enroll"), (self.operator, "ztp_session_verify"), (self.approver, "ztp_session_contact"),
                             (self.viewer, "ztp_session_cancel"), (self.executor, "ztp_session_cancel")):
            with self.subTest(name):
                self.assertEqual(client.post(self.session_url(name, session), {"fingerprint": L.HOST_KEY, "basis": "x", "reason": "x"}).status_code, 403)

    def test_session_flow_through_the_pages(self):
        from core.tests.test_ztp_workflow import served
        session = served(self.discovered())
        with mock.patch.dict(workflow.contact_management.__kwdefaults__, {"observe": lambda address: L.HOST_KEY}):
            response = self.operator.post(self.session_url("ztp_session_contact", session))
        self.assertNotIn("codes=", response.url)
        response = self.approver.post(self.session_url("ztp_session_enroll", session), {"fingerprint": L.HOST_KEY, "basis": "console"})
        self.assertNotIn("codes=", response.url)
        session.refresh_from_db()
        run = Z.fake_run(Z.eos_outputs(session))
        with mock.patch.dict(workflow.verify_management.__kwdefaults__, {"run": run}):
            response = self.executor.post(self.session_url("ztp_session_verify", session))
        self.assertNotIn("codes=", response.url)
        device = models.ManagedDevice.objects.get(pk=session.device_id)
        self.assertEqual((device.lifecycle_state, device.admission_state), ("BOOTSTRAPPED", "NOT_ADMITTED"))
        evidence = self.viewer.get(self.session_url("ztp_session_json", session)).json()
        self.assertEqual((evidence["stage"], evidence["production_admission"]["allowed"]), ("BOOTSTRAPPED", False))
        self.assertTrue(evidence["verification"]["ok"])

    def test_session_of_another_device_is_404(self):
        session = self.open_session()
        other = L.register("NEW2", serial="SN-NEW2", mac="00:1c:73:00:00:02").device
        url = reverse("core:ztp_session_json", args=[other.device_id, session.session_id])
        self.assertEqual(self.viewer.get(url).status_code, 404)
        self.assertEqual(self.viewer.get(reverse("core:ztp_session_json", args=[other.device_id, "ZTP-x"])).status_code, 404)

    def test_csrf_is_enforced(self):
        session = self.open_session()
        client = user_client("abe", "NMAS Approver", csrf=True)
        self.assertEqual(client.post(self.session_url("ztp_session_cancel", session), {"reason": "x"}).status_code, 403)
        session.refresh_from_db()
        self.assertTrue(session.is_open)

    def test_fail_device_requires_typed_confirmation(self):
        session = self.open_session()
        response = self.approver.post(self.session_url("ztp_session_fail_device", session), {"confirm_name": "wrong"})
        self.assertIn("AUTHORIZATION_CONFIRMATION_MISMATCH", response.url)

    def test_anonymous_is_redirected(self):
        from django.test import Client
        self.assertEqual(Client().get(reverse("core:ztp_networks")).status_code, 302)
