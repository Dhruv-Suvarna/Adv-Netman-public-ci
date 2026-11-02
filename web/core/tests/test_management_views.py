"""V2 Phase 4 pages and actions -- RBAC per step, CSRF, refusal codes, the SPOF statement and the absence of any secret.
No device is contacted: the probe transport and credential loading are replaced by in-memory fakes."""

from __future__ import annotations

from unittest import mock

from django.test import TestCase, override_settings
from django.urls import reverse

from core import models
from core.services.identity import policy
from core.services.management import probes, vrf
from core.tests.helpers import management as M
from core.tests.helpers.validation import Dev, new_change
from core.tests.test_lifecycle_views import user_client

A = policy.Action
MUTATIONS = {
    "management_attachment_register": A.EDIT, "management_path_register": A.EDIT, "bcred_plan": A.EDIT,
    "device_builder_management_add": A.EDIT, "device_builder_management_remove": A.EDIT,
    "management_attachment_approve": A.APPROVE, "management_attachment_revoke": A.APPROVE, "management_path_approve": A.APPROVE,
    "management_path_revoke": A.APPROVE, "management_reconcile": A.APPROVE, "bcred_approve": A.APPROVE, "bcred_cancel": A.APPROVE,
    "management_attachment_observe": A.VALIDATE, "management_path_probe": A.VALIDATE, "management_evaluate": A.VALIDATE,
    "bcred_execute": A.EXECUTE,
}
READS = {"management_overview", "management_spof_json", "management_device", "management_device_json"}


class PolicyTests(TestCase):
    def test_every_management_route_carries_the_permission_of_its_step(self):
        for name, action in MUTATIONS.items():
            with self.subTest(name):
                self.assertEqual(policy.MUTATION_ROUTES[name], action)
        self.assertTrue(READS <= policy.READ_ROUTES)
        self.assertTrue({"management_spof_json", "management_device_json"} <= policy.SENSITIVE_READ_ROUTES)

    def test_no_route_changes_the_nmas_host(self):
        names = set(policy.MUTATION_ROUTES) | set(policy.READ_ROUTES)
        forbidden = ("route_add", "iptables", "nftables", "netns", "nic_", "host_config", "docker")
        self.assertFalse({n for n in names if n.startswith(("management_", "bcred_")) and any(w in n for w in forbidden)})


@override_settings(NMAS_MGMT_MIN_PROBE_INTERVAL_SECONDS=0)
class ViewTests(TestCase):
    def setUp(self):
        self.operator = user_client("olivia", "NMAS Operator")
        self.approver = user_client("arthur", "NMAS Approver")
        self.executor = user_client("erin", "NMAS Executor")
        self.viewer = user_client("vera", "NMAS Viewer")
        self.lab = M.lab()
        self.r1 = self.lab["devices"]["R1"]

    def test_overview_read_only_and_never_claims_redundancy(self):
        response = self.viewer.get(reverse("core:management_overview"))
        self.assertContains(response, "NOT fully redundant")
        self.assertContains(response, "Telemetry does not follow management failover")
        self.assertContains(response, self.lab["nmas"].attachment_id)
        self.assertNotContains(response, "PRIVATE KEY")
        spof = self.viewer.get(reverse("core:management_spof_json")).json()
        self.assertFalse(spof["management_switch_failure_tolerant"])
        self.assertEqual([b["code"] for b in spof["blockers"]], ["NMAS_SINGLE_ATTACHMENT"])

    def test_attachment_register_needs_edit_and_approve_needs_another_operator(self):
        data = {"name": "nmas-second", "host_interface": "nmas-mgmt2", "source_address": "10.77.0.10", "network": "10.77.0.0/24",
                "upstream_device": "S1", "failure_domain": "rack-b"}
        self.assertEqual(self.viewer.post(reverse("core:management_attachment_register"), data).status_code, 403)
        response = self.operator.post(reverse("core:management_attachment_register"), data)
        self.assertNotIn("codes=", response.url)
        row = models.NmasManagementAttachment.objects.get(name="nmas-second")
        url = reverse("core:management_attachment_approve", args=[row.attachment_id])
        self.assertEqual(self.operator.post(url).status_code, 403)
        self.assertNotIn("codes=", self.approver.post(url).url)
        row.refresh_from_db()
        self.assertEqual(row.approval_state, models.ManagementApproval.APPROVED)

    def test_attachment_register_refuses_forbidden_address(self):
        data = {"name": "bad", "host_interface": "eth9", "source_address": "172.20.20.1", "network": "172.20.20.0/24", "upstream_device": "S1"}
        response = self.operator.post(reverse("core:management_attachment_register"), data)
        self.assertIn("codes=", response.url)
        self.assertFalse(models.NmasManagementAttachment.objects.filter(name="bad").exists())

    def test_device_page_register_approve_probe_and_evaluate(self):
        page = self.viewer.get(reverse("core:management_device", args=[self.r1.device_id]))
        self.assertContains(page, "No management path is registered")
        data = {"path_type": models.ManagementPathType.DIRECT_OOB, "endpoint_address": "192.168.200.1",
                "nmas_attachment_id": self.lab["nmas"].pk, "attachment_id": self.lab["oob"].pk,
                "credential_source": models.ManagementCredentialSource.INVENTORY, "credential_reference": "R1",
                "expected_host_key": M.HOST_KEY}
        self.assertEqual(self.viewer.post(reverse("core:management_path_register", args=[self.r1.device_id]), data).status_code, 403)
        response = self.operator.post(reverse("core:management_path_register", args=[self.r1.device_id]), data)
        self.assertNotIn("codes=", response.url, response.url)
        path = models.ManagementPath.objects.get(device=self.r1)
        self.assertEqual(self.approver.post(reverse("core:management_path_approve", args=[self.r1.device_id, path.path_id])).status_code, 302)
        probe_url = reverse("core:management_path_probe", args=[self.r1.device_id, path.path_id])
        self.assertEqual(self.approver.post(probe_url).status_code, 403)
        with M.fake_credentials(), mock.patch.object(probes, "ParamikoTransport", lambda: M.FakeTransport()):
            self.assertNotIn("codes=", self.operator.post(probe_url).url)
            self.assertNotIn("codes=", self.operator.post(reverse("core:management_evaluate", args=[self.r1.device_id])).url)
        path.refresh_from_db()
        self.assertTrue(path.is_active)
        page = self.viewer.get(reverse("core:management_device", args=[self.r1.device_id]))
        self.assertContains(page, path.path_id)
        self.assertContains(page, "active")
        self.assertNotContains(page, "PRIVATE KEY")
        status = self.viewer.get(reverse("core:management_device_json", args=[self.r1.device_id])).json()
        self.assertEqual((status["active_path"], status["endpoint"]["source"]), (path.path_id, "PATH"))

    def test_probe_failure_reports_layer_code(self):
        path = M.path(self.r1, self.lab["nmas"], attachment=self.lab["oob"])
        with M.fake_credentials(), mock.patch.object(probes, "ParamikoTransport", lambda: M.FakeTransport(host_key=M.OTHER_HOST_KEY)):
            response = self.operator.post(reverse("core:management_path_probe", args=[self.r1.device_id, path.path_id]))
        self.assertIn("L5_HOST_KEY_MISMATCH", response.url)

    def test_revoke_active_path_requires_acknowledgement(self):
        path = M.path(self.r1, self.lab["nmas"], attachment=self.lab["oob"])
        with M.fake_credentials(), mock.patch.object(probes, "ParamikoTransport", lambda: M.FakeTransport()):
            self.operator.post(reverse("core:management_evaluate", args=[self.r1.device_id]))
        url = reverse("core:management_path_revoke", args=[self.r1.device_id, path.path_id])
        self.assertIn("MGMT_PATH_ACTIVE", self.approver.post(url, {"reason": "rewire"}).url)
        self.assertNotIn("codes=", self.approver.post(url, {"reason": "rewire", "acknowledge_active": "yes"}).url)
        path.refresh_from_db()
        self.assertEqual(path.approval_state, models.ManagementApproval.REVOKED)

    def test_bcred_plan_without_bootstrap_session_refused(self):
        response = self.operator.post(reverse("core:bcred_plan", args=[self.r1.device_id]), {"replacement_credential_id": "1"})
        self.assertIn("BCRED_NO_BOOTSTRAP", response.url)
        self.assertEqual(self.viewer.post(reverse("core:bcred_plan", args=[self.r1.device_id]), {}).status_code, 403)

    def test_csrf_enforced_on_mutation(self):
        strict = user_client("carl", "NMAS Operator", csrf=True)
        response = strict.post(reverse("core:management_evaluate", args=[self.r1.device_id]))
        self.assertEqual(response.status_code, 403)


class DeviceBuilderManagementTests(TestCase):
    def setUp(self):
        self.operator = user_client("olivia", "NMAS Operator")
        self.viewer = user_client("vera", "NMAS Viewer")
        self.dev = Dev(new_change(), "R1")
        self.port = self.dev.iface("Ethernet5")
        self.dev.address(self.port, "10.99.0.1/30")

    def url(self, name, *extra):
        return reverse(f"core:{name}", args=[self.dev.change.change_id, self.dev.intent.pk, *extra])

    def test_management_add_remove_through_editor(self):
        self.assertEqual(self.viewer.post(self.url("device_builder_management_add", "vrf"), {"name": "MGMT"}).status_code, 403)
        self.assertEqual(self.operator.post(self.url("device_builder_management_add", "vrf"), {"name": "MGMT"}).status_code, 302)
        management = vrf.section(self.dev.refresh())
        vrf_id = next(iter(management["vrfs"]))
        self.operator.post(self.url("device_builder_management_add", "binding"), {"vrf_id": vrf_id, "interface_id": self.port["id"]})
        self.operator.post(self.url("device_builder_management_add", "service"), {"vrf_id": vrf_id, "service": "SSH"})
        management = vrf.section(self.dev.refresh())
        self.assertEqual((len(management["bindings"]), len(management["services"])), (1, 1))
        page = self.operator.get(reverse("core:device_builder_edit", args=[self.dev.change.change_id, self.dev.intent.pk]))
        self.assertContains(page, "Management VRF")
        self.assertContains(page, "vrf instance MGMT")
        service_id = next(iter(management["services"]))
        self.operator.post(self.url("device_builder_management_remove", "service", service_id))
        self.assertEqual(vrf.section(self.dev.refresh())["services"], {})

    def test_management_add_invalid_returns_error_not_saved(self):
        response = self.operator.post(self.url("device_builder_management_add", "vrf"), {"name": "default"})
        self.assertEqual(response.status_code, 302)
        self.assertIn("MGMT_VRF_INVALID", response.url)
        self.assertNotIn("management", self.dev.refresh().sections)

    def test_management_unknown_kind_not_found(self):
        self.assertEqual(self.operator.post(self.url("device_builder_management_add", "telnet"), {}).status_code, 404)
