"""V2 Phase 3 -- the template library pages: listing / filtering, version detail (provenance, intent, capabilities), export,
import, Use Template, publication authorization and authenticated audit attribution.  No device, NetBox or network access."""
from __future__ import annotations

from unittest import mock

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase
from django.urls import reverse

from core import models
from core.services.config_templates import baselines, service
from core.services.config_workbench import snapshots
from core.services.identity.policy import Action
from core.tests.runner import TEST_OPERATOR_USERNAME, make_test_operator, sign_in
from core.tests.test_config_templates import SECRET, Recorder
from core.tests.helpers.workbench import use_scope


class TemplateViewCase(TestCase):
    def setUp(self):
        use_scope(self)
        self.factory = Recorder()
        patcher = mock.patch.object(snapshots, "SESSION_FACTORY", self.factory)
        patcher.start()
        self.addCleanup(patcher.stop)

    def published(self, device="R1"):
        return service.publish(service.extract_from_device(device, actor="seed", session_factory=self.factory), actor="seed")


class LibraryPageTests(TemplateViewCase):
    def setUp(self):
        super().setUp()
        baselines.generate(actor="seed", live=True, session_factory=self.factory)

    def test_library_lists_the_six_baselines_marked_immutable(self):
        response = self.client.get(reverse("core:template_library"))
        self.assertEqual(response.status_code, 200)
        for name in ("Access Layer Switch", "Default Gateway Router", "Multilayer Switch", "Spine Device", "Internet Uplink Device", "End Device"):
            self.assertContains(response, name)
        self.assertContains(response, "Baseline · immutable", count=6)
        self.assertContains(response, "Not deployable")
        self.assertContains(response, "Create template from running config")
        self.assertContains(response, "Import template package")
        self.assertNotContains(response, 'value="R5"')                       # only managed devices can be extracted
        self.assertNotContains(response, 'value="H1"')

    def test_filters_by_family_platform_origin_and_name(self):
        url = reverse("core:template_library")
        self.assertEqual([r["template"].family for r in self.client.get(url, {"family": "SPINE"}).context["rows"]], ["SPINE"])
        frr = {r["template"].family for r in self.client.get(url, {"platform": "ubuntu_frr"}).context["rows"]}
        self.assertIn("INTERNET_UPLINK", frr)
        self.assertNotIn("END_DEVICE", frr)
        self.assertNotIn("ACCESS_SWITCH", frr)                               # trunk / access switching is not renderable on Ubuntu/FRR
        self.assertEqual(len(self.client.get(url, {"origin": "IMPORTED"}).context["rows"]), 0)
        self.assertEqual([r["template"].name for r in self.client.get(url, {"q": "uplink"}).context["rows"]], ["Internet Uplink Device"])
        self.assertEqual(len(self.client.get(url, {"family": "'; DROP"}).context["rows"]), 6)   # an unknown filter value is ignored

    def test_version_page_shows_provenance_intent_capabilities_and_no_edit_control(self):
        version = service.get_template("TPL-BASELINE-GATEWAY-ROUTER").latest_published()
        response = self.client.get(reverse("core:template_version_detail", args=[version.template.template_id, version.version]))
        self.assertEqual(response.status_code, 200)
        for needle in ("Published · immutable", "This version cannot be edited", version.digest, "R1", "R2", "Running-config digest",
                       "{{ mgmt_ipv4 }}", "routing.OSPFV2", "ceos/routing_ospfv2.j2", "Differences between the source devices", "Use template",
                       "Export package"):
            self.assertContains(response, needle)
        self.assertNotContains(response, "Publish immutable version")
        self.assertNotContains(response, SECRET)
        preset = self.client.get(reverse("core:template_version_detail", args=[version.template.template_id, version.version]), {"set": "R2"})
        self.assertContains(preset, "192.168.200.2/24")

    def test_mls_and_end_device_pages_explain_themselves(self):
        mls = service.get_template("TPL-BASELINE-MULTILAYER-SWITCH").latest_published()
        page = self.client.get(reverse("core:template_version_detail", args=[mls.template.template_id, mls.version]))
        self.assertContains(page, "Semantic combination decisions")
        self.assertContains(page, "TPL-BASELINE-ACCESS-SWITCH@v1")
        end = service.get_template("TPL-BASELINE-END-DEVICE").latest_published()
        page = self.client.get(reverse("core:template_version_detail", args=[end.template.template_id, end.version]))
        self.assertContains(page, "outside NMAS management")
        self.assertNotContains(page, "Clone into Device Builder")

    def test_template_detail_lists_versions(self):
        response = self.client.get(reverse("core:template_detail", args=["TPL-BASELINE-SPINE"]))
        self.assertContains(response, "Published · immutable")
        self.assertContains(response, "S3, S4")
        self.assertEqual(self.client.get(reverse("core:template_detail", args=["TPL-NOPE"])).status_code, 404)
        self.assertEqual(self.client.get(reverse("core:template_version_detail", args=["TPL-BASELINE-SPINE", 99])).status_code, 404)


class WorkflowTests(TemplateViewCase):
    def test_extract_publish_export_import_clone_round_trip_with_authenticated_attribution(self):
        response = self.client.post(reverse("core:template_extract"), {"device": "R1", "name": "From R1", "family": "GATEWAY_ROUTER"})
        self.assertEqual(response.status_code, 302)
        version = models.ConfigurationTemplateVersion.objects.get()
        self.assertEqual((version.status, version.template.name, version.created_by), ("DRAFT", "From R1", TEST_OPERATOR_USERNAME))
        page = self.client.get(response["Location"])
        self.assertContains(page, "Publish immutable version")
        self.assertContains(page, "It passes every publication check.")
        args = [version.template.template_id, version.version]

        self.assertEqual(self.client.get(reverse("core:template_export", args=args)).status_code, 302)       # a draft is not exportable
        self.assertEqual(self.client.post(reverse("core:template_publish", args=args)).status_code, 302)
        version = models.ConfigurationTemplateVersion.objects.get()
        self.assertEqual((version.status, version.published_by), ("PUBLISHED", TEST_OPERATOR_USERNAME))

        export = self.client.get(reverse("core:template_export", args=args))
        self.assertEqual(export.status_code, 200)
        self.assertIn(".nmas-template.yaml", export["Content-Disposition"])
        self.assertEqual(export["X-Content-Type-Options"], "nosniff")
        self.assertNotIn(SECRET.encode(), export.content)

        again = self.client.post(reverse("core:template_import"), {"package": SimpleUploadedFile("t.nmas-template.yaml", export.content)})
        self.assertIn("already+registered", again["Location"])
        tampered = export.content.replace(b"FABRIC_TRUNK", b"FABRIC_OTHER")
        refused = self.client.post(reverse("core:template_import"), {"package": SimpleUploadedFile("t.yaml", tampered)})
        self.assertIn("DIGEST_MISMATCH", refused["Location"])
        self.assertEqual(models.ConfigurationTemplateVersion.objects.count(), 1)

        cloned = self.client.post(reverse("core:template_clone", args=args), {
            "device_name": "R1", "platform": "arista_ceos", "target_type": "EXISTING_DEVICE", "mode": "FULL", "title": "From template",
            "p_hostname": "R1", "p_mgmt_ipv4": "192.168.200.1/24", "p_mgmt_ipv6": "2001:db8:200::1/64", "p_loopback_ipv4": "192.168.255.1/32",
            "p_loopback_ipv6": "2001:db8:255::1/128", "p_ospf_router_id": "192.168.255.1"})
        self.assertEqual(cloned.status_code, 302)
        change = models.Change.objects.get()
        self.assertIn(f"/device-builder/changes/{change.change_id}/intent/", cloned["Location"])
        editor = self.client.get(cloned["Location"])
        self.assertContains(editor, f"{version.template.template_id}@v1")
        self.assertContains(editor, "independent editable copy")
        self.assertFalse(models.ChangeExecutionRun.objects.exists())                 # cloning never executes

        user = make_test_operator()
        for event_type in ("TEMPLATE_EXTRACTED", "TEMPLATE_PUBLISHED", "TEMPLATE_EXPORTED", "TEMPLATE_IMPORT_REJECTED", "TEMPLATE_CLONED"):
            with self.subTest(event_type=event_type):
                event = models.AuditEvent.objects.filter(event_type=event_type).first()
                self.assertIsNotNone(event)
                self.assertEqual((event.actor, event.actor_user_id), (TEST_OPERATOR_USERNAME, user.pk))
                self.assertTrue(event.request_id)
        self.assertTrue(models.AuditEvent.objects.filter(event_type="SENSITIVE_READ", route="core:template_export").exists())

    def test_clone_refusal_is_reported_and_creates_nothing(self):
        version = self.published()
        response = self.client.post(reverse("core:template_clone", args=[version.template.template_id, 1]),
                                    {"device_name": "R1", "platform": "arista_ceos", "mode": "FULL", "p_mgmt_ipv4": "not-an-address"})
        self.assertIn("INVALID_PARAMETERS", response["Location"])
        self.assertFalse(models.Change.objects.exists())
        page = self.client.get(response["Location"])
        self.assertContains(page, "Refused.")

    def test_new_version_from_the_working_intent_and_draft_discard(self):
        version = self.published()
        self.client.post(reverse("core:template_clone", args=[version.template.template_id, 1]), {
            "device_name": "R1", "platform": "arista_ceos", "mode": "FULL", "p_hostname": "R1", "p_mgmt_ipv4": "192.168.200.1/24",
            "p_mgmt_ipv6": "2001:db8:200::1/64", "p_loopback_ipv4": "192.168.255.1/32", "p_loopback_ipv6": "2001:db8:255::1/128",
            "p_ospf_router_id": "192.168.255.1"})
        intent = models.DeviceIntent.objects.get()
        response = self.client.post(reverse("core:template_version_from_change", args=[intent.change.change_id, intent.pk]))
        draft = models.ConfigurationTemplateVersion.objects.get(version=2)
        self.assertEqual((draft.status, draft.source_version_id), ("DRAFT", version.pk))
        self.assertIn(f"/v/{draft.version}/", response["Location"])
        self.client.post(reverse("core:template_discard", args=[draft.template.template_id, 2]))
        self.assertFalse(models.ConfigurationTemplateVersion.objects.filter(version=2).exists())
        refused = self.client.post(reverse("core:template_discard", args=[version.template.template_id, 1]))
        self.assertIn("error=", refused["Location"])
        self.assertTrue(models.ConfigurationTemplateVersion.objects.filter(pk=version.pk).exists())

    def test_extract_of_an_unmanaged_device_is_refused(self):
        for device in ("R5", "H1"):
            response = self.client.post(reverse("core:template_extract"), {"device": device})
            self.assertIn("error=", response["Location"])
        self.assertFalse(models.ConfigurationTemplate.objects.exists())
        self.assertEqual(self.factory.devices, [])

    def test_retire_keeps_versions_and_blocks_new_use(self):
        version = self.published()
        self.client.post(reverse("core:template_retire", args=[version.template.template_id]))
        template = models.ConfigurationTemplate.objects.get()
        self.assertEqual(template.retired_by, TEST_OPERATOR_USERNAME)
        self.assertEqual(template.versions.count(), 1)
        self.assertEqual(len(self.client.get(reverse("core:template_library")).context["rows"]), 0)
        self.assertEqual(len(self.client.get(reverse("core:template_library"), {"retired": "1"}).context["rows"]), 1)


class AuthorizationTests(TemplateViewCase):
    def client_with(self, username, actions):
        client = Client()
        sign_in(client, make_test_operator(username, actions=actions))
        return client

    def test_anonymous_and_limited_roles_are_enforced_server_side(self):
        version = service.extract_from_device("R1", actor="seed", session_factory=self.factory)
        args = [version.template.template_id, 1]
        anonymous = Client()
        self.assertIn(anonymous.get(reverse("core:template_library")).status_code, (302, 403))
        viewer = self.client_with("tpl-viewer", [Action.VIEW])
        self.assertEqual(viewer.get(reverse("core:template_library")).status_code, 200)
        for name, route_args in (("core:template_extract", []), ("core:template_import", []), ("core:template_publish", args),
                                 ("core:template_discard", args), ("core:template_clone", args), ("core:template_retire", args[:1])):
            with self.subTest(route=name):
                self.assertEqual(viewer.post(reverse(name, args=route_args), {"device": "R1"}).status_code, 403)
        editor = self.client_with("tpl-editor", [Action.VIEW, Action.EDIT])
        self.assertEqual(editor.post(reverse("core:template_publish", args=args)).status_code, 403)   # publishing is an approval
        self.assertEqual(models.ConfigurationTemplateVersion.objects.get().status, "DRAFT")
        approver = self.client_with("tpl-approver", [Action.VIEW, Action.APPROVE])
        self.assertEqual(approver.post(reverse("core:template_publish", args=args)).status_code, 302)
        self.assertEqual(models.ConfigurationTemplateVersion.objects.get().published_by, "tpl-approver")
        self.assertEqual(approver.post(reverse("core:template_clone", args=args), {"device_name": "R1"}).status_code, 403)
        self.assertEqual(viewer.post(reverse("core:template_export", args=args)).status_code, 405)     # a read route refuses unsafe methods
