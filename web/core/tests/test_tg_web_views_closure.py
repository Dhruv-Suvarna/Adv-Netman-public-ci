"""Lab 7 closure -- the website's thin view adapters, each called directly with a RequestFactory request.

A view's job is to parse the request, call ONE service with server-owned arguments and render or redirect.  These tests
pin exactly that: the template and context handed to ``render`` (captured, not rendered), the redirect target, and the
arguments the service received.  Every service that would read a device, NetBox, Grafana or Slack is replaced with a
fake, and the workbench snapshot is captured from a fake read-only session, so nothing leaves the process.

POSITIVE: the exact service call and the exact redirect / context.  NEGATIVE: browser-supplied fields are ignored, an
unconfirmed or malformed request is refused with nothing written, unavailable sources render as unavailable, and a page
never carries a secret.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest import mock

from django.core.files.uploadedfile import SimpleUploadedFile
from django.http import Http404, HttpResponse
from django.test import RequestFactory, TestCase
from django.urls import reverse

from core import models, views
from core.models import Notification
from core.services import (
    bootstrap_service, health_service, monitoring_service, notification_service, nsot_service, provisioning_service,
    raw_configlet_service, workbench_service,
)
from core.services.config_import import service as config_import_service
from core.services.config_templates import service as template_service
from core.services.config_workbench import snapshots
from core.tests import test_identity_access as ia
from core.tests.helpers.validation import make_sources
from core.tests.helpers.workbench import use_scope
from core.tests.test_config_workbench import SWITCH
from core.tests.test_config_workflows import DEVICE, fetch_factory

UNAVAILABLE = {"status": "unavailable", "source": "NETBOX", "message": "NetBox temporarily unavailable.", "data": []}


class ViewCase(TestCase):
    """Signed-in operator requests; ``render`` is captured instead of producing HTML."""

    def setUp(self):
        self.user = ia.make_user("op", "NMAS Operator")
        self.rendered = []
        patcher = mock.patch.object(views, "render", side_effect=self.capture_render)
        patcher.start()
        self.addCleanup(patcher.stop)

    def capture_render(self, request, template, context=None, *args, **kwargs):
        self.rendered.append((template, context or {}))
        return HttpResponse(template)

    def request(self, method="get", path="/", data=None, **meta):
        req = getattr(RequestFactory(), method)(path, data or {}, **meta)
        req.user = self.user
        return req

    def post(self, data=None, **meta):
        return self.request("post", "/", data, **meta)

    @property
    def page(self):
        return self.rendered[-1]

    def patch(self, target, attribute, *args, **kwargs):
        patcher = mock.patch.object(target, attribute, *args, **kwargs)
        fake = patcher.start()
        self.addCleanup(patcher.stop)
        return fake


class BootstrapAndHealthViewTests(ViewCase):
    def test_bootstrap_probe_persists_nothing_and_never_writes(self):
        report = SimpleNamespace(ready=False)
        probe = self.patch(bootstrap_service, "readiness_probe", return_value=report)
        before = (models.ConfigurationBundle.objects.count(), models.AuditEvent.objects.count(), models.LegacyBootstrapRun.objects.count())
        views.bootstrap_probe(self.post({"device": "R9"}))
        probe.assert_called_once_with()
        self.assertEqual(self.page, ("core/bootstrap/probe.html", {"page_title": "Readiness probe", "report": report}))
        self.assertEqual((models.ConfigurationBundle.objects.count(), models.AuditEvent.objects.count(), models.LegacyBootstrapRun.objects.count()), before)

    def test_bootstrap_start_with_confirmation_starts_the_run(self):
        candidate = SimpleNamespace(bundle_id="BND-LEGACY-000001")
        self.patch(views.bundle_service, "get_bundle", return_value=candidate)
        start = self.patch(bootstrap_service, "start_bootstrap", return_value=SimpleNamespace(run=SimpleNamespace(run_id="BOOT-000001"), created=True, blockers=[]))
        response = views.bootstrap_start(self.post({"confirm": "on"}), "BND-LEGACY-000001")
        start.assert_called_once_with(candidate, actor="op")
        self.assertEqual(response["Location"], reverse("core:bootstrap_run_detail", args=["BOOT-000001"]) + "?notice=STARTED")
        with self.subTest("refused without confirm"):
            start.reset_mock()
            response = views.bootstrap_start(self.post({}), "BND-LEGACY-000001")
            start.assert_not_called()
            self.assertEqual(response["Location"], reverse("core:bootstrap_home") + "?notice=CONFIRM_REQUIRED")

    def test_health_device_renders_the_managed_device_read_model(self):
        managed = {"name": "R1", "platform": "eos"}
        self.patch(health_service, "get_managed_device", return_value=managed)
        self.patch(health_service, "get_device_quick", return_value={"status": "HEALTHY"})
        self.patch(health_service, "latest_run", return_value=None)
        self.patch(health_service, "latest_connectivity_run", return_value=None)
        self.patch(health_service, "get_capability", return_value={"deep": True})
        self.patch(health_service, "recent_runs", return_value=[])
        self.patch(health_service, "ping_targets", return_value=["R2"])
        views.health_device(self.request(), "R1")
        template, context = self.page
        self.assertEqual(template, "core/health/device.html")
        self.assertEqual((context["page_title"], context["device"], context["quick"], context["capability"], context["ping_targets"]),
                         ("Health: R1", managed, {"status": "HEALTHY"}, {"deep": True}, ["R2"]))
        self.assertIsNone(context["report"])

    def test_health_fleet_snapshot_ignores_browser_fields_never_trusting_them(self):
        record = self.patch(health_service, "record_fleet_snapshot")
        response = views.health_fleet_snapshot(self.post({"device": "R9", "status": "HEALTHY", "actor": "root"}))
        record.assert_called_once_with(actor="op")
        self.assertEqual(response["Location"], reverse("core:health_fleet") + "?recorded=1")

    def test_monitoring_link_pages_use_only_their_fixed_dashboard_key_never_a_browser_one(self):
        build = self.patch(monitoring_service, "get_monitoring_page_context", return_value={"page_title": "x"})
        for view, key, template in ((views.monitoring_link_events, "link_events", "core/monitoring/link_events.html"),
                                    (views.monitoring_link_state_traffic, "link_state_traffic", "core/monitoring/link_state_traffic.html")):
            with self.subTest("never a browser key", key=key):
                view(self.request("get", "/monitoring/x/", {"dashboard": "admin", "device": "R1"}))
                self.assertEqual(build.call_args.args[0], key)
                self.assertEqual(build.call_args.kwargs["reset_url"], "/monitoring/x/")
                self.assertEqual(self.page[0], template)


class NotificationAndProfileViewTests(ViewCase):
    def test_mark_all_read_with_no_unread_row_never_restamps(self):
        row = Notification.objects.create(event_type=Notification.EventType.values[0], severity=Notification.Severity.values[0],
                                          title="t", message="m", is_read=True)
        response = views.notification_mark_all_read(self.post())
        self.assertEqual(response["Location"], reverse("core:notifications"))
        row.refresh_from_db()
        self.assertIsNone(row.read_at)  # an already-read row is never re-stamped

    def test_notification_retry_slack_retries_and_returns_to_the_detail(self):
        retry = self.patch(notification_service, "retry_slack_delivery")
        response = views.notification_retry_slack(self.post(), 7)
        retry.assert_called_once_with(7)
        self.assertEqual(response["Location"], reverse("core:notification_detail", args=[7]))

    def test_profile_page_never_carries_secret_context(self):
        views.profile(self.request())
        self.assertEqual(self.page, ("core/profile.html", {"page_title": "Profile"}))


class NsotViewTests(ViewCase):
    def test_nsot_pages_render_an_unavailable_netbox_as_unavailable(self):
        for view, getter, template in ((views.nsot_drift, "get_drift", "core/nsot/drift.html"), (views.nsot_ipam, "get_ipam", "core/nsot/ipam.html"),
                                       (views.nsot_platforms, "get_platforms", "core/nsot/platforms.html"),
                                       (views.nsot_routing, "get_routing", "core/nsot/routing.html")):
            with self.subTest("unavailable", template=template):
                read = self.patch(nsot_service, getter, return_value=dict(UNAVAILABLE))
                view(self.request("get", "/", {"refresh": "yes"}))
                read.assert_called_once_with(force_refresh=False)  # only refresh=1 forces a re-read
                self.assertEqual((self.page[0], self.page[1]["status"], self.page[1]["data"]), (template, "unavailable", []))

    def test_nsot_interfaces_unavailable_is_an_empty_page(self):
        read = self.patch(nsot_service, "get_interfaces", return_value=dict(UNAVAILABLE))
        views.nsot_interfaces(self.request("get", "/", {"device": "  ", "refresh": "1", "page": "9"}))
        read.assert_called_once_with(None, force_refresh=True)
        context = self.page[1]
        self.assertEqual((list(context["interfaces"]), context["device_filter"], context["listing"]["status"]), ([], "", "unavailable"))

    def test_nsot_templates_without_a_selected_file_reads_no_file(self):
        self.patch(nsot_service, "get_templates_catalogue", return_value=dict(UNAVAILABLE))
        read_file = self.patch(nsot_service, "get_template_file")
        views.nsot_templates(self.request())
        read_file.assert_not_called()
        self.assertEqual((self.page[1]["files"], self.page[1]["selected_file"], self.page[1]["selected_path"]), ([], None, ""))


class DeviceBuilderViewTests(ViewCase):
    def setUp(self):
        super().setUp()
        self.change = models.Change.objects.create(change_id="CHG-000901", title="t")
        self.intent = SimpleNamespace(pk=3, target_type=models.DeviceIntentTargetType.EXISTING_DEVICE, device_name="R1")
        self.revision = SimpleNamespace(pk=4)
        self.editor = reverse("core:device_builder_edit", args=[self.change.change_id, 3])

    def target(self):
        return self.patch(views, "_resolve_editor_target", return_value=(self.change, self.intent, self.revision))

    def test_capabilities_page_is_read_only_and_never_writes(self):
        matrix = self.patch(views.capability_registry, "evidence_matrix", return_value={"rows": []})
        views.device_builder_capabilities(self.request())
        matrix.assert_called_once_with()
        self.assertEqual(self.page, ("core/device_builder/capabilities.html", {"page_title": "Platform Capabilities", "evidence_matrix": {"rows": []}}))
        self.assertFalse(models.CapabilityAssessment.objects.exists())

    def test_create_change_without_a_title_is_an_untitled_draft_with_no_intent(self):
        response = views.device_builder_create_change(self.post({"title": "   "}))
        change = models.Change.objects.exclude(pk=self.change.pk).get()
        self.assertEqual((change.title, change.created_by), ("Untitled draft", "op"))
        self.assertEqual(response["Location"], reverse("core:device_builder_change_detail", args=[change.change_id]))
        self.assertFalse(models.DeviceIntent.objects.filter(change=change).exists())

    def test_import_existing_config_imports_and_reports_the_counts(self):
        self.target()
        importer = self.patch(config_import_service, "import_existing_device",
                              return_value=SimpleNamespace(status="imported", interfaces_imported=3, unmanaged_block_count=1, message=""))
        response = views.device_builder_import_existing_config(self.post(), self.change.change_id, 3)
        importer.assert_called_once_with(change=self.change, intent=self.intent, revision=self.revision, device_name="R1")
        self.assertTrue(response["Location"].startswith(self.editor + "?import_notice=Imported%203%20interface"))
        self.assertIn("1%20configuration%20block", response["Location"])

    def test_ospf_network_add_and_remove_call_the_routing_service(self):
        self.target()
        add = self.patch(views.routing_intent_service, "add_ospf_network")
        remove = self.patch(views.routing_intent_service, "remove_ospf_network")
        added = views.device_builder_ospf_network_add(self.post({"prefix": "10.1.0.0/24", "area": "1"}), self.change.change_id, 3, "ospf-1")
        removed = views.device_builder_ospf_network_remove(self.post({"confirmation": "REMOVE"}), self.change.change_id, 3, "ospf-1", "net-1")
        add.assert_called_once_with(revision=self.revision, instance_id="ospf-1", prefix="10.1.0.0/24", area="1")
        remove.assert_called_once_with(revision=self.revision, instance_id="ospf-1", net_id="net-1", confirmation="REMOVE")
        self.assertEqual((added["Location"].split("?")[0], removed["Location"].split("?")[0]), (self.editor, self.editor))

    def test_service_mode_sets_the_mode(self):
        self.target()
        set_mode = self.patch(views.service_policy_intent_service, "set_service_mode")
        response = views.device_builder_service_mode(self.post({"mode": "ENABLED"}), self.change.change_id, 3, "dhcp")
        set_mode.assert_called_once_with(revision=self.revision, service="dhcp", mode="ENABLED")
        self.assertEqual(response["Location"].split("?")[0], self.editor)


class NetworkConfigValidationViewTests(ViewCase):
    def setUp(self):
        super().setUp()
        self.change = models.Change.objects.create(change_id="CHG-000902", title="t")
        self.run = models.NetworkConfigValidationRun.objects.create(change=self.change, operation_type="CANDIDATE", status="PASS",
                                                                     engine_version="t1", input_hash="a" * 64)
        ncv = views.network_config_validation
        self.patch(ncv, "get_currency", return_value={"latest": self.run, "state": "CURRENT"})
        self.patch(ncv, "serialize", return_value={"run": "doc"})
        self.patch(ncv, "list_runs", return_value=[self.run])

    def test_validation_page_and_detail_render_the_selected_run(self):
        views.network_config_validation_page(self.request(), self.change.change_id)
        views.network_config_validation_detail(self.request(), self.change.change_id, self.run.run_id)
        for template, context in self.rendered:
            self.assertEqual((template, context["run"], context["document"], context["history"]),
                             ("core/device_builder/network_config_validation.html", self.run, {"run": "doc"}, [self.run]))

    def test_validation_report_returns_the_json_attachment(self):
        response = views.network_config_validation_report(self.request(), self.change.change_id, self.run.run_id)
        self.assertEqual(json.loads(response.content), {"run": "doc"})
        self.assertEqual((response["Content-Disposition"], response["X-Content-Type-Options"]),
                         (f'attachment; filename="network-config-validation-{self.run.run_id}.json"', "nosniff"))

    def test_validation_run_validates_the_candidate_and_returns_to_the_page(self):
        validate = self.patch(views.network_config_validation, "validate_candidate")
        response = views.network_config_validation_run(self.post({"device": "R9"}), self.change.change_id)
        validate.assert_called_once_with(self.change, actor="op")
        self.assertEqual(response["Location"], reverse("core:network_config_validation", args=[self.change.change_id]))


class ProvisioningViewTests(ViewCase):
    def setUp(self):
        super().setUp()
        self.run = models.ProvisioningRun.objects.create(device_name="R9", platform="frr", role="edge", requested_by="op")

    def test_provisioning_steps_call_their_service_and_return_to_the_run(self):
        steps = (
            (views.provisioning_bootstrap, "classify_bootstrap", {}, {}),
            (views.provisioning_capability, "resolve_capabilities", {}, {}),
            (views.provisioning_ipam, "plan_ipam", {}, {}),
            (views.provisioning_candidate, "generate_candidate", {"execution_mode": "PARTIAL_UAT"}, {"execution_mode": "PARTIAL_UAT"}),
            (views.provisioning_validation, "record_validation", {}, {}),
            (views.provisioning_plan, "build_plan", {}, {}),
            (views.provisioning_precheck, "run_precheck", {}, {}),
            (views.provisioning_nsot_sync, "sync_nsot", {}, {}),
            (views.provisioning_decommission, "decommission", {"confirm": "on"}, {}),
        )
        for view, service, post, extra in steps:
            with self.subTest(service):
                call = self.patch(provisioning_service, service)
                response = view(self.post(post), self.run.prov_id)
                call.assert_called_once_with(self.run, actor="op", **extra)
                self.assertEqual(response["Location"], self.run.get_absolute_url())

    def test_provisioning_identity_passes_the_trimmed_identity(self):
        define = self.patch(provisioning_service, "define_identity")
        views.provisioning_identity(self.post({"bootstrap_transport": "DOCKER_EXEC", "container": " clab-R9 ", "lab": " lab ",
                                               "mgmt_interface": " eth0 ", "mgmt_ipv4": "", "mgmt_ipv6": "2001:db8::9/64"}), self.run.prov_id)
        define.assert_called_once_with(self.run, actor="op", bootstrap_transport="DOCKER_EXEC", bootstrap_target={"container": "clab-R9", "lab": "lab"},
                                       management={"interface": "eth0", "ipv4": None, "ipv6": "2001:db8::9/64", "vlan": None, "assignment": "static"})

    def test_provisioning_list_drops_unknown_refusal_codes_never_echoing_them(self):
        known = next(iter(provisioning_service.codes.BLOCKERS))
        views.provisioning_list(self.request("get", "/", {"codes": f"<script>,{known},NOT_A_CODE"}))
        context = self.page[1]
        self.assertEqual([r["code"] for r in context["refusals"]], [known])
        self.assertEqual(list(context["runs"]), [self.run])
        self.assertNotIn("<script>", str(context["refusals"]))


class RawAndTemplateViewTests(ViewCase):
    def test_raw_configlet_verification_renders_the_current_run(self):
        change = models.Change.objects.create(change_id="CHG-000903", title="t")
        revision = SimpleNamespace(pk=11)
        run = SimpleNamespace(pk=5, run_id="1234abcd-0000", result="PASS", revision=revision)
        raw = SimpleNamespace(latest_revision=lambda: revision)
        self.patch(raw_configlet_service, "get_raw", return_value=raw)
        self.patch(raw_configlet_service, "get_verification_run", return_value=run)
        self.patch(raw_configlet_service, "verification_currency", return_value={"run": run, "state": "CURRENT", "reasons": []})
        views.raw_configlet_verification(self.request(), change.change_id, "RAW-001", "1234abcd-0000")
        template, context = self.page
        self.assertEqual((template, context["page_title"], context["is_current"], context["is_latest_revision"], context["raw"]),
                         ("core/device_builder/raw_verification.html", "Verification 1234abcd", True, True, raw))

    def test_template_retire_retires_and_keeps_versions(self):
        template = SimpleNamespace(template_id="TPL-000001")
        self.patch(template_service, "get_template", return_value=template)
        retire = self.patch(template_service, "retire")
        response = views.template_retire(self.post(), "TPL-000001")
        retire.assert_called_once_with(template, actor="op")
        self.assertTrue(response["Location"].startswith(reverse("core:template_detail", args=["TPL-000001"]) + "?notice=Template+retired"))

    def test_template_import_refuses_a_missing_or_malformed_package(self):
        response = views.template_import(self.post())
        self.assertEqual(response["Location"], reverse("core:template_library") + "?error=Choose+a+template+package+file.")
        upload = SimpleUploadedFile("pkg.json", b"{not json", content_type="application/json")
        response = views.template_import(self.post({"package": upload}))
        self.assertIn("error=", response["Location"])
        self.assertFalse(models.ConfigurationTemplate.objects.exists())


class WorkbenchViewTests(ViewCase):
    """A real S1 snapshot from a fake read-only session; validation / planning are replaced (asserted as called)."""

    def setUp(self):
        super().setUp()
        use_scope(self)
        self.patch(snapshots, "SESSION_FACTORY", fetch_factory(SWITCH))
        sources = mock.patch("core.services.change_validation_service.build_source_snapshot", lambda change=None: make_sources())
        sources.start()
        self.addCleanup(sources.stop)
        self.snapshot, error = snapshots.capture_snapshot(DEVICE, actor="op", session_factory=fetch_factory(SWITCH))
        self.assertEqual(error, "")
        self.validate_and_plan = self.patch(workbench_service, "validate_and_plan")
        self.patch(views, "_workbench_context", return_value={"snapshot": self.snapshot})

    def operations(self):
        return [{"op": "static_route", "destination": "10.77.0.0/16", "next_hop": "192.168.110.0"}]

    def saved_change(self):
        response = views.workbench_changes_save(self.post({"operations": json.dumps(self.operations()), "title": "route"}))
        self.assertEqual(response.status_code, 302, response.get("Location"))
        return models.Change.objects.get(metadata__workflow="CONFIGURATION_CHANGES"), response

    def test_workbench_changes_preview_normalizes_and_writes_nothing(self):
        views.workbench_changes_preview(self.post({"mode": "cli", "fragment": "ip route 10.77.0.0/16 192.168.110.0\n"}))
        context = self.page[1]
        self.assertEqual([op["op"] for op in context["operations"]], ["static_route"])
        self.assertEqual((context["rejected"], context["preview"], context["mode"]), ([], True, "cli"))
        self.assertFalse(models.Change.objects.exists())

    def test_workbench_changes_save_creates_the_draft_and_plans_it(self):
        change, response = self.saved_change()
        self.validate_and_plan.assert_called_once_with(change, actor="op")
        self.assertIn(f"change={change.change_id}", response["Location"])
        self.assertEqual(change.created_by, "op")

    def test_workbench_changes_save_refuses_malformed_operations_writing_nothing(self):
        for label, raw in (("not json", "{"), ("not a list", "{}"), ("too many", json.dumps([{}] * 21)), ("not objects", "[1]")):
            with self.subTest(label):
                response = views.workbench_changes_save(self.post({"operations": raw}))
                self.assertEqual((response.status_code, response.content), (400, b"Malformed operations."))
        self.assertFalse(models.Change.objects.exists())
        self.validate_and_plan.assert_not_called()

    def test_workbench_revalidate_archive_and_revise_act_on_the_draft(self):
        change, _response = self.saved_change()
        self.validate_and_plan.reset_mock()
        views.workbench_revalidate(self.post(), change.change_id)
        self.validate_and_plan.assert_called_once_with(change, actor="op")
        revise = self.patch(workbench_service, "revise_change", return_value=[SimpleNamespace(device_intent_id=8)])
        response = views.workbench_revise(self.post({"title": "v2"}), change.change_id)
        revise.assert_called_once_with(change=change, actor="op", title="v2")
        self.assertEqual(response["Location"], reverse("core:device_builder_edit", args=[change.change_id, 8]))
        archive = self.patch(workbench_service, "archive_change")
        response = views.workbench_archive(self.post({"confirmation": "ARCHIVE"}), change.change_id)
        archive.assert_called_once_with(change=change, actor="op")
        self.assertTrue(response["Location"].startswith(reverse("core:workbench_changes")))

    def test_workbench_validate_running_assesses_the_snapshot(self):
        validate = self.patch(views.network_config_validation, "validate_running")
        response = views.workbench_validate_running(self.post({"workflow": "CONFIGURATION_CHANGES"}), str(self.snapshot.snapshot_id))
        validate.assert_called_once_with(self.snapshot, actor="op")
        self.assertIn(f"snapshot={self.snapshot.snapshot_id}", response["Location"])
        with self.subTest("unknown snapshot raises"), self.assertRaises(Http404):
            views.workbench_validate_running(self.post(), "00000000-0000-0000-0000-000000000000")
