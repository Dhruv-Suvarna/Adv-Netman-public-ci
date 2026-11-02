"""Fleet / device / precheck pages: the behavior that is specific to them.

The generic endpoint rules -- GET is 405 for a POST action, a POST without CSRF is 403, a pure page rejects POST,
an unknown Change is 404, untrusted text is escaped -- are rows in ``test_view_boundaries``.  What is asserted here:
GET never touches a device or persists anything, the explicit actions do exactly one bounded read-only thing and
ignore every browser-supplied field, and runs are only reachable through the object that owns them.
"""

from __future__ import annotations

import re
from unittest import mock

from django.test import TestCase
from django.urls import reverse

from core import models
from core.services import change_plan_service as cps, change_service, monitoring_service, topology_service
from core.services.health import live, telemetry
from core.tests.helpers import health as h
from core.tests.helpers.fakes import netbox_unreachable
from core.tests.helpers.validation import simple_pass_change, validate


def counts():
    return {"runs": models.OperationalCheckRun.objects.count(), "audit": models.AuditEvent.domain.count()}


class HealthViewTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.f = simple_pass_change()
        validate(cls.f.change, cls.f.sources)
        cls.plan, _ = cps.build_change_plan(cls.f.change, actor="t", sources=cls.f.sources)

    def setUp(self):
        # every source the passive pages could reach is faked; a forgotten fake would wait on the network
        patches = [
            mock.patch.object(topology_service, "get_topology_summary", side_effect=lambda: h.topology_summary(now=h.NOW)),
            mock.patch.object(telemetry, "utcnow", return_value=h.NOW, create=True),
            mock.patch.object(monitoring_service, "get_grafana_health", return_value={"status": "available"}),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.original_read = live.read_device
        self.fake = h.session_factory(default=h.eos_outputs())

    def read_via_fake(self):
        return mock.patch.object(live, "read_device", side_effect=lambda device, **kw: self.original_read(device, session_factory=self.fake, now=kw.get("now")))

    def test_get_pages_never_touch_a_device_and_persist_nothing(self):
        forbidden = AssertionError("a GET must not open a device session")
        before = counts()
        with mock.patch.object(live, "read_device", side_effect=forbidden), mock.patch.object(live, "dhcp_service_state", side_effect=forbidden), \
                mock.patch.object(live, "EosSession", side_effect=forbidden), mock.patch.object(live, "LinuxSession", side_effect=forbidden), \
                netbox_unreachable():
            fleet = self.client.get(reverse("core:health_fleet"))
            device = self.client.get(reverse("core:health_device", args=["R1"]))
            precheck = self.client.get(reverse("core:change_precheck", args=[self.f.change.change_id]))
            sidebar = self.client.get(reverse("core:home"))
        for response in (fleet, device, precheck):
            self.assertEqual(response.status_code, 200)
        self.assertEqual(counts(), before)
        self.assertContains(fleet, "Read-only")
        self.assertContains(fleet, "not available")  # routing is never shown as 0
        for name in ("R1", "R5", "mgmt_swt"):
            self.assertContains(fleet, f'href="{reverse("core:health_device", args=[name])}"')
        self.assertContains(device, 'name="csrfmiddlewaretoken"')
        self.assertContains(precheck, 'name="csrfmiddlewaretoken"')
        self.assertContains(precheck, "TARGET")  # the plan-derived scope preview needs no evidence
        self.assertContains(sidebar, reverse("core:health_fleet"))
        # a precheck page offers no deployment control of any kind
        self.assertIsNone(re.search(r"<button[^>]*>[^<]*(deploy|execute|rollback|apply|push)", precheck.content.decode(), re.I))

    def test_explicit_actions_do_one_read_only_thing_and_ignore_every_browser_field(self):
        hostile = {"device": "R5", "host": "10.9.9.9", "command": "reload", "cmd": "configure terminal", "url": "http://evil", "query": "drop"}
        with self.read_via_fake():
            # Fleet snapshot: persists one FLEET_QUICK run (existing telemetry only), one audit event
            response = self.client.post(reverse("core:health_fleet_snapshot"), hostile)
            self.assertRedirects(response, f"{reverse('core:health_fleet')}?recorded=1")
            # Deep Health for ONE device, chosen by the URL only
            deep = self.client.post(reverse("core:health_device_deep", args=["R1"]), hostile)
        run = models.OperationalCheckRun.objects.get(mode="DEVICE_DEEP")
        self.assertRedirects(deep, reverse("core:health_run", args=[run.run_id]))
        self.assertEqual((run.device, run.created_by), ("R1", "nmas-test-operator"))
        (name, session), = self.fake.created
        self.assertEqual(name, "R1", "only the URL's managed device was contacted")
        self.assertTrue(set(session.ran) <= set(live.CEOS_COMMANDS), "only fixed allowlisted commands ran")
        self.assertEqual(models.OperationalCheckRun.objects.filter(mode="FLEET_QUICK").count(), 1)
        self.assertEqual(models.AuditEvent.objects.filter(event_type="HEALTH_RUN_RECORDED").count(), 2)
        page = self.client.get(reverse("core:health_run", args=[run.run_id]))
        self.assertContains(page, "DEVICE_REACHABLE")
        report = self.client.get(reverse("core:health_run_report", args=[run.run_id]))
        self.assertEqual((report.status_code, report["X-Content-Type-Options"]), (200, "nosniff"))
        self.assertRegex(report["Content-Disposition"], r'^attachment; filename="health-device_deep-[0-9a-f]{8}\.json"$')

        # Precheck: a refused prerequisite is itself recorded (INCOMPLETE), never repaired; then a real one
        fresh = simple_pass_change()  # never validated
        refused = self.client.post(reverse("core:change_precheck_run", args=[fresh.change.change_id]), hostile)
        refused_run = models.OperationalCheckRun.objects.get(change__change_id=fresh.change.change_id)
        self.assertRedirects(refused, reverse("core:change_precheck_detail", args=[fresh.change.change_id, refused_run.run_id]))
        self.assertEqual(refused_run.status, "INCOMPLETE")
        self.assertEqual(models.ChangeValidationRun.objects.filter(change=fresh.change).count(), 0, "a precheck never runs validation")

    def test_connectivity_check_pings_only_an_inventory_known_destination(self):
        # a hostile "destination"/"address" field is ignored: only the server-owned "nmas" key is ever resolved
        hostile = {"destination": "nmas", "family": "4", "address": "8.8.8.8; reload", "command": "reload"}
        fake_session = mock.MagicMock()
        fake_session.ping.return_value = h.ping_output()
        # ``default_session_factory`` (not the session classes) is the seam a live call always goes through by name
        with mock.patch.object(live, "default_session_factory", return_value=lambda device: fake_session):
            response = self.client.post(reverse("core:health_device_connectivity", args=["R1"]), hostile)
        run = models.OperationalCheckRun.objects.get(mode="DEVICE_DEEP")
        self.assertRedirects(response, reverse("core:health_run", args=[run.run_id]))
        self.assertEqual((run.device, run.created_by, run.summary["check_type"]), ("R1", "nmas-test-operator", "CONNECTIVITY"))
        fake_session.ping.assert_called_once_with("192.168.200.100", count=3)
        fake_session.close.assert_called_once()
        page = self.client.get(reverse("core:health_run", args=[run.run_id]))
        self.assertContains(page, "CONNECTIVITY_REACHABLE")

    def test_connectivity_check_rejects_an_unknown_destination_without_opening_a_session(self):
        forbidden = mock.Mock(side_effect=AssertionError("must not open a device session"))
        with mock.patch.object(live, "default_session_factory", forbidden):
            bad_destination = self.client.post(reverse("core:health_device_connectivity", args=["R1"]), {"destination": "not-a-real-target"})
            bad_family = self.client.post(reverse("core:health_device_connectivity", args=["R1"]), {"destination": "nmas", "family": "5"})
            self_target = self.client.post(reverse("core:health_device_connectivity", args=["R1"]), {"destination": "R1"})
        self.assertEqual((bad_destination.status_code, bad_family.status_code, self_target.status_code), (400, 400, 400))
        self.assertEqual(models.OperationalCheckRun.objects.filter(mode="DEVICE_DEEP").count(), 0)

    def test_only_managed_devices_and_owned_runs_are_reachable(self):
        with self.read_via_fake():
            for verb in ("get", "post"):
                for path in ("core:health_device", "core:health_device_deep"):
                    if (verb, path) in (("get", "core:health_device_deep"), ("post", "core:health_device")):
                        continue  # wrong method -> 405, covered by the central matrix
                    for bad in ("R9", "r1", "R1%3Breload", "..", "WebServer"):
                        with self.subTest(verb=verb, route=path, device=bad):
                            self.assertEqual(getattr(self.client, verb)(reverse(path, args=[bad])).status_code, 404)
        self.assertEqual((self.fake.created, counts()["runs"]), ([], 0), "an unknown device is never probed and nothing is recorded")

        deep = live_run = None
        with self.read_via_fake():
            self.client.post(reverse("core:health_device_deep", args=["R1"]))
        deep = models.OperationalCheckRun.objects.get(mode="DEVICE_DEEP")
        self.client.post(reverse("core:change_precheck_run", args=[self.f.change.change_id]))
        pre = models.OperationalCheckRun.objects.get(mode="CHANGE_PRECHECK")
        other = change_service.create_change(title="another Change")  # only its identity matters here
        cases = [  # (label, url, status)
            ("a device run through the global run page", reverse("core:health_run", args=[deep.run_id]), 200),
            ("a precheck run is NOT a global health run", reverse("core:health_run", args=[pre.run_id]), 404),
            ("a precheck through its own Change", reverse("core:change_precheck_detail", args=[self.f.change.change_id, pre.run_id]), 200),
            ("a precheck through ANOTHER Change", reverse("core:change_precheck_detail", args=[other.change_id, pre.run_id]), 404),
            ("a device run through a Change", reverse("core:change_precheck_detail", args=[self.f.change.change_id, deep.run_id]), 404),
            ("a precheck report is not downloadable globally", reverse("core:health_run_report", args=[pre.run_id]), 404),
            ("an unknown run", reverse("core:health_run", args=["00000000-0000-4000-8000-000000000000"]), 404),
        ]
        for label, url, status in cases:
            with self.subTest(case=label):
                self.assertEqual(self.client.get(url).status_code, status)
        self.assertEqual(self.client.get("/health/runs/not-a-uuid/").status_code, 404)
