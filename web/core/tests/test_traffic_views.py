"""V2 Phase 5B traffic workbench pages: rendering, the closed POST contract, RBAC classification (real runner, scripted runtime)."""

from __future__ import annotations

import inspect
import re

from django.test import TestCase
from django.urls import reverse

from core import models, views
from core.services.identity import policy
from core.tests.helpers import traffic as t


class TrafficViewTests(TestCase):
    def test_workbench_page_offers_endpoints_and_bounds_but_no_command_or_address_field(self):
        response = self.client.get(reverse("core:traffic_workbench"))
        self.assertContains(response, "Traffic / test workbench")
        for name in ("H1", "H2", "H3", "H4", "WebServer"):
            self.assertContains(response, f'<option value="{name}"')
        self.assertContains(response, "No test has been run.")
        self.assertContains(response, "never makes one a managed device")
        html = response.content.decode()
        form = html[html.index('data-component="traffic-form"'):]
        form = form[:form.index("</form>")]
        names = set(re.findall(r'name="([a-z_]+)"', form)) - {"csrfmiddlewaretoken"}
        self.assertEqual(names, set(views._TRAFFIC_FIELDS))
        for forbidden in ("command", "argv", "pid", "flags", "destination_address", "<textarea"):
            self.assertNotIn(forbidden, form)

    def test_post_runs_one_test_and_shows_its_evidence(self):
        with t.wired():
            response = self.client.post(reverse("core:traffic_run_create"), t.request(family="IPERF3", protocol="TCP", duration="3"))
        run = models.TrafficRun.objects.get()
        self.assertEqual(response.url, run.get_absolute_url())
        self.assertEqual((run.status, run.operator), (models.TrafficRunStatus.PASSED, "nmas-test-operator"))
        detail = self.client.get(run.get_absolute_url())
        for text in (str(run.run_id), "192.168.10.102", "192.168.20.101", "iperf3 throughput", "confirmed stopped: yes", "bits_per_second"):
            self.assertContains(detail, text)
        history = self.client.get(reverse("core:traffic_workbench"))
        self.assertContains(history, str(run.run_id)[:8])
        self.assertContains(history, "1047038 bit/s")

    def test_refusal_redirects_with_stable_codes_and_runs_nothing(self):
        with t.wired() as world:
            response = self.client.post(reverse("core:traffic_run_create"), t.request(family="IPERF3", duration="86400"))
        self.assertIn("codes=PARAMETER_OUT_OF_BOUNDS", response.url)
        self.assertIn("field=duration", response.url)
        self.assertEqual((world.calls, models.TrafficRun.objects.count()), ([], 0))
        page = self.client.get(response.url)
        self.assertContains(page, "A parameter is outside its allowed range.")
        self.assertContains(page, "Nothing was run.")
        self.assertNotContains(self.client.get(reverse("core:traffic_workbench") + "?codes=<script>alert(1)</script>"), "<script>alert")

    def test_extra_post_fields_cannot_reach_the_process_boundary(self):
        with t.wired() as world:
            self.client.post(reverse("core:traffic_run_create"), {**t.request(), "command": "id", "argv": "--flood", "pid": "1",
                                                                  "destination_address": "8.8.8.8", "extra_flags": "-f"})
        run = models.TrafficRun.objects.get()
        self.assertEqual(run.destination_address, "192.168.20.101")
        self.assertNotIn("8.8.8.8", repr(world.calls) + repr(run.requested) + repr(run.operation))
        self.assertNotIn("flood", repr(world.calls))

    def test_failed_run_page_explains_the_failure(self):
        world = t.World(); world.outputs["tcp_connect"] = '{"result": "refused", "elapsed_ms": 0.6}'
        with t.wired(world):
            self.client.post(reverse("core:traffic_run_create"), t.request(family="TCP_CONNECT", port="81"))
        run = models.TrafficRun.objects.get()
        detail = self.client.get(run.get_absolute_url())
        self.assertContains(detail, "CONNECTION_REFUSED")
        self.assertContains(detail, "The destination refused the connection (port closed).")

    def test_get_cannot_run_a_test_and_unknown_run_is_404(self):
        self.assertEqual(self.client.get(reverse("core:traffic_run_create")).status_code, 405)
        self.assertEqual(self.client.get(reverse("core:traffic_run_detail", args=["00000000-0000-0000-0000-000000000000"])).status_code, 404)

    def test_views_are_thin_and_classified(self):
        self.assertIn("traffic_workbench", policy.READ_ROUTES)
        self.assertIn("traffic_run_detail", policy.READ_ROUTES)
        self.assertEqual(policy.MUTATION_ROUTES["traffic_run_create"], policy.Action.EXECUTE)
        for name in ("traffic_workbench", "traffic_run_create", "traffic_run_detail"):
            source = inspect.getsource(getattr(views, name))
            for forbidden in ("subprocess", "nsenter", "docker", "runner", "socket", "os."):
                self.assertNotIn(forbidden, source, name)
