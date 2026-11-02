from __future__ import annotations

import json
import re
import uuid
from unittest import mock

from django.test import TestCase
from django.urls import reverse

from core import models
from core.services import change_validation_service as cvs
from core.tests.helpers.validation import Dev, make_sources, new_change


class ValidationViewBase(TestCase):
    def setUp(self):
        self.change = new_change("View fixture")
        self.r1, self.r2 = Dev(self.change, "R1"), Dev(self.change, "R2")
        self.a = self.r1.iface("Ethernet1"); self.r1.address(self.a, "192.0.2.1/24")
        self.z = self.r2.iface("Ethernet1"); self.r2.address(self.z, "192.0.2.1/24")   # duplicate -> BLOCKED with findings
        patcher = mock.patch("core.services.validation.sources.build_source_bundle", side_effect=lambda: make_sources())
        self.build = patcher.start()
        self.addCleanup(patcher.stop)

    def url(self, name, *args):
        return reverse(f"core:{name}", args=[self.change.change_id, *args])

    def run_via_post(self):
        return self.client.post(self.url("change_validation_run"))


class PageTests(ValidationViewBase):
    """Method / CSRF / unknown-change rules for these endpoints live in test_view_boundaries."""

    def test_page_renders_for_a_change_that_was_never_validated_and_get_never_runs_anything(self):
        response = self.client.get(self.url("change_validation"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "NEVER RUN")
        self.assertContains(response, "Project validation uses committed/accepted intent only.")
        self.assertContains(response, "Run Change Validation")
        for _ in range(2):
            self.client.get(self.url("change_validation"))
        self.assertEqual(self.change.validation_runs.count(), 0)
        self.assertEqual(self.build.call_count, 0)     # not even a source read

    def test_post_run_creates_exactly_one_run_and_leaves_the_change_in_draft(self):
        response = self.run_via_post()
        self.assertRedirects(response, self.url("change_validation"), fetch_redirect_response=False)
        self.assertEqual(self.change.validation_runs.count(), 1)
        page = self.client.get(self.url("change_validation"))
        for text in ("BLOCKED", "IP_DUPLICATE", "CURRENT"):
            with self.subTest(text=text):
                self.assertContains(page, text)
        self.change.refresh_from_db()
        self.assertEqual(self.change.lifecycle_state, models.ChangeLifecycleState.DRAFT)
        self.assertEqual(models.Configlet.objects.count(), 0)

    def test_post_fields_cannot_select_sources_paths_or_urls(self):
        self.client.post(self.url("change_validation_run"), {"netbox_url": "http://evil", "path": "/etc/passwd", "sources": "x"})
        self.build.assert_called_once_with()
        self.assertEqual(self.change.validation_runs.count(), 1)

    def test_change_detail_links_to_validation(self):
        self.assertContains(self.client.get(reverse("core:device_builder_change_detail", args=[self.change.change_id])),
                            self.url("change_validation"))


class FilterTests(ValidationViewBase):
    def setUp(self):
        super().setUp()
        self.r1.static_route("10.9.0.0/24", next_hop="172.16.9.9")          # WARNING / ROUTING
        self.run_via_post()

    def get(self, **params):
        return self.client.get(self.url("change_validation"), params).content.decode()

    def test_findings_filters(self):
        """(query, must appear, must not appear).  IP_DUPLICATE is a blocking ADDRESSING ERROR on R1+R2;
        ROUTE_NEXT_HOP_UNRESOLVED is a non-blocking ROUTING WARNING on R1."""
        cases = [
            ("severity", {"severity": "WARNING"}, "ROUTE_NEXT_HOP_UNRESOLVED", "IP_DUPLICATE"),
            ("category", {"category": "ADDRESSING"}, "IP_DUPLICATE", "ROUTE_NEXT_HOP_UNRESOLVED"),
            ("device (related device counts)", {"device": "R2"}, "IP_DUPLICATE", "ROUTE_NEXT_HOP_UNRESOLVED"),
            ("blocking only", {"blocking": "1"}, "IP_DUPLICATE", "ROUTE_NEXT_HOP_UNRESOLVED"),
        ]
        for label, params, present, absent in cases:
            with self.subTest(filter=label):
                body = self.get(**params)
                self.assertIn(present, body)
                self.assertNotIn(absent, body)

    def test_unknown_filter_values_are_ignored_not_trusted(self):
        body = self.get(severity="<script>", category="NOPE", device="../../etc")
        self.assertNotIn("<script>", body)
        self.assertIn("No findings match", self.get(device="../../etc"))


class HistoryAndStaleTests(ValidationViewBase):
    def test_history_is_newest_first(self):
        self.run_via_post(); self.r1.set(f"interfaces.{self.a['id']}.description", "v2"); self.run_via_post()
        runs = cvs.list_validation_runs(self.change)
        body = self.client.get(self.url("change_validation")).content.decode()
        table = body.split("Validation history", 1)[1]
        newest, oldest = str(runs[0].run_id)[:8], str(runs[1].run_id)[:8]
        self.assertLess(table.index(newest), table.index(oldest))

    def test_historical_detail_opens_and_is_read_only(self):
        self.run_via_post(); first = cvs.get_latest_validation(self.change)
        self.r1.set(f"interfaces.{self.a['id']}.description", "v2"); self.run_via_post()
        detail = self.url("change_validation_detail", str(first.run_id))
        page = self.client.get(detail)
        self.assertContains(page, "Historical run")
        self.assertContains(page, "historical, read-only")
        before = self.change.validation_runs.count()
        self.client.get(detail)
        self.assertEqual(self.change.validation_runs.count(), before)
        self.assertEqual(self.client.post(detail).status_code, 405)

    def test_run_of_another_change_or_bad_id_is_404(self):
        self.run_via_post(); run = cvs.get_latest_validation(self.change)
        other = new_change("other")
        cases = {
            "detail via another change": reverse("core:change_validation_detail", args=[other.change_id, str(run.run_id)]),
            "detail, bad id": self.url("change_validation_detail", "not-a-uuid"),
            "detail, unknown run": self.url("change_validation_detail", str(uuid.uuid4())),
            "report, unknown run": self.url("change_validation_report", str(uuid.uuid4())),
            "report via another change": reverse("core:change_validation_report", args=[other.change_id, str(run.run_id)]),
        }
        for label, url in cases.items():
            with self.subTest(case=label):
                self.assertEqual(self.client.get(url).status_code, 404)

    def test_stale_badge_after_an_accepted_change(self):
        self.run_via_post()
        self.r1.set(f"interfaces.{self.a['id']}.description", "changed")
        page = self.client.get(self.url("change_validation"))
        self.assertContains(page, "STALE")
        self.assertContains(page, "Re-run required")
        self.assertContains(page, "ACCEPTED_INTENT_CHANGED")

    def test_source_freshness_check_is_explicit_and_read_only(self):
        self.run_via_post(); self.build.reset_mock()
        self.client.get(self.url("change_validation"))
        self.assertEqual(self.build.call_count, 0)
        changed = make_sources(netbox=__import__("core.tests.helpers.validation", fromlist=["x"]).netbox_data(
            ip_addresses=[__import__("core.tests.helpers.validation", fromlist=["x"]).nb_ip("203.0.113.9/24", "H1", "eth0")]))
        self.build.side_effect = lambda: changed
        page = self.client.get(self.url("change_validation"), {"check_sources": "1"})
        self.assertEqual(self.change.validation_runs.count(), 1)         # still no new run
        self.assertContains(page, "SOURCE_CHANGED:NETBOX")


class EscapingAndReportTests(ValidationViewBase):
    def hostile_run(self):
        finding = {
            "finding_id": "x", "code": "IP_DUPLICATE", "severity": "ERROR", "category": "ADDRESSING", "blocking": True,
            "incomplete": False, "device": "R1", "object_type": "address", "object_id": "<b>id</b>", "field_path": "a.b",
            "related_devices": ["<i>R2</i>"], "related_objects": ["<script>1</script>"], "source": "INTENT",
            "message": "<script>alert('xss')</script> & \"quoted\"", "evidence": {"<k>": "<img src=x onerror=alert(1)>"},
            "remediation": "<a href='javascript:alert(1)'>fix</a>", "message_extra": "",
        }
        summary = {"errors": 1, "warnings": 0, "info": 0, "blocking_findings": 1, "devices_checked": 1, "objects_checked": 1,
                   "sources_available": {"NETBOX": True}}
        return models.ChangeValidationRun.objects.create(
            change=self.change, status="BLOCKED", engine_version="t", input_hash="a" * 64, source_hash="b" * 64, summary=summary,
            report={"findings": [finding], "limitations": ["<u>l</u>"], "provenance": {"sources": {}}},
            dependency_graph={"nodes": [{"id": "n1", "label": "<script>n</script>"}], "edges": [], "cycles": []})

    def test_structured_findings_are_escaped_everywhere(self):
        run = self.hostile_run()
        body = self.client.get(self.url("change_validation_detail", str(run.run_id))).content.decode()
        for raw in ("<script>alert('xss')</script>", "<img src=x onerror=alert(1)>", "<b>id</b>", "<i>R2</i>", "<u>l</u>",
                    "<a href='javascript:alert(1)'>"):
            self.assertNotIn(raw, body)
        self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", body)
        from pathlib import Path
        template = (Path(__file__).resolve().parents[1] / "templates/core/device_builder/validation.html").read_text()
        self.assertNotIn("|safe", template)
        self.assertNotIn("autoescape off", template)

    def test_json_report_is_safe_structured_and_has_a_fixed_filename(self):
        self.run_via_post(); run = cvs.get_latest_validation(self.change)
        response = self.client.get(self.url("change_validation_report", str(run.run_id)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json; charset=utf-8")
        self.assertEqual(response["Content-Disposition"], f'attachment; filename="{self.change.change_id}-validation-{str(run.run_id)[:8]}.json"')
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        document = json.loads(response.content)
        for key in ("provenance", "status", "summary", "findings", "derived_facts", "dependency_graph", "input_hash", "source_hash"):
            self.assertIn(key, document)
        self.assertEqual(document["status"], "BLOCKED")
        self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", document["input_hash"]))

    def test_no_secret_material_in_page_or_report(self):
        revision = self.r1.refresh()
        revision.sections["interfaces"][self.a["id"]]["password"] = "hunter2-injected"
        revision.save(update_fields=["sections"])
        self.run_via_post(); run = cvs.get_latest_validation(self.change)
        page = self.client.get(self.url("change_validation")).content.decode()
        report = self.client.get(self.url("change_validation_report", str(run.run_id))).content.decode()
        for blob in (page, report, json.dumps(run.report)):
            self.assertNotIn("hunter2", blob)
        self.assertNotRegex(report.lower(), r'"(password|api_?token|secret|webhook|community)"')


class DerivedFactDisplayTests(ValidationViewBase):
    def test_auto_address_is_labelled_proposed_and_not_reserved(self):
        from core.tests.helpers.validation import nb_prefix, netbox_data
        e2 = self.r1.iface("Ethernet2"); self.r1.auto_address(e2, "198.51.100.0/29")
        self.build.side_effect = lambda: make_sources(netbox=netbox_data(prefixes=[nb_prefix("198.51.100.0/29")]))
        self.run_via_post()
        page = self.client.get(self.url("change_validation"))
        self.assertContains(page, "198.51.100.1/29")
        self.assertContains(page, "PROPOSED")
        self.assertContains(page, "NOT RESERVED")
        self.assertContains(page, "rechecked immediately before deployment")
        self.assertContains(page, "Dependency summary")
