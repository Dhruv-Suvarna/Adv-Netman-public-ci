"""HTTP boundary + workflow tests for the Phase-19 bundle pages.

The Phase-3/9 rule of ``test_view_boundaries`` applies here too and is asserted ONCE over every bundle endpoint (labelled matrices): mutation
endpoints reject GET (405) and a POST without a CSRF token (403); read-only pages reject POST (405); a GET never mutates.  A bundle page
takes NO payload, digest, kind or parent from the browser -- only a confirmation checkbox and an id in the URL that is looked up server-side.
"""

from __future__ import annotations

import json
import re

from core.tests.runner import OperatorClient  # V2 Phase 1: authenticated, MFA-verified operator
from django.test import TestCase
from django.urls import reverse

from core import models
from core.services import bundle_service as bs
from core.tests.helpers import bundles as bh


class BundleViewFixture(TestCase):
    @classmethod
    def setUpTestData(cls):
        good = bh.partial_run(through=1)
        cls.run_pk, cls.change_id = good.run.pk, good.change.change_id
        cls.failed_pk = bh.partial_run(through=3, fail={"CFG-003": ("COMMAND_REJECTED", True)}).run.pk
        unverified = bh.raw_run()
        cls.unverified_pk = unverified.run.pk

    def run_row(self, pk=None):
        return models.ChangeExecutionRun.objects.get(pk=pk or self.run_pk)

    def uat(self, pk=None):
        return bh.uat_of(type("P", (), {"run": self.run_row(pk)})())

    def urls(self, run=None):
        run = run or self.run_row()
        cid = run.change.change_id
        return {
            "execution": reverse("core:change_execution_detail", args=[cid, run.run_id]),
            "create": reverse("core:change_execution_bundle_create", args=[cid, run.run_id]),
        }

    @staticmethod
    def bundle_url(bundle, name="core:bundle_detail"):
        return reverse(name, args=[bundle.bundle_id])


class BoundaryMatrixTests(BundleViewFixture):
    def test_method_and_csrf_boundaries_over_every_bundle_endpoint(self):
        uat = self.uat()
        strict = OperatorClient(enforce_csrf_checks=True)
        mutations = {"create UAT bundle": self.urls()["create"], "derive Probation bundle": self.bundle_url(uat, "core:bundle_derive_probation")}
        pages = {"bundle list": reverse("core:bundles_list"), "bundle detail": self.bundle_url(uat), "manifest export": self.bundle_url(uat, "core:bundle_manifest")}
        before = bh.table_counts()
        for label, url in mutations.items():
            with self.subTest(mutation=label, rule="GET is rejected"):
                self.assertEqual(self.client.get(url).status_code, 405)
            with self.subTest(mutation=label, rule="POST without a CSRF token is rejected"):
                self.assertEqual(strict.post(url, {"confirm": "on"}).status_code, 403)
        for label, url in pages.items():
            with self.subTest(page=label, rule="POST is rejected"):
                self.assertEqual(self.client.post(url).status_code, 405)
            with self.subTest(page=label, rule="GET renders and mutates nothing"):
                self.assertEqual(self.client.get(url).status_code, 200)
        self.assertEqual(bh.count_changes(before, bh.table_counts()), {}, "no boundary probe created, changed or deleted anything")

    def test_unknown_and_malformed_ids_are_404_and_ids_are_only_reachable_through_their_own_change(self):
        rows = [("core:bundle_detail", ["BND-UAT-000999"]), ("core:bundle_detail", ["BND-GOLD-000001"]), ("core:bundle_detail", ["not-an-id"]),
                ("core:bundle_manifest", ["BND-PROB-000042"])]
        for name, args in rows:
            with self.subTest(route=name, id=args[0]):
                self.assertEqual(self.client.get(reverse(name, args=args)).status_code, 404)
        self.assertEqual(self.client.post(reverse("core:bundle_derive_probation", args=["BND-UAT-000999"]), {"confirm": "on"}).status_code, 404)
        run = self.run_row()
        foreign = bh.partial_run(through=0)     # another Change's run addressed through THIS change's URL
        url = reverse("core:change_execution_bundle_create", args=[self.change_id, foreign.run.run_id])
        self.assertEqual(self.client.post(url).status_code, 404)
        self.assertEqual(models.ConfigurationBundle.objects.count(), 0)
        self.assertEqual(run.change.change_id, self.change_id)


class CreateUatWorkflowTests(BundleViewFixture):
    def test_create_uat_from_the_execution_page_then_a_duplicate_shows_the_existing_bundle(self):
        page = self.client.get(self.urls()["execution"])
        self.assertContains(page, "Create UAT bundle")
        self.assertEqual(models.ConfigurationBundle.objects.count(), 0, "opening the page created nothing")
        created = self.client.post(self.urls()["create"])
        self.assertEqual((created.status_code, created["Location"]), (302, "/device-builder/bundles/BND-UAT-000001/?notice=UAT_CREATED"))
        detail = self.client.get(created["Location"])
        self.assertContains(detail, "UAT bundle created")
        self.assertContains(detail, "INTEGRITY: INTACT")
        self.assertContains(detail, "BND-UAT-000001")
        again = self.client.post(self.urls()["create"])
        self.assertEqual(again["Location"], "/device-builder/bundles/BND-UAT-000001/?notice=UAT_EXISTS")
        self.assertEqual(models.ConfigurationBundle.objects.count(), 1)
        after = self.client.get(self.urls()["execution"])
        self.assertContains(after, "already has its UAT bundle")
        self.assertNotContains(after, "Create UAT bundle</button>")
        self.assertEqual(models.AuditEvent.objects.filter(event_type="UAT_BUNDLE_CREATED").count(), 1)

    def test_the_server_refuses_ineligible_runs_whatever_the_page_offered(self):
        failed = self.run_row(self.failed_pk)
        page = self.client.get(self.urls(failed)["execution"])
        self.assertContains(page, "Not eligible for a UAT bundle")
        self.assertContains(page, "OUTCOME_NOT_BUNDLEABLE")
        self.assertNotContains(page, "Create UAT bundle</button>")
        refused = self.client.post(self.urls(failed)["create"])      # posting anyway: the server re-checks eligibility independently
        self.assertEqual(refused.status_code, 302)
        self.assertTrue(refused["Location"].endswith("?bundle=refused"))
        self.assertContains(self.client.get(refused["Location"]), "not created")
        self.assertEqual(models.ConfigurationBundle.objects.count(), 0)

    def test_a_complete_run_shows_no_bundle_offer_and_an_unverified_scope_says_so(self):
        complete = bh.complete_run()
        complete_page = self.client.get(self.urls(complete.run)["execution"])
        self.assertNotContains(complete_page, "UAT bundle")                 # a Complete run is never offered a UAT bundle ...
        self.assertContains(complete_page, "Seal Deployed bundle</button>")  # ... its own root is the Deployed bundle (test_deployed_lineage)
        unverified_page = self.client.get(self.urls(self.run_row(self.unverified_pk))["execution"])
        self.assertContains(unverified_page, "NOT verified")
        result = self.client.post(self.urls(self.run_row(self.unverified_pk))["create"])
        detail = self.client.get(result["Location"])
        self.assertContains(detail, "was NOT verified")
        self.assertContains(detail, "UNVERIFIED")
        self.assertContains(detail, "SYNTAX ONLY")


class ProbationWorkflowTests(BundleViewFixture):
    def test_probation_needs_confirmation_and_seals_the_same_payload_with_no_device_call(self):
        uat = self.uat()
        derive = self.bundle_url(uat, "core:bundle_derive_probation")
        page = self.client.get(self.bundle_url(uat))
        self.assertContains(page, "Create Probation bundle")
        self.assertContains(page, "the configuration payload will not change")
        self.assertContains(page, "seven-day soak is NOT part of this action")
        unconfirmed = self.client.post(derive)
        self.assertTrue(unconfirmed["Location"].endswith("?notice=CONFIRM_REQUIRED"))
        self.assertEqual(models.ConfigurationBundle.objects.filter(kind="PROBATION").count(), 0)
        with bh.no_device_or_network():
            done = self.client.post(derive, {"confirm": "on"})
        self.assertEqual(done["Location"], "/device-builder/bundles/BND-PROB-000001/?notice=PROBATION_CREATED")
        prob = models.ConfigurationBundle.objects.get(kind="PROBATION")
        self.assertEqual((prob.parent_id, prob.payload_digest), (uat.pk, uat.payload_digest))
        again = self.client.post(derive, {"confirm": "on"})
        self.assertTrue(again["Location"].endswith("PROBATION_EXISTS"))
        self.assertEqual(models.ConfigurationBundle.objects.filter(kind="PROBATION").count(), 1)
        uat_page = self.client.get(self.bundle_url(uat))
        self.assertContains(uat_page, "A Probation bundle already exists")
        self.assertNotContains(uat_page, "Create Probation bundle</button>")
        prob_page = self.client.get(self.bundle_url(prob)).content.decode()
        self.assertIn("promotion requires a technically passed soak and your explicit Golden decision", prob_page)
        self.assertNotIn("Promote to Golden", prob_page)
        self.assertNotIn("Approve Golden", prob_page)   # no decision form exists on the bundle page: only a technically passed soak page offers one
        self.assertNotIn("<form method=\"post\" action=\"/device-builder/bundles/BND-PROB-000001/probation", prob_page)

    def test_browser_supplied_fields_can_never_change_what_is_sealed(self):
        uat = self.uat()
        tampered = self.client.post(self.bundle_url(uat, "core:bundle_derive_probation"), {
            "confirm": "on", "kind": "GOLDEN", "parent": "999", "payload": "interface Evil", "payload_digest": "0" * 64, "bundle_digest": "0" * 64,
            "source_uat": "1", "manifest": "{}",
        })
        self.assertEqual(models.ConfigurationBundle.objects.count(), 2)     # exactly one NEW bundle besides the UAT
        prob = models.ConfigurationBundle.objects.get(kind="PROBATION")
        self.assertEqual((prob.parent_id, prob.payload_digest, prob.manifest["payload"]), (uat.pk, uat.payload_digest, uat.manifest["payload"]))
        self.assertNotIn("Evil", json.dumps(prob.manifest))
        self.assertEqual(tampered.status_code, 302)

    def test_ineligible_probation_shows_stable_blockers_and_creates_nothing(self):
        unverified = self.uat(self.unverified_pk)
        page = self.client.get(self.bundle_url(unverified)).content.decode()
        self.assertIn("Not eligible for Probation", page)
        self.assertIn("SOURCE_UNVERIFIED", page)
        self.assertNotIn("Create Probation bundle</button>", page)
        refused = self.client.post(self.bundle_url(unverified, "core:bundle_derive_probation"), {"confirm": "on"})
        self.assertTrue(refused["Location"].endswith("?notice=PROBATION_REFUSED"))
        self.assertEqual(models.ConfigurationBundle.objects.filter(kind="PROBATION").count(), 0)
        prob = bh.probation_of(self.uat())                # a Probation bundle can never be derived again
        again = self.client.post(self.bundle_url(prob, "core:bundle_derive_probation"), {"confirm": "on"})
        self.assertTrue(again["Location"].endswith("PROBATION_REFUSED"))
        self.assertEqual(models.ConfigurationBundle.objects.filter(kind="PROBATION").count(), 1)


class HistoricalReadOnlyTests(BundleViewFixture):
    def test_a_bundle_page_offers_no_edit_or_delete_and_no_route_creates_golden(self):
        uat = self.uat()
        prob = bh.probation_of(uat)
        golden = bh.golden_from(prob)
        for bundle, expected_forms in ((uat, 0), (prob, 0), (golden, 0)):     # neither has a derive form: UAT already has its Probation child
            with self.subTest(bundle=bundle.bundle_id):
                html = self.client.get(self.bundle_url(bundle)).content.decode()
                actions = [a for a in re.findall(r'<form[^>]*action="([^"]+)"', html) if "/bundles/" in a or "/bundle/" in a]
                self.assertEqual(len(actions), expected_forms)
                self.assertNotRegex(html, r'(?i)name="(payload|kind|parent|digest|manifest|bundle_digest|payload_digest)"')
                self.assertNotRegex(html.lower(), r"(edit|delete) bundle|promote to golden")
        self.assertContains(self.client.get(self.bundle_url(golden)), "Golden bundle")         # a Golden bundle renders structurally
        from django.urls import get_resolver

        for path in ("/device-builder/bundles/BND-PROB-000001/golden/", "/device-builder/bundles/BND-PROB-000001/promote/",
                     "/device-builder/bundles/BND-PROB-000001/probation/golden/", "/device-builder/bundles/golden/", "/device-builder/bundles/create/",
                     "/device-builder/bundles/BND-UAT-000001/delete/", "/device-builder/bundles/BND-UAT-000001/edit/"):
            with self.subTest(path=path):   # 404 (no such route) or 405 (it is the GET-only bundle page): never a success, never a creation
                self.assertIn(self.client.post(path, {"confirm": "on", "kind": "GOLDEN"}).status_code, (404, 405))
        names = {p.name for p in get_resolver().url_patterns if getattr(p, "name", None)}
        self.assertTrue({n for n in names if "golden" in n.lower()} == set())
        self.assertEqual(models.ConfigurationBundle.objects.filter(kind="GOLDEN").count(), 1, "only the factory-made bundle exists")

    def test_a_tampered_bundle_is_shown_as_failed_prominently_and_offers_no_derivation(self):
        uat = self.uat()
        row = models.ConfigurationBundleItem.objects.filter(bundle=uat).first()
        bh.oob(models.ConfigurationBundleItem).filter(pk=row.pk).update(payload="<script>alert(1)</script>")
        html = self.client.get(self.bundle_url(uat)).content.decode()
        self.assertIn("INTEGRITY: FAILED", html)
        self.assertIn("ITEM_PAYLOAD_HASH_MISMATCH", html)
        self.assertNotIn("<script>alert(1)</script>", html)          # untrusted text is escaped
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("Create Probation bundle</button>", html)
        self.assertIn("SOURCE_INTEGRITY_FAILED", html)
        refused = self.client.post(self.bundle_url(uat, "core:bundle_derive_probation"), {"confirm": "on"})
        self.assertTrue(refused["Location"].endswith("PROBATION_REFUSED"))
        self.assertEqual(models.AuditEvent.objects.filter(event_type="BUNDLE_INTEGRITY_FAILED").count(), 1)
        self.assertEqual(self.client.get(self.bundle_url(uat, "core:bundle_manifest")).status_code, 200)   # only an item row was altered: the manifest is intact


class ListAndExportTests(BundleViewFixture):
    def test_the_list_filters_by_kind_and_change_and_never_verifies_per_row(self):
        uat = self.uat()
        prob = bh.probation_of(uat)
        other = self.uat(self.unverified_pk)
        base = reverse("core:bundles_list")
        self.assertEqual(self.client.get(base + "?kind=UAT").context["bundles"], [other, uat])
        self.assertEqual(self.client.get(base + "?kind=PROBATION").context["bundles"], [prob])
        self.assertEqual(self.client.get(f"{base}?change={self.change_id}").context["bundles"], [prob, uat])
        self.assertEqual(len(self.client.get(base + "?kind=NOT_A_KIND").context["bundles"]), 3)     # an unknown filter is ignored, never an error
        html = self.client.get(base).content.decode()
        for needle in (uat.bundle_id, prob.bundle_id, self.change_id, uat.payload_digest[:12], "Verify on open"):
            self.assertIn(needle, html)
        self.assertNotIn("INTEGRITY: INTACT", html)
        self.assertEqual(models.ConfigurationBundle.objects.count(), 3)

    def test_the_manifest_download_is_deterministic_verifiable_and_read_only(self):
        prob = bh.probation_of(self.uat())
        before = bh.table_counts()
        first = self.client.get(self.bundle_url(prob, "core:bundle_manifest"))
        second = self.client.get(self.bundle_url(prob, "core:bundle_manifest"))
        self.assertEqual((first.status_code, first.content, first["Content-Type"]), (200, second.content, "application/json; charset=utf-8"))
        self.assertEqual(first["Content-Disposition"], 'attachment; filename="BND-PROB-000001.manifest.json"')
        self.assertEqual(first["X-Content-Type-Options"], "nosniff")
        self.assertEqual(first.content.decode(), bs.export_json(prob))
        self.assertTrue(bs.verify_export(first.content).ok)
        self.assertEqual(bh.count_changes(before, bh.table_counts()), {})

    def test_a_manifest_that_turned_secret_shaped_is_refused_with_409(self):
        uat = self.uat()
        manifest = json.loads(json.dumps(uat.manifest))
        manifest["payload"]["items"][0]["payload"] = "username admin secret hunter2"
        bh.oob(models.ConfigurationBundle).filter(pk=uat.pk).update(manifest=manifest)
        response = self.client.get(self.bundle_url(uat, "core:bundle_manifest"))
        self.assertEqual(response.status_code, 409)
        self.assertNotIn(b"hunter2", response.content)
