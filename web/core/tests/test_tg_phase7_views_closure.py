"""Test-governance closure for the V2 Phase 7 pages and actions (``core.decommission_views``): every view driven through the Django
test client by a user holding its role, once accepted and once refused (unknown row, wrong state, wrong confirmation, anonymous),
plus the view helpers called directly.  The runtime is the in-memory cEOS session and fake observer of ``helpers.decommission``."""

from __future__ import annotations

from unittest import mock

from django.http import Http404
from django.test import Client, TestCase
from django.urls import reverse

from core import decommission_views as V
from core import models
from core.services.decommission import service as svc
from core.tests.helpers import decommission as H
from core.tests.helpers import lifecycle as L
from core.tests.test_lifecycle_views import user_client

D, R = models.DecommissionState, models.RestorationState


class Base(TestCase):
    def setUp(self):
        self.device = L.adopt("R1", role="router").device
        self.fake = H.session()
        self.runtime = H.runtime(self.fake, H.FakeObserver(H.observation(active=False)))
        patcher = mock.patch.object(V.decommission, "configured_runtime", return_value=self.runtime)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.operator = user_client(L.OPERATOR, "NMAS Operator")
        self.approver = user_client(L.APPROVER, "NMAS Approver")
        self.executor = user_client("erin", "NMAS Executor")

    def url(self, name, *args):
        return reverse(f"core:{name}", args=[self.device.device_id, *args])

    def codes(self, response):
        self.assertEqual(response.status_code, 302)
        return response.url.split("codes=")[1].split("&")[0].split("%2C") if "codes=" in response.url else []

    def requested(self):
        self.assertEqual(self.codes(self.operator.post(self.url("decommission_request"), {"reason": "retire R1"})), [])
        return models.DecommissionRecord.objects.get(device=self.device)

    def ready(self):
        record = self.requested()
        self.assertEqual(self.codes(self.operator.post(self.url("decommission_evaluate", record.record_id))), [])
        record.refresh_from_db()
        return record

    def approved(self):
        record = self.ready()
        self.assertEqual(self.codes(self.approver.post(self.url("decommission_approve", record.record_id), {"confirmation": record.plan_hash})), [])
        record.refresh_from_db()
        return record

    def decommissioned(self):
        record = self.approved()
        self.assertEqual(self.codes(self.executor.post(self.url("decommission_execute", record.record_id), {"confirmation": record.plan_hash})), [])
        record.refresh_from_db()
        return record

    def restoration(self):
        record = self.decommissioned()
        self.assertEqual(self.codes(self.operator.post(self.url("restoration_request", record.record_id))), [])
        return models.RestorationRecord.objects.get(decommission=record)

    def planned(self):
        row = self.restoration()
        self.assertEqual(self.codes(self.operator.post(self.url("restoration_check", row.record_id))), [])
        row.refresh_from_db()
        return row

    def restore_approved(self):
        row = self.planned()
        self.assertEqual(self.codes(self.approver.post(self.url("restoration_approve", row.record_id), {"confirmation": row.plan_hash})), [])
        row.refresh_from_db()
        return row


class PageClosureTests(Base):
    def test_decommission_overview_lists_records(self):
        self.requested()
        response = self.operator.get(reverse("core:decommission_overview"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "DCM-")

    def test_decommission_overview_empty_without_records(self):
        response = self.operator.get(reverse("core:decommission_overview"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "DCM-")

    def test_decommission_overview_refuses_anonymous(self):
        response = Client().get(reverse("core:decommission_overview"))
        self.assertNotEqual(response.status_code, 200)

    def test_decommission_device_page_shows_the_record(self):
        record = self.ready()
        response = self.operator.get(self.url("decommission_device"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, record.plan_hash)
        self.assertNotContains(response, "PRIVATE KEY")

    def test_decommission_device_page_unknown_device_is_404(self):
        self.assertEqual(self.operator.get(reverse("core:decommission_device", args=["DEV-999999"])).status_code, 404)

    def test_view_helpers_resolve_records_and_url(self):
        row = self.restoration()
        record = row.decommission
        self.assertEqual(V._record_or_404(self.device, record.record_id), record)  # pylint: disable=protected-access
        self.assertTrue(V._device_url(self.device).endswith(f"/{self.device.device_id}/"))  # pylint: disable=protected-access
        self.assertEqual(V._restoration_or_404(self.device, row.record_id), row)  # pylint: disable=protected-access

    def test_view_helpers_refuse_unknown_records(self):
        other = L.adopt("R2", role="router").device
        record = self.requested()
        with self.assertRaises(Http404):
            V._record_or_404(other, record.record_id)  # pylint: disable=protected-access
        with self.assertRaises(Http404):
            V._record_or_404(self.device, "DCM-999999")  # pylint: disable=protected-access
        with self.assertRaises(Http404):
            V._restoration_or_404(self.device, "RST-999999")  # pylint: disable=protected-access
        self.assertNotIn("DEV-999999", V._device_url(self.device))  # pylint: disable=protected-access


class DecommissionActionClosureTests(Base):
    def test_decommission_request_records_the_intent(self):
        self.assertEqual(self.requested().state, D.REQUESTED)

    def test_decommission_request_refuses_missing_reason(self):
        self.assertEqual(self.codes(self.operator.post(self.url("decommission_request"), {"reason": ""})), ["REASON_REQUIRED"])

    def test_decommission_evaluate_reaches_ready(self):
        self.assertEqual(self.ready().state, D.READY)

    def test_decommission_evaluate_unknown_record_is_404(self):
        self.assertEqual(self.operator.post(self.url("decommission_evaluate", "DCM-999999")).status_code, 404)

    def test_decommission_approve_binds_the_plan(self):
        self.assertEqual(self.approved().state, D.APPROVED)

    def test_decommission_approve_refuses_wrong_confirmation(self):
        record = self.ready()
        found = self.codes(self.approver.post(self.url("decommission_approve", record.record_id), {"confirmation": "x"}))
        self.assertIn("DECOMMISSION_CONFIRMATION_MISMATCH", found)

    def test_decommission_execute_retires_the_device(self):
        record = self.decommissioned()
        self.assertEqual(record.state, D.DECOMMISSIONED)
        self.assertEqual(models.ManagedDevice.objects.get(pk=self.device.pk).lifecycle_state, models.DeviceLifecycleState.DECOMMISSIONED)

    def test_decommission_execute_refuses_wrong_confirmation(self):
        record = self.approved()
        found = self.codes(self.executor.post(self.url("decommission_execute", record.record_id), {"confirmation": "x"}))
        self.assertIn("DECOMMISSION_CONFIRMATION_MISMATCH", found)

    def test_decommission_cancel_closes_the_record(self):
        record = self.requested()
        self.assertEqual(self.codes(self.approver.post(self.url("decommission_cancel", record.record_id))), [])
        record.refresh_from_db()
        self.assertEqual(record.state, D.CANCELLED)

    def test_decommission_cancel_refuses_a_closed_record(self):
        record = self.requested()
        self.approver.post(self.url("decommission_cancel", record.record_id))
        self.assertEqual(self.codes(self.approver.post(self.url("decommission_cancel", record.record_id))), ["DECOMMISSION_STATE_INVALID"])

    def test_decommission_reconcile_returns_an_uncertain_record_to_baseline(self):
        record = self.approved()
        models.DecommissionRecord.objects.filter(pk=record.pk).update(state=D.UNCERTAIN)
        self.assertEqual(self.codes(self.approver.post(self.url("decommission_reconcile", record.record_id))), [])
        record.refresh_from_db()
        self.assertEqual(record.state, D.ROLLED_BACK)

    def test_decommission_reconcile_refuses_a_ready_record(self):
        record = self.ready()
        self.assertEqual(self.codes(self.approver.post(self.url("decommission_reconcile", record.record_id))), ["DECOMMISSION_STATE_INVALID"])


class RestorationActionClosureTests(Base):
    def test_restoration_request_opens_a_restoration(self):
        self.assertEqual(self.restoration().state, R.REQUESTED)

    def test_restoration_request_refuses_an_open_decommission(self):
        record = self.ready()
        self.assertEqual(self.codes(self.operator.post(self.url("restoration_request", record.record_id))), ["RESTORATION_STATE_INVALID"])

    def test_restoration_check_plans_it(self):
        self.assertEqual(self.planned().state, R.PLANNED)

    def test_restoration_check_unknown_record_is_404(self):
        self.assertEqual(self.operator.post(self.url("restoration_check", "RST-999999")).status_code, 404)

    def test_restoration_approve_binds_the_plan(self):
        self.assertEqual(self.restore_approved().state, R.APPROVED)

    def test_restoration_approve_refuses_wrong_confirmation(self):
        row = self.planned()
        found = self.codes(self.approver.post(self.url("restoration_approve", row.record_id), {"confirmation": "x"}))
        self.assertIn("DECOMMISSION_CONFIRMATION_MISMATCH", found)

    def test_restoration_execute_restores_the_device(self):
        row = self.restore_approved()
        self.assertEqual(self.codes(self.executor.post(self.url("restoration_execute", row.record_id), {"confirmation": row.plan_hash})), [])
        row.refresh_from_db()
        self.assertEqual(row.state, R.RESTORED)
        self.assertEqual(row.successor.origin, models.DeviceOrigin.RESTORED)

    def test_restoration_execute_refuses_wrong_confirmation(self):
        row = self.restore_approved()
        found = self.codes(self.executor.post(self.url("restoration_execute", row.record_id), {"confirmation": "x"}))
        self.assertIn("DECOMMISSION_CONFIRMATION_MISMATCH", found)

    def test_restoration_cancel_closes_it(self):
        row = self.restoration()
        self.assertEqual(self.codes(self.approver.post(self.url("restoration_cancel", row.record_id))), [])
        row.refresh_from_db()
        self.assertEqual(row.state, R.CANCELLED)

    def test_restoration_cancel_refuses_a_closed_restoration(self):
        row = self.restoration()
        self.approver.post(self.url("restoration_cancel", row.record_id))
        self.assertEqual(self.codes(self.approver.post(self.url("restoration_cancel", row.record_id))), ["RESTORATION_STATE_INVALID"])


class RouteContractTests(TestCase):
    def test_every_phase7_route_is_classified(self):
        from core.services.identity import policy

        for name in ("decommission_request", "decommission_evaluate", "decommission_approve", "decommission_execute", "decommission_cancel",
                     "decommission_reconcile", "restoration_request", "restoration_check", "restoration_approve", "restoration_execute",
                     "restoration_cancel", "infrastructure_dispatch"):
            self.assertIn(name, policy.MUTATION_ROUTES)
        for name in ("decommission_overview", "decommission_device", "infrastructure_overview", "infrastructure_json"):
            self.assertIn(name, policy.READ_ROUTES)
        self.assertNotEqual(svc.KIND, svc.RESTORE_KIND)
