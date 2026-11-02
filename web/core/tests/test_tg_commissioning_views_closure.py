"""Test-governance closure for the V2 Phases 5 / 6 pages and actions (``core.commissioning_views``): every view driven through the
Django test client by a user holding its role, once accepted and once refused (a wrong state, a wrong confirmation or an unknown
row), plus ``device_context`` called directly.  Same in-memory upstream and real cEOS executor as ``test_commissioning_views``."""

from __future__ import annotations

from unittest import mock

from django.test import TestCase, override_settings
from django.urls import reverse

from core import commissioning_views as V
from core import models
from core.services.commissioning import admission as A
from core.services.commissioning import service as C
from core.services.isolation import service as iso
from core.tests.helpers import isolation as I
from core.tests.helpers import lifecycle as L
from core.tests.helpers import ztp as Z
from core.tests.test_lifecycle_views import user_client

EXPECT = {"routing": "OSPF", "ospf_neighbors": "10.255.0.9", "routes_v4": "10.9.0.0/16", "reachable": "10.9.0.1"}
SERVICE_EXPECT = {"routing": "OSPF", "ospf_neighbors": ["10.255.0.9"], "routes_v4": ["10.9.0.0/16"], "reachable": ["10.9.0.1"]}


@override_settings(NMAS_ADMISSION_SETTLE_SECONDS=0)
class Base(Z.ZtpTestMixin, TestCase):
    real_isolation_gate = True

    def setUp(self):
        super().setUp()
        self.operator = user_client(L.OPERATOR, "NMAS Operator")
        self.approver = user_client(L.APPROVER, "NMAS Approver")
        self.executor = user_client("erin", "NMAS Executor")
        self.viewer = user_client("vera", "NMAS Viewer")

    def flow(self):
        self.f = I.Flow(self)
        patcher = mock.patch.object(iso, "default_access", return_value=self.f.access)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.device = self.f.device
        return self.f

    def url(self, name, *args):
        return reverse(f"core:{name}", args=[self.device.device_id, *args])

    def codes(self, response):
        self.assertEqual(response.status_code, 302)
        return response.url.split("codes=")[1].split("&")[0].split("%2C") if "codes=" in response.url else []

    def commissioned(self):
        self.flow().ready_for_commissioning()
        self.assertEqual(self.codes(self.operator.post(self.url("commissioning_open"))), [])
        record = models.CommissioningRecord.objects.get(device=self.device)
        self.lab = I.commissioning_lab(record.provisioning_run)
        I.candidate_ready(self.lab)
        self.assertEqual(self.codes(self.operator.post(self.url("commissioning_assess", record.commissioning_id))), [])
        record.refresh_from_db()
        return record

    def configured(self):
        record = self.commissioned()
        self.assertEqual(self.codes(self.approver.post(self.url("commissioning_approve", record.commissioning_id),
                                                       {"confirmation": record.evidence_digest})), [])
        self.assertTrue(self.lab.provision(actor=L.APPROVER).ok)
        self.assertEqual(self.codes(self.operator.post(self.url("commissioning_record", record.commissioning_id))), [])
        record.refresh_from_db()
        return record


class PageClosureTests(Base):
    def test_pages(self):
        self.flow().verified()
        with self.subTest("renders the overview, the device page, its JSON and its context"):
            self.assertContains(self.viewer.get(reverse("core:commissioning_overview")), self.device.name)
            self.assertContains(self.viewer.get(self.url("commissioning_device")), self.f.policy.policy_id)
            self.assertEqual(self.viewer.get(self.url("commissioning_device_json")).json()["policies"][0]["state"], "VERIFIED")
            found = V.device_context(self.device)
            self.assertEqual((found["policy"].pk, found["record"], found["admission"]), (self.f.policy.pk, None, None))
        with self.subTest("refuses an unknown device and shows the refusal codes of a refused step"):
            self.assertEqual(self.viewer.get(reverse("core:commissioning_device", args=["DEV-999999"])).status_code, 404)
            self.assertEqual(self.viewer.get(reverse("core:commissioning_device_json", args=["DEV-999999"])).status_code, 404)
            self.assertContains(self.viewer.get(reverse("core:commissioning_overview") + "?codes=ISOLATION_DRIFTED"), "ISOLATION_DRIFTED")
            empty = V.device_context(L.register("NEW2", serial="SN-NEW2", mac="00:1c:73:00:00:02").device)
            self.assertEqual((empty["policy"], empty["policies"], empty["outbox"]), (None, [], []))


class IsolationViewClosureTests(Base):
    def test_isolation_views(self):
        self.flow()
        data = {"attachment_id": self.f.attachment.pk, "network": self.f.network.name}
        unknown = "ISO-999999"
        with self.subTest("accepts require, plan, precheck, approve, apply, verify and drift"):
            self.assertEqual(self.codes(self.operator.post(self.url("isolation_require"), data)), [])
            pid = models.IsolationPolicy.objects.get(device=self.device).policy_id
            self.assertEqual(self.codes(self.operator.post(self.url("isolation_plan", pid))), [])
            self.assertEqual(self.codes(self.operator.post(self.url("isolation_precheck", pid))), [])
            confirm = {"confirmation": iso.get_policy(pid).plan_hash}
            self.assertEqual(self.codes(self.approver.post(self.url("isolation_approve", pid), confirm)), [])
            self.assertEqual(self.codes(self.executor.post(self.url("isolation_apply", pid), confirm)), [])
            self.f.counters()
            self.assertEqual(self.codes(self.operator.post(self.url("isolation_verify", pid))), [])
            self.assertEqual(self.codes(self.operator.post(self.url("isolation_drift", pid))), [])
            self.assertEqual(iso.get_policy(pid).state, models.IsolationState.ENFORCED)
        with self.subTest("refuses a duplicate, unknown policies, a wrong confirmation and steps out of order"):
            self.assertIn("ISOLATION_EXISTS", self.codes(self.operator.post(self.url("isolation_require"), data)))
            for name in ("isolation_plan", "isolation_precheck", "isolation_verify", "isolation_drift"):
                self.assertEqual(self.operator.post(self.url(name, unknown)).status_code, 404)
            self.assertEqual(self.codes(self.approver.post(self.url("isolation_approve", pid), {"confirmation": "0" * 64})),
                             ["ISOLATION_STATE_INVALID"])
            self.assertEqual(self.codes(self.executor.post(self.url("isolation_apply", pid), confirm)), ["ISOLATION_STATE_INVALID"])
            self.assertEqual(self.codes(self.approver.post(self.url("isolation_reconcile", pid))), ["ISOLATION_STATE_INVALID"])
            self.assertEqual(self.codes(self.approver.post(self.url("isolation_cancel", pid), {"reason": "late"})), ["ISOLATION_STATE_INVALID"])
            self.assertEqual(iso.get_policy(pid).state, models.IsolationState.ENFORCED)

    def test_isolation_reconcile_view_succeeds_for_an_upstream_holding_the_policy(self):
        self.flow().enforced()
        iso._save(self.f.refresh(), state=models.IsolationState.UNCERTAIN)
        self.assertEqual(self.codes(self.approver.post(self.url("isolation_reconcile", self.f.policy.policy_id))), [])
        self.assertEqual(self.f.refresh().state, models.IsolationState.ENFORCED)

    def test_isolation_cancel_view_succeeds_before_anything_reached_the_upstream(self):
        self.flow().required()
        self.assertEqual(self.codes(self.approver.post(self.url("isolation_cancel", self.f.policy.policy_id), {"reason": "re-cabled"})), [])
        self.assertEqual(self.f.refresh().state, models.IsolationState.RELEASED)
        self.assertEqual(self.f.session.sent, [])


class CommissioningViewClosureTests(Base):
    def test_commissioning_and_admission_views(self):
        record = self.commissioned()
        cid = record.commissioning_id
        with self.subTest("refuses a second open, an unknown record, a wrong digest and a recording before execution"):
            self.assertIn("COMMISSIONING_OPEN_EXISTS", self.codes(self.operator.post(self.url("commissioning_open"))))
            self.assertEqual(self.operator.post(self.url("commissioning_assess", "COM-999999")).status_code, 404)
            self.assertEqual(self.codes(self.approver.post(self.url("commissioning_approve", cid), {"confirmation": "f" * 64})),
                             ["COMMISSIONING_CONFIRMATION_MISMATCH"])
            self.assertEqual(self.codes(self.approver.post(self.url("commissioning_reconcile", cid))), ["COMMISSIONING_STATE_INVALID"])
            self.assertEqual(self.codes(self.approver.post(self.url("commissioning_abort", cid), {"reason": ""})), ["COMMISSIONING_STATE_INVALID"])
            self.assertIn("ADMISSION_STATE_INVALID", self.codes(self.operator.post(self.url("admission_plan", cid), EXPECT)))
        with self.subTest("accepts the approval and reconciles the executed run to configured"):
            self.assertEqual(self.codes(self.approver.post(self.url("commissioning_approve", cid), {"confirmation": record.evidence_digest})), [])
            self.assertEqual(self.codes(self.operator.post(self.url("commissioning_record", cid))), ["COMMISSIONING_CONFIG_NOT_APPLIED"])
            self.assertTrue(self.lab.provision(actor=L.APPROVER).ok)
            self.assertEqual(self.codes(self.approver.post(self.url("commissioning_reconcile", cid))), [])
            self.assertEqual(C.get_record(record.pk).state, models.CommissioningState.CONFIGURED)
        with self.subTest("accepts plan, precheck, approval and execution of the admission"):
            self.assertEqual(self.codes(self.operator.post(self.url("admission_plan", cid), EXPECT)), [])
            aid = models.ProductionAdmission.objects.get(device=self.device).admission_id
            self.assertEqual(self.codes(self.operator.post(self.url("admission_precheck", aid))), [])
            confirm = {"confirmation": A.get_admission(aid).evidence_digest}
            self.assertEqual(self.codes(self.approver.post(self.url("admission_approve", aid), confirm)), [])
            I.admitted_outputs(self.f.session)
            self.assertEqual(self.codes(self.executor.post(self.url("admission_execute", aid))), [])
            self.assertEqual(A.get_admission(aid).state, models.AdmissionState.ADMITTED)
        with self.subTest("refuses every admission step once admitted and unknown admissions"):
            self.assertEqual(self.codes(self.executor.post(self.url("admission_execute", aid))), ["ADMISSION_STATE_INVALID"])
            self.assertEqual(self.codes(self.approver.post(self.url("admission_approve", aid), confirm)), ["ADMISSION_STATE_INVALID"])
            self.assertEqual(self.codes(self.approver.post(self.url("admission_cancel", aid), {"reason": "late"})), ["ADMISSION_STATE_INVALID"])
            self.assertEqual(self.codes(self.approver.post(self.url("admission_reconcile", aid))), ["ADMISSION_STATE_INVALID"])
            self.assertEqual(self.operator.post(self.url("admission_precheck", "ADM-999999")).status_code, 404)
            self.assertEqual(self.codes(self.operator.post(self.url("commissioning_record", cid))), ["COMMISSIONING_STATE_INVALID"])

    def test_commissioning_abort_view_succeeds_before_configuration(self):
        record = self.commissioned()
        self.assertEqual(self.codes(self.approver.post(self.url("commissioning_abort", record.commissioning_id), {"reason": "postponed"})), [])
        self.assertEqual(C.get_record(record.pk).state, models.CommissioningState.ABORTED)

    def test_commissioning_record_view_succeeds_after_the_run(self):
        record = self.configured()
        self.assertEqual(record.state, models.CommissioningState.CONFIGURED)

    def test_admission_cancel_and_reconcile_views_succeed_in_their_states(self):
        record = self.configured()
        self.assertEqual(self.codes(self.operator.post(self.url("admission_plan", record.commissioning_id), EXPECT)), [])
        first = models.ProductionAdmission.objects.get(device=self.device)
        self.assertEqual(self.codes(self.approver.post(self.url("admission_cancel", first.admission_id), {"reason": "window closed"})), [])
        self.assertEqual(A.get_admission(first.pk).state, models.AdmissionState.CANCELLED)
        planned = A.plan(C.get_record(record.pk), actor=L.OPERATOR, expectations=SERVICE_EXPECT).admission
        checked = A.precheck(planned, actor=L.OPERATOR, access=self.f.access).admission
        approved = A.approve(checked, actor=L.APPROVER, confirmation=checked.evidence_digest).admission
        releasing = A._save(approved, state=models.AdmissionState.RELEASING)            # a crash right after the write-ahead
        A._record_state(releasing.commissioning, models.CommissioningState.ADMITTING)
        iso._save(self.f.refresh(), state=models.IsolationState.RELEASE_PENDING)
        self.assertEqual(self.codes(self.approver.post(self.url("admission_reconcile", releasing.admission_id))), [])
        self.assertEqual(A.get_admission(releasing.pk).state, models.AdmissionState.RESTORED)


class DependencyViewClosureTests(Base):
    def test_dependency_views(self):
        self.flow()
        other = L.register("CORE-Z", serial="SN-CORE-Z", mac="00:1c:73:00:02:01").device
        with self.subTest("accepts a declared dependency and its removal with a reason"):
            self.assertEqual(self.codes(self.operator.post(self.url("dependency_add"), {"upstream_id": other.pk, "kind": "DECLARED", "reason": "r"})), [])
            row = models.CommissioningDependency.objects.get(device=self.device)
            back = reverse("core:dependency_add", args=[other.device_id])
        with self.subTest("refuses a cycle, a removal without a reason and an unknown dependency"):
            self.assertEqual(self.codes(self.operator.post(back, {"upstream_id": self.device.pk, "kind": "DECLARED"})), ["COMMISSIONING_DEPENDENCY_CYCLE"])
            self.assertEqual(self.codes(self.approver.post(self.url("dependency_remove", row.pk), {"reason": ""})), ["COMMISSIONING_DEPENDENCY_INVALID"])
            self.assertEqual(self.approver.post(self.url("dependency_remove", 999999), {"reason": "x"}).status_code, 404)
        with self.subTest("accepts the removal with a reason"):
            self.assertEqual(self.codes(self.approver.post(self.url("dependency_remove", row.pk), {"reason": "re-cabled"})), [])
            row.refresh_from_db()
            self.assertEqual(row.state, models.DependencyState.REMOVED)
