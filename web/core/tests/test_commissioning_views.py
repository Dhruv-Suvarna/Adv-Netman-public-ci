"""V2 Phases 5 / 6 pages and actions: RBAC per step, CSRF, separation of requester and approver, refusal codes on the redirect,
read-only pages and the absence of any secret.  The trusted upstream is the in-memory cEOS of ``helpers.isolation`` driven by
the real CeosExecutor (``isolation.default_access`` is replaced); no device or host is contacted."""

from __future__ import annotations

from unittest import mock

from django.test import TestCase, override_settings
from django.urls import reverse

from core import models
from core.services.commissioning import service as C
from core.services.identity import policy
from core.services.isolation import service as iso
from core.tests.helpers import isolation as I
from core.tests.helpers import lifecycle as L
from core.tests.helpers import ztp as Z
from core.tests.test_lifecycle_views import user_client

A = policy.Action
MUTATIONS = {
    "isolation_require": A.EDIT, "isolation_plan": A.EDIT, "commissioning_open": A.EDIT, "dependency_add": A.EDIT, "admission_plan": A.EDIT,
    "isolation_precheck": A.VALIDATE, "isolation_verify": A.VALIDATE, "isolation_drift": A.VALIDATE, "commissioning_assess": A.VALIDATE,
    "commissioning_record": A.VALIDATE, "admission_precheck": A.VALIDATE,
    "isolation_approve": A.APPROVE, "isolation_cancel": A.APPROVE, "isolation_reconcile": A.APPROVE, "commissioning_approve": A.APPROVE,
    "commissioning_abort": A.APPROVE, "commissioning_reconcile": A.APPROVE, "dependency_remove": A.APPROVE, "admission_approve": A.APPROVE,
    "admission_cancel": A.APPROVE, "admission_reconcile": A.APPROVE,
    "isolation_apply": A.EXECUTE, "admission_execute": A.EXECUTE,
}
READS = {"commissioning_overview", "commissioning_device", "commissioning_device_json"}
EXPECT = {"routing": "OSPF", "ospf_neighbors": "10.255.0.9", "routes_v4": "10.9.0.0/16", "reachable": "10.9.0.1"}


class PolicyTests(TestCase):
    def test_every_commissioning_route_carries_the_permission_of_its_step(self):
        for name, action in MUTATIONS.items():
            with self.subTest(name):
                self.assertEqual(policy.MUTATION_ROUTES[name], action)
        self.assertTrue(READS <= policy.READ_ROUTES)
        self.assertIn("commissioning_device_json", policy.SENSITIVE_READ_ROUTES)

    def test_no_commissioning_page_is_a_mutation_or_unclassified(self):
        self.assertFalse(READS & set(policy.MUTATION_ROUTES))
        self.assertFalse(set(MUTATIONS) & policy.READ_ROUTES)


@override_settings(NMAS_ADMISSION_SETTLE_SECONDS=0)
class ViewTests(Z.ZtpTestMixin, TestCase):
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

    def test_pages_are_read_only_and_show_no_secret(self):
        self.flow().verified()
        before = (models.IsolationPolicy.objects.count(), models.DeviceLifecycleEvent.objects.count(), list(self.f.session.sent))
        page = self.viewer.get(self.url("commissioning_device"))
        self.assertContains(page, self.f.policy.policy_id)
        self.assertContains(page, "VERIFIED")
        self.assertContains(page, self.f.policy.plan_hash)
        overview = self.viewer.get(reverse("core:commissioning_overview"))
        self.assertContains(overview, "Trusted-upstream isolation")
        self.assertContains(overview, self.device.name)
        data = self.viewer.get(self.url("commissioning_device_json")).json()
        self.assertEqual(data["policies"][0]["state"], "VERIFIED")
        for body in (page.content, overview.content, str(data).encode()):
            self.assertNotIn(b"PRIVATE KEY", body)
            self.assertNotIn(b"secret", body.lower())
        self.assertEqual(before, (models.IsolationPolicy.objects.count(), models.DeviceLifecycleEvent.objects.count(), list(self.f.session.sent)))

    def test_unknown_policy_record_and_admission_are_not_found(self):
        self.flow()
        self.assertEqual(self.operator.post(self.url("isolation_plan", "ISO-999999")).status_code, 404)
        self.assertEqual(self.operator.post(self.url("commissioning_assess", "COM-999999")).status_code, 404)
        self.assertEqual(self.approver.post(self.url("admission_approve", "ADM-999999")).status_code, 404)
        self.assertEqual(self.approver.post(self.url("dependency_remove", "999999"), {"reason": "x"}).status_code, 404)

    def test_isolation_steps_need_their_role_and_a_different_approver(self):
        self.flow()
        data = {"attachment_id": self.f.attachment.pk, "network": self.f.network.name}
        self.assertEqual(self.viewer.post(self.url("isolation_require"), data).status_code, 403)
        self.assertEqual(self.codes(self.operator.post(self.url("isolation_require"), data)), [])
        policy_row = models.IsolationPolicy.objects.get(device=self.device)
        pid = policy_row.policy_id
        self.assertEqual(self.codes(self.operator.post(self.url("isolation_plan", pid))), [])
        self.assertEqual(self.codes(self.operator.post(self.url("isolation_precheck", pid))), [])
        policy_row.refresh_from_db()
        confirm = {"confirmation": policy_row.plan_hash}
        self.assertEqual(self.operator.post(self.url("isolation_approve", pid), confirm).status_code, 403)   # not an approver
        self.assertEqual(self.codes(self.approver.post(self.url("isolation_approve", pid), {"confirmation": "0" * 64})),
                         ["ISOLATION_CONFIRMATION_MISMATCH"])
        self.assertEqual(self.codes(self.approver.post(self.url("isolation_approve", pid), confirm)), [])
        self.assertEqual(self.approver.post(self.url("isolation_apply", pid), confirm).status_code, 403)    # not an executor
        self.assertEqual(self.codes(self.executor.post(self.url("isolation_apply", pid), confirm)), [])
        policy_row.refresh_from_db()
        self.assertEqual(policy_row.state, models.IsolationState.ENFORCED)
        self.assertIn("NMAS-ISO-", self.f.session.config.text())
        # verification from the page has no traffic probe: it never claims VERIFIED
        self.f.counters()
        self.assertEqual(self.codes(self.operator.post(self.url("isolation_verify", pid))), [])
        policy_row.refresh_from_db()
        self.assertEqual((policy_row.state, policy_row.failure), (models.IsolationState.ENFORCED, {"code": "ISOLATION_TRAFFIC_UNVERIFIED"}))
        self.assertEqual(self.codes(self.operator.post(self.url("isolation_drift", pid))), [])
        policy_row.refresh_from_db()
        self.assertEqual(policy_row.state, models.IsolationState.ENFORCED)

    def test_isolation_cancel_needs_a_reason_and_is_not_offered_to_an_operator(self):
        self.flow().required()
        pid = self.f.policy.policy_id
        self.assertEqual(self.operator.post(self.url("isolation_cancel", pid), {"reason": "no"}).status_code, 403)
        self.assertNotEqual(self.codes(self.approver.post(self.url("isolation_cancel", pid), {"reason": ""})), [])
        self.assertEqual(self.codes(self.approver.post(self.url("isolation_cancel", pid), {"reason": "re-cabled"})), [])

    def test_post_without_csrf_token_is_refused(self):
        self.flow().required()
        strict = user_client("oscar", "NMAS Operator", csrf=True)
        self.assertEqual(strict.post(self.url("isolation_plan", self.f.policy.policy_id)).status_code, 403)
        self.assertEqual(strict.post(self.url("commissioning_open")).status_code, 403)
        self.f.refresh()
        self.assertEqual(self.f.policy.state, models.IsolationState.REQUIRED)

    def test_get_on_a_mutation_route_is_not_allowed(self):
        self.flow().required()
        self.assertEqual(self.operator.get(self.url("isolation_plan", self.f.policy.policy_id)).status_code, 405)
        self.assertEqual(self.operator.get(self.url("commissioning_open")).status_code, 405)

    def test_commissioning_open_refuses_a_device_that_is_not_isolated(self):
        self.flow().verified()
        codes = self.codes(self.operator.post(self.url("commissioning_open")))
        self.assertIn("COMMISSIONING_DEVICE_NOT_ISOLATED", codes)
        self.assertFalse(models.CommissioningRecord.objects.exists())
        page = self.viewer.get(self.url("commissioning_device") + "?codes=" + ",".join(codes))
        self.assertContains(page, "COMMISSIONING_DEVICE_NOT_ISOLATED")

    def commissioned(self):
        self.flow().ready_for_commissioning()
        self.assertEqual(self.codes(self.operator.post(self.url("commissioning_open"))), [])
        record = models.CommissioningRecord.objects.get(device=self.device)
        self.lab = I.commissioning_lab(record.provisioning_run)
        I.candidate_ready(self.lab)
        self.assertEqual(self.codes(self.operator.post(self.url("commissioning_assess", record.commissioning_id))), [])
        record.refresh_from_db()
        self.assertEqual(record.state, models.CommissioningState.READY)
        return record

    def test_commissioning_approval_needs_a_different_approver_and_the_exact_digest(self):
        record = self.commissioned()
        cid = record.commissioning_id
        confirm = {"confirmation": record.evidence_digest}
        self.assertEqual(self.operator.post(self.url("commissioning_approve", cid), confirm).status_code, 403)
        self.assertEqual(self.codes(self.approver.post(self.url("commissioning_approve", cid), {"confirmation": "f" * 64})),
                         ["COMMISSIONING_CONFIRMATION_MISMATCH"])
        both = user_client("pat", "NMAS Operator", "NMAS Approver")
        # the requester can never approve, whatever the role
        models.CommissioningRecord.objects.filter(pk=record.pk).update(requested_by="pat")
        self.assertEqual(self.codes(both.post(self.url("commissioning_approve", cid), confirm)), ["COMMISSIONING_SELF_APPROVAL"])
        models.CommissioningRecord.objects.filter(pk=record.pk).update(requested_by=L.OPERATOR)
        self.assertEqual(self.codes(self.approver.post(self.url("commissioning_approve", cid), confirm)), [])
        record.refresh_from_db()
        self.device.refresh_from_db()
        self.assertEqual((record.state, record.approved_by, self.device.lifecycle_state),
                         (models.CommissioningState.APPROVED, L.APPROVER, models.DeviceLifecycleState.COMMISSIONING))

    def test_commissioning_abort_returns_the_device_to_isolated(self):
        record = self.commissioned()
        cid = record.commissioning_id
        self.assertEqual(self.operator.post(self.url("commissioning_abort", cid), {"reason": "x"}).status_code, 403)
        self.assertEqual(self.codes(self.approver.post(self.url("commissioning_abort", cid), {"reason": "postponed"})), [])
        record.refresh_from_db()
        self.device.refresh_from_db()
        self.assertEqual((record.state, self.device.lifecycle_state), (models.CommissioningState.ABORTED, models.DeviceLifecycleState.ISOLATED))

    def test_dependency_add_refuses_a_cycle_and_remove_needs_an_approver(self):
        self.flow()
        other = L.register("CORE-Z", serial="SN-CORE-Z", mac="00:1c:73:00:02:01").device
        self.assertEqual(self.codes(self.operator.post(self.url("dependency_add"), {"upstream_id": other.pk, "kind": "DECLARED", "reason": "r"})), [])
        back = reverse("core:dependency_add", args=[other.device_id])
        self.assertEqual(self.codes(self.operator.post(back, {"upstream_id": self.device.pk, "kind": "DECLARED"})), ["COMMISSIONING_DEPENDENCY_CYCLE"])
        row = models.CommissioningDependency.objects.get(device=self.device)
        self.assertContains(self.viewer.get(self.url("commissioning_device")), "CORE-Z")
        self.assertEqual(self.operator.post(self.url("dependency_remove", row.pk), {"reason": "x"}).status_code, 403)
        self.assertEqual(self.codes(self.approver.post(self.url("dependency_remove", row.pk), {"reason": "re-cabled"})), [])
        row.refresh_from_db()
        self.assertEqual(row.state, models.DependencyState.REMOVED)

    def test_admission_through_the_pages_releases_isolation_and_admits(self):
        record = self.commissioned()
        cid = record.commissioning_id
        self.assertEqual(self.codes(self.approver.post(self.url("commissioning_approve", cid), {"confirmation": record.evidence_digest})), [])
        self.assertTrue(self.lab.provision(actor=L.APPROVER).ok)
        self.assertEqual(self.codes(self.operator.post(self.url("commissioning_record", cid))), [])
        record.refresh_from_db()
        self.assertEqual(record.state, models.CommissioningState.CONFIGURED)
        self.assertEqual(self.codes(self.operator.post(self.url("admission_plan", cid), {**EXPECT, "routing": "BGP"})),
                         ["ADMISSION_EXPECTATIONS_INVALID"])
        self.assertEqual(self.codes(self.operator.post(self.url("admission_plan", cid), EXPECT)), [])
        admission = models.ProductionAdmission.objects.get(device=self.device)
        aid = admission.admission_id
        self.assertEqual(self.codes(self.operator.post(self.url("admission_precheck", aid))), [])
        admission.refresh_from_db()
        confirm = {"confirmation": admission.evidence_digest}
        self.assertEqual(self.operator.post(self.url("admission_approve", aid), confirm).status_code, 403)
        self.assertEqual(self.codes(self.approver.post(self.url("admission_approve", aid), confirm)), [])
        self.assertEqual(self.approver.post(self.url("admission_execute", aid)).status_code, 403)
        I.admitted_outputs(self.f.session)
        self.assertEqual(self.codes(self.executor.post(self.url("admission_execute", aid))), [])
        admission.refresh_from_db()
        self.device.refresh_from_db()
        self.assertEqual((admission.state, self.device.lifecycle_state, self.device.admission_state),
                         (models.AdmissionState.ADMITTED, models.DeviceLifecycleState.IN_SERVICE, models.ProductionAdmissionState.ADMITTED))
        self.assertNotIn("NMAS-ISO-", self.f.session.config.text())
        page = self.viewer.get(self.url("commissioning_device"))
        self.assertContains(page, "ADMITTED")
        self.assertContains(page, "NSOT")

    def test_admission_plan_record_and_reconcile_refuse_the_wrong_state(self):
        record = self.commissioned()
        self.assertIn("ADMISSION_STATE_INVALID", self.codes(self.operator.post(self.url("admission_plan", record.commissioning_id), EXPECT)))
        self.assertFalse(models.ProductionAdmission.objects.exists())
        self.assertEqual(self.codes(self.operator.post(self.url("commissioning_record", record.commissioning_id))),
                         ["COMMISSIONING_STATE_INVALID"])
        self.assertEqual(self.codes(self.approver.post(self.url("commissioning_reconcile", record.commissioning_id))),
                         ["COMMISSIONING_STATE_INVALID"])
        self.assertEqual(C.get_record(record.pk).state, models.CommissioningState.READY)
