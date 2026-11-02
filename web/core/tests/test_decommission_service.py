"""V2 Phase 7 governed decommissioning and restoration, end to end over the REAL cEOS executor on an in-memory EOS session.

Traffic, alternates and the continuous measurement are scripted observations (``helpers.decommission``); the live proof of the
same workflow is the isolated fixture run (labs/decommission-isolated, docs/evidence/v2-phase7-9/phase7)."""

from __future__ import annotations

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from core import models
from core.services.decommission import service as svc
from core.tests.helpers import decommission as H
from core.tests.helpers import lifecycle as L

D, R, S = models.DecommissionState, models.RestorationState, models.DeviceLifecycleState
OPERATOR, APPROVER = L.OPERATOR, L.APPROVER


def adopted(name="R1"):
    return L.adopt(name, role="router").device


class DecommissionWorkflowTests(TestCase):
    def setUp(self):
        self.device = adopted()
        self.fake = H.session()

    def ready(self, *, active=True, probe=None, observer=None):
        observer = observer or H.FakeObserver(H.observation(active=active), H.observation(active=active),
                                              H.observation(active=active, on_device=False))
        runtime = H.runtime(self.fake, observer, probe=probe if probe is not None else H.FakeProbe())
        record = svc.request(self.device, actor=OPERATOR, reason="retire T1").record
        result = svc.evaluate(record, actor=OPERATOR, runtime=runtime)
        record.refresh_from_db()
        return record, runtime, result

    def test_redundant_transit_is_decommissioned_losslessly_and_retired(self):
        record, runtime, evaluated = self.ready()
        self.assertTrue(evaluated.ok, evaluated.codes)
        self.assertEqual(record.readiness_mode, models.DecommissionReadiness.REDUNDANT_TRANSITION)
        self.assertEqual([op["key"] for op in record.plan["transition"]], ["cost-out-ipv4", "cost-out-ipv6"])
        self.assertTrue(svc.approve(record, actor=APPROVER, confirmation=record.plan_hash).ok)
        record.refresh_from_db()
        executed = svc.execute(record, actor=APPROVER, confirmation=record.plan_hash, runtime=runtime)
        record.refresh_from_db()
        self.assertTrue(executed.ok, (executed.codes, executed.detail.get("report", {}).get("failure")))
        self.assertEqual(record.state, D.DECOMMISSIONED)
        self.device.refresh_from_db()
        self.assertEqual(self.device.lifecycle_state, S.DECOMMISSIONED)
        text = self.fake.config.text()
        self.assertNotIn("router ospf 1", text.replace("ipv6 router ospf 1", ""))
        self.assertIn("   shutdown", text)
        self.assertIn("interface Ethernet5", text)
        self.assertEqual(record.transition["probe"]["HA->HB IPV4"]["received"], 100)
        self.assertTrue(models.LifecycleOutboxEvent.objects.filter(device=self.device, payload__fact="DECOMMISSIONED").exists())

    def test_traffic_loss_fails_the_postcheck_and_rolls_back_to_service(self):
        lossy = H.FakeProbe({"HA->HB IPV4": {"sent": 100, "received": 97}})
        record, runtime, _ = self.ready(probe=lossy)
        baseline = record.baseline.state_digest
        svc.approve(record, actor=APPROVER, confirmation=record.plan_hash)
        record.refresh_from_db()
        executed = svc.execute(record, actor=APPROVER, confirmation=record.plan_hash, runtime=runtime)
        record.refresh_from_db()
        self.assertFalse(executed.ok)
        self.assertEqual(record.state, D.ROLLED_BACK)
        self.device.refresh_from_db()
        self.assertEqual(self.device.lifecycle_state, S.IN_SERVICE)
        self.assertEqual(H.executor_factory(self.fake)({"name": "R1", "platform": "ceos"}).__class__.__name__, "CeosExecutor")
        executor = H.executor_factory(self.fake)({"name": "R1", "platform": "ceos"})
        executor.connect()
        self.assertEqual(executor.config_state_digest(), baseline)

    def test_traffic_not_moving_after_cost_out_is_refused_and_restored(self):
        stuck = H.FakeObserver(H.observation(), H.observation(), H.observation())
        record, runtime, _ = self.ready(observer=stuck)
        svc.approve(record, actor=APPROVER, confirmation=record.plan_hash)
        record.refresh_from_db()
        executed = svc.execute(record, actor=APPROVER, confirmation=record.plan_hash, runtime=runtime)
        record.refresh_from_db()
        self.assertFalse(executed.ok)
        self.assertEqual(record.state, D.ROLLED_BACK)
        self.assertTrue(record.transition["moves"][-1]["still_on_device"])

    def test_quiescent_device_needs_no_transition(self):
        record, runtime, evaluated = self.ready(active=False, observer=H.FakeObserver(H.observation(active=False)))
        self.assertTrue(evaluated.ok, evaluated.codes)
        self.assertEqual(record.readiness_mode, models.DecommissionReadiness.QUIESCENT)
        self.assertEqual(record.plan["transition"], [])
        svc.approve(record, actor=APPROVER, confirmation=record.plan_hash)
        record.refresh_from_db()
        self.assertTrue(svc.execute(record, actor=APPROVER, confirmation=record.plan_hash, runtime=runtime).ok)

    def test_active_traffic_without_alternate_is_blocked_with_the_operator_instruction(self):
        observer = H.FakeObserver(H.observation(alternate=False))
        record, _runtime, evaluated = self.ready(observer=observer)
        self.assertFalse(evaluated.ok)
        self.assertEqual(record.state, D.BLOCKED)
        self.assertIn("DECOMMISSION_TRAFFIC_BLOCKED", evaluated.codes)
        self.assertTrue(any("stop or relocate" in b["details"]["instruction"] or "alternate" in b["details"]["instruction"]
                            for b in record.blockers if b["code"] == "DECOMMISSION_TRAFFIC_BLOCKED"))
        self.assertIsNone(record.change)

    def test_readiness_changed_before_execution_is_refused_without_writes(self):
        observer = H.FakeObserver(H.observation(), H.observation(alternate=False))
        record, runtime, _ = self.ready(observer=observer)
        svc.approve(record, actor=APPROVER, confirmation=record.plan_hash)
        record.refresh_from_db()
        before = self.fake.config.text()
        result = svc.execute(record, actor=APPROVER, confirmation=record.plan_hash, runtime=runtime)
        self.assertIn("DECOMMISSION_READINESS_CHANGED", result.codes)
        self.assertEqual(before, self.fake.config.text())
        record.refresh_from_db()
        self.assertEqual(record.state, D.BLOCKED)

    def test_expired_approval_is_refused(self):
        record, runtime, _ = self.ready()
        svc.approve(record, actor=APPROVER, confirmation=record.plan_hash)
        models.DecommissionRecord.objects.filter(pk=record.pk).update(approval_expires_at=timezone.now() - timedelta(seconds=1))
        record.refresh_from_db()
        result = svc.execute(record, actor=APPROVER, confirmation=record.plan_hash, runtime=runtime)
        self.assertIn("DECOMMISSION_APPROVAL_EXPIRED", result.codes)
        record.refresh_from_db()
        self.assertEqual(record.state, D.BLOCKED)


class RestorationWorkflowTests(TestCase):
    def setUp(self):
        self.device = adopted()
        self.fake = H.session()
        self.observer = H.FakeObserver(H.observation(active=False))
        self.runtime = H.runtime(self.fake, self.observer)
        self.record = svc.request(self.device, actor=OPERATOR, reason="retire").record
        svc.evaluate(self.record, actor=OPERATOR, runtime=self.runtime)
        self.record.refresh_from_db()
        svc.approve(self.record, actor=APPROVER, confirmation=self.record.plan_hash)
        self.record.refresh_from_db()
        assert svc.execute(self.record, actor=APPROVER, confirmation=self.record.plan_hash, runtime=self.runtime).ok
        self.record.refresh_from_db()

    def test_restore_reapplies_the_snapshot_exactly_and_registers_a_successor(self):
        row = svc.request_restore(self.record, actor=OPERATOR).record
        checked = svc.check_restore(row, actor=OPERATOR, runtime=self.runtime)
        self.assertTrue(checked.ok, checked.codes)
        row.refresh_from_db()
        self.assertEqual(row.state, R.PLANNED)
        self.assertTrue(row.checks["identity"]["match"])
        self.assertIn("SELF_APPROVAL", " ".join(svc.approve_restore(row, actor=OPERATOR, confirmation=row.plan_hash).codes))
        self.assertTrue(svc.approve_restore(row, actor=APPROVER, confirmation=row.plan_hash).ok)
        row.refresh_from_db()
        done = svc.execute_restore(row, actor=APPROVER, confirmation=row.plan_hash, runtime=self.runtime)
        row.refresh_from_db()
        self.assertTrue(done.ok, (done.codes, done.detail.get("report", {}).get("failure")))
        self.assertEqual(row.state, R.RESTORED)
        self.assertEqual(row.outcome["digest"], self.record.baseline.state_digest)
        successor = row.successor
        self.assertEqual((successor.origin, successor.lifecycle_state, successor.predecessor_id),
                         (models.DeviceOrigin.RESTORED, S.IN_SERVICE, self.device.pk))
        self.assertEqual(successor.admission_state, models.ProductionAdmissionState.LEGACY_PREEXISTING)

    def test_restore_with_a_different_host_key_requires_reenrollment(self):
        self.fake.outputs["show management ssh hostkey ed25519 public"] = H.OTHER_KEY_LINE
        row = svc.request_restore(self.record, actor=OPERATOR).record
        result = svc.check_restore(row, actor=OPERATOR, runtime=self.runtime)
        row.refresh_from_db()
        self.assertFalse(result.ok)
        self.assertEqual(row.state, R.REENROLLMENT_REQUIRED)

    def test_restore_blocked_when_the_name_is_live_again(self):
        row = svc.request_restore(self.record, actor=OPERATOR).record
        L.adopt("R1", role="router")
        result = svc.check_restore(row, actor=OPERATOR, runtime=self.runtime)
        self.assertIn("RESTORATION_CONFLICT", result.codes)
        row.refresh_from_db()
        self.assertEqual(row.state, R.BLOCKED)

    def test_restore_postcheck_failure_rolls_back_to_decommissioned(self):
        row = svc.request_restore(self.record, actor=OPERATOR).record
        svc.check_restore(row, actor=OPERATOR, runtime=self.runtime)
        row.refresh_from_db()
        svc.approve_restore(row, actor=APPROVER, confirmation=row.plan_hash)
        row.refresh_from_db()
        broken = H.runtime(self.fake, H.FakeObserver(H.observation(active=False, full=())))
        result = svc.execute_restore(row, actor=APPROVER, confirmation=row.plan_hash, runtime=broken)
        row.refresh_from_db()
        self.assertFalse(result.ok)
        self.assertEqual(row.state, R.ROLLED_BACK)
        self.assertIsNone(row.successor)
