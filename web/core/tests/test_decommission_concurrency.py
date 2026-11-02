"""V2 Phase 7 -- concurrency: a decommission never writes while another execution holds the device, and one approved record
executes once even when two operators press "execute" with the same (now stale) record.

The device lock is the REAL execution lock (``execution.device_mutex.DeviceMutex``, a per-device file lock, then the
``ExecutionDeviceLock`` rows) held here as another execution would hold it.  The device is the REAL cEOS executor on an in-memory EOS
session (``helpers.decommission``).
"""

from __future__ import annotations

from django.test import TestCase

from core import models
from core.services.decommission import service as svc
from core.services.execution.device_mutex import DeviceMutex
from core.tests.helpers import decommission as H
from core.tests.helpers import lifecycle as L

D, S = models.DecommissionState, models.DeviceLifecycleState


class ConcurrencyTests(TestCase):
    def setUp(self):
        self.device = L.adopt("R1", role="router").device
        self.fake = H.session()

    def runtime(self):
        return H.runtime(self.fake, H.FakeObserver(H.observation(active=False)))

    def approved(self):
        record = svc.request(self.device, actor=L.OPERATOR, reason="retire R1").record
        self.assertTrue(svc.evaluate(record, actor=L.OPERATOR, runtime=self.runtime()).ok)
        record.refresh_from_db()
        self.assertTrue(svc.approve(record, actor=L.APPROVER, confirmation=record.plan_hash).ok)
        record.refresh_from_db()
        return record

    def test_execute_while_another_execution_holds_the_device_is_blocked_without_any_write(self):
        record = self.approved()
        before = self.fake.config.text()
        with DeviceMutex(["R1"]):                                       # another execution holds R1
            result = svc.execute(record, actor=L.APPROVER, confirmation=record.plan_hash, runtime=self.runtime())
        record.refresh_from_db()
        self.assertFalse(result.ok)
        self.assertEqual((record.state, result.detail["outcome"]), (D.BLOCKED, "BLOCKED"))
        self.assertEqual([b["code"] for b in record.outcome["blockers"]], ["DEVICE_LOCKED"])
        self.assertEqual(self.fake.config.text(), before)                # nothing reached the device
        self.device.refresh_from_db()
        self.assertEqual(self.device.lifecycle_state, S.IN_SERVICE)
        # once the other execution is gone the record is re-evaluated and approved again, then it runs
        self.assertTrue(svc.evaluate(record, actor=L.OPERATOR, runtime=self.runtime()).ok)
        record.refresh_from_db()
        self.assertTrue(svc.approve(record, actor=L.APPROVER, confirmation=record.plan_hash).ok)
        record.refresh_from_db()
        self.assertTrue(svc.execute(record, actor=L.APPROVER, confirmation=record.plan_hash, runtime=self.runtime()).ok)

    def test_two_operators_executing_the_same_record_never_write_twice(self):
        record = self.approved()
        stale = models.DecommissionRecord.objects.get(pk=record.pk)      # the second operator's copy, loaded before the first ran
        first = svc.execute(record, actor=L.APPROVER, confirmation=record.plan_hash, runtime=self.runtime())
        self.assertTrue(first.ok, first.codes)
        after_first = self.fake.config.text()
        second = svc.execute(stale, actor=L.APPROVER, confirmation=stale.plan_hash, runtime=self.runtime())
        self.assertFalse(second.ok)
        record.refresh_from_db()
        self.assertEqual(record.state, D.DECOMMISSIONED)
        self.assertEqual(record.change.execution_runs.count(), 1)       # one governed run only
        self.assertEqual(self.fake.config.text(), after_first)
