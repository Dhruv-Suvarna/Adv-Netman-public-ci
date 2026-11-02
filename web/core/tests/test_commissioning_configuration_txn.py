"""``commissioning.service.record_configuration``: the upstream isolation read-back happens OUTSIDE the write transaction.

The read-back is an SSH session to the trusted upstream.  Held inside ``transaction.atomic()`` it kept the database transaction
open across network I/O, and the nested drift-check write then failed with ``database is locked`` on SQLite even when the policy
was healthy.  The read now runs first; what it observed (the run status, the isolation policy version and state) is re-validated
under lock before CONFIGURED is written, so a change in between is refused and can be retried -- the window is never widened.
"""

from __future__ import annotations

from unittest import mock

from django.db import connection

from core import models
from core.services.commissioning import service as C
from core.services.devices.codes import blocker
from core.services.isolation import service as iso
from core.tests.helpers import lifecycle as L
from core.tests.test_commissioning import Base

St = models.CommissioningState


class ConfigurationReadBackTransactionTests(Base):
    def setUp(self):
        super().setUp()
        self.approved()
        provisioned = self.lab.provision(actor=L.APPROVER)
        self.assertTrue(provisioned.ok, provisioned.codes)
        self.assertEqual(C.get_record(self.record.pk).state, St.CONFIGURING)

    def record_now(self):
        return C.get_record(self.record.pk)

    def after_read_back(self, action):
        """Run the real drift check, then ``action`` -- another writer acting between the read-back and the write."""
        real = iso.check_drift

        def check_then_act(*args, **kwargs):
            result = real(*args, **kwargs)
            action()
            return result
        return mock.patch.object(C.isolation, "check_drift", side_effect=check_then_act)

    def configure(self):
        return C.record_configuration(self.record_now(), actor=L.APPROVER, access=self.flow.access)

    def recorded_configurations(self):
        """COM_CONFIGURE RECORDED events (the write-ahead "configuration started" one is recorded by ``mark_configuring``)."""
        return models.DeviceLifecycleEvent.objects.filter(device=self.device, action="COM_CONFIGURE",
                                                          outcome=models.DeviceLifecycleEventOutcome.RECORDED).count()

    # positive ---------------------------------------------------------------------------------------------------------------------
    def test_configuration_read_back_runs_outside_the_write_transaction(self):
        depth = len(connection.atomic_blocks)                # the test case's own wrapping blocks
        seen = []
        real = iso._read_upstream

        def read(policy, access):
            seen.append(len(connection.atomic_blocks))
            return real(policy, access)

        with mock.patch.object(iso, "_read_upstream", side_effect=read):
            result = self.configure()
        self.assertEqual((result.ok, result.record.state), (True, St.CONFIGURED))
        self.assertEqual(seen, [depth])                      # the SSH read-back held no transaction of record_configuration
        policy = models.IsolationPolicy.objects.get(pk=self.record.isolation_policy_id)
        self.assertTrue(policy.checks.filter(kind=models.IsolationCheckKind.DRIFT, ok=True).exists())

    def test_retry_after_a_concurrent_policy_change_configures(self):
        policy = models.IsolationPolicy.objects.get(pk=self.record.isolation_policy_id)
        with self.after_read_back(lambda: iso._save(models.IsolationPolicy.objects.get(pk=policy.pk), drift={"note": "touched"})):
            self.assertFalse(self.configure().ok)
        result = self.configure()                            # the retry reads the policy as it is now
        self.assertEqual((result.ok, result.record.state), (True, St.CONFIGURED))

    # negative ---------------------------------------------------------------------------------------------------------------------
    def test_policy_changed_after_read_back_blocks_configuration(self):
        def concurrent():
            iso._save(models.IsolationPolicy.objects.get(pk=self.record.isolation_policy_id), drift={"note": "concurrent writer"})

        before = self.recorded_configurations()
        with self.after_read_back(concurrent):
            result = self.configure()
        self.assertEqual((result.ok, result.codes), (False, ["ISOLATION_STATE_INVALID"]))
        self.assertEqual(self.record_now().state, St.CONFIGURING)         # nothing folded in: still retryable
        self.assertEqual(self.recorded_configurations(), before)

    def test_policy_drifted_after_read_back_never_configures(self):
        def drifted():
            iso._save(models.IsolationPolicy.objects.get(pk=self.record.isolation_policy_id), state=models.IsolationState.DRIFTED)

        with self.after_read_back(drifted):
            result = self.configure()
        self.assertFalse(result.ok)
        self.assertNotEqual(self.record_now().state, St.CONFIGURED)

    def test_record_changed_after_read_back_fails_as_stale(self):
        def concurrent():
            C._save(self.record_now(), failure={"note": "another writer"})

        with self.after_read_back(concurrent):
            result = C.record_configuration(self.record_now(), actor=L.APPROVER, access=self.flow.access)
        self.assertEqual(result.codes, ["COMMISSIONING_STATE_INVALID"])
        self.assertEqual(self.record_now().state, St.CONFIGURING)

    def test_run_changed_after_read_back_blocks_configuration(self):
        run_id = self.record.provisioning_run_id

        def rolled_back():
            models.ProvisioningRun.objects.filter(pk=run_id).update(status=models.ProvisioningStatus.ROLLED_BACK)

        with self.after_read_back(rolled_back):
            result = self.configure()
        self.assertEqual(result.codes, ["COMMISSIONING_STATE_INVALID"])
        self.assertEqual(self.record_now().state, St.CONFIGURING)

    def test_unreadable_upstream_fails_to_uncertain(self):
        unreadable = (None, "", "", blocker("ISOLATION_UPSTREAM_UNREADABLE", reason="TIMEOUT"))
        with mock.patch.object(iso, "_read_upstream", return_value=unreadable):
            result = self.configure()
        self.assertEqual((result.ok, result.record.state), (False, St.UNCERTAIN))
        self.assertEqual(result.record.failure["code"], "ISOLATION_DRIFTED")
        self.assertIn("ISOLATION_UPSTREAM_UNREADABLE", result.record.failure["detail"])

    def test_failure_inside_the_write_transaction_leaves_no_partial_configuration(self):
        real = C._event

        def failing(device, action, outcome, **kwargs):
            if action == "COM_CONFIGURE" and outcome == models.DeviceLifecycleEventOutcome.RECORDED:
                raise RuntimeError("audit write failed")
            return real(device, action, outcome, **kwargs)

        with mock.patch.object(C, "_event", side_effect=failing), self.assertRaises(RuntimeError):
            self.configure()
        self.assertEqual(self.record_now().state, St.CONFIGURING)         # rolled back with the failed event
        self.assertEqual(self.configure().record.state, St.CONFIGURED)    # and the retry completes

    def test_repeated_configuration_is_not_recorded_twice(self):
        self.assertTrue(self.configure().ok)
        recorded = self.recorded_configurations()
        again = self.configure()
        self.assertEqual((again.ok, again.codes), (False, ["COMMISSIONING_STATE_INVALID"]))
        self.assertEqual(self.record_now().state, St.CONFIGURED)
        self.assertEqual(self.recorded_configurations(), recorded)
