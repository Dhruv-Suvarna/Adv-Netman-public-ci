"""Lab 7 closure -- the read-only reconciliation helpers behind the predating / superseded Change gates, called directly.

The execution history comes from the real validation -> plan -> execution chain on the simulated network
(``helpers.execution``) and the device read is the existing fake, so nothing contacts a device or NetBox.  POSITIVE:
the devices a Change addresses, the newest baseline accepted after it, what became of its runs and the pinned previous
expectation are exact.  NEGATIVE: a Change with no intents / Configlets / runs addresses no device, a Change created
after the baseline predates nothing, an interrupted run is never reported as cleanly rolled back, and the helpers
never write a row.
"""

from __future__ import annotations

import io
from unittest import mock

from django.core.management import call_command
from django.core.management.base import CommandError

from core import models
from core.services import reconciliation_service as service
from core.tests import test_reconciliation as rc
from core.tests.helpers import execution as x


class ChangeDevicesTests(rc.ReconciliationFixture):
    def test_change_devices_returns_every_intent_configlet_and_run_device(self):
        intents = set(models.DeviceIntent.objects.filter(change=self.change).values_list("device_name", flat=True))
        self.assertEqual(service.change_devices(self.change), intents | set(self.exec_run.devices))
        self.assertIn("R2", service.change_devices(self.change))

    def test_change_devices_of_a_change_without_intents_configlets_or_runs_is_empty(self):
        bare = x.prepared().change
        models.Configlet.objects.filter(change=bare).delete()
        models.DeviceIntent.objects.filter(change=bare).delete()
        self.assertEqual(service.change_devices(bare), set())
        self.assertEqual(service.predating_records(bare), [])


class PredatingTests(rc.ReconciliationFixture):
    def test_predating_records_returns_the_baseline_accepted_after_the_change(self):
        stale = x.prepared()
        record, _ = self.accept()
        self.assertEqual(service.predating_records(stale.change), [record])

    def test_predating_records_are_none_for_a_change_created_after_the_baseline(self):
        self.accept()
        self.assertEqual(service.predating_records(x.prepared().change), [])

    def test_predating_history_reports_applied_and_rolled_back_runs(self):
        applied, rolled_back = x.prepared(), x.prepared()
        x.run(applied, x.FakeWorld())
        models.ChangeExecutionRun.objects.filter(pk=x.run(rolled_back, x.FakeWorld()).run.pk).update(outcome="POSTCHECK_FAILED_ROLLED_BACK")
        self.assertEqual((service.predating_history(applied.change), service.predating_history(rolled_back.change)),
                         (service.HISTORY_APPLIED, service.HISTORY_ROLLED_BACK))

    def test_predating_history_of_an_unexecuted_or_interrupted_change_is_never_clean(self):
        never, interrupted = x.prepared(), x.prepared()
        models.ChangeExecutionRun.objects.filter(pk=x.run(interrupted, x.FakeWorld()).run.pk).update(outcome="INTERRUPTED")
        self.assertEqual((service.predating_history(never.change), service.predating_history(interrupted.change)),
                         (service.HISTORY_NEVER_EXECUTED, service.HISTORY_UNRESOLVED))
        self.assertEqual(service.PREDATING_REASONS[service.HISTORY_UNRESOLVED], "An earlier execution of it did not finish cleanly")


class PreviousExpectationTests(rc.ReconciliationFixture):
    def test_previous_expectation_pins_the_prior_record_and_each_superseded_run(self):
        record, _ = self.accept()
        digest, basis = service.previous_expectation("R2", [self.exec_run])
        self.assertEqual(basis, {
            "schema": service.SCHEMA, "device": "R2",
            "prior_reconciliation": {"record_id": record.record_id, "accepted_digest": record.accepted_digest},
            "runs": [{"run_id": str(self.exec_run.run_id), "change_id": self.change.change_id, "mode": self.exec_run.mode,
                      "outcome": self.exec_run.outcome, "plan_hash": self.exec_run.plan_hash,
                      "finished_at": self.exec_run.finished_at.isoformat()}]})
        self.assertEqual(digest, service._digest({"domain": "nmas.reconciliation.expected", "value": basis}))
        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_previous_expectation_without_a_prior_record_or_runs_has_no_borrowed_basis(self):
        before = (models.StateReconciliation.objects.count(), models.AuditEvent.objects.count())
        digest, basis = service.previous_expectation("R1", [])
        self.assertEqual(basis, {"schema": service.SCHEMA, "device": "R1", "prior_reconciliation": None, "runs": []})
        self.assertNotEqual(digest, service.previous_expectation("R2", [])[0])
        self.assertEqual((models.StateReconciliation.objects.count(), models.AuditEvent.objects.count()), before)


def command(*args):
    out = io.StringIO()
    call_command("nmas_reconcile", *args, stdout=out)
    return out.getvalue()


class ReconcileCommandTests(rc.ReconciliationFixture):
    def test_observe_prints_the_observation_and_the_exact_acknowledgement(self):
        observation = rc.observe()
        with mock.patch.object(service, "observe", return_value=observation) as observe:
            out = command("observe", "--device", "R2")
        observe.assert_called_once_with("R2")
        self.assertTrue(out.endswith("acknowledgement: " + service.acknowledgement_phrase("R2", observation["digest"]) + "\n"))
        self.assertNotIn("SECRETHASH", out)

    def test_accept_creates_one_record_and_project_status_sets_one_fake_netbox_field(self):
        observation = rc.observe()
        with mock.patch.object(service, "observe", return_value=observation):
            out = command("accept", "--device", "R2", "--actor", "operator", "--reason", "Returned to service by hand.",
                          "--ack", service.acknowledgement_phrase("R2", observation["digest"]), "--run", str(self.exec_run.run_id),
                          "--section", "interface Ethernet1", "--section", "router rip")
        record = models.StateReconciliation.objects.get()
        self.assertEqual(out, f"{record.record_id} CREATED R2 previous={record.previous_expected_digest[:12]} accepted={record.accepted_digest[:12]}\n")
        netbox = rc.FakeNetBox({"R2": "offline", "R1": "active"})
        with mock.patch("modules.netbox_ipam.build_client", return_value=netbox):
            out = command("project-status", "--record", record.record_id, "--status", "active", "--actor", "operator", "--confirm")
        self.assertEqual(out, f"{record.record_id} NetBox R2: offline -> active (SET)\n")
        self.assertEqual(netbox.updates, [("R2", {"status": "active"})])

    def test_reconcile_command_refuses_a_wrong_acknowledgement_unknown_record_or_unconfirmed_projection(self):
        observation = rc.observe()
        with mock.patch.object(service, "observe", return_value=observation), self.assertRaisesRegex(CommandError, "^ACK"):
            command("accept", "--device", "R2", "--actor", "operator", "--reason", "x", "--ack", "ACCEPT R2 000000000000",
                    "--run", str(self.exec_run.run_id))
        self.assertFalse(models.StateReconciliation.objects.exists())
        netbox = rc.FakeNetBox({"R2": "offline"})
        with mock.patch("modules.netbox_ipam.build_client", return_value=netbox) as build:
            with self.assertRaisesRegex(CommandError, "^No reconciliation record REC-999999.$"):
                command("project-status", "--record", "REC-999999", "--status", "active", "--actor", "operator")
            build.assert_not_called()
            record, _ = self.accept()
            with self.assertRaisesRegex(CommandError, "^CONFIRMATION_REQUIRED: "):
                command("project-status", "--record", record.record_id, "--status", "active", "--actor", "operator")
        self.assertEqual(netbox.updates, [])
