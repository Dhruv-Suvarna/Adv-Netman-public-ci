"""Lab 7 -- execution history persistence (core.services.execution.persistence), each public function, positive + negative.

The execution history is the audit record of every device write, so the NEGATIVE cases prove that a secret-shaped key
is refused before anything is stored (and the run is left unchanged), that unknown / malformed run ids resolve to nothing,
that a failing notifier never corrupts the committed run, and that a secret value already in a report is redacted from
the UI / download.  Runs are created through the real locking path against a fake world -- no device is contacted.
"""

from __future__ import annotations

import json
import uuid
from unittest import mock

from django.test import TestCase

from core import models
from core.services.execution import locking, persistence as p
from core.services.execution.codes import Outcome, Phase, Status
from core.services.execution.executors.base import ConfigletSpec
from core.services.execution.scope import resolve_scope
from core.tests.helpers import execution as x


class PersistenceUnitTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.p = x.prepared()

    def setUp(self):
        scope, _ = resolve_scope(self.p.plan, "COMPLETE")
        self.run = locking.acquire(change=self.p.change, plan=self.p.plan, precheck_run=self.p.precheck, mode="COMPLETE", actor="tester",
                                   scope=scope, devices=scope.devices)
        self.specs = [ConfigletSpec.from_configlet(c) for c in self.p.plan.configlets.order_by("sequence")]

    # -- results --------------------------------------------------------------------------------------------
    def test_start_result_records_an_in_progress_row(self):
        result = p.start_result(self.run, self.specs[0], Phase.APPLY, previous_state={"kind": "address"})
        self.assertEqual((result.status, result.cfg_id, result.previous_state), (Status.IN_PROGRESS, self.specs[0].cfg_id, {"kind": "address"}))

    def test_start_result_refuses_secret_shaped_previous_state(self):
        with self.assertRaises(ValueError):
            p.start_result(self.run, self.specs[0], Phase.APPLY, previous_state={"enable_password": "x"})
        self.assertFalse(self.run.results.exists())

    def test_finish_result_mirrors_an_applied_status_onto_the_configlet(self):
        result = p.finish_result(p.start_result(self.run, self.specs[0], Phase.APPLY), Status.APPLIED, lines_sent=2)
        self.assertEqual(result.lines_sent, 2)
        self.assertEqual(models.Configlet.objects.get(pk=self.specs[0].pk).execution_status, models.ConfigletExecutionStatus.DEPLOYED)

    def test_finish_result_refuses_secret_detail_and_never_mirrors_an_unknown_status(self):
        result = p.start_result(self.run, self.specs[0], Phase.APPLY)
        with self.assertRaises(ValueError):
            p.finish_result(result, Status.APPLIED, detail={"api_token": "x"})
        before = models.Configlet.objects.get(pk=self.specs[0].pk).execution_status
        p.finish_result(result, Status.NOT_ATTEMPTED)
        self.assertEqual(models.Configlet.objects.get(pk=self.specs[0].pk).execution_status, before)

    def test_record_previous_state_stores_a_captured_reference(self):
        p.record_previous_state(self.run, self.specs[0], {"addresses": ["192.0.2.0/31"]}, strategy="EXACT_INVERSE")
        ref = models.Configlet.objects.get(pk=self.specs[0].pk).previous_state_ref
        self.assertEqual((ref["status"], ref["run_id"], ref["strategy"]), ("CAPTURED", str(self.run.run_id), "EXACT_INVERSE"))

    def test_record_previous_state_without_a_configlet_or_with_secrets_is_refused(self):
        unsaved = ConfigletSpec(**{**self.specs[0].__dict__, "pk": None})
        self.assertIsNone(p.record_previous_state(self.run, unsaved, {"a": 1}, strategy="X"))
        with self.assertRaises(ValueError):
            p.record_previous_state(self.run, self.specs[0], {"private_key": "x"}, strategy="X")

    def test_add_not_attempted_records_every_remaining_configlet(self):
        p.add_not_attempted(self.run, self.specs)
        self.assertEqual(set(self.run.results.values_list("status", flat=True)), {Status.NOT_ATTEMPTED})
        self.assertEqual(self.run.results.count(), len(self.specs))

    def test_add_not_attempted_never_duplicates_an_existing_result(self):
        p.finish_result(p.start_result(self.run, self.specs[0], Phase.APPLY), Status.APPLIED)
        p.add_not_attempted(self.run, self.specs)
        p.add_not_attempted(self.run, self.specs)
        self.assertEqual(self.run.results.count(), len(self.specs))
        self.assertEqual(self.run.results.get(sequence=self.specs[0].sequence).status, Status.APPLIED)

    # -- finalisation ---------------------------------------------------------------------------------------
    def test_finalize_run_finishes_once_frees_locks_and_audits(self):
        report = {"state": {"applied": ["CFG-001"]}, "compensation": {"attempted": True, "status": "COMPENSATED"}}
        run = p.finalize_run(self.run, outcome=Outcome.FAILED_ROLLED_BACK, report=report)
        self.assertEqual((run.state, run.summary["applied"], run.device_locks.count()), (models.ExecutionRunState.FINISHED, 1, 0))
        events = set(models.AuditEvent.objects.filter(object_id=str(run.run_id)).values_list("event_type", flat=True))
        self.assertEqual(events, {models.AuditEventType.DEPLOYMENT_RECORDED, models.AuditEventType.ROLLBACK_RECORDED})

    def test_finalize_run_refuses_a_secret_shaped_report_and_leaves_the_run_running(self):
        with self.assertRaises(ValueError):
            p.finalize_run(self.run, outcome=Outcome.SUCCEEDED, report={"state": {}, "device_password": "x"})
        self.run.refresh_from_db()
        self.assertEqual(self.run.state, models.ExecutionRunState.RUNNING)
        self.assertTrue(self.run.device_locks.exists())

    def test_record_blocked_creates_a_finished_blocked_run_and_audit(self):
        run = p.record_blocked(self.p.change, self.p.plan, precheck_run=self.p.precheck, mode="COMPLETE", actor="t",
                               blockers=[{"code": "DEVICE_LOCKED", "message": "m"}])
        self.assertEqual((run.state, run.outcome, run.summary["blockers"]), (models.ExecutionRunState.FINISHED, Outcome.BLOCKED, ["DEVICE_LOCKED"]))

    def test_record_blocked_without_a_plan_records_only_an_audit_event(self):
        before = models.ChangeExecutionRun.objects.count()
        self.assertIsNone(p.record_blocked(self.p.change, None, precheck_run=None, mode="COMPLETE", actor="t",
                                           blockers=[{"code": "PLAN_MISSING"}]))
        self.assertEqual(models.ChangeExecutionRun.objects.count(), before)
        self.assertTrue(models.AuditEvent.objects.filter(summary__contains="BLOCKED (PLAN_MISSING)").exists())

    # -- notifications --------------------------------------------------------------------------------------
    def test_notify_outcome_publishes_one_event_for_a_finished_run(self):
        run = p.finalize_run(self.run, outcome=Outcome.SUCCEEDED, report={"state": {"applied": ["CFG-001"]}})
        sink = x.Notifications()
        self.assertTrue(p.notify_outcome(run, notifier=sink))
        self.assertEqual((sink.events[0]["event_type"], sink.events[0]["metadata"]["applied"]), ("DEPLOYMENT_SUCCEEDED", 1))

    def test_notify_outcome_failing_notifier_or_blocked_run_publishes_nothing(self):
        run = p.finalize_run(self.run, outcome=Outcome.SUCCEEDED, report={"state": {}})
        self.assertFalse(p.notify_outcome(run, notifier=mock.Mock(side_effect=RuntimeError("slack down"))))
        run.refresh_from_db()
        self.assertEqual(run.outcome, Outcome.SUCCEEDED)                 # the committed record is untouched
        run.outcome = Outcome.BLOCKED
        sink = x.Notifications()
        self.assertFalse(p.notify_outcome(run, notifier=sink))
        self.assertEqual(sink.events, [])

    def test_default_notifier_publishes_through_the_notification_service(self):
        with mock.patch("core.services.notification_service.publish_event", return_value="ok") as publish:
            self.assertEqual(p.default_notifier(event_type="X", severity="INFO"), "ok")
        publish.assert_called_once_with(event_type="X", severity="INFO")

    def test_default_notifier_raises_when_the_notification_service_fails(self):
        with mock.patch("core.services.notification_service.publish_event", side_effect=RuntimeError("down")), self.assertRaises(RuntimeError):
            p.default_notifier(event_type="X")

    # -- reads ----------------------------------------------------------------------------------------------
    def test_get_list_and_latest_run_return_the_change_runs(self):
        self.assertEqual(p.get_run(self.p.change, str(self.run.run_id)), self.run)
        self.assertEqual(p.list_runs(self.p.change), [self.run])
        self.assertEqual(p.latest_run(self.p.change), self.run)

    def test_get_run_of_malformed_or_unknown_ids_and_empty_history_is_none(self):
        for value in ("not-a-uuid", "", None, "1; DROP TABLE x", str(uuid.uuid4())):
            with self.subTest(case=f"invalid {value!r}"):
                self.assertIsNone(p.get_run(self.p.change, value))
        other = x.prepared().change
        self.assertEqual((p.list_runs(other), p.latest_run(other)), ([], None))
        self.assertEqual(p.list_runs(self.p.change, limit=0), [])

    def test_report_json_and_filename_of_a_finished_run(self):
        run = p.finalize_run(self.run, outcome=Outcome.SUCCEEDED, report={"state": {"applied": []}})
        document = json.loads(p.report_json(run))
        self.assertEqual((document["run_id"], document["outcome"]), (str(run.run_id), Outcome.SUCCEEDED))
        self.assertEqual(p.report_filename(run), f"{run.change.change_id}-execution-{str(run.run_id)[:8]}.json")
        self.assertTrue(p.is_success(run))

    def test_report_json_never_exposes_a_secret_value_and_failed_runs_are_not_success(self):
        models.ChangeExecutionRun.objects.filter(pk=self.run.pk).update(report={"nested": {"device_password": "hunter2"}},
                                                                         outcome=Outcome.FAILED_NO_MUTATION)
        self.run.refresh_from_db()
        text = p.report_json(self.run)
        self.assertNotIn("hunter2", text)
        self.assertIn("[REDACTED]", text)
        self.assertFalse(p.is_success(self.run))
        with self.assertRaises(AttributeError):
            p.report_filename(None)
