"""Append-only state reconciliation: previous NMAS expectation != accepted current state.

The execution history is produced by the real validation -> plan -> precheck -> execution chain on a simulated network;
the device read is the soak's own allowlisted read, replaced by a fake.  No test contacts a device or NetBox.
"""

from __future__ import annotations

import hashlib
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase

from core import models
from core.services import execution_service as es, reconciliation_service as service
from core.services.health import live
from core.services.health.evidence import DeviceEvidence
from core.tests.helpers import execution as x

R2_RUNNING = ("! Command: show running-config\nhostname R2\ninterface Ethernet1\n   switchport mode trunk\n"
              "username admin secret sha512 $6$abcdefSECRETHASH\nrouter rip\n   no shutdown\nend\n")
R2_STARTUP = R2_RUNNING.replace("! Command: show running-config", "! Command: show startup-config\n! Startup-config last modified at Tue Sep 29")
SECTIONS = ["interface Ethernet1", "router rip"]


@contextmanager
def running(text=R2_RUNNING):
    def read(device, raw_keys=(), *, session_factory=None, now=None):
        evidence = DeviceEvidence(device=device["name"], platform=device.get("platform", ""))
        if text is None:
            return evidence, {}, {key: "CONNECTION_FAILED" for key in raw_keys}
        return evidence, {key: text for key in raw_keys}, {}
    with mock.patch.object(live, "read_device_with_raw", side_effect=read):
        yield


def startup(text=R2_STARTUP, error=""):
    return lambda device: (service.sanitize_config(text).text if not error else "", error)


def observe(device="R2", *, run_text=R2_RUNNING, start=None):
    with running(run_text):
        return service.observe(device, startup_reader=start or startup())


def user_with(role=None):
    user = get_user_model().objects.create_user(username=f"u-{role or 'none'}".replace(" ", "-"), password="x")
    if role:
        user.groups.add(Group.objects.get(name=role))
    return get_user_model().objects.get(pk=user.pk)


class ReconciliationFixture(TestCase):
    @classmethod
    def setUpTestData(cls):
        prepared = x.prepared()
        cls.exec_run = x.run(prepared, x.FakeWorld()).run
        cls.change = prepared.change
        assert cls.exec_run.state == "FINISHED" and "R2" in cls.exec_run.devices, (cls.exec_run.state, cls.exec_run.devices)

    def accept(self, **overrides):
        observation = overrides.pop("observation", None) or observe()
        options = dict(device_name="R2", actor="operator", reason="R2 was returned to service by hand after the drain test.",
                       acknowledgement=service.acknowledgement_phrase("R2", observation["digest"]),
                       execution_run_ids=[str(self.exec_run.run_id)], affected_sections=SECTIONS, observation=observation)
        options.update(overrides)
        return service.accept(**options)

    def refused(self, code, **overrides):
        before = (models.StateReconciliation.objects.count(), models.AuditEvent.objects.count())
        with self.assertRaises(service.ReconciliationError) as caught:
            self.accept(**overrides)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual((models.StateReconciliation.objects.count(), models.AuditEvent.objects.count()), before)


class ObservationTests(TestCase):
    def test_observation_holds_digests_only_and_proves_running_equals_startup(self):
        observation = observe()
        self.assertEqual((observation["state"], observation["running_matches_startup"]), ("OK", True))
        self.assertRegex(observation["digest"], r"^[0-9a-f]{64}$")
        self.assertRegex(observation["startup_digest"], r"^[0-9a-f]{64}$")
        self.assertNotIn("SECRETHASH", repr(observation))
        self.assertNotIn("hostname R2", repr(observation))

    def test_a_startup_difference_or_an_unreadable_device_is_reported_not_hidden(self):
        self.assertIs(observe(start=startup(R2_STARTUP.replace("router rip", "router rip\n   network 10.0.0.0/8")))["running_matches_startup"], False)
        self.assertIsNone(observe(start=startup(error="STARTUP_READ_FAILED"))["running_matches_startup"])
        self.assertEqual(observe(run_text=None)["state"], "UNAVAILABLE")

    def test_observing_writes_nothing(self):
        before = (models.StateReconciliation.objects.count(), models.AuditEvent.objects.count())
        observe()
        self.assertEqual((models.StateReconciliation.objects.count(), models.AuditEvent.objects.count()), before)


class AcceptTests(ReconciliationFixture):
    def test_record_pins_previous_and_accepted_digests_sections_and_runs(self):
        observation = observe()
        record, created = self.accept(observation=observation)
        self.assertTrue(created)
        self.assertEqual(record.record_id, "REC-000001")
        self.assertEqual((record.device_name, record.actor, record.cause), ("R2", "operator", "OUTSIDE_NMAS_RESTORATION"))
        self.assertEqual(record.accepted_digest, observation["digest"])
        self.assertEqual(record.startup_digest, observation["startup_digest"])
        self.assertEqual(record.section_digests, observation["sections"])
        self.assertEqual(record.affected_sections, sorted(SECTIONS))
        self.assertEqual(record.execution_run_ids, [str(self.exec_run.run_id)])
        self.assertNotEqual(record.previous_expected_digest, record.accepted_digest)
        self.assertEqual(record.previous_expected_basis["runs"][0]["plan_hash"], self.exec_run.plan_hash)
        self.assertEqual(record.previous_expected_basis["runs"][0]["change_id"], self.change.change_id)
        self.assertIsNone(record.previous_expected_basis["prior_reconciliation"])
        self.assertIs(record.evidence["configuration_text_stored"], False)
        self.assertEqual(service.current_baseline("R2"), record)
        self.assertIsNone(service.current_baseline("R1"))

    def test_audit_event_carries_the_whole_decision(self):
        record, _ = self.accept()
        (event,) = models.AuditEvent.objects.filter(event_type="STATE_RECONCILIATION_ACCEPTED")
        self.assertEqual((event.object_type, event.object_id, event.actor), ("StateReconciliation", record.record_id, "operator"))
        for key in ("record_id", "device", "actor", "reason", "previous_expected_digest", "accepted_digest", "affected_sections",
                    "execution_run_ids", "observed_at"):
            self.assertIn(key, event.metadata)
        self.assertEqual(event.metadata["accepted_digest"], record.accepted_digest)
        self.assertEqual(event.metadata["execution_run_ids"], [str(self.exec_run.run_id)])

    def test_history_is_untouched(self):
        def snapshot():
            run = models.ChangeExecutionRun.objects.get(pk=self.exec_run.pk)
            change = models.Change.objects.get(pk=self.change.pk)
            return (
                (change.lifecycle_state, change.validation_state, change.updated_at),
                (run.state, run.outcome, run.plan_hash, run.finished_at, run.report, run.summary),
                list(models.Configlet.objects.order_by("pk").values_list("pk", "cfg_id", "updated_at")),
                list(models.ConfigletExecutionResult.objects.order_by("pk").values_list("pk", "status")),
                list(models.ChangeValidationRun.objects.order_by("pk").values_list("pk", "status")),
                list(models.OperationalCheckRun.objects.order_by("pk").values_list("pk", "status", "finished_at")),
                list(models.AuditEvent.objects.order_by("pk").values_list("pk", "event_type", "summary")),
            )
        before = snapshot()
        self.accept()
        after = snapshot()
        self.assertEqual(after[:-1], before[:-1])
        self.assertEqual(after[-1][:len(before[-1])], before[-1])       # audit history only grows
        self.assertEqual(len(after[-1]), len(before[-1]) + 1)

    def test_records_are_append_only(self):
        record, _ = self.accept()
        record.reason = "edited"
        with self.assertRaises(ValueError):
            record.save()
        with self.assertRaises(ValueError):
            record.delete()
        with self.assertRaises(ValueError):
            models.StateReconciliation.objects.filter(pk=record.pk).update(reason="edited")
        with self.assertRaises(ValueError):
            models.StateReconciliation.objects.all().delete()
        self.assertEqual(models.StateReconciliation.objects.get(pk=record.pk).reason, "R2 was returned to service by hand after the drain test.")

    def test_accepting_the_same_state_twice_is_idempotent(self):
        first, created = self.accept()
        audits = models.AuditEvent.objects.count()
        second, created_again = self.accept()
        self.assertTrue(created)
        self.assertFalse(created_again)
        self.assertEqual((second.pk, models.StateReconciliation.objects.count(), models.AuditEvent.objects.count()), (first.pk, 1, audits))

    def test_a_later_outside_change_chains_from_the_previous_record(self):
        first, _ = self.accept()
        later = observe(run_text=R2_RUNNING.replace("hostname R2", "hostname R2\nip routing"),
                        start=startup(R2_STARTUP.replace("hostname R2", "hostname R2\nip routing")))
        second, created = self.accept(observation=later, cause=models.ReconciliationCause.OUTSIDE_NMAS_CHANGE)
        self.assertTrue(created)
        self.assertEqual(second.record_id, "REC-000002")
        self.assertEqual(second.previous_expected_basis["prior_reconciliation"],
                         {"record_id": first.record_id, "accepted_digest": first.accepted_digest})
        self.assertEqual(service.current_baseline("R2"), second)
        self.assertEqual(models.StateReconciliation.objects.get(pk=first.pk).accepted_digest, first.accepted_digest)

    def test_acceptance_is_explicit(self):
        observation = observe()
        self.refused("ACKNOWLEDGEMENT_MISMATCH", observation=observation, acknowledgement="yes")
        self.refused("ACKNOWLEDGEMENT_MISMATCH", observation=observation, acknowledgement=service.acknowledgement_phrase("R1", observation["digest"]))
        self.refused("ACTOR_AND_REASON_REQUIRED", reason="  ")
        self.refused("ACTOR_AND_REASON_REQUIRED", actor="")
        self.refused("AFFECTED_SECTIONS_REQUIRED", affected_sections=[])
        self.refused("RUNS_REQUIRED", execution_run_ids=[])

    def test_running_equal_to_startup_must_be_proven(self):
        self.refused("RUNNING_STARTUP_UNPROVEN", observation=observe(start=startup(R2_STARTUP + "ip routing\n")))
        self.refused("RUNNING_STARTUP_UNPROVEN", observation=observe(start=startup(error="STARTUP_READ_FAILED")))
        self.refused("OBSERVATION_INCOMPLETE", observation=observe(run_text=None))

    def test_execution_references_must_be_real_finished_runs_of_this_device(self):
        self.refused("UNKNOWN_RUN", execution_run_ids=["00000000-0000-0000-0000-000000000000"])
        self.refused("DUPLICATE_RUN", execution_run_ids=[str(self.exec_run.run_id)] * 2)
        self.refused("NOT_MANAGED", device_name="NOPE")
        self.assertNotIn("S1", self.exec_run.devices)
        observation = {**observe(), "device": "S1"}
        self.refused("RUN_NOT_FOR_DEVICE", device_name="S1", observation=observation,
                     acknowledgement=service.acknowledgement_phrase("S1", observation["digest"]))

    def test_existing_approve_permission_is_required_for_a_website_user(self):
        for role in (None, "NMAS Viewer", "NMAS Operator", "NMAS Executor"):
            with self.subTest(role=role):
                self.refused("PERMISSION_DENIED", user=user_with(role))
        approver = user_with("NMAS Approver")
        record, created = self.accept(user=approver, actor=approver.username)
        self.assertTrue(created)
        self.assertEqual(models.AuditEvent.objects.get(event_type="STATE_RECONCILIATION_ACCEPTED").actor_user, approver)
        self.assertFalse(any("maintenance" in codename for codename in
                             approver.user_permissions.model.objects.values_list("codename", flat=True)))


class FakeNetBox:
    """Only ``dcim.devices.get(name=)`` and ``device.update({...})``: anything else is an unexpected NetBox call."""

    def __init__(self, statuses, accept=True):
        self.statuses, self.updates, self.accept_writes = dict(statuses), [], accept
        self.dcim = SimpleNamespace(devices=SimpleNamespace(get=self._get))

    def _get(self, name):
        if name not in self.statuses:
            return None
        box = self

        class Device:
            status = SimpleNamespace(value=box.statuses[name])

            def update(self, fields):
                box.updates.append((name, dict(fields)))
                if box.accept_writes:
                    box.statuses[name] = fields["status"]
                return box.accept_writes
        return Device()


class NetBoxProjectionTests(ReconciliationFixture):
    def project(self, client, **overrides):
        options = dict(record=self.record, status="active", actor="operator", client=client, confirm=True)
        options.update(overrides)
        return service.project_netbox_status(**options)

    def setUp(self):
        self.record, _ = self.accept()

    def test_one_explicit_status_write_audited_against_the_record(self):
        netbox = FakeNetBox({"R2": "offline", "R1": "active", "S2": "active"})
        result = self.project(netbox)
        self.assertEqual(result, {"device": "R2", "previous": "offline", "status": "active", "action": "SET"})
        self.assertEqual(netbox.updates, [("R2", {"status": "active"})])              # one device, one field
        self.assertEqual((netbox.statuses["R1"], netbox.statuses["S2"]), ("active", "active"))
        (event,) = models.AuditEvent.objects.filter(event_type="NSOT_STATUS_PROJECTED")
        self.assertEqual((event.object_id, event.metadata["record_id"]), (self.record.record_id, self.record.record_id))
        self.assertIs(event.metadata["inferred_from_interfaces"], False)
        self.assertEqual((event.metadata["previous"], event.metadata["status"]), ("offline", "active"))

    def test_status_is_what_the_caller_states_never_derived_from_interfaces(self):
        """The service reads no device and no interface: with every device read failing it still projects exactly the stated status."""
        netbox = FakeNetBox({"R2": "offline"})
        with mock.patch.object(live, "read_device_with_raw", side_effect=AssertionError("no device read")), \
                mock.patch.object(live, "read_device", side_effect=AssertionError("no device read")):
            self.assertEqual(self.project(netbox)["action"], "SET")
        source = open(service.__file__).read()
        self.assertNotIn("data_ports", source)
        self.assertNotIn("nsot_drain_sync", source)

    def test_an_already_correct_status_is_not_rewritten(self):
        netbox = FakeNetBox({"R2": "active"})
        self.assertEqual(self.project(netbox)["action"], "UNCHANGED")
        self.assertEqual(netbox.updates, [])

    def test_projection_is_refused_without_confirmation_a_valid_status_or_a_current_record(self):
        netbox = FakeNetBox({"R2": "offline"})
        cases = [("CONFIRMATION_REQUIRED", dict(confirm=False)), ("UNKNOWN_STATUS", dict(status="up")),
                 ("PERMISSION_DENIED", dict(user=user_with("NMAS Viewer")))]
        for code, overrides in cases:
            with self.subTest(code=code), self.assertRaises(service.ReconciliationError) as caught:
                self.project(netbox, **overrides)
            self.assertEqual(caught.exception.code, code)
        with self.assertRaises(service.ReconciliationError) as caught:
            self.project(FakeNetBox({}))
        self.assertEqual(caught.exception.code, "NETBOX_DEVICE_MISSING")
        self.assertEqual(netbox.updates, [])
        self.assertFalse(models.AuditEvent.objects.filter(event_type="NSOT_STATUS_PROJECTED").exists())

    def test_a_failed_netbox_write_is_not_audited_as_done(self):
        with self.assertRaises(service.ReconciliationError) as caught:
            self.project(FakeNetBox({"R2": "offline"}, accept=False))
        self.assertEqual(caught.exception.code, "NETBOX_WRITE_FAILED")
        self.assertFalse(models.AuditEvent.objects.filter(event_type="NSOT_STATUS_PROJECTED").exists())


class SupersededChangeGateTests(ReconciliationFixture):
    """A reconciled Change is history: it stays readable and unchanged, and it can never be executed again."""

    CODE = "BLOCKED_SUPERSEDED_BY_RECONCILIATION"

    def gate(self, change, **kwargs):
        return es.check_execution_eligibility(change, confirm_mode=change.execution_mode, acknowledgements=x.ALL_ACKS, **kwargs)

    def test_a_reconciled_change_is_blocked_and_names_the_record(self):
        self.assertNotIn(self.CODE, self.gate(self.change).codes)
        record, _ = self.accept()
        report = self.gate(self.change)
        self.assertFalse(report.eligible)
        (found,) = [b for b in report.blockers if b["code"] == self.CODE]
        self.assertIn(record.record_id, found["message"])
        self.assertEqual(found["details"], {"records": [record.record_id], "devices": ["R2"]})
        self.assertEqual(service.superseding_records(self.change), [record])

    def test_no_acknowledgement_mode_or_fresh_plan_lifts_the_block(self):
        self.accept()
        for mode in models.ExecutionMode.values:
            with self.subTest(mode=mode):
                self.change.execution_mode = mode
                self.assertIn(self.CODE, es.check_execution_eligibility(
                    self.change, confirm_mode=mode, acknowledgements=x.ALL_ACKS, for_submission=True).codes)
        self.assertIn(self.CODE, self.gate(self.change, for_submission=False).codes)   # the page view shows it too

    def test_an_execution_attempt_is_refused_before_any_device_is_touched(self):
        self.accept()
        world = x.FakeWorld()
        before = models.ChangeExecutionRun.objects.filter(change=self.change).count()
        result = es.execute_change(self.change, actor="approver", confirm_mode=self.change.execution_mode, acknowledgements=x.ALL_ACKS,
                                   executor_factory=world.factory, evidence_provider=world.evidence_provider,
                                   notifier=x.Notifications(), sleep=lambda seconds: None, clock=x.stepping_clock())
        self.assertTrue(result.refused)
        self.assertIn(self.CODE, {b["code"] for b in result.blockers})
        self.assertEqual(world.mutating_calls(), [])
        applied = models.ChangeExecutionRun.objects.filter(change=self.change).exclude(outcome="BLOCKED").count()
        self.assertEqual(applied, before)

    def test_unrelated_changes_stay_executable_and_history_is_untouched(self):
        self.accept()
        other = x.prepared()
        self.assertNotIn(self.CODE, self.gate(other.change, sources=other.sources).codes)
        self.assertEqual(service.superseding_records(other.change), [])
        run = models.ChangeExecutionRun.objects.get(pk=self.exec_run.pk)
        self.assertEqual((run.state, run.outcome, run.plan_hash), (self.exec_run.state, self.exec_run.outcome, self.exec_run.plan_hash))
        self.assertEqual(models.Change.objects.get(pk=self.change.pk).lifecycle_state, self.change.lifecycle_state)


class PredatingChangeGateTests(ReconciliationFixture):
    """A Change that never took effect needs no reconciliation, but it must not run on top of a newer accepted baseline."""

    CODE = "BLOCKED_PREDATES_RECONCILED_BASELINE"

    def gate(self, prepared):
        return es.check_execution_eligibility(prepared.change, confirm_mode=prepared.change.execution_mode,
                                              acknowledgements=x.ALL_ACKS, sources=prepared.sources)

    def test_an_unexecuted_change_older_than_the_baseline_is_blocked_without_a_record_of_its_own(self):
        stale = x.prepared()                                  # targets R1/R2, never executed
        self.assertNotIn(self.CODE, self.gate(stale).codes)
        record, _ = self.accept()                             # R2 baseline accepted AFTER it was created
        report = self.gate(stale)
        (found,) = [b for b in report.blockers if b["code"] == self.CODE]
        self.assertIn(record.record_id, found["message"])
        self.assertEqual(found["details"], {"records": [record.record_id], "devices": ["R2"], "history": "NEVER_EXECUTED"})
        self.assertIn("never executed", found["message"])
        self.assertEqual(service.superseding_records(stale.change), [])            # no reconciliation was invented for it
        self.assertNotIn("BLOCKED_SUPERSEDED_BY_RECONCILIATION", report.codes)
        self.assertEqual(models.StateReconciliation.objects.count(), 1)

    def history(self, prepared):
        (found,) = [b for b in self.gate(prepared).blockers if b["code"] == self.CODE]
        return found["details"]["history"], found["message"]

    def test_the_reason_says_what_became_of_the_change(self):
        applied, rolled_back = x.prepared(), x.prepared()
        x.run(applied, x.FakeWorld())                          # succeeded, and is NOT one of the runs the record supersedes
        models.ChangeExecutionRun.objects.filter(pk=x.run(rolled_back, x.FakeWorld()).run.pk).update(outcome="POSTCHECK_FAILED_ROLLED_BACK")
        self.accept()
        history, message = self.history(applied)
        self.assertEqual(history, "APPLIED_BEFORE_BASELINE")
        self.assertIn("already part of the accepted state", message)
        history, message = self.history(rolled_back)
        self.assertEqual(history, "EXECUTED_AND_ROLLED_BACK")
        self.assertIn("rolled back", message)
        self.assertEqual(service.superseding_records(applied.change), [])
        self.assertEqual(models.StateReconciliation.objects.count(), 1)

    def test_an_execution_attempt_of_a_predating_change_touches_no_device(self):
        stale = x.prepared()
        self.accept()
        world = x.FakeWorld()
        result = x.run(stale, world, acks=x.ALL_ACKS)
        self.assertTrue(result.refused)
        self.assertIn(self.CODE, {b["code"] for b in result.blockers})
        self.assertEqual(world.mutating_calls(), [])

    def test_a_change_created_after_the_baseline_is_current_intent(self):
        self.accept()
        fresh = x.prepared()
        codes = self.gate(fresh).codes
        self.assertNotIn(self.CODE, codes)
        self.assertNotIn("BLOCKED_SUPERSEDED_BY_RECONCILIATION", codes)

    def test_the_superseded_reason_wins_for_a_change_that_did_execute(self):
        self.accept()
        codes = es.check_execution_eligibility(self.change, confirm_mode=self.change.execution_mode, acknowledgements=x.ALL_ACKS).codes
        self.assertIn("BLOCKED_SUPERSEDED_BY_RECONCILIATION", codes)
        self.assertNotIn(self.CODE, codes)


class BaselineDriftTests(ReconciliationFixture):
    """A reconciliation is a baseline at one digest.  It never disables drift detection."""

    def status(self, device="R2", text=R2_RUNNING):
        with running(text):
            return service.baseline_status(device)

    def test_the_accepted_state_is_in_sync(self):
        record, _ = self.accept()
        row = self.status()
        self.assertEqual((row["status"], row["record_id"], row["changed_sections"]), ("IN_SYNC", record.record_id, []))
        self.assertEqual(row["current"], record.accepted_digest)

    def test_a_later_configuration_change_is_drift(self):
        record, _ = self.accept()
        row = self.status(text=R2_RUNNING.replace("router rip", "router rip\n   network 10.0.0.0/8"))
        self.assertEqual((row["status"], row["accepted"]), ("DRIFT", record.accepted_digest))
        self.assertNotEqual(row["current"], record.accepted_digest)
        self.assertEqual(row["changed_sections"], ["running-config"])

    def test_an_unreadable_device_is_never_reported_in_sync(self):
        self.accept()
        self.assertEqual(self.status(text=None)["status"], "UNAVAILABLE")

    def test_a_device_without_a_record_gets_no_borrowed_baseline(self):
        self.accept()                                       # R2 only
        row = self.status("R1", text="hostname R1\nend\n")
        self.assertEqual((row["status"], row["record_id"]), ("NO_BASELINE", None))

    def test_reading_the_baseline_writes_nothing(self):
        self.accept()
        before = (models.StateReconciliation.objects.count(), models.AuditEvent.objects.count(),
                  list(models.ChangeExecutionRun.objects.values_list("pk", "state", "outcome")))
        self.status(); self.status(text=R2_RUNNING + "ip routing\n")
        self.assertEqual((models.StateReconciliation.objects.count(), models.AuditEvent.objects.count(),
                          list(models.ChangeExecutionRun.objects.values_list("pk", "state", "outcome"))), before)


class DigestTests(TestCase):
    def test_record_digest_changes_with_any_accepted_fact(self):
        one = service._digest({"domain": "nmas.reconciliation.record", "value": {"device_name": "R2", "reason": "a"}})
        two = service._digest({"domain": "nmas.reconciliation.record", "value": {"device_name": "R2", "reason": "b"}})
        self.assertNotEqual(one, two)
        self.assertEqual(len(one), len(hashlib.sha256(b"").hexdigest()))
