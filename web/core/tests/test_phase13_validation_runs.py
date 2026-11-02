from __future__ import annotations

import json

from django.test import TestCase

from core import models
from core.services import change_validation_service as cvs
from core.services.validation.findings import Status
from core.tests.helpers.validation import Dev, new_change, validate


class ValidationRunTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.change = new_change()
        cls.r1 = Dev(cls.change, "R1")
        cls.i1 = cls.r1.iface("Ethernet1")

    def test_run_belongs_to_change_and_records_provenance(self):
        run = validate(self.change)
        self.assertEqual(run.change_id, self.change.id)
        self.assertRegex(run.input_hash, r"^[0-9a-f]{64}$")
        self.assertRegex(run.source_hash, r"^[0-9a-f]{64}$")
        self.assertEqual(run.repository_head, "test-head")
        self.assertEqual(run.report["provenance"]["input_hash"], run.input_hash)
        self.assertEqual(run.intent_revision_map["R1"]["revision"], 1)
        self.assertIn("NETBOX", run.source_provenance["sources"])

    def test_history_appends_and_never_overwrites(self):
        first = validate(self.change)
        first_report = json.dumps(first.report, sort_keys=True)
        self.r1.set(f"interfaces.{self.i1['id']}.description", "v2")
        second = validate(self.change)
        self.assertEqual(self.change.validation_runs.count(), 2)
        self.assertNotEqual(first.run_id, second.run_id)
        first.refresh_from_db()
        self.assertEqual(json.dumps(first.report, sort_keys=True), first_report)
        self.assertEqual([r.pk for r in cvs.list_validation_runs(self.change)], [second.pk, first.pk])

    def test_completed_run_is_immutable(self):
        run = validate(self.change)
        run.status = Status.PASS_WITH_WARNINGS
        with self.assertRaises(ValueError):
            run.save()

    def test_status_vocabulary_is_enforced(self):
        with self.assertRaises(ValueError):
            models.ChangeValidationRun.objects.create(
                change=self.change, status="STALE", engine_version="x", input_hash="0" * 64, source_hash="0" * 64)
        self.assertEqual(set(models.ValidationRunStatus.values), set(Status.ALL))
        self.assertNotIn("STALE", Status.ALL)

    def test_validation_does_not_advance_lifecycle_or_validation_state(self):
        run = validate(self.change)
        self.change.refresh_from_db()
        self.assertEqual(run.status, "PASS")
        self.assertEqual(self.change.lifecycle_state, models.ChangeLifecycleState.DRAFT)
        self.assertEqual(self.change.validation_state, models.ValidationState.PENDING)
        self.assertEqual(self.change.lifecycle_events.count(), 1)

    def test_no_configlet_is_created(self):
        validate(self.change)
        self.assertEqual(models.Configlet.objects.count(), 0)
        self.assertEqual(models.ConfigletDependency.objects.count(), 0)

    def test_audit_event_records_run_without_snapshot_or_secrets(self):
        run = validate(self.change, actor="alice")
        event = models.AuditEvent.objects.get(event_type=models.AuditEventType.VALIDATION_RECORDED)
        self.assertEqual((event.actor, event.change_id, event.object_id), ("alice", self.change.id, str(run.run_id)))
        self.assertEqual(event.metadata["input_hash"], run.input_hash)
        self.assertEqual(set(event.metadata), {"run_id", "status", "input_hash", "errors", "warnings"})

    def test_no_notification_is_published(self):
        validate(self.change)
        self.assertEqual(models.Notification.objects.count(), 0)

    def test_report_json_is_sanitized(self):
        run = validate(self.change)
        document = cvs.serialize_validation_run(run)
        text = json.dumps(document)
        for word in ("password", "token", "webhook", "community"):
            self.assertNotIn(f'"{word}"', text.lower())
        self.assertEqual(document["change_id"], self.change.change_id)
        self.assertEqual(document["status"], run.status)

    def test_secret_shaped_evidence_is_redacted(self):
        from core.services.validation.findings import Finding
        finding = Finding(code="IP_DUPLICATE", message="x", evidence={"api_token": "s3cr3t", "nested": {"password": "p"}, "ok_ref": "v"})
        data = finding.to_dict()
        self.assertEqual(data["evidence"]["api_token"], "[REDACTED]")
        self.assertEqual(data["evidence"]["nested"]["password"], "[REDACTED]")
        self.assertEqual(data["evidence"]["ok_ref"], "v")

    def test_evidence_strings_and_lists_are_bounded(self):
        from core.services.validation.findings import Finding, MAX_LIST, MAX_STRING
        data = Finding(code="IP_DUPLICATE", message="m" * 5000,
                       evidence={"big": "x" * 5000, "many": list(range(500))}).to_dict()
        self.assertLessEqual(len(data["message"]), MAX_STRING)
        self.assertLessEqual(len(data["evidence"]["big"]), MAX_STRING)
        self.assertLessEqual(len(data["evidence"]["many"]), MAX_LIST)

    def test_run_is_addressed_only_through_its_change(self):
        run = validate(self.change)
        other = new_change("other")
        self.assertEqual(cvs.get_validation_run(self.change, run.run_id), run)
        self.assertIsNone(cvs.get_validation_run(other, run.run_id))
        self.assertIsNone(cvs.get_validation_run(self.change, "not-a-uuid"))

    def test_latest_validation(self):
        self.assertIsNone(cvs.get_latest_validation(self.change))
        first = validate(self.change)
        second = validate(self.change)
        self.assertEqual(cvs.get_latest_validation(self.change), second)
        self.assertNotEqual(first, second)
