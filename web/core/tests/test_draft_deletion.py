"""Phase 20.5 (spec section 13): explicit draft-lifecycle delete/abandon.

Candidate generation never deploys; a never-executed DRAFT Change may be
permanently discarded as pure application state, and this can NEVER alter a
device, NetBox, or a Golden/Probation/UAT bundle. See
docs/DEVICE_INTENT_CHANGE_MODEL.md "Draft deletion".
"""

from __future__ import annotations

from django.test import TestCase
from django.urls import reverse

from core import models
from core.services import change_service
from core.tests.helpers import bundles as bh
from core.tests.helpers import execution as ex
from core.tests.helpers.candidates import make_candidate
from core.tests.helpers.validation import simple_pass_change


class DeleteDraftChangeServiceTests(TestCase):
    def test_confirmation_is_required(self):
        change, _, _ = make_candidate()
        with self.assertRaisesRegex(change_service.DraftDeletionError, "DELETE confirmation"):
            change_service.delete_draft_change(change=change, confirmation="")
        self.assertTrue(models.Change.objects.filter(pk=change.pk).exists())

    def test_a_draft_change_can_be_deleted(self):
        change, intent, revision = make_candidate()
        change_id = change.change_id
        change_service.delete_draft_change(change=change, confirmation="DELETE", actor="tester")
        self.assertFalse(models.Change.objects.filter(pk=change.pk).exists())
        self.assertFalse(models.DeviceIntent.objects.filter(pk=intent.pk).exists())
        self.assertFalse(models.DeviceIntentRevision.objects.filter(pk=revision.pk).exists())

    def test_deletion_leaves_an_audit_trail_that_survives_the_change(self):
        change, _, _ = make_candidate()
        change_id = change.change_id
        change_service.delete_draft_change(change=change, confirmation="DELETE", actor="tester")
        event = models.AuditEvent.objects.filter(
            event_type=models.AuditEventType.DRAFT_CHANGE_DELETED, object_id=change_id
        ).first()
        self.assertIsNotNone(event)
        self.assertIsNone(event.change)  # SET_NULL: the audit row outlives the deleted Change
        self.assertEqual(event.actor, "tester")

    def test_a_non_draft_change_is_refused(self):
        change, _, _ = make_candidate()
        change.lifecycle_state = models.ChangeLifecycleState.VALIDATED
        change.save(update_fields=["lifecycle_state"])
        with self.assertRaisesRegex(change_service.DraftDeletionError, "still in DRAFT"):
            change_service.delete_draft_change(change=change, confirmation="DELETE")
        self.assertTrue(models.Change.objects.filter(pk=change.pk).exists())

    def test_a_change_with_recorded_precheck_history_is_refused(self):
        p = ex.prepared(simple_pass_change())
        self.assertEqual(p.change.lifecycle_state, models.ChangeLifecycleState.DRAFT)
        self.assertTrue(models.OperationalCheckRun.objects.filter(change=p.change).exists())
        with self.assertRaisesRegex(change_service.DraftDeletionError, "health/precheck history"):
            change_service.delete_draft_change(change=p.change, confirmation="DELETE")
        self.assertTrue(models.Change.objects.filter(pk=p.change.pk).exists())

    def test_a_change_with_execution_history_is_refused(self):
        run = bh.complete_run()
        self.assertTrue(models.ChangeExecutionRun.objects.filter(change=run.change).exists())
        with self.assertRaises(change_service.DraftDeletionError):
            change_service.delete_draft_change(change=run.change, confirmation="DELETE")
        self.assertTrue(models.Change.objects.filter(pk=run.change.pk).exists())
        calls_before = list(run.world.calls)
        with self.assertRaises(change_service.DraftDeletionError):
            change_service.delete_draft_change(change=run.change, confirmation="DELETE")
        # The refused delete attempt itself never touches the (simulated) device.
        self.assertEqual(run.world.calls, calls_before)

    def test_a_change_with_a_bundle_is_refused_and_the_bundle_is_untouched(self):
        run = bh.partial_run(through=0)
        bundle = bh.uat_of(run)
        with self.assertRaises(change_service.DraftDeletionError):
            change_service.delete_draft_change(change=run.change, confirmation="DELETE")
        self.assertTrue(models.Change.objects.filter(pk=run.change.pk).exists())
        self.assertTrue(models.ConfigurationBundle.objects.filter(pk=bundle.pk).exists())

    def test_deleting_one_draft_does_not_touch_another(self):
        keep, _, _ = make_candidate(device_name="R9")
        doomed, _, _ = make_candidate(device_name="R8")
        change_service.delete_draft_change(change=doomed, confirmation="DELETE")
        self.assertTrue(models.Change.objects.filter(pk=keep.pk).exists())
        self.assertFalse(models.Change.objects.filter(pk=doomed.pk).exists())


class DeleteDraftChangeViewTests(TestCase):
    def test_get_is_not_allowed(self):
        change, _, _ = make_candidate()
        response = self.client.get(reverse("core:device_builder_delete_change", args=[change.change_id]))
        self.assertEqual(response.status_code, 405)

    def test_post_without_confirmation_checkbox_is_refused_and_change_survives(self):
        change, _, _ = make_candidate()
        response = self.client.post(reverse("core:device_builder_delete_change", args=[change.change_id]), {})
        self.assertEqual(response.status_code, 302)
        self.assertIn("delete_error", response.url)
        self.assertTrue(models.Change.objects.filter(pk=change.pk).exists())

    def test_post_with_confirmation_deletes_and_redirects_to_the_changes_list(self):
        change, _, _ = make_candidate()
        change_id = change.change_id
        response = self.client.post(
            reverse("core:device_builder_delete_change", args=[change_id]), {"confirmation": "DELETE"}
        )
        self.assertRedirects(response, f"{reverse('core:device_builder_changes')}?deleted={change_id}")
        self.assertFalse(models.Change.objects.filter(change_id=change_id).exists())

    def test_changes_list_offers_delete_only_for_draft_rows(self):
        draft, _, _ = make_candidate(device_name="R1")
        executed = bh.complete_run().change
        response = self.client.get(reverse("core:device_builder_changes"))
        self.assertContains(
            response, reverse("core:device_builder_delete_change", args=[draft.change_id])
        )
        self.assertNotContains(
            response, reverse("core:device_builder_delete_change", args=[executed.change_id])
        )

    def test_change_detail_offers_delete_only_for_a_draft(self):
        draft, _, _ = make_candidate()
        response = self.client.get(reverse("core:device_builder_change_detail", args=[draft.change_id]))
        self.assertContains(response, "Delete Draft")

        executed = bh.complete_run().change
        response2 = self.client.get(reverse("core:device_builder_change_detail", args=[executed.change_id]))
        self.assertNotContains(response2, "Delete Draft")
