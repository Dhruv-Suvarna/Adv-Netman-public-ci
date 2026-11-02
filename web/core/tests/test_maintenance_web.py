"""Maintenance Mode pages: authorization per role, CSRF, POST-only actions, rendering, and that no page contacts a device.

Plain ``django.test.Client`` instances signed in with exactly the permissions of one role: the access boundary is the
middleware's, never assumed.  The network is the production-shaped fake of ``test_maintenance_live``; any device or host
contact from a page fails the test."""

from __future__ import annotations

from datetime import timedelta
from unittest import mock

from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from core import models
from core.services import automation_service
from core.services.identity import policy
from core.services.identity.policy import Action
from core.services.maintenance_mode import collector, drain, lifecycle, service
from core.services.route_shield import migration
from core.tests import test_maintenance_live as live
from core.tests.runner import make_test_operator, sign_in

ROLES = {"viewer": (Action.VIEW,), "operator": (Action.VIEW, Action.EDIT, Action.VALIDATE, Action.PLAN),
         "approver": (Action.VIEW, Action.APPROVE), "executor": (Action.VIEW, Action.EXECUTE)}
PAGES = ("maintenance_detail", "maintenance_readiness", "maintenance_plan", "maintenance_history")
ACTIONS = {"maintenance_evaluate": Action.VALIDATE, "maintenance_approve": Action.APPROVE, "maintenance_cancel": Action.EDIT,
           "maintenance_enter": Action.EXECUTE, "maintenance_restore": Action.EXECUTE}


def no_device(*args, **kwargs):
    raise AssertionError("a Maintenance page contacted a device or a host")


class MaintenancePagesTests(TestCase):
    def setUp(self):
        self.runtime = service.Runtime(live.sources(states=live.READY), no_device, no_device, migration.PRODUCTION, gated=False, probe_warmup=0,
                                       sleep=lambda _s: None, writable=lambda: {"R1", "R2", "R3", "R4", "S1", "S2", "mgmt_swt"})
        for patch in (mock.patch.object(service, "production_runtime", lambda: self.runtime),
                      mock.patch.object(collector, "observe", no_device), mock.patch.object(drain, "capture", no_device)):
            patch.start()
            self.addCleanup(patch.stop)
        self.clients = {}
        for role, actions in ROLES.items():
            client = Client()
            sign_in(client, make_test_operator(f"mm-{role}", actions=actions))
            self.clients[role] = client

    def planned(self, device="R1", state=lifecycle.PLANNED):
        """A record with a real plan, built through the service on the fake network (the only place a device is 'read')."""
        devices = {name: live.FakeDevice(name, []) for name in ("S1", "R1", "S2", "R2", "R3", "R4")}

        def environment():
            env = live.environment([])
            env.executors = dict(devices)
            return env

        runtime = service.Runtime(live.sources(states=live.READY), environment, lambda env: None, migration.PRODUCTION, gated=False, probe_warmup=0, sleep=lambda _s: None)
        now = timezone.now()                                                  # a plan is valid for PLAN_VALIDITY from now
        with mock.patch.object(live, "T0", now):                              # and is built only from evidence read FRESH at that moment
            scripted = [live.observation(device, moved=False, active=live.ACTIVE_H1)]
        with mock.patch.object(collector, "observe", lambda d, s: scripted.pop(0)), \
                mock.patch.object(drain, "capture", lambda env, access, definition: (dict(live.STATE), [])), \
                mock.patch.object(drain, "operations", lambda access, definition, state, cells, drain: live.simple_ops(drain)), \
                mock.patch.object(drain, "final_checks", lambda *a, **k: ()):
            row = service.request(device, "mm-operator", "replace a line card", timedelta(hours=3), now=now, runtime=runtime)
            row = service.evaluate(row.pk, "mm-operator", now=now, runtime=runtime)
        if state == lifecycle.APPROVED:
            row = service.approve(row.pk, "mm-approver", now=now, plan_hash=row.plan_hash)
        return row

    def url(self, name, row=None):
        return reverse(f"core:{name}", args=[row.record_id] if row is not None else [])

    # -- routes ---------------------------------------------------------------------------------------------------------
    def test_every_maintenance_route_is_classified_and_device_changes_need_execute(self):
        for name in ("maintenance_list", *PAGES):
            self.assertIn(name, policy.READ_ROUTES)
        for name, action in ACTIONS.items():
            self.assertEqual(policy.MUTATION_ROUTES[name], action)
        self.assertEqual(policy.MUTATION_ROUTES["maintenance_request"], Action.EDIT)
        self.assertEqual(automation_service.IMPLEMENTED_SECTIONS["maintenance-mode"], "core:maintenance_list")

    def test_every_page_renders_for_a_viewer_and_contacts_no_device(self):
        row = self.planned()
        viewer = self.clients["viewer"]
        self.assertContains(viewer.get(self.url("maintenance_list")), row.record_id)
        for name in PAGES:
            with self.subTest(page=name):
                self.assertEqual(viewer.get(self.url(name, row)).status_code, 200)
        plan_page = viewer.get(self.url("maintenance_plan", row))
        self.assertContains(plan_page, row.plan_hash)
        self.assertContains(plan_page, "isis metric 1000")
        self.assertContains(plan_page, "Approving needs the Approver role")
        readiness = viewer.get(self.url("maintenance_readiness", row))
        self.assertContains(readiness, "h1-v6-north")
        self.assertContains(readiness, "ISIS_ACCESS_METRIC_STEER")
        self.assertContains(viewer.get(self.url("maintenance_history", row)), "INTACT")
        self.assertEqual(viewer.get(reverse("core:maintenance_detail", args=["MNT-999999"])).status_code, 404)

    def test_the_request_page_shows_the_writable_scope_and_the_tracked_affected_scope(self):
        page = self.clients["operator"].get(self.url("maintenance_request"))
        self.assertContains(page, '<option value="R1"')
        self.assertNotContains(page, '<option value="R5"')
        self.assertContains(page, "Outside the writable managed scope")
        self.assertContains(page, "H1, H2")                                   # single-homed to S1, from the tracked cabling

    # -- RBAC -----------------------------------------------------------------------------------------------------------
    def test_a_viewer_can_change_nothing(self):
        row = self.planned(state=lifecycle.APPROVED)
        viewer = self.clients["viewer"]
        self.assertEqual(viewer.post(self.url("maintenance_request"), {"device": "R2", "reason": "x", "hours": "1"}).status_code, 403)
        for name in ACTIONS:
            with self.subTest(action=name):
                self.assertEqual(viewer.post(self.url(name, row), {"confirm": "on", "confirm_id": row.record_id, "plan_hash": row.plan_hash}).status_code, 403)
        row.refresh_from_db()
        self.assertEqual((row.state, row.queued_action, models.MaintenanceRecord.objects.count()), (lifecycle.APPROVED, "", 1))

    def test_each_role_can_do_exactly_its_own_step(self):
        operator, approver, executor = self.clients["operator"], self.clients["approver"], self.clients["executor"]
        response = operator.post(self.url("maintenance_request"), {"device": "R2", "reason": "fan", "hours": "200"})   # beyond 7 days: not capped
        created = models.MaintenanceRecord.objects.get(device_name="R2")
        self.assertRedirects(response, f"{self.url('maintenance_detail', created)}?notice=REQUESTED", fetch_redirect_response=False)
        self.assertEqual((created.requested_by, created.requested_duration_seconds), ("mm-operator", 200 * 3600))
        self.assertEqual(operator.post(self.url("maintenance_evaluate", created), {"confirm": "on"}).status_code, 302)
        created.refresh_from_db()
        self.assertEqual((created.queued_action, created.queued_by), (service.EVALUATE, "mm-operator"))

        row = self.planned()
        for client, name in ((operator, "maintenance_approve"), (executor, "maintenance_approve"), (operator, "maintenance_enter"), (approver, "maintenance_enter")):
            with self.subTest(client=client, action=name):
                self.assertEqual(client.post(self.url(name, row), {"confirm": "on", "confirm_id": row.record_id, "plan_hash": row.plan_hash}).status_code, 403)
        approver.post(self.url("maintenance_approve", row), {"confirm": "on", "plan_hash": row.plan_hash})
        row.refresh_from_db()
        self.assertEqual((row.state, row.approved_by), (lifecycle.APPROVED, "mm-approver"))
        executor.post(self.url("maintenance_enter", row), {"confirm": "on", "confirm_id": row.record_id, "plan_hash": row.plan_hash})
        row.refresh_from_db()
        self.assertEqual((row.state, row.queued_action, row.queued_by), (lifecycle.APPROVED, service.ENTER, "mm-executor"))   # queued, nothing contacted

    def test_approval_must_name_the_plan_that_was_shown(self):
        row = self.planned()
        response = self.clients["approver"].post(self.url("maintenance_approve", row), {"confirm": "on", "plan_hash": "f" * 64})
        self.assertIn("PLAN_HASH_MISMATCH", response["Location"])
        row.refresh_from_db()
        self.assertEqual(row.state, lifecycle.PLANNED)
        response = self.clients["approver"].post(self.url("maintenance_approve", row), {"plan_hash": row.plan_hash})      # no confirmation
        self.assertIn("CONFIRM_REQUIRED", response["Location"])

    def test_a_refusal_shows_only_a_stable_code_never_text_from_the_link(self):
        row = self.planned()
        response = self.clients["approver"].post(self.url("maintenance_approve", row), {"confirm": "on", "plan_hash": "f" * 64})
        self.assertNotIn("detail=", response["Location"])
        page = self.clients["viewer"].get(self.url("maintenance_plan", row) + "?notice=REFUSED&code=PLAN_HASH_MISMATCH&detail=Call+0800+now")
        self.assertContains(page, "PLAN_HASH_MISMATCH")
        self.assertNotContains(page, "Call 0800")
        page = self.clients["viewer"].get(self.url("maintenance_plan", row) + "?notice=REFUSED&code=%3Cb%3Ex%3C/b%3E")
        self.assertNotContains(page, "<b>x</b>")

    def test_device_changing_actions_need_the_typed_confirmation(self):
        row = self.planned(state=lifecycle.APPROVED)
        executor = self.clients["executor"]
        for data in ({"plan_hash": row.plan_hash, "confirm": "on"}, {"plan_hash": row.plan_hash, "confirm_id": row.record_id},
                     {"plan_hash": row.plan_hash, "confirm": "on", "confirm_id": "MNT-000777"}):
            with self.subTest(data=data):
                self.assertIn("CONFIRM_REQUIRED", executor.post(self.url("maintenance_enter", row), data)["Location"])
        row.refresh_from_db()
        self.assertEqual(row.queued_action, "")
        self.assertIn("PLAN_HASH_MISMATCH", executor.post(self.url("maintenance_enter", row), {"confirm": "on", "confirm_id": row.record_id, "plan_hash": "0" * 64})["Location"])
        models.MaintenanceRecord.objects.filter(pk=row.pk).update(state=lifecycle.ACTIVE)
        self.assertIn("RESTORE_QUEUED", executor.post(self.url("maintenance_restore", row), {"confirm": "on", "confirm_id": row.record_id.lower()})["Location"])
        row.refresh_from_db()
        self.assertEqual(row.queued_action, service.RESTORE)

    def test_write_actions_are_post_only_and_csrf_protected(self):
        row = self.planned(state=lifecycle.APPROVED)
        full = Client()
        sign_in(full, make_test_operator("mm-full"))
        for name in ACTIONS:
            with self.subTest(action=name):
                self.assertEqual(full.get(self.url(name, row)).status_code, 405)
        guarded = Client(enforce_csrf_checks=True)
        sign_in(guarded, make_test_operator("mm-full"))
        self.assertEqual(guarded.post(self.url("maintenance_enter", row), {"confirm": "on", "confirm_id": row.record_id, "plan_hash": row.plan_hash}).status_code, 403)
        self.assertEqual(guarded.post(self.url("maintenance_request"), {"device": "R2", "reason": "x", "hours": "1"}).status_code, 403)
        row.refresh_from_db()
        self.assertEqual((row.queued_action, models.MaintenanceRecord.objects.count()), ("", 1))

    def test_anonymous_and_mfa_pending_users_are_refused(self):
        row = self.planned()
        anonymous = Client()
        self.assertEqual(anonymous.get(self.url("maintenance_detail", row)).status_code, 302)
        pending = Client()
        sign_in(pending, make_test_operator("mm-pending"), mfa_verified=False)
        response = pending.post(self.url("maintenance_enter", row), {"confirm": "on", "confirm_id": row.record_id, "plan_hash": row.plan_hash})
        self.assertIn("/accounts/mfa/", response["Location"])                  # sent to website MFA (enrol or verify); the view never ran
        row.refresh_from_db()
        self.assertEqual(row.queued_action, "")

    def test_a_request_outside_the_writable_scope_is_refused_by_the_server(self):
        response = self.clients["operator"].post(self.url("maintenance_request"), {"device": "R5", "reason": "x", "hours": "1"})
        self.assertContains(response, "TARGET_OUTSIDE_WRITABLE_SCOPE")
        self.assertFalse(models.MaintenanceRecord.objects.exists())
        response = self.clients["operator"].post(self.url("maintenance_request"), {"device": "R1", "reason": "x", "hours": "0"})
        self.assertContains(response, "positive number of hours")

    def test_the_audit_ledger_records_who_did_each_step(self):
        row = self.planned()
        self.clients["approver"].post(self.url("maintenance_approve", row), {"confirm": "on", "plan_hash": row.plan_hash})
        event = models.AuditEvent.objects.filter(object_id=row.record_id, metadata__kind="APPROVAL").get()
        self.assertEqual((event.actor, event.actor_user.username, event.metadata["plan_hash"]), ("mm-approver", "mm-approver", row.plan_hash))
        self.assertTrue(models.AuditEvent.objects.filter(event_type="WEB_ACTION", route__icontains="maintenance_approve").exists())
