"""Lab 7 closure -- the Maintenance list / cancel pages and the Configuration Validation command's refusals.

Pages run on the production-shaped fake network of ``test_maintenance_live`` with every device or host contact patched
to fail the test (as in ``test_maintenance_web``).  POSITIVE: a confirmed cancel by an operator succeeds and the record
is CANCELLED.  NEGATIVE: an empty list shows no record in any group; the command refuses an unknown Change and a Change
without a passing validation run before any GitHub call.
"""

from __future__ import annotations

from unittest import mock

from django.core.management import CommandError, call_command
from django.test import Client, TestCase
from django.urls import reverse

from core import models
from core.services.identity.policy import Action
from core.services.maintenance_mode import collector, drain, lifecycle, service
from core.services.route_shield import migration
from core.tests import test_maintenance_live as live
from core.tests import test_maintenance_web as mw
from core.tests.helpers.validation import new_change
from core.tests.runner import make_test_operator, sign_in


class MaintenanceListAndCancelTests(TestCase):
    def setUp(self):
        runtime = service.Runtime(live.sources(states=live.READY), mw.no_device, mw.no_device, migration.PRODUCTION, gated=False, probe_warmup=0,
                                  sleep=lambda _s: None, writable=lambda: {"R1", "R2", "R3", "R4", "S1", "S2", "mgmt_swt"})
        for patch in (mock.patch.object(service, "production_runtime", lambda: runtime),
                      mock.patch.object(collector, "observe", mw.no_device), mock.patch.object(drain, "capture", mw.no_device)):
            patch.start()
            self.addCleanup(patch.stop)
        self.operator, self.viewer = Client(), Client()
        sign_in(self.operator, make_test_operator("mm-operator", actions=(Action.VIEW, Action.EDIT, Action.VALIDATE, Action.PLAN)))
        sign_in(self.viewer, make_test_operator("mm-viewer", actions=(Action.VIEW,)))

    def test_operator_cancel_of_a_confirmed_record_succeeds(self):
        row = mw.MaintenancePagesTests.planned(self)
        response = self.operator.post(reverse("core:maintenance_cancel", args=[row.record_id]), {"confirm": "on", "confirm_id": row.record_id.lower()})
        self.assertRedirects(response, f"{reverse('core:maintenance_detail', args=[row.record_id])}?notice=CANCELLED", fetch_redirect_response=False)
        row.refresh_from_db()
        self.assertEqual(row.state, lifecycle.CANCELLED)

    def test_maintenance_list_without_records_is_empty_in_every_group(self):
        response = self.viewer.get(reverse("core:maintenance_list"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["groups"], {"active": [], "pending": [], "blocked": [], "historical": []})
        self.assertEqual(models.MaintenanceRecord.objects.count(), 0)


class ConfigurationValidationCommandTests(TestCase):
    def test_command_refuses_an_unknown_change_or_one_without_a_passing_run(self):
        with mock.patch("core.services.configuration_validation.github._call", side_effect=AssertionError("GitHub was called")):
            with self.assertRaisesRegex(CommandError, "No such Change"):
                call_command("nmas_configuration_validation", "status", "--change", "CHG-NOPE")
            change = new_change("never validated")
            with self.assertRaisesRegex(CommandError, "needs a passing validation run"):
                call_command("nmas_configuration_validation", "demo-failure", "--change", change.change_id, "--actor", "tester")
