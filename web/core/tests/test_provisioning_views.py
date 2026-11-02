"""V2 Phase 5A provisioning pages: routing, rendering, RBAC classification and the explicit-confirmation contract (fakes only)."""

from __future__ import annotations

from unittest import mock

from django.test import TestCase
from django.urls import reverse

from core import models
from core.services import provisioning_service as ps
from core.services.identity import policy
from core.tests.helpers import provisioning as p

STAGE_ROUTES = ("identity", "bootstrap", "capability", "ipam", "candidate", "validation", "plan", "precheck", "approve",
                "nsot_sync", "probation", "cancel", "decommission")


class ProvisioningViewTests(TestCase):
    def _get(self, url):
        return self.client.get(url, follow=False)

    def test_list_page_renders_and_shows_honest_bootstrap_support(self):
        response = self._get(reverse("core:provisioning_list"))
        self.assertContains(response, "New device provisioning")
        self.assertContains(response, "UNSUPPORTED")
        self.assertContains(response, "No provisioning request has been created.")

    def test_create_refusal_redirects_with_stable_codes_only(self):
        response = self.client.post(reverse("core:provisioning_create"), {"device_name": "R1", "platform": p.FRR, "role": "router"})
        self.assertIn("codes=NAME_CONFLICT", response.url)
        self.assertEqual(models.ProvisioningRun.objects.count(), 0)

    def test_create_and_detail(self):
        response = self.client.post(reverse("core:provisioning_create"),
                                    {"device_name": "EDGE1", "platform": p.FRR, "role": "router", "disposable": "on"})
        run = models.ProvisioningRun.objects.first()
        self.assertEqual(response.url, run.get_absolute_url())
        self.assertTrue(run.disposable)
        detail = self._get(run.get_absolute_url())
        self.assertContains(detail, run.prov_id)
        self.assertContains(detail, "Record identity")
        self.assertContains(detail, "never DHCP or DHCPv6")

    def test_detail_shows_blockers_evidence_and_seven_day_probation(self):
        lab = p.Lab()
        lab.through("sync")
        ps.start_probation(lab.run, actor="approver")
        detail = self._get(lab.run.get_absolute_url())
        self.assertContains(detail, lab.run.candidate_hash)
        self.assertContains(detail, lab.run.post_config_digest)
        self.assertContains(detail, lab.run.soak_run.soak_id)
        self.assertContains(detail, "interface.LOOPBACK")
        self.assertContains(detail, "7d 0h 0m (168 h)")
        self.assertNotContains(detail, "30 minutes")

    def test_unknown_request_is_404(self):
        response = self._get(reverse("core:provisioning_detail", args=["PROV-999999"]))
        self.assertEqual(response.status_code, 404)

    def test_approval_probation_and_cancel_routes_need_explicit_confirmation(self):
        lab = p.Lab()
        lab.through("precheck")
        with mock.patch.object(ps, "approve") as approve, mock.patch.object(ps, "start_probation") as probation, \
                mock.patch.object(ps, "cancel") as cancel:
            for name in ("approve", "probation", "cancel"):
                self.client.post(reverse(f"core:provisioning_{name}", args=[lab.run.prov_id]), {"candidate_hash": lab.run.candidate_hash})
            self.assertFalse(approve.called or probation.called or cancel.called)

    def test_mutating_routes_refuse_get(self):
        lab = p.Lab()
        for name in STAGE_ROUTES:
            response = self.client.get(reverse(f"core:provisioning_{name}", args=[lab.run.prov_id]))
            self.assertEqual(response.status_code, 405, name)
        self.assertEqual(lab.run.events.count(), 0)


class ProvisioningAccessPolicyTests(TestCase):
    def test_every_route_is_classified_with_the_permission_of_its_lifecycle_step(self):
        self.assertIn("provisioning_list", policy.READ_ROUTES)
        self.assertIn("provisioning_detail", policy.READ_ROUTES)
        actions = policy.MUTATION_ROUTES
        self.assertNotIn("provisioning_provision", actions)                              # no provisioning route writes to a device
        self.assertEqual(actions["change_execute_run"], policy.Action.EXECUTE)           # ... the ordinary execute route does
        for name in ("approve", "nsot_sync", "probation", "decommission"):
            self.assertEqual(actions[f"provisioning_{name}"], policy.Action.APPROVE, name)
        for name in ("ipam", "plan"):
            self.assertEqual(actions[f"provisioning_{name}"], policy.Action.PLAN, name)
        for name in STAGE_ROUTES:
            self.assertIn(f"provisioning_{name}", actions, name)
