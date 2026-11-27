"""The lifecycle stage projection: derived (never stored) stages, separate verdicts, legacy truthfulness, evidence and its pages."""

from __future__ import annotations

from io import StringIO

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.db import connection
from django.test import Client, TestCase
from django.urls import reverse

from core import models
from core.services.devices import lifecycle, stage_report
from core.services.identity import policy
from core.tests.helpers import lifecycle as L
from core.tests.runner import sign_in

ONBOARDING = ("DISCOVERED", "AUTHORIZED", "BOOTSTRAPPED", "ISOLATED", "COMMISSIONING")


def user_client(username, *roles):
    user = get_user_model().objects.create_user(username=username, password="correct-horse-battery-9")
    for role in roles:
        user.groups.add(Group.objects.get(name=role))
    client = Client()
    sign_in(client, get_user_model().objects.get(pk=user.pk))
    return client


def raw_update(model, column, value, pk):
    """Out-of-band tampering (the ORM refuses it): the projection must detect, never repair."""
    with connection.cursor() as cursor:
        cursor.execute(f"UPDATE {model._meta.db_table} SET {column} = %s WHERE id = %s", [value, pk])


def stages(report):
    return {s["stage"]: s["status"] for s in report["stages"]}


class LegacyTruthfulnessTests(TestCase):
    def setUp(self):
        self.device = L.adopt().device

    def test_an_adopted_device_has_no_fabricated_onboarding_history(self):
        report = stage_report.device_report(self.device)
        got = stages(report)
        self.assertEqual(list(got), list(stage_report.STAGES))
        self.assertEqual(got["REGISTERED"], stage_report.COMPLETE)
        for name in ONBOARDING:
            self.assertEqual(got[name], stage_report.PREDATES, name)
        self.assertEqual(got["IN_SERVICE"], stage_report.CURRENT)
        self.assertEqual(report["admission_state"], models.ProductionAdmissionState.LEGACY_PREEXISTING)
        self.assertIn("not an NMAS admission", report["verdicts"]["admission"]["meaning"])
        self.assertTrue(report["legacy"])

    def test_the_projection_writes_nothing(self):
        counts = (models.DeviceLifecycleEvent.objects.count(), models.AuditEvent.objects.count(), models.ManagedDevice.objects.get(pk=self.device.pk).version)
        stage_report.fleet_report()
        self.assertEqual(counts, (models.DeviceLifecycleEvent.objects.count(), models.AuditEvent.objects.count(),
                                  models.ManagedDevice.objects.get(pk=self.device.pk).version))

    def test_fleet_summary_never_counts_legacy_as_admitted(self):
        summary = stage_report.fleet_report()["summary"]
        self.assertEqual((summary["admitted"], summary["legacy_preexisting"]), (0, 1))


class NewDeviceStageTests(TestCase):
    """The projection itself, fed by the lifecycle service directly (the ZTP pipeline has its own suites)."""
    def test_registered_and_authorized_but_not_yet_discovered(self):
        device, _attachment, auth = L.ready_device()
        report = stage_report.device_report(device)
        got = stages(report)
        self.assertEqual((got["REGISTERED"], got["DISCOVERED"], got["AUTHORIZED"], got["IN_SERVICE"]),
                         (stage_report.COMPLETE, stage_report.PENDING, stage_report.COMPLETE, stage_report.PENDING))
        verdict = report["verdicts"]["authorization"]
        self.assertEqual((verdict["auth_id"], verdict["live"], verdict["expired"]), (auth.auth_id, True, False))
        self.assertEqual(report["verdicts"]["identity"]["expected"], {"serial": L.SERIAL, "base_mac": L.MAC})
        self.assertIsNone(report["verdicts"]["identity"]["verified"])
        self.assertFalse(report["verdicts"]["readiness"]["ready"])

    def test_discovery_is_an_observation_never_identity_proof(self):
        device, _attachment, _auth = L.ready_device()
        identity = lifecycle.record_observation(device, kind=models.ObservationKind.IDENTITY, source=models.ObservationSource.DHCP_CLIENT_CLAIM,
                                                actor="system:ztp-dhcp-ingest", claims={"serial": L.SERIAL, "base_mac": L.MAC})
        self.assertTrue(identity.ok, identity.codes)
        attached = lifecycle.record_observation(device, kind=models.ObservationKind.ATTACHMENT, source=models.ObservationSource.DHCP_RELAY_ATTACHMENT,
                                                actor="system:ztp-dhcp-ingest", upstream_device="S1", upstream_interface="Ethernet7")
        self.assertTrue(attached.ok, attached.codes)
        report = stage_report.device_report(models.ManagedDevice.objects.get(pk=device.pk))
        got = stages(report)
        self.assertEqual(got["DISCOVERED"], stage_report.COMPLETE)
        self.assertEqual(got["IDENTITY_VERIFIED"], stage_report.PENDING)
        identity = report["verdicts"]["identity"]
        self.assertEqual(identity["state"], models.IdentityVerificationState.PENDING_VERIFICATION)
        self.assertEqual(identity["claimed"]["source"], models.ObservationSource.DHCP_CLIENT_CLAIM)
        self.assertEqual(identity["claimed"]["claims"]["serial"], L.SERIAL)
        self.assertEqual(report["verdicts"]["observation"]["latest_attachment_observation"]["upstream"], "S1:Ethernet7")
        self.assertEqual(report["admission_state"], models.ProductionAdmissionState.NOT_ADMITTED)


class EvidenceTests(TestCase):
    def setUp(self):
        self.device = L.adopt().device

    def test_an_altered_event_breaks_the_chain_and_readiness(self):
        event = self.device.lifecycle_events.order_by("sequence").first()
        raw_update(models.DeviceLifecycleEvent, "evidence", '{"tampered": true}', event.pk)
        report = stage_report.device_report(self.device)
        self.assertFalse(report["evidence"]["chain_intact"])
        self.assertFalse(report["verdicts"]["readiness"]["ready"])
        self.assertIn("lifecycle evidence chain broken", report["verdicts"]["readiness"]["reasons"])

    def test_command_verify_fails_on_a_broken_chain(self):
        out = StringIO()
        call_command("nmas_lifecycle_report", "--verify", stdout=out)
        self.assertIn("LEGACY_PREEXISTING", out.getvalue())
        event = self.device.lifecycle_events.order_by("sequence").first()
        raw_update(models.DeviceLifecycleEvent, "actor", "someone-else", event.pk)
        with self.assertRaises(SystemExit) as raised:
            call_command("nmas_lifecycle_report", "--verify", stdout=StringIO(), stderr=StringIO())
        self.assertEqual(raised.exception.code, 2)

    def test_command_verify_fails_when_an_adopted_device_claims_admission(self):
        raw_update(models.ManagedDevice, "admission_state", models.ProductionAdmissionState.ADMITTED, self.device.pk)
        with self.assertRaises(SystemExit):
            call_command("nmas_lifecycle_report", "--verify", stdout=StringIO(), stderr=StringIO())

    def test_command_json_for_one_device(self):
        out = StringIO()
        call_command("nmas_lifecycle_report", "--json", "--device", self.device.device_id, stdout=out)
        self.assertIn('"schema": "nmas.lifecycle.stage-report/1"', out.getvalue())


class PageTests(TestCase):
    def setUp(self):
        self.device = L.adopt().device
        self.viewer = user_client("olivia", "NMAS Operator")

    def test_routes_are_read_only_and_json_is_audited(self):
        for name in ("lifecycle_overview", "lifecycle_overview_json", "lifecycle_device", "lifecycle_device_json"):
            self.assertIn(name, policy.READ_ROUTES)
            self.assertNotIn(name, policy.MUTATION_ROUTES)
        self.assertTrue({"lifecycle_overview_json", "lifecycle_device_json"} <= policy.SENSITIVE_READ_ROUTES)

    def test_overview_and_device_pages_render(self):
        response = self.viewer.get(reverse("core:lifecycle_overview"))
        self.assertContains(response, "Device lifecycle")
        self.assertContains(response, "PREDATES_NMAS")
        self.assertContains(response, self.device.device_id)
        response = self.viewer.get(reverse("core:lifecycle_device", args=[self.device.device_id]))
        for text in ("IDENTITY_VERIFIED", "Bootstrap authorization", "Management path selection", "Transition failures", "Hash chain"):
            self.assertContains(response, text)
        self.assertEqual(self.viewer.get(reverse("core:lifecycle_device", args=["DEV-999999"])).status_code, 404)

    def test_device_page_renders_refused_transitions(self):
        """Live-data regression: a refused event row (no record state) must render, not raise VariableDoesNotExist."""
        refused = lifecycle.transition(self.device, models.DeviceLifecycleState.COMMISSIONING, actor=L.OPERATOR)
        self.assertFalse(refused.ok)
        report = stage_report.device_report(self.device)
        self.assertTrue(report["failures"])
        self.assertEqual({tuple(sorted(row)) for row in report["failures"]},
                         {("at", "codes", "kind", "reference", "rollback", "status")})
        response = self.viewer.get(reverse("core:lifecycle_device", args=[self.device.device_id]))
        self.assertContains(response, "TRANSITION_COMMISSIONING")
        self.assertContains(response, "REFUSED")

    def test_json_documents(self):
        body = self.viewer.get(reverse("core:lifecycle_device_json", args=[self.device.device_id])).json()
        self.assertEqual(body["schema"], stage_report.REPORT_SCHEMA)
        self.assertEqual(self.viewer.get(reverse("core:lifecycle_overview_json")).json()["summary"]["devices"], 1)

    def test_anonymous_is_refused_and_post_is_not_allowed(self):
        anonymous = Client()
        self.assertIn(anonymous.get(reverse("core:lifecycle_overview")).status_code, (302, 401, 403))
        self.assertIn(anonymous.get(reverse("core:lifecycle_overview_json")).status_code, (302, 401, 403))
        self.assertIn(self.viewer.post(reverse("core:lifecycle_overview")).status_code, (403, 405))
