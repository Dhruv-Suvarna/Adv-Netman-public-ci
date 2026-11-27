"""Direct governance tests for the lifecycle-branch additions: the stage projection's verdicts and its overview page
(devices/stage_report.py, lifecycle_views.py), the EOS control-plane closure and the OSPF admission release (isolation/eos.py),
the ZTP lease lifetime, the authorization window and the bootstrap path gate (ztp/lease.py, policy.py, workflow.py),
commissioning's bootstrap completion time and the provisioning close of an aborted commissioning.

A claim is never verified identity; a legacy device is never an admission; a device off the onboarding path is never ready;
an ended or expired binding is never active and a lapsed session re-advances only on a genuine renewal; the control plane
counts as closed only with NMAS's exact ACL; and an expired or missing grant carries no bootstrap further.
"""

from __future__ import annotations

from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.urls import reverse
from django.utils import timezone

from core import models
from core.services import provisioning_service as ps
from core.services.commissioning import service as commissioning
from core.services.devices import lifecycle, stage_report
from core.services.isolation import eos
from core.services.ztp import adapters, discovery, lease, policy, workflow
from core.tests import test_lifecycle_stage_report as SR
from core.tests import test_ztp_lease as T
from core.tests.helpers import lifecycle as L
from core.tests.helpers import provisioning as p
from core.tests.helpers import ztp as Z

S = models.DeviceLifecycleState


# ================================================================================================ stage report verdicts
class StageVerdictTests(TestCase):
    def test_identity_verdict_returns_the_expected_identity(self):
        device, _attachment, _auth = L.ready_device()
        verdict = stage_report.identity_verdict(device)
        self.assertEqual(verdict["expected"], {"serial": L.SERIAL, "base_mac": L.MAC})

    def test_identity_verdict_of_a_dhcp_claim_is_never_verified(self):
        device, _attachment, _auth = L.ready_device()
        lifecycle.record_observation(device, kind=models.ObservationKind.IDENTITY, source=models.ObservationSource.DHCP_CLIENT_CLAIM,
                                     actor="system:ztp-dhcp-ingest", claims={"serial": L.SERIAL, "base_mac": L.MAC})
        verdict = stage_report.identity_verdict(models.ManagedDevice.objects.get(pk=device.pk))
        self.assertEqual(verdict["claimed"]["claims"]["serial"], L.SERIAL)
        self.assertIsNone(verdict["verified"])

    def test_authorization_verdict_returns_the_live_grant(self):
        device, _attachment, auth = L.ready_device()
        verdict = stage_report.authorization_verdict(device, timezone.now())
        self.assertEqual((verdict["auth_id"], verdict["live"], verdict["expired"]), (auth.auth_id, True, False))

    def test_authorization_verdict_without_a_grant_is_none(self):
        verdict = stage_report.authorization_verdict(L.adopt().device, timezone.now())
        self.assertEqual(verdict["state"], "NONE")
        self.assertIn("predates NMAS onboarding", verdict["meaning"])

    def test_observation_verdict_returns_the_expected_attachment(self):
        device, attachment, _auth = L.ready_device()
        verdict = stage_report.observation_verdict(device)
        self.assertEqual([row["id"] for row in verdict["attachments"]], [attachment.pk])

    def test_observation_verdict_without_observations_is_empty(self):
        verdict = stage_report.observation_verdict(L.adopt().device)
        self.assertEqual((verdict["attachments"], verdict["latest_attachment_observation"], verdict["observations"]), ([], None, 0))

    def test_management_verdict_returns_the_path_hierarchy(self):
        verdict = stage_report.management_verdict(L.adopt().device)
        self.assertIn("DIRECT_OOB (1)", verdict["hierarchy"])

    def test_management_verdict_without_paths_is_unknown_and_never_active(self):
        verdict = stage_report.management_verdict(L.adopt().device)
        self.assertEqual((verdict["status"], verdict["active_path"], verdict["paths"]), (models.ManagementStatus.UNKNOWN, "", []))

    def test_admission_verdict_returns_the_device_state(self):
        device, _attachment, _auth = L.ready_device()
        self.assertEqual(stage_report.admission_verdict(device), {"state": models.ProductionAdmissionState.NOT_ADMITTED})

    def test_admission_verdict_of_a_legacy_device_is_not_an_admission(self):
        verdict = stage_report.admission_verdict(L.adopt().device)
        self.assertEqual(verdict["state"], models.ProductionAdmissionState.LEGACY_PREEXISTING)
        self.assertIn("not an NMAS admission", verdict["meaning"])

    def test_readiness_verdict_returns_ready_for_an_in_service_device(self):
        device = L.adopt().device
        verdict = stage_report.readiness_verdict(device, {"status": models.ManagementStatus.ACTIVE, "reconciliation_required": False}, {}, True)
        self.assertEqual((verdict["ready"], verdict["reasons"]), (True, []))

    def test_readiness_verdict_off_service_without_a_path_or_with_a_broken_chain_is_not_ready(self):
        device, _attachment, _auth = L.ready_device()
        verdict = stage_report.readiness_verdict(device, {"status": models.ManagementStatus.NO_PATH, "reconciliation_required": True}, {}, False)
        self.assertFalse(verdict["ready"])
        self.assertEqual(len(verdict["reasons"]), 4)

    def test_eligibility_returns_maintenance_for_an_in_service_device(self):
        out = stage_report.eligibility(L.adopt().device)
        self.assertTrue(out["maintenance"]["eligible_to_request"])

    def test_eligibility_of_a_registered_device_never_permits_maintenance_or_decommission(self):
        device, _attachment, _auth = L.ready_device()
        out = stage_report.eligibility(device)
        self.assertFalse(out["maintenance"]["eligible_to_request"])
        self.assertNotIn(S.IN_SERVICE, out["allowed_transitions"])

    def test_failures_returns_each_refused_transition(self):
        device = L.adopt().device
        lifecycle.transition(device, S.COMMISSIONING, actor=L.OPERATOR)
        rows = stage_report.failures(device)
        self.assertEqual((rows[0]["kind"], rows[0]["status"]), ("event", models.DeviceLifecycleEventOutcome.REFUSED))

    def test_failures_of_a_clean_device_is_empty(self):
        self.assertEqual(stage_report.failures(L.adopt().device), [])


class LifecycleOverviewPageTests(TestCase):
    def test_overview_of_an_empty_fleet_never_lists_a_device(self):
        viewer = SR.user_client("olivia", "NMAS Operator")
        response = viewer.get(reverse("core:lifecycle_overview"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["report"]["devices"], [])


# ======================================================================================================= EOS control plane
DENIED = {"v4": ["10.254.30.0/24"], "v6": []}


def control_plane_config(name="NMAS-ISO-DEV-000002-CP4", entries=None):
    lines = entries if entries is not None else eos.control_plane_entries("v4", DENIED["v4"])
    return (f"ip access-list {name}\n" + "".join(f"   {e}\n" for e in lines) +
            f"system control-plane\n   ip access-group {name} in\n")


class ControlPlaneTests(SimpleTestCase):
    def test_control_plane_entries_returns_the_bootstrap_denies_then_the_builtin_acl(self):
        entries = eos.control_plane_entries("v4", ["10.254.30.0/24"])
        self.assertEqual(entries[:2], ["1 permit udp 10.254.30.0/24 any eq bootps", "2 deny ip 10.254.30.0/24 any"])
        self.assertEqual(len(entries), 2 + len(eos.DEFAULT_CONTROL_PLANE["v4"]))

    def test_control_plane_acls_returns_the_configured_acl(self):
        self.assertEqual(eos.control_plane_acls(control_plane_config()), {"v4": "NMAS-ISO-DEV-000002-CP4", "v6": None})

    def test_control_plane_acls_of_the_builtin_acl_is_none(self):
        text = "system control-plane\n   ip access-group default-control-plane-acl in\n"
        self.assertEqual(eos.control_plane_acls(text), {"v4": None, "v6": None})

    def test_control_plane_closed_returns_true_for_the_exact_nmas_acl(self):
        self.assertTrue(eos.control_plane_closed(control_plane_config(), DENIED))

    def test_control_plane_with_a_custom_or_altered_acl_is_not_closed(self):
        altered = eos.control_plane_entries("v4", DENIED["v4"])[1:]
        for label, text in (("a custom acl", control_plane_config(name="OPS-CP")), ("an altered acl", control_plane_config(entries=altered)),
                            ("no acl", "")):
            with self.subTest(f"{label} is not closed"):
                self.assertFalse(eos.control_plane_closed(text, DENIED))

    def test_admission_ospf_release_rejects_an_invalid_interface(self):
        with self.assertRaises(eos.RenderError):
            eos.render_admission_ospf_release([{"process": "1"}], "Ethernet1; reload")


# ================================================================================================== ZTP lease lifetime
class LeaseUnitTests(T.ReadBackPath, Z.ZtpTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.start = timezone.now().replace(microsecond=0) - timedelta(minutes=1)
        self.session = self.open_session()
        self.network = self.session.network
        discovery.ingest(self.network, text=Z.lease(start=self.start, minutes=10))
        self.session.refresh_from_db()

    def test_binding_and_classify_return_the_active_correlated_lease(self):
        observation = lease.binding(self.session)
        self.assertEqual(observation.session_id, self.session.pk)
        self.assertEqual(lease.classify(observation, now=self.start + timedelta(minutes=2)), lease.ACTIVE)

    def test_classify_of_a_missing_ended_or_expired_binding_is_never_active(self):
        observation = lease.binding(self.session)
        self.assertEqual(lease.classify(None), lease.NONE)
        self.assertEqual(lease.classify(observation, now=self.start + timedelta(minutes=11)), lease.EXPIRED)
        observation.binding_state = "free"
        self.assertEqual(lease.classify(observation), lease.ENDED)

    def test_reconcile_returns_the_lapsed_session(self):
        self.assertEqual(lease.reconcile(self.network, now=self.start + timedelta(minutes=11)), [self.session.session_id])

    def test_reconcile_never_regresses_an_active_binding(self):
        self.assertEqual(lease.reconcile(self.network, now=self.start + timedelta(minutes=2)), [])
        self.session.refresh_from_db()
        self.assertEqual(self.session.stage, models.ZtpSessionStage.DISCOVERED)

    def test_resume_returns_resumed_for_a_genuine_renewal(self):
        later = self.start + timedelta(minutes=11)
        lease.reconcile(self.network, now=later)
        real_resume = lease.resume
        with mock.patch.object(lease, "resume", return_value=""):          # ingest the renewal without its automatic resume
            discovery.ingest(self.network, text=Z.lease(start=later, minutes=10), now=later + timedelta(seconds=5))
        observation = lease.binding(self.session)
        self.assertEqual(real_resume(observation, now=later + timedelta(seconds=5)), "RESUMED")
        self.session.refresh_from_db()
        self.assertEqual(self.session.stage, models.ZtpSessionStage.DISCOVERED)

    def test_resume_of_a_session_that_never_lapsed_is_nothing_to_do(self):
        self.assertEqual(lease.resume(lease.binding(self.session), now=self.start + timedelta(minutes=2)), "")


class RenewalWindowSecondsTests(SimpleTestCase):
    def test_renewal_window_seconds_returns_four_native_retries(self):
        self.assertEqual(lease.renewal_window_seconds(adapters.get("arista_eos")), 120)


# ================================================================================== authorization window / path gate
class AuthorizationAndPathGateTests(Z.ZtpTestMixin, TestCase):
    def test_authorization_problems_refuse_a_missing_revoked_or_lapsed_grant(self):
        _device, _attachment, auth = L.ready_device()
        self.assertEqual([b["code"] for b in policy.authorization_problems(None)], ["AUTHORIZATION_NOT_FOUND"])
        self.assertEqual([b["code"] for b in policy.authorization_problems(auth, now=auth.valid_until)], ["EXPIRED"])
        auth.state = models.BootstrapAuthorizationState.REVOKED
        self.assertEqual([b["code"] for b in policy.authorization_problems(auth)], ["AUTHORIZATION_STATE_INVALID"])

    def test_bootstrap_path_checks_returns_every_gate_passing(self):
        device, attachment, _auth = L.ready_device()
        checks = workflow.bootstrap_path_checks(device, attachment, self.network())
        self.assertTrue({row["check"] for row in T.OK_PATH} <= {row["check"] for row in checks})
        self.assertTrue(all(row["ok"] for row in checks), checks)


class PathGateWithoutRelayReadbackTests(Z.ZtpTestMixin, TestCase):
    relay_readback_present = False

    def test_bootstrap_path_checks_without_a_relay_readback_fails_option82(self):
        device, attachment, _auth = L.ready_device()
        checks = {row["check"]: row for row in workflow.bootstrap_path_checks(device, attachment, self.network())}
        self.assertEqual((checks["bootstrap_path_option82"]["ok"], checks["bootstrap_path_option82"]["code"]),
                         (False, "RELAY_READBACK_MISSING"))


# ============================================================================================ commissioning / provisioning
class CompletionAndCloseTests(TestCase):
    def test_bootstrap_completed_at_of_a_missing_or_malformed_record_is_none(self):
        self.assertIsNone(commissioning.bootstrap_completed_at(None))
        self.assertIsNone(commissioning.bootstrap_completed_at(models.ZtpSession(verification={"verified_at": "not-a-time"})))

    def test_close_configured_returns_a_closed_postchecked_run(self):
        lab = p.Lab()
        lab.through("provision")
        result = ps.close_configured(lab.run, actor="op", gateway=lab.gateway, reason="commissioning stopped before admission")
        self.assertTrue(result.ok)
        self.assertEqual((lab.run.status, lab.run.failure["code"]), (models.ProvisioningStatus.CANCELLED, "COMMISSIONING_ABORTED"))
