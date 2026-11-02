"""V2 Phase 3: the ZTP session -- opening (dependencies, authorization, enrollment key), first contact, out-of-band host-key
enrollment, authenticated verification, the DISCOVERED -> BOOTSTRAPPED edge, failures / retry and production-admission refusal.

Device contact is a stand-in (``observe`` / ``run``); the outputs are the live cEOS ones from ``fixtures/ztp``."""

from __future__ import annotations

import json
from unittest import mock

from django.test import TestCase

from core import models
from core.services.devices import attachments, authorization, events, lifecycle
from core.services.ztp import adapters, artifacts, dependencies, management, workflow
from core.tests.helpers import lifecycle as L
from core.tests.helpers import ztp as Z

S = models.DeviceLifecycleState
Stage = models.ZtpSessionStage


def served(session):
    artifact = session.artifacts.get(state=models.BootstrapArtifactState.ACTIVE)
    decision = artifacts.authorize(f"/ztp/v1/{artifact.artifact_id}/{artifact.filename}", session.reserved_address, "HTTP")
    assert decision.ok, decision.code
    artifacts.record(decision, client_address=session.reserved_address, transport="HTTP", outcome="SERVED", bytes_sent=len(decision.content))
    session.refresh_from_db()
    return session


class OpenSessionTests(Z.ZtpTestMixin, TestCase):
    def test_open_reserves_renders_and_keeps_the_private_key_out_of_the_artifact(self):
        session = self.open_session()
        self.assertEqual((session.stage, session.adapter, session.transport, session.reserved_address),
                         (Stage.AWAITING_DISCOVERY, "arista_eos", "HTTP", "10.254.30.10"))
        self.assertTrue(session.enrollment_public_key.startswith("ssh-ed25519 "))
        self.assertRegex(session.enrollment_key_ref, r"^runtime://device-credentials/ztp-enroll-")
        private = management.secret_provider().current(session.enrollment_key_ref).value
        self.assertIn("PRIVATE KEY", private)
        artifact = session.artifacts.get()
        self.assertNotIn("PRIVATE KEY", artifact.content)
        self.assertNotIn(private.strip().splitlines()[1], artifact.content)
        self.assertIn(session.enrollment_public_key, artifact.content)
        event = session.device.lifecycle_events.get(action="ZTP_SESSION_OPEN")
        self.assertFalse(event.evidence["bootstrap_plaintext_material"])
        self.assertFalse(event.evidence["production_admission"])

    def test_refused_open_leaves_no_enrollment_key_in_the_protected_store(self):
        """Review regression: a refusal after the key pair is generated (here: the adapter refuses the artifact) must not
        leave an orphaned private key in the protected provider."""
        device, _attachment, auth = L.ready_device()
        network = self.network()
        adapter = adapters.for_platform(device.platform)
        with mock.patch.object(type(adapter), "prepare_bootstrap_artifact", return_value=(None, ["ARTIFACT_SECRET_DETECTED"])):
            result = workflow.open_session(device, authorization=auth, network=network, actor=L.OPERATOR)
        self.assertEqual(result.codes, ["ARTIFACT_SECRET_DETECTED"])
        self.assertFalse(models.ZtpSession.objects.exists())
        store = management.secret_provider()
        self.assertFalse([k for k in store._load(allow_missing=True)["secrets"] if "ztp-enroll" in k])   # pylint: disable=protected-access
        self.assertTrue(workflow.open_session(device, authorization=auth, network=network, actor=L.OPERATOR).ok)

    def test_refusals(self):
        device, _attachment, auth = L.ready_device(approve_auth=False)
        network = self.network()
        cases = {"pending authorization": (auth, network, "PENDING_APPROVAL"), "no authorization": (None, network, "AUTHORIZATION_NOT_FOUND"),
                 "no network": (auth, None, "BOOTSTRAP_NETWORK_NOT_FOUND")}
        for label, (a, n, code) in cases.items():
            with self.subTest(label):
                result = workflow.open_session(device, authorization=a, network=n, actor=L.OPERATOR)
                self.assertFalse(result.ok)
                self.assertIn(code, result.codes)
        self.assertFalse(models.ZtpSession.objects.exists())

    def test_scope_without_dhcp_discovery_is_refused(self):
        device, auth = self.approved(L.register().device, scope=["BOOTSTRAP_FETCH"])
        result = workflow.open_session(device, authorization=auth, network=self.network(), actor=L.OPERATOR)
        self.assertIn("AUTHORIZATION_SCOPE_INVALID", result.codes)

    def approved(self, device, *, scope=None, port="Ethernet7"):
        from core.services.devices import authorization
        if not models.ManagedDevice.objects.filter(name="S1").exists():
            L.adopt()
        attachment = L.attach(device, port=port).attachment
        auth = L.request_auth(device, attachment, scope=scope).authorization
        auth = authorization.approve(auth, actor=L.APPROVER, confirm_digest=auth.binding_digest).authorization
        return device, auth

    def test_upstream_without_a_trusted_relay_on_the_network_is_refused(self):
        device, _attachment, auth = L.ready_device()
        L.adopt("S2")
        network = self.network(relays=[{"relay_address": Z.RELAY, "upstream_device": "S2"}])
        result = workflow.open_session(device, authorization=auth, network=network, actor=L.OPERATOR)
        self.assertIn("BOOTSTRAP_PATH_UNAVAILABLE", result.codes)

    def test_one_open_session_per_device(self):
        session = self.open_session()
        result = workflow.open_session(session.device, authorization=session.authorization, network=session.network, actor=L.OPERATOR)
        self.assertIn("ZTP_SESSION_OPEN_EXISTS", result.codes)

    def test_platform_without_an_operational_adapter_is_refused(self):
        L.adopt()
        device = L.register("NEWXR", serial="SN-XR1", mac="00:1c:73:00:00:0a", platform=models.Platform.CISCO_IOSXR).device
        device, auth = self.approved(device, port="Ethernet8")
        result = workflow.open_session(device, authorization=auth, network=self.network(), actor=L.OPERATOR)
        self.assertIn("ZTP_ADAPTER_UNAVAILABLE", result.codes)

    def test_cancel_closes_and_revokes_the_artifact(self):
        session = self.open_session()
        self.assertFalse(workflow.cancel_session(session, actor=L.APPROVER, reason="").ok)
        result = workflow.cancel_session(session, actor=L.APPROVER, reason="wrong port")
        self.assertTrue(result.ok)
        self.assertEqual(result.session.stage, Stage.CANCELLED)
        self.assertEqual(session.artifacts.get().state, models.BootstrapArtifactState.REVOKED)
        self.assertFalse(workflow.cancel_session(result.session, actor=L.APPROVER, reason="again").ok)


class DependencyTests(Z.ZtpTestMixin, TestCase):
    def test_generic_chain_new_upstream_blocks_until_in_service_and_admitted(self):
        """R4 -> R6 -> R7 in general: a registered-new upstream (R6) blocks its downstream (R7) with R6's own state."""
        L.adopt()
        r6 = L.register("R6NEW", serial="SN-R6", mac="00:1c:73:00:00:06").device
        problems = attachments.upstream_problems("R7NEW", "R6NEW")
        self.assertEqual(problems[0]["code"], "UPSTREAM_NOT_TRUSTED")
        self.assertEqual((problems[0]["details"]["dependency"], problems[0]["details"]["lifecycle_state"]), (r6.device_id, S.REGISTERED))
        # (the positive case needs R6 IN_SERVICE + ADMITTED, which only Phases 5-6 can produce: lifecycle fields are guarded)
        self.assertEqual(attachments.upstream_problems("R7NEW", "NOBODY")[0]["code"], "UPSTREAM_UNKNOWN")

    def test_evaluate_lists_every_check_and_downstream_waiting(self):
        session = self.open_session()
        checks = {c["check"]: c for c in dependencies.evaluate(session.device, session.authorization.attachment, session.network)}
        self.assertTrue(all(c["ok"] for c in checks.values()), checks)
        for name in ("upstream_ready", "attachment_approved", "bootstrap_path_relay", "native_ztp_adapter", "native_retry_known"):
            self.assertIn(name, checks)
        upstream = models.ManagedDevice.objects.get(name="S1")
        self.assertEqual([d["name"] for d in dependencies.downstream_waiting(upstream)], [session.device.name])


class ManagementTests(Z.ZtpTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.session = served(self.discovered())

    def contact(self, key=L.HOST_KEY, actor=L.OPERATOR):
        return workflow.contact_management(self.session, actor=actor, observe=lambda address: key)

    def enroll(self, key=L.HOST_KEY, actor=L.APPROVER, basis="console show management ssh hostkey"):
        self.session.refresh_from_db()
        return workflow.enroll_host_key(self.session, fingerprint=key, actor=actor, basis=basis)

    def verify(self, outputs=None, host_key=L.HOST_KEY):
        self.session.refresh_from_db()
        run = Z.fake_run(outputs or Z.eos_outputs(self.session), host_key)
        result = workflow.verify_management(self.session, actor="erin", run=run)
        return result, run

    def test_full_bootstrap_to_bootstrapped_without_admission(self):
        self.assertEqual(self.session.stage, Stage.DELIVERED)
        contact = self.contact()
        self.assertEqual((contact.ok, contact.session.stage, contact.session.observed_host_key), (True, Stage.MANAGEMENT_REACHED, L.HOST_KEY))
        self.assertFalse(contact.event.evidence["trusted"])
        self.assertTrue(self.enroll().ok)
        result, run = self.verify()
        self.assertTrue(result.ok, result.codes)
        call = run.calls[0]
        self.assertEqual((call["username"], call["enrolled_host_key"], call["key_reference"]),
                         ("nmas-enroll", L.HOST_KEY, self.session.enrollment_key_ref))
        session = workflow.get_session(self.session.session_id)
        device = session.device
        self.assertEqual((session.stage, device.lifecycle_state, device.admission_state, device.ztp_state),
                         (Stage.BOOTSTRAPPED, S.BOOTSTRAPPED, models.ProductionAdmissionState.NOT_ADMITTED, models.ZtpState.DISABLED_VERIFIED))
        self.assertNotEqual(device.identity_state, models.IdentityVerificationState.VERIFIED)      # promotion stays a human Phase 2 step
        self.assertEqual(session.artifacts.get().state, models.BootstrapArtifactState.EXPIRED)
        observation = models.DeviceObservation.objects.get(pk=session.verification["observation"])
        self.assertEqual((observation.source, observation.claims["host_key"]), (models.ObservationSource.AUTHENTICATED_SESSION, L.HOST_KEY))
        edge = device.lifecycle_events.get(action="BOOTSTRAP")
        self.assertEqual((edge.from_state, edge.to_state, edge.actor_kind), (S.DISCOVERED, S.BOOTSTRAPPED, events.AUTOMATION))
        self.assertIn("requested by erin", edge.actor)
        self.assertTrue(events.verify_chain(device))
        for target in (S.COMMISSIONING, S.IN_SERVICE):
            with self.subTest(target):
                self.assertFalse(lifecycle.transition(device, target, actor=L.APPROVER).ok)
        self.assertEqual(json.loads(json.dumps(workflow.status(session)))["production_admission"]["allowed"], False)

    def test_verify_requires_an_enrolled_host_key(self):
        self.contact()
        result, run = self.verify()
        self.assertEqual(result.codes, ["HOST_KEY_NOT_ENROLLED"])
        self.assertEqual(run.calls, [])

    def test_enrollment_rules(self):
        self.contact()
        self.assertIn("APPROVAL_SELF", self.enroll(actor=L.OPERATOR).codes)
        self.assertIn("HOST_KEY_MISMATCH", self.enroll(key="SHA256:" + "B" * 43).codes)
        self.assertIn("REASON_REQUIRED", self.enroll(basis="").codes)
        self.assertTrue(self.enroll().ok)

    def test_changed_host_key_on_contact_fails_the_session(self):
        self.contact()
        result = self.contact(key="SHA256:" + "C" * 43)
        self.assertEqual(result.codes, ["HOST_KEY_MISMATCH"])
        self.assertEqual(result.session.stage, Stage.FAILED)
        self.assertFalse(result.session.failure["retryable"])

    def test_unreachable_management_is_retryable(self):
        def unreachable(address):
            raise management.ManagementError("MANAGEMENT_UNREACHABLE", "timeout")
        result = workflow.contact_management(self.session, actor=L.OPERATOR, observe=unreachable)
        self.assertEqual(result.codes, ["MANAGEMENT_UNREACHABLE"])
        self.assertEqual((result.session.stage, result.session.attempts), (Stage.DELIVERED, 1))
        self.assertTrue(result.session.failure["retryable"])
        self.assertIn("retry", result.session.failure)

    def test_verification_failures(self):
        self.contact()
        self.enroll()
        with self.subTest("ZTP still running: retryable, session stays open"):
            result, _ = self.verify(Z.eos_outputs(self.session, **{"show zerotouch | json": '{"mode": "active"}'}))
            self.assertEqual(result.codes, ["BOOTSTRAP_VERIFICATION_FAILED"])
            self.assertTrue(result.session.is_open)
            self.assertEqual(models.ManagedDevice.objects.get(pk=self.session.device_id).lifecycle_state, S.DISCOVERED)
        with self.subTest("production routing found: not retryable"):
            route = Z.eos_outputs(self.session)["show ip route | json"]
            route = route.replace('"routingDisabled": true', '"routingDisabled": false')
            result, _ = self.verify(Z.eos_outputs(self.session, **{"show ip route | json": route}))
            self.assertEqual(result.session.stage, Stage.FAILED)
            self.assertFalse(result.session.failure["retryable"])
        self.assertEqual(models.ManagedDevice.objects.get(pk=self.session.device_id).lifecycle_state, S.DISCOVERED)
        failed = workflow.fail_device(result.session, actor=L.APPROVER)
        self.assertTrue(failed.ok, failed.codes)
        self.assertEqual(models.ManagedDevice.objects.get(pk=self.session.device_id).lifecycle_state, S.FAILED)

    def test_another_identity_over_the_authenticated_session_fails(self):
        self.contact()
        self.enroll()
        outputs = Z.eos_outputs(self.session)
        outputs["show version | json"] = outputs["show version | json"].replace(L.SERIAL, "SOMEONE-ELSE")
        result, _ = self.verify(outputs)
        self.assertEqual(result.session.stage, Stage.FAILED)
        self.assertIn("identity_matches_authorized", result.session.failure["detail"])

    def test_pinned_key_mismatch_during_verification(self):
        self.contact()
        self.enroll()
        self.session.refresh_from_db()

        def mismatch(*args, **kwargs):
            raise management.ManagementError("HOST_KEY_MISMATCH")
        result = workflow.verify_management(self.session, actor="erin", run=mismatch)
        self.assertEqual(result.session.stage, Stage.FAILED)

    def test_incomplete_bootstrap_cannot_take_the_lifecycle_edge(self):
        device = models.ManagedDevice.objects.get(pk=self.session.device_id)
        for kind, evidence in ((events.HUMAN, {"ztp_session": self.session.pk}), (events.AUTOMATION, {"ztp_session": self.session.pk}),
                               (events.AUTOMATION, {})):
            with self.subTest(kind=kind, evidence=evidence):
                result = lifecycle.transition(device, S.BOOTSTRAPPED, actor="system:x", actor_kind=kind, evidence=evidence)
                self.assertFalse(result.ok)
        self.assertEqual(models.ManagedDevice.objects.get(pk=device.pk).lifecycle_state, S.DISCOVERED)

    def test_failed_transition_needs_a_closed_non_retryable_failure(self):
        device = models.ManagedDevice.objects.get(pk=self.session.device_id)
        self.assertEqual(workflow.fail_device(self.session, actor=L.APPROVER).codes, ["ZTP_SESSION_STATE_INVALID"])
        self.assertEqual(device.lifecycle_state, S.DISCOVERED)


class RevocationTests(Z.ZtpTestMixin, TestCase):
    """A two-use authorization stays APPROVED (so revocable) after the first delivery."""

    contact, enroll, verify = ManagementTests.contact, ManagementTests.enroll, ManagementTests.verify

    def setUp(self):
        super().setUp()
        self.session = served(self.discovered(uses=2))

    def test_revoked_authorization_stops_bootstrap_completion(self):
        """Review regression: an operator's revocation after the first delivery must stop the DISCOVERED -> BOOTSTRAPPED edge
        (a multi-use authorization stays APPROVED, and so revocable, after one delivery)."""
        self.contact()
        self.enroll()
        auth = models.BootstrapAuthorization.objects.get(pk=self.session.authorization_id)
        self.assertEqual(auth.state, models.BootstrapAuthorizationState.APPROVED)
        self.assertTrue(authorization.revoke(auth, actor=L.APPROVER, reason="stop this onboarding").ok)
        result, run = self.verify()
        self.assertFalse(result.ok)
        self.assertIn("AUTHORIZATION_STATE_INVALID", result.codes)
        self.assertEqual(run.calls, [])                                   # nothing contacts the device
        self.assertEqual(models.ManagedDevice.objects.get(pk=self.session.device_id).lifecycle_state, S.DISCOVERED)

    def test_revocation_during_verification_is_refused_at_the_lifecycle_edge(self):
        """The lifecycle gate itself (defence in depth): a revocation that lands while the authenticated session runs leaves
        complete session evidence, yet the BOOTSTRAP edge refuses."""
        self.contact()
        self.enroll()
        self.session.refresh_from_db()
        outputs = Z.eos_outputs(self.session)

        def run_then_revoke(address, **kwargs):
            auth = models.BootstrapAuthorization.objects.get(pk=self.session.authorization_id)
            authorization.revoke(auth, actor=L.APPROVER, reason="revoked while verifying")
            return {"host_key": L.HOST_KEY, "outputs": outputs}

        result = workflow.verify_management(self.session, actor="erin", run=run_then_revoke)
        self.assertFalse(result.ok)
        self.assertIn("AUTHORIZATION_STATE_INVALID", result.codes)
        self.assertEqual(models.ManagedDevice.objects.get(pk=self.session.device_id).lifecycle_state, S.DISCOVERED)
