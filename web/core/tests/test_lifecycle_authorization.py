"""V2 Lifecycle Phase 2: expected attachments and bootstrap authorization (request / approve / revoke / expire / decide)."""

from __future__ import annotations

from datetime import timedelta
from unittest import mock

from django.db.models import F
from django.test import TestCase
from django.utils import timezone

from core import models
from core.services.devices import attachments, authorization, lifecycle
from core.services.devices.authorization import Decision
from core.tests.helpers import lifecycle as L

P, C = models.AttachmentPurpose, models.AttachmentConnectivity


class AttachmentTests(TestCase):
    def setUp(self):
        L.adopt()
        self.device = L.register().device

    def test_register_attachment_accepts_valid_expectation_pending(self):
        result = L.attach(self.device, approve=False)
        self.assertTrue(result.ok, result.codes)
        self.assertEqual((result.attachment.approval_state, result.attachment.verification_state, result.attachment.source),
                         ("PENDING", "UNVERIFIED", "OPERATOR"))
        second = L.attach(self.device, port="Ethernet8", local="Ethernet2", vlan=None, connectivity=C.ROUTED, approve=False)
        self.assertTrue(second.ok, second.codes)                      # multihoming: several expected attachments
        self.assertEqual(self.device.attachments.count(), 2)

    def test_register_attachment_refuses_invalid_untrusted_and_taken(self):
        cases = {
            "self upstream": ({"upstream": "NEW1"}, "UPSTREAM_UNKNOWN"),
            "unknown upstream": ({"upstream": "NOPE9"}, "UPSTREAM_UNKNOWN"),
            "not adopted": ({"upstream": "S2"}, "UPSTREAM_NOT_TRUSTED"),
            "read-only R5": ({"upstream": "R5"}, "UPSTREAM_NOT_TRUSTED"),
            "bad interface": ({"port": "bad port!"}, "INTERFACE_INVALID"),
            "routed with vlan": ({"connectivity": C.ROUTED, "vlan": 30}, "VLAN_INVALID"),
            "trunk without vlan": ({"connectivity": C.TRUNK, "vlan": None}, "VLAN_INVALID"),
            "vlan 200 production": ({"vlan": 200}, "VLAN200_PURPOSE_FORBIDDEN"),
            "vlan range": ({"vlan": 5000}, "VLAN_INVALID"),
            "vlan text": ({"vlan": "x"}, "VLAN_INVALID"),
            "bad purpose": ({"purpose": "nope"}, "ATTACHMENT_STATE_INVALID"),
        }
        for label, (kwargs, code) in cases.items():
            with self.subTest(label):
                self.assertIn(code, L.attach(self.device, approve=False, **kwargs).codes)
        self.assertFalse(self.device.attachments.exists())
        L.attach(self.device, approve=False)
        with self.subTest("upstream port taken"):
            other = L.register(name="NEW2", serial="SN-NEW2", mac="").device
            self.assertEqual(L.attach(other, approve=False, local="").codes, ["UPSTREAM_PORT_TAKEN"])
        with self.subTest("local port taken"):
            self.assertEqual(L.attach(self.device, port="Ethernet9", approve=False).codes, ["LOCAL_PORT_TAKEN"])
        with self.subTest("terminal device"):
            lifecycle.withdraw(self.device, actor="x", reason="cancelled")
            self.device.refresh_from_db()
            self.assertIn("DEVICE_TERMINAL", L.attach(self.device, port="Ethernet10", local="", approve=False).codes)

    def test_vlan200_management_attachment_is_allowed(self):
        self.assertTrue(L.attach(self.device, vlan=200, purpose=P.MANAGEMENT, approve=False).ok)

    def test_upstream_problems_accepts_adopted_writable_upstream(self):
        self.assertEqual(attachments.upstream_problems("NEW1", "S1"), [])

    def test_upstream_problems_refuses_missing_upstream(self):
        self.assertEqual([b["code"] for b in attachments.upstream_problems("NEW1", "")], ["UPSTREAM_UNKNOWN"])

    def test_vlan_problems_accepts_consistent_vlan(self):
        self.assertEqual(attachments.vlan_problems(purpose=P.PRODUCTION, connectivity=C.TRUNK, vlan=30), [])
        self.assertEqual(attachments.vlan_problems(purpose=P.PRODUCTION, connectivity=C.ACCESS, vlan=None), [])

    def test_vlan_problems_refuses_vlan200_for_production(self):
        self.assertEqual([b["code"] for b in attachments.vlan_problems(purpose=P.PRODUCTION, connectivity=C.SUBINTERFACE, vlan=200)],
                         ["VLAN200_PURPOSE_FORBIDDEN"])

    def test_get_attachment_returns_own_attachment(self):
        row = L.attach(self.device, approve=False).attachment
        self.assertEqual(attachments.get_attachment(self.device, row.pk), row)

    def test_get_attachment_unknown_or_other_device_is_none(self):
        row = L.attach(self.device, approve=False).attachment
        other = L.register(name="NEW2", serial="SN-NEW2", mac="").device
        self.assertIsNone(attachments.get_attachment(other, row.pk))
        self.assertIsNone(attachments.get_attachment(self.device, "x"))

    def test_approve_attachment_accepts_second_person(self):
        row = L.attach(self.device, approve=False).attachment
        result = attachments.approve_attachment(self.device, row.pk, actor=L.APPROVER)
        self.assertTrue(result.ok)
        self.assertEqual((result.attachment.approval_state, result.attachment.approved_by), ("APPROVED", L.APPROVER))

    def test_approve_attachment_refuses_self_unknown_repeat_and_concurrent(self):
        row = L.attach(self.device, approve=False).attachment
        self.assertEqual(attachments.approve_attachment(self.device, row.pk, actor=L.OPERATOR).codes, ["APPROVAL_SELF"])
        self.assertEqual(attachments.approve_attachment(self.device, 99999, actor=L.APPROVER).codes, ["ATTACHMENT_NOT_FOUND"])
        attachments.approve_attachment(self.device, row.pk, actor=L.APPROVER)
        self.assertEqual(attachments.approve_attachment(self.device, row.pk, actor=L.OTHER).codes, ["ATTACHMENT_STATE_INVALID"])
        pending = L.attach(self.device, port="Ethernet8", local="Ethernet2", approve=False).attachment
        stale = models.DeviceAttachment.objects.get(pk=pending.pk)
        attachments.revoke_attachment(self.device, pending.pk, actor=L.APPROVER, reason="wrong port")
        with mock.patch.object(attachments, "get_attachment", return_value=stale):
            self.assertEqual(attachments.approve_attachment(self.device, pending.pk, actor=L.OTHER).codes, ["CONCURRENT_MODIFICATION"])

    def test_revoke_attachment_cascades_to_bound_authorization(self):
        row = L.attach(self.device).attachment
        auth = L.request_auth(self.device, row).authorization
        result = attachments.revoke_attachment(self.device, row.pk, actor=L.APPROVER, reason="moved")
        self.assertTrue(result.ok)
        auth.refresh_from_db()
        self.assertEqual((result.attachment.approval_state, auth.state), ("REVOKED", "REVOKED"))
        self.assertEqual(result.event.evidence["revoked_bootstrap_ids"], [auth.auth_id])

    def test_revoke_attachment_refuses_missing_reason_unknown_and_repeat(self):
        row = L.attach(self.device).attachment
        self.assertEqual(attachments.revoke_attachment(self.device, row.pk, actor="a", reason="").codes, ["REASON_REQUIRED"])
        self.assertEqual(attachments.revoke_attachment(self.device, 9999, actor="a", reason="x").codes, ["ATTACHMENT_NOT_FOUND"])
        attachments.revoke_attachment(self.device, row.pk, actor="a", reason="moved")
        self.assertEqual(attachments.revoke_attachment(self.device, row.pk, actor="a", reason="again").codes, ["ATTACHMENT_STATE_INVALID"])

    def _observe_attachment(self, source, port="Ethernet7", local="Ethernet1"):
        return lifecycle.record_observation(self.device, kind=models.ObservationKind.ATTACHMENT, source=source, actor="collector",
                                            upstream_device="S1", upstream_interface=port, local_interface=local)

    def test_compare_returns_match_for_observed_expected_port(self):
        row = L.attach(self.device).attachment
        self.assertEqual(attachments.compare(self.device, models.ObservationTrust.OBSERVED, "S1", "Ethernet7", "Ethernet1"), (row, "MATCH", []))
        self.assertEqual(attachments.compare(self.device, models.ObservationTrust.REFERENCE, "S1", "Ethernet7"), (row, "UNTRUSTED", []))
        self.assertEqual(attachments.compare(self.device, models.ObservationTrust.CLAIMED, "S1", "Ethernet7"), (row, "UNTRUSTED", []))

    def test_compare_reports_mismatch_for_unexpected_port_and_wrong_local(self):
        L.attach(self.device)
        self.assertEqual(attachments.compare(self.device, models.ObservationTrust.OBSERVED, "S1", "Ethernet9")[1], "MISMATCH")
        self.assertEqual(attachments.compare(self.device, models.ObservationTrust.OBSERVED, "S1", "Ethernet7", "Ethernet5")[1], "MISMATCH")
        other = L.register(name="NEW2", serial="SN-NEW2", mac="").device
        self.assertEqual(attachments.compare(other, models.ObservationTrust.OBSERVED, "S1", "Ethernet7")[1], "MISMATCH")

    def test_compare_without_expectations_is_recorded_not_matched(self):
        self.assertEqual(attachments.compare(self.device, models.ObservationTrust.OBSERVED, "S1", "Ethernet7"), (None, "RECORDED", []))

    def test_apply_observation_verifies_only_from_observed_source(self):
        row = L.attach(self.device).attachment
        self._observe_attachment(models.ObservationSource.LAB_TOPOLOGY_REFERENCE)
        self._observe_attachment(models.ObservationSource.LLDP_NEIGHBOR_CLAIM)
        row.refresh_from_db()
        self.assertEqual(row.verification_state, "UNVERIFIED")
        self._observe_attachment(models.ObservationSource.TRUSTED_UPSTREAM_INTERFACE)
        row.refresh_from_db()
        self.assertEqual(row.verification_state, "VERIFIED")
        self.assertIsNotNone(row.observed_at)

    def test_apply_observation_claimed_mismatch_denies(self):
        row = L.attach(self.device).attachment
        self._observe_attachment(models.ObservationSource.LLDP_NEIGHBOR_CLAIM, local="Ethernet5")
        row.refresh_from_db()
        self.assertEqual(row.verification_state, "MISMATCH")
        self.assertIn("mismatches", row.mismatch)

    def test_apply_observation_verifies_matching_observed_attachment(self):
        row = L.attach(self.device).attachment
        observation = models.DeviceObservation.objects.create(
            device=self.device, kind=models.ObservationKind.ATTACHMENT, source=models.ObservationSource.DHCP_RELAY_ATTACHMENT,
            trust=models.ObservationTrust.OBSERVED, upstream_device="S1", upstream_interface="Ethernet7", attachment=row,
            result=models.ObservationResult.MATCH, recorded_by="collector", observed_at=timezone.now())
        attachments.apply_observation(self.device, observation)
        row.refresh_from_db()
        self.assertEqual(row.verification_state, "VERIFIED")

    def test_apply_observation_ignores_observation_without_attachment(self):
        observation = mock.Mock(attachment=None)
        self.assertIsNone(attachments.apply_observation(self.device, observation))

    def test_apply_observation_refuses_out_of_order_observation(self):
        row = L.attach(self.device).attachment
        self._observe_attachment(models.ObservationSource.TRUSTED_UPSTREAM_INTERFACE, local="Ethernet5")
        row.refresh_from_db()
        self.assertEqual(row.verification_state, "MISMATCH")
        late = lifecycle.record_observation(self.device, kind=models.ObservationKind.ATTACHMENT,
                                            source=models.ObservationSource.TRUSTED_UPSTREAM_INTERFACE, actor="collector",
                                            upstream_device="S1", upstream_interface="Ethernet7", local_interface="Ethernet1",
                                            observed_at=row.observed_at - timedelta(minutes=5))
        self.assertEqual(late.observation.result, "MATCH")
        row.refresh_from_db()
        self.assertEqual(row.verification_state, "MISMATCH")


class AuthorizationRequestTests(TestCase):
    def setUp(self):
        L.adopt()
        self.device = L.register().device
        self.attachment = L.attach(self.device).attachment

    def test_request_creates_pending_bound_authorization_without_secrets(self):
        result = L.request_auth(self.device, self.attachment)
        auth = result.authorization
        self.assertTrue(result.ok, result.codes)
        self.assertEqual((auth.state, auth.scope, auth.max_uses, auth.use_count), ("PENDING_APPROVAL", sorted(L.SCOPE), 1, 0))
        self.assertEqual(auth.binding_digest, authorization.current_digest(auth))
        self.assertFalse(result.event.evidence["production_admission"])
        field_names = {f.name for f in models.BootstrapAuthorization._meta.get_fields()}
        self.assertFalse({"password", "secret", "token", "key", "credential"} & field_names)

    def test_request_refuses_invalid_scope_window_uses_reason_and_open_duplicate(self):
        now = timezone.now()
        cases = {
            "empty scope": ({"scope": []}, "AUTHORIZATION_SCOPE_INVALID"),
            "production scope": ({"scope": ["PRODUCTION"]}, "AUTHORIZATION_SCOPE_INVALID"),
            "duplicate scope": ({"scope": ["DHCP_DISCOVERY", "DHCP_DISCOVERY"]}, "AUTHORIZATION_SCOPE_INVALID"),
            "window too short": ({"valid_from": now, "valid_until": now + timedelta(minutes=1)}, "AUTHORIZATION_WINDOW_INVALID"),
            "window too long": ({"valid_from": now, "valid_until": now + timedelta(days=8)}, "AUTHORIZATION_WINDOW_INVALID"),
            "window over": ({"valid_from": now - timedelta(hours=2), "valid_until": now - timedelta(hours=1)}, "AUTHORIZATION_WINDOW_INVALID"),
            "window missing": ({"valid_from": None, "valid_until": None}, "AUTHORIZATION_WINDOW_INVALID"),
            "uses zero": ({"max_uses": 0}, "AUTHORIZATION_USES_INVALID"),
            "uses eleven": ({"max_uses": 11}, "AUTHORIZATION_USES_INVALID"),
            "missing reason": ({"reason": ""}, "REASON_REQUIRED"),
            "secret-shaped reason": ({"reason": "psk=abc"}, "TEXT_INVALID"),
            "unknown attachment": ({"attachment_id": 9999}, "ATTACHMENT_NOT_FOUND"),
        }
        base = {"attachment_id": self.attachment.pk, "scope": L.SCOPE, "valid_from": now, "valid_until": now + timedelta(hours=1),
                "max_uses": 1, "actor": L.OPERATOR, "reason": "first boot"}
        for label, (overrides, code) in cases.items():
            with self.subTest(label):
                self.assertIn(code, authorization.request_authorization(self.device, **{**base, **overrides}).codes)
        self.assertFalse(models.BootstrapAuthorization.objects.exists())
        L.request_auth(self.device, self.attachment)
        self.assertEqual(L.request_auth(self.device, self.attachment).codes, ["AUTHORIZATION_OPEN_EXISTS"])

    def test_request_refuses_ineligible_device_and_attachment(self):
        adopted = models.ManagedDevice.objects.get(name="S1")
        self.assertIn("ALREADY_IN_SERVICE", L.request_auth(adopted, self.attachment).codes)
        unknown = L.register(name="NEW2", serial="", mac="").device
        other_attachment = L.attach(unknown, port="Ethernet8", local="").attachment
        self.assertIn("IDENTITY_EVIDENCE_INSUFFICIENT", L.request_auth(unknown, other_attachment).codes)
        pending = L.attach(self.device, port="Ethernet9", local="Ethernet2", approve=False).attachment
        self.assertIn("AUTHORIZATION_ATTACHMENT_INELIGIBLE", L.request_auth(self.device, pending).codes)
        management = L.attach(self.device, port="Ethernet10", local="Ethernet3", vlan=200, purpose=P.MANAGEMENT).attachment
        self.assertIn("AUTHORIZATION_ATTACHMENT_INELIGIBLE", L.request_auth(self.device, management).codes)

    def test_scope_window_and_uses_validators_accept_valid(self):
        self.assertEqual(authorization.scope_problems(["INITIAL_MANAGEMENT"]), [])
        self.assertEqual(authorization.window_problems(*L.window(30)), [])
        self.assertEqual(authorization.uses_problems(10), [])

    def test_validators_refuse_invalid_types(self):
        self.assertTrue(authorization.scope_problems("DHCP_DISCOVERY"))
        self.assertTrue(authorization.window_problems(timezone.now().replace(tzinfo=None), timezone.now()))
        self.assertTrue(authorization.uses_problems(True))

    def test_device_and_attachment_problems_accept_eligible(self):
        self.assertEqual(authorization.device_problems(self.device), [])
        self.assertEqual(authorization.attachment_problems(self.device, self.attachment), [])

    def test_device_and_attachment_problems_refuse_mismatch_and_terminal(self):
        lifecycle.record_observation(self.device, kind=models.ObservationKind.IDENTITY, source=models.ObservationSource.AUTHENTICATED_SESSION,
                                     actor="c", claims={"serial": "SN-OTHER", "host_key": L.HOST_KEY})
        self.device.refresh_from_db()
        self.assertEqual([b["code"] for b in authorization.device_problems(self.device)], ["IDENTITY_MISMATCH"])
        self.assertEqual([b["code"] for b in authorization.attachment_problems(self.device, None)], ["ATTACHMENT_NOT_FOUND"])
        lifecycle.withdraw(self.device, actor="x", reason="bad hardware")
        self.device.refresh_from_db()
        self.assertEqual([b["code"] for b in authorization.device_problems(self.device)], ["DEVICE_TERMINAL"])

    def test_attachment_problems_refuses_mismatched_attachment(self):
        lifecycle.record_observation(self.device, kind=models.ObservationKind.ATTACHMENT, source=models.ObservationSource.DHCP_RELAY_ATTACHMENT,
                                     actor="c", upstream_device="S1", upstream_interface="Ethernet7", local_interface="Ethernet5")
        self.attachment.refresh_from_db()
        self.assertEqual([b["code"] for b in authorization.attachment_problems(self.device, self.attachment)], ["ATTACHMENT_MISMATCH"])

    def test_binding_without_attachment_raises(self):
        valid_from, valid_until = L.window()
        with self.assertRaises(AttributeError):
            authorization.binding(self.device, None, platform="x", scope=[], valid_from=valid_from, valid_until=valid_until, max_uses=1)

    def test_binding_digest_rejects_non_json_payload(self):
        with self.assertRaises(TypeError):
            authorization.binding_digest({"x": object()})

    def test_current_digest_of_unbound_authorization_raises(self):
        with self.assertRaises(models.ManagedDevice.DoesNotExist):
            authorization.current_digest(models.BootstrapAuthorization())

    def test_binding_and_digest_are_deterministic(self):
        valid_from, valid_until = L.window()
        payload = authorization.binding(self.device, self.attachment, platform=self.device.platform, scope=["B", "A"],
                                        valid_from=valid_from, valid_until=valid_until, max_uses=2)
        self.assertEqual(payload["scope"], ["A", "B"])
        self.assertEqual(authorization.binding_digest(payload), authorization.binding_digest(dict(payload)))
        self.assertNotEqual(authorization.binding_digest(payload), authorization.binding_digest({**payload, "max_uses": 3}))

    def test_get_authorization_returns_known_id(self):
        auth = L.request_auth(self.device, self.attachment).authorization
        self.assertEqual(authorization.get_authorization(auth.auth_id), auth)

    def test_get_authorization_unknown_or_malformed_is_none(self):
        for value in ("BAUTH-999999", "DEV-000001", "", None):
            with self.subTest(value=value):
                self.assertIsNone(authorization.get_authorization(value))


class AuthorizationApprovalTests(TestCase):
    def setUp(self):
        self.device, self.attachment, self.auth = L.ready_device(approve_auth=False)

    def test_approve_accepts_second_person_with_confirmed_digest(self):
        result = authorization.approve(self.auth, actor=L.APPROVER, confirm_digest=self.auth.binding_digest.upper())
        self.assertTrue(result.ok, result.codes)
        self.assertEqual((result.authorization.state, result.authorization.approved_by), ("APPROVED", L.APPROVER))
        self.assertEqual(len(result.authorization.approval_digest), 64)
        self.assertEqual(self.device.admission_state, "NOT_ADMITTED")

    def test_approve_refuses_self_wrong_digest_stale_and_repeat(self):
        self.assertIn("APPROVAL_SELF", authorization.approve(self.auth, actor=L.OPERATOR, confirm_digest=self.auth.binding_digest).codes)
        self.assertIn("AUTHORIZATION_CONFIRMATION_MISMATCH", authorization.approve(self.auth, actor=L.APPROVER, confirm_digest="0" * 64).codes)
        models.ManagedDevice.objects.compare_and_swap(self.device.pk, self.device.version, expected_base_mac="00:1c:73:00:00:99")
        self.assertIn("STALE", authorization.approve(self.auth, actor=L.APPROVER, confirm_digest=self.auth.binding_digest).codes)
        self.auth.refresh_from_db()
        self.assertEqual(self.auth.state, "PENDING_APPROVAL")

    def test_approve_refuses_expired_window(self):
        with mock.patch.object(authorization.timezone, "now", return_value=self.auth.valid_until + timedelta(seconds=1)):
            self.assertIn("EXPIRED", authorization.approve(self.auth, actor=L.APPROVER, confirm_digest=self.auth.binding_digest).codes)

    def test_revoke_closes_open_authorization(self):
        result = authorization.revoke(self.auth, actor=L.APPROVER, reason="hardware swapped")
        self.assertTrue(result.ok)
        self.assertEqual(result.authorization.state, "REVOKED")
        self.assertIsNotNone(result.authorization.closed_at)

    def test_revoke_refuses_missing_reason_and_closed_authorization(self):
        self.assertEqual(authorization.revoke(self.auth, actor="a", reason="").codes, ["REASON_REQUIRED"])
        authorization.revoke(self.auth, actor="a", reason="done")
        self.assertEqual(authorization.revoke(self.auth, actor="a", reason="again").codes, ["AUTHORIZATION_STATE_INVALID"])

    def test_expire_due_with_no_window_over_expires_none(self):
        self.assertEqual(authorization.expire_due(now=self.auth.valid_from), [])

    def test_expire_due_closes_only_windows_that_are_over(self):
        self.assertEqual(authorization.expire_due(), [])
        expired = authorization.expire_due(now=self.auth.valid_until)
        self.assertEqual(expired, [self.auth.auth_id])
        self.auth.refresh_from_db()
        self.assertEqual(self.auth.state, "EXPIRED")
        self.assertEqual(authorization.expire_due(now=self.auth.valid_until), [])

    def test_authorization_result_codes_returns_blocker_codes(self):
        self.assertEqual(authorization.AuthorizationResult(None, False, "X", [{"code": "B"}]).codes, ["B"])


class DecisionTests(TestCase):
    def setUp(self):
        self.device, self.attachment, self.auth = L.ready_device()

    def decide(self, **overrides):
        return authorization.decide(self.auth, L.good_request(**overrides))

    def test_decide_authorizes_matching_request_for_bootstrap_scope_only(self):
        outcome = self.decide()
        self.assertEqual(outcome.decision, Decision.AUTHORIZED)
        self.assertTrue(outcome.authorized)
        self.assertFalse(outcome.production_admission)
        self.assertFalse(outcome.as_dict()["production_admission"])
        self.assertEqual(outcome.as_dict()["auth_id"], self.auth.auth_id)

    def test_decide_returns_each_refusal_decision(self):
        cases = {
            "out of scope token": ({"scope": "PRODUCTION"}, Decision.OUT_OF_SCOPE),
            "not granted scope": ({"scope": "INITIAL_MANAGEMENT"}, Decision.OUT_OF_SCOPE),
            "unknown request key": ({"password": "x"}, Decision.OUT_OF_SCOPE),
            "identity mismatch": ({"serial": "SN-OTHER"}, Decision.IDENTITY_MISMATCH),
            "mac mismatch": ({"base_mac": "00:1c:73:00:00:77"}, Decision.IDENTITY_MISMATCH),
            "attachment mismatch": ({"upstream_interface": "Ethernet8"}, Decision.ATTACHMENT_MISMATCH),
            "no identity claim": ({"serial": "", "base_mac": ""}, Decision.PENDING_EVIDENCE),
            "claimed attachment only": ({"attachment_source": models.ObservationSource.LLDP_NEIGHBOR_CLAIM}, Decision.PENDING_EVIDENCE),
            "no attachment evidence": ({"attachment_source": "", "upstream_device": "", "upstream_interface": ""}, Decision.PENDING_EVIDENCE),
        }
        for label, (overrides, expected) in cases.items():
            with self.subTest(label):
                self.assertEqual(self.decide(**overrides).decision, expected)

    def test_decide_reports_conflicting_request(self):
        other = L.register(name="NEW2", serial="SN-NEW2", mac="").device
        L.attach(other, port="Ethernet8", local="")
        self.assertEqual(self.decide(serial="SN-NEW2").decision, Decision.CONFLICTING_REQUEST)
        self.assertEqual(self.decide(upstream_interface="Ethernet8").decision, Decision.CONFLICTING_REQUEST)

    def test_decide_reports_time_and_state_refusals(self):
        with self.subTest("not yet valid"):
            self.assertEqual(authorization.decide(self.auth, L.good_request(), now=self.auth.valid_from - timedelta(seconds=1)).decision,
                             Decision.NOT_YET_VALID)
        with self.subTest("expired"):
            self.assertEqual(authorization.decide(self.auth, L.good_request(), now=self.auth.valid_until).decision, Decision.EXPIRED)
        with self.subTest("stale"):
            models.ManagedDevice.objects.compare_and_swap(self.device.pk, self.device.version, expected_serial="SN-CHANGED")
            self.assertEqual(self.decide().decision, Decision.STALE)
        with self.subTest("revoked"):
            authorization.revoke(self.auth, actor="a", reason="done")
            self.auth.refresh_from_db()
            self.assertEqual(self.decide().decision, Decision.REVOKED)
        with self.subTest("unknown authorization"):
            self.assertEqual(authorization.decide(None).decision, Decision.NOT_FOUND)

    def test_decide_pending_approval_and_already_in_service(self):
        L.adopt("S2")
        device = L.register(name="NEW3", serial="SN-NEW3", mac="").device
        attachment = L.attach(device, upstream="S2", port="Ethernet3", local="").attachment
        pending = L.request_auth(device, attachment).authorization
        self.assertEqual(authorization.decide(pending, L.good_request(serial="SN-NEW3")).decision, Decision.PENDING_APPROVAL)
        with mock.patch.object(models.ManagedDevice.objects, "get", return_value=mock.Mock(
                origin=models.DeviceOrigin.LEGACY_ADOPTION, is_terminal=False, device_id="DEV-1")):
            self.auth.state = models.BootstrapAuthorizationState.APPROVED
            self.assertEqual(self.decide().decision, Decision.ALREADY_IN_SERVICE)

    def test_decide_with_verified_attachment_needs_no_request_evidence(self):
        lifecycle.record_observation(self.device, kind=models.ObservationKind.ATTACHMENT, source=models.ObservationSource.TRUSTED_UPSTREAM_INTERFACE,
                                     actor="c", upstream_device="S1", upstream_interface="Ethernet7", local_interface="Ethernet1")
        self.assertEqual(authorization.decide(self.auth, {"scope": "DHCP_DISCOVERY", "serial": L.SERIAL}).decision, Decision.AUTHORIZED)

    def test_normalize_request_accepts_valid_description(self):
        normalized, problems = authorization.normalize_request(L.good_request(base_mac="00-1C-73-00-00-01"))
        self.assertEqual(problems, [])
        self.assertEqual((normalized["base_mac"], normalized["attachment_trust"]), (L.MAC, "OBSERVED"))

    def test_normalize_request_refuses_malformed_description(self):
        _, problems = authorization.normalize_request({"scope": "X", "serial": "bad serial!", "upstream_device": "bad!", "attachment_source": "NOPE"})
        self.assertEqual({b["code"] for b in problems}, {"AUTHORIZATION_SCOPE_INVALID", "SERIAL_INVALID", "OBSERVATION_INVALID"})
        self.assertTrue(authorization.normalize_request("not a dict")[1])

    def test_evaluate_records_dry_run_and_keeps_use_count(self):
        outcome = authorization.evaluate(self.auth, L.good_request(), actor=L.OPERATOR)
        self.assertTrue(outcome.authorized)
        self.auth.refresh_from_db()
        self.assertEqual(self.auth.use_count, 0)
        event = self.device.lifecycle_events.order_by("-sequence").first()
        self.assertEqual((event.action, event.authorization["decision"], event.authorization["production_admission"]),
                         ("BOOTSTRAP_AUTH_DECIDE", "AUTHORIZED", False))

    def test_evaluate_unknown_authorization_records_nothing(self):
        before = models.DeviceLifecycleEvent.objects.count()
        self.assertEqual(authorization.evaluate(None, {}, actor="x").decision, Decision.NOT_FOUND)
        self.assertEqual(models.DeviceLifecycleEvent.objects.count(), before)

    def test_consume_counts_uses_and_closes_at_limit(self):
        outcome = authorization.consume(self.auth, L.good_request(), actor="system:bootstrap")
        self.assertTrue(outcome.authorized)
        self.auth.refresh_from_db()
        self.assertEqual((self.auth.use_count, self.auth.state), (1, "CONSUMED"))
        self.assertEqual(authorization.consume(self.auth, L.good_request(), actor="system:bootstrap").decision, Decision.EXHAUSTED)
        self.device.refresh_from_db()
        self.assertEqual((self.device.lifecycle_state, self.device.admission_state), ("REGISTERED", "NOT_ADMITTED"))

    def test_consume_refused_request_counts_nothing(self):
        self.assertEqual(authorization.consume(self.auth, L.good_request(serial="SN-OTHER"), actor="s").decision, Decision.IDENTITY_MISMATCH)
        self.assertEqual(authorization.consume(None, {}, actor="s").decision, Decision.NOT_FOUND)
        self.auth.refresh_from_db()
        self.assertEqual(self.auth.use_count, 0)
        self.assertEqual(self.device.lifecycle_events.order_by("-sequence").first().outcome, "REFUSED")

    def test_consume_refuses_when_a_concurrent_consumer_won(self):
        real_decide = authorization.decide

        def racing(auth, request, now=None):
            outcome = real_decide(auth, request, now=now)
            models.BootstrapAuthorization.objects.filter(pk=auth.pk).update(use_count=F("use_count") + 1)   # another worker's use
            return outcome

        with mock.patch.object(authorization, "decide", side_effect=racing):
            outcome = authorization.consume(self.auth, L.good_request(), actor="system:bootstrap")
        self.assertEqual((outcome.decision, outcome.as_dict()["codes"]), (Decision.CONFLICTING_REQUEST, ["CONCURRENT_MODIFICATION"]))
        self.auth.refresh_from_db()
        self.assertEqual((self.auth.use_count, self.auth.state), (1, "APPROVED"))
        self.assertEqual(self.device.lifecycle_events.order_by("-sequence").first().outcome, "REFUSED")

    def test_decision_result_authorized_false_for_refusal(self):
        self.assertFalse(authorization.DecisionResult(Decision.EXPIRED).authorized)
