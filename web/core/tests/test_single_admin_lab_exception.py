"""The owner-authorized lab exception is narrow, expiring, audited and off by default."""

from __future__ import annotations

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.test import TestCase
from django.utils import timezone

from core import models
from core.services.devices import attachments, lifecycle
from core.services.identity import policy
from core.services.identity import single_admin_exception as exception
from core.services.management import paths


class SingleAdminExceptionTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        user = get_user_model().objects.create_user("dhruv", password="test-only-password", is_staff=True)
        for role in ("NMAS Approver", "NMAS Security Admin", "NMAS Executor"):
            group, _ = Group.objects.get_or_create(name=role)
            codenames = [item.value for item in policy.ROLE_PERMISSIONS[role]]
            group.permissions.add(*Permission.objects.filter(content_type__app_label="core", codename__in=codenames))
            user.groups.add(group)
        models.AppMfaDevice.objects.create(user=user, encrypted_seed="test-only", confirmed_at=self.now)
        lifecycle.adopt_existing("mgmt_swt", role="switch", actor="bootstrap-admin")
        self.device = lifecycle.adopt_existing("R2", role="router", actor="bootstrap-admin").device
        nmas = paths.register_nmas_attachment(
            name="nmas-mgmt", host_interface="nmas-mgmt", upstream_device="mgmt_swt", upstream_interface="Ethernet9",
            source_address="192.168.200.100", network="192.168.200.0/24", actor="dhruv").attachment
        paths.record_nmas_observation(nmas, {"interface": "nmas-mgmt", "exists": True, "oper_up": True,
                                                    "addresses": ["192.168.200.100/24"], "holds_source": True}, actor="observer")
        self.nmas = models.NmasManagementAttachment.objects.get(pk=nmas.pk)
        attached = attachments.register_attachment(
            self.device, upstream_device="mgmt_swt", upstream_interface="Ethernet2", local_interface="Ethernet3",
            purpose=models.AttachmentPurpose.MANAGEMENT, connectivity=models.AttachmentConnectivity.ACCESS, vlan=200,
            actor="dhruv").attachment
        seen = lifecycle.record_observation(
            self.device, kind=models.ObservationKind.ATTACHMENT,
            source=models.ObservationSource.TRUSTED_UPSTREAM_INTERFACE, actor="source:nmas-topology",
            upstream_device="mgmt_swt", upstream_interface="Ethernet2", local_interface="Ethernet3")
        self.attachment = models.DeviceAttachment.objects.get(pk=attached.pk)
        self.observation = seen.observation

    def capability(self, *, exception_id="OWNER-LAB-TEST-0001", scope=None, max_uses=4, issued=None, expires=None):
        issued = issued or self.now - timedelta(seconds=5)
        expires = expires or issued + timedelta(minutes=30)
        document = {
            "schema": exception.SCHEMA, "marker": exception.MARKER, "mode": exception.MODE,
            "exception_id": exception_id, "actor": "dhruv", "lab_id": "srlceos01",
            "issued_at": issued.isoformat(), "expires_at": expires.isoformat(), "max_uses": max_uses,
            "scope": scope or {
                "NMAS_ATTACHMENT_APPROVE": [self.nmas.attachment_id],
                "ATTACHMENT_APPROVE": [f"{self.device.device_id}:{self.attachment.pk}"],
            },
            "evidence": {"attachment_observation_id": self.observation.pk,
                         "attachment_evidence_sha256": "a" * 64},
        }
        parsed = exception.parse(document)
        self.assertTrue(parsed.ok, parsed.codes)
        return parsed.capability

    def activate(self, cap):
        activated = exception.activate(cap, actor="dhruv", now=self.now)
        self.assertTrue(activated.ok, activated.codes)

    def uses(self, cap):
        return [e for e in models.AuditEvent.objects.filter(object_type=exception.OBJECT_TYPE, object_id=cap.exception_id)
                if (e.metadata or {}).get("exception_operation") == "USE"]

    def test_disabled_by_default_preserves_normal_two_person_policy(self):
        self.assertEqual(exception.load().codes, ["EXCEPTION_DISABLED"])
        self.assertIn("MGMT_PATH_SELF_APPROVAL", paths.approve_nmas_attachment(self.nmas, actor="dhruv").codes)
        self.assertIn("APPROVAL_SELF", attachments.approve_attachment(self.device, self.attachment.pk, actor="dhruv").codes)
        self.assertTrue(paths.approve_nmas_attachment(self.nmas, actor="bootstrap-admin").ok)

    def test_exact_two_record_scope_approves_and_audits_without_claiming_sod(self):
        cap = self.capability()
        self.activate(cap)
        self.assertTrue(paths.approve_nmas_attachment(self.nmas, actor="dhruv", exception=cap).ok)
        self.assertTrue(attachments.approve_attachment(self.device, self.attachment.pk, actor="dhruv", exception=cap).ok)
        self.nmas.refresh_from_db(); self.attachment.refresh_from_db()
        self.assertEqual((self.nmas.approval_state, self.nmas.created_by, self.nmas.approved_by), ("APPROVED", "dhruv", "dhruv"))
        self.assertEqual((self.attachment.approval_state, self.attachment.created_by, self.attachment.approved_by),
                         ("APPROVED", "dhruv", "dhruv"))
        uses = self.uses(cap)
        self.assertEqual(len(uses), 2)
        self.assertTrue(all(e.metadata["approval_mode"] == exception.MODE and
                            e.metadata["separation_of_duties_satisfied"] is False and
                            e.metadata["original_requester"] == "dhruv" for e in uses))

    def test_unrelated_target_and_actor_are_denied(self):
        cap = self.capability()
        self.activate(cap)
        self.assertEqual(exception.authorize(cap, action="ATTACHMENT_APPROVE", target="DEV-999999:9", actor="dhruv").codes,
                         ["EXCEPTION_TARGET_OUT_OF_SCOPE"])
        self.assertEqual(exception.authorize(cap, action="ATTACHMENT_APPROVE",
                                             target=f"{self.device.device_id}:{self.attachment.pk}", actor="other").codes,
                         ["EXCEPTION_ACTOR_MISMATCH"])

    def test_replay_is_denied_and_record_state_is_stable(self):
        cap = self.capability()
        self.activate(cap)
        first = paths.approve_nmas_attachment(self.nmas, actor="dhruv", exception=cap)
        self.assertTrue(first.ok)
        replay = exception.authorize(cap, action="NMAS_ATTACHMENT_APPROVE", target=self.nmas.attachment_id, actor="dhruv")
        self.assertEqual(replay.codes, ["EXCEPTION_REPLAY"])
        self.assertEqual(len(self.uses(cap)), 1)

    def test_stale_or_missing_attachment_evidence_consumes_nothing(self):
        cap = self.capability()
        self.activate(cap)
        self.attachment.verification_state = models.AttachmentVerification.UNVERIFIED
        self.attachment.save(update_fields=["verification_state", "updated_at"])
        result = attachments.approve_attachment(self.device, self.attachment.pk, actor="dhruv", exception=cap)
        self.assertFalse(result.ok)
        self.attachment.refresh_from_db()
        self.assertEqual(self.attachment.approval_state, "PENDING")
        self.assertEqual(self.uses(cap), [])

    def test_expiration_budget_and_revocation_fail_closed(self):
        cap = self.capability(max_uses=1)
        self.activate(cap)
        self.assertTrue(paths.approve_nmas_attachment(self.nmas, actor="dhruv", exception=cap).ok)
        self.assertEqual(exception.state(cap).codes, ["EXCEPTION_EXHAUSTED"])

        other = self.capability(exception_id="OWNER-LAB-TEST-0002",
                                scope={"ATTACHMENT_APPROVE": [f"{self.device.device_id}:{self.attachment.pk}"]})
        self.activate(other)
        revoked = exception.revoke(other, actor="dhruv", reason="exercise complete")
        self.assertTrue(revoked.ok)
        self.assertEqual(exception.state(other).codes, ["EXCEPTION_REVOKED"])

    def test_expired_window_and_document_over_30_minutes_are_refused(self):
        cap = self.capability(issued=self.now - timedelta(minutes=20), expires=self.now + timedelta(minutes=10))
        self.activate(cap)
        self.assertEqual(exception.state(cap, now=cap.expires_at + timedelta(seconds=1)).codes, ["EXCEPTION_EXPIRED"])
        too_long = {
            "schema": exception.SCHEMA, "marker": exception.MARKER, "mode": exception.MODE,
            "exception_id": "OWNER-LAB-BAD-1", "actor": "dhruv", "lab_id": "srlceos01",
            "issued_at": self.now.isoformat(), "expires_at": (self.now + timedelta(minutes=31)).isoformat(), "max_uses": 1,
            "scope": {"X": ["Y"]}, "evidence": {},
        }
        self.assertEqual(exception.parse(too_long).codes, ["EXCEPTION_DOCUMENT_INVALID"])

    def test_activation_requires_real_mfa_security_admin(self):
        cap = self.capability()
        user = get_user_model().objects.get(username="dhruv")
        user.nmas_app_mfa.delete()
        self.assertEqual(exception.activate(cap, actor="dhruv", now=self.now).codes, ["EXCEPTION_ACTOR_UNAUTHORIZED"])

    def test_exact_management_path_scope_uses_existing_approval_logic(self):
        first = self.capability()
        self.activate(first)
        self.assertTrue(paths.approve_nmas_attachment(self.nmas, actor="dhruv", exception=first).ok)
        self.assertTrue(attachments.approve_attachment(
            self.device, self.attachment.pk, actor="dhruv", exception=first).ok)
        created = paths.register_path(
            self.device, path_type=models.ManagementPathType.DIRECT_OOB,
            endpoint_address="192.168.200.2", nmas_attachment_id=self.nmas.pk,
            credential_source=models.ManagementCredentialSource.INVENTORY,
            credential_reference="R2", actor="dhruv", attachment_id=self.attachment.pk,
            via_device="mgmt_swt", remote_interface="Ethernet2", vlan=200,
            expected_host_key="SHA256:OyuxmXszJ9liLZjlWuKOvoKhGCxuryrmLDf0GIB4dtk",
            reason="test-only scoped path")
        self.assertTrue(created.ok, created.blockers)
        cap = self.capability(
            exception_id="OWNER-LAB-TEST-PATH-0001", max_uses=1,
            scope={"MGMT_PATH_APPROVE": [created.path.path_id]})
        self.activate(cap)
        approved = paths.approve_path(created.path, actor="dhruv", exception=cap)
        self.assertTrue(approved.ok, approved.blockers)
        approved.path.refresh_from_db()
        self.assertEqual((approved.path.approval_state, approved.path.created_by, approved.path.approved_by),
                         ("APPROVED", "dhruv", "dhruv"))
