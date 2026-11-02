"""V2 Lifecycle Phase 2: identity normalization, conflict detection and the model-level guards of the new tables."""

from __future__ import annotations

from django.db import IntegrityError, transaction
from django.test import SimpleTestCase, TestCase

from core import models
from core.services.devices import codes, identity
from core.tests.helpers import lifecycle as L


class IdentityNormalizationTests(SimpleTestCase):
    def test_serial_accepts_and_uppercases_valid(self):
        self.assertEqual(identity.normalize_serial(" sn-abc.1/2 "), ("SN-ABC.1/2", []))
        self.assertEqual(identity.normalize_serial(""), ("", []))

    def test_serial_rejects_malformed(self):
        self.assertEqual(codes.codes(identity.normalize_serial("bad serial!")[1]), ["SERIAL_INVALID"])

    def test_mac_accepts_valid_forms(self):
        for value in ("00:1C:73:AA:BB:CC", "00-1c-73-aa-bb-cc", "001c.73aa.bbcc", "001c73aabbcc"):
            with self.subTest(value=value):
                self.assertEqual(identity.normalize_mac(value), ("00:1c:73:aa:bb:cc", []))
        self.assertEqual(identity.normalize_mac(None), ("", []))

    def test_mac_rejects_invalid_group_zero_and_broadcast(self):
        for value in ("01:00:5e:00:00:01", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "00:1c:73", "zz:1c:73:aa:bb:cc"):
            with self.subTest("rejected", value=value):
                self.assertEqual(codes.codes(identity.normalize_mac(value)[1]), ["MAC_INVALID"])

    def test_host_key_accepts_valid_and_rejects_malformed(self):
        self.assertEqual(identity.normalize_host_key(L.HOST_KEY), (L.HOST_KEY, []))
        self.assertEqual(identity.normalize_host_key(""), ("", []))
        with self.subTest("invalid"):
            self.assertEqual(codes.codes(identity.normalize_host_key("MD5:aa")[1]), ["HOST_KEY_INVALID"])

    def test_clean_text_accepts_plain_label(self):
        self.assertEqual(identity.clean_text("  Arista  ", max_length=64), ("Arista", []))

    def test_clean_text_rejects_control_secret_and_overlong(self):
        for value in ("bad\x00text", "password=hunter2secret", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", "x" * 65):
            with self.subTest(value=value[:10]):
                self.assertEqual(codes.codes(identity.clean_text(value, max_length=64)[1]), ["TEXT_INVALID"])

    def test_validate_name_accepts_valid(self):
        self.assertEqual(identity.validate_name(" NEW1 "), ("NEW1", []))

    def test_validate_name_rejects_invalid(self):
        self.assertEqual(codes.codes(identity.validate_name("bad name;")[1]), ["NAME_INVALID"])

    def test_blocker_and_codes_render_fixed_messages(self):
        found = codes.blocker("IDENTITY_CONFLICT", kind="serial")
        self.assertEqual(found["details"], {"kind": "serial"})
        self.assertEqual(codes.codes([found]), ["IDENTITY_CONFLICT"])

    def test_blocker_unknown_code_raises(self):
        with self.assertRaises(KeyError):
            codes.blocker("NOT_A_CODE")

    def test_codes_of_empty_list_is_empty(self):
        self.assertEqual(codes.codes([]), [])


class IdentityConflictTests(TestCase):
    def test_identity_conflicts_accepts_unique_identity(self):
        self.assertEqual(identity.identity_conflicts(serial="SN-X", mac="00:1c:73:00:00:09", host_key=L.HOST_KEY), [])

    def test_identity_conflicts_detects_duplicate_expected_identity(self):
        device = L.register().device
        found = identity.identity_conflicts(serial=L.SERIAL, mac=L.MAC)
        self.assertEqual(codes.codes(found), ["IDENTITY_CONFLICT", "IDENTITY_CONFLICT"])
        self.assertEqual(identity.identity_conflicts(serial=L.SERIAL, exclude_pk=device.pk), [])

    def test_name_collisions_accepts_free_name(self):
        self.assertEqual(identity.name_collisions("FRESH1"), [])

    def test_name_collisions_detects_inventory_and_registry_conflict(self):
        self.assertEqual(identity.name_collisions("R1")[0]["details"]["holders"], ["INVENTORY"])
        self.assertEqual(identity.name_collisions("WebServer")[0]["details"]["holders"], ["INVENTORY"])
        self.assertEqual(identity.name_collisions("R1", allow_adopted_inventory=True), [])
        L.register()
        self.assertEqual(identity.name_collisions("NEW1")[0]["details"]["holders"], ["LIFECYCLE_REGISTRY"])


class ManagedDeviceModelGuardTests(TestCase):
    def test_device_ids_and_url_render(self):
        device = L.register().device
        self.assertEqual(device.device_id, f"DEV-{device.pk:06d}")
        self.assertIn(device.device_id, device.get_absolute_url())
        self.assertFalse(device.is_terminal)
        self.assertIn("NEW1", str(device))
        self.assertEqual(models.ManagedDevice(name="X").device_id, "DEV-NEW")

    def test_save_refuses_creation_outside_the_service(self):
        with self.assertRaises(ValueError):
            models.ManagedDevice(name="ROGUE1", platform=models.Platform.ARISTA_CEOS, role="router", registered_by="x").save()

    def test_save_refuses_invalid_choice_and_malformed_identity(self):
        row = models.ManagedDevice(name="ROGUE2", platform="nope", role="router", registered_by="x")
        row._lifecycle_write = True
        with self.assertRaises(ValueError):
            row.save()
        row = models.ManagedDevice(name="ROGUE3", platform=models.Platform.ARISTA_CEOS, role="router", registered_by="x", expected_base_mac="bad")
        row._lifecycle_write = True
        with self.assertRaises(ValueError):
            row.save()

    def test_save_accepts_non_lifecycle_edit_and_refuses_unguarded_lifecycle_edit(self):
        device = L.register().device
        device.model = "cEOS-lab"
        device.save()
        device.lifecycle_state = models.DeviceLifecycleState.IN_SERVICE
        with self.assertRaises(ValueError):
            device.save()

    def test_save_refuses_immutable_name_change(self):
        device = L.register().device
        device.name = "RENAMED1"
        with self.assertRaises(ValueError):
            device.save()

    def test_delete_and_bulk_writes_are_refused(self):
        device = L.register().device
        with self.assertRaises(ValueError):
            device.delete()
        with self.assertRaises(ValueError):
            models.ManagedDevice.objects.all().delete()
        with self.assertRaises(ValueError):
            models.ManagedDevice.objects.filter(pk=device.pk).update(lifecycle_state=models.DeviceLifecycleState.IN_SERVICE)
        self.assertEqual(models.ManagedDevice.objects.filter(pk=device.pk).update(model="ok"), 1)

    def test_bulk_update_accepts_non_lifecycle_field(self):
        device = L.register().device
        self.assertEqual(models.ManagedDevice.objects.filter(pk=device.pk).update(manufacturer="Arista"), 1)

    def test_compare_and_swap_writes_at_the_current_version(self):
        device = L.register().device
        before = device.version
        self.assertEqual(models.ManagedDevice.objects.compare_and_swap(device.pk, device.version, model="m1"), 1)
        device.refresh_from_db()
        self.assertEqual((device.model, device.version), ("m1", before + 1))

    def test_compare_and_swap_refuses_stale_version(self):
        device = L.register().device
        self.assertEqual(models.ManagedDevice.objects.compare_and_swap(device.pk, device.version + 5, model="m1"), 0)

    def test_unique_live_name_constraint_rejects_duplicate(self):
        L.register()
        row = models.ManagedDevice(name="NEW1", platform=models.Platform.ARISTA_CEOS, role="router", registered_by="x",
                                   lifecycle_state=models.DeviceLifecycleState.REGISTERED, origin=models.DeviceOrigin.REGISTERED_NEW,
                                   inventory_authority=models.InventoryAuthority.NMAS_REGISTRY)
        row._lifecycle_write = True
        with self.assertRaises(IntegrityError), transaction.atomic():
            row.save()


class AttachmentObservationAuthorizationModelTests(TestCase):
    def setUp(self):
        self.device, self.attachment, self.auth = L.ready_device(approve_auth=False)

    def test_attachment_str_and_permitted_state_update(self):
        self.assertIn("S1:Ethernet7", str(self.attachment))
        self.attachment.verification_state = models.AttachmentVerification.VERIFIED
        self.attachment.save()

    def test_attachment_refuses_immutable_change_invalid_choice_and_delete(self):
        self.attachment.vlan = 31
        with self.assertRaises(ValueError):
            self.attachment.save()
        self.attachment.refresh_from_db()
        self.attachment.purpose = "nope"
        with self.assertRaises(ValueError):
            self.attachment.save()
        with self.assertRaises(ValueError):
            self.attachment.delete()

    def test_observation_accepts_matching_trust(self):
        row = models.DeviceObservation(device=self.device, kind=models.ObservationKind.IDENTITY, source=models.ObservationSource.DHCP_CLIENT_CLAIM,
                                       trust=models.ObservationTrust.CLAIMED, result=models.ObservationResult.UNTRUSTED, recorded_by="t",
                                       observed_at=self.device.created_at)
        row.save()
        self.assertIn("DHCP_CLIENT_CLAIM", str(row))

    def test_observation_refuses_forged_trust_and_delete(self):
        row = models.DeviceObservation(device=self.device, kind=models.ObservationKind.IDENTITY, source=models.ObservationSource.DHCP_CLIENT_CLAIM,
                                       trust=models.ObservationTrust.OBSERVED, result=models.ObservationResult.MATCH, recorded_by="t",
                                       observed_at=self.device.created_at)
        with self.assertRaises(ValueError):
            row.save()
        row.source = "nope"
        with self.assertRaises(ValueError):
            row.save()
        with self.assertRaises(ValueError):
            row.delete()

    def test_authorization_ids_and_permitted_edge(self):
        self.assertEqual(self.auth.auth_id, f"BAUTH-{self.auth.pk:06d}")
        self.assertTrue(self.auth.is_open)
        self.assertIn(self.auth.auth_id, str(self.auth))
        self.assertEqual(models.BootstrapAuthorization().auth_id, "BAUTH-NEW")
        self.auth.reason = "edited reason"
        self.auth.save()

    def test_authorization_refuses_invalid_edge_digest_immutable_and_delete(self):
        self.auth.state = models.BootstrapAuthorizationState.CONSUMED
        with self.assertRaises(ValueError):
            self.auth.save()
        self.auth.refresh_from_db()
        self.auth.max_uses = 5
        with self.assertRaises(ValueError):
            self.auth.save()
        self.auth.refresh_from_db()
        self.auth.binding_digest = "short"
        with self.assertRaises(ValueError):
            self.auth.save()
        self.auth.refresh_from_db()
        self.auth.state = "nope"
        with self.assertRaises(ValueError):
            self.auth.save()
        with self.assertRaises(ValueError):
            self.auth.delete()

    def test_closed_authorization_is_immutable_history(self):
        self.auth.state = models.BootstrapAuthorizationState.REVOKED
        self.auth.save()
        self.auth.reason = "changed"
        with self.assertRaises(ValueError):
            self.auth.save()

    def test_self_approval_constraint_rejects_same_person(self):
        self.auth.approved_by = self.auth.requested_by
        with self.assertRaises(IntegrityError), transaction.atomic():
            self.auth.save()

    def test_event_save_accepts_new_chained_row(self):
        previous = self.device.lifecycle_events.order_by("-sequence").first()
        row = models.DeviceLifecycleEvent(device=self.device, sequence=previous.sequence + 1, action="NOTE", outcome="RECORDED", actor="t",
                                          actor_kind="HUMAN", correlation_id="c", previous_digest=previous.entry_digest, entry_digest="a" * 64)
        row.save()
        self.assertEqual(self.device.lifecycle_events.count(), previous.sequence + 1)

    def test_event_str_and_refuses_mutation_bad_outcome_and_delete(self):
        event = self.device.lifecycle_events.first()
        self.assertIn(self.device.device_id, str(event))
        with self.assertRaises(ValueError):
            event.save()
        with self.assertRaises(ValueError):
            event.delete()
        fresh = models.DeviceLifecycleEvent(device=self.device, sequence=99, action="X", outcome="nope", actor="t", actor_kind="HUMAN",
                                            correlation_id="c", entry_digest="0" * 64)
        with self.assertRaises(ValueError):
            fresh.save()
        fresh.outcome, fresh.entry_digest = models.DeviceLifecycleEventOutcome.RECORDED, "bad"
        with self.assertRaises(ValueError):
            fresh.save()
