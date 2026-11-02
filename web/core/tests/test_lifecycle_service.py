"""V2 Lifecycle Phase 2: registration, adoption, the transition engine, observations, identity verification and evidence."""

from __future__ import annotations

from unittest import mock

from django.db import connection
from django.test import TestCase

from core import models
from core.services.devices import events, lifecycle
from core.tests.helpers import lifecycle as L

S = models.DeviceLifecycleState


class RegistrationTests(TestCase):
    def test_register_creates_registered_unverified_not_admitted(self):
        result = L.register()
        device = result.device
        self.assertTrue(result.ok and result.changed)
        self.assertEqual((device.lifecycle_state, device.identity_state, device.admission_state, device.origin),
                         (S.REGISTERED, "UNVERIFIED", "NOT_ADMITTED", "REGISTERED_NEW"))
        self.assertEqual((device.expected_serial, device.expected_base_mac, device.verified_serial), (L.SERIAL, L.MAC, ""))
        self.assertEqual(device.lifecycle_events.get().action, "REGISTER")
        self.assertTrue(models.AuditEvent.objects.filter(event_type=models.AuditEventType.DEVICE_REGISTERED).exists())

    def test_register_refuses_invalid_and_conflicting_input(self):
        cases = {
            "name": ({"name": "bad name"}, "NAME_INVALID"), "inventory": ({"name": "R1"}, "NAME_COLLISION"),
            "endpoint": ({"name": "H1"}, "NAME_COLLISION"), "platform": ({"platform": "nope"}, "PLATFORM_UNKNOWN"),
            "serial": ({"serial": "bad serial!"}, "SERIAL_INVALID"), "mac": ({"mac": "ff:ff:ff:ff:ff:ff"}, "MAC_INVALID"),
        }
        for label, (kwargs, code) in cases.items():
            with self.subTest(label):
                self.assertIn(code, L.register(**kwargs).codes)
        self.assertIn("ROLE_INVALID", lifecycle.register_device(name="NEW9", platform=models.Platform.ARISTA_CEOS, role="nope", actor="x").codes)
        self.assertIn("TEXT_INVALID", lifecycle.register_device(name="NEW9", platform=models.Platform.ARISTA_CEOS, role="router", actor="x",
                                                                manufacturer="token=abc").codes)
        self.assertIn("TEXT_INVALID", lifecycle.register_device(name="NEW9", platform=models.Platform.ARISTA_CEOS, role="router", actor="x",
                                                                netbox_device_id="x1").codes)
        self.assertFalse(models.ManagedDevice.objects.exists())
        self.assertTrue(models.AuditEvent.objects.filter(event_type=models.AuditEventType.DEVICE_LIFECYCLE_REFUSED).exists())

    def test_register_refuses_duplicate_identity_and_name(self):
        L.register()
        self.assertIn("NAME_COLLISION", L.register(serial="SN-OTHER", mac="").codes)
        self.assertIn("IDENTITY_CONFLICT", L.register(name="NEW2").codes)

    def test_update_expected_identity_accepts_valid_edit(self):
        device = L.register().device
        result = lifecycle.update_expected_identity(device, actor=L.OPERATOR, expected_serial="sn-new1b", expected_base_mac="",
                                                    manufacturer="Arista", model="cEOS", expected_version=device.version)
        self.assertTrue(result.ok, result.codes)
        device.refresh_from_db()
        self.assertEqual((device.expected_serial, device.expected_base_mac, device.manufacturer), ("SN-NEW1B", "", "Arista"))

    def test_update_expected_identity_refuses_stale_locked_invalid_and_conflicting(self):
        device = L.register().device
        with self.subTest("stale version"):
            self.assertEqual(lifecycle.update_expected_identity(device, actor="x", expected_version=device.version + 1).codes, ["CONCURRENT_MODIFICATION"])
        with self.subTest("invalid"):
            self.assertEqual(lifecycle.update_expected_identity(device, actor="x", expected_serial="bad serial!").codes, ["SERIAL_INVALID"])
        with self.subTest("conflict"):
            L.register(name="NEW2", serial="SN-NEW2", mac="")
            self.assertEqual(lifecycle.update_expected_identity(device, actor="x", expected_serial="SN-NEW2").codes[0], "IDENTITY_CONFLICT")
        with self.subTest("locked by an open authorization"):
            device, _, _ = self._authorized()
            self.assertEqual(lifecycle.update_expected_identity(device, actor="x", expected_serial="SN-NEW3").codes, ["IDENTITY_LOCKED"])

    def _authorized(self):
        L.adopt()
        device = models.ManagedDevice.objects.get(name="NEW1")
        attachment = L.attach(device).attachment
        return device, attachment, L.request_auth(device, attachment).authorization

    def test_get_device_returns_known_id(self):
        device = L.register().device
        self.assertEqual(lifecycle.get_device(device.device_id), device)

    def test_get_device_unknown_or_malformed_is_none(self):
        for value in ("DEV-999999", "PROV-000001", "", None, "DEV-x"):
            with self.subTest(value=value):
                self.assertIsNone(lifecycle.get_device(value))

    def test_lifecycle_result_codes_returns_blocker_codes(self):
        self.assertEqual(lifecycle.LifecycleResult(None, False, "X", [{"code": "A"}]).codes, ["A"])


class AdoptionTests(TestCase):
    def test_adopt_creates_legacy_in_service_record_with_honest_evidence(self):
        result = L.adopt("R1", role="router")
        device = result.device
        self.assertTrue(result.ok and result.changed)
        self.assertEqual((device.origin, device.inventory_authority, device.lifecycle_state, device.identity_state, device.admission_state,
                          device.ztp_state, device.compliance_state),
                         ("LEGACY_ADOPTION", "INVENTORY_FILE", S.IN_SERVICE, "UNVERIFIED", "LEGACY_PREEXISTING", "UNKNOWN", "UNKNOWN"))
        evidence = device.lifecycle_events.get().evidence
        self.assertIn("NONE", evidence["onboarding_history"])
        self.assertEqual(len(evidence["inventory_entry_digest"]), 64)
        self.assertEqual(set(evidence["linked_history"]), {"changes", "executions", "access_records", "maintenance_records", "provisioning_runs"})
        self.assertFalse(models.ProvisioningRun.objects.exists())
        self.assertFalse(device.bootstrap_authorizations.exists())
        self.assertNotIn("password", str(evidence).lower())

    def test_adopt_repeat_is_unchanged_not_duplicated(self):
        first = L.adopt("R2", role="router")
        again = L.adopt("R2", role="router")
        self.assertTrue(again.ok)
        self.assertFalse(again.changed)
        self.assertEqual(again.device, first.device)
        self.assertEqual(models.ManagedDevice.objects.filter(name="R2").count(), 1)
        self.assertEqual(list(first.device.lifecycle_events.values_list("outcome", flat=True)), ["ADVANCED", "UNCHANGED"])

    def test_adopt_refuses_r5_hosts_webserver_unknown_and_bad_role(self):
        for name, code in (("R5", "OUT_OF_WRITABLE_SCOPE"), ("H1", "NOT_IN_INVENTORY"), ("H4", "NOT_IN_INVENTORY"),
                           ("WebServer", "NOT_IN_INVENTORY"), ("NOPE1", "NOT_IN_INVENTORY")):
            with self.subTest(name=name):
                self.assertEqual(L.adopt(name, role="router").codes, [code])
        self.assertEqual(L.adopt("R3", role="nope").codes, ["ROLE_INVALID"])
        self.assertFalse(models.ManagedDevice.objects.exists())

    def test_adopt_refuses_name_collision_with_provisioning(self):
        with mock.patch("core.services.devices.identity.name_collisions", return_value=[{"code": "NAME_COLLISION", "message": "", "remediation": ""}]):
            self.assertEqual(L.adopt("R4", role="router").codes, ["NAME_COLLISION"])

    def test_adoption_candidates_returns_every_inventory_device_with_eligibility(self):
        L.adopt("S2")
        rows = {row["target"].name: row for row in lifecycle.adoption_candidates()}
        self.assertEqual(rows["R5"]["refusal"], "OUT_OF_WRITABLE_SCOPE")
        self.assertTrue(rows["S2"]["adopted"])
        self.assertEqual(rows["R1"]["refusal"], "")
        self.assertNotIn("H1", rows)

    def test_adoption_candidates_without_inventory_devices_is_empty(self):
        self.assertEqual(lifecycle.adoption_candidates(document={"network_devices": {}}), [])


class TransitionTests(TestCase):
    def test_allowed_targets_lists_owner_phases(self):
        edges = {e["to"]: e for e in lifecycle.allowed_targets(S.DISCOVERED)}
        self.assertTrue(edges[S.WITHDRAWN]["available"])
        # Phase 3 enabled DISCOVERED -> BOOTSTRAPPED (automation only, behind ZTP management-verification evidence)
        self.assertEqual((edges[S.BOOTSTRAPPED]["owner_phase"], edges[S.BOOTSTRAPPED]["available"]), (3, True))

    def test_terminal_state_has_no_edges(self):
        self.assertEqual(lifecycle.allowed_targets(S.WITHDRAWN), [])

    def test_transition_refuses_unavailable_invalid_unknown_and_unauthorized_edges(self):
        device = L.register().device
        with self.subTest("unknown state"):
            self.assertEqual(lifecycle.transition(device, "NOPE", actor="x").codes, ["TRANSITION_INVALID"])
        with self.subTest("invalid edge"):
            self.assertEqual(lifecycle.transition(device, S.IN_SERVICE, actor="x").codes, ["TRANSITION_INVALID"])
        with self.subTest("discover without an observation"):
            self.assertEqual(lifecycle.transition(device, S.DISCOVERED, actor="x").codes, ["OBSERVATION_INVALID"])
        with self.subTest("missing actor"):
            self.assertEqual(lifecycle.transition(device, S.WITHDRAWN, actor="").codes, ["ACTOR_NOT_AUTHORIZED"])
        L.adopt("S3")
        adopted = models.ManagedDevice.objects.get(name="S3")
        for to in (S.DECOMMISSION_PENDING,):
            # Phase 7 made the edge available; a bare request without its approved decommission record is still refused
            with self.subTest("no decommission record", to=to):
                result = lifecycle.transition(adopted, to, actor="x")
                self.assertEqual(result.codes, ["DECOMMISSION_STATE_INVALID"])
                self.assertEqual(result.blockers[0]["details"]["action"], "DECOMMISSION_REQUEST")
        device.refresh_from_db()
        self.assertEqual(device.lifecycle_state, S.REGISTERED)
        self.assertEqual(set(device.lifecycle_events.exclude(action="REGISTER").values_list("outcome", flat=True)), {"REFUSED"})

    def test_transition_to_current_state_is_unchanged(self):
        device = L.register().device
        result = lifecycle.transition(device, S.REGISTERED, actor="x")
        self.assertTrue(result.ok)
        self.assertFalse(result.changed)
        self.assertEqual(result.event.outcome, "UNCHANGED")

    def test_transition_refuses_concurrent_modification(self):
        device = L.register().device
        stale = models.ManagedDevice.objects.get(pk=device.pk)
        lifecycle.update_expected_identity(device, actor="x", expected_serial="SN-Z", expected_version=device.version)
        result = lifecycle.withdraw(stale, actor="x", reason="duplicate order", expected_version=stale.version)
        self.assertEqual(result.codes, ["CONCURRENT_MODIFICATION"])
        self.assertEqual(models.ManagedDevice.objects.get(pk=device.pk).lifecycle_state, S.REGISTERED)

    def test_transition_failure_rolls_back_every_write(self):
        device, _, auth = L.ready_device(approve_auth=False)
        with mock.patch.object(events, "record", side_effect=[RuntimeError("boom"), mock.DEFAULT]), self.assertRaises(RuntimeError):
            lifecycle.withdraw(device, actor="x", reason="cancelled order")
        device.refresh_from_db()
        auth.refresh_from_db()
        self.assertEqual((device.lifecycle_state, auth.state), (S.REGISTERED, "PENDING_APPROVAL"))

    def test_withdraw_revokes_open_authorizations_and_is_terminal(self):
        device, _, auth = L.ready_device()
        result = lifecycle.withdraw(device, actor=L.OPERATOR, reason="order cancelled", expected_version=device.version)
        self.assertTrue(result.ok, result.codes)
        auth.refresh_from_db()
        self.assertEqual((result.device.lifecycle_state, auth.state), (S.WITHDRAWN, "REVOKED"))
        self.assertIsNotNone(result.device.retired_at)
        self.assertEqual(lifecycle.withdraw(result.device, actor="x", reason="again").codes, ["DEVICE_TERMINAL"])

    def test_withdraw_refuses_missing_reason_and_adopted_device(self):
        device = L.register().device
        self.assertEqual(lifecycle.withdraw(device, actor="x", reason="").codes, ["REASON_REQUIRED"])
        adopted = L.adopt("R3", role="router").device
        self.assertEqual(lifecycle.withdraw(adopted, actor="x", reason="no").codes, ["TRANSITION_INVALID"])

    def test_maintenance_state_without_record_is_empty(self):
        self.assertEqual(lifecycle.maintenance_state(L.register().device), {})

    def test_maintenance_state_reads_the_maintenance_record(self):
        device = L.adopt("R1", role="router").device
        self.assertEqual(lifecycle.maintenance_state(device), {})
        record = mock.Mock(record_id="MNT-000009", state="ACTIVE")
        with mock.patch.object(models.MaintenanceRecord.objects, "filter") as found:
            found.return_value.order_by.return_value.first.return_value = record
            self.assertEqual(lifecycle.maintenance_state(device), {"record_id": "MNT-000009", "state": "ACTIVE"})


class ObservationAndVerificationTests(TestCase):
    def setUp(self):
        L.adopt()
        self.device = L.register().device

    def _observe(self, source, claims, **extra):
        return lifecycle.record_observation(self.device, kind=models.ObservationKind.IDENTITY, source=source, actor="collector",
                                            claims=claims, **extra)

    def test_record_observation_discovers_and_trust_follows_source(self):
        result = self._observe(models.ObservationSource.DHCP_CLIENT_CLAIM, {"serial": L.SERIAL, "hostname": "NEW1"})
        self.assertTrue(result.ok and result.changed)
        self.assertEqual((result.observation.trust, result.observation.result), ("CLAIMED", "UNTRUSTED"))
        self.device.refresh_from_db()
        self.assertEqual((self.device.lifecycle_state, self.device.identity_state), (S.DISCOVERED, "PENDING_VERIFICATION"))
        self.assertEqual(list(self.device.lifecycle_events.values_list("action", flat=True))[-2:], ["OBSERVE_IDENTITY", "DISCOVER"])

    def test_record_observation_refuses_invalid_kind_source_and_claims(self):
        self.assertEqual(lifecycle.record_observation(self.device, kind="NOPE", source="X", actor="c").codes, ["OBSERVATION_INVALID"])
        self.assertEqual(self._observe(models.ObservationSource.DHCP_CLIENT_CLAIM, {"password": "x"}).codes, ["OBSERVATION_INVALID"])
        self.assertEqual(self._observe(models.ObservationSource.DHCP_CLIENT_CLAIM, {"serial": "bad serial!"}).codes, ["SERIAL_INVALID"])
        self.assertEqual(lifecycle.record_observation(self.device, kind=models.ObservationKind.ATTACHMENT,
                                                      source=models.ObservationSource.DHCP_RELAY_ATTACHMENT, actor="c").codes, ["OBSERVATION_INVALID"])
        self.assertEqual(self._observe(models.ObservationSource.DHCP_CLIENT_CLAIM, {}, upstream_device="bad name!").codes, ["OBSERVATION_INVALID"])
        self.assertFalse(models.DeviceObservation.objects.exists())

    def test_claimed_mismatch_never_grants_and_observed_mismatch_marks_identity(self):
        claim = self._observe(models.ObservationSource.DHCP_CLIENT_CLAIM, {"serial": "SN-OTHER"})
        self.assertEqual(claim.observation.result, "MISMATCH")
        self.device.refresh_from_db()
        self.assertEqual(self.device.identity_state, "PENDING_VERIFICATION")
        self._observe(models.ObservationSource.AUTHENTICATED_SESSION, {"serial": "SN-OTHER", "host_key": L.HOST_KEY})
        self.device.refresh_from_db()
        self.assertEqual(self.device.identity_state, "MISMATCH")

    def test_verify_identity_accepts_authenticated_observation(self):
        observed = self._observe(models.ObservationSource.AUTHENTICATED_SESSION, {"serial": L.SERIAL, "base_mac": L.MAC, "host_key": L.HOST_KEY})
        self.device.refresh_from_db()
        result = lifecycle.verify_identity(self.device, observed.observation.pk, actor=L.APPROVER, expected_version=self.device.version)
        self.assertTrue(result.ok, result.codes)
        self.device.refresh_from_db()
        self.assertEqual((self.device.identity_state, self.device.verified_serial, self.device.verified_host_key, self.device.identity_verified_by),
                         ("VERIFIED", L.SERIAL, L.HOST_KEY, L.APPROVER))

    def test_verify_identity_refuses_claims_insufficient_mismatch_and_unknown(self):
        claim = self._observe(models.ObservationSource.DHCP_CLIENT_CLAIM, {"serial": L.SERIAL, "base_mac": L.MAC, "host_key": L.HOST_KEY})
        self.assertEqual(lifecycle.verify_identity(self.device, claim.observation.pk, actor="a").codes, ["IDENTITY_NOT_OBSERVED"])
        reference = self._observe(models.ObservationSource.LAB_TOPOLOGY_REFERENCE, {"serial": L.SERIAL})
        self.assertEqual(lifecycle.verify_identity(self.device, reference.observation.pk, actor="a").codes, ["IDENTITY_NOT_OBSERVED"])
        no_key = self._observe(models.ObservationSource.AUTHENTICATED_SESSION, {"serial": L.SERIAL, "base_mac": L.MAC})
        self.assertEqual(lifecycle.verify_identity(self.device, no_key.observation.pk, actor="a").codes, ["IDENTITY_EVIDENCE_INSUFFICIENT"])
        no_mac = self._observe(models.ObservationSource.AUTHENTICATED_SESSION, {"serial": L.SERIAL, "host_key": L.HOST_KEY})
        self.assertEqual(lifecycle.verify_identity(self.device, no_mac.observation.pk, actor="a").codes, ["IDENTITY_EVIDENCE_INSUFFICIENT"])
        for value in ("999999", "x"):
            with self.subTest(observation=value):
                self.assertEqual(lifecycle.verify_identity(self.device, value, actor="a").codes, ["OBSERVATION_INVALID"])
        wrong = self._observe(models.ObservationSource.AUTHENTICATED_SESSION, {"serial": "SN-OTHER", "base_mac": L.MAC, "host_key": L.HOST_KEY})
        self.assertEqual(lifecycle.verify_identity(self.device, wrong.observation.pk, actor="a").codes, ["IDENTITY_MISMATCH"])
        self.device.refresh_from_db()
        self.assertEqual(self.device.verified_host_key, "")

    def test_verify_identity_refuses_host_key_of_another_device(self):
        other = L.register(name="NEW2", serial="SN-NEW2", mac="00:1c:73:00:00:02").device
        seen = lifecycle.record_observation(other, kind=models.ObservationKind.IDENTITY, source=models.ObservationSource.AUTHENTICATED_SESSION,
                                            actor="c", claims={"serial": "SN-NEW2", "base_mac": "00:1c:73:00:00:02", "host_key": L.HOST_KEY})
        self.assertTrue(lifecycle.verify_identity(other, seen.observation.pk, actor="a").ok)
        mine = self._observe(models.ObservationSource.AUTHENTICATED_SESSION, {"serial": L.SERIAL, "base_mac": L.MAC, "host_key": L.HOST_KEY})
        self.assertEqual(lifecycle.verify_identity(self.device, mine.observation.pk, actor="a").codes, ["IDENTITY_CONFLICT"])

    def test_verify_identity_refuses_observation_older_than_trusted_mismatch(self):
        good = self._observe(models.ObservationSource.AUTHENTICATED_SESSION, {"serial": L.SERIAL, "base_mac": L.MAC, "host_key": L.HOST_KEY})
        self._observe(models.ObservationSource.AUTHENTICATED_SESSION, {"serial": "SN-OTHER", "base_mac": L.MAC, "host_key": L.HOST_KEY})
        self.device.refresh_from_db()
        self.assertEqual(self.device.identity_state, "MISMATCH")
        self.assertEqual(lifecycle.verify_identity(self.device, good.observation.pk, actor=L.APPROVER).codes, ["IDENTITY_MISMATCH"])
        self.device.refresh_from_db()
        self.assertEqual((self.device.identity_state, self.device.verified_host_key), ("MISMATCH", ""))

    def test_update_expected_identity_refuses_verified_device(self):
        seen = self._observe(models.ObservationSource.AUTHENTICATED_SESSION, {"serial": L.SERIAL, "base_mac": L.MAC, "host_key": L.HOST_KEY})
        self.assertTrue(lifecycle.verify_identity(self.device, seen.observation.pk, actor=L.APPROVER).ok)
        self.device.refresh_from_db()
        result = lifecycle.update_expected_identity(self.device, actor=L.OPERATOR, expected_serial="SN-CHANGED", expected_base_mac=L.MAC,
                                                    expected_version=self.device.version)
        self.assertEqual(result.codes, ["IDENTITY_LOCKED"])
        self.device.refresh_from_db()
        self.assertEqual((self.device.identity_state, self.device.expected_serial), ("VERIFIED", L.SERIAL))

    def test_reference_observation_never_discovers_registered_device(self):
        reference = self._observe(models.ObservationSource.LAB_TOPOLOGY_REFERENCE, {"serial": L.SERIAL})
        self.assertTrue(reference.ok)
        self.assertFalse(reference.changed)
        self.device.refresh_from_db()
        self.assertEqual((self.device.lifecycle_state, self.device.identity_state), ("REGISTERED", "UNVERIFIED"))
        refused = lifecycle.transition(self.device, S.DISCOVERED, actor="collector", actor_kind="AUTOMATION",
                                       evidence={"observation": reference.observation.pk})
        self.assertEqual(refused.codes, ["OBSERVATION_INVALID"])


class EvidenceChainTests(TestCase):
    def test_record_chains_events_and_verify_chain_accepts_intact_chain(self):
        device = L.register().device
        event = events.record(device, "NOTE", models.DeviceLifecycleEventOutcome.RECORDED, actor="x", evidence={"k": "v"}, head="")
        self.assertEqual(event.sequence, 2)
        self.assertEqual(event.previous_digest, device.lifecycle_events.get(sequence=1).entry_digest)
        self.assertTrue(events.verify_chain(device))

    def test_record_refuses_unknown_actor_kind(self):
        device = L.register().device
        with self.assertRaises(ValueError):
            events.record(device, "NOTE", "RECORDED", actor="x", actor_kind="DEVICE")

    def test_record_redacts_secret_shaped_evidence(self):
        device = L.register().device
        event = events.record(device, "NOTE", "RECORDED", actor="x", evidence={"password": "hunter2", "note": "ok"}, head="")
        self.assertNotIn("hunter2", str(event.evidence))

    def test_verify_chain_detects_tampered_entry(self):
        device = L.register().device
        events.record(device, "NOTE", "RECORDED", actor="x", head="")
        with connection.cursor() as cursor:
            cursor.execute(f"UPDATE {models.DeviceLifecycleEvent._meta.db_table} SET actor = %s WHERE device_id = %s AND sequence = 1",
                           ["mallory", device.pk])
        self.assertFalse(events.verify_chain(device))

    def test_audit_maps_refusals_and_known_actions(self):
        self.assertEqual(events.audit("ADOPT", "ADVANCED", actor="x", object_id="DEV-1", summary="s").event_type, "DEVICE_ADOPTED")
        self.assertEqual(events.audit("ADOPT", "REFUSED", actor="x", object_id="DEV-1", summary="s").event_type, "DEVICE_LIFECYCLE_REFUSED")
        self.assertEqual(events.audit("OTHER", "RECORDED", actor="x", object_id="DEV-1", summary="s").event_type, "DEVICE_LIFECYCLE_CHANGED")

    def test_audit_refusal_without_metadata_records_action_only(self):
        self.assertEqual(events.audit("X", "REFUSED", actor="x", object_id="", summary="").metadata, {"action": "X"})

    def test_repository_head_returns_sha_or_empty_when_git_fails(self):
        self.assertIn(len(events.repository_head()), (0, 40))
        with mock.patch.object(events.subprocess, "run", side_effect=OSError("no git")):
            self.assertEqual(events.repository_head(), "")

    def test_new_correlation_id_returns_uuid(self):
        self.assertEqual(len(events.new_correlation_id()), 36)
