"""Authenticated version / identity observations: authentication, provenance, replay, staleness, mismatch, independence, exclusion."""

from __future__ import annotations

import json
from datetime import timedelta

from django.db import IntegrityError
from django.test import TestCase
from django.utils import timezone

from core import models
from core.services.devices import lifecycle, observations
from core.tests.helpers import lifecycle as L

KEY = b"k" * 40
SOURCES = {"collector-1": {"key": KEY, "platforms": ()}}
HOST_KEY = L.HOST_KEY
EOS_OUT = json.dumps({"mfgName": "Arista", "modelName": "cEOSLab", "version": "4.36.2F", "serialNumber": "SN-S1-1",
                      "systemMacAddress": "00:1c:73:aa:bb:01"})
FRR_OUT = "FRRouting 8.4.4 (R3) on Linux(6.8.0).\nCopyright 1996-2005 Kunihiro Ishiguro, et al.\n"
IOSXE_OUT = "Cisco IOS XE Software, Version 17.06.01a\nProcessor board ID 9ABCDEF1234\n"


def envelope(device="S1", *, output=EOS_OUT, command="show version | json", when=None, nonce="nonce-0001", host_key=HOST_KEY,
             ref="gateway:ev-1", key=KEY, source="collector-1"):
    env = {"source_id": source, "nonce": nonce, "command": command, "output": output, "host_key": host_key, "evidence_ref": ref,
           "observed_at": (when or timezone.now()).isoformat()}
    env["signature"] = observations.sign(key, device, env)
    return env


class IngestTests(TestCase):
    def setUp(self):
        self.device = L.adopt("S1").device

    def ingest(self, env=None, **kw):
        return observations.ingest("S1", envelope() if env is None else env, sources=SOURCES, **kw)

    def test_accepts_and_persists_provenance(self):
        res = self.ingest()
        self.assertTrue(res.ok, res.codes)
        row = res.record
        self.assertEqual((row.version, row.platform, row.source_id, row.host_key), ("4.36.2F", "arista_ceos", "collector-1", HOST_KEY))
        self.assertEqual(row.evidence_ref, "gateway:ev-1")
        self.assertEqual(len(row.raw_digest), 64)
        self.assertEqual(row.identity_observation.source, models.ObservationSource.AUTHENTICATED_SESSION)
        self.assertEqual(row.identity_observation.recorded_by, "source:collector-1")
        self.assertEqual(row.serial, "SN-S1-1")

    def test_ingest_never_verifies_or_admits(self):
        self.ingest()
        d = models.ManagedDevice.objects.get(pk=self.device.pk)
        self.assertEqual(d.identity_state, models.IdentityVerificationState.UNVERIFIED)
        self.assertEqual(d.admission_state, self.device.admission_state)
        self.assertEqual(d.verified_host_key, "")

    def test_other_platform_parsers(self):
        frr = L.adopt("R3", role="router").device
        res = observations.ingest("R3", envelope("R3", output=FRR_OUT, command="vtysh -c 'show version'", nonce="nonce-frr1"), sources=SOURCES)
        self.assertTrue(res.ok, res.codes)
        self.assertEqual((res.record.version, res.record.device_id), ("8.4.4", frr.pk))

    def test_iosxe_parser(self):
        spec = observations.SPECS[models.Platform.CISCO_C8000V_IOSXE]
        self.assertEqual(spec.parse(IOSXE_OUT)["version"], "17.06.01a")
        self.assertIsNone(spec.parse("garbage"))

    def test_unknown_source_and_bad_signature_write_nothing(self):
        for env, code in ((envelope(source="rogue", key=b"r" * 40), "SOURCE_UNTRUSTED"),
                          (envelope(key=b"x" * 40), "SIGNATURE_INVALID")):
            self.assertEqual(self.ingest(env).codes, [code])
        tampered = envelope()
        tampered["output"] = EOS_OUT.replace("4.36.2F", "4.99.9F")
        self.assertEqual(self.ingest(tampered).codes, ["SIGNATURE_INVALID"])
        self.assertEqual(models.DeviceVersionObservation.objects.count(), 0)
        self.assertFalse(models.DeviceObservation.objects.filter(device=self.device).exists())

    def test_signature_is_bound_to_device_and_command(self):
        L.adopt("S2")
        self.assertEqual(observations.ingest("S2", envelope("S1"), sources=SOURCES).codes, ["SIGNATURE_INVALID"])
        self.assertEqual(self.ingest(envelope(command="show version")).codes, ["COMMAND_MISMATCH"])

    def test_malformed_envelope(self):
        self.assertEqual(observations.ingest('S1', None, sources=SOURCES).codes, ['ENVELOPE_INVALID'])
        for bad in ({}, {**envelope(), "nonce": "x"}, {**envelope(), "output": ""}, {**envelope(), "observed_at": "yesterday"}):
            self.assertEqual(self.ingest(bad).codes, ["ENVELOPE_INVALID"])
        self.assertEqual(self.ingest(envelope(host_key="MD5:aa")).codes, ["ENVELOPE_INVALID"])

    def test_unparseable_output_and_wrong_vendor(self):
        self.assertEqual(self.ingest(envelope(output="not json")).codes, ["PARSE_FAILED"])
        self.assertEqual(self.ingest(envelope(output=json.dumps({"mfgName": "Other", "version": "1.2.3"}))).codes, ["PARSE_FAILED"])
        self.assertEqual(self.ingest(envelope(output=EOS_OUT.replace("4.36.2F", "latest"))).codes, ["PARSE_FAILED"])

    def test_stale_and_future(self):
        now = timezone.now()
        self.assertEqual(self.ingest(envelope(when=now - timedelta(hours=3))).codes, ["OBSERVATION_STALE"])
        self.assertEqual(self.ingest(envelope(when=now + timedelta(hours=1))).codes, ["OBSERVATION_FUTURE"])

    def test_replay_nonce_refresh_unchanged_output_and_out_of_order(self):
        now = timezone.now()
        self.assertTrue(self.ingest(envelope(when=now - timedelta(minutes=5))).ok)
        self.assertEqual(self.ingest(envelope(when=now - timedelta(minutes=5))).codes, ["REPLAY"])
        self.assertTrue(self.ingest(envelope(when=now - timedelta(minutes=4), nonce="nonce-0002")).ok)  # fresh signed session, unchanged version
        older = EOS_OUT.replace("SN-S1-1", "SN-S1-1 ")
        self.assertEqual(self.ingest(envelope(output=older, when=now - timedelta(minutes=9), nonce="nonce-0003")).codes,
                         ["OBSERVATION_OUT_OF_ORDER"])
        self.assertEqual(models.DeviceVersionObservation.objects.count(), 2)

    def test_identity_mismatch_rejected_and_recorded_as_denial(self):
        dev = L.register("NEW1", serial="SN-NEW1", mac=L.MAC)
        out = json.dumps({"mfgName": "Arista", "version": "4.36.2F", "serialNumber": "SN-OTHER", "systemMacAddress": L.MAC})
        res = observations.ingest("NEW1", envelope("NEW1", output=out, nonce="nonce-new1"), sources=SOURCES)
        self.assertEqual(res.codes, ["IDENTITY_MISMATCH"])
        self.assertFalse(models.DeviceVersionObservation.objects.exists())
        self.assertEqual(models.ManagedDevice.objects.get(pk=dev.device.pk).identity_state, models.IdentityVerificationState.MISMATCH)

    def test_excluded_unknown_and_unregistered_devices(self):
        self.assertEqual(observations.ingest("R5", envelope("R5"), sources=SOURCES).codes, ["DEVICE_EXCLUDED"])
        self.assertEqual(observations.ingest("NOPE", envelope("NOPE"), sources=SOURCES).codes, ["DEVICE_UNKNOWN"])
        self.assertFalse(models.ManagedDevice.objects.filter(name="R5").exists())

    def test_source_platform_restriction(self):
        src = {"collector-1": {"key": KEY, "platforms": ("ubuntu_frr",)}}
        self.assertEqual(observations.ingest("S1", envelope(), sources=src).codes, ["SOURCE_NOT_ALLOWED"])

    def test_unsupported_platform(self):
        d = L.register("SRL1", platform=models.Platform.NOKIA_SRLINUX, serial="SN-SRL", mac="00:1c:73:00:00:09")
        self.assertEqual(observations.ingest("SRL1", envelope("SRL1", nonce="nonce-srl1"), sources=SOURCES).codes, ["PLATFORM_UNSUPPORTED"])
        self.assertTrue(d.ok)

    def test_reverify_against_retained_raw(self):
        row = self.ingest().record
        self.assertTrue(observations.reverify(row, EOS_OUT, sources=SOURCES))
        self.assertFalse(observations.reverify(row, EOS_OUT.replace("4.36.2F", "4.30.0F"), sources=SOURCES))
        self.assertFalse(observations.reverify(row, EOS_OUT, sources={"collector-1": {"key": b"z" * 40, "platforms": ()}}))

    def test_rows_are_append_only(self):
        row = self.ingest().record
        row.version = "9.9.9"
        with self.assertRaises(ValueError):
            row.save()
        with self.assertRaises(ValueError):
            row.delete()
        with self.assertRaises(ValueError):
            models.DeviceVersionObservation.objects.update(version="1.1.1")

    def test_db_uniqueness_backstops_replay(self):
        row = self.ingest().record
        with self.assertRaises(IntegrityError):
            models.DeviceVersionObservation.objects.create(
                device=row.device, platform=row.platform, version="4.36.2F", source_id=row.source_id, nonce=row.nonce, command=row.command,
                raw_digest="a" * 64, signature="b" * 64, host_key=HOST_KEY, identity_observation=row.identity_observation, observed_at=timezone.now())


class IndependentApprovalAndCurrentTests(TestCase):
    def setUp(self):
        self.device = L.adopt("S1").device
        self.row = observations.ingest("S1", envelope(), sources=SOURCES).record

    def verify(self, actor):
        return lifecycle.verify_identity(models.ManagedDevice.objects.get(pk=self.device.pk), self.row.identity_observation_id, actor=actor)

    def test_unverified_identity_yields_no_authoritative_version(self):
        info = observations.current("S1")
        self.assertEqual((info["version"], info["usable"], info["reason"]), ("4.36.2F", False, "IDENTITY_NOT_VERIFIED"))
        self.assertIsNone(observations.observed_version("S1"))

    def test_collector_and_automation_cannot_self_approve(self):
        for actor in ("source:collector-1", "SOURCE:collector-1", "system:anything"):
            res = self.verify(actor)
            self.assertFalse(res.ok)
            self.assertEqual(res.codes, ["ACTOR_NOT_AUTHORIZED"])
        self.assertEqual(models.ManagedDevice.objects.get(pk=self.device.pk).identity_state, models.IdentityVerificationState.UNVERIFIED)

    def test_independent_operator_verifies_then_version_is_authoritative(self):
        res = self.verify("arthur")
        self.assertTrue(res.ok, res.codes)
        self.assertEqual(observations.observed_version("S1"), "4.36.2F")
        info = observations.current("S1")
        self.assertTrue(info["usable"] and info["fresh"])
        self.assertEqual((info["source_id"], info["raw_digest"], info["evidence_ref"]), ("collector-1", self.row.raw_digest, "gateway:ev-1"))

    def test_observed_version_is_database_read_only(self):
        self.verify("arthur")
        before = (models.DeviceVersionObservation.objects.count(), models.DeviceLifecycleEvent.objects.count(), models.AuditEvent.objects.count())
        with self.assertNumQueries(3):
            observations.observed_version("S1")
        after = (models.DeviceVersionObservation.objects.count(), models.DeviceLifecycleEvent.objects.count(), models.AuditEvent.objects.count())
        self.assertEqual(before, after)

    def test_stale_version_is_not_current(self):
        self.verify("arthur")
        later = timezone.now() + timedelta(days=2)
        self.assertEqual(observations.current("S1", now=later)["reason"], "STALE")

    def test_contradicting_later_identity_invalidates_version(self):
        self.verify("arthur")
        lifecycle.record_observation(models.ManagedDevice.objects.get(pk=self.device.pk), kind=models.ObservationKind.IDENTITY,
                                     source=models.ObservationSource.AUTHENTICATED_SESSION, actor="source:collector-1",
                                     claims={"host_key": "SHA256:" + "B" * 43}, observed_at=timezone.now() + timedelta(seconds=5))
        self.assertIsNone(observations.observed_version("S1"))
        # the contradicting authenticated observation also moves the device to MISMATCH, which is reported first
        self.assertIn(observations.current("S1")["reason"], ("IDENTITY_NOT_VERIFIED", "IDENTITY_CONTRADICTED"))

    def test_unknown_device_and_no_observation(self):
        self.assertEqual(observations.current("NOPE")["reason"], "NO_DEVICE")
        L.adopt("S2")
        self.assertEqual(observations.current("S2")["reason"], "NO_OBSERVATION")
        self.assertIsNone(observations.observed_version("S2"))


class ProviderIntegrationTests(TestCase):
    def test_real_observation_provider_requires_independent_verification(self):
        from core.services.troubleshooting.adapters import nmas_providers
        from core.services.troubleshooting import qualification
        device = L.adopt("S1").device
        result = observations.ingest("S1", envelope(), sources=SOURCES)
        self.assertTrue(result.ok, result.codes)
        self.assertIsNone(nmas_providers.version("S1"))
        approved = lifecycle.verify_identity(device, result.record.identity_observation_id, actor="arthur")
        self.assertTrue(approved.ok, approved.codes)
        self.assertEqual(nmas_providers.version("S1"), "4.36.2F")
        rows = {r["device"]: r for r in qualification.device_matrix(dict(nmas_providers.RECOMMENDED_BINDING))["devices"]}
        self.assertEqual(rows["S1"]["observed_version"], "4.36.2F")
        self.assertEqual(rows["S1"]["collector"]["status"], "BASELINE")
        self.assertEqual(rows["R5"]["classification"], "EXCLUDED")
