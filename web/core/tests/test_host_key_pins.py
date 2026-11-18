"""Host-key pin evidence (HK01-HK11): pins are computed from independent device-side key material, never trusted as typed."""

from __future__ import annotations

import json
import tempfile
from datetime import timedelta
from io import StringIO
from pathlib import Path
from unittest import mock

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils import timezone

from core import models
from core.services.devices import host_key_pins as hk, resolver
from core.services.management import probes
from core.tests.helpers import lifecycle as L
from core.tests.test_observation_collector import DOC

REAL_RESOLVE = resolver.resolve


def openssh_public(private) -> str:
    return private.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()


ED = openssh_public(ed25519.Ed25519PrivateKey.generate())
EC = openssh_public(ec.generate_private_key(ec.SECP256R1()))


def paramiko_pin(line: str) -> str:
    """The pin NMAS's own handshake check (``probes.fingerprint``) computes for the same key loaded by paramiko."""
    kind, blob = line.split()[:2]
    return probes.fingerprint(paramiko.PKey.from_type_string(kind, __import__("base64").b64decode(blob)))


def evidence(**over):
    doc = {"schema": hk.SCHEMA, "device": "S1", "platform": "arista_ceos", "channel": "DEVICE_CONSOLE", "public_key": ED,
           "captured_by": "collector-c", "captured_at": timezone.now().isoformat(), "ticket": "CHG-4001"}
    doc.update(over)
    return doc


class PinEvidenceTests(TestCase):
    def setUp(self):
        p = mock.patch.object(hk.resolver, "resolve", lambda name, **kw: REAL_RESOLVE(name, document=DOC))
        p.start()
        self.addCleanup(p.stop)

    def check(self, doc=None, **kw):
        return hk.validate_evidence(doc or evidence(), enroller=kw.pop("enroller", "enroller-e"), inventory=DOC, **kw)

    # HK01
    def test_pin_is_computed_exactly_as_the_handshake_check_computes_it(self):
        for line in (ED, EC):
            pin, kind = hk.fingerprint(line)
            self.assertEqual(pin, paramiko_pin(line))
            self.assertRegex(pin, r"^SHA256:[A-Za-z0-9+/]{43}$")
            self.assertEqual(kind, line.split()[0])

    # HK02
    def test_valid_console_capture_is_accepted_with_its_computed_pin(self):
        verdict = self.check()
        self.assertTrue(verdict.ok, verdict.codes)
        self.assertEqual(verdict.pin, paramiko_pin(ED))
        self.assertEqual(len(verdict.evidence_digest), 64)
        self.assertFalse(verdict.registered["conflict"])

    # HK03
    def test_network_handshake_channels_are_never_accepted(self):
        for channel in ("SSH_KEYSCAN", "TOFU", "KNOWN_HOSTS", "ssh_handshake", "FIRST_CONTACT"):
            self.assertIn("CHANNEL_NOT_INDEPENDENT", self.check(evidence(channel=channel)).codes, channel)
        self.assertIn("CHANNEL_UNKNOWN", self.check(evidence(channel="EMAIL")).codes)

    # HK04
    def test_collector_and_enroller_must_differ(self):
        self.assertIn("ENROLLER_NOT_INDEPENDENT", self.check(enroller="Collector-C").codes)
        self.assertIn("ENROLLER_NOT_INDEPENDENT", self.check(enroller="").codes)
        self.assertIn("COLLECTOR_MISSING", self.check(evidence(captured_by="")).codes)

    # HK05
    def test_a_fingerprint_or_invented_string_is_not_key_material(self):
        pin = paramiko_pin(ED)
        for bad in (pin, "ssh-ed25519 " + pin.split(":", 1)[1], "ssh-ed25519 AAAA", "ssh-dss AAAAB3NzaC1kc3M=",
                    "ssh-rsa " + ED.split()[1]):           # type string inside the blob must match the declared type
            self.assertIn("PUBLIC_KEY_INVALID", self.check(evidence(public_key=bad)).codes, bad)

    # HK06
    def test_claimed_pin_is_compared_never_trusted(self):
        self.assertTrue(self.check(claimed_pin=paramiko_pin(ED)).ok)
        self.assertIn("CLAIMED_PIN_MISMATCH", self.check(claimed_pin=paramiko_pin(EC)).codes)
        self.assertIn("CLAIMED_PIN_INVALID", self.check(claimed_pin="SHA256:short").codes)

    # HK07
    def test_r5_unknown_and_platform_mismatch_are_refused(self):
        self.assertEqual(self.check(evidence(device="R5")).codes, ["DEVICE_EXCLUDED"])
        self.assertEqual(self.check(evidence(device="S9")).codes, ["DEVICE_UNKNOWN"])
        self.assertIn("PLATFORM_MISMATCH", self.check(evidence(platform="ubuntu_frr")).codes)
        self.assertTrue(self.check(evidence(device="R3", platform="ubuntu_frr", channel="CONTAINER_HOST_ADMIN")).ok)

    # HK08
    def test_stale_and_future_captures_are_refused(self):
        self.assertIn("EVIDENCE_STALE", self.check(evidence(captured_at=(timezone.now() - timedelta(days=8)).isoformat())).codes)
        self.assertIn("EVIDENCE_FUTURE", self.check(evidence(captured_at=(timezone.now() + timedelta(hours=1)).isoformat())).codes)
        self.assertIn("EVIDENCE_INVALID", self.check(evidence(captured_at="yesterday")).codes)
        self.assertEqual(self.check({"schema": "other"}).codes, ["EVIDENCE_INVALID"])

    # HK09
    def test_registered_pins_are_compared_and_conflicts_reported(self):
        device = L.adopt("S1").device
        other = paramiko_pin(EC)
        inv = {**DOC, "network_devices": {**DOC["network_devices"], "S1": {**DOC["network_devices"]["S1"], "ssh_host_key": other}}}
        report = hk.compare_registered("S1", paramiko_pin(ED), inventory=inv)
        self.assertEqual((report["inventory_ssh_host_key"], report["conflict"]), ("MISMATCH", True))
        self.assertEqual(report["verified_host_key"], "ABSENT")
        from core.services.devices import lifecycle
        recorded = lifecycle.record_observation(
            device, kind=models.ObservationKind.IDENTITY, source=models.ObservationSource.AUTHENTICATED_SESSION,
            actor="source:collector-1", actor_kind=lifecycle.AUTOMATION, claims={"host_key": paramiko_pin(ED)},
            observed_at=timezone.now())
        self.assertTrue(recorded.ok, recorded.codes)
        report = hk.compare_registered("S1", paramiko_pin(ED), inventory=DOC)
        self.assertEqual((report["latest_authenticated_observation"], report["conflict"]), ("MATCH", False))
        report = hk.compare_registered("S1", paramiko_pin(EC), inventory=DOC)
        self.assertEqual((report["latest_authenticated_observation"], report["conflict"]), ("MISMATCH", True))

    # HK10
    def test_validation_writes_nothing(self):
        L.adopt("S1")
        before = (models.ManagementPath.objects.count(), models.DeviceObservation.objects.count(),
                  models.DeviceLifecycleEvent.objects.count(), models.ManagedDevice.objects.get(name="S1").verified_host_key)
        self.check()
        after = (models.ManagementPath.objects.count(), models.DeviceObservation.objects.count(),
                 models.DeviceLifecycleEvent.objects.count(), models.ManagedDevice.objects.get(name="S1").verified_host_key)
        self.assertEqual(before, after)

    # HK11
    def test_command_reports_route_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            good, bad = Path(tmp, "good.json"), Path(tmp, "bad.json")
            good.write_text(json.dumps(evidence()))
            bad.write_text(json.dumps(evidence(channel="SSH_KEYSCAN")))
            with mock.patch("core.services.health.inventory.load_inventory", lambda: DOC), \
                    mock.patch.object(resolver, "resolve", lambda name, **kw: REAL_RESOLVE(name, document=DOC)):
                out = StringIO()
                call_command("host_key_pin_check", "--evidence", str(good), "--enroller", "enroller-e", "--json", stdout=out)
                report = json.loads(out.getvalue())
                self.assertEqual((report["ok"], report["pin"]), (True, paramiko_pin(ED)))
                self.assertIn("register a management path", report["enrollment_route"])
                with self.assertRaises(CommandError):
                    call_command("host_key_pin_check", "--evidence", str(bad), "--enroller", "enroller-e", stdout=StringIO())
