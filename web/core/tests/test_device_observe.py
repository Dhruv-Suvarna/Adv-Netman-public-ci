"""device_observe command: explicit prerequisites, refusal before connecting, durable evidence, no approval side effects."""

from __future__ import annotations

import tempfile
from io import StringIO
from pathlib import Path
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from core import models
from core.management.commands import device_observe as cmd
from core.services.devices import observation_authorizations as authz, observation_evidence as ev, observations, resolver
from core.tests.helpers import lifecycle as L
from core.tests.test_device_observations import EOS_OUT
from core.tests.test_observation_collector import DOC, Session

SRC = {"collector-1": {"key": b"k" * 40, "platforms": ()}}
REAL_RESOLVE = resolver.resolve
REAL_SINK = ev.LocalEvidenceSink


def account(username, *roles):
    user = get_user_model().objects.create_user(username=username, password="unused-test-password")
    for role in roles:
        user.groups.add(Group.objects.get(name=role))
    return user


class DeviceObserveTests(TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name).resolve()
        self.dir = self.root / "ev"
        self.dir.mkdir(mode=0o700)
        self.s1 = L.adopt("S1").device
        account("approver-a", "NMAS Approver")
        account("operator-o", "NMAS Executor")
        granted = authz.grant(devices=["S1"], commands=["nos-version"], ttl_seconds=3600, approver="approver-a",
                              requested_by="operator-o", ticket="CHG-1001", max_observations=4, document=DOC)
        assert granted.ok, granted.codes
        self.auth = granted.authorization
        self.ref = authz.reference(self.auth)
        self.session = Session()
        self.factory_calls = 0
        self.provider_calls = []
        test = self

        def provider(factory, auth, **kw):
            test.provider_calls.append(auth)
            test.session.authorization_ref = auth        # the session carries exactly what the command handed the provider
            return lambda target, address: test.session

        def build(_self):
            test.factory_calls += 1
            return object()

        patches = [mock.patch.object(cmd.observations, "trusted_sources", lambda: dict(SRC)),
                   mock.patch.object(cmd.resolver, "resolve", lambda name, **kw: REAL_RESOLVE(name, document=DOC)),
                   mock.patch.object(authz.resolver, "resolve", lambda name, **kw: REAL_RESOLVE(name, document=DOC)),
                   mock.patch.object(cmd.observation_sessions, "session_provider", provider),
                   mock.patch.object(cmd.Command, "build_connection_factory", build),
                   mock.patch.object(cmd.observation_evidence, "LocalEvidenceSink",
                                     lambda d: REAL_SINK(d, approved_roots=[self.root]))]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def run_cmd(self, **over):
        args = {"device": "S1", "source": "collector-1", "authorization_ref": self.ref, "operator": "operator-o",
                "evidence_dir": str(self.dir), **over}
        out = StringIO()
        call_command("device_observe", stdout=out, **args)
        return out.getvalue()

    def assert_refused_without_connecting(self, **over):
        with self.assertRaises(CommandError):
            self.run_cmd(**over)
        self.assertEqual((self.factory_calls, self.session.sent), (0, []))
        self.assertEqual(models.DeviceVersionObservation.objects.count(), 0)

    def test_success_retains_verifiable_evidence_and_ingests(self):
        out = self.run_cmd()
        row = models.DeviceVersionObservation.objects.get()
        self.assertEqual(row.version, "4.36.2F")
        self.assertTrue(row.evidence_ref.startswith("local-unattested:"))
        record = ev.verify_reference(self.dir, row.evidence_ref, [self.root])
        self.assertEqual((record["output"], record["authorization_ref"]), (EOS_OUT, self.ref))
        self.assertEqual(self.provider_calls, [self.ref])
        self.assertTrue(observations.reverify(row, record["output"], sources=SRC))
        self.assertIn("NOT admitted", out)
        self.assertNotIn("kkkk", out)

    def test_no_approval_side_effects(self):
        self.run_cmd()
        d = models.ManagedDevice.objects.get(pk=self.s1.pk)
        self.assertEqual(d.identity_state, models.IdentityVerificationState.UNVERIFIED)
        self.assertEqual((d.verified_host_key, d.admission_state, d.lifecycle_state),
                         ("", self.s1.admission_state, self.s1.lifecycle_state))

    def test_write_failure_prevents_ingest(self):
        with mock.patch("os.fsync", side_effect=OSError("disk")), self.assertRaises(CommandError) as cm:
            self.run_cmd()
        self.assertIn("EVIDENCE_UNAVAILABLE", str(cm.exception))
        self.assertEqual(models.DeviceVersionObservation.objects.count(), 0)
        self.assertEqual(list(self.dir.iterdir()), [])

    def test_missing_arguments_refused(self):
        for key in ("device", "source", "authorization_ref", "operator", "evidence_dir"):
            args = {"device": "S1", "source": "collector-1", "authorization_ref": self.ref, "operator": "operator-o",
                    "evidence_dir": str(self.dir)}
            args.pop(key)
            with self.subTest(key), self.assertRaises(CommandError):
                call_command("device_observe", **args)
        self.assertEqual(self.factory_calls, 0)

    def test_blank_authorization_and_unknown_source_refused(self):
        self.assert_refused_without_connecting(authorization_ref="  ")
        self.assert_refused_without_connecting(source="other")

    def test_free_form_label_is_no_longer_an_authorization(self):
        """The pre-0039 free-form ``--authorization-ref auth-1`` label is refused before any connection."""
        self.assert_refused_without_connecting(authorization_ref="auth-1")
        self.assert_refused_without_connecting(authorization_ref="CHG-1001|devices=S1|expires=2099-01-01")

    def test_authorization_scope_is_enforced_before_connecting(self):
        other = authz.grant(devices=["R3"], commands=["nos-version"], ttl_seconds=3600, approver="approver-a",
                            requested_by="operator-o", ticket="CHG-1002", document=DOC).authorization
        self.assert_refused_without_connecting(authorization_ref=authz.reference(other))           # device out of scope
        self.assert_refused_without_connecting(operator="approver-a")                              # approver may not run it
        self.assert_refused_without_connecting(operator="nobody")                                  # not an NMAS account
        self.assert_refused_without_connecting(authorization_ref=f"{self.auth.auth_id}#sha256={'0' * 64}")   # digest mismatch
        authz.revoke(self.auth, actor="approver-a", reason="window closed")
        self.assert_refused_without_connecting()

    def test_expiry_between_connection_and_ingest_prevents_ingest(self):
        with mock.patch.object(cmd.observation_authorizations, "still_valid",
                               side_effect=["", "AUTHORIZATION_EXPIRED"]), self.assertRaises(CommandError) as cm:
            self.run_cmd()
        self.assertIn("AUTHORIZATION_EXPIRED", str(cm.exception))
        self.assertEqual(models.DeviceVersionObservation.objects.count(), 0)
        use = models.ObservationAuthorizationUse.objects.get()
        self.assertEqual((use.state, use.outcome_codes), ("REFUSED", ["AUTHORIZATION_EXPIRED"]))

    def test_accepted_use_links_the_observation_and_budget_is_enforced(self):
        self.auth = authz.grant(devices=["S1"], commands=["nos-version"], ttl_seconds=3600, approver="approver-a",
                                requested_by="operator-o", ticket="CHG-1003", max_observations=1, document=DOC).authorization
        self.ref = authz.reference(self.auth)
        self.run_cmd()
        use = models.ObservationAuthorizationUse.objects.get(authorization=self.auth)
        row = models.DeviceVersionObservation.objects.get()
        self.assertEqual((use.state, use.version_observation_id, use.operator, use.command), ("ACCEPTED", row.pk, "operator-o", "nos-version"))
        self.factory_calls = 0
        self.session.sent = []
        with self.assertRaises(CommandError) as cm:
            self.run_cmd()
        self.assertIn("AUTHORIZATION_EXHAUSTED", str(cm.exception))
        self.assertEqual(self.factory_calls, 0)

    def test_bad_evidence_dir_refused(self):
        self.assert_refused_without_connecting(evidence_dir="relative")
        self.assert_refused_without_connecting(evidence_dir=str(self.root / "missing"))
        with mock.patch.object(cmd.observation_evidence, "LocalEvidenceSink", REAL_SINK):
            self.assert_refused_without_connecting()           # real approved roots: tmp dir is outside them

    def test_r5_and_unknown_refused_without_connecting(self):
        self.assert_refused_without_connecting(device="R5")
        self.assert_refused_without_connecting(device="NOPE")
        self.assertEqual(list(self.dir.iterdir()), [])
