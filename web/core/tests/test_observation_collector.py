"""Observation collector bridge: governed capture through injected sessions; no approval or admission side effects."""

from __future__ import annotations

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from core import models
from core.services.devices import observation_collector as oc, observations
from core.tests.helpers import lifecycle as L
from core.tests.test_device_observations import EOS_OUT, FRR_OUT

KEY = b"k" * 40
SOURCES = {"collector-1": {"key": KEY, "platforms": ()}}
DOC = {"lab_name": "unit", "management": {"nmas_ipv4": "192.168.200.100/24"},
       "network_devices": {
           "S1": {"credential_ref": "runtime://s1", "monitoring": {"platform": "ceos", "address": "192.168.200.11"}},
           "R3": {"ssh_key_ref": "runtime://r3", "monitoring": {"platform": "linux", "address": "192.168.200.13"}},
           "R5": {"edge": True, "monitoring": {"platform": "ceos", "address": "auto"}},
           "DOCK": {"credential_ref": "runtime://d", "monitoring": {"platform": "ceos", "address": "172.20.20.9"}}}}
HK = L.HOST_KEY


class Session:
    def __init__(self, output=EOS_OUT, address="192.168.200.11", **attrs):
        self.output, self.address, self.sent, self.closed = output, address, [], False
        self.transport, self.read_only, self.authorization_ref, self.host_key_pinned, self.host_key = "SSH", True, "auth-1", True, HK
        self.__dict__.update(attrs)

    def execute(self, command):
        self.sent.append(command)
        if isinstance(self.output, Exception):
            raise self.output
        return self.output

    def close(self):
        self.closed = True


class Sink:
    def __init__(self, ref="evidence:1", fail=False):
        self.ref, self.fail, self.records = ref, fail, []

    def __call__(self, record):
        if self.fail:
            raise OSError("disk")
        self.records.append(record)
        return self.ref


class CollectorTests(TestCase):
    def setUp(self):
        self.s1 = L.adopt("S1").device
        self.session = Session()
        self.sink = Sink()

    def run_collect(self, name="S1", session="default", sink=None, **kw):
        session = self.session if session == "default" else session
        provider = (lambda target, address: session) if not callable(session) or hasattr(session, "execute") else session
        return oc.collect(name, source_id="collector-1", sources=kw.pop("sources", SOURCES), session_provider=provider,
                          evidence_sink=sink or self.sink, document=DOC, **kw)

    def test_ceos_capture_persists_with_provenance(self):
        res = self.run_collect()
        self.assertTrue(res.ok, res.codes)
        row = res.record
        self.assertEqual((row.version, row.host_key, row.evidence_ref, row.source_id), ("4.36.2F", HK, "evidence:1", "collector-1"))
        self.assertEqual(self.session.sent, ["show version | json"])
        self.assertTrue(self.session.closed)
        rec = self.sink.records[0]
        self.assertEqual((rec["output"], rec["host_key"], rec["authorization_ref"]), (EOS_OUT, HK, "auth-1"))
        self.assertTrue(observations.reverify(row, EOS_OUT, sources=SOURCES))

    def test_frr_capture_uses_vtysh_command(self):
        L.adopt("R3", role="router")
        session = Session(output=FRR_OUT, address="192.168.200.13")
        res = self.run_collect("R3", session)
        self.assertTrue(res.ok, res.codes)
        self.assertEqual((res.record.version, session.sent), ("8.4.4", ["vtysh -c 'show version'"]))

    def test_no_approval_side_effects(self):
        self.assertTrue(self.run_collect().ok)
        d = models.ManagedDevice.objects.get(pk=self.s1.pk)
        self.assertEqual(d.identity_state, models.IdentityVerificationState.UNVERIFIED)
        self.assertEqual(d.verified_host_key, "")
        self.assertEqual(d.admission_state, self.s1.admission_state)
        self.assertEqual(d.lifecycle_state, self.s1.lifecycle_state)
        self.assertIsNone(observations.observed_version("S1"))

    def refused(self, code, **kw):
        res = self.run_collect(**kw)
        self.assertEqual(res.codes[:1], [code], res.codes)
        self.assertFalse(res.ok)
        self.assertEqual(models.DeviceVersionObservation.objects.count(), 0)
        return res

    def test_prohibited_targets(self):
        self.refused("TARGET_NOT_MANAGEABLE", name="R5", session=Session())
        self.refused("TARGET_UNKNOWN", name="NOPE")
        # a Containerlab-range address is dropped by the resolver, leaving no management path
        L.adopt("DOCK")
        self.refused("NO_MANAGEMENT_PATH", name="DOCK")

    def test_unsupported_platform(self):
        doc = {**DOC, "network_devices": {"X": {"credential_ref": "runtime://x", "monitoring": {"platform": "srl", "address": "192.168.200.50"}}}}
        res = oc.collect("X", source_id="collector-1", sources=SOURCES, session_provider=lambda t, a: self.session,
                         evidence_sink=self.sink, document=doc)
        self.assertEqual(res.codes, ["PLATFORM_UNSUPPORTED"])
        self.assertEqual(self.session.sent, [])

    def test_unconfigured_source(self):
        self.refused("SOURCE_UNCONFIGURED", sources={})

    def test_session_provenance_requirements(self):
        cases = {"SESSION_NOT_SSH": {"transport": "DOCKER_EXEC_LAB_RUNTIME"}, "SESSION_ADDRESS_NOT_DECLARED": {"address": "10.9.9.9"},
                 "SESSION_NOT_READ_ONLY": {"read_only": False}, "SESSION_NOT_AUTHORIZED": {"authorization_ref": ""},
                 "HOST_KEY_NOT_PINNED": {"host_key_pinned": False}, "HOST_KEY_MISSING": {"host_key": ""}}
        for code, attrs in cases.items():
            session = Session(**attrs)
            self.refused(code, session=session)
            self.assertEqual(session.sent, [], code)
            self.assertTrue(session.closed)
        self.assertEqual(self.sink.records, [])

    def test_absent_session_and_failed_session(self):
        self.refused("SESSION_UNAVAILABLE", session=lambda t, a: None)

        def boom(t, a):
            raise RuntimeError("password=hunter2")
        self.refused("SESSION_UNAVAILABLE", session=boom)
        self.refused("SESSION_FAILED", session=Session(output=TimeoutError()))
        self.refused("OUTPUT_EMPTY", session=Session(output="  "))

    def test_garbage_output_is_parse_failure_from_ingest(self):
        res = self.run_collect(session=Session(output="not a version report"))
        self.assertEqual(res.codes, ["PARSE_FAILED"])

    def test_evidence_retention_required(self):
        self.refused("EVIDENCE_UNAVAILABLE", sink=Sink(fail=True))
        self.refused("EVIDENCE_UNAVAILABLE", sink=Sink(ref=""))

    def test_replay_of_nonce_is_refused(self):
        fixed = lambda: "nonce-fixed-01"  # noqa: E731
        first = self.run_collect(nonce_factory=fixed)
        self.assertTrue(first.ok, first.codes)
        again = self.run_collect(session=Session(), nonce_factory=fixed, now=timezone.now() + timedelta(seconds=5))
        self.assertEqual(again.codes, ["REPLAY"])
        self.assertEqual(models.DeviceVersionObservation.objects.count(), 1)

    def test_fresh_nonce_older_capture_is_out_of_order(self):
        self.assertTrue(self.run_collect().ok)
        res = self.run_collect(session=Session(), now=timezone.now() - timedelta(seconds=30))
        self.assertEqual(res.codes, ["OBSERVATION_OUT_OF_ORDER"])
