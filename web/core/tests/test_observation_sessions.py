"""Observation session provider: policy-selected endpoints, no fallback, version-command-only, host-key provenance."""

from __future__ import annotations

from django.test import TestCase

from core import models
from core.services.devices import observation_collector as oc, observation_sessions as os_, resolver
from core.services.management import resolve as mr
from core.tests.helpers import lifecycle as L
from core.tests.test_device_observations import EOS_OUT, FRR_OUT
from core.tests.test_observation_collector import DOC, KEY, SOURCES, Sink

HK = L.HOST_KEY


class Conn:
    def __init__(self, host_key=HK, pinned=True, output=EOS_OUT, status=0):
        self.host_key, self.host_key_pinned, self.output, self.status = host_key, pinned, output, status
        self.sent, self.argv, self.closed = [], [], False

    def send_command(self, command):
        self.sent.append(command)
        return self.output

    def run(self, argv, timeout):
        self.argv.append(list(argv))
        return self.status, self.output

    def close(self):
        self.closed = True


class Factory:
    def __init__(self, conn=None, fail=False):
        self.conn, self.fail, self.requests = conn or Conn(), fail, []

    def __call__(self, request):
        self.requests.append(request)
        if self.fail:
            raise OSError("secret-host")
        return self.conn


def legacy(address, source=mr.LEGACY, **kw):
    return lambda name, legacy_address="", purpose="READ": mr.Endpoint(source, address=address, **kw)


def blocked(name, legacy_address="", purpose="READ"):
    return mr.Endpoint(mr.BLOCKED)


class ProviderTests(TestCase):
    def target(self, name):
        return resolver.resolve(name, document=DOC)

    def provider(self, factory=None, endpoint=None, doc=DOC, **kw):
        self.factory = factory or Factory()
        return os_.session_provider(self.factory, "auth-1", document=doc, endpoint_resolver=endpoint, **kw)

    def test_legacy_real_resolver_and_exact_command(self):
        L.adopt("S1")
        p = self.provider()                                   # real management resolver: no registered path -> LEGACY
        s = p(self.target("S1"), "192.168.200.11")
        self.assertEqual((s.address, s.authorization_ref, s.host_key, s.host_key_pinned, s.read_only), ("192.168.200.11", "auth-1", HK, True, True))
        self.assertEqual(self.factory.requests[0].source, "LEGACY")
        self.assertEqual(s.execute("show version | json"), EOS_OUT)
        for bad in ("show running-config", "show version | json; reload", "configure terminal"):
            with self.assertRaises(os_.CommandNotPermitted):
                s.execute(bad)
        self.assertEqual(self.factory.conn.sent, ["show version | json"])
        s.close()
        self.assertTrue(self.factory.conn.closed)
        with self.assertRaises(os_.CommandNotPermitted):
            s.execute("show version | json")

    def test_governed_refusal_has_no_fallback(self):
        p = self.provider(endpoint=blocked)
        t = self.target("S1")
        self.assertIsNone(p(t, "192.168.200.11"))
        self.assertEqual(p.last_refusal, "PATH_BLOCKED")
        self.assertEqual(self.factory.requests, [])

    def test_requested_address_must_be_policy_endpoint(self):
        p = self.provider(endpoint=legacy("192.168.200.99", mr.PATH, path_id="P1"), path_authorizer=lambda *a: True)
        self.assertIsNone(p(self.target("S1"), "192.168.200.11"))
        self.assertEqual((p.last_refusal, self.factory.requests), ("ENDPOINT_NOT_REQUESTED", []))

    def test_prohibited_endpoints(self):
        for addr in ("172.20.20.9", "127.0.0.1", "169.254.1.1", "0.0.0.0"):
            p = self.provider(endpoint=legacy(addr))
            self.assertIsNone(p(self.target("S1"), addr), addr)
            self.assertEqual(p.last_refusal, "ENDPOINT_PROHIBITED")
        self.assertEqual(self.factory.requests, [])

    def test_approved_path_needs_authorizer_and_supported_platform(self):
        ep = legacy("192.168.200.11", mr.PATH, path_id="P1")
        p = self.provider(endpoint=ep, path_authorizer=lambda *a: False)
        self.assertIsNone(p(self.target("S1"), "192.168.200.11"))
        self.assertEqual(p.last_refusal, "PATH_NOT_AUTHORIZED")
        p = self.provider(endpoint=ep, path_authorizer=lambda *a: True)
        self.assertEqual(p(self.target("S1"), "192.168.200.11").evidence_refs, ("path:P1",))
        self.assertEqual(self.factory.requests[0].path_id, "P1")
        p = self.provider(endpoint=legacy("192.168.200.13", mr.PATH, path_id="P2"), path_authorizer=lambda *a: True)
        self.assertIsNone(p(self.target("R3"), "192.168.200.13"))
        self.assertEqual(p.last_refusal, "PATH_PLATFORM_UNSUPPORTED")

    def test_unregistered_path_is_not_authorized_by_real_guard(self):
        p = self.provider(endpoint=legacy("192.168.200.11", mr.PATH, path_id="NOPE"))
        self.assertIsNone(p(self.target("S1"), "192.168.200.11"))
        self.assertEqual(p.last_refusal, "PATH_NOT_AUTHORIZED")

    def test_unsupported_platform_and_missing_prerequisites(self):
        doc = {**DOC, "network_devices": {"X1": {"credential_ref": "runtime://x", "monitoring": {"platform": "cisco_c8000v_iosxe", "address": "192.168.200.21"}}}}
        p = self.provider(doc=doc)
        self.assertIsNone(p(resolver.resolve("X1", document=doc), "192.168.200.21"))
        self.assertEqual(p.last_refusal, "PLATFORM_UNSUPPORTED")
        for provider, code in ((os_.session_provider(Factory(), "  ", document=DOC), "AUTHORIZATION_MISSING"),
                               (os_.session_provider(None, "a", document=DOC), "CONNECTION_FACTORY_MISSING")):
            self.assertIsNone(provider(self.target("S1"), "192.168.200.11"))
            self.assertEqual(provider.last_refusal, code)

    def test_host_key_provenance_gaps_close_connection(self):
        for conn, code in ((Conn(host_key=""), "HOST_KEY_MISSING"), (Conn(host_key="junk"), "HOST_KEY_MISSING"),
                           (Conn(pinned=False), "HOST_KEY_NOT_PINNED")):
            p = self.provider(Factory(conn))
            self.assertIsNone(p(self.target("S1"), "192.168.200.11"))
            self.assertEqual(p.last_refusal, code)
            self.assertTrue(conn.closed)

    def test_inventory_pin_is_enforced_not_invented(self):
        doc = {**DOC, "network_devices": {**DOC["network_devices"], "S1": {**DOC["network_devices"]["S1"], "ssh_host_key": "SHA256:" + "B" * 43}}}
        p = self.provider(doc=doc)
        self.assertIsNone(p(resolver.resolve("S1", document=doc), "192.168.200.11"))
        self.assertEqual(p.last_refusal, "HOST_KEY_PIN_MISMATCH")
        self.assertEqual(self.factory.requests[0].expected_host_key, "SHA256:" + "B" * 43)
        self.assertTrue(self.factory.conn.closed)

    def test_factory_failure_is_sanitized(self):
        p = self.provider(Factory(fail=True))
        self.assertIsNone(p(self.target("S1"), "192.168.200.11"))
        self.assertEqual(p.last_refusal, "CONNECTION_FAILED")

    def test_frr_uses_argv_only_version_query(self):
        L.adopt("R3", role="router")
        conn = Conn(output=FRR_OUT)
        p = self.provider(Factory(conn))
        s = p(self.target("R3"), "192.168.200.13")
        self.assertEqual(s.execute("vtysh -c 'show version'"), FRR_OUT)
        self.assertEqual(conn.argv, [["vtysh", "-c", "show version"]])
        self.assertEqual(conn.sent, [])
        with self.assertRaises(os_.CommandNotPermitted):
            s.execute("vtysh -c 'configure terminal'")
        conn.status = 1
        with self.assertRaises(Exception):
            s.execute("vtysh -c 'show version'")

    def test_connection_without_interface_refused(self):
        class Bare:
            host_key, host_key_pinned = HK, True
        p = self.provider(Factory(Bare()))
        self.assertIsNone(p(self.target("S1"), "192.168.200.11"))
        self.assertEqual(p.last_refusal, "CONNECTION_UNUSABLE")

    def test_end_to_end_collect_no_admission_side_effects(self):
        device = L.adopt("S1").device
        paths_before = models.ManagementPath.objects.count()
        p = self.provider()
        res = oc.collect("S1", source_id="collector-1", sources=SOURCES, session_provider=p, evidence_sink=Sink(), document=DOC)
        self.assertTrue(res.ok, res.codes)
        self.assertEqual(res.record.host_key, HK)
        self.assertTrue(self.factory.conn.closed)
        self.assertEqual(self.factory.conn.sent, ["show version | json"])
        device.refresh_from_db()
        self.assertEqual(device.identity_state, models.IdentityVerificationState.UNVERIFIED)
        self.assertEqual(device.verified_host_key, "")
        self.assertEqual(models.ManagementPath.objects.count(), paths_before)

    def test_collect_with_blocked_governed_path_never_connects(self):
        L.adopt("S1")
        p = self.provider(endpoint=blocked)
        res = oc.collect("S1", source_id="collector-1", sources=SOURCES, session_provider=p, evidence_sink=Sink(), document=DOC)
        self.assertFalse(res.ok)
        self.assertEqual(res.codes, ["SESSION_UNAVAILABLE"])
        self.assertEqual(self.factory.requests, [])
