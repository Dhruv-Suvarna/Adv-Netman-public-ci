"""Broker-backed observation connection factory: factory -> provider -> collector, fully mocked (no network, no credentials)."""

from __future__ import annotations

from types import SimpleNamespace

from django.test import TestCase
from netmiko.exceptions import NetmikoAuthenticationException

from core.services.devices import observation_collector as oc, observation_connections as oconn, observation_sessions as os_
from core.services.execution.executors.base import ExecutorError
from core.services.management import linux_ssh, probes, ssh_transport
from core.services.management import resolve as mr
from core.tests.helpers import lifecycle as L
from core.tests.test_device_observations import EOS_OUT, FRR_OUT
from core.tests.test_observation_collector import DOC as BASE_DOC, SOURCES, Sink


class Key:
    def __init__(self, blob=b"presented-key"):
        self.blob = blob

    def asbytes(self):
        return self.blob


PIN = probes.fingerprint(Key())
OTHER = probes.fingerprint(Key(b"other"))


def doc(pin=PIN):
    nd = {name: dict(entry) for name, entry in BASE_DOC["network_devices"].items()}
    if pin:
        nd["S1"]["ssh_host_key"] = pin
        nd["R3"]["ssh_host_key"] = pin
    return {**BASE_DOC, "network_devices": nd}


class FakeNetmiko:
    def __init__(self, key=None, output=EOS_OUT):
        transport = SimpleNamespace(get_remote_server_key=lambda: key or Key())
        self.remote_conn_pre = SimpleNamespace(get_transport=lambda: transport)
        self.output, self.sent, self.disconnected = output, [], False

    def send_command(self, command):
        self.sent.append(command)
        return self.output

    def disconnect(self):
        self.disconnected = True


class FakeLinux:
    def __init__(self, host_key=PIN, output=FRR_OUT):
        self.host_key, self.host_key_pinned, self.output = host_key, bool(host_key), output
        self.argv, self.closed = [], False

    def run(self, argv, timeout):
        self.argv.append(list(argv))
        return 0, self.output

    def close(self):
        self.closed = True


def live(address="192.168.200.11", source=mr.LEGACY, path_id="", port=22, keyed=True):
    def fn(name, purpose="READ", platform=""):
        cand = {"username": "svc", "password": "", "ssh_auth": {"pkey": object()} if keyed else {}}
        return {"device_name": name, "address": address, "management": {"source": source, "path_id": path_id, "port": port},
                "auth_candidates": (cand, dict(cand))}
    return fn


class Base(TestCase):
    def build(self, document=None, **kw):
        self.doc = document or doc()
        authorizer = kw.pop("_authorizer", None)
        self.factory = oconn.connection_factory(document=self.doc, **kw)
        self.provider = os_.session_provider(self.factory, "auth-1", document=self.doc,
                                             endpoint_resolver=kw.get("endpoint_resolver"),
                                             path_authorizer=authorizer)
        return self.provider

    def collect(self, name):
        return oc.collect(name, source_id="collector-1", sources=SOURCES, session_provider=self.provider,
                          evidence_sink=Sink(), document=self.doc)


class CeosTests(Base):
    def setUp(self):
        L.adopt("S1")
        self.conn = FakeNetmiko()
        self.calls = []

        def connect(target, auth, timeout):
            self.calls.append(target)
            return self.conn
        self.connect = connect

    def test_legacy_pinned_end_to_end(self):
        self.build(live_target=live(), eos_connect=self.connect)
        res = self.collect("S1")
        self.assertTrue(res.ok, res.codes)
        self.assertEqual((res.record.host_key, res.record.version), (PIN, "4.36.2F"))
        self.assertEqual(self.calls[0]["pinned_host_key"], PIN)
        self.assertEqual(self.conn.sent, ["show version | json"])
        self.assertTrue(self.conn.disconnected)

    def test_approved_path_end_to_end(self):
        ep = lambda name, legacy_address="", purpose="READ": mr.Endpoint(mr.PATH, address="192.168.200.11", path_id="MPATH-1")
        path = SimpleNamespace(expected_host_key=PIN, endpoint_address="192.168.200.11")
        self.build(live_target=live(source=mr.PATH, path_id="MPATH-1"), eos_connect=self.connect, endpoint_resolver=ep,
                   active_path=lambda t: path, _authorizer=lambda *a: path)
        res = self.collect("S1")
        self.assertTrue(res.ok, res.codes)
        self.assertNotIn("pinned_host_key", self.calls[0])
        self.assertEqual(res.record.host_key, PIN)

    def test_path_pin_changed_is_refused(self):
        ep = lambda name, legacy_address="", purpose="READ": mr.Endpoint(mr.PATH, address="192.168.200.11", path_id="MPATH-1")
        path = SimpleNamespace(expected_host_key=OTHER)
        self.build(live_target=live(source=mr.PATH, path_id="MPATH-1"), eos_connect=self.connect, endpoint_resolver=ep,
                   active_path=lambda t: path, _authorizer=lambda *a: SimpleNamespace(expected_host_key=PIN))
        self.assertFalse(self.collect("S1").ok)
        self.assertEqual((self.factory.last_error, self.calls), ("PIN_CHANGED", []))

    def test_endpoint_changed_between_provider_and_connect(self):
        self.build(live_target=live(), eos_connect=self.connect,
                   endpoint_resolver=lambda *a, **k: mr.Endpoint(mr.LEGACY, address="192.168.200.11"))
        self.factory._endpoint = lambda *a, **k: mr.Endpoint(mr.LEGACY, address="192.168.200.55")
        res = self.collect("S1")
        self.assertEqual((res.codes, self.factory.last_error, self.calls), (["SESSION_UNAVAILABLE"], "ENDPOINT_CHANGED", []))
        for ep in (mr.Endpoint(mr.LEGACY, address="192.168.200.11", port=2222), mr.Endpoint(mr.PATH, address="192.168.200.11", path_id="X"),
                   mr.Endpoint(mr.BLOCKED)):
            self.factory._endpoint = lambda *a, ep=ep, **k: ep
            self.assertFalse(self.collect("S1").ok)
            self.assertIn(self.factory.last_error, ("ENDPOINT_CHANGED", "PATH_BLOCKED"))
        self.assertEqual(self.calls, [])

    def test_live_target_endpoint_change_refused(self):
        self.build(live_target=live(address="192.168.200.12"), eos_connect=self.connect)
        self.assertFalse(self.collect("S1").ok)
        self.assertEqual((self.factory.last_error, self.calls), ("ENDPOINT_CHANGED", []))

    def test_missing_pin_never_connects(self):
        self.build(document=doc(pin=""), live_target=live(), eos_connect=self.connect)
        self.assertFalse(self.collect("S1").ok)
        self.assertEqual((self.factory.last_error, self.calls), ("PIN_MISSING", []))

    def test_presented_key_mismatch_closes_and_refuses(self):
        self.conn = FakeNetmiko(key=Key(b"other"))
        self.build(live_target=live(), eos_connect=self.connect)
        self.assertFalse(self.collect("S1").ok)
        self.assertEqual(self.factory.last_error, "HOST_KEY_MISMATCH")
        self.assertTrue(self.conn.disconnected)

    def test_unobservable_key_refused(self):
        self.conn = FakeNetmiko()
        self.conn.remote_conn_pre = SimpleNamespace(get_transport=lambda: None)
        self.build(live_target=live(), eos_connect=self.connect)
        self.assertFalse(self.collect("S1").ok)
        self.assertEqual(self.factory.last_error, "HOST_KEY_UNOBSERVED")
        self.assertTrue(self.conn.disconnected)

    def test_failed_authentication_tries_candidates_and_is_sanitized(self):
        attempts = []

        def connect(target, auth, timeout):
            attempts.append(1)
            raise NetmikoAuthenticationException("bad password for admin@192.168.200.11")
        self.build(live_target=live(), eos_connect=connect)
        self.assertFalse(self.collect("S1").ok)
        self.assertEqual((self.factory.last_error, len(attempts)), ("AUTH_FAILED", 2))

    def test_transport_pin_refusal_and_generic_failure(self):
        for exc, code in ((ssh_transport.ManagedConnectionRejected("HOST_KEY_MISMATCH"), "HOST_KEY_MISMATCH"),
                          (OSError("secret"), "CONNECTION_FAILED")):
            def connect(target, auth, timeout, exc=exc):
                raise exc
            self.build(live_target=live(), eos_connect=connect)
            with self.assertRaises(oconn.ObservationConnectionError) as caught:
                self.factory(os_.ConnectionRequest("S1", "arista_ceos", "192.168.200.11", 22, "LEGACY", "", "a", PIN))
            self.assertEqual(caught.exception.code, code)
            self.assertNotIn("secret", str(caught.exception))

    def test_legacy_without_key_is_refused_without_connecting(self):
        self.build(live_target=live(keyed=False), eos_connect=self.connect)
        self.assertFalse(self.collect("S1").ok)
        self.assertEqual((self.factory.last_error, self.calls), ("KEY_AUTH_UNAVAILABLE", []))

    def test_wrapper_permits_only_version_command(self):
        self.build(live_target=live(), eos_connect=self.connect)
        wrapped = self.factory(os_.ConnectionRequest("S1", "arista_ceos", "192.168.200.11", 22, "LEGACY", "", "a", PIN))
        with self.assertRaises(PermissionError):
            wrapped.send_command("show running-config")
        wrapped.close()
        self.assertTrue(self.conn.disconnected)

    def test_invalid_requests(self):
        self.build(live_target=live(), eos_connect=self.connect)
        for kw in ({"read_only": False}, {"authorization_ref": " "}, {"platform": "cisco_c8000v_iosxe"}):
            base = dict(device="S1", platform="arista_ceos", address="192.168.200.11", port=22, source="LEGACY", path_id="",
                        authorization_ref="a", expected_host_key=PIN)
            with self.assertRaises(oconn.ObservationConnectionError):
                self.factory(os_.ConnectionRequest(**{**base, **kw}))
        self.assertEqual(self.calls, [])


class FrrTests(Base):
    def setUp(self):
        L.adopt("R3", role="router")
        self.session = FakeLinux()
        self.found = {"address": "192.168.200.13", "username": "svc", "ssh_key_ref": "runtime://x", "host_key": PIN, "port": 22}
        self.connected = []

        def connect(found, timeout):
            self.connected.append(found)
            return self.session
        self.connect = connect

    def test_end_to_end_argv_only(self):
        self.build(linux_target=lambda n, purpose: self.found, linux_connect=self.connect)
        res = self.collect("R3")
        self.assertTrue(res.ok, res.codes)
        self.assertEqual((res.record.host_key, res.record.version), (PIN, "8.4.4"))
        self.assertEqual(self.session.argv, [["vtysh", "-c", "show version"]])
        self.assertTrue(self.session.closed)

    def test_changes_and_missing_pin_refused(self):
        for found, document, code in (({**self.found, "address": "192.168.200.99"}, None, "ENDPOINT_CHANGED"),
                                      ({**self.found, "port": 2222}, None, "ENDPOINT_CHANGED"),
                                      ({**self.found, "host_key": OTHER}, None, "PIN_CHANGED"),
                                      (self.found, doc(pin=""), "PIN_MISSING")):
            self.build(document=document, linux_target=lambda n, purpose, f=found: f, linux_connect=self.connect)
            self.assertFalse(self.collect("R3").ok)
            self.assertEqual(self.factory.last_error, code)
        self.assertEqual(self.connected, [])

    def test_unverified_or_mismatched_session_is_closed(self):
        for session, code in ((FakeLinux(host_key=OTHER), "HOST_KEY_MISMATCH"), (FakeLinux(host_key=""), "HOST_KEY_UNOBSERVED")):
            self.session = session
            self.build(linux_target=lambda n, purpose: self.found, linux_connect=self.connect)
            self.assertFalse(self.collect("R3").ok)
            self.assertEqual(self.factory.last_error, code)
            self.assertTrue(session.closed)

    def test_auth_failure_and_path_source_unsupported(self):
        def connect(found, timeout):
            raise ExecutorError("AUTH_FAILED")
        self.build(linux_target=lambda n, purpose: self.found, linux_connect=connect)
        self.assertFalse(self.collect("R3").ok)
        self.assertEqual(self.factory.last_error, "AUTH_FAILED")
        with self.assertRaises(oconn.ObservationConnectionError) as caught:
            self.factory._frr(os_.ConnectionRequest("R3", "ubuntu_frr", "192.168.200.13", 22, "PATH", "P", "a", PIN), PIN)
        self.assertEqual(caught.exception.code, "ROUTE_UNSUPPORTED")


class LinuxSessionTests(TestCase):
    def test_host_key_provenance_only_when_observed(self):
        self.assertFalse(linux_ssh.LinuxSession(object(), "u").host_key_pinned)
        session = linux_ssh.LinuxSession(object(), "u", host_key=PIN)
        self.assertEqual((session.host_key, session.host_key_pinned), (PIN, True))


class SharedCredentialTests(Base):
    """SC01-SC04: an identity observation is never made with a fleet-shared credential (production resolvers still emit
    ``profile == FLEET_FALLBACK`` for inventory entries without their own reference; public resolvers emit no reference)."""

    def setUp(self):
        L.adopt("S1")
        self.calls = []

        def connect(target, auth, timeout):
            self.calls.append(target)
            return FakeNetmiko()
        self.connect = connect

    def _fleet(self, real):
        import dataclasses

        def resolve(name, **kw):
            target = real(name, **kw)
            if target is None:
                return None
            return dataclasses.replace(target, credential_refs={**target.credential_refs, "profile": "FLEET_FALLBACK"})
        return resolve

    def test_sc01_legacy_route_with_fleet_profile_is_refused_before_connecting(self):
        from unittest import mock
        self.build(live_target=live(), eos_connect=self.connect)
        with mock.patch.object(oconn.resolver, "resolve", self._fleet(oconn.resolver.resolve)):
            res = self.collect("S1")
        self.assertFalse(res.ok)
        self.assertEqual((self.factory.last_error, self.calls), ("SHARED_CREDENTIAL_REFUSED", []))

    def test_sc02_inventory_credential_path_with_fleet_profile_is_refused(self):
        from unittest import mock
        from core import models
        ep = lambda name, legacy_address="", purpose="READ": mr.Endpoint(mr.PATH, address="192.168.200.11", path_id="MPATH-1")
        path = SimpleNamespace(expected_host_key=PIN, endpoint_address="192.168.200.11",
                               credential_source=models.ManagementCredentialSource.INVENTORY, device_credential=None)
        self.build(live_target=live(source=mr.PATH, path_id="MPATH-1"), eos_connect=self.connect, endpoint_resolver=ep,
                   active_path=lambda t: path, _authorizer=lambda *a: path)
        with mock.patch.object(oconn.resolver, "resolve", self._fleet(oconn.resolver.resolve)):
            res = self.collect("S1")
        self.assertFalse(res.ok)
        self.assertEqual((self.factory.last_error, self.calls), ("SHARED_CREDENTIAL_REFUSED", []))

    def test_sc03_path_bound_to_a_legacy_shared_account_is_refused(self):
        from core import models
        ep = lambda name, legacy_address="", purpose="READ": mr.Endpoint(mr.PATH, address="192.168.200.11", path_id="MPATH-1")
        shared = SimpleNamespace(account_kind=models.AccountKind.LEGACY_SHARED)
        path = SimpleNamespace(expected_host_key=PIN, endpoint_address="192.168.200.11",
                               credential_source=models.ManagementCredentialSource.DEVICE_CREDENTIAL, device_credential=shared)
        self.build(live_target=live(source=mr.PATH, path_id="MPATH-1"), eos_connect=self.connect, endpoint_resolver=ep,
                   active_path=lambda t: path, _authorizer=lambda *a: path)
        res = self.collect("S1")
        self.assertFalse(res.ok)
        self.assertEqual((self.factory.last_error, self.calls), ("SHARED_CREDENTIAL_REFUSED", []))

    def test_sc04_inventory_with_only_a_fleet_reference_never_connects_on_either_lineage(self):
        """Real resolver, no mock: an entry without its own reference under a document-level fleet reference."""
        fleet_doc = doc()
        fleet_doc["ceos_username"], fleet_doc["ceos_credential_ref"] = "admin", "runtime://device-credentials/ceos-admin-shared"
        fleet_doc["network_devices"]["S1"] = {k: v for k, v in fleet_doc["network_devices"]["S1"].items() if k != "credential_ref"}
        self.build(fleet_doc, live_target=live(), eos_connect=self.connect)
        res = self.collect("S1")
        self.assertFalse(res.ok)
        self.assertEqual(self.calls, [])
        refs = oconn.resolver.resolve("S1", document=fleet_doc).credential_refs
        if refs.get("profile") == "FLEET_FALLBACK":            # production-lineage resolver
            self.assertEqual(self.factory.last_error, "SHARED_CREDENTIAL_REFUSED")
