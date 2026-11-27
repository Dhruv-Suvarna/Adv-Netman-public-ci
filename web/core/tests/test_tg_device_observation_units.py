"""Direct tests for the device-observation, host-key-pin and management-probe helpers and their evidence models.

Observation authorizations are exact-scope and digest-bound; a version observation is signed, device-bound and
re-verifiable; a session or connection performs only the version command over a pinned host key; and the evidence models
are append-only.  The SSH boundary (Netmiko / paramiko) is a fake: nothing connects to a device.
"""

from __future__ import annotations

import base64
import hashlib
import struct
import tempfile
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from core import models
from core.services.devices import host_key_pins as pins
from core.services.devices import observation_authorizations as authz
from core.services.devices import observation_collector as collector
from core.services.devices import observation_connections as conns
from core.services.devices import observation_evidence as evidence
from core.services.devices import observation_sessions as sessions
from core.services.devices import observations
from core.services.execution.executors.base import ExecutorError
from core.services.management import linux_ssh, paths, probes
from core.tests.test_device_observations import EOS_OUT, HOST_KEY, KEY, SOURCES, envelope
from core.tests import test_observation_authorizations as oa_tests
from core.tests.helpers import lifecycle as L


def ssh_key_line(key_type="ssh-ed25519", body=b"\x01" * 32):
    blob = struct.pack(">I", len(key_type)) + key_type.encode() + struct.pack(">I", len(body)) + body
    return f"{key_type} {base64.b64encode(blob).decode()} test@nmas", blob


class FakeKey:
    def __init__(self, raw: bytes):
        self.raw = raw

    def asbytes(self):
        return self.raw


def pin_of(raw: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


# ================================================================================================ authorizations
class AuthorizationUnitTests(TestCase):
    setUp = oa_tests.AuthorizationTests.setUp
    grant = oa_tests.AuthorizationTests.grant

    def test_result_messages_and_command_id_return_the_reviewed_vocabulary(self):
        self.assertEqual(authz.command_id(models.Platform.ARISTA_CEOS, oa_tests.EOS), "nos-version")
        self.assertEqual(authz.Result(False, ["AUTHORIZATION_UNKNOWN"]).messages, [authz.REFUSALS["AUTHORIZATION_UNKNOWN"]])

    def test_command_id_of_an_unauthorizable_command_is_empty(self):
        self.assertEqual(authz.command_id(models.Platform.ARISTA_CEOS, "show running-config"), "")

    def test_scope_digest_returns_an_order_independent_digest(self):
        t0 = timezone.now()
        args = {"commands": ["nos-version"], "not_before": t0, "expires_at": t0 + timedelta(hours=1), "max_observations": 2,
                "approved_by": "alice", "requested_by": "bob", "ticket": "CHG-2001"}
        self.assertEqual(authz.scope_digest(devices=["S1", "R3"], **args), authz.scope_digest(devices=["R3", "S1"], **args))

    def test_scope_digest_of_a_widened_scope_is_a_mismatch(self):
        t0 = timezone.now()
        args = {"commands": ["nos-version"], "not_before": t0, "expires_at": t0 + timedelta(hours=1), "approved_by": "alice",
                "requested_by": "bob", "ticket": "CHG-2001", "devices": ["S1"]}
        self.assertNotEqual(authz.scope_digest(max_observations=1, **args), authz.scope_digest(max_observations=9, **args))

    def test_lookup_returns_the_authorization_for_its_exact_reference(self):
        auth = self.grant().authorization
        self.assertEqual(authz.lookup(authz.reference(auth), require_digest=True).authorization.pk, auth.pk)
        self.assertEqual(authz.lookup(auth.auth_id).authorization.pk, auth.pk)

    def test_revoke_by_a_non_approver_is_refused(self):
        auth = self.grant().authorization
        self.assertEqual(authz.revoke(auth, actor="dave", reason="no longer needed").codes, ["REVOKER_NOT_AUTHORIZED"])
        self.assertIsNone(models.ObservationAuthorization.objects.get(pk=auth.pk).revoked_at)

    def test_observation_authorization_and_use_save_record_the_reservation(self):
        auth = models.ObservationAuthorization.objects.create(
            devices=["S1"], commands=["nos-version"], ticket="CHG-2001", reason="r", requested_by="bob", approved_by="alice",
            not_before=timezone.now(), expires_at=timezone.now() + timedelta(hours=1), max_observations=1, scope_digest="d" * 64)
        use = models.ObservationAuthorizationUse(authorization=auth, device="S1", command="nos-version", operator="bob")
        use.save()
        use.state, use.finished_at = models.ObservationUseState.ACCEPTED, timezone.now()
        use.save()
        self.assertEqual(models.ObservationAuthorizationUse.objects.get(pk=use.pk).state, models.ObservationUseState.ACCEPTED)

    def test_observation_authorization_use_save_refuses_an_unauthorized_command_or_a_second_finish(self):
        auth = self.grant().authorization
        with self.subTest("an unauthorized command is refused"), self.assertRaises(ValueError):
            models.ObservationAuthorizationUse(authorization=auth, device="S1", command="running-config", operator="bob").save()
        use = models.ObservationAuthorizationUse.objects.create(authorization=auth, device="S1", command="nos-version", operator="bob")
        use.state, use.finished_at = models.ObservationUseState.REFUSED, timezone.now()
        use.save()
        with self.subTest("a second finish is refused"), self.assertRaises(ValueError):
            use.save()


# =========================================================================================== version observations
class ObservationUnitTests(TestCase):
    def setUp(self):
        self.device = L.adopt("S1").device

    def test_ingest_result_messages_and_canonical_return_the_signed_body(self):
        env = envelope()
        body = observations.canonical("S1", env, "a" * 64)
        self.assertIn(b'"device":"S1"', body)
        self.assertEqual(observations.IngestResult(False, ["REPLAY"]).messages, [observations.REFUSALS["REPLAY"]])

    def test_canonical_of_another_device_is_a_mismatch(self):
        env = envelope()
        self.assertNotEqual(observations.canonical("S1", env, "a" * 64), observations.canonical("S2", env, "a" * 64))

    def test_current_max_age_returns_the_configured_bound(self):
        with self.settings(NMAS_VERSION_MAX_AGE_SECONDS=120):
            self.assertEqual(observations.current_max_age(), 120)

    def test_key_is_strong_refuses_short_or_degenerate_keys(self):
        self.assertFalse(observations.key_is_strong("k" * 40))
        self.assertFalse(observations.key_is_strong("0123456789abc"))
        self.assertTrue(observations.key_is_strong(KEY.decode().replace("k", "") + "0123456789abcdef0123456789abcdef"))

    def test_reverify_refuses_tampered_raw_evidence(self):
        row = observations.ingest("S1", envelope(), sources=SOURCES).record
        self.assertTrue(observations.reverify(row, EOS_OUT, sources=SOURCES))
        self.assertFalse(observations.reverify(row, EOS_OUT.replace("4.36.2F", "4.99.9F"), sources=SOURCES))
        self.assertFalse(observations.reverify(row, EOS_OUT, sources={}))

    def test_device_version_observation_save_persists_a_signed_row(self):
        row = observations.ingest("S1", envelope(), sources=SOURCES).record
        clone = models.DeviceVersionObservation(device=row.device, platform=row.platform, version=row.version, source_id=row.source_id,
                                                nonce="nonce-0002", command=row.command, raw_digest=row.raw_digest, signature=row.signature,
                                                host_key=HOST_KEY, identity_observation=row.identity_observation, observed_at=timezone.now())
        clone.save()
        self.assertTrue(models.DeviceVersionObservation.objects.filter(nonce="nonce-0002").exists())

    def test_collect_result_messages_return_operator_text(self):
        self.assertEqual(collector.CollectResult(False, ["REPLAY"]).messages, [observations.REFUSALS["REPLAY"]])


# ============================================================================================== host-key pins
class HostKeyPinTests(TestCase):
    def test_verdict_messages_and_evidence_digest_return_stable_values(self):
        self.assertEqual(pins.Verdict(False, ["PUBLIC_KEY_INVALID"]).messages, [pins.REFUSALS["PUBLIC_KEY_INVALID"]])
        self.assertEqual(pins.evidence_digest({"b": 1, "a": 2}), pins.evidence_digest({"a": 2, "b": 1}))

    def test_evidence_digest_of_a_tampered_capture_differs(self):
        self.assertNotEqual(pins.evidence_digest({"public_key": "a"}), pins.evidence_digest({"public_key": "b"}))

    def test_fingerprint_refuses_non_key_material(self):
        line, blob = ssh_key_line()
        self.assertEqual(pins.fingerprint(line), (pin_of(blob), "ssh-ed25519"))
        for label, value in (("a fingerprint", HOST_KEY), ("a mislabelled blob", line.replace("ssh-ed25519", "ssh-rsa", 1)),
                             ("garbage base64", "ssh-ed25519 !!!!")):
            with self.subTest(f"{label} is refused"):
                self.assertEqual(pins.fingerprint(value), ("", ""))

    def test_compare_registered_reports_a_conflicting_held_pin(self):
        inventory = {"network_devices": {"S1": {"ssh_host_key": "SHA256:" + "B" * 43}}}
        report = pins.compare_registered("S1", HOST_KEY, inventory=inventory)
        self.assertEqual((report["inventory_ssh_host_key"], report["verified_host_key"], report["conflict"]), ("MISMATCH", "ABSENT", True))

    def test_enrollment_route_returns_the_platform_mechanism(self):
        self.assertIn("approve_path refuses self-approval", pins.enrollment_route(models.Platform.ARISTA_CEOS))
        self.assertIn("inventory.yml", pins.enrollment_route(models.Platform.UBUNTU_FRR))

    def test_enrollment_route_of_an_unsupported_platform_is_none(self):
        self.assertEqual(pins.enrollment_route(models.Platform.CISCO_C8000V_IOSXE), "no supported enrollment route")


# =================================================================================== sessions and connections
class ConnectionAndSessionTests(SimpleTestCase):
    def test_eos_connection_sends_exactly_the_version_command(self):
        inner = mock.Mock(send_command=mock.Mock(return_value=EOS_OUT))
        conn = conns.EosObservationConnection(inner, HOST_KEY, oa_tests.EOS)
        self.assertEqual((conn.send_command(oa_tests.EOS), conn.host_key, conn.host_key_pinned), (EOS_OUT, HOST_KEY, True))

    def test_eos_connection_refuses_any_other_command(self):
        inner = mock.Mock()
        conn = conns.EosObservationConnection(inner, HOST_KEY, oa_tests.EOS)
        with self.assertRaises(PermissionError):
            conn.send_command("show running-config")
        inner.send_command.assert_not_called()

    def test_presented_host_key_returns_the_peer_fingerprint(self):
        transport = mock.Mock(get_remote_server_key=mock.Mock(return_value=FakeKey(b"peer-key")))
        conn = SimpleNamespace(remote_conn_pre=mock.Mock(get_transport=mock.Mock(return_value=transport)))
        self.assertEqual(conns.presented_host_key(conn), pin_of(b"peer-key"))

    def test_presented_host_key_of_an_unreadable_transport_is_empty(self):
        self.assertEqual(conns.presented_host_key(SimpleNamespace()), "")

    def test_connection_factory_starts_ready_for_a_request(self):
        factory = conns.ObservationConnectionFactory(document={}, endpoint_resolver=mock.Mock(), eos_connect=mock.Mock())
        self.assertEqual(factory.last_error, "")

    def test_connection_factory_refuses_a_request_that_is_not_read_only(self):
        factory = conns.ObservationConnectionFactory(document={}, endpoint_resolver=mock.Mock(), eos_connect=mock.Mock())
        request = SimpleNamespace(read_only=False, authorization_ref="OBSAUTH-000001", platform=models.Platform.ARISTA_CEOS.value,
                                  source="PATH", expected_host_key=HOST_KEY)
        with self.assertRaises(conns.ObservationConnectionError):
            factory(request)
        self.assertEqual(factory.last_error, "REQUEST_INVALID")

    def test_observation_session_executes_the_version_command(self):
        inner = mock.Mock(send_command=mock.Mock(return_value=EOS_OUT))
        session = sessions.ObservationSession(inner, platform=models.Platform.ARISTA_CEOS.value, command=oa_tests.EOS, address="192.168.200.11",
                                              authorization_ref="OBSAUTH-000001", host_key=HOST_KEY, host_key_pinned=True)
        self.assertEqual((session.execute(oa_tests.EOS), session.commands_sent), (EOS_OUT, [oa_tests.EOS]))

    def test_observation_session_refuses_another_command_or_a_closed_session(self):
        session = sessions.ObservationSession(mock.Mock(), platform=models.Platform.ARISTA_CEOS.value, command=oa_tests.EOS, address="192.168.200.11",
                                              authorization_ref="OBSAUTH-000001", host_key=HOST_KEY, host_key_pinned=True)
        with self.subTest("another command is refused"), self.assertRaises(sessions.CommandNotPermitted):
            session.execute("show running-config")
        session.close()
        with self.subTest("a closed session is refused"), self.assertRaises(sessions.CommandNotPermitted):
            session.execute(oa_tests.EOS)

    def test_session_provider_starts_bound_to_its_authorization(self):
        provider = sessions.ObservationSessionProvider(mock.Mock(), " OBSAUTH-000001 ", document={})
        self.assertEqual(provider.last_refusal, "")

    def test_session_provider_without_an_authorization_refuses_every_target(self):
        factory = mock.Mock()
        provider = sessions.ObservationSessionProvider(factory, "", document={})
        self.assertIsNone(provider(SimpleNamespace(name="S1", platform=models.Platform.ARISTA_CEOS.value), "192.168.200.11"))
        self.assertTrue(provider.last_refusal)
        factory.assert_not_called()

    def test_validate_directory_returns_an_approved_private_directory(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d).chmod(0o700)
            self.assertEqual(evidence.validate_directory(d, approved_roots=(d,)), Path(d).resolve())


# ============================================================================================ management helpers
class ManagementHelperTests(SimpleTestCase):
    def test_is_nmas_switch_self_returns_true_for_the_nmas_management_switch(self):
        device = SimpleNamespace(name="mgmt_swt")
        nmas = SimpleNamespace(upstream_device="mgmt_swt")
        self.assertTrue(paths.is_nmas_switch_self(device, models.ManagementPathType.DIRECT_OOB, None, nmas, ""))

    def eos_outputs(self, vlan_status="active"):
        import json

        return {"show ip interface brief | json": json.dumps({"interfaces": {"Vlan200": {"interfaceAddress": {"ipAddr": {"address": "192.168.200.11"}}}}}),
                "show interfaces switchport | json": json.dumps({"switchports": {"Ethernet3": {"enabled": True, "switchportInfo":
                                                                                               {"mode": "access", "accessVlanId": 200}}}}),
                "show vlan | json": json.dumps({"vlans": {"200": {"status": vlan_status, "interfaces": {"Ethernet3": {}, "Cpu": {}}}}})}

    def path(self):
        return SimpleNamespace(endpoint_address="192.168.200.11", path_type=models.ManagementPathType.DIRECT_OOB, vlan=200,
                               local_interface="Ethernet3", tagged=False)

    def test_eos_operational_config_problems_accepts_a_carried_management_vlan(self):
        self.assertEqual(probes.eos_operational_config_problems(self.path(), self.eos_outputs()), [])

    def test_eos_operational_config_problems_blocks_an_inactive_or_unconfigured_vlan(self):
        with self.subTest("an inactive VLAN is blocked"):
            self.assertEqual(probes.eos_operational_config_problems(self.path(), self.eos_outputs("suspended"))[0]["code"], "L2_CONFIG_MISMATCH")
        with self.subTest("an unconfigured endpoint is blocked"):
            self.assertEqual(probes.eos_operational_config_problems(self.path(), {})[0]["code"], "L2_CONFIG_MISMATCH")

    def found(self):
        return {"ssh_key_ref": "runtime://r3", "host_key": pin_of(b"r3-key"), "address": "192.168.200.3", "port": 22, "username": "nmas-diag"}

    def test_connect_found_returns_a_session_carrying_the_presented_pin(self):
        transport = mock.Mock(get_remote_server_key=mock.Mock(return_value=FakeKey(b"r3-key")))
        client = mock.Mock(get_transport=mock.Mock(return_value=transport))
        with mock.patch("modules.device_credentials.load_ssh_private_key", return_value=object()), \
                mock.patch("paramiko.SSHClient", return_value=client):
            session = linux_ssh.connect_found(self.found(), timeout=5)
        self.assertEqual((session.host_key, session.username), (pin_of(b"r3-key"), "nmas-diag"))
        self.assertEqual(client.connect.call_args.kwargs["allow_agent"], False)

    def test_connect_found_refuses_a_mismatched_host_key_and_closes(self):
        transport = mock.Mock(get_remote_server_key=mock.Mock(return_value=FakeKey(b"someone-else")))
        client = mock.Mock(get_transport=mock.Mock(return_value=transport))
        with mock.patch("modules.device_credentials.load_ssh_private_key", return_value=object()), \
                mock.patch("paramiko.SSHClient", return_value=client), self.assertRaises(ExecutorError) as caught:
            linux_ssh.connect_found(self.found(), timeout=5)
        self.assertEqual(str(caught.exception), "CONNECTION_FAILED")
        client.close.assert_called_once()
