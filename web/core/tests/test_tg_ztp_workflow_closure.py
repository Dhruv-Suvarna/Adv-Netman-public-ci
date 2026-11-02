"""Lab 7 closure -- V2 Phase 3 workflow helpers, the SSH management layer, the new ZTP models and the two Phase 2 services
Phase 3 added, each called directly.

``test_ztp_workflow`` drives open -> discovery -> delivery -> enrollment -> verification with a fake ``run``; this module
proves the pieces themselves:

* workflow -- session lookup, locked crypt hashes, enrollment key generation, bootstrap context, open prerequisites, failure
  recording (retryable and not) and the status document;
* management -- fingerprints, enrollment-key loading from the protected store, first-contact key exchange and pinned,
  key-only command execution against a REAL SSH server on 127.0.0.1 (paramiko server mode; no device, no network);
* models -- ``save`` of valid updates versus immutable / malformed fields, and ``delete`` refused on every evidence model;
* ``lifecycle.record_ztp_state`` and ``attachments.commissioned_upstream_problems``.

NEGATIVE cases: unsupported key types, missing / unreadable / foreign keys, an unreachable port, a host key that is not the
enrolled one, an unauthorized key, unknown sessions, invalid ZTP states and untrusted upstreams are all refused.
"""
from __future__ import annotations

import io
import logging
import socket
import threading
from types import SimpleNamespace

import paramiko
from django.test import TestCase

from core import models
from core.services.devices import attachments, lifecycle
from core.services.ztp import management, workflow
from core.tests.helpers import lifecycle as L
from core.tests.helpers import ztp as Z
from modules.device_credentials import SecretNotFound, make_reference

logging.getLogger("paramiko").setLevel(logging.CRITICAL)
USER = "nmas-enroll"


class _Iface(paramiko.ServerInterface):
    def __init__(self, server):
        self.server = server

    def get_allowed_auths(self, username):
        return "publickey"

    def check_auth_publickey(self, username, key):
        ok = username == USER and key.get_base64() == self.server.authorized
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        # Reply synchronously (output, exit status, EOF) from the transport thread, BEFORE paramiko sends the request's success
        # message: a reply thread could close the channel before that message and the client would see "Channel closed".  EOF
        # does not close the client's channel, so it still receives the success, then reads the output to EOF.
        text = self.server.outputs.get(command.decode(), "% Invalid input\n")
        self.server.commands.append(command.decode())
        channel.sendall(text.encode())
        channel.send_exit_status(0)
        channel.shutdown_write()
        return True


class LocalSshServer:
    """A key-only SSH server on 127.0.0.1 with an Ed25519 host key (accepts one connection at a time, test lifetime only)."""

    def __init__(self, *, authorized_public: str = "", outputs: dict | None = None):
        private, _public, self.fingerprint = workflow.generate_enrollment_key(("ssh-ed25519",), "host@test")
        self.host_key = paramiko.Ed25519Key.from_private_key(io.StringIO(private))
        self.authorized = authorized_public.split()[1] if authorized_public else ""
        self.outputs, self.commands = dict(outputs or {}), []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.transports, self.channels = [], []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.stop.is_set():
            try:
                conn, _addr = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            transport = paramiko.Transport(conn)
            transport.add_server_key(self.host_key)
            self.transports.append(transport)
            try:
                transport.start_server(server=_Iface(self))
            except (paramiko.SSHException, EOFError, OSError):
                continue
            threading.Thread(target=self._channels, args=(transport,), daemon=True).start()

    def _channels(self, transport):
        while transport.is_active():
            channel = transport.accept(0.5)
            if channel is not None:
                self.channels.append(channel)      # keep a reference: paramiko closes a garbage-collected channel

    def close(self):
        self.stop.set()
        for transport in self.transports:
            transport.close()
        self.sock.close()
        self.thread.join(5)


def closed_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


class ManagementClosureTests(Z.ZtpTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.private, self.public, self.key_fp = workflow.generate_enrollment_key(("ssh-ed25519",), f"{USER}@DEV-test")
        self.reference = make_reference("ztp-enroll-closure-test")
        management.secret_provider().initialize(self.reference, self.private)

    def server(self, **kwargs) -> LocalSshServer:
        server = LocalSshServer(**kwargs)
        self.addCleanup(server.close)
        return server

    def test_management_exception_carries_its_code_and_bounded_detail(self):
        error = management.ManagementError("HOST_KEY_MISMATCH", "x" * 900)
        self.assertEqual((error.code, str(error), len(error.detail)), ("HOST_KEY_MISMATCH", "HOST_KEY_MISMATCH", 300))

    def test_fingerprint_is_the_openssh_sha256_form(self):
        key = management.load_private_key(self.reference)
        self.assertEqual(management.fingerprint(key), self.key_fp)

    def test_fingerprint_of_something_that_is_not_a_key_raises(self):
        with self.assertRaises(AttributeError):
            management.fingerprint("ssh-ed25519 AAAA")

    def test_load_private_key_reads_the_enrollment_key_from_the_secret_store(self):
        key = management.load_private_key(self.reference)
        self.assertIsInstance(key, paramiko.Ed25519Key)
        self.assertEqual(key.get_base64(), self.public.split()[1])

    def test_load_private_key_of_unreadable_or_missing_material_is_refused(self):
        bad = make_reference("ztp-enroll-closure-bad")
        management.secret_provider().initialize(bad, "not a private key")
        with self.assertRaises(management.ManagementError) as caught:
            management.load_private_key(bad)
        self.assertEqual(caught.exception.code, "MANAGEMENT_AUTH_FAILED")
        with self.assertRaises(SecretNotFound):
            management.load_private_key(make_reference("ztp-enroll-closure-absent"))

    def test_observe_host_key_returns_the_presented_host_key(self):
        server = self.server()
        self.assertEqual(management.observe_host_key("127.0.0.1", server.port, timeout=5), server.fingerprint)
        self.assertEqual(server.commands, [])                  # key exchange only: no authentication, no command

    def test_observe_host_key_of_an_unreachable_port_is_refused(self):
        with self.assertRaises(management.ManagementError) as caught:
            management.observe_host_key("127.0.0.1", closed_port(), timeout=2)
        self.assertEqual(caught.exception.code, "MANAGEMENT_UNREACHABLE")

    def test_run_commands_executes_over_a_pinned_key_only_session(self):
        server = self.server(authorized_public=self.public, outputs={"show version | json": '{"mfgName": "Arista"}'})
        found = management.run_commands("127.0.0.1", username=USER, key_reference=self.reference, enrolled_host_key=server.fingerprint,
                                        commands=["show version | json"], port=server.port)
        self.assertEqual(found, {"host_key": server.fingerprint, "outputs": {"show version | json": '{"mfgName": "Arista"}'}})
        self.assertEqual(server.commands, ["show version | json"])

    def test_run_commands_refuses_an_unenrolled_or_mismatched_host_key_and_a_rejected_key(self):
        server = self.server(authorized_public=self.public)
        for label, enrolled, code in (("not enrolled", "", "HOST_KEY_NOT_ENROLLED"),
                                      ("mismatch", "SHA256:" + "B" * 43, "HOST_KEY_MISMATCH")):
            with self.subTest(label), self.assertRaises(management.ManagementError) as caught:
                management.run_commands("127.0.0.1", username=USER, key_reference=self.reference, enrolled_host_key=enrolled,
                                        commands=["show version"], port=server.port)
            self.assertEqual(caught.exception.code, code)
        foreign = self.server(authorized_public=workflow.generate_enrollment_key(("ssh-ed25519",), "other")[1])
        with self.assertRaises(management.ManagementError) as caught:
            management.run_commands("127.0.0.1", username=USER, key_reference=self.reference, enrolled_host_key=foreign.fingerprint,
                                    commands=["show version"], port=foreign.port)
        self.assertEqual(caught.exception.code, "MANAGEMENT_AUTH_FAILED")
        self.assertEqual(server.commands + foreign.commands, [])


class WorkflowHelperClosureTests(Z.ZtpTestMixin, TestCase):
    def test_get_session_returns_the_session_by_its_id(self):
        session = self.open_session()
        self.assertEqual(workflow.get_session(session.session_id), session)

    def test_locked_sha512_crypt_returns_a_fresh_sha512_crypt_hash(self):
        first, second = workflow.locked_sha512_crypt(), workflow.locked_sha512_crypt()
        self.assertTrue(first.startswith("$6$"))
        self.assertNotEqual(first, second)

    def test_generate_enrollment_key_returns_the_strongest_installable_key(self):
        private, public, fingerprint = workflow.generate_enrollment_key(("ssh-rsa", "ssh-ed25519"), "nmas-enroll@DEV-1")
        self.assertTrue(public.startswith("ssh-ed25519 ") and public.endswith(" nmas-enroll@DEV-1"))
        self.assertTrue(fingerprint.startswith("SHA256:"))
        self.assertIn("OPENSSH " "PRIVATE KEY", private)
        _private, rsa_public, _fp = workflow.generate_enrollment_key(("ssh-rsa",), "nmas-enroll@DEV-2")
        self.assertTrue(rsa_public.startswith("ssh-rsa "))

    def test_generate_enrollment_key_for_an_uninstallable_key_type_raises(self):
        with self.assertRaises(ValueError):
            workflow.generate_enrollment_key(("ecdsa-sha2-nistp256",), "nmas-enroll@DEV-1")

    def test_context_for_builds_the_bootstrap_context_of_the_session(self):
        session = self.open_session()
        ctx = workflow.context_for(session, locked_password_hash="$6$s$h")
        self.assertEqual((ctx.hostname, ctx.interface, ctx.address, ctx.prefixlen, ctx.gateway), ("NEW1", "Ethernet1", "10.254.30.10", 24, Z.RELAY))
        self.assertEqual((ctx.enrollment_user, ctx.enrollment_public_key, ctx.locked_password_hash), (USER, session.enrollment_public_key, "$6$s$h"))

    def test_context_for_an_upstream_without_a_listed_relay_falls_back_to_the_gateway(self):
        network = SimpleNamespace(trusted_relays=[], gateway="10.254.30.1", ipv4_prefix="10.254.30.0/24", service_address="10.254.31.2",
                                  service_prefix="10.254.31.0/30")
        session = SimpleNamespace(network=network, device=SimpleNamespace(name="NEW1"), session_id="ZTP-000009", reserved_address="10.254.30.12",
                                  enrollment_public_key="ssh-ed25519 AAAA x",
                                  authorization=SimpleNamespace(auth_id="BAUTH-000009",
                                                                attachment=SimpleNamespace(upstream_device="S9", local_interface="Ethernet2")))
        self.assertEqual(workflow.context_for(session).gateway, "10.254.30.1")

    def test_open_prerequisites_of_a_ready_device_are_all_satisfied(self):
        device, _attachment, auth = L.ready_device()
        self.assertEqual(workflow.open_problems(device, auth, self.network()), [])

    def test_open_problems_without_an_authorization_or_with_an_open_session_are_refused(self):
        session = self.open_session()
        device = models.ManagedDevice.objects.get(pk=session.device_id)
        self.assertIn("AUTHORIZATION_NOT_FOUND", [p["code"] for p in workflow.open_problems(device, None, session.network)])
        self.assertIn("ZTP_SESSION_OPEN_EXISTS", [p["code"] for p in workflow.open_problems(device, session.authorization, session.network)])

    def test_retryable_attempt_keeps_the_session_open_with_native_guidance(self):
        session = self.open_session()
        result = workflow.record_failure(session, "MANAGEMENT_UNREACHABLE", retryable=True, actor=L.OPERATOR, detail="timeout")
        self.assertEqual((result.session.stage, result.session.attempts), (models.ZtpSessionStage.AWAITING_DISCOVERY, 1))
        self.assertEqual(result.detail["failure"]["retry"]["dhcp_retry_interval_seconds"], 30)
        self.assertEqual(result.codes, ["MANAGEMENT_UNREACHABLE"])

    def test_a_mismatch_closes_the_session_and_never_retries(self):
        session = self.open_session()
        result = workflow.record_failure(session, "HOST_KEY_MISMATCH", retryable=False, actor=L.OPERATOR)
        self.assertEqual(result.session.stage, models.ZtpSessionStage.FAILED)
        self.assertFalse(result.session.artifacts.filter(state=models.BootstrapArtifactState.ACTIVE).exists())

    def test_status_reports_every_evidence_stage_separately(self):
        session = self.open_session()
        doc = workflow.status(session)
        self.assertEqual((doc["session"], doc["stage"], doc["adapter"]), (session.session_id, "AWAITING_DISCOVERY", "arista_eos"))
        self.assertEqual((doc["discovery"]["correlated"], doc["delivery"]["served"], doc["management"]["verified"]), (False, 0, False))
        self.assertEqual(doc["production_admission"], {"state": "NOT_ADMITTED", "allowed": False, "owner_phases": [5, 6]})


class ModelClosureTests(Z.ZtpTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.session = self.discovered()
        self.artifact = self.session.artifacts.get(state=models.BootstrapArtifactState.ACTIVE)
        self.lease = self.session.lease_observations.get()

    def test_ztp_session_save_accepts_an_open_session_update(self):
        self.session.attempts += 1
        self.session.observed_host_key = L.HOST_KEY
        self.session.save()
        self.assertEqual(models.ZtpSession.objects.get(pk=self.session.pk).attempts, 1)

    def test_ztp_session_save_of_an_immutable_or_malformed_field_is_refused(self):
        for label, field, value in (("immutable address", "reserved_address", "10.254.30.11"), ("bad fingerprint", "observed_host_key", "md5:x"),
                                    ("private key", "enrollment_public_key", "-----BEGIN OPENSSH " "PRIVATE KEY-----"),
                                    ("unknown stage", "stage", "DONE")):
            fresh = models.ZtpSession.objects.get(pk=self.session.pk)
            setattr(fresh, field, value)
            with self.subTest(label), self.assertRaises(ValueError):
                fresh.save()

    def test_bootstrap_artifact_save_accepts_a_state_change_of_an_active_artifact(self):
        self.artifact.state = models.BootstrapArtifactState.REVOKED
        self.artifact.save()
        self.assertEqual(models.BootstrapArtifact.objects.get(pk=self.artifact.pk).state, "REVOKED")

    def test_bootstrap_artifact_save_of_changed_content_or_reopened_history_is_refused(self):
        changed = models.BootstrapArtifact.objects.get(pk=self.artifact.pk)
        changed.content += "\nrouter bgp 1"
        with self.assertRaises(ValueError):
            changed.save()
        self.artifact.state = models.BootstrapArtifactState.EXPIRED
        self.artifact.save()
        self.artifact.state = models.BootstrapArtifactState.ACTIVE
        with self.assertRaises(ValueError):
            self.artifact.save()

    def test_bootstrap_delivery_save_appends_one_evidence_row(self):
        row = models.BootstrapDelivery(artifact=self.artifact, session=self.session, transport="HTTP", client_address="10.254.30.10",
                                       request_digest="0" * 64, outcome=models.BootstrapDeliveryOutcome.REFUSED, code="REQUESTER_NOT_BOUND")
        row.save()
        self.assertEqual(models.BootstrapDelivery.objects.filter(session=self.session).count(), 1)

    def test_bootstrap_delivery_save_of_an_existing_row_or_unknown_outcome_is_refused(self):
        row = models.BootstrapDelivery(artifact=self.artifact, session=self.session, transport="HTTP", client_address="10.254.30.10",
                                       request_digest="0" * 64, outcome="MAYBE")
        with self.assertRaises(ValueError):
            row.save()
        row.outcome = models.BootstrapDeliveryOutcome.REFUSED
        row.save()
        row.code = "CHANGED"
        with self.assertRaises(ValueError):
            row.save()

    def test_dhcp_lease_observation_save_moves_the_counters(self):
        self.lease.seen_count += 1
        self.lease.save()
        self.assertEqual(models.DhcpLeaseObservation.objects.get(pk=self.lease.pk).seen_count, 2)

    def test_dhcp_lease_observation_save_of_changed_evidence_is_refused(self):
        self.lease.relay_trusted = False
        with self.assertRaises(ValueError):
            self.lease.save()
        self.lease.refresh_from_db()
        self.lease.outcome = "INVENTED"
        with self.assertRaises(ValueError):
            self.lease.save()

    def test_dhcp_provider_application_save_appends_one_record(self):
        row = models.DhcpProviderApplication(network=self.session.network, provider="ISC_DHCP", state="VALIDATED", config_sha256="a" * 64,
                                             config_text="authoritative;\n", actor=L.OPERATOR)
        row.save()
        self.assertTrue(models.DhcpProviderApplication.objects.filter(pk=row.pk).exists())

    def test_dhcp_provider_application_save_of_a_bad_digest_or_an_existing_row_is_refused(self):
        row = models.DhcpProviderApplication(network=self.session.network, provider="ISC_DHCP", state="VALIDATED", config_sha256="short",
                                             actor=L.OPERATOR)
        with self.assertRaises(ValueError):
            row.save()
        row.config_sha256 = "b" * 64
        row.save()
        row.state = "APPLIED"
        with self.assertRaises(ValueError):
            row.save()

    def test_evidence_models_refuse_deletion(self):
        delivery = models.BootstrapDelivery.objects.create(artifact=self.artifact, session=self.session, transport="HTTP",
                                                           client_address="10.254.30.10", request_digest="0" * 64,
                                                           outcome=models.BootstrapDeliveryOutcome.REFUSED)
        application = models.DhcpProviderApplication.objects.create(network=self.session.network, provider="ISC_DHCP", state="VALIDATED",
                                                                    config_sha256="c" * 64, actor=L.OPERATOR)
        for row in (self.session, self.artifact, delivery, self.lease, application):
            with self.subTest(type(row).__name__), self.assertRaises(ValueError):
                row.delete()
            self.assertTrue(type(row).objects.filter(pk=row.pk).exists())


class DeviceServiceClosureTests(Z.ZtpTestMixin, TestCase):
    def test_record_ztp_state_records_an_observed_state_once(self):
        device, _attachment, _auth = L.ready_device()
        first = lifecycle.record_ztp_state(device, models.ZtpState.ENABLED, actor=L.OPERATOR, evidence={"basis": "test"})
        self.assertEqual((first.ok, first.changed, first.device.ztp_state), (True, True, models.ZtpState.ENABLED))
        again = lifecycle.record_ztp_state(device, models.ZtpState.ENABLED, actor=L.OPERATOR, evidence={})
        self.assertEqual((again.ok, again.changed, again.event), (True, False, None))

    def test_record_ztp_state_of_an_unobservable_state_is_refused(self):
        device, _attachment, _auth = L.ready_device()
        result = lifecycle.record_ztp_state(device, models.ZtpState.UNKNOWN, actor=L.OPERATOR, evidence={})
        self.assertFalse(result.ok)
        self.assertEqual([b["code"] for b in result.blockers], ["OBSERVATION_INVALID"])

    def test_commissioned_upstream_check_clears_an_admitted_in_service_upstream(self):
        device, _attachment, _auth = L.ready_device()
        # Phases 5-6 own commissioning and admission (no Phase 3 service reaches it); the disposable test row is put in that
        # state with the model's own compare-and-swap writer, as the Phase 2 tests do for fixture states
        self.assertEqual(models.ManagedDevice.objects.compare_and_swap(device.pk, device.version,
                                                                       lifecycle_state=models.DeviceLifecycleState.IN_SERVICE,
                                                                       admission_state=models.ProductionAdmissionState.ADMITTED), 1)
        self.assertEqual(attachments.commissioned_upstream_problems("NEW1"), [])

    def test_commissioned_upstream_problems_of_an_unknown_or_unadmitted_upstream_are_refused(self):
        self.assertEqual([p["code"] for p in attachments.commissioned_upstream_problems("NOPE")], ["UPSTREAM_UNKNOWN"])
        L.ready_device()
        self.assertEqual([p["code"] for p in attachments.commissioned_upstream_problems("NEW1")], ["UPSTREAM_NOT_TRUSTED"])
