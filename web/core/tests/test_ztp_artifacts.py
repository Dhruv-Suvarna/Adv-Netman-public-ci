"""V2 Phase 3: bootstrap artifact authorization and delivery -- bounded, session-bound, secret-free -- plus the real HTTP and
TFTP delivery servers on localhost."""

from __future__ import annotations

import socket
import struct
import threading
import urllib.error
import urllib.request
from datetime import timedelta
from http.server import HTTPServer
from socketserver import UDPServer
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from core import models
from core.services.devices import authorization
from core.services.ztp import adapters, artifacts, servers
from core.services.ztp.adapters.base import RenderedBootstrap
from core.tests.helpers import lifecycle as L
from core.tests.helpers import ztp as Z

CLIENT = "10.254.30.10"
State = models.BootstrapArtifactState


class ArtifactDecisionTests(Z.ZtpTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.session = self.discovered()
        self.artifact = self.session.artifacts.get(state=State.ACTIVE)
        self.path = f"/ztp/v1/{self.artifact.artifact_id}/{self.artifact.filename}"

    def deliver(self, path=None, client=CLIENT, transport="HTTP"):
        decision = artifacts.authorize(self.path if path is None else path, client, transport)
        artifacts.record(decision, client_address=client, transport=transport,
                         outcome=models.BootstrapDeliveryOutcome.SERVED if decision.ok else models.BootstrapDeliveryOutcome.REFUSED,
                         bytes_sent=len(decision.content))
        return decision

    def test_artifact_is_secret_free_and_bound_to_the_session(self):
        self.assertEqual(adapters.base.secret_findings(self.artifact.content), [])
        self.assertRegex(self.artifact.artifact_id, r"^ART-[0-9a-f]{24}$")
        self.assertEqual(self.artifact.transport, "HTTP")
        self.assertIn(self.session.reserved_address, self.artifact.content)

    def test_first_delivery_consumes_one_authorization_use_and_advances_to_delivered(self):
        decision = self.deliver()
        self.assertTrue(decision.ok)
        self.assertTrue(decision.counted)
        self.assertEqual(decision.content.decode(), self.artifact.content)
        auth = models.BootstrapAuthorization.objects.get(pk=self.session.authorization_id)
        self.assertEqual((auth.use_count, auth.state), (1, models.BootstrapAuthorizationState.CONSUMED))
        self.session.refresh_from_db()
        self.assertEqual(self.session.stage, models.ZtpSessionStage.DELIVERED)
        event = self.session.device.lifecycle_events.get(action="ZTP_ARTIFACT_DELIVERED")
        self.assertIn("not proof the device applied", event.evidence["meaning"])

    def test_duplicate_fetch_does_not_consume_again_and_is_bounded(self):
        self.deliver()
        repeat = self.deliver()
        self.assertTrue(repeat.ok)
        self.assertEqual((repeat.duplicate, repeat.counted), (True, False))
        self.assertEqual(models.BootstrapAuthorization.objects.get(pk=self.session.authorization_id).use_count, 1)
        self.assertEqual(self.session.device.lifecycle_events.filter(action="ZTP_ARTIFACT_DELIVERED").count(), 1)
        for _ in range(artifacts.MAX_DELIVERIES - 2):
            self.assertTrue(self.deliver().ok)
        self.assertEqual(self.deliver().code, "ARTIFACT_DELIVERY_LIMIT")

    def test_path_traversal_enumeration_and_unknown_paths_are_refused_uniformly(self):
        for path in ("/ztp/v1/../../web/db.sqlite3", "/etc/passwd", "/ztp/v1/", "/ztp/v1/ART-000000000000000000000000/startup-config",
                     f"/ztp/v1/{self.artifact.artifact_id}/../startup-config", f"/ztp/v1/{self.artifact.artifact_id}/other-file",
                     f"/ztp/v1/{self.artifact.artifact_id}/startup-config%00", "", "/" * 600):
            with self.subTest(path[:60]):
                decision = self.deliver(path)
                self.assertFalse(decision.ok)
                self.assertIn(decision.code, ("PATH_INVALID", "ARTIFACT_UNKNOWN"))
                self.assertEqual(decision.content, b"")
        self.assertEqual(models.BootstrapAuthorization.objects.get(pk=self.session.authorization_id).use_count, 0)

    def test_requester_must_hold_the_sessions_trusted_lease(self):
        self.assertEqual(self.deliver(client="10.254.30.11").code, "REQUESTER_NOT_BOUND")
        self.assertEqual(self.deliver(client="10.254.31.2").code, "REQUESTER_NOT_BOUND")

    def test_wrong_transport_expiry_revocation_and_closed_session(self):
        self.assertEqual(self.deliver(transport="TFTP").code, "TRANSPORT_MISMATCH")
        with self.subTest("expired artifact"):
            models.BootstrapArtifact.objects.filter(pk=self.artifact.pk).update(expires_at=timezone.now() - timedelta(seconds=1))
            self.assertEqual(self.deliver().code, "ARTIFACT_EXPIRED")
            self.assertEqual(artifacts.expire_due(), 1)                  # restart recovery closes it
            self.assertEqual(models.BootstrapArtifact.objects.get(pk=self.artifact.pk).state, State.EXPIRED)

    def test_revoked_authorization_refuses_first_and_repeat_delivery(self):
        auth = models.BootstrapAuthorization.objects.get(pk=self.session.authorization_id)
        authorization.revoke(auth, actor=L.APPROVER, reason="stop")
        self.assertTrue(self.deliver().code.startswith("AUTH_"))

    def test_closed_session_refuses(self):
        from core.services.ztp import workflow
        workflow.cancel_session(self.session, actor=L.APPROVER, reason="operator stop")
        self.assertEqual(self.deliver().code, "ARTIFACT_REVOKED")

    def test_refusals_are_recorded_and_audited_without_the_path(self):
        self.deliver("/ztp/v1/../../secret")
        row = models.BootstrapDelivery.objects.get()
        self.assertEqual((row.outcome, row.code), ("REFUSED", "PATH_INVALID"))
        self.assertEqual(len(row.request_digest), 64)
        audit = models.AuditEvent.objects.filter(metadata__action="ZTP_ARTIFACT_DELIVERY").get()
        self.assertNotIn("secret", str(audit.metadata) + audit.summary)

    def test_create_refuses_secret_content_and_unsafe_names_and_supersedes(self):
        with self.assertRaises(ValueError):
            artifacts.create(self.session, RenderedBootstrap("startup-config", "username a password 0 x\n", "text/plain", "startup-config"),
                             expires_at=timezone.now() + timedelta(hours=1))
        with self.assertRaises(ValueError):
            artifacts.create(self.session, RenderedBootstrap("../x", "hostname a\n", "text/plain", "startup-config"),
                             expires_at=timezone.now() + timedelta(hours=1))
        newer = artifacts.create(self.session, RenderedBootstrap("startup-config", "hostname b\n", "text/plain", "startup-config"),
                                 expires_at=timezone.now() + timedelta(hours=1))
        self.assertEqual(models.BootstrapArtifact.objects.get(pk=self.artifact.pk).state, State.SUPERSEDED)
        self.assertEqual(self.deliver().code, "ARTIFACT_SUPERSEDED")
        self.assertTrue(self.deliver(f"/ztp/v1/{newer.artifact_id}/startup-config").ok)


class MultiUseAuthorizationTests(Z.ZtpTestMixin, TestCase):
    def test_revocation_after_first_delivery_stops_repeats(self):
        session = self.discovered(uses=2)
        artifact = session.artifacts.get(state=State.ACTIVE)
        path = f"/ztp/v1/{artifact.artifact_id}/{artifact.filename}"
        self.assertTrue(artifacts.authorize(path, CLIENT, "HTTP").ok)
        auth = models.BootstrapAuthorization.objects.get(pk=session.authorization_id)
        self.assertEqual((auth.state, auth.use_count), (models.BootstrapAuthorizationState.APPROVED, 1))
        self.assertTrue(artifacts.authorize(path, CLIENT, "HTTP").duplicate)
        authorization.revoke(auth, actor=L.APPROVER, reason="stop")
        self.assertEqual(artifacts.authorize(path, CLIENT, "HTTP").code, "AUTH_REVOKED")


@mock.patch("core.services.ztp.servers.close_old_connections", lambda: None)   # the test's own DB connection stays open
class DeliveryServerTests(Z.ZtpTestMixin, TestCase):
    """The real request handlers on real 127.0.0.1 sockets.  The server handles one request in the test thread (the test
    database is not shared across threads); the client runs in a helper thread.  A lease row binds the loopback requester:
    ingestion itself is tested elsewhere."""

    def setUp(self):
        super().setUp()
        self.session = self.open_session()
        self.artifact = self.session.artifacts.get(state=State.ACTIVE)
        models.DhcpLeaseObservation.objects.create(
            network=self.session.network, session=self.session, device=self.session.device, idempotency_key="loopback", provider="ISC_DHCP",
            address="127.0.0.1", client_mac="a2:27:1c:9a:b6:7b", client_id=Z.CLIENT_ID, vendor_class=Z.VENDOR, relay_address=Z.RELAY,
            circuit_id="Ethernet7", relay_trusted=True, upstream_device="S1", upstream_interface="Ethernet7", binding_state="active",
            lease_ends=timezone.now() + timedelta(minutes=10), outcome=models.DhcpLeaseOutcome.CORRELATED, last_seen=timezone.now())

    def http(self, path, method="GET"):
        server = HTTPServer(("127.0.0.1", 0), servers.BootstrapHttpHandler)
        self.addCleanup(server.server_close)
        url = f"http://127.0.0.1:{server.server_address[1]}{path}"
        result = {}

        def client():
            try:
                with urllib.request.urlopen(urllib.request.Request(url, method=method), timeout=5) as response:
                    result["value"] = (response.status, response.read())
            except urllib.error.HTTPError as exc:
                result["value"] = (exc.code, exc.read())

        thread = threading.Thread(target=client)
        thread.start()
        server.handle_request()
        thread.join(5)
        return result["value"]

    def test_http_serves_the_artifact_and_refuses_everything_else(self):
        path = f"/ztp/v1/{self.artifact.artifact_id}/startup-config"
        self.assertEqual(self.http("/ztp/v1/../../manage.py"), (404, b"not found\n"))
        self.assertEqual(self.http(path, "HEAD")[0], 405)                  # HEAD never consumes an authorization use
        self.assertEqual(self.http(path, "POST")[0], 405)
        self.assertEqual(models.BootstrapAuthorization.objects.get(pk=self.session.authorization_id).use_count, 0)
        status, body = self.http(path)
        self.assertEqual((status, body.decode()), (200, self.artifact.content))
        served = models.BootstrapDelivery.objects.get(outcome="SERVED")
        self.assertEqual((served.client_address, served.bytes_sent, served.transport), ("127.0.0.1", len(body), "HTTP"))

    def tftp(self, opcode, name, *, ack=True):
        server = UDPServer(("127.0.0.1", 0), servers.BootstrapTftpHandler)
        self.addCleanup(server.server_close)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        self.addCleanup(sock.close)
        packets = []

        def client():
            sock.sendto(struct.pack("!H", opcode) + name.encode() + b"\0octet\0", server.server_address)
            while True:
                packet, peer = sock.recvfrom(516)
                packets.append(packet)
                code = struct.unpack("!H", packet[:2])[0]
                if code != servers.DATA:
                    return
                sock.sendto(struct.pack("!HH", servers.ACK, struct.unpack("!H", packet[2:4])[0]), peer)
                if len(packet) - 4 < servers.BLOCK:
                    return

        thread = threading.Thread(target=client)
        thread.start()
        server.handle_request()
        thread.join(5)
        return packets

    def test_tftp_is_read_only_and_transfers_in_blocks(self):
        models.BootstrapArtifact.objects.filter(pk=self.artifact.pk).update(transport="TFTP", content="x" * 1100)
        name = f"ztp/v1/{self.artifact.artifact_id}/startup-config"
        self.assertEqual(struct.unpack("!HH", self.tftp(servers.WRQ, name)[0][:4]), (servers.ERROR, 2))
        self.assertEqual(struct.unpack("!HH", self.tftp(servers.RRQ, "ztp/v1/../../etc/passwd")[0][:4]), (servers.ERROR, 1))
        packets = self.tftp(servers.RRQ, name)
        self.assertEqual([struct.unpack("!HH", p[:4]) for p in packets], [(servers.DATA, 1), (servers.DATA, 2), (servers.DATA, 3)])
        self.assertEqual(b"".join(p[4:] for p in packets), b"x" * 1100)
        self.assertEqual(models.BootstrapDelivery.objects.get(outcome="SERVED").bytes_sent, 1100)
