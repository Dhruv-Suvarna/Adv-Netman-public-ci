"""Lab 7 closure -- V2 Phase 3 delivery servers, ZTP pages and the ``nmas_ztp`` command, each boundary called directly.

``test_ztp_artifacts`` / ``test_ztp_views`` prove refusals and the end-to-end flow; this module proves the positive path of every
server handler, view and command boundary, plus the server helpers' own refusals:

* servers -- HTTP GET and a TFTP read on real 127.0.0.1 sockets, the lock-step block transfer, RRQ parsing, error packets,
  server construction, the background serving thread and request logging (only the client and a format token, never a path);
* pages -- bootstrap-network create / apply / rollback / ingest, session cancel and fail-device, the device-page ZTP card;
* ``nmas_ztp`` -- the read-only adapter report and session status, an authorized network creation, and refusals for an actor
  without the step's permission and for unknown sessions.

Isolated provider root and fake provider commands only (``ZtpTestMixin``); no device, DHCP service or network is touched.
"""
from __future__ import annotations

import io
import json
import socket
import struct
import threading
import urllib.error
import urllib.request
from datetime import timedelta
from http.server import HTTPServer
from socketserver import UDPServer
from unittest import mock

from django.core.management import CommandError, call_command
from django.test import SimpleTestCase, TestCase
from django.urls import reverse
from django.utils import timezone

from core import models, ztp_views
from core.services.ztp import dhcp, servers, workflow
from core.tests.helpers import lifecycle as L
from core.tests.helpers import ztp as Z
from core.tests.test_lifecycle_views import user_client
from core.tests.test_ztp_dhcp import SupervisorRunner

State = models.BootstrapArtifactState


def udp_socket(timeout=2.0) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(timeout)
    return sock


class ServerHelperTests(SimpleTestCase):
    def test_tftp_error_packet_encoding_matches_rfc_1350(self):
        self.assertEqual(servers.tftp_error(1, "file not found"), b"\x00\x05\x00\x01file not found\x00")

    def test_tftp_error_code_beyond_16_bits_raises(self):
        with self.assertRaises(struct.error):
            servers.tftp_error(70000, "x")

    def test_parse_rrq_returns_opcode_filename_and_mode(self):
        self.assertEqual(servers.parse_rrq(b"\x00\x01ztp/v1/ART-a/startup-config\x00OCTET\x00"), (1, "ztp/v1/ART-a/startup-config", "octet"))

    def test_parse_rrq_of_malformed_packets_yields_no_filename(self):
        self.assertEqual(servers.parse_rrq(b"\x00"), (0, "", ""))
        self.assertEqual(servers.parse_rrq(b"\x00\x01name-without-terminator"), (1, "", ""))
        self.assertEqual(servers.parse_rrq(b"\x00\x01\xff\xfe\x00octet\x00"), (1, "", ""))

    def test_send_file_transfers_the_content_in_lock_step_data_packets(self):
        sender, receiver = udp_socket(), udp_socket()
        self.addCleanup(sender.close)
        self.addCleanup(receiver.close)
        received = []

        def peer():
            while True:
                packet, source = receiver.recvfrom(516)
                received.append(packet)
                receiver.sendto(struct.pack("!HH", servers.ACK, struct.unpack("!H", packet[2:4])[0]), source)
                if len(packet) - 4 < servers.BLOCK:
                    return

        thread = threading.Thread(target=peer)
        thread.start()
        sent = servers.send_file(sender, receiver.getsockname(), b"y" * 1024)
        thread.join(5)
        self.assertEqual(sent, 1024)
        self.assertEqual([struct.unpack("!HH", p[:4]) for p in received], [(servers.DATA, 1), (servers.DATA, 2), (servers.DATA, 3)])
        self.assertEqual(len(received[-1]), 4)                         # an exact multiple of 512 ends with an empty block

    def test_send_file_without_acknowledgements_times_out(self):
        sender, silent = udp_socket(timeout=0.05), udp_socket()
        self.addCleanup(sender.close)
        self.addCleanup(silent.close)
        with self.assertRaises(TimeoutError):
            servers.send_file(sender, silent.getsockname(), b"z" * 10)

    def test_make_http_and_tftp_servers_bind_the_service_address(self):
        http_server = servers.make_http_server("127.0.0.1", 0)
        self.addCleanup(http_server.server_close)
        tftp_server = servers.make_tftp_server("127.0.0.1", 0)
        self.addCleanup(tftp_server.server_close)
        self.assertEqual((http_server.server_address[0], http_server.daemon_threads), ("127.0.0.1", True))
        self.assertEqual((tftp_server.server_address[0], tftp_server.daemon_threads, tftp_server.RequestHandlerClass),
                         ("127.0.0.1", True, servers.BootstrapTftpHandler))

    def test_make_servers_with_an_invalid_port_are_refused(self):
        with self.assertRaises(ValueError):
            servers.make_http_server("127.0.0.1", "http")
        with self.assertRaises(ValueError):
            servers.make_tftp_server("127.0.0.1", "tftp")

    def test_serve_forever_in_thread_serves_until_shutdown(self):
        server = servers.make_http_server("127.0.0.1", 0)
        self.addCleanup(server.server_close)
        thread = servers.serve_forever_in_thread(server)
        self.assertTrue(thread.is_alive() and thread.daemon)
        server.shutdown()
        thread.join(5)
        self.assertFalse(thread.is_alive())

    def test_serve_forever_in_thread_of_an_object_that_is_not_a_server_raises(self):
        with self.assertRaises(AttributeError):
            servers.serve_forever_in_thread(object())

    def handler(self):
        handler = servers.BootstrapHttpHandler.__new__(servers.BootstrapHttpHandler)
        handler.client_address = ("127.0.0.1", 40000)
        return handler

    def test_http_log_message_records_the_client_and_the_format_token(self):
        with self.assertLogs("nmas.ztp.delivery", "INFO") as logs:
            self.handler().log_message('"%s" %s %s', "GET /ztp/v1/ART-x/startup-config HTTP/1.0", "200", "-")
        self.assertEqual(logs.output, ['INFO:nmas.ztp.delivery:http 127.0.0.1 "%s"'])

    def test_http_log_message_never_logs_the_request_path(self):
        with self.assertLogs("nmas.ztp.delivery", "INFO") as logs:
            self.handler().log_message("%s", "GET /ztp/v1/ART-secretpath/startup-config")
            self.handler().log_message("")
        self.assertFalse(any("ART-secretpath" in line for line in logs.output))
        self.assertEqual(logs.output[-1], "INFO:nmas.ztp.delivery:http 127.0.0.1 ")


@mock.patch("core.services.ztp.servers.close_old_connections", lambda: None)   # the test's own DB connection stays open
class DeliveryHandlerTests(Z.ZtpTestMixin, TestCase):
    """The real handlers on 127.0.0.1; the server handles one request in the test thread, the client runs in a helper thread."""

    def setUp(self):
        super().setUp()
        self.session = self.open_session()
        self.artifact = self.session.artifacts.get(state=State.ACTIVE)
        models.DhcpLeaseObservation.objects.create(
            network=self.session.network, session=self.session, device=self.session.device, idempotency_key="loopback", provider="ISC_DHCP",
            address="127.0.0.1", client_mac="a2:27:1c:9a:b6:7b", client_id=Z.CLIENT_ID, vendor_class=Z.VENDOR, relay_address=Z.RELAY,
            circuit_id="Ethernet7", relay_trusted=True, upstream_device="S1", upstream_interface="Ethernet7", binding_state="active",
            lease_ends=timezone.now() + timedelta(minutes=10), outcome=models.DhcpLeaseOutcome.CORRELATED, last_seen=timezone.now())

    def test_http_get_serves_the_artifact_bytes_to_the_bound_requester(self):
        server = HTTPServer(("127.0.0.1", 0), servers.BootstrapHttpHandler)
        self.addCleanup(server.server_close)
        url = f"http://127.0.0.1:{server.server_address[1]}/ztp/v1/{self.artifact.artifact_id}/startup-config"
        result = {}

        def client():
            with urllib.request.urlopen(url, timeout=5) as response:
                result["value"] = (response.status, response.headers["Cache-Control"], response.read())

        thread = threading.Thread(target=client)
        thread.start()
        server.handle_request()
        thread.join(5)
        self.assertEqual(result["value"], (200, "no-store", self.artifact.content.encode()))
        self.assertEqual(models.BootstrapAuthorization.objects.get(pk=self.session.authorization_id).use_count, 1)

    def test_tftp_read_request_transfers_the_artifact_to_the_bound_requester(self):
        models.BootstrapArtifact.objects.filter(pk=self.artifact.pk).update(transport="TFTP")
        server = UDPServer(("127.0.0.1", 0), servers.BootstrapTftpHandler)
        self.addCleanup(server.server_close)
        sock = udp_socket(timeout=5)
        self.addCleanup(sock.close)
        data = []

        def client():
            sock.sendto(b"\x00\x01" + f"ztp/v1/{self.artifact.artifact_id}/startup-config".encode() + b"\x00octet\x00", server.server_address)
            while True:
                packet, peer = sock.recvfrom(516)
                data.append(packet[4:])
                sock.sendto(struct.pack("!HH", servers.ACK, struct.unpack("!H", packet[2:4])[0]), peer)
                if len(packet) - 4 < servers.BLOCK:
                    return

        thread = threading.Thread(target=client)
        thread.start()
        server.handle_request()
        thread.join(5)
        self.assertEqual(b"".join(data), self.artifact.content.encode())
        self.assertEqual(models.BootstrapDelivery.objects.get(outcome="SERVED").transport, "TFTP")


class ZtpPageClosureTests(Z.ZtpTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.approver = user_client("arthur", "NMAS Approver")
        self.executor = user_client("erin", "NMAS Executor")
        self.validator = user_client("olivia", "NMAS Operator")
        self.viewer = user_client("vera", "NMAS Viewer")
        real = dhcp.for_network
        patcher = mock.patch("core.services.ztp.dhcp.for_network",
                             lambda network, runner=None: real(network, runner=SupervisorRunner(self.root / "dhcp")))
        patcher.start()
        self.addCleanup(patcher.stop)

    def session_url(self, name, session):
        return reverse(f"core:{name}", args=[session.device.device_id, session.session_id])

    def test_codes_wrapper_of_an_empty_list_is_ok(self):
        codes = ztp_views._Codes([])
        self.assertEqual((codes.ok, codes.codes), (True, []))

    def test_codes_wrapper_of_refused_steps_is_a_refusal(self):
        codes = ztp_views._Codes([{"code": "VLAN200_PURPOSE_FORBIDDEN"}, {"code": "NAME_COLLISION"}])
        self.assertEqual((codes.ok, codes.codes), (False, ["VLAN200_PURPOSE_FORBIDDEN", "NAME_COLLISION"]))

    def test_device_panel_lists_the_adapter_paths_and_the_open_session(self):
        session = self.open_session()
        device = models.ManagedDevice.objects.get(pk=session.device_id)
        panel = ztp_views.device_panel(device)
        self.assertEqual((panel["adapter"]["adapter"], panel["open_session"], panel["open"]["session"]), ("arista_eos", session, session.session_id))
        self.assertEqual([n.name for n in panel["networks"]], ["ztp-test"])

    def test_device_panel_without_an_approved_authorization_offers_no_bootstrap_path(self):
        L.adopt()
        device = L.register().device
        panel = ztp_views.device_panel(device)
        self.assertEqual((panel["approved"], panel["paths"], panel["open"], panel["downstream"]), ([], [], None, []))

    def test_networks_page_shows_the_refusal_codes_of_a_refused_action(self):
        response = self.viewer.get(reverse("core:ztp_networks") + "?codes=VLAN200_PURPOSE_FORBIDDEN")
        self.assertContains(response, "VLAN200_PURPOSE_FORBIDDEN")

    def test_network_create_with_an_invalid_name_is_refused(self):
        response = self.approver.post(reverse("core:ztp_network_create"), {**Z.NET, "name": "bad name!", "trusted_relays": f"{Z.RELAY}=S1",
                                                                           "config_root": str(self.root / "dhcp")})
        self.assertIn("NAME_INVALID", response.url)
        self.assertFalse(models.BootstrapNetwork.objects.exists())

    def test_network_apply_writes_the_isolated_provider_and_records_applied(self):
        session = self.open_session()
        response = self.executor.post(reverse("core:ztp_network_apply", args=[session.network.name]))
        self.assertNotIn("codes=", response.url)
        self.assertEqual(session.network.applications.get().state, "APPLIED")
        self.assertTrue((self.root / "dhcp" / "dhcpd.conf").exists())

    def test_network_rollback_restores_the_previous_policy(self):
        session = self.open_session()
        self.executor.post(reverse("core:ztp_network_apply", args=[session.network.name]))
        self.executor.post(reverse("core:ztp_network_apply", args=[session.network.name]))
        response = self.executor.post(reverse("core:ztp_network_rollback", args=[session.network.name]))
        self.assertNotIn("codes=", response.url)
        self.assertEqual(session.network.applications.order_by("-id").first().state, "ROLLED_BACK")

    def test_network_ingest_reads_the_provider_lease_database(self):
        session = self.open_session()
        (self.root / "dhcp" / "dhcpd.leases").write_text(Z.lease(), encoding="utf-8")
        response = self.validator.post(reverse("core:ztp_network_ingest", args=[session.network.name]))
        self.assertNotIn("codes=", response.url)
        self.assertEqual(session.lease_observations.get().outcome, models.DhcpLeaseOutcome.CORRELATED)

    def test_session_cancel_closes_the_session(self):
        session = self.open_session()
        response = self.approver.post(self.session_url("ztp_session_cancel", session), {"reason": "re-plan the bootstrap network"})
        self.assertNotIn("codes=", response.url)
        session.refresh_from_db()
        self.assertEqual(session.stage, models.ZtpSessionStage.CANCELLED)

    def test_session_fail_device_succeeds_for_a_discovered_device_after_a_closed_session(self):
        session = self.discovered()
        workflow.record_failure(session, "HOST_KEY_MISMATCH", retryable=False, actor=L.APPROVER)
        response = self.approver.post(self.session_url("ztp_session_fail_device", session), {"confirm_name": session.device.name})
        self.assertNotIn("codes=", response.url)
        self.assertEqual(models.ManagedDevice.objects.get(pk=session.device_id).lifecycle_state, models.DeviceLifecycleState.FAILED)


class NmasZtpCommandTests(Z.ZtpTestMixin, TestCase):
    def call(self, *args) -> str:
        out = io.StringIO()
        call_command("nmas_ztp", *args, stdout=out)
        return out.getvalue()

    def test_adapters_and_status_print_the_read_only_reports(self):
        report = json.loads(self.call("adapters"))
        self.assertIn("arista_eos", {r["adapter"] for r in report})
        session = self.open_session()
        status = json.loads(self.call("status", "--session", session.session_id))
        self.assertEqual((status["session"], status["production_admission"]["allowed"]), (session.session_id, False))

    def test_network_create_by_an_authorized_actor_records_the_network(self):
        L.adopt()
        user_client("arthur", "NMAS Approver")
        out = self.call("network-create", "--name", "ztp-cli", "--prefix", Z.NET["ipv4_prefix"], "--gateway", Z.NET["gateway"],
                        "--pool-start", Z.NET["pool_start"], "--pool-end", Z.NET["pool_end"], "--service-prefix", Z.NET["service_prefix"],
                        "--service-address", Z.NET["service_address"], "--relay", f"{Z.RELAY}=S1", "--config-root", str(self.root / "dhcp"),
                        "--actor", "arthur")
        self.assertIn("bootstrap network ztp-cli recorded", out)
        self.assertEqual(models.BootstrapNetwork.objects.get().created_by, "arthur")

    def test_command_refuses_an_actor_without_permission_and_unknown_sessions(self):
        user_client("vera", "NMAS Viewer")
        with self.assertRaises(CommandError):
            self.call("dhcp-apply", "--network", "ztp-test", "--actor", "vera")
        with self.assertRaises(CommandError):
            self.call("status", "--session", "ZTP-999999")
        self.assertFalse(models.DhcpProviderApplication.objects.exists())
