"""The NMAS bootstrap delivery servers: read-only HTTP and read-only TFTP (RFC 1350), thin shells over ``artifacts``.

They serve nothing from disk.  Every request goes through ``artifacts.authorize`` and leaves a ``BootstrapDelivery`` row; the
requester only ever sees the artifact or one uniform "not found".  No request path, query or header is logged -- only its
SHA-256 digest -- and no write method exists (HTTP answers 405 to everything but GET, a TFTP WRQ gets "access violation").
"""

from __future__ import annotations

import logging
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import BaseRequestHandler, ThreadingUDPServer

from django.db import close_old_connections

from ... import models
from . import artifacts

log = logging.getLogger("nmas.ztp.delivery")
SERVED, REFUSED, FAILED = models.BootstrapDeliveryOutcome.SERVED, models.BootstrapDeliveryOutcome.REFUSED, models.BootstrapDeliveryOutcome.FAILED


def _deliver(path: str, client: str, transport: str):
    try:
        return artifacts.authorize(path, client, transport)
    except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - a broken request must never become a served file
        log.exception("bootstrap delivery decision failed")
        return artifacts.DeliveryDecision(False, code="INTERNAL_ERROR")


# --- HTTP -----------------------------------------------------------------------------------------------------------------------
class BootstrapHttpHandler(BaseHTTPRequestHandler):
    server_version = "NMAS-bootstrap"
    sys_version = ""
    protocol_version = "HTTP/1.0"

    def do_GET(self):  # noqa: N802 - http.server API
        self._serve()

    def _refuse(self, status=404, reason=b"not found\n"):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(reason)))
        self.end_headers()
        self.wfile.write(reason)

    def _deny_method(self):
        self._refuse(405, b"method not allowed\n")

    # HEAD too: a delivery decision consumes an authorization use, so only a request that receives the bytes may make one
    do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _deny_method  # noqa: N815

    def _serve(self):
        client = self.client_address[0]
        try:
            decision = _deliver(self.path, client, "HTTP")
            if not decision.ok:
                artifacts.record(decision, client_address=client, transport="HTTP", outcome=REFUSED)
                self._refuse()
                return
            self.send_response(200)
            self.send_header("Content-Type", decision.content_type)
            self.send_header("Content-Length", str(len(decision.content)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            sent = 0
            try:
                self.wfile.write(decision.content)
                sent = len(decision.content)
                outcome = SERVED
            except OSError:
                outcome = FAILED
            artifacts.record(decision, client_address=client, transport="HTTP", outcome=outcome, bytes_sent=sent)
        finally:
            close_old_connections()

    def log_message(self, format, *args):  # noqa: A002 - never log the request line (it is a path)
        log.info("http %s %s", self.client_address[0], format.split(" ")[0] if format else "")


def make_http_server(address: str, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((address, int(port)), BootstrapHttpHandler)
    server.daemon_threads = True
    return server


# --- TFTP (RFC 1350, read requests only, octet / netascii, 512-byte blocks) --------------------------------------------------
RRQ, WRQ, DATA, ACK, ERROR = 1, 2, 3, 4, 5
BLOCK = 512
TIMEOUT, RETRIES = 2.0, 5


def tftp_error(code: int, message: str) -> bytes:
    return struct.pack("!HH", ERROR, code) + message.encode() + b"\0"


def parse_rrq(packet: bytes):
    """-> (opcode, filename, mode) or (opcode, '', '') when malformed."""
    if len(packet) < 4:
        return 0, "", ""
    opcode = struct.unpack("!H", packet[:2])[0]
    parts = packet[2:].split(b"\0")
    if len(parts) < 3:
        return opcode, "", ""
    try:
        return opcode, parts[0].decode("ascii"), parts[1].decode("ascii").lower()
    except UnicodeDecodeError:
        return opcode, "", ""


def send_file(sock: socket.socket, peer, content: bytes) -> int:
    """Lock-step DATA/ACK transfer from a fresh transfer socket -> bytes acknowledged (raises TimeoutError on loss)."""
    block, offset = 1, 0
    while True:
        chunk = content[offset:offset + BLOCK]
        packet = struct.pack("!HH", DATA, block & 0xFFFF) + chunk
        for _ in range(RETRIES):
            sock.sendto(packet, peer)
            try:
                reply, source = sock.recvfrom(516)
            except socket.timeout:
                continue
            if source != peer:
                sock.sendto(tftp_error(5, "unknown transfer id"), source)
                continue
            if len(reply) >= 4 and struct.unpack("!HH", reply[:4]) == (ACK, block & 0xFFFF):
                break
        else:
            raise TimeoutError("tftp transfer timed out")
        offset += len(chunk)
        if len(chunk) < BLOCK:
            return offset
        block += 1


class BootstrapTftpHandler(BaseRequestHandler):
    def handle(self):
        packet, listener = self.request
        peer = self.client_address
        opcode, filename, mode = parse_rrq(packet)
        if opcode == WRQ:
            listener.sendto(tftp_error(2, "access violation"), peer)
            return
        if opcode != RRQ or not filename or mode not in ("octet", "netascii"):
            listener.sendto(tftp_error(4, "illegal operation"), peer)
            return
        try:
            decision = _deliver("/" + filename.lstrip("/"), peer[0], "TFTP")
            if not decision.ok:
                artifacts.record(decision, client_address=peer[0], transport="TFTP", outcome=REFUSED)
                listener.sendto(tftp_error(1, "file not found"), peer)
                return
            transfer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            transfer.settimeout(TIMEOUT)
            transfer.bind((self.server.server_address[0], 0))
            try:
                sent = send_file(transfer, peer, decision.content)
                artifacts.record(decision, client_address=peer[0], transport="TFTP", outcome=SERVED, bytes_sent=sent)
            except (TimeoutError, OSError):
                artifacts.record(decision, client_address=peer[0], transport="TFTP", outcome=FAILED)
            finally:
                transfer.close()
        finally:
            close_old_connections()


def make_tftp_server(address: str, port: int) -> ThreadingUDPServer:
    server = ThreadingUDPServer((address, int(port)), BootstrapTftpHandler)
    server.daemon_threads = True
    return server


def serve_forever_in_thread(server) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread
