#!/usr/bin/env python3
"""Real NETCONF-over-SSH server -- the NMAS Linux/FRR telemetry ADAPTER,
Part B (see docs/STREAMING_TELEMETRY_IMPLEMENTATION.md "R3/R4 adapter").

R3/R4 have no native NETCONF server, and installing a full standards stack
(Netopeer2/sysrepo) was evaluated and rejected: Ubuntu 24.04's `noble`
repository ships `libnetconf2`/`sysrepo` as libraries only, not a
`netopeer2-server` binary -- building one from source was judged
disproportionate to a lab router's resource budget and this session's time
(see docs/STREAMING_TELEMETRY_IMPLEMENTATION.md for the comparison). This is
instead a minimal, real implementation of the actual NETCONF-over-SSH wire
protocol (RFC 6242 framing, RFC 6241 `<hello>`/`<get>`/`<rpc-reply>`) using
`paramiko` as an SSH *server* (already Debian/Ubuntu-packaged,
`python3-paramiko`) -- not a fake TCP/JSON service.

Deliberately, honestly scoped (advertised capabilities match exactly what's
implemented, nothing more):
  - urn:ietf:params:netconf:base:1.0 ONLY (no :base:1.1 chunked framing --
    EOM `]]>]]>` framing only, to keep the parser small and correct)
  - <get> with a subtree filter for openconfig-system (hostname) or
    openconfig-interfaces (interface name list) -- the exact two shapes
    modules/netconf.py's verification client sends. No general XPath/full
    subtree filter engine.
  - <close-session> (clean shutdown). No <get-config>/<edit-config>/
    <copy-config> -- this is a read-only adapter; those RPCs get a real
    NETCONF <rpc-error> with operation-not-supported, not a silent success.
  - No :candidate/:writable-running/:startup capabilities are advertised,
    because none of them are implemented.

All returned data is live: read from nmas_linux_telemetry_metrics.py at
request time, same as the gNMI adapter (linux_gnmi_server.py) -- both
adapters share that one metrics module so "gNMI says X" and "NETCONF says X"
can never disagree about what the router's real state is.
"""
import pathlib
import socket
import sys
import threading
import time
import xml.etree.ElementTree as ET
from xml.sax.saxutils import quoteattr

import paramiko

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nmas_linux_telemetry_metrics as metrics  # noqa: E402

ETC = pathlib.Path("/etc/nmas-telemetry")
LOG_PATH = pathlib.Path("/var/log/nmas-netconf-adapter.log")
EOM = b"]]>]]>"

HELLO_CAPS = [
    "urn:ietf:params:netconf:base:1.0",
    "http://openconfig.net/yang/system?module=openconfig-system (subset: state/hostname only)",
    "http://openconfig.net/yang/interfaces?module=openconfig-interfaces (subset: interface/name list only)",
]

SERVER_HELLO = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">\n'
    "  <capabilities>\n"
    + "".join(f"    <capability>{c}</capability>\n" for c in HELLO_CAPS)
    + "  </capabilities>\n</hello>\n"
).encode()


def log(message):
    try:
        with LOG_PATH.open("a") as f:
            f.write(time.strftime("%Y-%m-%dT%H:%M:%S ") + message + "\n")
    except OSError:
        pass


def load_env(name):
    return dict(line.split("=", 1) for line in (ETC / name).read_text().splitlines() if "=" in line)


def load_or_create_host_key():
    # RSAKey.generate() is supported on the older paramiko (2.12) apt ships
    # on Ubuntu 24.04; Ed25519Key has no .generate() there.
    path = ETC / "netconf_host_key"
    if path.exists():
        return paramiko.RSAKey.from_private_key_file(str(path))
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(path))
    path.chmod(0o600)
    return key


def rpc_reply(message_id, body):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id={quoteattr(message_id)}>'
        f"{body}</rpc-reply>\n"
    ).encode()


def error_reply(message_id, tag="operation-not-supported"):
    body = (
        f"<rpc-error><error-type>application</error-type><error-tag>{tag}</error-tag>"
        "<error-severity>error</error-severity>"
        "<error-message>This read-only NMAS Linux/FRR telemetry adapter implements &lt;get&gt; "
        "for openconfig-system/openconfig-interfaces only; see docs/STREAMING_TELEMETRY_IMPLEMENTATION.md.</error-message>"
        "</rpc-error>"
    )
    return rpc_reply(message_id, body)


def build_system_data():
    return f'<data><system xmlns="http://openconfig.net/yang/system"><state><hostname>{metrics.hostname()}</hostname></state></system></data>'


def build_interfaces_data():
    names = sorted(metrics.interfaces().keys())
    entries = "".join(f"<interface><name>{n}</name></interface>" for n in names)
    return f'<data><interfaces xmlns="http://openconfig.net/yang/interfaces">{entries}</interfaces></data>'


def local_name(tag):
    return tag.rsplit("}", 1)[-1]


def parse_rpc(raw):
    """Parse one NETCONF RPC independently of the client's XML prefix.

    ncclient serializes operations as ``<nc:get>``/``<nc:close-session>``;
    other clients may use a default namespace or a different prefix.  XML
    expanded names, rather than raw-string spelling, are authoritative.
    """
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return "0", None, None
    message_id = next(
        (value for attr, value in root.attrib.items() if local_name(attr) == "message-id"),
        "0",
    )
    operation = next(iter(root), None)
    return message_id, local_name(operation.tag) if operation is not None else None, operation


def handle_get(message_id, operation):
    """Only the two filter shapes modules/netconf.py's verification client
    sends are recognized -- see module docstring. Anything else (or no
    filter) conservatively returns both blocks, since this adapter has
    nothing else to withhold."""
    descendants = list(operation.iter())
    wants_system = any(
        elem.tag.startswith("{http://openconfig.net/yang/system}")
        or local_name(elem.tag) in ("system", "hostname")
        for elem in descendants
    )
    wants_interfaces = any(
        elem.tag.startswith("{http://openconfig.net/yang/interfaces}")
        or local_name(elem.tag) in ("interfaces", "interface")
        for elem in descendants
    )
    if wants_system and not wants_interfaces:
        return rpc_reply(message_id, build_system_data())
    if wants_interfaces and not wants_system:
        return rpc_reply(message_id, build_interfaces_data())
    # No recognizable filter -- return both rather than guess incorrectly.
    sys_data = build_system_data().replace("<data>", "").replace("</data>", "")
    if_data = build_interfaces_data().replace("<data>", "").replace("</data>", "")
    return rpc_reply(message_id, f"<data>{sys_data}{if_data}</data>")


def dispatch(raw: str):
    """Return ``(rpc-reply bytes, close_after_reply)`` for one parsed RPC."""
    message_id, operation_name, operation = parse_rpc(raw)
    if operation_name == "get":
        return handle_get(message_id, operation), False
    if operation_name == "close-session":
        return rpc_reply(message_id, "<ok/>"), True
    if operation_name is None:
        return error_reply(message_id, tag="malformed-message"), False
    return error_reply(message_id, tag="operation-not-supported"), False


def read_framed(channel) -> str:
    buf = b""
    while EOM not in buf:
        chunk = channel.recv(65536)
        if not chunk:
            return ""
        buf += chunk
    return buf.split(EOM, 1)[0].decode(errors="replace")


def write_framed(channel, payload: bytes):
    channel.sendall(payload + EOM)


def serve_session(channel, peer):
    log(f"session start peer={peer}")
    try:
        write_framed(channel, SERVER_HELLO)
        client_hello = read_framed(channel)
        if "urn:ietf:params:netconf:base:1.0" not in client_hello and "urn:ietf:params:netconf:base:1.1" not in client_hello:
            log(f"peer={peer}: no compatible base capability in client hello")
            return
        while True:
            raw = read_framed(channel)
            if not raw:
                break
            log(f"peer={peer}: request={raw!r}")
            reply, close_after_reply = dispatch(raw)
            write_framed(channel, reply)
            if close_after_reply:
                break
    except (OSError, EOFError) as exc:
        log(f"peer={peer}: session error {exc!r}")
    finally:
        log(f"session end peer={peer}")
        try:
            channel.close()
        except OSError:
            pass


class NetconfServerInterface(paramiko.ServerInterface):
    def __init__(self, creds):
        super().__init__()
        self._creds = creds
        self.subsystem_ok = threading.Event()

    def check_auth_password(self, username, password):
        if username == self._creds.get("TELEMETRY_USERNAME") and password == self._creds.get("TELEMETRY_PASSWORD"):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_subsystem_request(self, channel, name):
        if name == "netconf":
            self.subsystem_ok.set()
            return True
        return False


def handle_connection(sock, addr, host_key, creds):
    transport = None
    try:
        transport = paramiko.Transport(sock)
        transport.add_server_key(host_key)
        server = NetconfServerInterface(creds)
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel is None:
            return
        if not server.subsystem_ok.wait(10):
            log(f"peer={addr}: no netconf subsystem request within timeout")
            return
        serve_session(channel, addr)
    except (paramiko.SSHException, OSError, EOFError) as exc:
        log(f"peer={addr}: transport error {exc!r}")
    finally:
        if transport is not None:
            transport.close()


def main():
    address = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 830
    host_key = load_or_create_host_key()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((address, port))
    listener.listen(4)
    log(f"listening on {address}:{port}")
    while True:
        sock, addr = listener.accept()
        creds = load_env("credentials.env")
        threading.Thread(target=handle_connection, args=(sock, addr, host_key, creds), daemon=True).start()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        log(f"FATAL {exc!r}")
        raise
