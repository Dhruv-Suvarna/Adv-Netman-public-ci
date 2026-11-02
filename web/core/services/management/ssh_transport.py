"""Open a cEOS SSH session over the active, approved NMAS management attachment.

The probe's success is not a route guarantee for a later connection.  This
module binds the actual socket to both the registered source address and host
interface, and checks the path's pinned host key before offering credentials.
It does not alter host routing or use Docker/Containerlab management access.
"""

from __future__ import annotations

import ipaddress
import socket
from contextlib import suppress

from ... import models
from . import guard, probes, resolve


class ManagedConnectionRejected(Exception):
    """An approved path cannot be enforced for this connection."""


def active_path(target: dict):
    """Re-read the selected path immediately before connection establishment."""
    selected = target.get("management") or {}
    if selected.get("source") != resolve.PATH:
        raise ManagedConnectionRejected("NO_SELECTED_PATH")
    path_id = selected.get("path_id", "")
    try:
        pk = int(path_id.removeprefix("MPATH-")) if path_id.startswith("MPATH-") else 0
    except ValueError:
        pk = 0
    path = models.ManagementPath.objects.select_related("device", "nmas_attachment", "device_credential").filter(pk=pk).first()
    if path is None or path.path_id != path_id or path.device.name != target.get("device_name"):
        raise ManagedConnectionRejected("PATH_CHANGED")
    stored, problems = guard.authorized_target(path)
    current = resolve.endpoint(path.device.name, purpose=target.get("purpose", resolve.READ))
    if problems or stored is None or current.source != resolve.PATH or current.path_id != path_id:
        raise ManagedConnectionRejected("PATH_CHANGED")
    if path.endpoint_address != target.get("address") or path.port != selected.get("port"):
        raise ManagedConnectionRejected("ENDPOINT_CHANGED")
    if path.transport != models.ManagementTransport.SSH or not path.expected_host_key:
        raise ManagedConnectionRejected("SSH_NOT_PINNED")
    attachment = path.nmas_attachment
    if attachment.verification_state != models.AttachmentVerification.VERIFIED:
        raise ManagedConnectionRejected("ATTACHMENT_UNVERIFIED")
    return path


def bound_socket(path, timeout: float) -> socket.socket:
    """Connect through precisely the registered host interface and source."""
    attachment = path.nmas_attachment
    address = ipaddress.ip_address(path.endpoint_address)
    source = ipaddress.ip_address(attachment.source_address)
    if address.version != source.version or not hasattr(socket, "SO_BINDTODEVICE"):
        raise ManagedConnectionRejected("BIND_UNAVAILABLE")
    sock = socket.socket(socket.AF_INET6 if address.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, attachment.host_interface.encode("ascii") + b"\x00")
        sock.bind((str(source), 0))
        sock.connect((str(address), path.port))
        return sock
    except (OSError, UnicodeError, ValueError) as exc:
        sock.close()
        raise ManagedConnectionRejected("BOUND_CONNECT_FAILED") from exc


def connect_eos(target: dict, auth: dict, timeout: float):
    """Netmiko on the pinned, bound socket; no agent/key-file or route fallback."""
    from netmiko import ConnectHandler

    kwargs = {
        "device_type": "arista_eos", "host": target["address"], "username": auth["username"],
        "password": auth.get("password", ""), "secret": auth.get("password", ""), "fast_cli": False,
        "conn_timeout": timeout, "auth_timeout": timeout, "banner_timeout": timeout,
        **auth.get("ssh_auth", {}),
    }
    if target.get("pinned_host_key"):           # V2 Phase 6 commissioning transport: pinned ZTP host key, key-only
        from ..commissioning.transport import connect_pinned

        return connect_pinned(target, auth, timeout)
    # Netmiko's use_keys flag means "look for a key_file" and rejects an in-memory pkey without one; Paramiko receives the pkey
    # independently (V2 Phase 5/6 finding: a key-only cEOS inventory account could never connect on the legacy branch).
    if kwargs.get("pkey") is not None:
        kwargs["use_keys"] = False
    if (target.get("management") or {}).get("source") != resolve.PATH:
        return ConnectHandler(**kwargs)

    import paramiko
    from netmiko.arista.arista import AristaSSH

    path = active_path(target)
    expected = path.expected_host_key
    refused = []

    class PinnedHostKey(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, _client, _hostname, key):
            if probes.fingerprint(key) != expected:
                refused.append(probes.fingerprint(key))
                raise paramiko.SSHException("HOST_KEY_MISMATCH")

    class BoundAristaSSH(AristaSSH):
        def _build_ssh_client(self):
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(PinnedHostKey())
            return client

    sock = bound_socket(path, timeout)
    conn = None
    try:
        kwargs.update({"port": path.port, "sock": sock, "auto_connect": False, "allow_agent": False,
                       "ssh_strict": True, "system_host_keys": False, "alt_host_keys": False})
        conn = BoundAristaSSH(**kwargs)
        conn._open()
        return conn
    except Exception as exc:
        if conn is not None:
            with suppress(Exception):  # preserve the original connection failure during best-effort cleanup
                conn.disconnect()
        sock.close()
        if refused:
            # Netmiko re-raises every Paramiko SSHException as a *timeout*; a pinned-key refusal is not one (found live, V2 Phase 8)
            raise ManagedConnectionRejected("HOST_KEY_MISMATCH") from exc
        raise
