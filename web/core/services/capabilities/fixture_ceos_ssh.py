"""Pinned SSH to the one disposable capability cEOS over its Docker management bridge.

Docker CLI is used only to attest the fixture identity and read its public host
key out of band. Device configuration and read-back use authenticated SSH.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket

from ..health import live
from .isolated_live import LAB, NETWORK, _run, _target


def _fingerprint(key: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip("=")


class FixtureCeosSsh:
    """One pinned, source-bound fixture session; no agent, key search or route fallback."""

    def __init__(self):
        import paramiko
        from netmiko.arista.arista import AristaSSH

        self.device, _, _ = _target("arista_ceos")
        password = os.environ.get("NMAS_CAP_CEOS_PASSWORD", "")
        if not password:
            raise RuntimeError("NMAS_CAP_CEOS_PASSWORD is required for the disposable cEOS fixture.")
        inspected = _run(["docker", "inspect", self.device["container"]], timeout=10)
        (row,) = json.loads(inspected.stdout)
        network = (row.get("NetworkSettings") or {}).get("Networks", {}).get(NETWORK) or {}
        address = network.get("IPAddress")
        netid = network.get("NetworkID")
        if not address or not netid or row["Config"]["Labels"].get("containerlab") != LAB:
            raise RuntimeError("Disposable cEOS management identity changed.")
        bridge = "br-" + netid[:12]
        route = _run(["ip", "route", "get", address], timeout=5)
        gateway = (network.get("Gateway") or "").strip()
        if route.returncode or f"dev {bridge} " not in route.stdout or f"src {gateway} " not in route.stdout:
            raise RuntimeError("Disposable cEOS management path is not the expected bridge/source.")
        public = _run(["docker", "exec", self.device["container"], "Cli", "-p", "15", "-c",
                       "show management ssh hostkey ed25519 public"], timeout=10)
        keys = [line for line in public.stdout.splitlines() if line.startswith("ssh-ed25519 ")]
        if public.returncode or len(keys) != 1:
            raise RuntimeError("Disposable cEOS public host key is unavailable out of band.")
        expected = _fingerprint(base64.b64decode(keys[0].split()[1]))

        class PinnedHostKey(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self, _client, _hostname, key):
                if _fingerprint(key.asbytes()) != expected:
                    raise paramiko.SSHException("HOST_KEY_MISMATCH")

        class PinnedAristaSSH(AristaSSH):
            def _build_ssh_client(self):
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(PinnedHostKey())
                return client

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn = None
        try:
            sock.settimeout(12)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, bridge.encode() + b"\0")
            sock.bind((gateway, 0))
            sock.connect((address, 22))
            self.conn = PinnedAristaSSH(device_type="arista_eos", host=address, username="admin", password=password,
                                         secret=password, fast_cli=False, conn_timeout=12, auth_timeout=12,
                                         banner_timeout=12, sock=sock, auto_connect=False, allow_agent=False,
                                         use_keys=False, ssh_strict=True, system_host_keys=False, alt_host_keys=False)
            self.conn._open()
            if not self.conn.check_enable_mode():
                self.conn.enable()
        except Exception:
            if self.conn is not None:
                self.conn.disconnect()
            sock.close()
            raise
        self.management = {"address": address, "source": gateway, "bridge": bridge, "host_key": expected}

    def session(self, _device):
        """The allowlisted NMAS health reader over this pinned SSH connection."""
        conn = self.conn

        class ReadSession:
            def run(self, key):
                command = live.CEOS_COMMANDS.get(key)
                if command is None:
                    raise live.LiveError("COMMAND_NOT_ALLOWED")
                return conn.send_command(command, read_timeout=60)

            def close(self):
                pass  # the executor owns this session and closes it after compensation

        return ReadSession()

    def close(self):
        if self.conn is not None:
            self.conn.disconnect()
            self.conn = None
