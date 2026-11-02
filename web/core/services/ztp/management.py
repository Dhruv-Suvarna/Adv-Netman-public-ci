"""Initial management contact and verification over the bootstrap network -- SSH only, host key pinned, never Docker exec.

``observe_host_key`` performs the SSH key exchange and nothing else: no authentication, no command.  The key it returns is a
first-seen key and is NEVER trusted by itself (see ``workflow.enroll_host_key``).

``run_commands`` authenticates with the session's enrollment private key (read from the protected runtime provider at use
time, never stored elsewhere) and accepts the server only if its key matches the ENROLLED fingerprint exactly -- a different
or unknown key aborts before authentication.  Host-key checking is never disabled.
"""

from __future__ import annotations

import base64
import hashlib
import io
import socket

from django.conf import settings

CONNECT_TIMEOUT = 10
COMMAND_TIMEOUT = 30
MAX_OUTPUT = 256 * 1024


class ManagementError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code = code
        self.detail = str(detail)[:300]


def fingerprint(key) -> str:
    """OpenSSH ``SHA256:<base64>`` fingerprint of a paramiko public key."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def observe_host_key(address: str, port: int = 22, timeout: int = CONNECT_TIMEOUT) -> str:
    import paramiko

    try:
        sock = socket.create_connection((address, int(port)), timeout=timeout)
    except OSError as exc:
        raise ManagementError("MANAGEMENT_UNREACHABLE", type(exc).__name__) from None
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=timeout)
        return fingerprint(transport.get_remote_server_key())
    except (paramiko.SSHException, OSError, EOFError) as exc:
        raise ManagementError("MANAGEMENT_UNREACHABLE", type(exc).__name__) from None
    finally:
        transport.close()


def secret_provider():
    from modules.device_credentials import FileSecretProvider

    path = getattr(settings, "NMAS_ZTP_ENROLLMENT_STORE", None)
    return FileSecretProvider(path) if path else FileSecretProvider()


def load_private_key(reference: str):
    import paramiko

    material = secret_provider().current(reference).value
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key(io.StringIO(material))
        except (paramiko.SSHException, ValueError):
            continue
    raise ManagementError("MANAGEMENT_AUTH_FAILED", "the enrollment key could not be loaded")


def run_commands(address: str, *, username: str, key_reference: str, enrolled_host_key: str, commands, port: int = 22) -> dict:
    """-> {"host_key": fingerprint, "outputs": {command: text}}.  Raises ManagementError with a stable code."""
    import paramiko

    if not enrolled_host_key:
        raise ManagementError("HOST_KEY_NOT_ENROLLED")

    class PinnedHostKey(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            if fingerprint(key) != enrolled_host_key:
                raise ManagementError("HOST_KEY_MISMATCH", "the presented host key is not the enrolled one")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(PinnedHostKey())
    try:
        client.connect(address, port=int(port), username=username, pkey=load_private_key(key_reference), timeout=CONNECT_TIMEOUT,
                       banner_timeout=CONNECT_TIMEOUT, auth_timeout=CONNECT_TIMEOUT, allow_agent=False, look_for_keys=False)
        presented = fingerprint(client.get_transport().get_remote_server_key())
        if presented != enrolled_host_key:
            raise ManagementError("HOST_KEY_MISMATCH")
        outputs = {}
        for command in commands:
            _stdin, stdout, _stderr = client.exec_command(command, timeout=COMMAND_TIMEOUT)
            outputs[command] = stdout.read(MAX_OUTPUT).decode("utf-8", "replace")
        return {"host_key": presented, "outputs": outputs}
    except paramiko.AuthenticationException:
        raise ManagementError("MANAGEMENT_AUTH_FAILED") from None
    except (paramiko.SSHException, OSError, EOFError) as exc:
        raise ManagementError("MANAGEMENT_UNREACHABLE", type(exc).__name__) from None
    finally:
        client.close()
