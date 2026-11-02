"""The authorized SSH transport to an Ubuntu/FRR device (V2 Phase 9): replaces ``docker exec`` for the trusted-upstream
isolation executor.

Who may be reached, and how, is decided by the same inventory resolver every other executor uses
(``nsot_live.get_live_target_metadata``): a ``linux`` device in WRITABLE scope with a declared management address, its
dedicated automation account (``username``) and a provider REFERENCE to its private key (``ssh_key_ref``).  On top of that this
transport requires, and checks before any credential is offered:

* a pinned host key (``ssh_host_key``: ``SHA256:<base64>`` in the device's inventory entry) -- an unknown or different
  key refuses the session (no trust-on-first-use, no system ``known_hosts``);
* key-only authentication from the provider (no agent, no key files, no password);
* the legacy management source only: Linux devices cannot register a management path yet (``paths.VERIFIED_PLATFORMS``),
  so a device that somehow has one is refused rather than reached by a different route.

Commands are argv lists.  Each token is quoted with ``shlex.quote`` (the remote login shell sees exactly one word per
token; a multi-line nftables ruleset stays one single-quoted word -- newlines are literal inside single quotes).  A token
with a NUL byte cannot be carried and is refused.  ``nft`` and ``vtysh`` run through ``sudo -n`` when the account is not root (the
device grants the account exactly those two programs); nothing else is elevated.  Every failure is a sanitized
``ExecutorError`` code; no host, key or output detail leaves this module in an exception.
"""

from __future__ import annotations

import re
import shlex
import socket

from ..execution.executors.base import ExecutorError

PRIVILEGED = frozenset({"nft", "vtysh"})
_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
_TOKEN = re.compile(r"^[^\x00]*$")
_SHOW = re.compile(r"^show [A-Za-z0-9 ._:/-]+$")


def frr_show(command: str) -> list[str]:
    """The argv of one read-only FRR shell query: ``show ...`` only (no configure, no chaining, no shell metacharacters).

    Execution modules never spell the FRR shell's argv themselves; this is the one place it is built, and it builds reads only.
    """
    if not isinstance(command, str) or not _SHOW.fullmatch(command) or "  " in command:
        raise ExecutorError("UNSUPPORTED")
    return ["vtysh", "-c", command]


def command_line(argv, username: str) -> str:
    """The exact remote command for ``argv``: shell-quoted tokens, ``sudo -n --`` for the privileged programs."""
    if not argv or not all(isinstance(token, str) and _TOKEN.fullmatch(token) for token in argv):
        raise ExecutorError("UNSUPPORTED")
    prefix = ["sudo", "-n", "--"] if username != "root" and argv[0] in PRIVILEGED else []
    return shlex.join([*prefix, *argv])


class LinuxSession:
    """One open SSH connection; ``run(argv, timeout) -> (exit status, stdout)``."""

    def __init__(self, client, username: str):
        self._client = client
        self.username = username

    def run(self, argv, timeout: float) -> tuple[int, str]:
        command = command_line(argv, self.username)
        import paramiko

        try:
            stdin, stdout, _stderr = self._client.exec_command(command, timeout=timeout)
            stdin.close()
            out = stdout.read().decode("utf-8", "replace")
            code = stdout.channel.recv_exit_status()
        except socket.timeout as exc:
            raise ExecutorError("TIMEOUT") from exc
        except (paramiko.SSHException, OSError, EOFError) as exc:
            raise ExecutorError("TRANSPORT_ERROR") from exc
        return code, out

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - closing a session never masks the outcome
            pass


def target(device_name: str, *, purpose: str = "WRITE") -> dict:
    """The resolved, authorized target: {address, username, ssh_key_ref, host_key}.  Raises ExecutorError NOT_CONFIGURED."""
    from .. import nsot_live
    from . import resolve

    meta = nsot_live.get_live_target_metadata(device_name, purpose=purpose)
    if meta is None or meta.get("platform") != "linux" or (meta.get("management") or {}).get("source") != resolve.LEGACY:
        raise ExecutorError("NOT_CONFIGURED")
    entry = ((nsot_live._load_inventory() or {}).get("network_devices") or {}).get(device_name) or {}   # pylint: disable=protected-access
    pin = str(entry.get("ssh_host_key") or "")
    if not meta.get("username") or not meta.get("ssh_key_ref") or not _FINGERPRINT.fullmatch(pin):
        raise ExecutorError("NOT_CONFIGURED")
    return {"address": meta["address"], "username": meta["username"], "ssh_key_ref": meta["ssh_key_ref"], "host_key": pin,
            "port": int(entry.get("ssh_port") or 22)}


def connect(device_name: str, *, timeout: float, purpose: str = "WRITE") -> LinuxSession:
    """Open an authorized session to ``device_name`` (see the module docstring)."""
    import paramiko

    from . import probes

    found = target(device_name, purpose=purpose)          # importing nsot_live first puts the repository root on sys.path
    from modules.device_credentials import SecretProviderError, load_ssh_private_key  # pylint: disable=import-outside-toplevel


    try:
        key = load_ssh_private_key(found["ssh_key_ref"])
    except SecretProviderError as exc:
        raise ExecutorError("NOT_CONFIGURED") from exc
    expected = found["host_key"]

    class PinnedHostKey(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, _client, _hostname, key):
            if probes.fingerprint(key) != expected:
                raise paramiko.SSHException("HOST_KEY_MISMATCH")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(PinnedHostKey())
    try:
        client.connect(found["address"], port=found["port"], username=found["username"], pkey=key, timeout=timeout,
                       banner_timeout=timeout, auth_timeout=timeout, allow_agent=False, look_for_keys=False)
    except paramiko.AuthenticationException as exc:
        client.close()
        raise ExecutorError("AUTH_FAILED") from exc
    except socket.timeout as exc:
        client.close()
        raise ExecutorError("TIMEOUT") from exc
    except (paramiko.SSHException, OSError, EOFError) as exc:          # includes HOST_KEY_MISMATCH
        client.close()
        raise ExecutorError("CONNECTION_FAILED") from exc
    return LinuxSession(client, found["username"])
