"""A pinned, key-only SSH CLI session for governed management writes (bootstrap credential replacement).

SSH only -- never Docker exec, never the Containerlab management bridge.  The server is accepted only when its host key
matches the pinned fingerprint exactly (checked BEFORE authentication); agent and key-file lookup are disabled, and only
the in-memory private key handed in is offered.  Output is bounded and never logged; CLI rejections are reduced to a
stable code.

``show(command)`` runs one exec request.  ``configure(lines)`` sends lines over one interactive shell (the EOS
``configure session`` flow needs a persistent mode) and fails on any CLI rejection marker.  Each line is complete only when
the CLI prompt returns: silence alone is not completion (live finding: a slow ``commit timer`` whose channel was closed
early left the EOS session pending and uncommitted).  No prompt before the timeout is TRANSPORT_ERROR -- the caller cannot
tell whether the line took effect.
"""

from __future__ import annotations

import re
import socket
import time

from ..ztp.management import fingerprint

CONNECT_TIMEOUT = 10
COMMAND_TIMEOUT = 30
MAX_OUTPUT = 256 * 1024
REJECTIONS = ("% Invalid input", "% Incomplete command", "% Ambiguous command", "% Error", "% Unavailable command",
              "% Authorization denied", "% Cannot commit")
PROMPT = re.compile(r"[\w.\-/:@()]+[#>]\s*$")       # DUT1#  DUT1(config-s-nmas-b)#  DUT1>


class CliError(Exception):
    """Stable codes: UNREACHABLE, HOST_KEY_MISMATCH, AUTH_FAILED, COMMAND_REJECTED, TRANSPORT_ERROR."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code = code
        self.detail = str(detail)[:200]


class PinnedCli:
    def __init__(self, *, address: str, port: int, username: str, pkey, expected_host_key: str, sock=None):
        import paramiko

        if not expected_host_key:
            raise CliError("HOST_KEY_MISMATCH", "no pinned host key")
        if sock is None:
            try:
                sock = socket.create_connection((address, int(port)), timeout=CONNECT_TIMEOUT)
            except OSError as exc:
                raise CliError("UNREACHABLE", type(exc).__name__) from None
        self._transport = paramiko.Transport(sock)
        try:
            self._transport.start_client(timeout=CONNECT_TIMEOUT)
            presented = fingerprint(self._transport.get_remote_server_key())
            if presented != expected_host_key:
                raise CliError("HOST_KEY_MISMATCH", "the presented host key is not the pinned one")
            self.host_key = presented
            try:
                self._transport.auth_publickey(username, pkey)
            except paramiko.AuthenticationException:
                raise CliError("AUTH_FAILED") from None
            if not self._transport.is_authenticated():
                raise CliError("AUTH_FAILED")
        except CliError:
            self._transport.close()
            raise
        except (paramiko.SSHException, OSError, EOFError) as exc:
            self._transport.close()
            raise CliError("UNREACHABLE", type(exc).__name__) from None

    def show(self, command: str) -> str:
        import paramiko

        try:
            channel = self._transport.open_session(timeout=CONNECT_TIMEOUT)
            channel.settimeout(COMMAND_TIMEOUT)
            channel.exec_command(command)
            chunks, size = [], 0
            while size < MAX_OUTPUT:
                data = channel.recv(65536)
                if not data:
                    break
                chunks.append(data)
                size += len(data)
            channel.close()
        except (paramiko.SSHException, OSError, EOFError) as exc:
            raise CliError("TRANSPORT_ERROR", type(exc).__name__) from None
        return b"".join(chunks).decode("utf-8", "replace")

    def configure(self, lines: list[str], *, settle: float = 0.4, timeout: float = COMMAND_TIMEOUT) -> str:
        """Send exactly ``lines`` over one interactive shell, each after the previous one's prompt has returned.  The caller
        ends the mode itself (``commit`` leaves an EOS configure session)."""
        import paramiko

        channel = None
        try:
            channel = self._transport.open_session(timeout=CONNECT_TIMEOUT)
            channel.get_pty(width=511)
            channel.invoke_shell()
            channel.settimeout(COMMAND_TIMEOUT)
            output = [self._drain(channel, settle, timeout)]
            for line in ["terminal length 0", *lines]:
                channel.send((line + "\n").encode())
                output.append(self._drain(channel, settle, timeout))
        except (paramiko.SSHException, OSError, EOFError) as exc:
            raise CliError("TRANSPORT_ERROR", type(exc).__name__) from None
        finally:
            if channel is not None:
                channel.close()
        text = "".join(output)[:MAX_OUTPUT]
        if any(marker in text for marker in REJECTIONS):
            raise CliError("COMMAND_REJECTED")
        return text

    @staticmethod
    def _drain(channel, settle: float, timeout: float = COMMAND_TIMEOUT) -> str:
        """Read until the output ends in a CLI prompt and has been quiet for ``settle`` seconds."""
        deadline, chunks = time.monotonic() + timeout, []
        quiet_since = time.monotonic()
        while time.monotonic() < deadline:
            if channel.recv_ready():
                chunks.append(channel.recv(65536))
                quiet_since = time.monotonic()
            elif time.monotonic() - quiet_since >= settle and PROMPT.search(b"".join(chunks)[-256:].decode("utf-8", "replace")):
                return b"".join(chunks).decode("utf-8", "replace")
            else:
                time.sleep(0.05)
        raise CliError("TRANSPORT_ERROR", "no CLI prompt before the timeout")

    def close(self) -> None:
        self._transport.close()


def connect(*, address: str, port: int, username: str, pkey, expected_host_key: str, sock=None) -> PinnedCli:
    return PinnedCli(address=address, port=port, username=username, pkey=pkey, expected_host_key=expected_host_key, sock=sock)
