"""The one process boundary of the console, and its read-only allowlist.

Every command the console can run is checked here before it starts.  The allowlist is structural, not advisory:

    docker inspect ...                       container state / health
    docker ps ...                            which lab containers are running
    docker exec <container> ping ...         one bounded ICMP probe from an endpoint
    docker exec <container> ip -j ... show   addresses / link counters (iproute2 JSON, read-only)
    docker exec <container> Cli -p 15 -c "show ... | json"      an EOS show command (never configuration mode)
    systemctl show <unit> -p ...             unit state (needs no privilege)

There is no ``sudo``, no shell (argv lists only, ``shell=False``), no stdin, and no other executable.  Anything else raises
``CommandNotAllowed`` before a process exists -- there is no write path to fall through to.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass

MAX_OUTPUT_BYTES = 4_000_000
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$")
_EOS_SHOW = re.compile(r"^show [a-z0-9 -]+( \| json)?$")
_FORBIDDEN_EOS = ("configure", "conf t", "write", "copy", "clear", "reload", "delete", "erase", "bash", ";", "&", "`", "$", ">", "<")
_SYSTEMD_PROPERTIES = frozenset({"ActiveState", "SubState", "Result", "LoadState", "UnitFileState", "ActiveEnterTimestamp",
                                 "LastTriggerUSec", "ExecMainStatus", "ExecMainExitTimestamp", "NextElapseUSecRealtime"})


class CommandNotAllowed(ValueError):
    """The argv is outside the read-only allowlist.  Raised before any process is started."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int | None          # None when the command did not finish
    stdout: str = ""
    error: str = ""                 # "" / TIMEOUT / RUNTIME_UNAVAILABLE / OUTPUT_TOO_LARGE
    stderr_class: str = ""          # a fixed class derived from stderr; the text itself is never kept

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.error


def _check_inner(argv: tuple[str, ...]) -> None:
    head = argv[0] if argv else ""
    if head == "ping":
        # ping -n -c 1 -W <1-5> [-4|-6] [-I <iface>] <literal address>
        options, address = argv[1:-1], argv[-1]
        ipaddress.ip_address(address.split("%")[0])
        allowed = iter(options)
        for token in allowed:
            if token in ("-n", "-4", "-6"):
                continue
            if token in ("-c", "-W"):
                value = next(allowed, "")
                if not value.isdigit() or not 1 <= int(value) <= 5:
                    raise CommandNotAllowed("ping count / wait out of bounds")
                continue
            raise CommandNotAllowed("ping option not allowed")
        return
    if head == "ip":
        if len(argv) < 4 or argv[1] != "-j" or argv[-1] != "show" or any(t in ("add", "del", "set", "flush", "replace", "change") for t in argv):
            raise CommandNotAllowed("only `ip -j ... show` is allowed")
        return
    if head == "Cli":
        if len(argv) != 5 or argv[1:4] != ("-p", "15", "-c"):
            raise CommandNotAllowed("unexpected Cli invocation")
        command = argv[4]
        if not _EOS_SHOW.match(command) or any(token in command.lower() for token in _FORBIDDEN_EOS):
            raise CommandNotAllowed("only EOS `show ...` commands are allowed")
        return
    raise CommandNotAllowed("executable not allowed inside a container")


def assert_read_only(argv) -> tuple[str, ...]:
    """Validate ``argv`` against the allowlist and return it as a tuple.  Raises ``CommandNotAllowed`` otherwise."""
    argv = tuple(str(part) for part in argv)
    if len(argv) < 2 or any("\n" in part or "\x00" in part for part in argv):
        raise CommandNotAllowed("malformed command")
    try:
        if argv[0] == "docker":
            if argv[1] == "exec":
                if len(argv) < 4 or not _NAME.match(argv[2]):
                    raise CommandNotAllowed("docker exec needs a container name and a command; no options are allowed")
                _check_inner(argv[3:])
                return argv
            if argv[1] in ("inspect", "ps"):
                return argv
            raise CommandNotAllowed("docker subcommand not allowed")
        if argv[0] == "systemctl":
            if argv[1] != "show" or len(argv) < 3 or not _NAME.match(argv[2]):
                raise CommandNotAllowed("only `systemctl show <unit>` is allowed")
            rest = iter(argv[3:])
            for token in rest:
                if token != "-p" or next(rest, "") not in _SYSTEMD_PROPERTIES:
                    raise CommandNotAllowed("systemctl property not allowed")
            return argv
    except ValueError as exc:
        if isinstance(exc, CommandNotAllowed):
            raise
        raise CommandNotAllowed("argument is not a literal address") from exc
    raise CommandNotAllowed("executable not allowed")


def _stderr_class(text: str) -> str:
    lowered = (text or "").lower()
    if "no such container" in lowered or "no such object" in lowered:
        return "NO_SUCH_CONTAINER"
    if "is not running" in lowered:
        return "CONTAINER_NOT_RUNNING"
    if "permission denied" in lowered:
        return "PERMISSION_DENIED"
    if "cannot connect to the docker daemon" in lowered:
        return "RUNTIME_UNAVAILABLE"
    if "network is unreachable" in lowered or "no route" in lowered:
        return "NETWORK_UNREACHABLE"
    return "COMMAND_FAILED" if lowered.strip() else ""


def run(argv, *, timeout: float = 8.0) -> CommandResult:
    """Run one allowlisted read-only command.  Never raises for a failed / slow / missing command: the result says what happened."""
    argv = assert_read_only(argv)
    try:
        done = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout, shell=False, check=False,  # noqa: S603
                              stdin=subprocess.DEVNULL, errors="replace")
    except subprocess.TimeoutExpired:
        return CommandResult(None, error="TIMEOUT")
    except (FileNotFoundError, PermissionError):
        return CommandResult(None, error="RUNTIME_UNAVAILABLE")
    except OSError:
        return CommandResult(None, error="RUNTIME_UNAVAILABLE")
    if len(done.stdout) > MAX_OUTPUT_BYTES:
        return CommandResult(done.returncode, error="OUTPUT_TOO_LARGE")
    return CommandResult(done.returncode, stdout=done.stdout, stderr_class=_stderr_class(done.stderr) if done.returncode else "")
