"""The trusted, server-owned sandbox boundary: configuration, argv construction, the ONLY process spawn, output sanitization.

Security contract (each point is enforced by a contract test):

* The ONLY ``subprocess`` use in the Raw Configlet package is ``run_process`` below: a ``docker`` argv LIST, ``shell=False``, a
  minimal allowlisted environment, a hard timeout and bounded capture.  There is no ``eval`` / ``exec`` / ``os.system`` / ``sh -c``.
* Browser-supplied text is NEVER part of an argv.  It can only travel over STDIN of a fixed, server-owned command.  Every argv
  element is a code constant, a server-configured image name (validated against a strict pattern) or a generated container name.
* Every sandbox is a uniquely named, disposable container; ``Sandbox.remove`` runs in a ``finally`` on success, failure and timeout.
* Isolation is applied as strongly as the backend allows: ``--network none``, no mounts, no Docker socket, no host PID / network
  namespace, bounded memory / CPU / PIDs, no credentials or environment forwarded.  Backends that cannot honour a control (cEOS
  needs ``--privileged``) say so in their adapter and are disabled by default -- nothing here claims a property it cannot provide.
* Output is bounded, control-character-stripped, secret-redacted and path-scrubbed before it is stored; it is never stored raw.
"""

from __future__ import annotations

import os
import re
import subprocess
import uuid
from dataclasses import dataclass

from django.conf import settings

from ..ci import redact as ci_redact
from ..nsot_live import redact_config
from . import codes

DOCKER = "docker"
LABEL = "io.clab-dualstack.raw-verifier=1"
_IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,120}(:[A-Za-z0-9][A-Za-z0-9._-]{0,80})?$")
_NAME_RE = re.compile(r"^clab-rawverify-[a-z0-9]{1,16}-[0-9a-f]{12}$")
_ENV_ALLOWLIST = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "XDG_RUNTIME_DIR")

# server-owned resource limits (constants, not settings): (memory, cpus, pids)
FRR_LIMITS = ("256m", "1", "64")
CEOS_LIMITS = ("3g", "2", "4096")
CEOS_INIT_COMMAND = (  # exactly the systemd environment containerlab uses for the same image, minus lab-specific settings
    "/sbin/init", "systemd.setenv=INTFTYPE=eth", "systemd.setenv=ETBA=1", "systemd.setenv=SKIP_ZEROTOUCH_BARRIER_IN_SYSDBINIT=1",
    "systemd.setenv=CEOS=1", "systemd.setenv=EOS_PLATFORM=ceoslab", "systemd.setenv=container=docker",
)


@dataclass(frozen=True)
class SandboxConfig:
    frr_image: str
    ceos_image: str
    allow_privileged: bool
    timeout: float
    boot_timeout: float
    cleanup_timeout: float


def load_config() -> SandboxConfig:
    """Read the server-owned settings.  An image name that does not match the strict pattern is refused (never used in argv)."""
    frr = str(getattr(settings, "RAW_VERIFIER_FRR_IMAGE", ""))
    ceos = str(getattr(settings, "RAW_VERIFIER_CEOS_IMAGE", ""))
    for image in (frr, ceos):
        if not _IMAGE_RE.match(image):
            raise ValueError("A raw verifier image setting is not a valid local image reference.")
    return SandboxConfig(
        frr_image=frr, ceos_image=ceos, allow_privileged=bool(getattr(settings, "RAW_VERIFIER_ALLOW_PRIVILEGED", False)),
        timeout=float(getattr(settings, "RAW_VERIFIER_TIMEOUT_SECONDS", 30)),
        boot_timeout=float(getattr(settings, "RAW_VERIFIER_CEOS_BOOT_TIMEOUT_SECONDS", 150)),
        cleanup_timeout=float(getattr(settings, "RAW_VERIFIER_CLEANUP_TIMEOUT_SECONDS", 30)),
    )


# --- the ONE process boundary -----------------------------------------------------------------------------------------------
@dataclass
class ProcessResult:
    returncode: int | None = None
    output: str = ""
    timed_out: bool = False
    truncated: bool = False
    error: str = ""          # "" | "DOCKER_UNAVAILABLE" | "OS_ERROR"


def _minimal_env() -> dict:
    env = {key: os.environ[key] for key in _ENV_ALLOWLIST if key in os.environ}
    env.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    return env


def _decode(data: bytes | None) -> tuple[str, bool]:
    data = data or b""
    truncated = len(data) > codes.MAX_CAPTURE_BYTES
    return data[: codes.MAX_CAPTURE_BYTES].decode("utf-8", errors="replace"), truncated


def run_process(argv: list[str], *, stdin: bytes | None = None, timeout: float) -> ProcessResult:
    """Run ONE ``docker`` argv list.  ``shell=False``, allowlisted environment, hard timeout, bounded capture.  Never raises."""
    if not isinstance(argv, list) or not argv or argv[0] != DOCKER or not all(isinstance(a, str) and "\x00" not in a for a in argv):
        raise ValueError("Only a docker argv list of strings may be run.")  # a programming error, never reachable from a request
    try:
        done = subprocess.run(  # noqa: S603 - a validated list, shell=False
            argv, input=stdin, capture_output=True, timeout=timeout, shell=False, check=False, env=_minimal_env(),
        )
    except subprocess.TimeoutExpired as exc:
        text, truncated = _decode((exc.stdout or b"") + (exc.stderr or b""))
        return ProcessResult(None, text, timed_out=True, truncated=truncated)
    except FileNotFoundError:
        return ProcessResult(error="DOCKER_UNAVAILABLE")
    except OSError:
        return ProcessResult(error="OS_ERROR")
    text, truncated = _decode((done.stdout or b"") + (done.stderr or b""))
    return ProcessResult(done.returncode, text, truncated=truncated)


# --- pure argv builders (unit-tested; no user text can reach them) ---------------------------------------------------------
def container_name(adapter_short: str, token: str | None = None) -> str:
    name = f"clab-rawverify-{adapter_short}-{(token or uuid.uuid4().hex)[:12]}"
    if not _NAME_RE.match(name):
        raise ValueError("Invalid sandbox name.")
    return name


def _limits(memory: str, cpus: str, pids: str) -> list[str]:
    return ["--memory", memory, "--memory-swap", memory, "--cpus", cpus, "--pids-limit", pids]


def oneshot_argv(name: str, image: str, entrypoint: str, entry_args: list[str], limits: tuple[str, str, str]) -> list[str]:
    """An UNPRIVILEGED, network-less, read-only, capability-less, non-root one-shot container reading its input from stdin."""
    assert _NAME_RE.match(name) and _IMAGE_RE.match(image)
    return [
        DOCKER, "run", "--rm", "-i", "--name", name, "--label", LABEL, "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "65534:65534", *_limits(*limits),
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m", "-e", "HOME=/tmp", "--entrypoint", entrypoint, image, *entry_args,
    ]


def detached_argv(name: str, image: str, command: tuple[str, ...], limits: tuple[str, str, str], *, privileged: bool) -> list[str]:
    """A long-running disposable container (cEOS).  ``--privileged`` is used ONLY when the backend requires it AND policy allows."""
    assert _NAME_RE.match(name) and _IMAGE_RE.match(image)
    return [
        DOCKER, "run", "-d", "--name", name, "--label", LABEL, "--network", "none", *(["--privileged"] if privileged else []),
        *_limits(*limits), image, *command,
    ]


def exec_argv(name: str, argv: list[str], *, interactive: bool = False) -> list[str]:
    assert _NAME_RE.match(name)
    return [DOCKER, "exec", *(["-i"] if interactive else []), name, *argv]


def remove_argv(name: str) -> list[str]:
    assert _NAME_RE.match(name)
    return [DOCKER, "rm", "-f", name]


def exists_argv(name: str) -> list[str]:
    assert _NAME_RE.match(name)
    return [DOCKER, "ps", "-a", "-q", "--filter", f"name=^/{name}$"]


def image_argv(image: str) -> list[str]:
    assert _IMAGE_RE.match(image)
    return [DOCKER, "image", "inspect", "--format", "{{.Id}}", image]


# --- lifecycle --------------------------------------------------------------------------------------------------------------
class Sandbox:
    """One disposable sandbox: a unique name and a guaranteed-attempted, verified removal."""

    def __init__(self, adapter_short: str, config: SandboxConfig, runner=run_process, token: str | None = None):
        self.config, self.run, self.name = config, runner, container_name(adapter_short, token)

    def image_state(self, image: str) -> str:
        """"OK" | "MISSING" | "UNAVAILABLE" (the runtime itself could not be asked)."""
        result = self.run(image_argv(image), timeout=self.config.cleanup_timeout)
        if result.error or result.timed_out or result.returncode is None:
            return "UNAVAILABLE"
        return "OK" if result.returncode == 0 else ("MISSING" if "no such" in result.output.lower() else "UNAVAILABLE")

    def remove(self) -> bool:
        """Force-remove the container and CONFIRM it is gone.  True only when nothing with this name remains."""
        self.run(remove_argv(self.name), timeout=self.config.cleanup_timeout)  # "No such container" (already removed by --rm) is fine
        check = self.run(exists_argv(self.name), timeout=self.config.cleanup_timeout)
        return check.error == "" and not check.timed_out and check.returncode == 0 and not check.output.strip()


# --- output sanitization ----------------------------------------------------------------------------------------------------
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_PATH_RE = re.compile(r"(?:/[A-Za-z0-9_.@+-]+){2,}")


def sanitize_line(line: str) -> str:
    """One bounded, printable, redacted, path-scrubbed line.  Never raises."""
    line = _ANSI_RE.sub("", str(line))
    line = "".join(ch if 0x20 <= ord(ch) <= 0x7E else ("" if ch in "\r\n" else "?") for ch in line)
    line = ci_redact.redact_text(redact_config(line))
    line = _PATH_RE.sub("<path>", line)
    return line.strip()[: codes.MAX_EVIDENCE_LINE_LENGTH]


def sanitize_output(text: str, *, limit: int = codes.MAX_EVIDENCE_LINES) -> list[str]:
    lines = [sanitize_line(raw) for raw in str(text).splitlines()]
    return [line for line in lines if line][:limit]
