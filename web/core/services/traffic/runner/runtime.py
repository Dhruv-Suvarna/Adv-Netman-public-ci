"""THE one process boundary of the traffic subsystem.

Every process the traffic workbench causes to exist is started by ``_docker`` below and nowhere else (a contract test enforces it, for
the website's code and for this package).  Rules:

* an argv LIST to one fixed binary, ``shell=False``, a finite timeout, no stdin, a minimal environment;
* a diagnostic runs in a throw-away container of the PINNED tools image (an image ID, ``--pull never``) that JOINS one endpoint's network
  namespace (``--network container:<id>``).  Nothing is installed into, or executed from, the endpoint itself;
* that container is locked down: read-only root, every capability dropped (``NET_RAW`` alone is added back for ping / ICMP traceroute),
  ``no-new-privileges``, pid / memory / CPU limits, no volume, no tty, no ``--privileged``;
* the binary is one of ``TOOLS`` with its fixed leading arguments; a caller adds short validated tokens only;
* a container is addressed by the exact name this run was given (``nmas-traffic-<run uuid>-<role>``) -- there is no name-pattern kill,
  no ``pkill`` and no prune.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass

DOCKER = "/usr/bin/docker"
_ENV = {"PATH": "/usr/bin:/bin", "DOCKER_CONFIG": "/nonexistent"}          # nothing inherited: no credentials, no client configuration

# tool -> (entrypoint inside the tools image, fixed leading arguments, needs NET_RAW)
TOOLS = {
    "ip": ("/sbin/ip", (), False),
    "ping": ("/bin/ping", (), True),
    "traceroute": ("/usr/bin/traceroute", (), True),
    "iperf3": ("/usr/bin/iperf3", (), False),
    "tcp_connect": ("/usr/bin/python3", ("-I", "-B", "/opt/nmas-traffic/tcp_connect.py"), False),
    "udp_probe": ("/usr/bin/python3", ("-I", "-B", "/opt/nmas-traffic/udp_probe.py"), False),
}
ROLES = frozenset({"asrc", "adst", "tool", "server"})
_NAME = re.compile(r"^nmas-traffic-[0-9a-f]{32}-(asrc|adst|tool|server)$")
_ENDPOINT = re.compile(r"^clab-[A-Za-z0-9_]{1,32}-[A-Za-z0-9_]{1,32}$")
_ID = re.compile(r"^[0-9a-f]{64}$")
_IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
_INSTANCE = re.compile(r"^[a-z0-9]{1,16}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_ARG = re.compile(r"^[A-Za-z0-9_.:%/=,-]{0,128}$")       # an argument is a short token: an option name, a number, an address
LABEL_INSTANCE, LABEL_RUN, LABEL_ROLE = "nmas.traffic.instance", "nmas.traffic.run", "nmas.traffic.role"


class RuntimeFailure(Exception):
    """A sanitized runtime failure: only ``code`` leaves this module."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass
class Completed:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def _text(value) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


def _docker(args: list, *, timeout: float) -> Completed:
    """Run the container-runtime client once.  THE single spawn of the traffic subsystem."""
    try:
        done = subprocess.run([DOCKER, *args], capture_output=True, text=True, timeout=timeout, shell=False, check=False,  # noqa: S603
                              stdin=subprocess.DEVNULL, env=_ENV)
    except subprocess.TimeoutExpired as exc:
        return Completed(-1, _text(exc.stdout), _text(exc.stderr), timed_out=True)
    except OSError as exc:
        raise RuntimeFailure("RUNTIME_UNAVAILABLE") from exc
    return Completed(done.returncode, done.stdout, done.stderr)


def inspect_endpoint(container: str, *, lab: str, node: str) -> str:
    """The container ID of a RUNNING node ``node`` of Containerlab lab ``lab`` -- the identity the run is pinned to."""
    if not _ENDPOINT.fullmatch(container or ""):
        raise RuntimeFailure("ENDPOINT_INVALID")
    done = _docker(["inspect", "--type", "container", container], timeout=10)
    if done.timed_out:
        raise RuntimeFailure("RUNTIME_UNAVAILABLE")
    if done.returncode:
        raise RuntimeFailure("ENDPOINT_NOT_FOUND")
    try:
        document = json.loads(done.stdout)[0]
        state, labels, identity = document.get("State") or {}, (document.get("Config") or {}).get("Labels") or {}, str(document.get("Id") or "")
    except (ValueError, IndexError, TypeError, AttributeError) as exc:
        raise RuntimeFailure("ENDPOINT_NOT_FOUND") from exc
    if not state.get("Running") or not _ID.fullmatch(identity):
        raise RuntimeFailure("ENDPOINT_NOT_RUNNING")
    if labels.get("containerlab") != lab or labels.get("clab-node-name") != node:
        raise RuntimeFailure("ENDPOINT_WRONG_LAB")
    return identity


def image_available(image: str) -> bool:
    if not _IMAGE.fullmatch(image or ""):
        raise RuntimeFailure("OPERATION_NOT_ALLOWED")
    return _docker(["image", "inspect", "--format", "{{.Id}}", image], timeout=10).returncode == 0


def _run_args(*, name: str, instance: str, run_id: str, netns: str, image: str, tool: str, args, detached: bool) -> list:
    """The exact ``docker run`` argv of one tools container.  Everything is checked here, whoever the caller is."""
    if tool not in TOOLS or not _NAME.fullmatch(name or "") or not _ID.fullmatch(netns or "") or not _IMAGE.fullmatch(image or "") \
            or not _INSTANCE.fullmatch(instance or "") or not _UUID.fullmatch(run_id or "") or run_id.replace("-", "") != name[13:45]:
        raise RuntimeFailure("OPERATION_NOT_ALLOWED")
    args = [str(a) for a in args]
    if any(not _ARG.fullmatch(a) for a in args):
        raise RuntimeFailure("OPERATION_NOT_ALLOWED")
    entrypoint, fixed, raw = TOOLS[tool]
    return [
        "run", *(["--detach"] if detached else ["--rm"]), "--pull", "never", "--name", name,
        "--label", f"{LABEL_INSTANCE}={instance}", "--label", f"{LABEL_RUN}={run_id}", "--label", f"{LABEL_ROLE}={name.rsplit('-', 1)[1]}",
        "--network", f"container:{netns}",
        "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--cap-drop", "ALL", *(["--cap-add", "NET_RAW"] if raw else []),
        "--security-opt", "no-new-privileges", "--pids-limit", "32", "--memory", "96m", "--memory-swap", "96m", "--cpus", "1",
        "--user", "0:0" if raw else "65534:65534",          # a raw socket needs uid 0 + NET_RAW (and nothing else); the rest run as nobody
        "--entrypoint", entrypoint, image, *fixed, *args,
    ]


def run_tool(*, name: str, instance: str, run_id: str, netns: str, image: str, tool: str, args, timeout: float) -> Completed:
    """Run one tool to completion in the namespace of container ``netns``.  A timeout is reported, not raised; the caller removes ``name``."""
    return _docker(_run_args(name=name, instance=instance, run_id=run_id, netns=netns, image=image, tool=tool, args=args, detached=False),
                   timeout=timeout)


def start_server(*, name: str, instance: str, run_id: str, netns: str, image: str, tool: str, args) -> Completed:
    """Start one tool detached (the temporary iperf3 server).  The caller owns ``name`` and MUST ``remove`` it."""
    return _docker(_run_args(name=name, instance=instance, run_id=run_id, netns=netns, image=image, tool=tool, args=args, detached=True),
                   timeout=20)


def _own(name: str) -> str:
    if not _NAME.fullmatch(name or ""):
        raise RuntimeFailure("OPERATION_NOT_ALLOWED")
    return name


def container_state(name: str) -> dict | None:
    """``{"running": bool, "exit_code": int}`` of one of the runner's own containers, or None when it does not exist."""
    done = _docker(["inspect", "--type", "container", "--format", "{{json .State}}", _own(name)], timeout=10)
    if done.timed_out:
        raise RuntimeFailure("RUNTIME_UNAVAILABLE")
    if done.returncode:
        return None
    try:
        state = json.loads(done.stdout)
        return {"running": bool(state.get("Running")), "exit_code": int(state.get("ExitCode") or 0)}
    except (ValueError, TypeError, AttributeError) as exc:
        raise RuntimeFailure("RUNTIME_UNAVAILABLE") from exc


def logs(name: str) -> str:
    done = _docker(["logs", _own(name)], timeout=10)
    return (done.stdout + done.stderr)[:8192]


def remove(name: str) -> None:
    """Force-remove EXACTLY this container (running or not).  Absent is fine: the caller verifies with ``container_state``."""
    _docker(["rm", "--force", _own(name)], timeout=20)


def owned(instance: str) -> list:
    """Names of every container this runner instance ever created and that still exists (startup reconciliation only)."""
    if not _INSTANCE.fullmatch(instance or ""):
        raise RuntimeFailure("OPERATION_NOT_ALLOWED")
    done = _docker(["ps", "--all", "--filter", f"label={LABEL_INSTANCE}={instance}", "--format", "{{.Names}}"], timeout=10)
    if done.returncode or done.timed_out:
        raise RuntimeFailure("RUNTIME_UNAVAILABLE")
    return sorted(line.strip() for line in done.stdout.splitlines() if _NAME.fullmatch(line.strip()))
