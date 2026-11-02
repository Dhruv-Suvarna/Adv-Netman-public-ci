"""One traffic run inside the runner: revalidate, resolve, discover addresses, execute, and remove exactly what the run created.

``Engine.handle`` never raises.  Its reply is a closed document: either ``ok: false`` with a stable ``code``, or the tool's exit status
and bounded output for the website to parse -- plus, always, a ``cleanup`` record saying which temporary containers of THIS run were
removed and that none is left.

The operator never supplies an address, a container, an image or a flag.  The endpoint ids are looked up in the runner's own catalogue,
the container identity is read from the runtime and pinned for the run, the destination address is discovered inside the destination's
namespace, and each test family builds its own fixed argument list from bounded integers.

iperf3 needs a receiver: a temporary ONE-OFF server (``-s -1``, bound to the discovered address, with an idle timeout) is started in the
destination namespace, the client runs in the source namespace, and the server container -- by its exact name -- is removed afterwards
whether or not it already exited.  A listener that somebody else owns on that port makes the server fail to bind; it is never disturbed.
"""

from __future__ import annotations

import ipaddress
import json
import threading
import time

from . import PROTOCOL_VERSION, RUNNER_VERSION, policy
from . import runtime as docker_runtime
from .policy import V4, V6
from .runtime import RuntimeFailure

MANAGEMENT_INTERFACES = frozenset({"lo", "eth0"})     # Containerlab's own management link is never a test path
START_FAILED = (125, 126, 127)                        # the runtime could not create / start the tools container


def parse_addresses(text: str) -> dict:
    """``ip -j addr show`` -> {"IPV4": [...], "IPV6": [...]} global-scope addresses on data interfaces, in a stable order."""
    result = {V4: [], V6: []}
    try:
        links = json.loads(text or "[]")
    except ValueError:
        return result
    for link in links if isinstance(links, list) else []:
        if str(link.get("ifname") or "") in MANAGEMENT_INTERFACES or str(link.get("operstate") or "").upper() == "DOWN":
            continue
        for info in link.get("addr_info") or []:
            if info.get("scope") != "global":
                continue
            try:
                address = ipaddress.ip_address(str(info.get("local")))
            except ValueError:
                continue
            result[V4 if address.version == 4 else V6].append(str(address))
    return {family: sorted(set(values), key=lambda a: int(ipaddress.ip_address(a))) for family, values in result.items()}


class _Failure(Exception):
    def __init__(self, code: str, **extra):
        super().__init__(code)
        self.code, self.extra = code, extra


class _Run:
    """The state of one run: the pinned endpoint identities and every container name the run created (and must remove)."""

    def __init__(self, job, config):
        self.job, self.config, self.created = job, config, []
        self.identity = {}

    def common(self, role: str, endpoint: str) -> dict:
        name = self.job.container_name(role)
        self.created.append(name)
        return {"name": name, "instance": self.config.instance, "run_id": str(self.job.run_id), "netns": self.identity[endpoint],
                "image": self.config.tools_image}


class Engine:
    def __init__(self, config, *, runtime=docker_runtime, sleep=time.sleep, clock=time.monotonic, log=lambda record: None):
        self.config, self.runtime, self.sleep, self.clock, self.log = config, runtime, sleep, clock, log
        self._slots = threading.BoundedSemaphore(policy.MAX_ACTIVE_RUNS)

    # --- startup -----------------------------------------------------------------------------------------------------------------
    def reconcile(self) -> list:
        """Remove what a previous instance of THIS runner left behind (a crash or restart mid-run).  Exact names, own label only."""
        removed = []
        try:
            for name in self.runtime.owned(self.config.instance):
                self.runtime.remove(name)
                if self.runtime.container_state(name) is None:
                    removed.append(name)
                self.log({"event": "abandoned_container_removed", "container": name, "run_id": _hex_to_uuid(name[13:45])})
        except RuntimeFailure as exc:
            self.log({"event": "reconcile_failed", "code": exc.code})
        return removed

    # --- one request -------------------------------------------------------------------------------------------------------------
    def handle(self, document, *, peer_uid: int | None = None) -> dict:
        started = self.clock()
        raw_id = document.get("run_id") if isinstance(document, dict) else None
        reply = {"v": PROTOCOL_VERSION, "ok": False, "run_id": raw_id if isinstance(raw_id, str) and len(raw_id) == 36 else "",
                 "runner": RUNNER_VERSION}
        record = {"event": "traffic_run", "run_id": reply["run_id"], "peer_uid": peer_uid}
        try:
            job = policy.validate(document, self.config.endpoints)
        except policy.Refusal as refusal:
            reply.update(code=refusal.code, refused=True, **({"field": refusal.field} if refusal.field else {}))
            self.log({**record, "outcome": refusal.code, "refused": True, "duration_ms": _ms(self.clock() - started)})
            return reply
        record.update(source=job.source, destination=job.destination, test_type=job.test_type, address_family=job.address_family, protocol=job.protocol)
        if not self._slots.acquire(blocking=False):                   # the runner's own concurrency bound, whatever the website allowed
            reply.update(code="BUSY", refused=True)
            self.log({**record, "outcome": "BUSY", "refused": True, "duration_ms": _ms(self.clock() - started)})
            return reply
        run = _Run(job, self.config)
        try:
            try:
                reply.update(self._execute(run))
            except _Failure as failure:
                reply.update(ok=False, code=failure.code, **failure.extra)
            except RuntimeFailure as failure:
                reply.update(ok=False, code=failure.code)
            except Exception:  # noqa: BLE001 - a runner defect is a refused run with a stable code, never a traceback on the socket
                reply.update(ok=False, code="INTERNAL_ERROR")
            reply["cleanup"] = self._cleanup(run)
            if not reply["cleanup"]["verified"] and reply.get("code") != "SERVER_NOT_STOPPED":
                reply.update(ok=False, code="RUNTIME_NOT_CLEANED")
        finally:
            self._slots.release()
        reply["image"] = self.config.tools_image
        self.log({**record, "outcome": "OK" if reply["ok"] else reply["code"], "exit_code": reply.get("exit_code"), "timed_out": reply.get("timed_out", False),
                  "containers": len(run.created), "cleanup_verified": reply["cleanup"]["verified"], "duration_ms": _ms(self.clock() - started)})
        return reply

    def _cleanup(self, run: _Run) -> dict:
        """Remove every container THIS run created -- by exact name -- and confirm each one is gone."""
        removed, left = [], []
        for name in run.created:
            try:
                self.runtime.remove(name)
                (removed if self.runtime.container_state(name) is None else left).append(name)
            except Exception:  # noqa: BLE001
                left.append(name)
        return {"containers": removed, "left_behind": left, "verified": not left}

    # --- execution ---------------------------------------------------------------------------------------------------------------
    def _execute(self, run: _Run) -> dict:
        job, config, runtime = run.job, self.config, self.runtime
        if not runtime.image_available(config.tools_image):
            raise _Failure("TOOLS_IMAGE_MISSING")
        for endpoint in (job.source, job.destination):
            run.identity[endpoint] = runtime.inspect_endpoint(config.endpoints[endpoint].container, lab=config.lab, node=endpoint)
        if any(runtime.container_state(job.container_name(role)) is not None for role in sorted(docker_runtime.ROLES)):
            raise _Failure("RUN_ID_REPLAYED")              # nothing of that earlier run is touched: ``run.created`` is still empty
        mine = self._addresses(run, "asrc", job.source)[job.address_family]
        theirs = self._addresses(run, "adst", job.destination)[job.address_family]
        if not mine or not theirs:
            raise _Failure("NO_ADDRESS_FOR_FAMILY")
        result = {"source_address": mine[0], "destination_address": theirs[0]}
        try:
            result.update(self._iperf(run, theirs[0]) if job.test_type == "IPERF3" else self._simple(run, theirs[0]))
        except _Failure as failure:
            failure.extra = {**result, **failure.extra}
            raise
        return result

    def _addresses(self, run: _Run, role: str, endpoint: str) -> dict:
        done = self._tool(run, role, endpoint, "ip", ["-j", "addr", "show"], timeout=15)
        if done.returncode or done.timed_out:
            raise _Failure("ADDRESS_DISCOVERY_FAILED")
        return parse_addresses(done.stdout)

    def _tool(self, run: _Run, role: str, endpoint: str, tool: str, args, *, timeout: float):
        """Run one tool in ``endpoint``'s namespace.  A tool that could not run is told apart from an endpoint that went away."""
        done = self.runtime.run_tool(**run.common(role, endpoint), tool=tool, args=args, timeout=timeout)
        if done.returncode:                               # any failure: was it the test, or did the endpoint go away under it?
            self._still_there(run, endpoint)
            if done.returncode in START_FAILED:
                raise _Failure("TOOLS_START_FAILED")
        return done

    def _still_there(self, run: _Run, endpoint: str) -> None:
        try:
            now = self.runtime.inspect_endpoint(self.config.endpoints[endpoint].container, lab=self.config.lab, node=endpoint)
        except RuntimeFailure as exc:
            raise _Failure("ENDPOINT_LOST") from exc
        if now != run.identity[endpoint]:                 # same name, different container: not the endpoint this run was pinned to
            raise _Failure("ENDPOINT_LOST")

    def _simple(self, run: _Run, address: str) -> dict:
        job = run.job
        p, flag = job.parameters, "-6" if job.address_family == V6 else "-4"
        if job.test_type == "ICMP":
            tool, args = "ping", [flag, "-n", "-c", p["count"], "-s", p["size"], "-W", policy.PING_PER_PACKET_WAIT, address]
        elif job.test_type == "TRACEROUTE":
            tool, args = "traceroute", [flag, "-n", "-q", 1, "-w", policy.TRACEROUTE_WAIT, "-m", p["max_hops"],
                                        *(["-I"] if job.protocol == "ICMP" else []), address]
        elif job.test_type == "TCP_CONNECT":
            tool, args = "tcp_connect", [address, p["port"], p["timeout"]]
        else:
            tool, args = "udp_probe", [address, p["port"], p["timeout"], p["count"], p["size"]]
        operation = {"tool": tool, "namespace": job.source, "arguments": [str(a) for a in args]}
        done = self._tool(run, "tool", job.source, tool, args, timeout=policy.tool_timeout_seconds(job.test_type, p))
        return {"ok": True, "operation": operation, **_output(done)}

    def _iperf(self, run: _Run, address: str) -> dict:
        job, runtime = run.job, self.runtime
        p, udp, flag = job.parameters, job.protocol == "UDP", "-6" if job.address_family == V6 else "-4"
        server_args = ["-s", "-1", flag, "-B", address, "-p", p["port"], "--idle-timeout", policy.IPERF_SERVER_READY_SECONDS + p["duration"] + 5,
                       "--forceflush"]
        client_args = ["-c", address, flag, "-p", p["port"], "-t", p["duration"], "-b", f"{p['bandwidth_kbps']}K", "-P", p["parallel"], "-J",
                       "--connect-timeout", 3000, *(["-u", "-l", p["length"]] if udp else [])]
        operation = {"tool": "iperf3", "server": {"namespace": job.destination, "arguments": [str(a) for a in server_args]},
                     "client": {"namespace": job.source, "arguments": [str(a) for a in client_args]}}
        server = {"started": False, "ready": False, "exit_code": None, "terminated": False, "stopped": False}
        name = job.container_name("server")
        started = runtime.start_server(**run.common("server", job.destination), tool="iperf3", args=server_args)
        if started.returncode or started.timed_out:
            self._still_there(run, job.destination)
            raise _Failure("TOOLS_START_FAILED", operation=operation, server=server)
        server["started"] = True
        result, failure = None, None
        try:
            for _ in range(policy.IPERF_SERVER_READY_SECONDS * 5):
                state = runtime.container_state(name)
                if state is None or not state["running"]:
                    break                                   # it exited: the port was taken, or the address could not be bound
                if "Server listening" in runtime.logs(name):
                    server["ready"] = True
                    break
                self.sleep(0.2)
            if not server["ready"]:
                self._still_there(run, job.destination)
                failure = _Failure("SERVER_START_FAILED")
            else:
                done = self._tool(run, "tool", job.source, "iperf3", client_args, timeout=policy.tool_timeout_seconds(job.test_type, p))
                result = {"ok": True, **_output(done)}
                for _ in range(15 if (not done.returncode and not done.timed_out) else 0):   # a served one-off server exits by itself
                    state = runtime.container_state(name)
                    if state is None or not state["running"]:
                        break
                    self.sleep(0.2)
        except _Failure as raised:
            failure = raised
        finally:
            # make sure THIS run's server is gone: read how it ended, then remove that exact container and confirm it no longer exists
            try:
                state = runtime.container_state(name)
                server["terminated"] = bool(state and state["running"])
                server["exit_code"] = state["exit_code"] if state and not state["running"] else None
                runtime.remove(name)
                server["stopped"] = runtime.container_state(name) is None
            except RuntimeFailure:
                server["stopped"] = False
        if not server["stopped"]:
            raise _Failure("SERVER_NOT_STOPPED", operation=operation, server=server)
        if failure is not None:
            failure.extra = {**failure.extra, "operation": operation, "server": server}
            raise failure
        return {**result, "operation": operation, "server": server}


def _output(done) -> dict:
    return {"exit_code": done.returncode, "timed_out": bool(done.timed_out), "stdout": (done.stdout or "")[: policy.MAX_STDOUT_BYTES],
            "stderr": (done.stderr or "")[: policy.MAX_STDERR_BYTES]}


def _ms(seconds: float) -> int:
    return int(round(seconds * 1000))


def _hex_to_uuid(text: str) -> str:
    return f"{text[:8]}-{text[8:12]}-{text[12:16]}-{text[16:20]}-{text[20:]}"
