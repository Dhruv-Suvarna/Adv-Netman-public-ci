"""V2 Phase 5B -- the traffic runner: its own validation, the one process boundary, the Unix-socket IPC, failures and exact cleanup.

The container runtime is scripted (``helpers.traffic.World``) or ``runtime._docker`` is mocked: nothing is spawned except, in two tests,
the Python interpreter itself (to prove the package runs standalone).  Real Unix sockets are used, in a private temporary directory.
"""

from __future__ import annotations

import ast
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase, TestCase, override_settings

from core import models
from core.services import traffic_service as ts
from core.services.traffic import client
from core.services.traffic.runner import PROTOCOL_VERSION, config, engine, policy, runtime, server
from core.services.traffic.runner import __main__ as entry
from core.tests.helpers import traffic as t

S = models.TrafficRunStatus
RUNNER_DIR = Path(engine.__file__).parent
RID = "3f2b8c1e-5a4d-4e6f-8a9b-0c1d2e3f4a5b"


def doc(**overrides) -> dict:
    document = {"v": PROTOCOL_VERSION, "run_id": RID, "source_endpoint_id": "H1", "destination_endpoint_id": "H2", "address_family": "IPV4",
                "test_type": "ICMP", "protocol": "ICMP", "parameters": {"count": 3, "size": 56}}
    document.update(overrides)
    return document


def iperf(**parameters) -> dict:
    return doc(test_type="IPERF3", protocol="TCP", parameters={"port": 5201, "duration": 3, "bandwidth_kbps": 1000, "parallel": 1, **parameters})


def make(world=None, **kwargs):
    world = world or t.World()
    logs = []
    return engine.Engine(t.runner_configuration(), runtime=world, sleep=lambda s: None, log=logs.append, **kwargs), world, logs


class PolicyTests(SimpleTestCase):
    """Validation layer two: what the runner refuses whatever the website sent."""

    def refuse(self, document):
        broker, world, _logs = make()
        reply = broker.handle(document, peer_uid=t.PEER_UID)
        self.assertEqual((reply["ok"], reply.get("refused")), (False, True), document)
        self.assertEqual((world.calls, world.argv, world.inspected, world.removed), ([], [], [], []), "a refused request touched the runtime")
        self.assertNotIn("cleanup", reply)
        return reply["code"], reply.get("field", "")

    def test_a_valid_request_is_accepted(self):
        broker, world, _ = make()
        reply = broker.handle(doc(), peer_uid=t.PEER_UID)
        self.assertEqual((reply["ok"], reply["run_id"], reply["exit_code"], reply["destination_address"]), (True, RID, 0, "192.168.20.101"))

    def test_malformed_requests(self):
        for bad in (None, [], "ping", 7, {}, {k: v for k, v in doc().items() if k != "parameters"}, doc(parameters=None), doc(parameters=[3, 56]),
                    doc(parameters={"count": 3}), doc(parameters={"count": 3, "size": 56, "flood": 1}), doc(run_id="not-a-uuid"),
                    doc(run_id=RID.upper()), doc(run_id=RID.replace("-", "")), doc(run_id=str(uuid.uuid1())), doc(run_id=None),
                    doc(source_endpoint_id=["H1"]), doc(test_type=None), doc(source_endpoint_id="H" * 65)):
            self.assertEqual(self.refuse(bad)[0], "MALFORMED_REQUEST", bad)
        self.assertEqual(self.refuse(doc(v=2))[0], "UNSUPPORTED_VERSION")
        self.assertEqual(self.refuse(doc(v="1"))[0], "UNSUPPORTED_VERSION")
        self.assertEqual(self.refuse(doc(v=True))[0], "UNSUPPORTED_VERSION")

    def test_unknown_endpoint_ids_and_arbitrary_container_identities(self):
        for bad in ("R1", "R5", "mgmt_swt", "clab-srlceos01-H1", "clab-srlceos01-R1", "a" * 64, "1234", "host", "", "h1", "H1 ", "../H1",
                    "netbox-netbox-1", "container:clab-srlceos01-H1"):
            self.assertEqual(self.refuse(doc(source_endpoint_id=bad)), ("UNKNOWN_ENDPOINT", "source_endpoint_id"), bad)
            self.assertEqual(self.refuse(doc(destination_endpoint_id=bad)), ("UNKNOWN_ENDPOINT", "destination_endpoint_id"), bad)
        self.assertEqual(self.refuse(doc(destination_endpoint_id="H1"))[0], "SAME_ENDPOINT")

    def test_a_request_cannot_name_a_container_an_image_a_binary_a_namespace_or_a_command(self):
        for key, value in (("container", "clab-srlceos01-R1"), ("container_id", "a" * 64), ("pid", 1), ("namespace", "/proc/1/ns/net"),
                           ("image", "alpine:latest"), ("tools_image", "sha256:" + "0" * 64), ("binary", "/bin/sh"), ("entrypoint", "/bin/sh"),
                           ("argv", ["sh", "-c", "id"]), ("command", "id"), ("args", ["--privileged"]), ("flags", "-f"), ("privileged", True),
                           ("network", "host"), ("volumes", ["/:/host"]), ("env", {"X": "1"}), ("source_address", "10.0.0.1"),
                           ("destination_address", "8.8.8.8")):
            self.assertEqual(self.refuse({**doc(), key: value})[0], "MALFORMED_REQUEST", key)
            self.assertEqual(self.refuse(doc(parameters={"count": 3, "size": 56, key: value}))[0], "MALFORMED_REQUEST", key)

    def test_unsupported_test_type_family_and_protocol(self):
        for bad in ("FLOOD", "NMAP", "icmp", "SHELL", "IPERF", ""):
            self.assertEqual(self.refuse(doc(test_type=bad))[0], "UNSUPPORTED_TEST_TYPE", bad)
        self.assertEqual(self.refuse(doc(address_family="IPX"))[0], "ADDRESS_FAMILY_UNKNOWN")
        self.assertEqual(self.refuse(doc(protocol="TCP"))[0], "PROTOCOL_NOT_APPLICABLE")
        self.assertEqual(self.refuse(iperf() | {"protocol": "ICMP"})[0], "PROTOCOL_NOT_APPLICABLE")
        self.assertEqual(self.refuse(doc(destination_endpoint_id="H4"))[0], "FAMILY_NOT_SUPPORTED_BY_ENDPOINT")       # H4 is IPv6-only
        self.assertEqual(self.refuse(doc(source_endpoint_id="H4"))[0], "FAMILY_NOT_SUPPORTED_BY_ENDPOINT")

    def test_duration_bandwidth_port_stream_and_size_bounds(self):
        cases = ((iperf(duration=11), "duration"), (iperf(duration=3600), "duration"), (iperf(duration=0), "duration"),
                 (iperf(bandwidth_kbps=10_001), "bandwidth_kbps"), (iperf(bandwidth_kbps=0), "bandwidth_kbps"), (iperf(bandwidth_kbps=63), "bandwidth_kbps"),
                 (iperf(port=22), "port"), (iperf(port=5200), "port"), (iperf(port=5211), "port"), (iperf(port=80), "port"),
                 (iperf(parallel=3), "parallel"), (iperf(parallel=0), "parallel"),
                 (doc(parameters={"count": 6, "size": 56}), "count"), (doc(parameters={"count": 3, "size": 9000}), "size"),
                 (doc(parameters={"count": -1, "size": 56}), "count"),
                 (doc(test_type="TRACEROUTE", parameters={"max_hops": 64}), "max_hops"),
                 (doc(test_type="TCP_CONNECT", protocol="TCP", parameters={"port": 70000, "timeout": 3}), "port"),
                 (doc(test_type="TCP_CONNECT", protocol="TCP", parameters={"port": 0, "timeout": 3}), "port"),
                 (doc(test_type="TCP_CONNECT", protocol="TCP", parameters={"port": 80, "timeout": 60}), "timeout"),
                 (doc(test_type="UDP_PROBE", protocol="UDP", parameters={"port": 53, "timeout": 2, "count": 100, "size": 64}), "count"),
                 (doc(test_type="UDP_PROBE", protocol="UDP", parameters={"port": 53, "timeout": 2, "count": 3, "size": 65000}), "size"),
                 (iperf(length=65507) | {"protocol": "UDP"}, "length"))
        for document, field in cases:
            self.assertEqual(self.refuse(document), ("PARAMETER_OUT_OF_BOUNDS", field), document)

    def test_a_parameter_is_a_real_integer_never_a_string_a_bool_a_float_or_a_flag(self):
        for value in ("3", "3 -f", True, 3.0, None, [3], "-f", "$(id)"):
            self.assertEqual(self.refuse(doc(parameters={"count": value, "size": 56})), ("PARAMETER_OUT_OF_BOUNDS", "count"), value)
        self.assertEqual(self.refuse(iperf(length=1200))[0], "MALFORMED_REQUEST")                     # ``length`` belongs to UDP only
        self.assertEqual(self.refuse(iperf() | {"protocol": "UDP"})[0], "MALFORMED_REQUEST")            # ... and UDP requires it

    def test_every_tool_budget_is_bounded(self):
        worst = {"ICMP": {"count": 5}, "TRACEROUTE": {"max_hops": 20}, "TCP_CONNECT": {"timeout": 5}, "UDP_PROBE": {"timeout": 5, "count": 5},
                 "IPERF3": {"duration": 10}}
        for test_type, parameters in worst.items():
            self.assertLessEqual(policy.tool_timeout_seconds(test_type, parameters), 60, test_type)


class RuntimeBoundaryTests(SimpleTestCase):
    """The one process boundary: what a ``docker`` invocation of the runner can and cannot be."""

    BASE = dict(name=f"nmas-traffic-{RID.replace('-', '')}-tool", instance="nmas", run_id=RID, netns="1" * 64, image=t.IMAGE)

    def test_the_exact_argv_of_a_ping(self):
        argv = runtime._run_args(**self.BASE, tool="ping", args=["-4", "-n", "-c", 3, "192.168.20.101"], detached=False)
        self.assertEqual(argv, [
            "run", "--rm", "--pull", "never", "--name", self.BASE["name"],
            "--label", "nmas.traffic.instance=nmas", "--label", f"nmas.traffic.run={RID}", "--label", "nmas.traffic.role=tool",
            "--network", "container:" + "1" * 64,
            "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--cap-drop", "ALL", "--cap-add", "NET_RAW",
            "--security-opt", "no-new-privileges", "--pids-limit", "32", "--memory", "96m", "--memory-swap", "96m", "--cpus", "1",
            "--user", "0:0", "--entrypoint", "/bin/ping", t.IMAGE, "-4", "-n", "-c", "3", "192.168.20.101"])

    def test_every_tool_is_locked_down_and_only_raw_socket_tools_get_one_capability(self):
        for tool, (entrypoint, fixed, raw) in runtime.TOOLS.items():
            for detached in (False, True):
                argv = runtime._run_args(**self.BASE, tool=tool, args=["x"], detached=detached)
                for required in ("--read-only", "--pull", "never", "no-new-privileges", "--pids-limit", "--memory", "--cpus"):
                    self.assertIn(required, argv, tool)
                self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")
                self.assertEqual(argv.count("--cap-add"), 1 if raw else 0, tool)
                self.assertEqual(argv[argv.index("--user") + 1], "0:0" if raw else "65534:65534", tool)
                self.assertEqual(argv[argv.index("--network") + 1], "container:" + "1" * 64)
                self.assertEqual(argv[argv.index("--entrypoint") + 1:][:2 + len(fixed)], [entrypoint, t.IMAGE, *fixed])
                self.assertEqual(("--detach" in argv, "--rm" in argv), (detached, not detached))
                for forbidden in ("--privileged", "-v", "--volume", "--mount", "--pid", "--ipc", "--device", "-i", "-t", "-it", "--env", "-e",
                                  "host", "--cap-add=ALL", "SYS_ADMIN", "NET_ADMIN"):
                    self.assertNotIn(forbidden, argv, (tool, forbidden))
        self.assertEqual({tool for tool, (_e, _f, raw) in runtime.TOOLS.items() if raw}, {"ping", "traceroute"})
        self.assertEqual(sorted(runtime.TOOLS), ["ip", "iperf3", "ping", "tcp_connect", "traceroute", "udp_probe"])     # no shell, no nc, no nmap
        for tool in ("tcp_connect", "udp_probe"):                                    # python runs ONLY a script baked into the pinned image
            self.assertEqual(runtime.TOOLS[tool][1][:2], ("-I", "-B"))
            self.assertTrue(runtime.TOOLS[tool][1][2].startswith("/opt/nmas-traffic/"))

    def test_no_arbitrary_tool_argument_name_namespace_image_or_instance(self):
        good = dict(self.BASE, tool="ping", args=["x"], detached=False)
        runtime._run_args(**good)
        for change in ({"tool": "sh"}, {"tool": "bash"}, {"tool": "python3"}, {"tool": "nc"}, {"tool": "/bin/ping"},
                       {"args": ["192.168.1.1; id"]}, {"args": ["$(id)"]}, {"args": ["a b"]}, {"args": ["`id`"]}, {"args": ["x\ny"]},
                       {"args": ["x" * 200]}, {"args": ["a|b"]}, {"args": ["a&b"]}, {"args": [">x"]},
                       {"name": "netbox-netbox-1"}, {"name": "clab-srlceos01-R1"}, {"name": self.BASE["name"] + "x"},
                       {"name": f"nmas-traffic-{'0' * 32}-tool"},                     # a well-formed name of ANOTHER run
                       {"name": self.BASE["name"][:-4] + "evil"},
                       {"netns": "clab-srlceos01-H1"}, {"netns": "host"}, {"netns": "1" * 63}, {"netns": ""},
                       {"image": "alpine:latest"}, {"image": "nmas-traffic-tools:1"}, {"image": "sha256:xyz"}, {"image": "ceos:4.36.2F"},
                       {"instance": "x y"}, {"instance": "--privileged"}, {"run_id": "nope"}):
            with self.assertRaises(runtime.RuntimeFailure, msg=change) as raised:
                runtime._run_args(**{**good, **change})
            self.assertEqual(raised.exception.code, "OPERATION_NOT_ALLOWED")

    def test_only_the_runners_own_containers_can_be_inspected_logged_or_removed(self):
        with mock.patch.object(runtime, "_docker") as spawned:
            for name in ("clab-srlceos01-R1", "netbox-netbox-1", "", "nmas-traffic-", "$(id)", "-f", "--all", "nmas-traffic-" + "g" * 32 + "-tool"):
                for call in (runtime.remove, runtime.container_state, runtime.logs):
                    with self.assertRaises(runtime.RuntimeFailure, msg=name):
                        call(name)
            spawned.assert_not_called()
            spawned.return_value = runtime.Completed(0, "", "")
            runtime.remove(self.BASE["name"])
        self.assertEqual(spawned.call_args.args[0], ["rm", "--force", self.BASE["name"]])     # one exact name: no filter, no prune, no pkill

    def test_the_single_spawn_uses_a_fixed_binary_no_shell_no_stdin_and_a_timeout(self):
        with mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "out", "err")) as spawned:
            done = runtime._docker(["ps"], timeout=7)
        self.assertEqual((done.returncode, done.stdout, done.timed_out), (0, "out", False))
        self.assertEqual(spawned.call_args.args[0], ["/usr/bin/docker", "ps"])
        kwargs = spawned.call_args.kwargs
        self.assertEqual((kwargs["shell"], kwargs["timeout"], kwargs["stdin"], kwargs["check"]), (False, 7, subprocess.DEVNULL, False))
        self.assertEqual(set(kwargs["env"]), {"PATH", "DOCKER_CONFIG"})               # nothing inherited from the service environment
        with mock.patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired(["x"], 5, output=b"partial")):
            done = runtime._docker(["run"], timeout=5)
        self.assertEqual((done.timed_out, done.stdout), (True, "partial"))
        with mock.patch.object(subprocess, "run", side_effect=FileNotFoundError()), self.assertRaises(runtime.RuntimeFailure) as raised:
            runtime._docker(["ps"], timeout=5)
        self.assertEqual(raised.exception.code, "RUNTIME_UNAVAILABLE")

    def _inspect(self, document, code=0):
        return mock.patch.object(runtime, "_docker", return_value=runtime.Completed(code, json.dumps([document]), ""))

    def test_an_endpoint_is_a_running_node_of_the_lab_with_the_expected_node_name(self):
        good = {"Id": "c" * 64, "State": {"Running": True}, "Config": {"Labels": {"containerlab": "srlceos01", "clab-node-name": "H1"}}}
        with self._inspect(good) as spawned:
            self.assertEqual(runtime.inspect_endpoint("clab-srlceos01-H1", lab="srlceos01", node="H1"), "c" * 64)
        self.assertEqual(spawned.call_args.args[0], ["inspect", "--type", "container", "clab-srlceos01-H1"])
        labels = good["Config"]["Labels"]
        cases = (({**good, "Config": {"Labels": {**labels, "containerlab": "other"}}}, 0, "ENDPOINT_WRONG_LAB"),
                 ({**good, "Config": {"Labels": {**labels, "clab-node-name": "R1"}}}, 0, "ENDPOINT_WRONG_LAB"),
                 ({**good, "Config": {"Labels": {}}}, 0, "ENDPOINT_WRONG_LAB"),
                 ({**good, "State": {"Running": False}}, 0, "ENDPOINT_NOT_RUNNING"), ({**good, "Id": "short"}, 0, "ENDPOINT_NOT_RUNNING"),
                 ({}, 1, "ENDPOINT_NOT_FOUND"))
        for document, code, expected in cases:
            with self._inspect(document, code), self.assertRaises(runtime.RuntimeFailure) as raised:
                runtime.inspect_endpoint("clab-srlceos01-H1", lab="srlceos01", node="H1")
            self.assertEqual(raised.exception.code, expected)
        with mock.patch.object(runtime, "_docker") as spawned:
            for name in ("1234", "H1; rm -rf /", "../x", "", "clab-srlceos01-H1 --format x", "host", "netbox-netbox-1", "a" * 64):
                with self.assertRaises(runtime.RuntimeFailure):
                    runtime.inspect_endpoint(name, lab="srlceos01", node="H1")
        spawned.assert_not_called()

    def test_contract_one_launch_point_in_a_self_contained_package(self):
        """Exactly ONE ``subprocess`` call in the whole runner, in ``runtime.py``; standard library and relative imports only."""
        allowed = {"__future__", "argparse", "dataclasses", "ipaddress", "json", "os", "re", "signal", "socket", "stat", "struct", "subprocess",
                   "sys", "threading", "time", "uuid"}
        spawns = {}
        for path in sorted(RUNNER_DIR.glob("*.py")):
            tree, text = ast.parse(path.read_text()), path.read_text()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertIn(alias.name.split(".")[0], allowed, f"{path.name} imports {alias.name}")
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    self.assertIn((node.module or "").split(".")[0], allowed, f"{path.name} imports {node.module}")
            calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                     and getattr(n.func.value, "id", "") == "subprocess"]
            if calls or "import subprocess" in text:
                spawns[path.name] = calls
            for forbidden in ("shell=True", "os.system", "os.popen", "os.exec", "os.spawn", "os.fork", "Popen", "pkill", "killall", "prune",
                              "--privileged", "nsenter", "sudo", "eval(", "exec(", "django"):
                cleaned = text.replace("no ``--privileged``", "").replace("no ``pkill``", "").replace("no prune", "")
                self.assertFalse(forbidden in cleaned, f"{path.name}: {forbidden}")
        self.assertEqual(sorted(spawns), ["runtime.py"])
        self.assertEqual(len(spawns["runtime.py"]), 1)
        shell = [k.value.value for k in spawns["runtime.py"][0].keywords if k.arg == "shell"]
        self.assertEqual(shell, [False])
        tree = ast.parse((RUNNER_DIR / "runtime.py").read_text())
        direct = [n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "_docker"]
        self.assertGreaterEqual(len(direct), 6)                                       # every runtime operation goes through the one spawn
        for path in RUNNER_DIR.glob("*.py"):                                          # and nobody outside runtime.py reaches it
            if path.name != "runtime.py":
                self.assertNotIn("_docker", path.read_text(), path.name)

    def test_the_package_runs_standalone_from_a_copy_without_django(self):
        with tempfile.TemporaryDirectory() as root:
            shutil.copytree(RUNNER_DIR, Path(root) / "nmas_traffic_runner", ignore=shutil.ignore_patterns("__pycache__"))
            code = ("import sys, nmas_traffic_runner.__main__ as m, nmas_traffic_runner.engine as e; "
                    "assert 'django' not in sys.modules and 'core' not in sys.modules; print(m.RUNNER_VERSION)")
            done = subprocess.run([sys.executable, "-I", "-c", f"import sys; sys.path.insert(0, {root!r}); {code}"], capture_output=True,
                                  text=True, timeout=60, check=False)
        self.assertEqual((done.returncode, done.stdout.strip()), (0, "traffic-runner-1"), done.stderr)


class EngineFailureTests(SimpleTestCase):
    def run_one(self, world=None, document=None):
        broker, world, logs = make(world)
        return broker.handle(document or doc(), peer_uid=t.PEER_UID), world, logs

    def assert_clean(self, reply, world):
        self.assertEqual(world.containers, {})
        self.assertTrue(reply["cleanup"]["verified"])
        prefix = f"nmas-traffic-{RID.replace('-', '')}-"
        self.assertTrue(all(name.startswith(prefix) for name in world.removed), world.removed)

    def test_every_family_removes_exactly_the_containers_it_created(self):
        families = (doc(), doc(address_family="IPV6"), doc(test_type="TRACEROUTE", parameters={"max_hops": 15}),
                    doc(test_type="TCP_CONNECT", protocol="TCP", parameters={"port": 80, "timeout": 3}),
                    doc(test_type="UDP_PROBE", protocol="UDP", parameters={"port": 53, "timeout": 2, "count": 3, "size": 64}),
                    iperf(), iperf(length=1200) | {"protocol": "UDP", "address_family": "IPV6"})
        for document in families:
            reply, world, _ = self.run_one(document=document)
            self.assertTrue(reply["ok"], reply)
            self.assert_clean(reply, world)
            created = {argv[argv.index("--name") + 1] for argv in world.argv}
            self.assertEqual(set(reply["cleanup"]["containers"]), created)             # everything started was removed, and nothing else
            self.assertEqual({argv[argv.index("--label") + 3].split("=")[1] for argv in world.argv}, {RID})
            self.assertTrue(all(t.IMAGE in argv for argv in world.argv))

    def test_two_runs_never_share_a_container_name(self):
        broker, world, _ = make()
        other = str(uuid.uuid4())
        broker.handle(iperf(), peer_uid=1)
        broker.handle(iperf() | {"run_id": other}, peer_uid=1)
        names = [argv[argv.index("--name") + 1] for argv in world.argv]
        first, second = {n for n in names if RID.replace("-", "") in n}, {n for n in names if other.replace("-", "") in n}
        self.assertEqual((len(first), len(second), first & second), (4, 4, set()))
        self.assertEqual(first | second, set(names))

    def test_tools_image_missing_and_tools_container_fails_to_start(self):
        world = t.World(); world.image_present = False
        reply, world, _ = self.run_one(world)
        self.assertEqual((reply["ok"], reply["code"], world.calls), (False, "TOOLS_IMAGE_MISSING", []))
        for tool in ("ip", "ping"):
            world = t.World(); world.start_fails.add(tool)
            reply, world, _ = self.run_one(world)
            self.assertEqual((reply["ok"], reply["code"]), (False, "TOOLS_START_FAILED"), tool)
            self.assert_clean(reply, world)

    def test_endpoint_missing_before_and_disappearing_during_the_run(self):
        world = t.World(); world.missing.add("clab-srlceos01-H1")
        reply, world, _ = self.run_one(world)
        self.assertEqual((reply["code"], world.calls), ("ENDPOINT_NOT_FOUND", []))
        for document, tool in ((doc(), "ping"), (iperf(), "iperf3")):
            world = t.World(); world.vanish_during.add(tool)
            reply, world, _ = self.run_one(world, document)
            self.assertEqual((reply["ok"], reply["code"]), (False, "ENDPOINT_LOST"), tool)
            self.assertNotIn("stdout", reply)                                          # a half-run measurement is not evidence
            self.assert_clean(reply, world)

    def test_an_endpoint_replaced_by_another_container_of_the_same_name_is_lost_not_trusted(self):
        world = t.World(); world.timeouts.add("ping")
        original = world.inspect_endpoint
        seen = []

        def swapped(container, *, lab, node):
            seen.append(container)
            identity = original(container, lab=lab, node=node)
            return "9" * 64 if seen.count(container) > 1 else identity

        world.inspect_endpoint = swapped
        reply, world, _ = self.run_one(world)
        self.assertEqual(reply["code"], "ENDPOINT_LOST")

    def test_iperf_server_fails_to_start_or_to_listen(self):
        world = t.World(); world.start_fails.add("server")
        reply, world, _ = self.run_one(world, iperf())
        self.assertEqual((reply["code"], reply["server"]["started"]), ("TOOLS_START_FAILED", False))
        self.assertNotIn("iperf3", world.tools())
        self.assert_clean(reply, world)
        for flag in ("server_listens", "port_busy"):
            world = t.World(); setattr(world, flag, flag == "port_busy")
            reply, world, _ = self.run_one(world, iperf())
            self.assertEqual((reply["code"], reply["server"]["ready"], reply["server"]["stopped"], reply["server"]["exit_code"]),
                             ("SERVER_START_FAILED", False, True, 1), flag)
            self.assertNotIn("iperf3", world.tools())
            self.assert_clean(reply, world)

    def test_a_tool_timeout_is_reported_and_its_container_removed(self):
        world = t.World(); world.timeouts.add("ping")
        reply, world, _ = self.run_one(world)
        self.assertEqual((reply["ok"], reply["timed_out"]), (True, True))
        self.assert_clean(reply, world)
        self.assertIn(f"nmas-traffic-{RID.replace('-', '')}-tool", world.removed)

    def test_a_container_that_cannot_be_removed_fails_the_run_loudly(self):
        world = t.World(); world.timeouts.add("ping"); world.unremovable.add("-tool")
        reply, world, logs = self.run_one(world)
        self.assertEqual((reply["ok"], reply["code"], reply["cleanup"]["verified"]), (False, "RUNTIME_NOT_CLEANED", False))
        self.assertEqual(reply["cleanup"]["left_behind"], [f"nmas-traffic-{RID.replace('-', '')}-tool"])
        self.assertFalse(logs[-1]["cleanup_verified"])

    def test_a_replayed_run_id_is_refused_and_the_earlier_runs_containers_are_untouched(self):
        world = t.World()
        earlier = f"nmas-traffic-{RID.replace('-', '')}-server"
        world.containers[earlier] = {"running": True, "exit_code": 0, "logs": ""}
        reply, world, _ = self.run_one(world, iperf())
        self.assertEqual((reply["ok"], reply["code"]), (False, "RUN_ID_REPLAYED"))
        self.assertEqual((world.removed, list(world.containers), world.calls), ([], [earlier], []))

    def test_concurrent_run_limit_is_the_runners_own(self):
        world, entered, release = t.World(), threading.Event(), threading.Event()
        original = world.run_tool

        def slow(**kwargs):
            entered.set()
            release.wait(10)
            return original(**kwargs)

        world.run_tool = slow
        broker, world, logs = make(world)
        replies = []
        first = threading.Thread(target=lambda: replies.append(broker.handle(doc(), peer_uid=1)))
        first.start()
        self.assertTrue(entered.wait(10))
        busy = broker.handle(doc(run_id=str(uuid.uuid4())), peer_uid=1)
        self.assertEqual((busy["ok"], busy["code"], busy["refused"]), (False, "BUSY", True))
        self.assertNotIn("cleanup", busy)
        self.assertEqual(world.removed, [])                                            # the refused request did not disturb the running one
        release.set(); first.join(10)
        self.assertTrue(replies[0]["ok"])
        self.assertTrue(broker.handle(doc(run_id=str(uuid.uuid4())), peer_uid=1)["ok"])   # the slot is released afterwards

    def test_a_runner_defect_is_a_stable_code_and_the_slot_and_containers_are_released(self):
        world = t.World(); world.run_tool = mock.Mock(side_effect=RuntimeError("boom: secret /etc/shadow"))
        broker, world, logs = make(world)
        reply = broker.handle(doc(), peer_uid=1)
        self.assertEqual((reply["ok"], reply["code"]), (False, "INTERNAL_ERROR"))
        self.assertNotIn("boom", json.dumps(reply) + json.dumps(logs))
        world.run_tool = t.World.run_tool.__get__(world)
        self.assertTrue(broker.handle(doc(run_id=str(uuid.uuid4())), peer_uid=1)["ok"])

    def test_restart_reconciliation_removes_only_this_instances_abandoned_containers(self):
        world = t.World()
        abandoned = [f"nmas-traffic-{uuid.uuid4().hex}-server", f"nmas-traffic-{uuid.uuid4().hex}-tool"]
        for name in abandoned:
            world.containers[name] = {"running": True, "exit_code": 0, "logs": ""}
        broker, world, logs = make(world)
        self.assertEqual(broker.reconcile(), sorted(abandoned))
        self.assertEqual((world.containers, sorted(world.removed)), ({}, sorted(abandoned)))
        self.assertEqual([r["event"] for r in logs], ["abandoned_container_removed"] * 2)
        with mock.patch.object(runtime, "_docker", return_value=runtime.Completed(0, "clab-srlceos01-R1\nnetbox-netbox-1\n" + abandoned[0] + "\n", "")) as spawned:
            self.assertEqual(runtime.owned("nmas"), [abandoned[0]])                   # even a mislabelled foreign container is never ours
        self.assertEqual(spawned.call_args.args[0], ["ps", "--all", "--filter", "label=nmas.traffic.instance=nmas", "--format", "{{.Names}}"])
        failing = t.World(); failing.owned = mock.Mock(side_effect=runtime.RuntimeFailure("RUNTIME_UNAVAILABLE"))
        broker, _w, logs = make(failing)
        self.assertEqual((broker.reconcile(), logs[-1]["event"]), ([], "reconcile_failed"))

    def test_the_audit_line_correlates_to_the_run_and_carries_no_output_or_environment(self):
        world = t.World(); world.outputs["ping"] = t.PING_OK + "SECRET-TOOL-OUTPUT"
        with mock.patch.dict(os.environ, {"NMAS_TEST_SECRET": "hunter2-do-not-log"}):
            reply, world, logs = self.run_one(world)
            refused, _w, refused_logs = self.run_one(document=doc(test_type="FLOOD"))
        self.assertEqual(len(logs), 1)
        self.assertEqual({k: logs[0][k] for k in ("event", "run_id", "source", "destination", "test_type", "address_family", "protocol", "outcome",
                                                 "peer_uid", "cleanup_verified", "containers")},
                         {"event": "traffic_run", "run_id": RID, "source": "H1", "destination": "H2", "test_type": "ICMP", "address_family": "IPV4",
                          "protocol": "ICMP", "outcome": "OK", "peer_uid": t.PEER_UID, "cleanup_verified": True, "containers": 3})
        self.assertIsInstance(logs[0]["duration_ms"], int)
        self.assertEqual((refused_logs[0]["run_id"], refused_logs[0]["outcome"], refused_logs[0]["refused"]), (RID, "UNSUPPORTED_TEST_TYPE", True))
        text = json.dumps(logs + refused_logs)
        for forbidden in ("SECRET-TOOL-OUTPUT", "hunter2", "NMAS_TEST_SECRET", "PATH", "192.168.", "environ"):
            self.assertNotIn(forbidden, text)


class ConfigurationTests(TestCase):
    def test_the_installed_catalogue_is_the_tracked_endpoints_with_a_pinned_image(self):
        settings = t.runner_configuration()
        self.assertEqual(sorted(settings.endpoints), ["H1", "H2", "H3", "H4", "WebServer"])
        self.assertEqual((settings.lab, settings.endpoints["H1"].container, settings.endpoints["H4"].families), ("srlceos01", "clab-srlceos01-H1", ("IPV6",)))
        self.assertEqual((settings.tools_image, settings.allowed_peer_uids), (t.IMAGE, frozenset({t.PEER_UID})))

    def test_a_configuration_cannot_point_an_endpoint_at_an_arbitrary_container_or_a_mutable_image(self):
        from core.services.traffic import endpoints
        good = endpoints.runner_config(tools_image=t.IMAGE, allowed_peer_uids=[1001])
        config.parse(good)
        bad = (
            {**good, "tools_image": "nmas-traffic-tools:1"}, {**good, "tools_image": "alpine:latest"}, {**good, "tools_image": "ceos:4.36.2F"},
            {**good, "allowed_peer_uids": []}, {**good, "allowed_peer_uids": ["1001"]}, {**good, "allowed_peer_uids": [True]},
            {**good, "endpoints": {}}, {**good, "endpoints": {**good["endpoints"], "R1": {"container": "netbox-netbox-1", "families": ["IPV4"]}}},
            {**good, "endpoints": {"H1": {"container": "clab-other-H1", "families": ["IPV4"]}}},
            {**good, "endpoints": {"H1": {"container": "clab-srlceos01-H2", "families": ["IPV4"]}}},
            {**good, "endpoints": {"H1": {"container": "clab-srlceos01-H1", "families": ["IPX"]}}},
            {**good, "endpoints": {"H1": {"container": "clab-srlceos01-H1", "families": ["IPV4"], "image": "x"}}},
            {**good, "instance": "a b"}, {**good, "lab": "x; y"}, {**good, "extra": 1}, {k: v for k, v in good.items() if k != "lab"}, [], None,
        )
        for document in bad:
            with self.assertRaises(config.ConfigError, msg=document):
                config.parse(document)

    def test_a_configuration_file_others_can_write_is_refused(self):
        from core.services.traffic import endpoints
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "traffic-runner.json"
            path.write_text(json.dumps(endpoints.runner_config(tools_image=t.IMAGE, allowed_peer_uids=[1001])))
            path.chmod(0o644)
            self.assertEqual(config.load(str(path)).lab, "srlceos01")
            for mode in (0o664, 0o646, 0o666):
                path.chmod(mode)
                with self.assertRaises(config.ConfigError):
                    config.load(str(path))
            path.chmod(0o644)
            with mock.patch.object(os, "geteuid", return_value=os.geteuid() + 1), self.assertRaises(config.ConfigError):
                config.load(str(path))                                                 # owned by somebody who is neither root nor the runner
            path.write_text("{not json")
            with self.assertRaises(config.ConfigError):
                config.load(str(path))
        with mock.patch.object(entry, "_log") as logged:
            self.assertEqual(entry.main(["--config", "/nonexistent/traffic-runner.json"]), 2)
        self.assertEqual(logged.call_args.args[0]["event"], "startup_refused")

    def test_the_render_command_refuses_a_tag_and_prints_what_the_runner_accepts(self):
        from io import StringIO
        from django.core.management import CommandError, call_command
        out = StringIO()
        call_command("traffic_runner_config", "--tools-image", t.IMAGE, "--peer-uid", "1001", stdout=out)
        parsed = config.parse(json.loads(out.getvalue()))
        self.assertEqual((sorted(parsed.endpoints), parsed.allowed_peer_uids), (["H1", "H2", "H3", "H4", "WebServer"], frozenset({1001})))
        with self.assertRaises(CommandError):
            call_command("traffic_runner_config", "--tools-image", "nmas-traffic-tools:1", "--peer-uid", "1001", stdout=StringIO())


class _Runner:
    """A real runner (engine + socket server) on a private Unix socket, over a scripted runtime."""

    def __init__(self, world=None, *, allowed=None, mode=0o660, engine_override=None):
        self.directory = tempfile.mkdtemp(prefix="nmas-traffic-test-")
        self.path = os.path.join(self.directory, "runner.sock")
        self.world, self.logs, self.stop = world or t.World(), [], threading.Event()
        self.engine = engine_override or engine.Engine(t.runner_configuration(), runtime=self.world, sleep=lambda s: None, log=self.logs.append)
        self.listener = entry._listener(self.path)
        self.created_mode = stat.S_IMODE(os.stat(self.path).st_mode)
        os.chmod(self.path, mode)
        allowed = {os.getuid()} if allowed is None else allowed
        self.thread = threading.Thread(target=server.serve, args=(self.listener, self.engine, allowed, self.logs.append), kwargs={"stop": self.stop})
        self.thread.start()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join(10)
        self.listener.close()
        shutil.rmtree(self.directory, ignore_errors=True)

    def raw(self, payload: bytes, *, close_write=True) -> dict:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(10)
            connection.connect(self.path)
            connection.sendall(payload)
            if close_write:
                connection.shutdown(socket.SHUT_WR)
            data = b""
            while chunk := connection.recv(65536):
                data += chunk
        return json.loads(data)


class IpcTests(TestCase):
    """The website's client against a real runner over a real Unix socket."""

    def request(self, runner, **overrides):
        with override_settings(NMAS_TRAFFIC_RUNNER_SOCKET=runner.path):
            return ts.request_run(t.request(**overrides), operator="tester")

    def test_the_whole_chain_over_the_socket(self):
        world = t.World(); world.outputs["iperf3"] = t.iperf_udp()
        with _Runner(world) as runner:
            run, errors = self.request(runner, family="IPERF3", protocol="UDP", address_family="IPV6", length="1000")
            self.assertEqual(runner.created_mode, 0o660)                              # a self-bound socket is never world-accessible
        self.assertEqual((errors, run.status, run.failure_reason), ([], S.PASSED, ""))
        self.assertEqual((run.source_address, run.destination_address), ("2001:db8:10::2001", "2001:db8:20::2001"))
        self.assertEqual(run.operation["runtime"]["cleanup"]["verified"], True)
        self.assertEqual(runner.world.containers, {})
        self.assertEqual([r["run_id"] for r in runner.logs if r["event"] == "traffic_run"], [str(run.run_id)])
        self.assertEqual(runner.logs[-1]["peer_uid"], os.getuid())

    def test_socket_permission_refusal_fails_closed(self):
        if os.geteuid() == 0:
            self.skipTest("root bypasses socket file permissions")
        with _Runner(mode=0o000) as runner:
            run, _errors = self.request(runner)
            self.assertEqual((run.status, run.failure_reason, run.metrics, run.raw_output), (S.FAILED, "RUNNER_UNAVAILABLE", {}, ""))
            self.assertEqual((runner.world.calls, runner.logs), ([], []))

    def test_a_peer_that_is_not_the_website_account_is_refused_before_its_request_is_read(self):
        with _Runner(allowed={os.getuid() + 1}) as runner:
            reply = runner.raw(json.dumps(doc()).encode() + b"\n")
            self.assertEqual((reply["ok"], reply["code"], reply["run_id"]), (False, "UNAUTHORIZED", ""))
            run, _errors = self.request(runner)
            self.assertEqual((run.status, run.failure_reason), (S.FAILED, "UNAUTHORIZED"))
            self.assertEqual(runner.world.calls, [])
            self.assertEqual({r["outcome"] for r in runner.logs}, {"UNAUTHORIZED"})
        engine_spy = mock.Mock()
        connection = mock.Mock()
        server.handle_connection(connection, engine_spy, {0}, lambda record: None, peer=mock.Mock(side_effect=OSError()))
        engine_spy.handle.assert_not_called()                                         # credentials that cannot be read are not trusted
        self.assertIn(b"UNAUTHORIZED", connection.sendall.call_args.args[0])

    def test_malformed_bytes_on_the_socket_are_refused(self):
        with _Runner() as runner:
            for payload in (b"", b"\n", b"ping -f 8.8.8.8\n", b"not json\n", b"[1,2,3]\n", b'"H1"\n', b"\xff\xfe\n", b"{" * 100 + b"\n",
                            b'{"v":1,"pad":"' + b"x" * 8000 + b'"}\n', b"x" * 100_000):
                reply = runner.raw(payload)
                self.assertEqual((reply["ok"], reply["code"], reply["refused"]), (False, "MALFORMED_REQUEST", True), payload[:30])
            reply = runner.raw(json.dumps({**doc(), "command": "id"}).encode() + b"\n")
            self.assertEqual(reply["code"], "MALFORMED_REQUEST")
            self.assertEqual(runner.world.calls, [])
            good = runner.raw(json.dumps(doc()).encode() + b"\n", close_write=False)    # a client need not half-close
            self.assertTrue(good["ok"])

    def test_a_silent_peer_cannot_hold_the_runner(self):
        with mock.patch.object(server, "READ_TIMEOUT_SECONDS", 0.2), _Runner() as runner:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as idle:
                idle.settimeout(10)
                idle.connect(runner.path)
                idle.sendall(b'{"v":1')                                                 # never finishes its request
                self.assertTrue(runner.raw(json.dumps(doc()).encode() + b"\n")["ok"])  # another client is still served meanwhile
                self.assertEqual(json.loads(idle.recv(65536))["code"], "MALFORMED_REQUEST")

    def test_runner_unavailable_and_runner_timeout_are_recorded_never_passed(self):
        with override_settings(NMAS_TRAFFIC_RUNNER_SOCKET="/nonexistent/nmas/runner.sock"):
            run, _errors = ts.request_run(t.request(), operator="tester")
        self.assertEqual((run.status, run.failure_reason), (S.FAILED, "RUNNER_UNAVAILABLE"))
        self.assertIsNone(ts.active_run())
        hung = mock.Mock()
        hung.handle.side_effect = lambda document, peer_uid=None: threading.Event().wait(1.0) or {"v": 1, "ok": False, "run_id": document["run_id"], "code": "TIMEOUT"}
        with _Runner(engine_override=hung) as runner, mock.patch.object(client, "RUNNER_OVERHEAD_SECONDS", -10.8):
            run, _errors = self.request(runner)                                        # budget: 3 * 2 + 5 - 10.8 = 0.2 s
        self.assertEqual((run.status, run.failure_reason, run.metrics), (S.TIMED_OUT, "RUNNER_TIMEOUT", {}))
        self.assertIsNone(ts.active_run())

    def test_a_reply_that_is_not_the_runners_answer_to_this_run_is_a_failure(self):
        for reply in ({"v": 1, "ok": True, "run_id": "00000000-0000-4000-8000-000000000000", "exit_code": 0, "stdout": t.PING_OK}, "garbage",
                      {"v": 9, "ok": True}):
            fake = mock.Mock(); fake.handle.return_value = reply
            with _Runner(engine_override=fake) as runner:
                run, _errors = self.request(runner)
            self.assertEqual((run.status, run.failure_reason, run.metrics), (S.FAILED, "RUNNER_PROTOCOL_ERROR", {}), reply)

    def test_the_runners_own_refusal_reaches_the_run_when_the_website_layer_is_bypassed(self):
        """Layer two alone: a run row the website would never have created (as if its validation had been removed)."""
        cases = (({"family": "IPERF3", "protocol": "TCP", "parameters": {"port": 5201, "duration": 3600, "bandwidth_kbps": 1000, "parallel": 1}}, "PARAMETER_OUT_OF_BOUNDS"),
                 ({"family": "IPERF3", "protocol": "TCP", "parameters": {"port": 22, "duration": 3, "bandwidth_kbps": 1000, "parallel": 1}}, "PARAMETER_OUT_OF_BOUNDS"),
                 ({"family": "IPERF3", "protocol": "TCP", "parameters": {"port": 5201, "duration": 3, "bandwidth_kbps": 10**6, "parallel": 1}}, "PARAMETER_OUT_OF_BOUNDS"),
                 ({"source": "R1"}, "UNKNOWN_ENDPOINT"), ({"destination": "clab-srlceos01-R1"}, "UNKNOWN_ENDPOINT"),
                 ({"destination": "H4"}, "FAMILY_NOT_SUPPORTED_BY_ENDPOINT"), ({"family": "FLOOD"}, "UNSUPPORTED_TEST_TYPE"),
                 ({"parameters": {"count": 3, "size": 56, "argv": "--flood"}}, "MALFORMED_REQUEST"))
        with t.wired() as world:
            for overrides, code in cases:
                values = dict(operator="t", source="H1", destination="H2", address_family="IPV4", family="ICMP", protocol="ICMP",
                              parameters={"count": 3, "size": 56})
                values.update(overrides)
                run = ts.service.execute(models.TrafficRun.objects.create(**values))
                self.assertEqual((run.status, run.failure_reason), (S.FAILED, code), overrides)
            self.assertEqual((world.calls, world.argv), ([], []))


@unittest.skipUnless(shutil.which("docker"), "needs a container runtime")
class LiveRuntimeSmokeTests(SimpleTestCase):
    """Opt-in (NMAS_TRAFFIC_LIVE_TESTS=1): the real ``docker`` client must accept the runner's fixed argument shapes."""

    @unittest.skipUnless(os.environ.get("NMAS_TRAFFIC_LIVE_TESTS") == "1", "set NMAS_TRAFFIC_LIVE_TESTS=1 on the lab host")
    def test_an_absent_container_is_absent_and_removal_is_idempotent(self):
        name = f"nmas-traffic-{uuid.uuid4().hex}-tool"
        self.assertIsNone(runtime.container_state(name))
        runtime.remove(name)
        self.assertNotIn(name, runtime.owned("nmastest"))
