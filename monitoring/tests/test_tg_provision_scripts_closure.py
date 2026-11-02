"""Lab 7 closure -- the root-only provisioning scripts piped into containers / the NMAS host (``provision_*.py``).

Their module bodies converge real system state the moment they are imported (they read a JSON payload on stdin, write
under ``/etc``, call ``apt-get`` / ``systemctl`` / ``start-stop-daemon``), so the module body is never executed here and
the deployed files are never edited.  Instead ``function_namespace`` compiles ONLY the named function definitions from
the tracked source, under the script's real path (each function keeps its identity), into a namespace whose
``subprocess`` / ``os`` / ``pathlib`` / ``socket`` / ``time`` are fakes and whose absolute paths are re-rooted into a
temporary directory.

POSITIVE: exact command lines, written content and modes, discovered / managed PIDs.  NEGATIVE: a failing command
raises ``CalledProcessError``, unchanged content is never rewritten, a symlink is refused, absent processes are never
matched, a process that ignores SIGTERM is killed, an adapter that dies after start fails the run.
"""
from __future__ import annotations

import ast
import contextlib
import signal
import subprocess
import tempfile
import types
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
RUN_SCRIPTS = ("provision_ceos_syslog_forwarder.py", "provision_gnmi_collector.py", "provision_linux_snmp.py", "provision_linux_syslog.py",
               "provision_linux_telemetry.py", "provision_snmp_receiver.py", "provision_syslog_receiver.py", "provision_topology.py")


def function_namespace(name, functions, **module_globals):
    path = SCRIPTS / name
    tree = ast.parse(path.read_text(), filename=str(path))
    tree.body = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in functions]
    if {node.name for node in tree.body} != set(functions):
        raise AssertionError(f"{name} no longer defines {sorted(functions)}")
    namespace = {"__name__": "nmas_provision_" + path.stem, "__file__": str(path), **module_globals}
    exec(compile(tree, str(path), "exec"), namespace)   # noqa: S102 - the tracked repository script's own definitions
    return namespace


class FakeSubprocess:
    DEVNULL = subprocess.DEVNULL
    CalledProcessError = subprocess.CalledProcessError

    def __init__(self, returncode=0, on_run=None):
        self.returncode, self.on_run, self.calls = returncode, on_run, []

    def run(self, args, check=False, **kwargs):
        self.calls.append((list(args), dict(kwargs, check=check)))
        if self.on_run:
            self.on_run(list(args))
        if check and self.returncode:
            raise subprocess.CalledProcessError(self.returncode, list(args))
        return subprocess.CompletedProcess(list(args), self.returncode)


class FakeOs:
    def __init__(self):
        self.chowns, self.kills = [], []

    def chown(self, path, uid, gid):
        self.chowns.append((Path(path), uid, gid))

    def kill(self, pid, sig):
        self.kills.append((pid, sig))


class TempCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        # Absolute paths named by the scripts ("/proc", "/run/...") are re-rooted under the temporary directory.
        self.pathlib = types.SimpleNamespace(Path=lambda value: self.root / str(value).lstrip("/"))


class RunHelperTests(TempCase):
    def test_run_executes_the_command_checked_with_stdout_discarded(self):
        for name in RUN_SCRIPTS:
            with self.subTest(name):
                fake = FakeSubprocess()
                function_namespace(name, {"run"}, subprocess=fake)["run"]("systemctl", "daemon-reload")
                self.assertEqual(fake.calls, [(["systemctl", "daemon-reload"], {"stdout": subprocess.DEVNULL, "check": True})])

    def test_run_of_a_failing_command_raises(self):
        for name in RUN_SCRIPTS:
            with self.subTest("refused exit 1 " + name):
                run = function_namespace(name, {"run"}, subprocess=FakeSubprocess(returncode=1))["run"]
                with self.assertRaises(subprocess.CalledProcessError):
                    run("systemctl", "restart", "x.service")


class ChownWriteIfChangedTests(TempCase):
    """``provision_gnmi_collector`` and ``provision_topology`` share the write / chmod / ``chown root:root`` helper."""

    def namespace(self, name):
        fake = FakeSubprocess()
        return function_namespace(name, {"run", "write_if_changed"}, subprocess=fake, changed=False), fake

    def test_write_if_changed_writes_new_content_with_mode_and_root_owner(self):
        for name in ("provision_gnmi_collector.py", "provision_topology.py"):
            with self.subTest(name):
                ns, fake = self.namespace(name)
                target = self.root / (name + ".conf")
                self.assertIsNone(ns["write_if_changed"](target, "a=1\n", 0o640))
                self.assertEqual((target.read_text(), target.stat().st_mode & 0o777, ns["changed"]), ("a=1\n", 0o640, True))
                self.assertEqual(fake.calls[0][0], ["chown", "root:root", str(target)])

    def test_write_if_changed_never_rewrites_unchanged_content(self):
        for name in ("provision_gnmi_collector.py", "provision_topology.py"):
            with self.subTest("unchanged never rewritten " + name):
                ns, fake = self.namespace(name)
                target = self.root / (name + ".same")
                target.write_text("a=1\n")
                target.chmod(0o600)
                ns["write_if_changed"](target, "a=1\n", 0o644)
                self.assertEqual((target.stat().st_mode & 0o777, ns["changed"], fake.calls), (0o600, False, []))


class LinuxTelemetryProvisionerTests(TempCase):
    NAME = "provision_linux_telemetry.py"

    def namespace(self, *functions, **extra):
        self.os, self.sub = FakeOs(), extra.pop("subprocess", FakeSubprocess())
        defaults = {"subprocess": self.sub, "os": self.os, "pathlib": self.pathlib, "signal": signal, "changed": False,
                    "BASE": self.root / "etc/nmas-telemetry", "payload": {"address": "192.168.200.13"}}
        return function_namespace(self.NAME, set(functions), **dict(defaults, **extra))

    def proc(self, pid, *argv):
        (self.root / "proc" / str(pid)).mkdir(parents=True)
        (self.root / "proc" / str(pid) / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")

    def test_imports_available_is_true_when_the_import_probe_succeeds(self):
        ns = self.namespace("imports_available")
        self.assertTrue(ns["imports_available"]())
        self.assertEqual(self.sub.calls[0][0], ["python3", "-c", "import grpc, google.protobuf, paramiko"])

    def test_imports_available_is_false_when_the_import_probe_fails(self):
        ns = self.namespace("imports_available", subprocess=FakeSubprocess(returncode=1))
        with self.subTest("refused missing grpc"):
            self.assertFalse(ns["imports_available"]())

    def test_write_if_changed_writes_content_mode_and_root_owner(self):
        ns = self.namespace("write_if_changed")
        target = self.root / "credentials.env"
        ns["write_if_changed"](target, "TELEMETRY_USERNAME=nmas-telemetry\n", 0o600)
        self.assertEqual((target.read_text(), target.stat().st_mode & 0o777, ns["changed"]), ("TELEMETRY_USERNAME=nmas-telemetry\n", 0o600, True))
        self.assertEqual(self.os.chowns, [(target, 0, 0)])

    def test_write_if_changed_refuses_to_replace_a_symlink(self):
        ns = self.namespace("write_if_changed")
        real, link = self.root / "real", self.root / "link"
        real.write_text("keep")
        link.symlink_to(real)
        with self.assertRaisesRegex(SystemExit, "^refusing to replace symlink: .*link$"):
            ns["write_if_changed"](link, "replaced", 0o644)
        self.assertEqual((real.read_text(), ns["changed"], self.os.chowns), ("keep", False, []))

    def test_cmdline_returns_the_process_argv(self):
        self.proc(42, "/usr/bin/python3", "/etc/nmas-telemetry/linux_gnmi_server.py", "192.168.200.13", "6030")
        self.assertEqual(self.namespace("cmdline")["cmdline"](42),
                         ["/usr/bin/python3", "/etc/nmas-telemetry/linux_gnmi_server.py", "192.168.200.13", "6030"])

    def test_cmdline_of_an_absent_process_is_empty(self):
        self.assertEqual(self.namespace("cmdline")["cmdline"](99999), [])

    def test_matching_pids_returns_processes_running_the_script(self):
        script = self.root / "etc/nmas-telemetry/linux_gnmi_server.py"
        self.proc(10, "/usr/bin/python3", str(script), "192.168.200.13", "6030")
        self.proc(11, "/usr/bin/python3", "/opt/other.py")
        self.proc(12, "python3", "linux_gnmi_server.py")
        (self.root / "proc/self").mkdir()
        self.assertEqual(sorted(self.namespace("cmdline", "matching_pids")["matching_pids"](script)), [10, 12])

    def test_matching_pids_of_an_unknown_script_is_none(self):
        self.proc(10, "/usr/bin/python3", "/opt/other.py")
        self.assertEqual(self.namespace("cmdline", "matching_pids")["matching_pids"](self.root / "absent.py"), [])

    def clock(self):
        state = {"now": 0.0}
        return types.SimpleNamespace(time=lambda: state["now"], sleep=lambda s: state.update(now=state["now"] + s))

    def test_stop_pids_terminates_processes_that_exit(self):
        ns = self.namespace("stop_pids", time=self.clock(), cmdline=lambda pid: [])
        self.assertIsNone(ns["stop_pids"]([5, 6]))
        self.assertEqual(self.os.kills, [(5, signal.SIGTERM), (6, signal.SIGTERM)])

    def test_stop_pids_kills_a_process_that_never_exits_and_tolerates_vanished_pids(self):
        def kill(pid, sig):
            if pid == 6:
                raise ProcessLookupError(pid)
            self.os.kills.append((pid, sig))

        ns = self.namespace("stop_pids", time=self.clock(), cmdline=lambda pid: ["python3"] if pid == 5 else [])
        ns["os"] = types.SimpleNamespace(kill=kill)
        ns["stop_pids"]([5, 6])
        self.assertEqual(self.os.kills, [(5, signal.SIGTERM), (5, signal.SIGKILL)])

    def adapter(self, **extra):
        functions = ("cmdline", "matching_pids", "stop_pids", "run", "ensure_process")
        ns = self.namespace(*functions, time=self.clock(), socket=types.SimpleNamespace(create_connection=self.connect), **extra)
        (self.root / "run").mkdir(exist_ok=True)
        (self.root / "proc").mkdir(exist_ok=True)
        return ns

    def connect(self, address, timeout):
        self.connections = getattr(self, "connections", []) + [(address, timeout)]
        return contextlib.nullcontext()

    def test_ensure_process_returns_the_running_managed_pid_unchanged(self):
        ns = self.adapter()
        script = ns["BASE"] / "linux_gnmi_server.py"
        self.proc(321, "/usr/bin/python3", str(script), "192.168.200.13", "6030")
        (self.root / "run/nmas-gnmi-adapter.pid").write_text("321\n")
        self.assertEqual(ns["ensure_process"]("gnmi", "linux_gnmi_server.py", 6030), 321)
        self.assertEqual((self.sub.calls, self.os.kills, ns["changed"], self.connections), ([], [], False, [(("192.168.200.13", 6030), 5)]))

    def test_ensure_process_whose_adapter_dies_after_start_fails(self):
        def started(args):
            if args[0] == "start-stop-daemon":
                (self.root / "run/nmas-netconf-adapter.pid").write_text("555\n")   # pid 555 never appears in /proc

        ns = self.adapter(subprocess=FakeSubprocess(on_run=started))
        with self.assertRaisesRegex(SystemExit, "^netconf adapter failed to stay running$"):
            ns["ensure_process"]("netconf", "linux_netconf_server.py", 830)
        self.assertEqual(self.sub.calls[0][0][:2], ["start-stop-daemon", "--start"])
        self.assertTrue(ns["changed"])
        self.assertFalse(hasattr(self, "connections"))


if __name__ == "__main__":
    unittest.main()
