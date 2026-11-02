"""The read-only / standalone boundary of the whole package, checked structurally."""

from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

from challenge_console.adapters import process
from challenge_console.adapters.process import CommandNotAllowed, assert_read_only

PACKAGE = Path(__file__).resolve().parent.parent
SOURCES = sorted(path for path in PACKAGE.rglob("*.py") if "tests" not in path.parts)


def imports(path: Path) -> set[str]:
    found = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            found |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.add(node.module.split(".")[0])
    return found


class AllowlistTests(unittest.TestCase):
    ALLOWED = (
        ("docker", "exec", "clab-srlceos01-H1", "ping", "-n", "-c", "1", "-W", "1", "-4", "192.168.20.101"),
        ("docker", "exec", "clab-srlceos01-H4", "ping", "-n", "-c", "1", "-W", "1", "-6", "2001:db8:10::2001"),
        ("docker", "exec", "clab-srlceos01-H1", "ip", "-j", "addr", "show"),
        ("docker", "exec", "clab-srlceos01-R3", "ip", "-j", "-s", "link", "show"),
        ("docker", "exec", "clab-srlceos01-R1", "Cli", "-p", "15", "-c", "show interfaces | json"),
        ("docker", "inspect", "-f", "{{.State.Status}}", "netbox-netbox-1"),
        ("docker", "ps", "--filter", "name=clab-srlceos01-", "--format", "{{.Names}}"),
        ("systemctl", "show", "nmas-web.service", "-p", "ActiveState", "-p", "SubState"),
    )
    REFUSED = (
        ("sudo", "docker", "ps"), ("sudo", "systemctl", "restart", "nmas-web.service"), ("bash", "-c", "docker ps"),
        ("docker", "run", "alpine"), ("docker", "restart", "clab-srlceos01-R1"), ("docker", "stop", "clab-srlceos01-R1"), ("docker", "rm", "x"),
        ("docker", "exec", "clab-srlceos01-R1", "Cli", "-p", "15", "-c", "configure terminal"),
        ("docker", "exec", "clab-srlceos01-R1", "Cli", "-p", "15", "-c", "show interfaces ; configure"),
        ("docker", "exec", "clab-srlceos01-R1", "Cli", "-p", "15", "-c", "clear counters"),
        ("docker", "exec", "clab-srlceos01-R1", "Cli", "-p", "15", "-c", "write memory"),
        ("docker", "exec", "clab-srlceos01-R1", "Cli", "-p", "15", "-c", "show running-config | bash"),
        ("docker", "exec", "clab-srlceos01-R1", "Cli", "-c", "show version"),
        ("docker", "exec", "clab-srlceos01-R1", "FastCli", "-p", "15", "-c", "show version"),
        ("docker", "exec", "clab-srlceos01-R3", "ip", "addr", "add", "10.0.0.1/24", "dev", "eth1"),
        ("docker", "exec", "clab-srlceos01-R3", "ip", "-j", "link", "set", "eth1", "down"),
        ("docker", "exec", "clab-srlceos01-R3", "ip", "-j", "addr", "flush", "show"),
        ("docker", "exec", "clab-srlceos01-R3", "vtysh", "-c", "configure terminal"),
        ("docker", "exec", "clab-srlceos01-R3", "sh", "-c", "ip link set eth1 down"),
        ("docker", "exec", "--privileged", "clab-srlceos01-R3", "ip", "-j", "addr", "show"),
        ("docker", "exec", "-u", "root", "clab-srlceos01-H1", "ping", "-c", "1", "192.0.2.1"),
        ("docker", "exec", "clab-srlceos01-H1", "ping", "-n", "-c", "1000", "-W", "1", "192.0.2.1"),      # not a load generator
        ("docker", "exec", "clab-srlceos01-H1", "ping", "-f", "192.0.2.1"),
        ("docker", "exec", "clab-srlceos01-H1", "ping", "-n", "-c", "1", "-W", "1", "example.com; reboot"),
        ("docker", "exec", "clab-srlceos01-H1", "iperf3", "-c", "192.0.2.1"),
        ("systemctl", "restart", "nmas-web.service"), ("systemctl", "stop", "nmas-probation-soak-tick.timer"),
        ("systemctl", "show", "nmas-web.service", "-p", "Environment"), ("systemctl", "show", "x.service", "--property=Environment"),
        ("containerlab", "destroy"), ("ping", "192.0.2.1"), ("docker",), (),
    )

    def test_every_command_the_console_uses_is_allowed(self):
        for argv in self.ALLOWED:
            self.assertEqual(assert_read_only(argv), argv)

    def test_everything_else_is_refused_before_a_process_exists(self):
        for argv in self.REFUSED:
            with self.assertRaises(CommandNotAllowed, msg=argv):
                assert_read_only(argv)
            with self.assertRaises(CommandNotAllowed, msg=argv):
                process.run(argv)

    def test_run_reports_instead_of_raising_for_runtime_problems(self):
        original = process.subprocess.run
        self.addCleanup(setattr, process.subprocess, "run", original)

        def missing(*args, **kwargs):
            raise FileNotFoundError("docker")

        def slow(*args, **kwargs):
            raise process.subprocess.TimeoutExpired("docker", 1)

        process.subprocess.run = missing
        self.assertEqual(process.run(self.ALLOWED[2]).error, "RUNTIME_UNAVAILABLE")
        process.subprocess.run = slow
        self.assertEqual(process.run(self.ALLOWED[2]).error, "TIMEOUT")
        captured = {}
        process.subprocess.run = lambda argv, **kwargs: captured.update(kwargs, argv=argv) or type("P", (), {"returncode": 1, "stdout": "", "stderr": "Error: No such container: x"})()
        result = process.run(self.ALLOWED[2])
        self.assertEqual((result.ok, result.stderr_class), (False, "NO_SUCH_CONTAINER"))
        self.assertEqual((captured["shell"], captured["stdin"]), (False, process.subprocess.DEVNULL))
        self.assertIsInstance(captured["argv"], list)


class StructureTests(unittest.TestCase):
    def test_the_console_does_not_depend_on_django_or_the_website(self):
        for path in SOURCES:
            self.assertFalse(imports(path) & {"django", "core", "config", "web", "gunicorn", "requests", "pynetbox", "netmiko", "paramiko"},
                             path.relative_to(PACKAGE))
        for path in SOURCES:
            self.assertNotIn("DJANGO_SETTINGS_MODULE", path.read_text(), path.name)

    def test_only_the_adapters_touch_processes_sockets_or_the_database(self):
        boundary = {"subprocess": {"adapters/process.py"}, "sqlite3": {"adapters/automation_db.py"}, "urllib": {"adapters/http.py", "adapters/netbox.py"},
                    "socket": {"adapters/http.py"}, "ssl": {"adapters/http.py"}}
        for path in SOURCES:
            relative = str(path.relative_to(PACKAGE))
            for module, allowed in boundary.items():
                if module in imports(path):
                    self.assertIn(relative, allowed, f"{relative} imports {module}")

    def test_tkinter_stays_in_the_ui_package(self):
        for path in SOURCES:
            relative = path.relative_to(PACKAGE)
            if "tkinter" in imports(path):
                self.assertEqual(relative.parts[0], "ui", relative)
        for path in SOURCES:                                                                        # and no collector / adapter knows the UI
            if path.relative_to(PACKAGE).parts[0] in ("adapters", "collectors"):
                self.assertNotIn("from ..ui", path.read_text())
                self.assertNotIn("from .ui", path.read_text())

    def test_no_privilege_escalation_no_shell_no_canvas(self):
        for path in SOURCES:
            text = path.read_text()
            code = "\n".join(line.split("#")[0] for line in text.splitlines())
            self.assertNotIn("shell=True", code, path.name)
            self.assertNotIn("os.system", code, path.name)
            self.assertNotIn("Canvas", code, path.name)
            self.assertIsNone(re.search(r"""["']sudo["']""", code), path.name)

    def test_no_http_write_verb_and_no_secret_in_source(self):
        for path in SOURCES:
            text = path.read_text()
            for verb in ("POST", "PUT", "PATCH", "DELETE"):
                self.assertNotIn(f'method="{verb}"', text, path.name)
            self.assertIsNone(re.search(r"(?i)(password|token|secret)\s*=\s*[\"'][^\"']{6,}[\"']", text), path.name)
