"""Phase-18 sandbox / verifier-adapter security and interpretation.  No Docker, no DB, no device: a fake process runner stands in for the
single ``run_process`` boundary, so the REAL adapters, argv builders, sanitizer and lifecycle are what is exercised.

Tests assert architectural invariants (what may reach argv / env, what is always cleaned up, what is never PASS), never Docker's own
output formatting.
"""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, override_settings

from core.services.raw_configlets import adapters, sandbox, text as text_module, verifier
from core.services.raw_configlets.sandbox import ProcessResult

PKG = Path(__file__).resolve().parents[1] / "services" / "raw_configlets"
HOSTILE = "hostname $(touch /tmp/pwned); rm -rf / --no-preserve-root"


def revision(text, platform):
    normalized = text_module.normalize(text)
    return SimpleNamespace(content=normalized, content_hash=text_module.content_hash(normalized), platform=platform)


def config(*, allow_privileged=True):
    return sandbox.SandboxConfig("frr:test", "ceos:test", allow_privileged, 5.0, 5.0, 5.0)


def ctx(runner, *, allow_privileged=True, clock=None):
    steps = iter(range(0, 10_000, 1))
    return verifier.VerificationContext(config=config(allow_privileged=allow_privileged), runner=runner, sleep=lambda s: None,
                                        clock=clock or (lambda: float(next(steps))))


class FakeRunner:
    """Scripted ``docker`` boundary.  Records every call; behaviour is chosen per verb."""

    def __init__(self, *, image_rc=0, image_error="", run=None, eos=None, cleanup_leftover="", raise_on_run=False, ready=True):
        self.calls: list[tuple[list, bytes | None]] = []
        self.image_rc, self.image_error, self.run_result, self.eos_output = image_rc, image_error, run or ProcessResult(0, ""), eos
        self.cleanup_leftover, self.raise_on_run, self.ready = cleanup_leftover, raise_on_run, ready

    def __call__(self, argv, *, stdin=None, timeout):
        self.calls.append((list(argv), stdin))
        verb = argv[1]
        if verb == "image":
            return ProcessResult(self.image_rc, "Error: No such image: x" if self.image_rc else "sha256:abc", error=self.image_error)
        if verb == "run":
            if self.raise_on_run:
                raise RuntimeError("boom")
            return self.run_result
        if verb == "exec":
            if "-c" in argv:                                   # cEOS readiness probe
                return ProcessResult(0, "Architecture: x86_64" if self.ready else "")
            return ProcessResult(0, self.eos_output if self.eos_output is not None else "Architecture: x86_64\n")
        if verb == "rm":
            return ProcessResult(0, "")
        if verb == "ps":
            return ProcessResult(0, self.cleanup_leftover)
        raise AssertionError(f"unexpected docker verb {verb!r}")

    def verbs(self):
        return [argv[1] for argv, _ in self.calls]


class BoundaryTests(SimpleTestCase):
    def test_argv_builders_isolate_and_never_contain_user_text(self):
        name = sandbox.container_name("frr", "0123456789abcdef")
        one = sandbox.oneshot_argv(name, "frr:test", "vtysh", ["-C", "-f", "/dev/stdin"], sandbox.FRR_LIMITS)
        flags = " ".join(one)
        for required in ("--network none", "--read-only", "--cap-drop ALL", "no-new-privileges", "--user 65534:65534", "--pids-limit 64",
                         "--memory 256m", "--entrypoint vtysh"):
            self.assertIn(required, flags)
        detached = sandbox.detached_argv(name, "ceos:test", sandbox.CEOS_INIT_COMMAND, sandbox.CEOS_LIMITS, privileged=True)
        self.assertIn("--privileged", detached)
        self.assertNotIn("--privileged", sandbox.detached_argv(name, "ceos:test", sandbox.CEOS_INIT_COMMAND, sandbox.CEOS_LIMITS, privileged=False))
        for argv in (one, detached, sandbox.exec_argv(name, ["FastCli", "-p", "15"], interactive=True), sandbox.remove_argv(name)):
            self.assertEqual(argv[0], "docker")
            self.assertTrue(all(isinstance(a, str) for a in argv))
            joined = " ".join(argv)
            for forbidden in ("--network host", "--pid host", "--pid=host", "docker.sock", "--mount", " -v ", "--volume", "--env-file", "sh -c", "bash"):
                self.assertNotIn(forbidden, joined)
        self.assertIn("--network none", " ".join(detached))
        with self.assertRaises(AssertionError):
            sandbox.remove_argv("clab-srlceos01-R1")                       # a lab container name can never be built into an argv

    def test_run_process_is_shell_free_bounded_and_forwards_no_secret_environment(self):
        secrets = {"GITHUB_TOKEN": "x", "DJANGO_SECRET_KEY": "y", "NETBOX_TOKEN": "z", "SLACK_WEBHOOK_URL": "w", "SSH_AUTH_SOCK": "s"}
        with mock.patch.dict(os.environ, secrets), mock.patch.object(sandbox.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=b"ok", stderr=b"")) as run:
            result = sandbox.run_process(["docker", "version"], stdin=b"payload", timeout=3)
        kwargs = run.call_args.kwargs
        self.assertEqual((result.returncode, result.output), (0, "ok"))
        self.assertIs(kwargs["shell"], False)
        self.assertEqual((kwargs["timeout"], kwargs["input"]), (3, b"payload"))
        self.assertTrue(set(kwargs["env"]) <= set(sandbox._ENV_ALLOWLIST))
        self.assertFalse(set(kwargs["env"]) & set(secrets))
        for bad in ("docker version", ["ls", "-l"], ["docker", "run\x00x"], [], ["docker", 5]):
            with self.subTest(argv=bad):
                with self.assertRaises(ValueError):
                    sandbox.run_process(bad, timeout=1)

    def test_output_is_bounded_redacted_control_stripped_and_path_scrubbed(self):
        token = "gh" + "p_" + "A1b2C3d4E5" * 4
        raw = "\x1b[31mred\x1b[0m\nsnmp-server community topsecret ro\nusername a secret sha512 $6$zzz\npassword=hunter2\n" \
              f"error in /etc/frr/vtysh.conf and /home/student/x/y\n{token}\n" + "\n".join(f"line{n}" for n in range(200)) + "\n" + "z" * 5000
        lines = sandbox.sanitize_output(raw)
        blob = "\n".join(lines)
        self.assertLessEqual(len(lines), 40)
        self.assertTrue(all(len(line) <= 240 for line in lines))
        for leaked in ("topsecret", "$6$zzz", "hunter2", token, "/etc/frr", "/home/student", "\x1b"):
            self.assertNotIn(leaked, blob)
        self.assertIn("<path>", blob)

    def test_images_and_container_names_are_server_owned_and_strictly_shaped(self):
        for bad in ("--privileged", "img; rm -rf /", "UPPER:tag", "", "a b"):
            with self.subTest(image=bad), override_settings(RAW_VERIFIER_FRR_IMAGE=bad):
                with self.assertRaises(ValueError):
                    sandbox.load_config()
        self.assertTrue(sandbox.load_config().frr_image)
        for name in (sandbox.container_name("ceos"), sandbox.container_name("frr")):
            self.assertRegex(name, r"^clab-rawverify-[a-z0-9]+-[0-9a-f]{12}$")
            self.assertFalse(name.startswith("clab-srlceos01"))
        self.assertNotEqual(sandbox.container_name("frr"), sandbox.container_name("frr"))


class FrrAdapterTests(SimpleTestCase):
    def verify(self, text, runner, **kwargs):
        return verifier.verify_raw_configlet(revision(text, "ubuntu_frr"), ctx(runner, **kwargs))

    def test_browser_text_travels_only_over_stdin_never_argv_or_environment(self):
        runner = FakeRunner()
        # the static gate would refuse this text; call the adapter directly to prove the BOUNDARY holds even if the gate were bypassed
        normalized = text_module.normalize(f"router ospf\n {HOSTILE}\n")
        adapters.FrrVtyshDryRun().verify(normalized, config=config(), runner=runner, clock=lambda: 0.0, sleep=lambda s: None)
        run_calls = [(argv, stdin) for argv, stdin in runner.calls if argv[1] == "run"]
        self.assertEqual(len(run_calls), 1)
        argv, stdin = run_calls[0]
        self.assertIn(HOSTILE.encode(), stdin)
        for call_argv, _ in runner.calls:
            self.assertFalse(any(HOSTILE[:12] in part or "pwned" in part for part in call_argv), call_argv)
        self.assertEqual(argv[-3:], ["-C", "-f", "/dev/stdin"])
        self.assertIn("vtysh", argv)

    def test_parser_output_is_interpreted_structurally(self):
        text = "router ospf\n! a comment\n ospf router-id BAD\n"     # statements are source lines 1 and 3
        benign = "% Can't open configuration file /etc/frr/vtysh.conf due to 'Permission denied'.\n"
        rows = [
            ("accepted", ProcessResult(0, ""), "PASS", {"SYNTAX_ACCEPTED", "SEMANTICS_NOT_VERIFIED"}, None),
            ("benign vtysh.conf notice only", ProcessResult(0, benign), "PASS", {"SYNTAX_ACCEPTED"}, None),
            ("rejected -> mapped to the SOURCE line", ProcessResult(2, benign + "line 2: % Unknown command[41]:  ospf router-id BAD\n"), "BLOCKED", {"SYNTAX_REJECTED"}, 3),
            ("warning", ProcessResult(0, "line 2: % Warning: something odd\n"), "PASS_WITH_WARNINGS", {"PLATFORM_WARNING"}, 3),
            ("unparseable non-zero exit", ProcessResult(1, "garbage\n"), "INCOMPLETE", {"VERIFIER_OUTPUT_UNPARSEABLE"}, None),
            ("truncated output is a warning, never silently PASS", ProcessResult(0, "", truncated=True), "PASS_WITH_WARNINGS", {"SANDBOX_OUTPUT_TRUNCATED"}, None),
        ]
        for case, result, expected, codes_, line in rows:
            with self.subTest(case=case):
                outcome = self.verify(text, FakeRunner(run=result))
                self.assertEqual(outcome.result, expected)
                self.assertTrue(codes_ <= {f["code"] for f in outcome.findings})
                if line:
                    self.assertIn(line, [f["line"] for f in outcome.findings if f["line"]])

    def test_every_failure_is_incomplete_never_pass_and_cleanup_always_runs(self):
        text = "router ospf\n ospf router-id 192.0.2.1\n"
        rows = [
            ("runtime unavailable", FakeRunner(image_rc=1, image_error="DOCKER_UNAVAILABLE"), "SANDBOX_UNAVAILABLE", False),
            ("image missing", FakeRunner(image_rc=1), "SANDBOX_IMAGE_MISSING", False),
            ("sandbox timeout", FakeRunner(run=ProcessResult(None, "", timed_out=True)), "SANDBOX_TIMEOUT", True),
            ("start failure", FakeRunner(run=ProcessResult(error="OS_ERROR")), "SANDBOX_START_FAILED", True),
            ("verifier crash", FakeRunner(raise_on_run=True), "VERIFIER_INTERNAL_ERROR", True),
            ("cleanup cannot be proven after an accepted syntax", FakeRunner(cleanup_leftover="abc123\n"), "SANDBOX_CLEANUP_FAILED", True),
        ]
        for case, runner, code, started in rows:
            with self.subTest(case=case):
                outcome = self.verify(text, runner)
                self.assertEqual(outcome.result, "INCOMPLETE")
                self.assertIn(code, [f["code"] for f in outcome.findings])
                self.assertEqual(outcome.evidence["sandbox"]["started"], started)
                self.assertEqual("rm" in runner.verbs(), started)          # a started sandbox is ALWAYS removed, on every path

    def test_verification_only_ever_names_its_own_disposable_sandbox(self):
        runner = FakeRunner()
        self.verify("router ospf\n ospf router-id 192.0.2.1\n", runner)
        names = set()
        for argv, _ in runner.calls:
            if argv[1] in ("run", "exec", "rm"):
                names.update(part for part in argv if part.startswith("clab-"))
            if argv[1] == "ps":
                names.update(part for part in argv if "clab-" in part)
        self.assertTrue(names)
        self.assertTrue(all("clab-rawverify-" in n for n in names), names)
        self.assertFalse(any("clab-srlceos01" in " ".join(argv) for argv, _ in runner.calls))


class CeosAdapterTests(SimpleTestCase):
    TEXT = "interface Loopback99\n   frobnicate nonsense\n"

    def verify(self, runner, **kwargs):
        return verifier.verify_raw_configlet(revision(self.TEXT, "arista_ceos"), ctx(runner, **kwargs))

    def test_the_privileged_backend_is_disabled_unless_policy_opts_in_and_starts_nothing_when_disabled(self):
        runner = FakeRunner()
        outcome = self.verify(runner, allow_privileged=False)
        self.assertEqual(outcome.result, "INCOMPLETE")
        self.assertIn("SANDBOX_DISABLED", [f["code"] for f in outcome.findings])
        self.assertEqual(runner.calls, [])                                   # no runtime call of any kind
        self.assertFalse(outcome.evidence["sandbox"]["started"])

    def test_config_session_output_is_interpreted_structurally_and_the_session_is_aborted(self):
        rows = [
            ("accepted", "Architecture: x86_64\n", "PASS", None),
            ("rejected -> mapped to the source line", "% Invalid input at line 3\nArchitecture: x86_64\n", "BLOCKED", 2),
            ("error in the verifier's own preamble", "% Invalid input at line 1\nArchitecture: x86_64\n", "INCOMPLETE", None),
            ("script did not run to the end (no sentinel)", "", "INCOMPLETE", None),
        ]
        for case, output, expected, line in rows:
            with self.subTest(case=case):
                runner = FakeRunner(eos=output)
                outcome = self.verify(runner)
                self.assertEqual(outcome.result, expected)
                if line:
                    self.assertIn(line, [f["line"] for f in outcome.findings if f["line"]])
                script = next(stdin for argv, stdin in runner.calls if argv[1] == "exec" and "-i" in argv).decode()
                lines = script.splitlines()
                self.assertEqual(lines[0], "configure session rawverify")
                self.assertEqual(lines[-2:], ["abort", adapters.CeosConfigSession.SENTINEL_COMMAND])   # never committed
                self.assertEqual(runner.verbs().count("rm"), 1)

    def test_a_sandbox_that_never_becomes_ready_times_out_incomplete_and_is_removed(self):
        runner = FakeRunner(ready=False)
        outcome = self.verify(runner, clock=iter([0.0, 1.0, 2.0, 99.0, 100.0, 101.0]).__next__)
        self.assertEqual(outcome.result, "INCOMPLETE")
        self.assertIn("SANDBOX_TIMEOUT", [f["code"] for f in outcome.findings])
        self.assertIn("rm", runner.verbs())


class PackageContractTests(SimpleTestCase):
    def modules(self):
        return {p.name: ast.parse(p.read_text()) for p in PKG.glob("*.py")}

    def test_only_the_sandbox_module_can_spawn_a_process_and_nothing_uses_a_shell_or_dynamic_execution(self):
        for name, tree in self.modules().items():
            imports = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} | \
                      {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
            with self.subTest(module=name):
                self.assertEqual("subprocess" in imports, name == "sandbox.py")
                self.assertFalse({"os", "pty", "socket", "paramiko", "netmiko", "pynetbox", "requests", "urllib"} & imports - ({"os"} if name == "sandbox.py" else set()))
            source = (PKG / name).read_text()
            for pattern in (r"shell\s*=\s*True", r"\bos\.system\(", r"\bos\.popen\(", r"(?<![\w.])eval\(", r"(?<![\w.])exec\(", r"__import__\(", r"[\"']sh[\"']\s*,\s*[\"']-c[\"']"):
                with self.subTest(module=name, pattern=pattern):
                    self.assertIsNone(re.search(pattern, source))
        run_calls = [n for n in ast.walk(self.modules()["sandbox.py"]) if isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "run"
                     and getattr(getattr(n.func, "value", None), "id", "") == "subprocess"]
        self.assertEqual(len(run_calls), 1)
        self.assertIn("shell", [k.arg for k in run_calls[0].keywords])

    def test_the_raw_package_never_touches_a_managed_device_or_a_lab_container(self):
        for name in (p.name for p in PKG.glob("*.py")):
            source = (PKG / name).read_text()
            with self.subTest(module=name):
                for token in ("get_live_target", "clab-srlceos01", "inventory.managed_devices", "ConnectHandler", "containerlab deploy", "containerlab destroy", "write memory"):
                    self.assertNotIn(token, source)

    def test_views_and_templates_never_spawn_processes_or_expose_a_raw_execute_endpoint(self):
        views_source = (Path(__file__).resolve().parents[1] / "views.py").read_text()
        start = views_source.index("# Phase 18 -- Raw Configlets")
        raw_views = views_source[start:]
        for token in ("subprocess", "docker", "netmiko", "execute_change", "run_process", "shell"):
            self.assertNotIn(token, raw_views.replace("shell-free", ""))
        urls = (Path(__file__).resolve().parents[1] / "urls.py").read_text()
        self.assertEqual(re.findall(r'raw/[^"]*/(?:execute|run)/"', urls), [])
