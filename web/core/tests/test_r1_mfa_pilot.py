"""Phase 24 reviewed R1 2FA pilot helper (``manage.py r1_mfa_pilot``).

Fixture/simulator only: an in-memory EOS model stands in for
``docker exec ... Cli``.  No test contacts a device, a container or a real
secret; every secret below is a fake TEST-ONLY value.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase

from modules.device_credentials import FileSecretProvider, make_reference

from core.models import (AccountKind, AuditEvent, AuditEventType, DeviceAuthMethod, DeviceCredential,
                         DeviceLoginMfaPolicy, MfaEnforcementState, MfaMechanism)
from core.services.credentials import mfa
from core.services.credentials import r1_pilot as p
from core.services.credentials.r1_pilot_runner import PilotDependencies, PilotEvidence, R1PilotRunner

FAKE = {
    "runtime://device-credentials/r1-nmas-automation": "TESTONLYautomationSecret0001",
    "runtime://device-credentials/r1-breakglass": "TESTONLYbreakglassSecret0002",
    "runtime://device-credentials/ceos-admin-shared": "TSTadm3",  # short, like the lab default: login-only
    "runtime://human-mfa/radius/r1": "TESTONLY+radius/Shared=Secret04",  # base64-shaped, like the live value
}
HUMAN_PASSWORD, HUMAN_OTP = "TESTONLYhumanPassword5", "123456"
ORIGINAL_CONFIG = """! Command: show running-config
! device: R1 (cEOS-lab, EOS-4.36.2F)
hostname R1
no aaa root
username admin privilege 15 role network-admin secret sha512 $6$ORIGINALHASH
username nmas-telemetry role network-operator secret sha512 $6$TELEMETRYHASH
interface Vlan200
   ip address 192.168.200.1/24
end"""


def _hash(clear: str) -> str:
    return "$6$" + hashlib.sha256(clear.encode()).hexdigest()[:24]


class FakeEos:
    """Minimal EOS model: running config, named sessions, commit timer, flash, echo-on-error."""

    def __init__(self, config: str = ORIGINAL_CONFIG):
        self.running = config.splitlines()
        self.sessions: dict[str, dict] = {}
        self.flash: dict[str, bytes] = {}
        self.logs: dict[str, str] = {"/var/log/messages": "boot ok", "/var/log/account.log": ""}
        self.clear: dict[str, str] = {"admin": FAKE["runtime://device-credentials/ceos-admin-shared"]}
        self.calls: list[dict] = []
        self.stop_on_error = True
        self.timer: tuple[str, float] | None = None  # EOS top-level commitTimerSessionName / ExpireTime
        self.startup = list(self.running)  # `write memory` is modelled by assigning running to startup
        self.radius = dict.fromkeys(("Messages sent", "Messages received", "Requests accepted", "Requests rejected",
                                     "Requests timeout", "Requests retransmitted", "Bad responses", "Connection errors"), 0)

    # -- config model
    @staticmethod
    def _store(line: str) -> str:
        m = re.match(r"^(username \S+ .*secret) (\S+)$", line)
        if m:
            return f"{m.group(1)} sha512 {_hash(m.group(2))}"
        m = re.match(r"^(radius-server host \S+ key) 0 (\S+)$", line)
        if m:
            return f"{m.group(1)} 7 {hashlib.md5(m.group(2).encode()).hexdigest().upper()}"
        return line

    def _apply(self, lines: list[str], line: str) -> None:
        text = line.strip()
        if text.startswith("no username "):
            lines[:] = [l for l in lines if not l.startswith(f"username {text.split()[2]} ")]
        elif text.startswith("username "):
            name = text.split()[1]
            stored = self._store(text)
            idx = next((i for i, l in enumerate(lines) if l.startswith(f"username {name} ")), None)
            if idx is None:
                lines.insert(len([l for l in lines if not l.startswith("end")]), stored)
            else:
                lines[idx] = stored
        elif text == "default authentication protocol":
            lines[:] = [l for l in lines if l.strip() != "authentication protocol password"]
        elif text.startswith("no "):
            target = text[3:]
            out, skip = [], False
            for l in lines:
                if l.startswith(target):
                    skip = True
                    continue
                if skip and l.startswith("   "):
                    continue
                skip = False
                out.append(l)
            lines[:] = out
        elif line.startswith("   "):
            lines.insert(len(lines) - 1, line)
        elif text not in lines:
            lines.insert(len(lines) - 1, self._store(text))

    def text(self, lines=None) -> str:
        lines = self.running if lines is None else lines
        out = []
        for i, l in enumerate(lines):
            has_child = i + 1 < len(lines) and lines[i + 1].startswith("   ")
            if l in ("management ssh",) and not has_child:
                continue
            out.append(l)
        return "\n".join(out) + "\n"

    # -- subprocess.run replacement
    def __call__(self, argv, input=None, env=None, **kwargs):
        self.calls.append({"argv": list(argv), "input": input, "env": dict(env or {})})
        binary = not kwargs.get("text")
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, "running healthy\n", "")
        if argv[-2:] == ["-c", argv[-1]] and "Cli" in argv:
            return subprocess.CompletedProcess(argv, 0, self._show(argv[-1]), "")
        if "cat" in argv:
            path = argv[-1]
            name = path.rsplit("/", 1)[-1]
            if name not in self.flash:
                return subprocess.CompletedProcess(argv, 1, b"" if binary else "", "No such file")
            return subprocess.CompletedProcess(argv, 0, self.flash[name], b"")
        if "grep" in argv:
            patterns = [l for l in (input or "").splitlines() if l]
            hits = [path for path, body in {**{f"/mnt/flash/{k}": v.decode() for k, v in self.flash.items()},
                                            **self.logs}.items() if any(pat in body for pat in patterns)]
            return subprocess.CompletedProcess(argv, 0, "\n".join(hits), "")
        if argv[-3:] == ["Cli", "-p", "15"]:
            return subprocess.CompletedProcess(argv, 0, self._batch(input or ""), "")
        raise AssertionError(f"unexpected argv {argv}")

    def _show(self, command: str) -> str:
        if command == "show running-config":
            return self.text()
        if command == "show configuration sessions detail | json":
            data = {"sessions": {n: {"state": s["state"], **({"completedTime": 1.0} if s["state"] == "committed" else {})}
                                 for n, s in self.sessions.items()}}
            if self.timer:
                data.update(commitTimerSessionName=self.timer[0], commitTimerExpireTime=self.timer[1])
            return json.dumps(data)
        if command == "show version":
            return "Software image version: 4.36.2F-TEST\n"
        if command == "show running-config section username":
            return "\n".join(l for l in self.running if l.startswith("username ")) + "\n"
        if command == "show startup-config":
            return self.text(self.startup)
        if command == "show radius":  # live EOS 4.36.2F layout (first server block)
            body = "\n".join(f"{name:>30}:{value:>11}" for name, value in self.radius.items())
            return f"RADIUS server             : 192.168.200.100, authentication port 1812\n{body}\n"
        raise AssertionError(command)

    def _account(self, line: str, rejected: bool) -> None:
        """EOS command accounting: secrets masked for parsed commands, rejected commands verbatim."""
        logged = line if rejected else re.sub(r"\b(secret|key 0)\s+\S+", r"\1 *", line)
        self.logs["/var/log/account.log"] += f"root\t{logged}\n"

    def _batch(self, script: str) -> str:
        out, current = [], None
        for number, line in enumerate(script.splitlines(), start=1):
            if not line.strip():
                continue
            self._account(line, rejected=line.startswith("nmas-canary-invalid") or "INVALID" in line)
            m = re.fullmatch(r"configure session (\S+)(?: (abort|commit)(?: timer (\S+))?)?", line)
            if m:
                name, action, timer = m.groups()
                if action == "abort":
                    self.sessions.pop(name, None)
                elif action == "commit":
                    session = self.sessions.get(name)
                    if session is None:
                        continue
                    if self.timer and self.timer[0] == name:
                        self.timer = None  # confirmation
                    else:
                        self.running = list(session["lines"])
                        session["state"] = "committed"  # EOS reads "committed" even while the timer runs
                        if timer:
                            self.timer = (name, 1_000_600.0)
                    # EOS keeps only the most recent finished session listed (maxSavedSessions 1).
                    for other in [n for n, s in self.sessions.items() if s["state"] == "committed" and n != name]:
                        self.sessions.pop(other)
                else:
                    self.sessions.setdefault(name, {"lines": list(self.running), "state": "pending"})
                    current = name
                continue
            if line == "abort":
                self.sessions.pop(current, None)
                current = None
                continue
            if line == "show session-config diffs":
                before, after = self.text().splitlines(), self.text(self.sessions[current]["lines"]).splitlines()
                out += ["--- system:/running-config", "+++ session:/x"]
                out += [f"-{l}" for l in before if l not in after] + [f"+{l}" for l in after if l not in before]
                continue
            if line == "show clock":
                out.append("Timezone: UTC")
                continue
            m = re.fullmatch(r"copy running-config flash:(\S+)", line)
            if m:
                self.flash[m.group(1)] = self.text().encode()
                continue
            if line == "write memory":
                self.startup = list(self.running)
                continue
            m = re.fullmatch(r"configure replace flash:(\S+) md5 (\S+)", line)
            if m:
                blob = self.flash[m.group(1)]
                if hashlib.md5(blob).hexdigest() != m.group(2):
                    out.append("% md5 mismatch")
                else:
                    self.running = [l for l in blob.decode().splitlines()]
                continue
            if line.startswith("nmas-canary-invalid") or "INVALID" in line:
                out += [f"> {line}", f"% Invalid input at line {number}"]
                if self.stop_on_error:
                    break
                continue
            if current is None:
                raise AssertionError(f"config line outside a session: {line}")
            self._apply(self.sessions[current]["lines"], line)
        return "\n".join(out) + "\n"

    def expire_timer(self, original_lines: list[str]) -> None:
        if self.timer:
            self.running = original_lines
            self.timer = None

    # -- fake SSH (knows the cleartexts only because it is a simulator)
    def ssh_login(self, user: str, password: str) -> dict:
        users = {l.split()[1]: l for l in self.running if l.startswith("username ")}
        if user in users:
            accepted = users[user].endswith(_hash(password))
            return {"login": "ACCEPT" if accepted else "REJECT", "privilege_level": 15 if accepted else None}
        aaa = p.ACTIVATION_MARKER in self.running
        if user == p.HUMAN_USERNAME and aaa and password == HUMAN_PASSWORD + HUMAN_OTP:
            return {"login": "ACCEPT", "privilege_level": 15}
        return {"login": "REJECT"}


def _policy():
    return DeviceLoginMfaPolicy(device_name="R1", platform="arista_ceos", mechanism=MfaMechanism.RADIUS_TOTP,
                                radius_server="192.168.200.100", radius_secret_ref="runtime://human-mfa/radius/r1",
                                radius_source_interface="Vlan200")


def _accounts():
    return [
        DeviceCredential(device_name="R1", platform="arista_ceos", username="nmas-automation", account_kind=AccountKind.SERVICE,
                         secret_ref=make_reference("r1-nmas-automation"), account_role="network-admin", privilege_level=15),
        DeviceCredential(device_name="R1", platform="arista_ceos", username="r1-breakglass", account_kind=AccountKind.BREAK_GLASS,
                         secret_ref=make_reference("r1-breakglass"), account_role="network-admin", privilege_level=15),
        DeviceCredential(device_name="R1", platform="arista_ceos", username="nmas-admin", account_kind=AccountKind.HUMAN,
                         auth_method=DeviceAuthMethod.PASSWORD_AND_TOTP),
        DeviceCredential(device_name="R1", platform="arista_ceos", username="admin", account_kind=AccountKind.LEGACY_SHARED,
                         secret_ref=make_reference("ceos-admin-shared"), account_role="network-admin", privilege_level=15),
    ]


def _staged():
    return p.staged_candidate(mfa.render_candidate(_policy(), _accounts()))


class _Clock:
    def __init__(self, start=1_000_000.0):
        self.now = start

    def __call__(self):
        self.now += 1.0
        return self.now


class PilotHarness(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        provider = self.provider = FileSecretProvider(root / "device-credentials" / "store.json")
        for ref, value in FAKE.items():
            if ref.startswith("runtime://device-credentials/"):
                provider.initialize(ref, value)
        radius_dir = root / "radius"
        radius_dir.mkdir(mode=0o700)
        secret = radius_dir / "radius_r1_secret"
        secret.write_text(FAKE["runtime://human-mfa/radius/r1"] + "\n")
        secret.chmod(0o600)
        self.eos = FakeEos()
        self.original_lines = list(self.eos.running)
        self.clock = _Clock()
        self.approval = mock.Mock(return_value=p.APPROVAL_PHRASE)
        self.reads = {"r1_identities": ["nmas-automation", "admin"], "fleet_identities": {d: ["admin"] for d in ("R2", "S1")},
                      "nsot": True, "config_retrieval": True, "health": True, "health_status": "HEALTHY"}
        self.deps = PilotDependencies(
            transport=p.EosCliTransport(runner=self.eos, scanner_factory=lambda known: p.ProcessTableScanner(known, proc_root=root / "noproc")),
            resolver=p.PilotSecretResolver(provider=provider, radius_root=radius_dir),
            evidence=PilotEvidence(), candidate=_staged, infrastructure=lambda: (True, []), reachable=lambda: True,
            ssh_login=self.eos.ssh_login, nmas_reads=lambda: dict(self.reads),
            human_factors=lambda: (HUMAN_PASSWORD, HUMAN_OTP), approval=self.approval, clock=self.clock,
        )
        self.runner = R1PilotRunner(self.deps)
        self.patches = [
            mock.patch.object(p, "REVIEWED_ORIGINAL_DIGEST", hashlib.sha256(self.eos.text().encode()).hexdigest()),
            mock.patch.object(p, "REVIEWED_CANDIDATE_DIGEST", _staged().digest),
        ]
        for patcher in self.patches:
            patcher.start()
        DeviceLoginMfaPolicy.objects.update_or_create(device_name="R1", defaults={
            "platform": "arista_ceos", "mechanism": MfaMechanism.RADIUS_TOTP, "enforcement_state": MfaEnforcementState.PLANNED,
            "radius_secret_ref": "runtime://human-mfa/radius/r1", "radius_source_interface": "Vlan200"})

    def tearDown(self):
        for patcher in self.patches:
            patcher.stop()
        self.tmp.cleanup()

    # helpers
    def secrets_everywhere(self) -> list[str]:
        """Every place a secret could escape: argv, env, recorded evidence."""
        places = [" ".join(c["argv"]) for c in self.eos.calls] + [json.dumps(c["env"]) for c in self.eos.calls]
        places += [json.dumps(e.metadata) + e.summary for e in AuditEvent.objects.all()]
        return [text for text in places for secret in [*FAKE.values(), HUMAN_PASSWORD] if secret in text]

    def inputs(self) -> str:
        return "\n".join(c["input"] or "" for c in self.eos.calls if c["argv"][-3:] == ["Cli", "-p", "15"])

    def run_to_stage2(self):
        self.runner.validate()
        self.runner.checkpoint(p.CHECKPOINT_ORIGINAL)
        self.runner.stage1()
        self.runner.checkpoint(p.CHECKPOINT_STAGE2)
        return self.runner.stage2()


class TransportSafetyTests(SimpleTestCase):
    known = p.SecretSet(["TESTONLYleakyValue123456"])

    def _transport(self, stdout="", stderr="", calls=None):
        def runner(argv, **kwargs):
            if calls is not None:
                calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, stdout, stderr)
        return p.EosCliTransport(runner=runner, scanner_factory=lambda known: p.ProcessTableScanner(known, proc_root=Path("/nonexistent")))

    def test_secret_travels_on_stdin_only_with_a_minimal_environment(self):
        calls = []
        self._transport(calls=calls).run(["username x secret TESTONLYleakyValue123456"], self.known)
        argv, kwargs = calls[0]
        self.assertEqual(argv, ["docker", "exec", "-i", p.PILOT_CONTAINER, "Cli", "-p", "15"])
        self.assertNotIn("TESTONLYleakyValue123456", " ".join(argv))
        self.assertIn("TESTONLYleakyValue123456", kwargs["input"])
        self.assertLessEqual(set(kwargs["env"]), {"PATH", "LANG", "HOME", "DOCKER_HOST", "DOCKER_CONFIG"})
        self.assertFalse(self.known.occurs_in(json.dumps(kwargs["env"])))

    def test_secret_in_environment_refuses_to_start(self):
        with mock.patch.dict("os.environ", {"DOCKER_HOST": "TESTONLYleakyValue123456"}):
            with self.assertRaises(p.PilotError):
                self._transport().run(["show clock"], self.known)

    def test_stdout_and_stderr_are_redacted_and_marked_failed(self):
        result = self._transport(stdout="ok TESTONLYleakyValue123456", stderr="err TESTONLYleakyValue123456").run(["x"], self.known)
        self.assertNotIn("TESTONLYleakyValue123456", result.output)
        self.assertTrue(result.leaks["cli_output"])
        self.assertFalse(result.clean)

    def test_parser_error_echo_is_redacted(self):
        echo = "> username x secret 0 TESTONLYleakyValue123456 bogus\n% Invalid input at line 1\n"
        result = self._transport(stdout=echo).run(["x"], self.known)
        self.assertEqual(len(result.errors), 1)
        self.assertNotIn("TESTONLYleakyValue123456", result.output)
        self.assertTrue(result.leaked)

    def test_structural_redaction_masks_hashes_and_type7_keys_without_known_values(self):
        text, leaked = p.SecretSet().redact("username a secret sha512 $6$abc\nradius-server host 1.2.3.4 key 7 ABCDEF")
        self.assertNotIn("$6$abc", text)
        self.assertNotIn("ABCDEF", text)
        self.assertFalse(leaked)

    def test_process_table_scanner_detects_argv_and_environment(self):
        with tempfile.TemporaryDirectory() as proc:
            entry = Path(proc) / "4242"
            entry.mkdir()
            (entry / "cmdline").write_bytes(b"docker\0exec\0TESTONLYleakyValue123456\0")
            (entry / "environ").write_bytes(b"X=TESTONLYleakyValue123456\0")
            scanner = p.ProcessTableScanner(self.known, proc_root=Path(proc))
            scanner.scan_once()
        self.assertEqual(scanner.hits, {"process_argv", "process_environment"})

    def test_show_path_rejects_non_show_or_placeholder_commands(self):
        for command in ("configure", "show x <provider:runtime://device-credentials/a>"):
            with self.assertRaises(p.PilotError):
                self._transport().show(command)

    def test_secret_set_repr_never_renders_values(self):
        self.assertNotIn("TESTONLY", repr(self.known))


class CandidateAndPairingTests(SimpleTestCase):
    def test_reviewed_digest_pins_the_rendered_r1_candidate(self):
        self.assertEqual(_staged().digest, p.REVIEWED_CANDIDATE_DIGEST)

    def test_stage_split_and_rollback_pairing(self):
        staged = _staged()
        self.assertEqual(len(staged.stage1), 2)
        self.assertEqual(staged.stage2[0], "no username admin")
        self.assertTrue(p.rollback_pairing(staged)["valid"])

    def test_broken_rollback_is_detected(self):
        staged = _staged()
        broken = p.StagedCandidate(staged.digest, staged.stage1, staged.stage2,
                                   tuple(l for l in staged.rollback if "nmas-automation" not in l) + ("no bogus",))
        result = p.rollback_pairing(broken)
        self.assertFalse(result["valid"])
        self.assertIn("username nmas-automation privilege 15 role network-admin", result["unpaired"])
        self.assertIn("no bogus", result["orphans"])

    def test_substitution_uses_provider_refs_and_canaries_are_distinct(self):
        canary = p.CanaryResolver()
        lines, known = p.substitute(_staged().stage2, canary)
        self.assertEqual(len(known), 1)
        self.assertFalse(any("<provider:" in l for l in lines))
        self.assertTrue(all(v.startswith("nmasCanary") for v in known))

    def test_shaped_canary_mirrors_length_and_punctuation_but_not_value(self):
        template = "Ab+cd/ef=gh" * 5
        for _ in range(50):
            canary = p.shaped_canary(template)
            self.assertEqual(len(canary), len(template))
            self.assertEqual(sorted(c for c in canary if not c.isalnum()), sorted(c for c in template if not c.isalnum()))
            self.assertNotEqual(canary, template)
        self.assertTrue(p.shaped_canary("/" + "a" * 20).startswith("/"))

    def test_base64_config_secret_is_accepted_and_login_only_ref_may_be_short(self):
        with tempfile.TemporaryDirectory() as root:
            provider = FileSecretProvider(Path(root) / "store.json")
            provider.initialize("runtime://device-credentials/r1-breakglass", "Zm9v+YmFy/YmF6=cXV4LnF1dXg")
            provider.initialize("runtime://device-credentials/ceos-admin-shared", "admin")
            resolver = p.PilotSecretResolver(provider=provider)
            self.assertTrue(resolver.exists("runtime://device-credentials/r1-breakglass"))
            self.assertFalse(resolver.exists("runtime://device-credentials/ceos-admin-shared"))
            self.assertTrue(resolver.exists("runtime://device-credentials/ceos-admin-shared", for_config=False))

    def test_unsafe_secret_charset_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            provider = FileSecretProvider(Path(root) / "store.json")
            provider.initialize("runtime://device-credentials/r1-breakglass", "has space and ? mark")
            with self.assertRaises(p.PilotError):
                p.PilotSecretResolver(provider=provider).resolve("runtime://device-credentials/r1-breakglass")


class TimerStateTests(SimpleTestCase):
    def test_live_eos_commit_timer_shape_is_armed_and_open(self):
        class _T:
            def show(self, command):
                return json.dumps({"sessions": {p.STAGE2_SESSION: {"state": "committed", "completedTime": 1790631624.87}},
                                   "commitTimerSessionName": p.STAGE2_SESSION, "commitTimerExpireTime": 1790632224.87})
        sessions = p.config_sessions(_T())
        self.assertIn(p.STAGE2_SESSION, p.open_sessions(sessions))
        state = p.timer_state(sessions=sessions, config_text=p.ACTIVATION_MARKER, armed_at=None, confirmed_at=None, now=1790631740.0)
        self.assertEqual((state["state"], state["remaining_seconds"]), (p.TimerState.ARMED, 484))

    def test_live_eos_session_shapes(self):
        live = {"NMAS-R1-2FA-CLEANUP": {"state": "committed", "completedTime": 1790630830.3, "instances": {}},
                "OPEN": {"state": "pending"}, "LEGACY": {"completedTime": 1.0}}
        self.assertEqual(sorted(p.open_sessions(live)), ["OPEN"])

    def test_states(self):
        armed = {p.STAGE2_SESSION: {"state": "committed", "timer_pending": True, "commitTimerExpireTime": 700}}
        done = {p.STAGE2_SESSION: {"state": "committed", "completedTime": 1.0}}
        active = p.ACTIVATION_MARKER
        self.assertEqual(p.timer_state(sessions={}, config_text="", armed_at=None, confirmed_at=None, now=0)["state"], "NOT_ARMED")
        state = p.timer_state(sessions=armed, config_text=active, armed_at=100, confirmed_at=None, now=160)
        self.assertEqual((state["state"], state["remaining_seconds"]), ("ARMED", 540))
        self.assertEqual(p.timer_state(sessions=done, config_text=active, armed_at=100, confirmed_at=200, now=300)["state"], "CONFIRMED")
        self.assertEqual(p.timer_state(sessions=done, config_text="hostname R1", armed_at=100, confirmed_at=None, now=800)["state"], "AUTO_REVERTED")
        self.assertEqual(p.timer_state(sessions={}, config_text=active, armed_at=100, confirmed_at=None, now=800)["state"], "UNKNOWN")


class ValidateTests(PilotHarness):
    def test_canary_validation_passes_without_changing_the_device_or_exposing_canaries(self):
        created = []

        class Capturing(p.CanaryResolver):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                created.append(self)

        with mock.patch.object(p, "CanaryResolver", Capturing):
            result = self.runner.validate()
        self.assertTrue(result["PASS"], result)
        self.assertTrue(result["running_config_unchanged"])
        self.assertEqual(result["sessions_after"], [])
        self.assertTrue(result["echo_probe"]["PASS"])
        self.assertEqual(self.eos.running, self.original_lines)
        canaries = [value for resolver in created for value in resolver.known]
        self.assertTrue(canaries and all(c in self.inputs() for c in canaries))
        self.assertEqual(result["canaries_shaped_like_real_secrets"], sorted(p.CONFIG_REFS))
        stored = json.dumps([e.metadata for e in AuditEvent.objects.all()])
        self.assertFalse(any(c in stored or c in json.dumps(result) for c in canaries))
        self.assertFalse(any(v in self.inputs() for v in FAKE.values()), "validation must never use real secrets")
        self.assertNotIn(" commit", self.inputs())
        # Only the deliberately rejected probe line is accounted verbatim; candidate canaries are masked.
        self.assertEqual(result["rejected_command_logged_verbatim_in"], ["/var/log/account.log"])
        self.assertEqual(result["device_leak_files"], [])
        account = self.eos.logs["/var/log/account.log"]
        self.assertEqual(sum(c in account for c in set(canaries)), 1)

    def test_validation_refuses_with_an_open_session(self):
        self.eos.sessions["other"] = {"lines": [], "state": "pending"}
        with self.assertRaises(p.PilotError):
            self.runner.validate()


class GateTests(PilotHarness):
    def assertNothingMutated(self):
        self.assertNotIn("commit", self.inputs())
        self.assertNotIn("copy running-config", self.inputs())
        self.assertEqual(self.eos.running, self.original_lines)

    def test_absent_or_wrong_approval_blocks_every_mutation(self):
        self.approval.return_value = "apply"
        for call in (lambda: self.runner.checkpoint(p.CHECKPOINT_ORIGINAL), self.runner.stage1, self.runner.stage2,
                     self.runner.confirm, lambda: self.runner.replace(p.CHECKPOINT_ORIGINAL)):
            with self.assertRaises(p.PilotError):
                call()
        self.assertNothingMutated()

    def test_wrong_device_is_refused(self):
        for runner in (R1PilotRunner(self.deps, device="R2"),
                       R1PilotRunner(PilotDependencies(**{**self.deps.__dict__, "transport": p.EosCliTransport("clab-srlceos01-R2", runner=self.eos)}))):
            with self.assertRaises(p.PilotError):
                runner.checkpoint(p.CHECKPOINT_ORIGINAL)
        self.assertNothingMutated()

    def test_command_refuses_other_devices(self):
        with self.assertRaises(CommandError):
            call_command("r1_mfa_pilot", "status", "--device", "R2")

    def test_candidate_digest_mismatch_blocks_mutation(self):
        self.runner.validate()
        with mock.patch.object(p, "REVIEWED_CANDIDATE_DIGEST", "0" * 64):
            with self.assertRaisesRegex(p.PilotError, "candidate_digest"):
                self.runner.checkpoint(p.CHECKPOINT_ORIGINAL)
        self.assertNothingMutated()

    def test_pre_state_digest_mismatch_blocks_mutation(self):
        self.eos.running.insert(2, "! drifted")
        with self.assertRaisesRegex(p.PilotError, "pre_change_digest"):
            self.runner.checkpoint(p.CHECKPOINT_ORIGINAL)
        self.assertNotIn("copy running-config", self.inputs())

    def test_unhealthy_infrastructure_unreachable_device_or_missing_refs_block(self):
        for override in ({"infrastructure": lambda: (False, ["radius"])}, {"reachable": lambda: False},
                         {"resolver": p.PilotSecretResolver(provider=FileSecretProvider(Path(self.tmp.name) / "empty.json"))}):
            runner = R1PilotRunner(PilotDependencies(**{**self.deps.__dict__, **override}))
            with self.assertRaises(p.PilotError):
                runner.checkpoint(p.CHECKPOINT_ORIGINAL)
        self.assertNothingMutated()

    def test_checkpoint_ordering_and_account_stage_gates(self):
        with self.assertRaisesRegex(p.PilotError, "original checkpoint"):
            self.runner.checkpoint(p.CHECKPOINT_STAGE2)
        with self.assertRaisesRegex(p.PilotError, "not been recorded"):
            self.runner.stage1()
        with self.assertRaisesRegex(p.PilotError, "not been recorded"):
            self.runner.stage2()
        self.runner.checkpoint(p.CHECKPOINT_ORIGINAL)
        with self.assertRaisesRegex(p.PilotError, "already exists"):
            self.runner.checkpoint(p.CHECKPOINT_ORIGINAL)
        with self.assertRaisesRegex(p.PilotError, "validate"):
            self.runner.stage1()  # two-phase proof (validate) is required
        self.runner.validate()
        self.runner.stage1()
        self.assertEqual(self.eos.running.count("username admin privilege 15 role network-admin secret sha512 $6$ORIGINALHASH"), 1)
        with self.assertRaisesRegex(p.PilotError, "not been recorded"):
            self.runner.stage2()  # stage-2 checkpoint is mandatory

    def test_original_checkpoint_refused_once_pilot_accounts_exist(self):
        self.eos.running.insert(4, "username r1-breakglass privilege 15 role network-admin secret sha512 $6$x")
        with self.assertRaisesRegex(p.PilotError, "precede Stage 1"):
            self.runner.checkpoint(p.CHECKPOINT_ORIGINAL)


class StagedApplyTests(PilotHarness):
    def test_full_happy_path_is_secret_safe(self):
        armed = self.run_to_stage2()
        self.assertEqual(armed["timer"]["state"], p.TimerState.ARMED)
        self.assertNotIn("username admin", "\n".join(self.eos.running))
        verification = self.runner.verify("post-stage2")
        self.assertTrue(verification["PASS"], verification)
        confirmed = self.runner.confirm()
        self.assertTrue(confirmed["ok"])
        self.assertEqual(self.runner.status()["timer"]["state"], p.TimerState.CONFIRMED)
        self.assertEqual(DeviceLoginMfaPolicy.objects.get(device_name="R1").enforcement_state, MfaEnforcementState.ENFORCED)
        self.assertEqual(self.secrets_everywhere(), [])
        self.assertTrue(all(v in self.inputs() for k, v in FAKE.items() if "admin-shared" not in k))
        checkpoints = self.runner.status()["checkpoints"]
        self.assertTrue(all(checkpoints[n]["file_md5"] and checkpoints[n]["file_sha256"] for n in p.CHECKPOINTS))

    def test_stage1_commits_only_after_a_clean_inspection(self):
        self.runner.validate()
        self.runner.checkpoint(p.CHECKPOINT_ORIGINAL)
        with mock.patch.object(p, "substitute", side_effect=lambda lines, resolve: (
                [*[l.replace("<provider:", "INVALID <provider:") for l in lines]], p.SecretSet())):
            with self.assertRaises(p.PilotError):
                self.runner.stage1()
        self.assertEqual(self.eos.running, self.original_lines)
        self.assertEqual(self.eos.sessions, {})
        self.assertNotIn(f"configure session {p.STAGE1_SESSION} commit", self.inputs())

    def test_canary_preflight_failure_never_sends_real_secrets(self):
        self.runner.validate()
        self.runner.checkpoint(p.CHECKPOINT_ORIGINAL)
        staged = _staged()
        broken = p.StagedCandidate(staged.digest, (staged.stage1[0].replace(" secret ", " INVALID secret "), staged.stage1[1]),
                                   staged.stage2, staged.rollback)
        self.deps.candidate = lambda: broken
        with self.assertRaisesRegex(p.PilotError, "pre-flight"):
            self.runner.stage1()
        self.assertFalse(any(v in self.inputs() for v in FAKE.values()))
        self.assertFalse(any(v in "".join(self.eos.logs.values()) for v in FAKE.values()))
        self.assertEqual(p.open_sessions(self.eos.sessions), {})
        self.assertEqual(self.eos.running, self.original_lines)

    def test_real_secrets_are_masked_in_device_accounting(self):
        self.run_to_stage2()
        account = self.eos.logs["/var/log/account.log"]
        self.assertFalse(any(v in account for v in FAKE.values()))
        self.assertIn("secret *", account)

    def test_stage1_verification_failure_removes_both_accounts(self):
        self.runner.validate()
        self.runner.checkpoint(p.CHECKPOINT_ORIGINAL)
        self.reads["health"] = False
        with self.assertRaisesRegex(p.PilotError, "removed"):
            self.runner.stage1()
        self.assertFalse(any(l.startswith(("username nmas-automation", "username r1-breakglass")) for l in self.eos.running))
        self.assertEqual(self.eos.text(), "\n".join(self.original_lines) + "\n")

    def test_nmas_fleet_identity_outside_r1_must_be_unchanged(self):
        self.runner.validate()
        self.runner.checkpoint(p.CHECKPOINT_ORIGINAL)
        self.reads["fleet_identities"]["R2"] = ["nmas-automation"]
        with self.assertRaises(p.PilotError):
            self.runner.stage1()

    def test_failed_verification_prevents_confirm_and_timer_reverts(self):
        self.run_to_stage2()
        self.deps.human_factors = lambda: (HUMAN_PASSWORD, "000000")
        self.assertFalse(self.runner.verify("post-stage2")["PASS"])
        with self.assertRaisesRegex(p.PilotError, "let the timer expire"):
            self.runner.confirm()
        pre_stage2 = PilotEvidence().latest(f"checkpoint:{p.CHECKPOINT_STAGE2}")
        self.eos.expire_timer(self.eos.flash[f"{p.CHECKPOINT_STAGE2}.cfg"].decode().splitlines())
        self.clock.now += p.COMMIT_TIMER_SECONDS
        status = self.runner.status()
        self.assertEqual(status["timer"]["state"], p.TimerState.AUTO_REVERTED)
        self.assertEqual(status["running_digest"], pre_stage2["running_sha256"])

    def test_confirm_refused_when_timer_nearly_expired(self):
        self.run_to_stage2()
        self.runner.verify("post-stage2")
        self.clock.now += p.COMMIT_TIMER_SECONDS
        with self.assertRaisesRegex(p.PilotError, "refusing to confirm"):
            self.runner.confirm()

    def test_replace_requires_intact_checkpoint_and_restores_original(self):
        self.run_to_stage2()
        self.runner.verify("post-stage2")
        self.runner.confirm()
        self.eos.flash[f"{p.CHECKPOINT_ORIGINAL}.cfg"] += b"tampered"
        with self.assertRaisesRegex(p.PilotError, "no longer matches"):
            self.runner.replace(p.CHECKPOINT_ORIGINAL)
        self.eos.flash[f"{p.CHECKPOINT_ORIGINAL}.cfg"] = self.eos.flash[f"{p.CHECKPOINT_ORIGINAL}.cfg"][:-8]
        restored = self.runner.replace(p.CHECKPOINT_ORIGINAL)
        self.assertTrue(restored["ok"], restored)
        self.assertEqual(restored["running_digest_after"], p.REVIEWED_ORIGINAL_DIGEST)
        self.assertIn("md5 " + hashlib.md5(self.eos.flash[f"{p.CHECKPOINT_ORIGINAL}.cfg"]).hexdigest(), self.inputs())
        self.assertEqual(DeviceLoginMfaPolicy.objects.get(device_name="R1").enforcement_state, MfaEnforcementState.PLANNED)

    def test_replace_refused_while_timer_armed(self):
        self.run_to_stage2()
        with self.assertRaisesRegex(p.PilotError, "armed"):
            self.runner.replace(p.CHECKPOINT_STAGE2)

    def test_short_login_only_admin_secret_does_not_block_post_stage2_evidence(self):
        self.provider.initialize("runtime://device-credentials/ceos-admin-shared", "admin", replace=True)
        self.eos.clear["admin"] = "admin"
        self.eos.running = [l if not l.startswith("username admin ") else
                            f"username admin privilege 15 role network-admin secret sha512 {_hash('admin')}" for l in self.eos.running]
        self.original_lines = list(self.eos.running)
        with mock.patch.object(p, "REVIEWED_ORIGINAL_DIGEST", hashlib.sha256(self.eos.text().encode()).hexdigest()):
            self.run_to_stage2()
            verification = self.runner.verify("post-stage2")
        self.assertTrue(verification["PASS"], verification)
        self.assertTrue(self.runner.confirm()["ok"])

    def test_evidence_refuses_to_store_a_known_secret(self):
        with self.assertRaises(p.PilotError):
            PilotEvidence().record("x", ok=True, known=p.SecretSet(["TESTONLYsecretValue9"]), at=1.0, note="TESTONLYsecretValue9")
        self.assertFalse(AuditEvent.objects.filter(event_type=AuditEventType.MFA_PILOT_STEP).exists())


class HealthVerdictTests(SimpleTestCase):
    @staticmethod
    def report(*results, status="DEGRADED"):
        base = [{"check_code": "LINK_STATE", "status": "PASS", "observed": {}}]
        return {"status": status, "results": base + list(results)}

    def test_config_change_traps_and_cpu_warning_are_tolerated(self):
        from core.services.credentials.r1_pilot_runner import health_verdict

        verdict = health_verdict(self.report(
            {"check_code": "CRITICAL_EVENTS_RECENT", "status": "WARN", "observed": {"critical_syslog": 0, "snmp_traps": 2}},
            {"check_code": "CPU_HIGH", "status": "WARN", "observed": {}, "message": "CPU 70% (warning)."}))
        self.assertTrue(verdict["ok"])
        self.assertEqual([w["check_code"] for w in verdict["tolerated_warnings"]], ["CRITICAL_EVENTS_RECENT", "CPU_HIGH"])

    def test_critical_syslog_fail_unknown_or_other_warnings_block(self):
        from core.services.credentials.r1_pilot_runner import health_verdict

        for bad in ({"check_code": "CRITICAL_EVENTS_RECENT", "status": "WARN", "observed": {"critical_syslog": 1, "snmp_traps": 0}},
                    {"check_code": "CPU_HIGH", "status": "FAIL", "observed": {}},
                    {"check_code": "MEMORY_HIGH", "status": "WARN", "observed": {}},
                    {"check_code": "LINK_STATE", "status": "UNKNOWN", "observed": {}},
                    {"check_code": "ROUTING", "status": "FAIL", "observed": {}}):
            with self.subTest(bad=bad):
                self.assertFalse(health_verdict(self.report(bad))["ok"])
        self.assertFalse(health_verdict({"status": "HEALTHY", "results": []})["ok"])
        self.assertTrue(health_verdict(self.report(status="HEALTHY"))["ok"])


class TerminalApprovalTests(SimpleTestCase):
    def test_approval_is_read_from_a_real_pseudo_terminal(self):
        import os
        from core.services.credentials.r1_pilot_runner import _read_tty_line

        master, slave = os.openpty()
        try:
            os.write(master, (p.APPROVAL_PHRASE + "\n").encode())
            self.assertEqual(_read_tty_line("approve: ", device=os.ttyname(slave)), p.APPROVAL_PHRASE)
        finally:
            os.close(master)
            os.close(slave)

    def test_missing_terminal_is_refused(self):
        from core.services.credentials.r1_pilot_runner import _read_tty_line

        with self.assertRaisesRegex(p.PilotError, "interactive terminal"):
            _read_tty_line("approve: ", device="/nonexistent/tty")


class CommandTests(SimpleTestCase):
    def test_live_operations_require_their_arguments(self):
        for argv in (("checkpoint",), ("replace",), ("verify-logins",)):
            with self.assertRaises(CommandError):
                call_command("r1_mfa_pilot", *argv, stdout=io.StringIO())

    def test_no_secret_or_approval_argument_exists(self):
        from core.management.commands.r1_mfa_pilot import Command

        parser = Command().create_parser("manage.py", "r1_mfa_pilot")
        options = {a for action in parser._actions for a in action.option_strings}
        self.assertFalse(options & {"--approval", "--password", "--secret", "--otp"})
