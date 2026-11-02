"""Lab 7 closure -- the cEOS MFA rollout helpers (``credentials/r1_pilot.py``), each called directly.

No device is contacted: every docker command goes to an injected runner that records its argv, the secret provider and
/proc are fakes in a temporary directory, and the reachability probe uses a socket bound on localhost.  POSITIVE: exact
target views, redaction, canaries, parsed device state and transport argv.  NEGATIVE: an unknown reference, a short or
whitespace value, a missing store, a non-zero exit, unreadable metadata or a secret that would reach argv each fail
closed -- and no secret value ever appears in output, argv, child environment or an exception message.
"""

from __future__ import annotations

import os
import socket
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from core.services.credentials import r1_pilot as p
from modules.device_credentials import SecretProviderError

LONG = "Abcdefghijklmnop0123+/="                       # an EOS-safe 23-character value (fake)
TARGET = p.CeosMfaTarget(
    device="R2", container="clab-srlceos01-R2", management_address="192.168.200.2", automation_account="nmas-automation", breakglass_account="r2-breakglass",
    automation_ref="runtime://device-credentials/r2-nmas-automation", breakglass_ref="runtime://device-credentials/r2-breakglass",
    legacy_ref="runtime://device-credentials/ceos-admin-shared", radius_ref="runtime://human-mfa/radius/r2", checkpoint_original="pre-mfa-r2",
    checkpoint_stage2="pre-mfa-stage2-r2", stage1_session="NMAS-R2-MFA-S1", stage2_session="NMAS-R2-MFA-S2", cleanup_session="NMAS-R2-MFA-CLEAN",
    validation_sessions=("a", "b", "c", "d"), approval_phrase="APPLY R2 MFA ROLLOUT")


class Runner:
    """Records each docker argv; answers with a fixed CompletedProcess."""

    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr, self.calls = stdout, returncode, stderr, []

    def __call__(self, argv, **kw):
        self.calls.append((list(argv), kw))
        return subprocess.CompletedProcess(argv, self.returncode, self.stdout, self.stderr)


class TargetViewTests(SimpleTestCase):
    def test_target_views_list_its_accounts_refs_and_checkpoints(self):
        self.assertEqual(TARGET.accounts, ("nmas-automation", "r2-breakglass"))
        self.assertEqual(TARGET.account_refs, {"nmas-automation": TARGET.automation_ref, "r2-breakglass": TARGET.breakglass_ref, "admin": TARGET.legacy_ref})
        self.assertEqual(TARGET.config_refs, (TARGET.automation_ref, TARGET.breakglass_ref, TARGET.radius_ref))
        self.assertEqual(TARGET.login_only_refs, (TARGET.legacy_ref,))
        self.assertEqual(TARGET.checkpoints, ("pre-mfa-r2", "pre-mfa-stage2-r2"))
        checks = TARGET.required_post_stage2_checks
        self.assertEqual(
            (len(checks), checks[3:7]),
            (13, ("nmas-automation_login", "nmas-automation_privilege15",
                  "r2-breakglass_login", "r2-breakglass_privilege15")),
        )


class SecretSetTests(SimpleTestCase):
    def test_checkable_keeps_values_long_enough_to_search(self):
        found = p.SecretSet(["admin", LONG]).checkable()
        self.assertEqual(list(found), [LONG])

    def test_checkable_drops_short_values_never_searched_for(self):
        self.assertEqual(len(p.SecretSet(["admin", "123456"]).checkable()), 0)

    def test_merged_holds_both_sets_once(self):
        self.assertEqual(sorted(p.SecretSet([LONG]).merged(p.SecretSet([LONG, "x" * 20]))), sorted([LONG, "x" * 20]))

    def test_merged_with_an_empty_set_adds_nothing(self):
        self.assertEqual(list(p.SecretSet([LONG]).merged(p.SecretSet())), [LONG])

    def test_occurs_in_text_and_bytes_without_the_value_is_false(self):
        known = p.SecretSet([LONG])
        self.assertEqual((known.occurs_in("nothing here"), known.occurs_in(b"nothing here"), known.occurs_in(f"x{LONG}x".encode())), (False, False, True))

    def test_redact_replaces_known_values_and_structural_secrets(self):
        text, leaked = p.SecretSet([LONG]).redact(f"echo {LONG}\nusername admin secret sha512 $6$abc\nradius-server key 7 0822455D0A16")
        self.assertTrue(leaked)
        self.assertEqual(text, "echo <REDACTED>\nusername admin secret sha512 <REDACTED>\nradius-server key 7 <REDACTED>")
        self.assertEqual(repr(p.SecretSet([LONG])), "SecretSet(<1 redacted>)")


class ResolverTests(SimpleTestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp))

    def radius(self, value=LONG, mode=0o600):
        path = self.tmp / "radius_r2_secret"
        path.write_text(value + "\n", encoding="utf-8")
        path.chmod(mode)
        return path

    def resolver(self, value=LONG, error=None):
        def current(_ref):
            if error:
                raise error
            return SimpleNamespace(value=value)

        return p.PilotSecretResolver(provider=SimpleNamespace(current=current), radius_root=self.tmp)

    def test_radius_secret_path_maps_the_reference_to_its_store(self):
        self.assertEqual(p.radius_secret_path("runtime://human-mfa/radius/r2", root=self.tmp), self.tmp / "radius_r2_secret")

    def test_radius_secret_path_refuses_any_other_reference(self):
        for ref in ("runtime://human-mfa/radius/../etc", "runtime://device-credentials/r2", "runtime://human-mfa/radius/R2"):
            with self.subTest(case=f"refused {ref}"), self.assertRaises(p.PilotError):
                p.radius_secret_path(ref, root=self.tmp)

    def test_resolve_reads_a_device_credential_and_a_private_radius_store(self):
        self.radius()
        found = self.resolver()
        self.assertEqual(found.resolve(TARGET.automation_ref), LONG)
        self.assertEqual(found.resolve(TARGET.radius_ref), LONG)
        self.assertEqual(found.resolve(TARGET.legacy_ref, for_config=False), LONG)

    def test_exists_false_for_an_unavailable_unsafe_or_unsupported_reference(self):
        self.radius(mode=0o644)
        for label, resolver, ref in (("provider error", self.resolver(error=SecretProviderError("gone")), TARGET.automation_ref),
                                     ("short value", self.resolver(value="short"), TARGET.automation_ref),
                                     ("world readable store", self.resolver(), TARGET.radius_ref),
                                     ("missing store", self.resolver(), "runtime://human-mfa/radius/r9"),
                                     ("unsupported scheme", self.resolver(), "vault://x")):
            with self.subTest(case=f"failure {label}"):
                self.assertFalse(resolver.exists(ref))
        with self.assertRaises(p.PilotError) as caught:
            self.resolver(value="has space in it 0123456789").resolve(TARGET.automation_ref, for_config=False)
        self.assertNotIn("has space", str(caught.exception))


class PlaceholderTests(SimpleTestCase):
    def test_references_in_lists_each_placeholder_once(self):
        lines = [f"username a secret <provider:{TARGET.automation_ref}>", f"x <provider:{TARGET.automation_ref}> <provider:{TARGET.radius_ref}>"]
        self.assertEqual(p.references_in(lines), sorted([TARGET.automation_ref, TARGET.radius_ref]))

    def test_references_in_plain_lines_is_empty(self):
        self.assertEqual(p.references_in(["username a secret sha512 x", "<provider:vault://x>"]), [])

    def test_substitute_without_placeholders_changes_nothing_and_a_failing_resolver_raises(self):
        lines, known = p.substitute(["show version"], lambda ref: LONG)
        self.assertEqual((lines, len(known)), (["show version"], 0))

        def refuse(ref):
            raise p.PilotError(f"{ref} is unavailable")

        with self.assertRaises(p.PilotError):
            p.substitute([f"<provider:{TARGET.automation_ref}>"], refuse)

    def test_shaped_canary_keeps_length_punctuation_and_first_character_class(self):
        for template in (LONG, "+abc/def=ghij.klmn-op"):
            canary = p.shaped_canary(template)
            with self.subTest(case=f"shape {template[:4]}"):
                self.assertEqual(len(canary), len(template))
                self.assertEqual(sorted(c for c in canary if c in "_+/=.-"), sorted(c for c in template if c in "_+/=.-"))
                self.assertEqual(canary[0] in "_+/=.-", template[0] in "_+/=.-")

    def test_canary_resolver_shapes_and_remembers_each_reference(self):
        resolver = p.CanaryResolver(shape_of=lambda ref: LONG)
        first = resolver(TARGET.automation_ref)
        self.assertEqual((resolver(TARGET.automation_ref), len(first), resolver.shaped), (first, len(LONG), {TARGET.automation_ref}))
        self.assertNotEqual(first, LONG)
        self.assertEqual(resolver.extra("probe"), resolver("canary://probe"))

    def test_canary_resolver_without_a_shape_never_reuses_a_real_value(self):
        resolver = p.CanaryResolver()
        value = resolver.extra("probe")
        self.assertTrue(value.startswith("nmasCanary"))
        self.assertEqual((len(value), resolver.shaped), (50, set()))
        self.assertEqual(p.CanaryResolver(shape_of=lambda ref: None)(TARGET.radius_ref)[:10], "nmasCanary")


class ProcessIsolationTests(SimpleTestCase):
    def test_minimal_child_environment_carries_only_the_listed_keys(self):
        with mock.patch.dict(os.environ, {"PATH": "/bin", "HOME": "/h", "NMAS_SECRET": LONG}, clear=True):
            self.assertEqual(p.minimal_child_environment(), {"PATH": "/bin", "LANG": "C.UTF-8", "HOME": "/h"})

    def test_process_table_scanner_reports_a_secret_in_argv_on_exit(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        (root / "123").mkdir()
        (root / "123" / "cmdline").write_bytes(f"cli\0{LONG}\0".encode())
        (root / "self").mkdir()
        with p.ProcessTableScanner(p.SecretSet([LONG]), proc_root=root, interval=0.01) as scanner:
            pass
        self.assertEqual(scanner.hits, {"process_argv"})
        with p.ProcessTableScanner(p.SecretSet(), proc_root=root) as idle:
            pass
        self.assertEqual((idle.hits, idle._thread), (set(), None))

    def test_cli_result_clean_and_leaked(self):
        self.assertEqual((p.CliResult("ok", [], {"cli_output": False}, 0).clean, p.CliResult("ok", [], {"cli_output": False}, 0).leaked), (True, False))
        self.assertEqual((p.CliResult("x", ["% Invalid"], {"cli_output": True}, 0).clean, p.CliResult("x", [], {"cli_output": True}, 0).leaked), (False, True))


class TransportTests(SimpleTestCase):
    def test_stdin_argv_and_show_use_fixed_commands(self):
        runner = Runner(stdout="Arista vEOS\n")
        transport = p.EosCliTransport("clab-srlceos01-R2", runner=runner)
        self.assertEqual(transport.stdin_argv, ["docker", "exec", "-i", "clab-srlceos01-R2", "Cli", "-p", "15"])
        self.assertEqual(transport.show("show version"), "Arista vEOS\n")
        self.assertEqual(runner.calls[0][0], ["docker", "exec", "clab-srlceos01-R2", "Cli", "-p", "15", "-c", "show version"])
        self.assertEqual(p.running_config(p.EosCliTransport(runner=Runner(stdout="hostname R2\n"))), "hostname R2\n")

    def test_running_config_of_a_failing_device_raises(self):
        with self.assertRaises(p.PilotError):
            p.running_config(p.EosCliTransport(runner=Runner(returncode=1)))

    def test_running_digest_is_the_sha256_of_the_text(self):
        self.assertEqual(p.running_digest("hostname R2\n"), __import__("hashlib").sha256(b"hostname R2\n").hexdigest())

    def test_running_digest_of_a_tampered_config_differs(self):
        self.assertNotEqual(p.running_digest("hostname R2\n"), p.running_digest("hostname R2 \n"))

    def test_file_digests_hash_in_memory(self):
        found = p.EosCliTransport(runner=Runner(stdout=b"hostname R2\n")).file_digests("/mnt/flash/startup-config")
        self.assertEqual((found["sha256"], len(found["md5"])), (__import__("hashlib").sha256(b"hostname R2\n").hexdigest(), 32))

    def test_file_digests_none_for_an_unreadable_file(self):
        self.assertIsNone(p.EosCliTransport(runner=Runner(returncode=1)).file_digests("/mnt/flash/absent"))

    def test_device_leak_scan_sends_patterns_on_stdin_and_lists_file_names(self):
        runner = Runner(stdout="/var/log/b\n/tmp/a\n/tmp/a\n")
        found = p.EosCliTransport(runner=runner).device_leak_scan(p.SecretSet([LONG]))
        self.assertEqual(found, ["/tmp/a", "/var/log/b"])
        argv, kw = runner.calls[0]
        self.assertNotIn(LONG, " ".join(argv))
        self.assertEqual(kw["input"], LONG + "\n")

    def test_device_leak_scan_without_known_values_runs_nothing(self):
        runner = Runner()
        self.assertEqual((p.EosCliTransport(runner=runner).device_leak_scan(p.SecretSet()), runner.calls), ([], []))

    def test_config_sessions_refuses_malformed_output(self):
        with self.assertRaises(ValueError):
            p.config_sessions(p.EosCliTransport(runner=Runner(stdout="% Invalid input")))


class DeviceStateTests(SimpleTestCase):
    def test_session_closed_for_finished_sessions(self):
        self.assertTrue(p.session_closed({"state": "Committed"}))
        self.assertTrue(p.session_closed({"completedTime": 1.0}))

    def test_session_closed_false_for_pending_timer_or_unknown_sessions(self):
        for label, meta in (("timer pending", {"state": "committed", "timer_pending": True}), ("pending", {"state": "pending"}), ("none", None)):
            with self.subTest(case=f"failure {label}"):
                self.assertFalse(p.session_closed(meta))

    def test_local_usernames_and_security_summary(self):
        config = "hostname R2\nusername admin privilege 15 secret sha512 $6$x\naaa authorization exec default local\n" \
                 "management ssh\n   authentication mode password\nrouter bgp 1\n"
        self.assertEqual(p.local_usernames(config), ["admin"])
        self.assertEqual(p.security_summary(config), ["username admin privilege 15 secret sha512 <REDACTED>", "aaa authorization exec default local",
                                                      "management ssh", "   authentication mode password"])

    def test_local_usernames_and_security_summary_of_a_config_without_them_are_empty(self):
        self.assertEqual((p.local_usernames("hostname R2\n"), p.security_summary("hostname R2\nrouter bgp 1\n   neighbor x\n")), ([], []))

    def test_diff_changed_lines_are_the_added_and_removed_lines(self):
        self.assertEqual(p.diff_changed_lines("--- a\n+++ b\n@@\n-old\n+new\n same\n"), ["-old", "+new"])

    def test_diff_changed_lines_of_an_unchanged_diff_are_none(self):
        self.assertEqual(p.diff_changed_lines("--- a\n+++ b\n same\n"), [])

    def test_timer_state_not_armed_reverted_or_unknown(self):
        marker = p.ACTIVATION_MARKER
        for label, kw, state in (("never armed", dict(armed_at=None, confirmed_at=None), p.TimerState.NOT_ARMED),
                                 ("reverted", dict(armed_at=10.0, confirmed_at=None, config_text="hostname R1"), p.TimerState.AUTO_REVERTED),
                                 ("active without confirmation", dict(armed_at=10.0, confirmed_at=None, config_text=marker), p.TimerState.UNKNOWN)):
            with self.subTest(case=f"failure {label}"):
                args = {"sessions": {}, "config_text": "", "now": 20.0, **kw}
                self.assertEqual(p.timer_state(**args)["state"], state)

    def test_gate_report_check_and_ok(self):
        report = p.GateReport()
        report.check("health", True)
        self.assertEqual((report.ok, report.passed), (True, ["health"]))

    def test_gate_report_records_a_failure_with_its_detail(self):
        report = p.GateReport()
        report.check("nsot", False, "unreachable")
        report.check("radius", False)
        self.assertEqual((report.ok, report.failures), (False, ["nsot: unreachable", "radius"]))


class InfrastructureTests(SimpleTestCase):
    def test_mfa_infrastructure_healthy_when_every_container_runs(self):
        self.assertEqual(p.mfa_infrastructure_healthy(Runner(stdout="running healthy\n"), {"radius": "healthy", "db": "running"}), (True, []))

    def test_mfa_infrastructure_unhealthy_names_each_failed_container(self):
        self.assertEqual(p.mfa_infrastructure_healthy(Runner(stdout="running starting\n"), {"radius": "healthy", "db": "running"}), (False, ["radius"]))
        self.assertEqual(p.mfa_infrastructure_healthy(Runner(returncode=1), {"db": "running"}), (False, ["db"]))

    def test_management_reachable_on_a_listening_port(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        self.addCleanup(server.close)
        self.assertTrue(p.management_reachable("127.0.0.1", server.getsockname()[1], timeout=2))

    def test_management_reachable_is_false_on_an_unreachable_port(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        self.assertFalse(p.management_reachable("127.0.0.1", port, timeout=2))

    def test_radius_delta_per_counter(self):
        self.assertEqual(p.radius_delta({"messages_sent": 6, "requests_accepted": 1}, {"messages_sent": 9, "requests_accepted": 2}), {"messages_sent": 3, "requests_accepted": 1})

    def test_radius_delta_refuses_a_missing_counter(self):
        with self.assertRaises(KeyError):
            p.radius_delta({"messages_sent": 6}, {})

    def test_classify_command_output_denied_or_unknown_output(self):
        for label, text, expected in (("authorization denied", "% Authorization denied for command 'enable'", "DENIED"), ("invalid input", "% Invalid input", "OTHER")):
            with self.subTest(case=f"failure {label}"):
                self.assertEqual(p.classify_command_output(text), expected)

    def test_privilege_parser_requires_exact_level_fifteen(self):
        self.assertEqual(p.parse_privilege_level("Current privilege level is 15"), 15)
        self.assertEqual(p.classify_command_output("Current privilege level is 15"), "OK")
        self.assertEqual(p.classify_command_output("Current privilege level is 1"), "UNEXPECTED_LEVEL")
        self.assertIsNone(p.parse_privilege_level("Current privilege level is unavailable"))

    def test_privilege_parser_rejects_a_non_text_response(self):
        with self.assertRaises(TypeError):
            p.parse_privilege_level(None)


class PrivacyIdeaReaderTests(SimpleTestCase):
    def test_token_and_audit_read_the_marked_json_line(self):
        runner = Runner(stdout='noise\nNMAS-JSON:{"serial": "TOTP0001522E", "failcount": 0}\n')
        reader = p.PrivacyIdeaReader("pi-app", runner=runner)
        self.assertEqual(reader.token(), {"serial": "TOTP0001522E", "failcount": 0})
        self.assertEqual(reader.audit(after_id=7), {"serial": "TOTP0001522E", "failcount": 0})
        self.assertEqual(runner.calls[0][0][:4], ["docker", "exec", "-i", "pi-app"])
        self.assertIn('"after_id": 7', runner.calls[1][1]["input"])

    def test_token_and_audit_without_a_marked_line_raise(self):
        reader = p.PrivacyIdeaReader(runner=Runner(stdout="Traceback\n", returncode=1))
        for call in (reader.token, reader.audit):
            with self.subTest(case=f"failure {call.__name__}"), self.assertRaises(p.PilotError) as caught:
                call()
            self.assertEqual(str(caught.exception), "privacyIDEA metadata read failed (exit 1).")
