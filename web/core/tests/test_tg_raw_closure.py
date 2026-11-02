"""Lab 7 closure -- Raw Configlets (operator-authored device text): sandbox boundary, store, verification currency, capability,
codes and the static gate, each public function called directly, positive + negative.

Raw text is the riskiest input NMAS accepts, so the NEGATIVE cases are the point: a non-docker / malformed argv is refused before
any process exists, a lab container name can never be built into an argv, a secret-shaped line is never stored nor echoed back,
an unverified / stale / tampered pin is never executable, and a gap in verification is never PASS.  No Docker, device or NetBox.
"""

from __future__ import annotations

import subprocess
import uuid
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from core import models
from core.services.raw_configlets import assertions, capability, codes, sandbox, static_gate, store, verification, verifier
from core.services.raw_configlets.codes import Currency, Result, finding
from core.tests.helpers import raw as rh

NAME = "clab-rawverify-frr-0123456789ab"


class SandboxBoundaryTests(SimpleTestCase):
    def test_run_process_returns_exit_code_and_output(self):
        with mock.patch.object(sandbox.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=b"sha256:1", stderr=b"")):
            result = sandbox.run_process(["docker", "image", "inspect", "frr:test"], timeout=3)
        self.assertEqual((result.returncode, result.output, result.error, result.timed_out), (0, "sha256:1", "", False))

    def test_run_process_failures_become_fixed_results_never_exceptions(self):
        for label, effect, expected in (("timeout", subprocess.TimeoutExpired(["docker"], 3, output=b"partial"), (None, True, "")),
                                        ("docker missing", FileNotFoundError(), (None, False, "DOCKER_UNAVAILABLE")),
                                        ("os error", OSError("x"), (None, False, "OS_ERROR"))):
            with self.subTest(case=f"failure {label}"), mock.patch.object(sandbox.subprocess, "run", side_effect=effect):
                result = sandbox.run_process(["docker", "ps"], timeout=3)
                self.assertEqual((result.returncode, result.timed_out, result.error), expected)

    def test_argv_builders_produce_the_isolated_docker_commands(self):
        self.assertEqual(sandbox.exec_argv(NAME, ["vtysh"], interactive=True), ["docker", "exec", "-i", NAME, "vtysh"])
        self.assertEqual(sandbox.remove_argv(NAME), ["docker", "rm", "-f", NAME])
        self.assertEqual(sandbox.exists_argv(NAME), ["docker", "ps", "-a", "-q", "--filter", f"name=^/{NAME}$"])
        self.assertEqual(sandbox.image_argv("frr:test"), ["docker", "image", "inspect", "--format", "{{.Id}}", "frr:test"])
        one = sandbox.oneshot_argv(NAME, "frr:test", "vtysh", ["-C"], sandbox.FRR_LIMITS)
        self.assertEqual((one[:4], one[-3:]), (["docker", "run", "--rm", "-i"], ["vtysh", "frr:test", "-C"]))
        self.assertIn("--privileged", sandbox.detached_argv(NAME, "ceos:test", ("/sbin/init",), sandbox.CEOS_LIMITS, privileged=True))

    def test_argv_builders_refuse_a_lab_container_name_or_an_unsafe_image(self):
        for label, call in (("exists lab name", lambda: sandbox.exists_argv("clab-srlceos01-R1")),
                            ("exec lab name", lambda: sandbox.exec_argv("clab-srlceos01-R1", ["sh"])),
                            ("unsafe image", lambda: sandbox.image_argv("img; rm -rf /")),
                            ("oneshot unsafe image", lambda: sandbox.oneshot_argv(NAME, "--privileged", "vtysh", [], sandbox.FRR_LIMITS)),
                            ("detached lab name", lambda: sandbox.detached_argv("R1", "ceos:test", (), sandbox.CEOS_LIMITS, privileged=False))):
            with self.subTest(case=f"refused {label}"), self.assertRaises(AssertionError):
                call()

    def config(self):
        return sandbox.SandboxConfig("frr:test", "ceos:test", False, 5.0, 5.0, 5.0)

    def test_sandbox_names_itself_and_reports_an_available_image(self):
        box = sandbox.Sandbox("frr", self.config(), runner=lambda argv, **kw: sandbox.ProcessResult(0, "sha256:x"), token="0123456789abcdef")
        self.assertEqual((box.name, box.image_state("frr:test")), ("clab-rawverify-frr-0123456789ab", "OK"))

    def test_sandbox_image_state_missing_or_unavailable_runtime(self):
        for label, result, expected in (("missing image", sandbox.ProcessResult(1, "Error: No such image: x"), "MISSING"),
                                        ("unavailable runtime", sandbox.ProcessResult(error="DOCKER_UNAVAILABLE"), "UNAVAILABLE"),
                                        ("timeout", sandbox.ProcessResult(None, "", timed_out=True), "UNAVAILABLE"),
                                        ("other failure", sandbox.ProcessResult(1, "permission denied"), "UNAVAILABLE")):
            with self.subTest(case=f"failure {label}"):
                box = sandbox.Sandbox("frr", self.config(), runner=lambda argv, r=result, **kw: r)
                self.assertEqual(box.image_state("frr:test"), expected)

    def test_sandbox_remove_confirms_nothing_remains(self):
        calls = []
        box = sandbox.Sandbox("frr", self.config(), runner=lambda argv, **kw: calls.append(argv[1]) or sandbox.ProcessResult(0, ""))
        self.assertTrue(box.remove())
        self.assertEqual(calls, ["rm", "ps"])

    def test_sandbox_remove_is_never_true_while_a_container_remains_or_the_check_fails(self):
        for label, check in (("leftover container", sandbox.ProcessResult(0, "abc123\n")), ("check failed", sandbox.ProcessResult(error="OS_ERROR"))):
            with self.subTest(case=f"failure {label}"):
                box = sandbox.Sandbox("frr", self.config(), runner=lambda argv, c=check, **kw: c if argv[1] == "ps" else sandbox.ProcessResult(0, ""))
                self.assertFalse(box.remove())

    def test_sanitize_line_strips_ansi_control_characters_paths_and_secrets(self):
        self.assertEqual(sandbox.sanitize_line("\x1b[31m% Invalid input\x1b[0m at /etc/frr/frr.conf\r"), "% Invalid input at <path>")
        self.assertNotIn("hunter2", sandbox.sanitize_line("username admin secret hunter2"))

    def test_sanitize_line_never_raises_for_non_text_or_overlong_input(self):
        self.assertEqual(sandbox.sanitize_line(None), "None")
        self.assertEqual(len(sandbox.sanitize_line("x" * 10_000)), codes.MAX_EVIDENCE_LINE_LENGTH)

    def test_sanitize_output_drops_blank_lines_and_bounds_the_count(self):
        self.assertEqual(sandbox.sanitize_output("a\n\n b \n"), ["a", "b"])
        self.assertEqual(len(sandbox.sanitize_output("\n".join(f"l{n}" for n in range(500)), limit=3)), 3)

    def test_sanitize_output_never_echoes_secrets_or_empty_lines(self):
        self.assertEqual(sandbox.sanitize_output("\n\n"), [])
        self.assertFalse(any("topsecret" in line for line in sandbox.sanitize_output("snmp-server community topsecret ro")))


class RawCapabilityAndCodesTests(SimpleTestCase):
    def test_capability_lookups_for_supported_platforms(self):
        self.assertTrue(capability.can_author("arista_ceos"))
        self.assertEqual(capability.verification_capability("arista_ceos").status, capability.Capability.SUPPORTED)
        self.assertIs(capability.execution_capability("arista_ceos"), capability.EXECUTION["arista_ceos"])
        self.assertTrue(capability.compensation_note())

    def test_capability_lookups_for_an_unknown_platform_are_never_available(self):
        self.assertFalse(capability.can_author("junos"))
        self.assertNotEqual(capability.verification_capability("junos").status, capability.Capability.SUPPORTED)
        self.assertEqual((capability.execution_capability("junos").apply, capability.execution_capability("junos").compensation),
                         (capability.Capability.UNKNOWN, capability.Capability.UNKNOWN))

    def test_derive_result_orders_blocked_incomplete_warning_pass(self):
        self.assertEqual(codes.derive_result([finding("SYNTAX_ACCEPTED")]), Result.PASS)
        self.assertEqual(codes.derive_result([finding("SYNTAX_ACCEPTED"), finding("PLATFORM_WARNING")]), Result.PASS_WITH_WARNINGS)

    def test_derive_result_with_a_gap_or_a_rejection_is_never_clean(self):
        self.assertEqual(codes.derive_result([finding("SYNTAX_ACCEPTED"), finding("SANDBOX_UNAVAILABLE")]), Result.INCOMPLETE)
        self.assertEqual(codes.derive_result([finding("SANDBOX_UNAVAILABLE"), finding("SYNTAX_REJECTED")]), Result.BLOCKED)

    def test_bounded_findings_put_blocking_first(self):
        ordered = codes.bounded_findings([finding("SEMANTICS_NOT_VERIFIED"), finding("PLATFORM_WARNING"), finding("SYNTAX_REJECTED")])
        self.assertEqual(ordered[0]["code"], "SYNTAX_REJECTED")

    def test_bounded_findings_never_exceed_the_bound(self):
        self.assertEqual(len(codes.bounded_findings([finding("PLATFORM_WARNING")] * (codes.MAX_FINDINGS + 10))), codes.MAX_FINDINGS)

    def test_secret_patterns_returns_the_construct_name_only(self):
        names = static_gate.secret_patterns("username admin secret 0 hunter2")
        self.assertIn("KEYWORD:secret", names)
        self.assertFalse(any("hunter2" in n for n in names))

    def test_secret_patterns_none_for_clean_or_free_text_lines(self):
        self.assertEqual(static_gate.secret_patterns("interface Ethernet1"), [])
        self.assertEqual(static_gate.secret_patterns(""), [])
        self.assertEqual(static_gate.secret_patterns("secret"), [])                 # a keyword without a value is not a secret

    def test_assertion_descriptors_without_assertions_are_the_deferred_marker(self):
        got = assertions.descriptors([], device="R1", label="Loopback", raw_id="RAW-001")
        self.assertEqual([(d["requirement"], d["status"], d["subject"]["object_id"]) for d in got],
                         [(assertions.RAW_REQUIREMENT, "DEFERRED", "RAW-001")])


class RawStoreTests(TestCase):
    def setUp(self):
        self.p = rh.raw_change()

    def test_node_id_is_the_stable_graph_reference(self):
        self.assertEqual(store.node_id("R1", "RAW-001"), "R1/raw_configlet/RAW-001")

    def test_validate_authoring_accepts_a_valid_submission(self):
        clean, findings = store.validate_authoring(self.p.change, target_device="R1", name="Loopback", description="", priority=6,
                                                   content=rh.EOS_TEXT_2, dependencies=[], assertions=[])
        self.assertFalse([f for f in findings if f["blocking"]])
        self.assertEqual((clean["target_device"], clean["platform"], clean["name"]), ("R1", "arista_ceos", "Loopback"))

    def test_validate_authoring_refuses_invalid_name_unknown_target_and_secret_content(self):
        for label, kwargs, code in (("invalid name", {"name": ""}, "RAW_NAME_INVALID"), ("unknown target", {"target_device": "NOPE"}, "RAW_TARGET_INVALID"),
                                    ("secret content", {"content": "username admin secret 0 hunter2\n"}, "RAW_SECRET_SHAPED_CONTENT")):
            with self.subTest(case=f"invalid {label}"):
                fields = {"target_device": "R1", "name": "Loopback", "description": "", "priority": 6, "content": rh.EOS_TEXT_2,
                          "dependencies": [], "assertions": [], **kwargs}
                _clean, findings = store.validate_authoring(self.p.change, **fields)
                self.assertIn(code, {f["code"] for f in findings if f["blocking"]})

    def test_redisplay_safe_keeps_a_clean_submission(self):
        fields = {"name": "Loopback", "description": "d", "content": "interface Loopback1\n"}
        self.assertEqual(store.redisplay_safe(fields, []), fields)

    def test_redisplay_safe_never_echoes_a_refused_secret_line_or_name(self):
        fields = {"name": "pw hunter2", "description": "d", "content": "interface Loopback1\nusername admin secret 0 hunter2\n"}
        safe = store.redisplay_safe(fields, [finding("RAW_SECRET_SHAPED_CONTENT", line=2), finding("RAW_NAME_INVALID")])
        self.assertNotIn("hunter2", safe["content"])
        self.assertEqual((safe["name"], safe["description"]), ("", ""))
        self.assertIn("! [line 2: secret-shaped content was not kept]", safe["content"])

    def test_save_revision_creates_a_new_revision_or_reuses_an_identical_one(self):
        revision, created = store.save_revision(self.p.raw, target_device="R1", name="Loopback", content=rh.EOS_TEXT_2, priority=6, actor="tester")
        self.assertEqual((revision.revision, created), (2, True))
        again, created_again = store.save_revision(self.p.raw, target_device="R1", name="Loopback", content=rh.EOS_TEXT_2, priority=6)
        self.assertEqual((again.pk, created_again), (revision.pk, False))

    def test_save_revision_refuses_a_secret_and_stores_nothing(self):
        before = self.p.raw.revisions.count()
        with self.assertRaises(store.RawConfigletError) as caught:
            store.save_revision(self.p.raw, target_device="R1", name="Loopback", content="username a secret 0 hunter2\n", priority=6)
        self.assertIn("RAW_SECRET_SHAPED_CONTENT", str(caught.exception))
        self.assertEqual(self.p.raw.revisions.count(), before)

    def test_set_enabled_toggles_and_audits_once(self):
        self.assertTrue(store.set_enabled(self.p.raw, False, actor="tester"))
        self.assertFalse(models.RawConfiglet.objects.get(pk=self.p.raw.pk).enabled)
        self.assertTrue(models.AuditEvent.objects.filter(event_type=models.AuditEventType.RAW_ENABLED_CHANGED, object_id=self.p.raw.raw_id).exists())

    def test_set_enabled_to_the_current_state_is_refused_as_no_change(self):
        self.assertFalse(store.set_enabled(self.p.raw, True))

    def test_lookups_return_the_configlet_revision_and_run(self):
        run = rh.verify(self.p.revision)
        self.assertEqual(store.list_raw(self.p.change), [self.p.raw])
        self.assertEqual(store.get_raw(self.p.change, self.p.raw.raw_id), self.p.raw)
        self.assertEqual(store.get_revision(self.p.raw, "1"), self.p.revision)
        self.assertEqual(store.get_verification_run(self.p.raw, str(run.run_id)), run)

    def test_lookups_for_unknown_or_malformed_ids_return_nothing(self):
        self.assertIsNone(store.get_raw(self.p.change, "RAW-999"))
        for number in ("x", None, 99):
            with self.subTest(case=f"invalid revision {number!r}"):
                self.assertIsNone(store.get_revision(self.p.raw, number))
        self.assertIsNone(store.get_verification_run(self.p.raw, "not-a-uuid"))
        self.assertIsNone(store.get_verification_run(self.p.raw, str(uuid.uuid4())))
        from core.tests.helpers.validation import simple_pass_change

        self.assertEqual(store.list_raw(simple_pass_change().change), [])

    def test_status_of_a_verified_revision_is_current_and_acceptable(self):
        rh.verify(self.p.revision)
        status = store.status_of(self.p.raw)
        self.assertEqual((status["currency"], status["result"], status["in_progress"], status["acceptable"]), (Currency.CURRENT, Result.PASS, False, True))

    def test_status_of_an_unverified_revision_is_never_run_and_not_acceptable(self):
        status = store.status_of(self.p.raw)
        self.assertEqual((status["currency"], status["result"], status.get("acceptable", False)), (Currency.NEVER_RUN, None, False))


class RawVerificationTests(TestCase):
    def setUp(self):
        self.p = rh.verified()

    def test_lease_seconds_default_and_override(self):
        self.assertEqual(verification.lease_seconds(), 600.0)
        with override_settings(RAW_VERIFIER_LEASE_SECONDS=30):
            self.assertEqual(verification.lease_seconds(), 30.0)

    def test_latest_finished_and_currency_of_a_verified_revision(self):
        self.assertEqual(verification.latest_finished(self.p.revision), self.p.run)
        status = verification.currency(self.p.revision)
        self.assertTrue(verification.acceptable(status))

    def test_unverified_or_stale_or_blocked_status_is_never_acceptable(self):
        for label, status in (("never run", {"state": Currency.NEVER_RUN, "result": None}), ("stale", {"state": Currency.STALE, "result": Result.PASS}),
                              ("blocked", {"state": Currency.CURRENT, "result": Result.BLOCKED})):
            with self.subTest(case=f"invalid {label}"):
                self.assertFalse(verification.acceptable(status))
        other = rh.raw_change(name="Other", text=rh.EOS_TEXT_2)
        self.assertIsNone(verification.latest_finished(other.revision))

    def test_active_run_finds_a_running_run_within_its_lease(self):
        run = models.RawConfigletVerificationRun.objects.filter(pk=self.p.run.pk)
        run.update(state=models.RawVerificationState.RUNNING, lease_expires_at=timezone.now() + timedelta(minutes=5))
        self.assertEqual(verification.active_run(self.p.revision), self.p.run)

    def test_active_run_none_when_finished_or_lease_expired(self):
        self.assertIsNone(verification.active_run(self.p.revision))
        models.RawConfigletVerificationRun.objects.filter(pk=self.p.run.pk).update(
            state=models.RawVerificationState.RUNNING, lease_expires_at=timezone.now() - timedelta(minutes=5))
        self.assertIsNone(verification.active_run(self.p.revision))

    def test_reap_expired_finalises_an_abandoned_run_as_incomplete(self):
        models.RawConfigletVerificationRun.objects.filter(pk=self.p.run.pk).update(
            state=models.RawVerificationState.RUNNING, lease_expires_at=timezone.now() - timedelta(minutes=5))
        self.assertEqual(verification.reap_expired(), [str(self.p.run.run_id)])
        self.p.run.refresh_from_db()
        self.assertEqual((self.p.run.result, [f["code"] for f in self.p.run.findings]), (Result.INCOMPLETE, ["VERIFICATION_INTERRUPTED"]))

    def _configlet(self, **pins):
        return SimpleNamespace(raw_revision=self.p.revision, raw_verification=self.p.run,
                               metadata={"raw": {"content_hash": self.p.revision.content_hash, **pins}})

    def test_pinned_verification_state_ok_for_a_current_acceptable_pin(self):
        self.assertEqual(verification.pinned_verification_state(self._configlet()), (True, ""))

    def test_pinned_verification_state_refuses_missing_tampered_or_mismatched_pins(self):
        self.assertEqual(verification.pinned_verification_state(SimpleNamespace(raw_revision=None, raw_verification=None, metadata={})),
                         (False, "RAW_PIN_MISSING"))
        self.assertEqual(verification.pinned_verification_state(self._configlet(content_hash="0" * 64)), (False, "RAW_REVISION_INTEGRITY"))
        models.RawConfigletVerificationRun.objects.filter(pk=self.p.run.pk).update(result=Result.BLOCKED)
        self.p.run.refresh_from_db()
        self.assertEqual(verification.pinned_verification_state(self._configlet()), (False, "RAW_VERIFICATION_NOT_ACCEPTABLE"))

    def test_verifier_identity_names_adapter_backend_and_versions(self):
        identity = verifier.identity("arista_ceos")
        self.assertEqual(identity["adapter_id"], "ceos_config_session")
        self.assertTrue(identity["backend"].startswith("docker:"))

    def test_verifier_identity_with_an_invalid_image_setting_degrades_never_raises(self):
        with override_settings(RAW_VERIFIER_CEOS_IMAGE="bad image; rm"):
            self.assertEqual(verifier.identity("arista_ceos")["backend"], "INVALID_SANDBOX_CONFIGURATION")
