"""Phase-18 Raw Configlets: static gate, text, capability, assertions, identity / revisions, verification results and currency.

Matrix / subTest style on purpose: one method per invariant, many rows per method.  The sandbox is faked (``helpers.raw``); the real
adapters are covered by ``test_raw_sandbox``.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from unittest import mock

from django.db import IntegrityError, transaction
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from core import models
from core.services import raw_configlet_service as rcs
from core.services.raw_configlets import assertions, capability, codes, static_gate, text as text_module, verification
from core.tests.helpers import raw as rh
from core.tests.helpers.validation import Dev, new_change

DOC = Path(__file__).resolve().parents[3] / "docs" / "RAW_CONFIGLETS_AND_SANDBOX.md"
TOKEN = "gh" + "p_" + "A1b2C3d4E5" * 4          # credential-shaped samples are assembled at runtime
PRIVATE = "-----BEGIN " + "RSA PRIVATE KEY-----"


def gate_codes(text):
    return set(static_gate.evaluate(text).codes)


class StaticGateTests(SimpleTestCase):
    def test_blocking_rows(self):
        rows = [
            ("empty", "  \n\n", "RAW_EMPTY"),
            ("NUL byte", "hostname a\x00b\n", "RAW_NUL_BYTE"),
            ("invalid encoding (lone surrogate)", "hostname \udc80\n", "RAW_INVALID_ENCODING"),
            ("tab", "interface Ethernet1\n\tdescription x\n", "RAW_CONTROL_CHARACTER"),
            ("non-ASCII", "description café\n" + "hostname r1\n", "RAW_NON_ASCII_CHARACTER"),
            ("too large", "hostname r1\n" + "!" * (codes.MAX_BYTES + 1), "RAW_TOO_LARGE"),
            ("too many lines", "\n".join(f"vlan {n}" for n in range(codes.MAX_LINES + 1)) + "\n", "RAW_TOO_MANY_LINES"),
            ("line too long", "description " + "x" * (codes.MAX_LINE_LENGTH + 1) + "\n", "RAW_LINE_TOO_LONG"),
            ("device prompt transcript", "R1(config)# interface Ethernet1\n", "RAW_PROMPT_TRANSCRIPT"),
            ("enable", "enable\n", "RAW_MODE_CONTROL_COMMAND"),
            ("configure terminal", "configure terminal\n", "RAW_MODE_CONTROL_COMMAND"),
            ("explicit exit", "interface Ethernet1\nexit\n", "RAW_MODE_CONTROL_COMMAND"),
            ("bash", "bash rm -rf /\n", "RAW_HOST_SHELL_COMMAND"),
            ("docker", "docker ps\n", "RAW_HOST_SHELL_COMMAND"),
            ("ssh", "ssh admin@10.0.0.1\n", "RAW_HOST_SHELL_COMMAND"),
            ("python", "python3 -c 'print(1)'\n", "RAW_HOST_SHELL_COMMAND"),
            ("show", "show running-config\n", "RAW_EXEC_MODE_COMMAND"),
            ("write", "write memory\n", "RAW_EXEC_MODE_COMMAND"),
            ("reload", "reload now\n", "RAW_EXEC_MODE_COMMAND"),
            ("erase", "erase startup-config\n", "RAW_EXEC_MODE_COMMAND"),
            ("event-handler", "event-handler x\n   action bash /tmp/x\n", "RAW_HOST_EXECUTION_CONSTRUCT"),
            ("daemon", "daemon foo\n   command /bin/foo\n", "RAW_HOST_EXECUTION_CONSTRUCT"),
            ("alias", "alias x show version\n", "RAW_HOST_EXECUTION_CONSTRUCT"),
            ("command substitution", "hostname $(id)\n", "RAW_SHELL_METACHARACTER"),
            ("chained command", "hostname a; hostname b\n", "RAW_SHELL_METACHARACTER"),
            ("banner", "banner login\n", "RAW_UNSUPPORTED_CONTEXT"),
            ("user secret", "username admin secret sha512 $6$abcdef\n", "RAW_SECRET_SHAPED_CONTENT"),
            ("neighbor password", "router bgp 65001\n   neighbor 10.0.0.2 password 7 abcdef\n", "RAW_SECRET_SHAPED_CONTENT"),
            ("snmp community", "snmp-server community public ro\n", "RAW_SECRET_SHAPED_CONTENT"),
            ("snmpv3 key", "snmp-server user u g v3 auth sha 0123456789abcdef priv aes 0123456789abcdef\n", "RAW_SECRET_SHAPED_CONTENT"),
            ("private key block", f"{PRIVATE}\n", "RAW_SECRET_SHAPED_CONTENT"),
            ("token format", f"ntp authentication-key 1 md5 {TOKEN}\n", "RAW_SECRET_SHAPED_CONTENT"),
        ]
        for case, text, expected in rows:
            with self.subTest(case=case):
                result = static_gate.evaluate(text)
                self.assertIn(expected, result.codes)
                self.assertFalse(result.passed)

    def test_benign_configuration_is_not_a_false_positive(self):
        rows = [
            "interface Ethernet1\n   description rotate the password on the link\n   ip address 192.0.2.1/31\n",
            "! this comment mentions a password and a secret token\n# community strings are described here\nhostname r1\n",
            "router bgp 65001\n   neighbor 10.0.0.2 send-community\n   neighbor 10.0.0.2 route-map RM out\n",
            "route-map RM permit 10\n   set community 65000:100\nip community-list standard C1 permit 65000:100\n",
            "no enable password\n",
            "interface Loopback99\n   ip address 192.0.2.99/32\n\n",
        ]
        for text in rows:
            with self.subTest(text=text[:40]):
                result = static_gate.evaluate(text)
                self.assertTrue(result.passed, result.findings)
                self.assertFalse(any(f["code"] == "RAW_SECRET_SHAPED_CONTENT" for f in result.findings))

    def test_findings_never_carry_the_matched_secret_text(self):
        secret_line = "username admin secret sha512 $6$SuperSecretValue123\n"
        blob = repr(static_gate.evaluate(secret_line).findings)
        self.assertNotIn("SuperSecretValue123", blob)
        self.assertNotIn(TOKEN, repr(static_gate.evaluate(f"ntp authentication-key 1 md5 {TOKEN}\n").findings))


class TextAndCapabilityTests(SimpleTestCase):
    def test_normalization_is_deterministic_idempotent_and_hash_sensitive(self):
        unix = "interface Loopback1\n   ip address 192.0.2.1/32\n"
        for variant in ("interface Loopback1\r\n   ip address 192.0.2.1/32\r\n", "interface Loopback1\r   ip address 192.0.2.1/32  \n\n\n"):
            with self.subTest(variant=variant):
                self.assertEqual(text_module.normalize(variant), unix)
        self.assertEqual(text_module.normalize(unix), unix)
        self.assertEqual(text_module.content_hash(unix), text_module.content_hash(text_module.normalize(unix)))
        self.assertNotEqual(text_module.content_hash(unix), text_module.content_hash(unix.replace("192.0.2.1", "192.0.2.2")))
        self.assertEqual(text_module.command_lines("! c\ninterface X\n   # d\n   ip address 1.1.1.1/32\n"), ["interface X", "   ip address 1.1.1.1/32"])

    def test_capability_matrix_is_evidence_based_and_separates_verification_from_execution(self):
        rows = {
            "arista_ceos": ("SUPPORTED", "SUPPORTED", "NOT_IMPLEMENTED"),
            "ubuntu_frr": ("SUPPORTED", "NOT_IMPLEMENTED", "NOT_IMPLEMENTED"),
            "nokia_srlinux": ("UNSUPPORTED", "UNSUPPORTED", "UNSUPPORTED"),
            "cisco_c8000v_iosxe": ("NOT_IMPLEMENTED", "NOT_IMPLEMENTED", "NOT_IMPLEMENTED"),
            "cisco_iosxr": ("NOT_IMPLEMENTED", "NOT_IMPLEMENTED", "NOT_IMPLEMENTED"),
            "sonic": ("NOT_IMPLEMENTED", "NOT_IMPLEMENTED", "NOT_IMPLEMENTED"),
            "made_up_platform": ("UNKNOWN", "UNKNOWN", "UNKNOWN"),
        }
        for platform, (verify, apply, compensation) in rows.items():
            with self.subTest(platform=platform):
                self.assertEqual(capability.verification_capability(platform).status, verify)
                self.assertEqual(capability.execution_capability(platform).apply, apply)
                self.assertEqual(capability.execution_capability(platform).compensation, compensation)
        self.assertTrue(capability.verification_capability("arista_ceos").requires_privileged)
        self.assertFalse(capability.verification_capability("ubuntu_frr").requires_privileged)
        self.assertEqual({r["platform"] for r in capability.capability_matrix()}, set(models.Platform.values))

    def test_assertion_catalogue_is_closed_strict_and_maps_to_existing_evaluators(self):
        parsed, errors = assertions.parse_lines(
            "# comment\nADDRESS_PRESENT interface=Loopback99 address=192.0.2.99/32\nROUTE_PRESENT prefix=10.9.0.0/24 next_hop=192.0.2.1\n"
            "OSPF_ADJACENCY interface=Ethernet1\nBGP_ADJACENCY peer=192.0.2.1\nINTERFACE_STATE interface=Loopback99 admin_enabled=true\n")
        self.assertEqual(errors, [])
        clean, problems = assertions.normalize(parsed)
        self.assertEqual(problems, [])
        kinds = {row["requirement"] for row in assertions.descriptors(clean, device="R1", label="RAW-001", raw_id="RAW-001")}
        self.assertEqual(kinds, {"ADDRESS_PRESENT", "ROUTE_INTENDED", "ROUTING_INTERFACE_ENABLED", "BGP_PEER_INTENDED", "INTERFACE_PRESENT"})
        bad = [
            ("unknown kind", "SHOW_COMMAND cmd=show-version"),
            ("free-form key", "ADDRESS_PRESENT interface=Lo1 address=192.0.2.1/32 command=bash"),
            ("bad address", "ADDRESS_PRESENT interface=Lo1 address=999.1.1.1/32"),
            ("missing required", "ADDRESS_PRESENT interface=Lo1"),
            ("bad interface", "INTERFACE_STATE interface=;rm"),
        ]
        for case, line in bad:
            with self.subTest(case=case):
                parsed, errors = assertions.parse_lines(line)
                _clean, problems = assertions.normalize(parsed)
                self.assertTrue(errors or problems)
        marker = assertions.descriptors([], device="R1", label="RAW-001", raw_id="RAW-001")
        self.assertEqual([m["requirement"] for m in marker], ["RAW_CONFIG_APPLIED"])   # no assertion -> the honestly unverifiable marker


class IdentityAndRevisionTests(TestCase):
    def test_identity_is_stable_per_change_and_never_a_database_key(self):
        a, b = rh.raw_change(), rh.raw_change()
        second, _ = rcs.create_raw_configlet(a.change, target_device="R1", name="two", content=rh.EOS_TEXT_2, priority=3, actor="tester")
        self.assertEqual((a.raw.raw_id, second.raw_id, b.raw.raw_id), ("RAW-001", "RAW-002", "RAW-001"))
        self.assertEqual(rcs.node_id("R1", "RAW-001"), "R1/raw_configlet/RAW-001")
        with self.assertRaises(ValueError):  # raw_id is immutable once persisted
            a.raw.raw_id = "RAW-999"
            a.raw.save()

    def test_a_revision_is_immutable_and_an_edit_creates_a_new_one_preserving_history(self):
        p = rh.raw_change()
        first_hash = p.revision.content_hash
        with self.assertRaises(ValueError):
            p.revision.content = "hostname changed\n"
            p.revision.save()
        same, created = rcs.save_revision(p.raw, target_device="R1", name="Loopback", content=rh.EOS_TEXT, priority=6, actor="tester")
        self.assertFalse(created)                                   # an identical save is a no-op
        self.assertEqual(p.raw.revisions.count(), 1)
        new, created = rcs.save_revision(p.raw, target_device="R1", name="Loopback", content=rh.EOS_TEXT + "   no shutdown\n", priority=6, actor="tester")
        self.assertTrue(created)
        self.assertEqual((new.revision, p.raw.revisions.count()), (2, 2))
        self.assertEqual(p.raw.revisions.get(revision=1).content_hash, first_hash)   # history preserved exactly
        self.assertNotEqual(new.content_hash, first_hash)
        self.assertEqual(p.raw.latest_revision().pk, new.pk)

    def test_save_refuses_and_persists_nothing_for_every_invalid_input(self):
        p = rh.raw_change()
        Dev(p.change, "SRL", platform=models.Platform.NOKIA_SRLINUX)
        good = dict(target_device="R1", name="n", content=rh.EOS_TEXT, priority=6, actor="tester")
        rows = [
            ("secret-shaped content", dict(content="username x secret sha512 $6$abc\n"), "RAW_SECRET_SHAPED_CONTENT"),
            ("shell command", dict(content="bash -c id\n"), "RAW_HOST_SHELL_COMMAND"),
            ("unknown target", dict(target_device="R9"), "RAW_TARGET_INVALID"),
            ("unsupported platform", dict(target_device="SRL"), "RAW_PLATFORM_UNSUPPORTED"),
            ("bad priority", dict(priority=42), "RAW_PRIORITY_INVALID"),
            ("empty name", dict(name="  "), "RAW_NAME_INVALID"),
            ("secret in description", dict(description=f"token {TOKEN}"), "RAW_NAME_INVALID"),
            ("malformed dependency", dict(dependencies=["not a ref"]), "RAW_DEPENDENCY_INVALID"),
            ("self dependency", dict(dependencies=["R1/raw_configlet/RAW-002"]), "RAW_DEPENDENCY_SELF"),
            ("bad assertion", dict(assertions=[{"kind": "SHOW_COMMAND"}]), "RAW_ASSERTION_INVALID"),
        ]
        before = (models.RawConfiglet.objects.count(), models.RawConfigletRevision.objects.count(), models.AuditEvent.objects.count())
        for case, override, code in rows:
            with self.subTest(case=case):
                with self.assertRaises(rcs.RawConfigletError) as caught:
                    rcs.create_raw_configlet(p.change, **{**good, **override})
                self.assertIn(code, [f["code"] for f in caught.exception.findings])
        self.assertEqual((models.RawConfiglet.objects.count(), models.RawConfigletRevision.objects.count(), models.AuditEvent.objects.count()), before)

    def test_disable_is_soft_audited_and_leaves_the_effective_input(self):
        p = rh.verified()
        self.assertEqual([e["raw_id"] for e in rcs.snapshot_entries(p.change)], ["RAW-001"])
        self.assertTrue(rcs.set_enabled(p.raw, False, actor="tester"))
        self.assertFalse(rcs.set_enabled(p.raw, False, actor="tester"))       # idempotent
        self.assertEqual(rcs.snapshot_entries(p.change), [])
        self.assertEqual((p.raw.revisions.count(), models.RawConfigletVerificationRun.objects.count()), (1, 1))  # history preserved
        self.assertTrue(models.AuditEvent.objects.filter(event_type="RAW_ENABLED_CHANGED", change=p.change).exists())
        for event in models.AuditEvent.objects.filter(change=p.change):
            self.assertNotIn("content", event.metadata)                       # audit never carries the configuration text


class VerificationSemanticsTests(TestCase):
    def test_every_result_is_derived_from_structured_findings(self):
        rows = [
            ("pass", rh.ACCEPT, "PASS"),
            ("warnings", (*rh.ACCEPT, "PLATFORM_WARNING"), "PASS_WITH_WARNINGS"),
            ("syntax reject", rh.REJECT, "BLOCKED"),
            ("sandbox unavailable", ("SANDBOX_UNAVAILABLE",), "INCOMPLETE"),
            ("timeout", ("SANDBOX_TIMEOUT",), "INCOMPLETE"),
            ("cleanup failed after accept", (*rh.ACCEPT, "SANDBOX_CLEANUP_FAILED"), "INCOMPLETE"),
            ("reject beats a cleanup problem", (*rh.REJECT, "SANDBOX_CLEANUP_FAILED"), "BLOCKED"),
        ]
        for case, script, expected in rows:
            with self.subTest(case=case):
                run = rh.verify(rh.raw_change().revision, *script)
                self.assertEqual((run.result, run.state), (expected, models.RawVerificationState.FINISHED))
                self.assertNotEqual(run.result, "STALE")

    def test_static_and_capability_failures_block_without_starting_a_sandbox(self):
        p = rh.raw_change()
        registry, ceos, _frr = rh.fakes()
        models.RawConfigletRevision.objects.filter(pk=p.revision.pk).update(content="bash -c id\n")   # a hand-edited row
        p.revision.refresh_from_db()
        run = rh.verify(p.revision, registry=registry)
        self.assertEqual(run.result, "BLOCKED")
        self.assertEqual(ceos.calls, [])                                                             # the sandbox was never reached
        self.assertIn("RAW_REVISION_INTEGRITY", [f["code"] for f in run.findings])
        srl = rh.raw_change()
        models.RawConfigletRevision.objects.filter(pk=srl.revision.pk).update(platform="nokia_srlinux")
        srl.revision.refresh_from_db()
        self.assertIn("RAW_PLATFORM_UNSUPPORTED", [f["code"] for f in rh.verify(srl.revision).findings])

    def test_currency_never_run_current_and_every_stale_reason(self):
        p = rh.raw_change()
        self.assertEqual(rcs.verification_currency(p.revision)["state"], "NEVER_RUN")
        run = rh.verify(p.revision)
        self.assertEqual(rcs.verification_currency(p.revision)["state"], "CURRENT")
        rows = [
            ("platform of the device changed", lambda: rcs.verification_currency(p.revision, current_platform="ubuntu_frr"), "PLATFORM_CHANGED", None),
            ("policy version", None, "POLICY_VERSION_CHANGED", ("core.services.raw_configlets.codes.POLICY_VERSION", "18.9.9-static")),
            ("verifier version", None, "VERIFIER_VERSION_CHANGED", ("core.services.raw_configlets.codes.VERIFIER_VERSION", "18.9.9")),
            ("adapter version", None, "ADAPTER_CHANGED", ("core.services.raw_configlets.adapters.CeosConfigSession.adapter_version", "9.9.9")),
            ("backend / image", None, "BACKEND_CHANGED", ("core.services.raw_configlets.sandbox.load_config", None)),
        ]
        for case, probe, reason, patch in rows:
            with self.subTest(case=case):
                if patch is None:
                    status = probe()
                elif patch[1] is None:
                    config = rh.context().config.__class__("frr:test", "ceos:other-image", True, 5.0, 5.0, 5.0)
                    with mock.patch(patch[0], return_value=config):
                        status = rcs.verification_currency(p.revision)
                else:
                    with mock.patch(patch[0], patch[1]):
                        status = rcs.verification_currency(p.revision)
                self.assertEqual(status["state"], "STALE")
                self.assertIn(reason, status["reasons"])
        self.assertEqual(rcs.verification_currency(p.revision)["run"].pk, run.pk)   # the stored run itself was never touched

    def test_a_malformed_server_setting_degrades_to_stale_and_incomplete_and_never_raises(self):
        p = rh.verified()
        with override_settings(RAW_VERIFIER_CEOS_IMAGE="--not a valid image"):
            status = rcs.verification_currency(p.revision)
            self.assertEqual((status["state"], "BACKEND_CHANGED" in status["reasons"]), ("STALE", True))
            self.assertEqual(rcs.snapshot_entries(p.change)[0]["verification"]["currency"], "STALE")   # validation / plan pages keep rendering
            outcome = rcs.verify_raw_configlet(p.revision)                                             # the REAL adapter; no runtime is ever reached
            self.assertEqual(outcome.result, "INCOMPLETE")
            self.assertIn("VERIFIER_INTERNAL_ERROR", [f["code"] for f in outcome.findings])

    def test_a_one_byte_edit_leaves_the_old_result_with_the_old_revision_only(self):
        p = rh.verified()
        new, _ = rcs.save_revision(p.raw, target_device="R1", name="Loopback", content=rh.EOS_TEXT.replace("99", "98"), priority=6, actor="tester")
        self.assertEqual(rcs.verification_currency(new)["state"], "NEVER_RUN")           # not carried forward
        self.assertEqual(rcs.verification_currency(p.revision)["state"], "CURRENT")      # the historical revision keeps its own result
        self.assertEqual(rcs.status_of(p.raw)["currency"], "NEVER_RUN")                  # ... but the effective (latest) revision is unverified

    def test_verification_is_explicit_and_reuse_applies_only_to_current_acceptable_results(self):
        p = rh.raw_change()
        registry, ceos, _ = rh.fakes()
        ctx = rh.context(registry)
        self.assertEqual(ceos.calls, [])                                                     # creating / saving / reading never verified
        first = rcs.request_verification(p.revision, actor="tester", context=ctx)
        again = rcs.request_verification(p.revision, actor="tester", context=ctx)
        self.assertEqual((first.reused, again.reused, again.run.pk, len(ceos.calls)), (False, True, first.run.pk, 1))
        forced = rcs.request_verification(p.revision, actor="tester", context=ctx, reuse=False)
        self.assertFalse(forced.reused)
        self.assertEqual(len(ceos.calls), 2)
        bad = rh.raw_change()
        registry2, ceos2, _ = rh.fakes(*rh.REJECT)
        for _ in range(2):                                                                   # BLOCKED is never reused
            rcs.request_verification(bad.revision, actor="tester", context=rh.context(registry2))
        self.assertEqual(len(ceos2.calls), 2)

    def test_duplicate_active_verification_is_refused_by_the_database(self):
        p = rh.raw_change()
        now = timezone.now()
        common = dict(revision=p.revision, content_hash=p.revision.content_hash, platform="arista_ceos", verifier_version="v", policy_version="p",
                      started_at=now, lease_expires_at=now + timedelta(seconds=600))
        models.RawConfigletVerificationRun.objects.create(**common)
        with self.assertRaises(IntegrityError), transaction.atomic():
            models.RawConfigletVerificationRun.objects.create(**common)
        response = rcs.request_verification(p.revision, actor="tester", context=rh.context(), reuse=False)
        self.assertEqual((response.run, response.refused), (None, "VERIFICATION_IN_PROGRESS"))
        # a crashed run cannot block the revision forever: its expired lease is reaped as INCOMPLETE
        models.RawConfigletVerificationRun.objects.filter(revision=p.revision).update(lease_expires_at=now - timedelta(seconds=1))
        self.assertEqual(len(verification.reap_expired(now)), 1)
        self.assertEqual(rcs.verification_currency(p.revision)["result"], "INCOMPLETE")

    def test_verification_runs_are_append_only_and_audited_without_secrets(self):
        p = rh.raw_change()
        run = rh.verify(p.revision)
        with self.assertRaises(ValueError):
            run.result = "BLOCKED"
            run.save()
        second = rh.verify(p.revision, *rh.REJECT, reuse=False)
        run.refresh_from_db()
        self.assertEqual((run.result, second.result), ("PASS", "BLOCKED"))                  # the old run was never mutated into the new result
        events = models.AuditEvent.objects.filter(change=p.change, event_type__in=["RAW_VERIFICATION_REQUESTED", "RAW_VERIFICATION_COMPLETED"])
        self.assertEqual(events.count(), 4)
        self.assertNotIn(rh.EOS_TEXT.strip().splitlines()[0], repr([e.metadata for e in events]))


class DocumentationTests(SimpleTestCase):
    def test_documentation_exists_and_documents_every_raw_code_and_required_topic(self):
        self.assertTrue(DOC.exists())
        body = DOC.read_text()
        self.assertEqual([code for code in codes.CODE_CATALOG if code not in body], [])
        lowered = body.lower()
        for phrase in ("structured", "immutable", "verification", "sandbox", "static", "secret", "partial (uat)", "complete", "postcheck",
                       "network none", "privileged", "not_implemented", "syntax", "known limitations"):
            self.assertIn(phrase, lowered, phrase)
