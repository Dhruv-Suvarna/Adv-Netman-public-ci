"""Lab 7 closure -- the Raw Configlet verifier self-test command, with the verifier and the container runtime replaced.

``verify_raw_configlet`` and ``sandbox.run_process`` are patched: no container is started, no image is pulled and no
device exists.  POSITIVE: a PASS for the valid sample, BLOCKED for the invalid one and a clean runtime exit 0 with
RESULT: PASS.  NEGATIVE: a sandbox that cannot complete exits 2 (INCOMPLETE, never faked), and a leftover container or
an accepted invalid snippet exits 1; an unknown platform is refused by the parser.
"""

from __future__ import annotations

import io
from types import SimpleNamespace
from unittest import mock

from django.core.management import CommandError, call_command
from django.test import SimpleTestCase

from core.management.commands import raw_verifier_selftest as selftest


def outcome(result, *codes):
    return SimpleNamespace(result=result, findings=[{"code": c} for c in codes], provenance={"backend": "fake"},
                           evidence={"sandbox": {"started": True, "privileged": False, "network": "none", "cleanup": "REMOVED"}})


def runtime(output="", returncode=0, error=""):
    return SimpleNamespace(output=output, returncode=returncode, error=error)


class RawVerifierSelftestTests(SimpleTestCase):
    def run_command(self, results, leftover):
        out = io.StringIO()
        with mock.patch.object(selftest.verifier, "verify_raw_configlet", side_effect=results) as verify, \
                mock.patch.object(selftest.sandbox, "run_process", return_value=leftover) as process, \
                self.assertRaises(SystemExit) as stopped:
            call_command("raw_verifier_selftest", "--platform", "ubuntu_frr", stdout=out)
        return stopped.exception.code, out.getvalue(), verify, process

    def test_selftest_passes_a_valid_and_blocks_an_invalid_sample(self):
        code, out, verify, process = self.run_command([outcome("PASS"), outcome("BLOCKED", "RAW_PARSER_REJECTED")], runtime())
        self.assertEqual(code, 0)
        self.assertEqual(out.splitlines()[-2:], ["sandbox containers remaining after the run: 0", "RESULT: PASS"])
        self.assertEqual([call.args[0].content for call in verify.call_args_list], [selftest.text_module.normalize(s) for s in selftest.SAMPLES["ubuntu_frr"]])
        self.assertEqual(process.call_args.args[0][1:], ["ps", "-a", "-q", "--filter", "name=^/clab-rawverify-"])

    def test_selftest_refuses_an_incomplete_sandbox_a_leftover_container_or_an_accepted_invalid_snippet(self):
        for name, results, leftover, expected in (
                ("incomplete", [outcome("INCOMPLETE"), outcome("INCOMPLETE")], runtime(), (2, "RESULT: INCOMPLETE")),
                ("leftover", [outcome("PASS"), outcome("BLOCKED")], runtime(output="abc123\n"), (1, "RESULT: FAIL")),
                ("unknown runtime", [outcome("PASS"), outcome("BLOCKED")], runtime(returncode=1, error="docker missing"), (1, "RESULT: FAIL")),
                ("invalid let through", [outcome("PASS"), outcome("PASS")], runtime(), (1, "RESULT: FAIL"))):
            with self.subTest(case=f"refused {name}"):
                code, out, _verify, _process = self.run_command(results, leftover)
                self.assertEqual((code, out.splitlines()[-1].split(" (")[0]), expected)

    def test_selftest_refuses_an_unknown_platform(self):
        with self.assertRaises(CommandError):
            call_command("raw_verifier_selftest", "--platform", "cisco_iosxe")
