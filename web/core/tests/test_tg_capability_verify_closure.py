"""Lab 7 closure -- the capability verifiers that sit next to a device: the reversible loopback verifier, the IOS XR
runtime-absence scan, the offline fixture sessions and the non-destructive verify entry point.

Every device-, Docker- and filesystem-facing call is replaced (inventory, executor, live read, ``subprocess.run``,
``IMAGE_ROOT``): nothing is written to a device and no container command runs.  POSITIVE: a proven create / read-back
/ removal is reported verified, an empty runtime scan classifies IOS XR fail-closed, fixture sessions serve exactly the
running configuration.  NEGATIVE: a foreign device or platform is refused before connecting, a missing read-back still
compensates every applied step, an unavailable Docker inventory or a present image is refused, and a fixture refuses
every other command.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase

from core.management.commands import nmas_capabilities
from core.services.capabilities import features, live_verify, offline_verify, runtime_scan
from core.services.execution.executors.base import APPLY

HEAD = "4adec06ef04161d01340a1b94e5e1b2440a7e37c"


class Read:
    def __init__(self, interfaces=(), addresses=None, reachable=True):
        self.live_reachable, self._facts = reachable, {"interfaces": {n: {} for n in interfaces}, "addresses": addresses or {}}

    def facts(self, key):
        return self._facts[key]


class FakeExecutor:
    def __init__(self):
        self.calls = []

    def connect(self):
        self.calls.append("connect")

    def assess(self, spec):
        self.calls.append(("assess", spec.cfg_id))
        return SimpleNamespace(action=APPLY, restorable=True)

    def apply(self, spec, _assessment):
        self.calls.append(("apply", spec.cfg_id))
        return SimpleNamespace(ok=True, error_code="")

    def compensate(self, spec, _assessment):
        self.calls.append(("compensate", spec.cfg_id))
        return SimpleNamespace(status="COMPENSATED")

    def close(self):
        self.calls.append("close")


class VerifyLoopbackTests(SimpleTestCase):
    def run_verifier(self, reads, platform="arista_ceos", device=None):
        executor = FakeExecutor()
        device = device or {"name": "R1", "platform": "ceos"}
        with mock.patch.object(live_verify.inventory, "get_managed_device", return_value=device), \
                mock.patch.object(live_verify, "executor_for", return_value=executor), \
                mock.patch.object(live_verify.live, "read_device", side_effect=reads):
            try:
                return live_verify.verify_loopback(platform), executor
            except RuntimeError as exc:
                return exc, executor

    def test_verify_loopback_proves_create_read_back_and_removal(self):
        found, executor = self.run_verifier([Read(), Read(["Loopback444"], {"Loopback444": ["198.18.44.1/32"]}), Read()])
        self.assertEqual(found, live_verify.LiveVerification("arista_ceos", "R1", "Loopback444", "198.18.44.1/32", True, True, True, True,
                                                             "R1: created/read back/removed Loopback444 198.18.44.1/32; final read proved absence."))
        self.assertEqual(executor.calls, ["connect", ("assess", "P4-LB-IF"), ("apply", "P4-LB-IF"), ("assess", "P4-LB-IP"), ("apply", "P4-LB-IP"),
                                          ("compensate", "P4-LB-IP"), ("compensate", "P4-LB-IF"), "close"])

    def test_verify_loopback_without_read_back_still_compensates_and_is_refused(self):
        found, executor = self.run_verifier([Read(), Read(), Read()])
        self.assertIsInstance(found, RuntimeError)
        self.assertEqual(executor.calls[-3:], [("compensate", "P4-LB-IP"), ("compensate", "P4-LB-IF"), "close"])
        present, untouched = self.run_verifier([Read(["Loopback444"]), Read()])
        self.assertEqual((str(present), [c for c in untouched.calls if c[0] in ("apply", "compensate")]), ("Temporary loopback is not safely absent before the run.", []))

    def test_verify_loopback_refuses_foreign_platforms_devices_and_inventory_mismatches(self):
        with self.assertRaisesRegex(ValueError, "limited to arista_ceos and ubuntu_frr"):
            live_verify.verify_loopback("nokia_srlinux")
        with self.assertRaisesRegex(ValueError, "restricted to managed target R1"):
            live_verify.verify_loopback("arista_ceos", device_name="R2")
        with mock.patch.object(live_verify.inventory, "get_managed_device", return_value={"name": "R1", "platform": "linux"}), \
                mock.patch.object(live_verify, "executor_for", side_effect=AssertionError("connected")), self.assertRaisesRegex(ValueError, "does not match"):
            live_verify.verify_loopback("arista_ceos")


class RuntimeScanTests(SimpleTestCase):
    def scan(self, *, returncode=0, stdout="", files=()):
        with tempfile.TemporaryDirectory() as root:
            for name in files:
                Path(root, name).write_text("x")
            with mock.patch.object(runtime_scan, "IMAGE_ROOT", Path(root)), \
                    mock.patch.object(runtime_scan.subprocess, "run", return_value=SimpleNamespace(returncode=returncode, stdout=stdout)) as run:
                try:
                    return runtime_scan.inspect_iosxr_runtime(), run
                except RuntimeError as exc:
                    return exc, run

    def test_inspect_iosxr_runtime_of_an_empty_inventory_returns_a_stamped_reference(self):
        found, run = self.scan(stdout="ceos:4.36.2F\nalpine:3.20\n")
        self.assertEqual((found["files"], found["docker_images"]), ([], []))
        self.assertRegex(found["reference"], r"^runtime:iosxr-artifact-scan/[0-9a-f]{16}$")
        self.assertEqual(run.call_args.args[0], ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"])

    def test_inspect_iosxr_runtime_refuses_an_unavailable_docker_inventory(self):
        found, _run = self.scan(returncode=1)
        self.assertEqual(str(found), "Docker image inventory was unavailable; runtime absence is not established.")


class RuntimeAbsenceTests(TestCase):
    def test_verify_unavailable_iosxr_returns_a_complete_classification_for_every_feature(self):
        with mock.patch.object(runtime_scan, "inspect_iosxr_runtime", return_value={"files": [], "docker_images": [], "reference": "runtime:iosxr-artifact-scan/0"}):
            cells = runtime_scan.verify_unavailable_iosxr(head=HEAD, actor="tester", record=False)
        self.assertEqual(len(cells), len(features.catalogue()))
        self.assertEqual({(c.platform, c.complete, c.status, c.probes["runtime_validation"]["reason"]) for c in cells},
                         {("cisco_iosxr", True, "UNSUPPORTED", "RUNTIME_IMAGE_UNAVAILABLE")})

    def test_verify_unavailable_iosxr_refuses_when_an_artifact_exists(self):
        with mock.patch.object(runtime_scan, "inspect_iosxr_runtime", return_value={"files": ["xrd.tar"], "docker_images": [], "reference": "r"}), \
                self.assertRaisesRegex(RuntimeError, "IOS XR artifact exists"):
            runtime_scan.verify_unavailable_iosxr(head=HEAD, actor="tester", record=False)


class OfflineFixtureAndCommandTests(TestCase):
    def test_fixture_sessions_serve_only_the_running_configuration(self):
        session, gnmi = offline_verify._FixtureConfigSession("hostname R1\n"), offline_verify._FixtureGnmi({"system": {}})
        self.assertEqual((session.send_command("show running-config"), session.send_command("show tcp brief")), ("hostname R1\n", ""))
        self.assertEqual(gnmi.get("/"), {"notification": [{"update": [{"path": None, "val": {"system": {}}}]}]})

    def test_fixture_sessions_refuse_every_other_command_or_path(self):
        session, gnmi = offline_verify._FixtureConfigSession("x"), offline_verify._FixtureGnmi({})
        for name, call in (("configure", lambda: session.send_command("configure terminal")), ("state", lambda: gnmi.get("/", datatype="state")),
                           ("subtree", lambda: gnmi.get("/interface"))):
            with self.subTest(case=f"refused {name}"), self.assertRaises(ValueError):
                call()

    def test_verify_non_destructive_passes_a_cell_whose_offline_layers_pass(self):
        with mock.patch.object(nmas_capabilities, "_head", return_value=HEAD):
            self.assertEqual(nmas_capabilities.verify_non_destructive("arista_ceos", "interface.LOOPBACK", "STATIC"),
                             (True, "Actual offline fixture probes passed for interface.LOOPBACK; live stages remain outstanding."))

    def test_verify_non_destructive_reports_each_failed_layer(self):
        with mock.patch.object(nmas_capabilities, "_head", return_value=HEAD):
            ok, detail = nmas_capabilities.verify_non_destructive("cisco_iosxr", "interface.LOOPBACK", "STATIC")
        self.assertFalse(ok)
        self.assertTrue(detail.startswith("executor: EXECUTOR_ABSENT — "), detail)
