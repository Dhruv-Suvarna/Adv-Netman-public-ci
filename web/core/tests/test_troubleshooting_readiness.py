"""Troubleshooting operational readiness (services/troubleshooting/readiness.py, manage.py troubleshooting_readiness).

RDY-* tests run the readiness report over the real lifecycle registry (devices adopted through ``adopt_existing``) and the real
``DeploymentAdmission``.  They prove the report never admits more than the runtime, lists every blocker with its corrective action,
and contacts nothing and writes nothing.
"""

from __future__ import annotations

import io
import json
from unittest import mock

from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from core import models
from core.services.devices import lifecycle as device_lifecycle
from core.services.troubleshooting import readiness

P = "core.services.troubleshooting.adapters.nmas_providers"
T = "core.tests.test_troubleshooting_readiness"
NMAS = {"inventory": f"{P}.inventory", "lifecycle_provider": f"{P}.lifecycle"}
OPERATOR = "nmas-test-operator"
VERIFIED = {"identity_state": models.IdentityVerificationState.VERIFIED, "identity_verified_by": OPERATOR,
            "identity_verified_at": timezone.now(), "verified_serial": "TESTSERIAL01"}


def version_stub(device, entry):   # stand-in for the missing authoritative version record (only used to reach later gates)
    return "4.36.2F"


def adopt(name="R1"):
    result = device_lifecycle.adopt_existing(name, role="router", actor=OPERATOR)
    assert result.ok, result
    return models.ManagedDevice.objects.get(name=name)


def set_row(row, **fields):
    fresh = models.ManagedDevice.objects.get(pk=row.pk)
    assert models.ManagedDevice.objects.compare_and_swap(fresh.pk, fresh.version, **fields) == 1


def codes(row):
    return [b["code"] for b in row["blockers"]]


def by_device(report):
    return {r["device"]: r for r in report["devices"]}


class ReadinessTests(TestCase):
    def setUp(self):
        for cls in ("EosSession", "LinuxSession", "DockerEosSession", "SrLinuxSession", "IosXeSession"):
            patcher = mock.patch(f"core.services.health.live.{cls}", side_effect=AssertionError("no device may be contacted"))
            patcher.start()
            self.addCleanup(patcher.stop)

    @override_settings(NMAS_TS_DEPLOYMENT={})
    def test_RDY01_unbound_deployment_refuses_every_device_and_names_both_missing_providers(self):
        rows = by_device(readiness.device_readiness())
        self.assertIn("R1", rows)
        for row in rows.values():
            self.assertFalse(row["admitted"])
            self.assertEqual(row["admission"], "LIFECYCLE_UNKNOWN")
            self.assertEqual(codes(row)[:2], ["LIFECYCLE_PROVIDER_UNBOUND", "VERSION_PROVIDER_UNBOUND"])
            self.assertTrue(row["consistent"])

    def test_RDY02_unregistered_adoptable_device_points_to_adopt_existing(self):
        row = by_device(readiness.device_readiness(NMAS, ["R1"]))["R1"]
        self.assertEqual(row["admission"], "UNREGISTERED")
        self.assertEqual(codes(row), ["UNREGISTERED", "VERSION_PROVIDER_UNBOUND"])
        self.assertIn("Adopt Existing Device", row["blockers"][0]["action"])
        self.assertFalse(models.ManagedDevice.objects.filter(name="R1").exists(), "readiness must never adopt a device")

    def test_RDY03_r5_is_not_adoptable_and_has_no_management_address(self):
        row = by_device(readiness.device_readiness(NMAS, ["R5"]))["R5"]
        self.assertEqual(row["admission"], "UNREGISTERED")
        self.assertEqual(row["blockers"][0]["code"], "NOT_ADOPTABLE")
        self.assertEqual(row["blockers"][0]["detail"], "OUT_OF_WRITABLE_SCOPE")
        self.assertEqual([w["code"] for w in row["warnings"]], ["NO_MANAGEMENT_ADDRESS"])

    def test_RDY04_adopted_device_reports_identity_gap_and_missing_producer(self):
        adopt()
        row = by_device(readiness.device_readiness(NMAS, ["R1"]))["R1"]
        self.assertEqual(row["admission"], "IDENTITY_UNVERIFIED")
        self.assertEqual((row["lifecycle_state"], row["production_admission"]), ("IN_SERVICE", "LEGACY_PREEXISTING"))
        self.assertEqual(codes(row), ["IDENTITY_UNVERIFIED", "IDENTITY_NO_PRODUCER", "VERSION_PROVIDER_UNBOUND"])
        producer = next(b for b in row["blockers"] if b["code"] == "IDENTITY_NO_PRODUCER")
        self.assertEqual(producer["owner"], "operator")              # the deployed device_observe workflow is the producer
        self.assertIn("device_observe", producer["action"])

    def test_RDY05_authenticated_session_observation_removes_only_the_producer_blocker(self):
        row = adopt()
        result = device_lifecycle.record_observation(row, kind=models.ObservationKind.IDENTITY,
                                                     source=models.ObservationSource.AUTHENTICATED_SESSION, actor=OPERATOR,
                                                     claims={"host_key": "SHA256:" + "A" * 43})
        self.assertTrue(result.ok, result)
        rep = by_device(readiness.device_readiness(NMAS, ["R1"]))["R1"]
        self.assertEqual(codes(rep), ["IDENTITY_UNVERIFIED", "VERSION_PROVIDER_UNBOUND"])
        self.assertEqual(models.ManagedDevice.objects.get(name="R1").identity_state, models.IdentityVerificationState.UNVERIFIED,
                         "readiness must never verify identity")

    def test_RDY06_verified_device_without_version_is_refused_with_version_blocker_only(self):
        set_row(adopt(), **VERIFIED)
        row = by_device(readiness.device_readiness(NMAS, ["R1"]))["R1"]
        self.assertEqual((row["admission"], codes(row)), ("VERSION_UNKNOWN", ["VERSION_PROVIDER_UNBOUND"]))
        self.assertTrue(row["consistent"])

    def test_RDY07_all_gates_satisfied_is_admitted_and_report_agrees_with_runtime(self):
        set_row(adopt(), **VERIFIED)
        row = by_device(readiness.device_readiness({**NMAS, "version_provider": f"{T}.version_stub"}, ["R1"]))["R1"]
        self.assertEqual((row["admission"], row["admitted"], row["os_version"], row["blockers"]), ("VERIFIED", True, "4.36.2F", []))
        self.assertTrue(row["consistent"])

    def test_RDY08_withdrawn_and_mismatch_are_never_reported_as_fixable_by_override(self):
        row = adopt()
        set_row(row, identity_state=models.IdentityVerificationState.MISMATCH)
        rep = by_device(readiness.device_readiness(NMAS, ["R1"]))["R1"]
        self.assertEqual(codes(rep)[0], "IDENTITY_MISMATCH")
        self.assertIn("never override", rep["blockers"][0]["action"])
        set_row(row, **VERIFIED, admission_state=models.ProductionAdmissionState.WITHDRAWN)
        rep = by_device(readiness.device_readiness(NMAS, ["R1"]))["R1"]
        self.assertEqual((rep["admission"], codes(rep)[0]), ("WITHDRAWN", "WITHDRAWN"))

    def test_RDY09_runbooks_need_bindings_and_an_admitted_device_rb07_needs_hardware(self):
        rbs = {r["runbook"]: r for r in readiness.runbook_readiness(readiness.device_readiness(NMAS))}
        self.assertEqual(sorted(rbs), [f"RB0{i}" for i in range(1, 8)])
        self.assertEqual(rbs["RB07"]["status"], "EXTERNALLY_BLOCKED_HARDWARE")
        for rb in ("RB01", "RB02", "RB03", "RB04", "RB05", "RB06"):
            self.assertEqual(rbs[rb]["status"], "NOT_READY")
            self.assertTrue(rbs[rb]["missing_bindings"])
        fake = {"sources": {k: True for k in readiness.SOURCE_BINDINGS.values()} | {"baseline_sources_provider": True},
                "devices": [{"device": "R1", "admitted": False}]}
        self.assertEqual(readiness.runbook_readiness(fake)[4]["status"], "NOT_READY", "bindings without an admitted device are not ready")
        fake["devices"][0]["admitted"] = True
        self.assertEqual(readiness.runbook_readiness(fake)[4]["status"], "READY_PENDING_FIXTURE_APPROVAL")

    def test_RDY10_runbook_requirements_name_only_real_deployment_keys(self):
        from core.services.troubleshooting import deployment as dep
        for req in readiness.RUNBOOK_REQUIREMENTS.values():
            for key in req["all"] + [k for group in req["any"] for k in group]:
                self.assertIn(key, dep._KEYS)          # pylint: disable=protected-access
        self.assertTrue(set(readiness.SOURCE_BINDINGS.values()) <= dep._KEYS)   # pylint: disable=protected-access

    def test_RDY11_failing_provider_is_a_blocker_not_a_crash(self):
        rows = by_device(readiness.device_readiness({**NMAS, "lifecycle_provider": f"{T}.boom"}, ["R1"]))
        self.assertFalse(rows["R1"]["admitted"])
        self.assertIn("LIFECYCLE_PROVIDER_UNBOUND", codes(rows["R1"]))
        self.assertTrue(any("lifecycle_provider" in p for p in readiness.device_readiness({**NMAS, "lifecycle_provider": f"{T}.boom"},
                                                                                           ["R1"])["deployment_problems"]))

    def test_RDY12_command_is_read_only_and_emits_json(self):
        before = (models.ManagedDevice.objects.count(), models.DeviceObservation.objects.count())
        out = io.StringIO()
        call_command("troubleshooting_readiness", "--json", "--with-nmas-providers", "--device", "R1", "--device", "R5", stdout=out)
        data = json.loads(out.getvalue())
        self.assertEqual(data["version"], readiness.REPORT_VERSION)
        self.assertEqual([d["device"] for d in data["devices"]], ["R1", "R5"])
        self.assertEqual(len(data["runbooks"]), 7)
        self.assertEqual((models.ManagedDevice.objects.count(), models.DeviceObservation.objects.count()), before)
        text = io.StringIO()
        call_command("troubleshooting_readiness", "--with-nmas-providers", "--device", "R1", stdout=text)
        self.assertIn("[UNREGISTERED]", text.getvalue())


class CaptureProvenanceTests(TestCase):
    """The gateway capture script must import the code of the worktree the gateway pinned, never another checkout."""

    def test_RDY13_capture_script_imports_only_its_own_worktree(self):
        import ast
        from pathlib import Path
        script = Path(__file__).resolve().parent / "fixtures" / "troubleshooting_collectors" / "capture_live.py"
        source = script.read_text()
        tree = ast.parse(source)
        inserted = [ast.unparse(node.args[1]) for node in ast.walk(tree) if isinstance(node, ast.Call)
                    and ast.unparse(node.func) == "sys.path.insert"]
        self.assertEqual(inserted, ["'/opt/ai-orchestrator/gateway/client'", "str(WEB_ROOT)"])
        self.assertNotIn("clab_dualstack_lab", source)
        web_root = script.resolve().parents[4]                 # the expression WEB_ROOT evaluates
        self.assertTrue((web_root / "manage.py").is_file())
        self.assertTrue((web_root / "core" / "services" / "troubleshooting" / "collectors.py").is_file())
