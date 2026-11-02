"""Direct cases for the Phase 9 isolated live harness entry points.

Each harness is driven with its lab, database and Git dependencies replaced, so the test proves the evidence record the
harness writes (ephemeral database, pinned source hashes, restoration) and its refusals without touching a lab.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase


REPO_ROOT = Path(__file__).resolve().parents[3]


def load_harness(lab: str):
    path = REPO_ROOT / "labs" / lab / "run.py"
    spec = importlib.util.spec_from_file_location(f"nmas_{lab.replace('-', '_')}_run", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fake_root(directory: str, paths) -> Path:
    root = Path(directory)
    for name in paths:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("safe fixture\n")
    return root


def supported_cell(feature: str = "") -> SimpleNamespace:
    return SimpleNamespace(feature=feature, probes={"renderer": {"outcome": "PASS"}}, complete=True, status="SUPPORTED",
                           as_dict=lambda: {"feature": feature, "status": "SUPPORTED"})


class CeosAcl6HarnessTests(SimpleTestCase):
    def setUp(self):
        self.module = load_harness("phase9-ceos-acl6-isolated")

    def run_main(self, root: Path, *, restored: bool = True, password: str = "unit-test-placeholder"):
        module = self.module
        lab = mock.Mock()
        lab.close.return_value = restored
        cells = [supported_cell(key) for key in module.KEYS]
        environment = {"NMAS_CAP_CEOS_PASSWORD": password} if password else {}
        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.dict(module.settings.DATABASES["default"], {}, clear=False), \
                mock.patch.object(module, "ROOT", root), \
                mock.patch.object(module.subprocess, "check_output", return_value="revision\n"), \
                mock.patch.object(module, "call_command"), \
                mock.patch.object(module, "verify_cell", side_effect=cells), \
                mock.patch.object(module, "CeosServiceLab", return_value=lab), \
                mock.patch.object(module, "probe_cell") as probe, \
                mock.patch.object(module.phase9_ledger, "stages_for", return_value={"live": True}), \
                mock.patch("builtins.print"):
            module.main()
        return probe, lab

    def test_acl6_harness_main_positive_writes_ephemeral_restored_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = fake_root(directory, self.module.SOURCE)
            probe, lab = self.run_main(root)
            evidence = json.loads((root / "docs/evidence/v2-phase9-closure/ceos-acl6/assessment.json").read_text())
        self.assertEqual(probe.call_count, 3)
        lab.close.assert_called_once_with()
        self.assertTrue(evidence["ephemeral_database"])
        self.assertTrue(evidence["fixture_restored"])
        self.assertEqual(evidence["repository_head"], "revision")
        self.assertEqual(set(evidence["uncommitted_source_sha256"]), set(self.module.SOURCE))
        self.assertEqual([cell["feature"] for cell in evidence["assessments"]], list(self.module.KEYS))

    def test_acl6_harness_main_refuses_a_missing_secret_and_an_unrestored_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = fake_root(directory, self.module.SOURCE)
            with self.assertRaisesRegex(SystemExit, "NMAS_CAP_CEOS_PASSWORD"):
                self.run_main(root, password="")
            with self.assertRaisesRegex(RuntimeError, "restore the baseline"):
                self.run_main(root, restored=False)
            self.assertFalse((root / "docs/evidence/v2-phase9-closure/ceos-acl6/assessment.json").exists())


class SrLinuxHarnessTests(SimpleTestCase):
    SOURCES = (
        "web/core/services/capabilities/batch_srlinux_phase9.py", "web/core/services/capabilities/batch_srlinux.py",
        "web/core/services/capabilities/offline_verify.py", "web/core/services/config_import/parser_srlinux.py",
        "web/core/services/platform_drivers.py", "web/core/services/planning/configlet_factory.py",
        "web/core/services/srlinux_model.py", "web/core/services/execution/executors/srlinux.py",
        "web/core/services/execution/writers/srlinux_gnmi.py", "web/core/services/health/live.py",
        "web/core/services/health/routing_config.py", "templates/features/srlinux/acl_ipv4.j2",
        "templates/features/srlinux/acl_ipv6.j2", "templates/features/srlinux/routing_ospfv2.j2",
        "templates/features/srlinux/routing_ospfv3.j2",
    )

    def setUp(self):
        self.module = load_harness("phase9-srlinux-isolated")

    def run_main(self, root: Path, cell, *, password: str = "unit-test-placeholder"):
        module = self.module
        environment = {"NMAS_CAP_SRL_PASSWORD": password} if password else {}
        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(sys, "argv", ["run.py", "routing.OSPFV2"]), \
                mock.patch.dict(module.settings.DATABASES["default"], {}, clear=False), \
                mock.patch.object(module, "ROOT", root), \
                mock.patch.object(module.subprocess, "check_output", return_value="revision\n"), \
                mock.patch.object(module, "call_command"), \
                mock.patch.object(module, "verify_cell", return_value=cell), \
                mock.patch.object(module, "probe_srlinux_phase9", return_value={"pristine": {"restored": True}}) as probe, \
                mock.patch("builtins.print"):
            module.main()
        return probe

    def test_srlinux_harness_main_positive_writes_one_record_per_cell(self):
        with tempfile.TemporaryDirectory() as directory:
            root = fake_root(directory, self.SOURCES)
            probe = self.run_main(root, supported_cell("routing.OSPFV2"))
            evidence = json.loads((root / "docs/evidence/v2-phase9-closure/srlinux/routing-OSPFV2.json").read_text())
        probe.assert_called_once()
        self.assertTrue(evidence["ephemeral_database"])
        self.assertEqual(evidence["repository_head"], "revision")
        self.assertEqual(set(evidence["uncommitted_source_sha256"]), set(self.SOURCES))
        self.assertEqual(evidence["scenarios"], {"pristine": {"restored": True}})

    def test_srlinux_harness_main_refuses_a_missing_secret_and_skips_an_offline_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = fake_root(directory, self.SOURCES)
            with self.assertRaisesRegex(SystemExit, "NMAS_CAP_SRL_PASSWORD"):
                self.run_main(root, supported_cell("routing.OSPFV2"), password="")
            failed = SimpleNamespace(probes={"renderer": {"outcome": "FAIL"}}, complete=False, status="NOT_IMPLEMENTED",
                                     as_dict=lambda: {})
            probe = self.run_main(root, failed)
            probe.assert_not_called()
            self.assertFalse((root / "docs/evidence/v2-phase9-closure/srlinux/routing-OSPFV2.json").exists())
