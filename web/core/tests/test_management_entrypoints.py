"""Regression coverage for the real Django command-line entry point."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile

from django.test import SimpleTestCase


REPO_ROOT = Path(__file__).resolve().parents[3]
MANAGE_PY = REPO_ROOT / "web" / "manage.py"
PHASE23_COMMANDS = (
    "import_device_credential",
    "reconcile_device_credential",
    "rotate_due_credentials",
    "enroll_service_ssh_key",
    "register_operator_ssh_key",
    "prepare_r1_mfa_rollout_metadata",
    "prepare_ceos_mfa_rollout_metadata",
    "render_device_mfa_candidate",
    "verify_device_mfa",
    "r1_mfa_pilot",
    "ceos_mfa_rollout",
)


class ManagePyEntrypointTests(SimpleTestCase):
    @staticmethod
    def _environment() -> dict[str, str]:
        # Deliberately construct a minimal environment rather than inheriting
        # PYTHONPATH (or any runtime credentials) from the test runner.
        return {
            "DJANGO_DEBUG": "true",
            "PATH": os.environ.get("PATH", ""),
        }

    def _help(self, command: str, *, cwd: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(MANAGE_PY), command, "--no-color", "--help"],
            cwd=cwd,
            env=self._environment(),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def test_all_phase23_commands_load_through_manage_py_without_pythonpath(self):
        for command in PHASE23_COMMANDS:
            with self.subTest(command=command):
                completed = self._help(command, cwd=REPO_ROOT)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn(command, completed.stdout)
                self.assertNotIn("ModuleNotFoundError", completed.stderr)

    def test_repository_import_bootstrap_does_not_depend_on_caller_cwd(self):
        with tempfile.TemporaryDirectory(prefix="manage-entrypoint-") as directory:
            completed = self._help("import_device_credential", cwd=Path(directory))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("import_device_credential", completed.stdout)
