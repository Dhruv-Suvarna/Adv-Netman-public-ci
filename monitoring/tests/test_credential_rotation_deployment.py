import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALLER = REPO_ROOT / "monitoring" / "scripts" / "install_credential_rotation_timer.sh"
TEMPLATE = REPO_ROOT / "monitoring" / "config" / "nmas-credential-rotation.service.in"
DEPLOYMENT_ROOT = Path("/home/student/Scripts/clab_dualstack_lab-deploy")
LEGACY_RUNTIME_ROOT = "/home/student/Scripts/clab_dualstack_lab/"
RUNTIME_ENV = REPO_ROOT / "monitoring" / "runtime" / "credential-rotation.env"


class CredentialRotationDeploymentTests(unittest.TestCase):
    def _installer(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(INSTALLER), *args],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

    def _render(self, output: Path) -> str:
        completed = self._installer("--render-only", str(output))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return output.read_text()

    def test_installer_rejects_every_noncanonical_worktree_without_creating_runtime_secret(self):
        existed_before = RUNTIME_ENV.exists()
        completed = self._installer()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("non-canonical checkout", completed.stderr)

        for checkout in (Path("/home/student/Scripts/clab_dualstack_lab"),
                         Path("/home/student/Scripts/clab_dualstack_lab-phase20_5")):
            with self.subTest(checkout=checkout):
                completed = self._installer("--check-root", str(checkout))
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("non-canonical checkout", completed.stderr)
        self.assertEqual(RUNTIME_ENV.exists(), existed_before)

    def test_installer_accepts_only_the_dedicated_deployment_root_shape(self):
        completed = self._installer("--check-root", str(DEPLOYMENT_ROOT))
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_rendered_unit_uses_only_absolute_dedicated_deployment_paths(self):
        with tempfile.TemporaryDirectory(prefix="credential-rotation-unit-") as directory:
            text = self._render(Path(directory) / "nmas-credential-rotation.service")

        root = str(DEPLOYMENT_ROOT)
        self.assertIn(f"WorkingDirectory={root}\n", text)
        self.assertIn(f"EnvironmentFile={root}/monitoring/runtime/credential-rotation.env\n", text)
        self.assertIn(
            f"ExecStart=/home/student/Scripts/.venv/bin/python {root}/web/manage.py rotate_due_credentials --json\n",
            text,
        )
        self.assertIn(f"ReadWritePaths={root}/monitoring/runtime {root}/web\n", text)
        self.assertNotIn(LEGACY_RUNTIME_ROOT, text)
        self.assertNotIn("@@DEPLOYMENT_ROOT@@", text)
        self.assertNotIn("PYTHONPATH", text)

    def test_sandboxing_is_preserved_and_template_has_no_fixed_checkout_path(self):
        template = TEMPLATE.read_text()
        for directive in (
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
        ):
            self.assertIn(directive, template)
        self.assertNotIn("/home/student/Scripts/clab_dualstack_lab", template)
        self.assertEqual(template.count("@@DEPLOYMENT_ROOT@@"), 5)

    def test_read_only_validation_modes_never_create_runtime_environment(self):
        existed_before = RUNTIME_ENV.exists()
        with tempfile.TemporaryDirectory(prefix="credential-rotation-unit-") as directory:
            output = Path(directory) / "unit.service"
            self.assertEqual(self._installer("--render-only", str(output)).returncode, 0)
            self.assertTrue(output.is_file())
        self.assertEqual(RUNTIME_ENV.exists(), existed_before)


if __name__ == "__main__":
    unittest.main()
