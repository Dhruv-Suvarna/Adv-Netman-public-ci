import json
import os
import tempfile
import unittest
from pathlib import Path

from modules import device_credentials
from modules.device_credentials import (
    FileSecretProvider,
    SecretConflict,
    SecretProviderError,
    load_ssh_private_key,
    make_reference,
    reference_key,
    ssh_auth_kwargs,
)


FAKE_SECRET = "TEST_ONLY_ROTATION_SECRET_NEVER_REAL"


class FileSecretProviderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "runtime" / "device-credentials.json"
        self.provider = FileSecretProvider(self.path)
        self.ref = make_reference("r1-dedicated")

    def tearDown(self):
        self.temp.cleanup()

    def test_initialization_is_mode_600_and_reference_only_is_safe_metadata(self):
        version = self.provider.initialize(self.ref, FAKE_SECRET)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.path.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.provider.current(self.ref).version, version)
        self.assertEqual(self.provider.current(self.ref).value, FAKE_SECRET)
        self.assertNotIn(FAKE_SECRET, self.ref)

    def test_stage_preserves_both_recovery_candidates_until_atomic_promotion(self):
        self.provider.initialize(self.ref, "old-test-value")
        old_version, new_version = self.provider.stage(self.ref, FAKE_SECRET)
        self.assertEqual([m.value for m in self.provider.candidates(self.ref)], ["old-test-value", FAKE_SECRET])
        self.assertEqual(self.provider.promote(self.ref, new_version), (old_version, new_version))
        self.assertEqual([m.value for m in self.provider.candidates(self.ref)], [FAKE_SECRET])
        self.assertNotIn("old-test-value", self.path.read_text())

    def test_pending_must_be_resolved_before_another_stage(self):
        self.provider.initialize(self.ref, "old-test-value")
        self.provider.stage(self.ref, FAKE_SECRET)
        with self.assertRaises(SecretConflict):
            self.provider.stage(self.ref, "another-test-value")

    def test_unsafe_file_permissions_and_symlinks_fail_closed(self):
        self.provider.initialize(self.ref, FAKE_SECRET)
        self.path.chmod(0o644)
        with self.assertRaises(SecretProviderError):
            self.provider.current(self.ref)
        self.path.chmod(0o600)
        link = self.path.parent / "link.json"
        link.symlink_to(self.path)
        with self.assertRaises(SecretProviderError):
            FileSecretProvider(link).current(self.ref)

    def test_store_shape_has_only_current_pending_and_opaque_version_metadata(self):
        self.provider.initialize(self.ref, FAKE_SECRET)
        data = json.loads(self.path.read_text())
        self.assertEqual(set(data), {"schema_version", "secrets"})
        self.assertEqual(set(data["secrets"]["r1-dedicated"]), {"current", "pending"})
        self.assertIsNone(data["secrets"]["r1-dedicated"]["pending"])

    def test_default_store_lives_in_a_dedicated_directory_never_the_shared_runtime_root(self):
        self.assertEqual(device_credentials.DEFAULT_STORE.parent.name, "device-credentials")
        self.assertEqual(device_credentials.DEFAULT_STORE.parent.parent.name, "runtime")

    def test_shared_parent_directory_is_not_re_permissioned(self):
        shared = Path(self.temp.name) / "shared-runtime"
        shared.mkdir(mode=0o775)
        shared.chmod(0o775)
        FileSecretProvider(shared / "device-credentials" / "store.json").initialize(self.ref, FAKE_SECRET)
        self.assertEqual(shared.stat().st_mode & 0o777, 0o775)
        self.assertEqual((shared / "device-credentials").stat().st_mode & 0o777, 0o700)

    def test_replace_is_refused_while_a_rotation_is_pending(self):
        self.provider.initialize(self.ref, "old-test-value")
        self.provider.stage(self.ref, FAKE_SECRET)
        self.assertTrue(self.provider.has_pending(self.ref))
        with self.assertRaises(SecretConflict):
            self.provider.initialize(self.ref, "operator-import", replace=True)

    def test_lock_file_is_private_and_holds_no_secret(self):
        self.provider.initialize(self.ref, FAKE_SECRET)
        lock = self.path.with_name(self.path.name + ".lock")
        self.assertEqual(lock.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(FAKE_SECRET, lock.read_text())

    def test_reference_keys_reject_traversal_and_foreign_schemes(self):
        for bad in ("runtime://device-credentials/../x", "runtime://device-credentials/a/b", "file:///etc/shadow",
                    "runtime://device-credentials/UPPER", "runtime://device-credentials/.hidden"):
            with self.assertRaises(SecretProviderError):
                reference_key(bad)

    def test_provider_errors_never_echo_values(self):
        self.provider.initialize(self.ref, FAKE_SECRET)
        with self.assertRaises(SecretProviderError) as caught:
            self.provider.promote(self.ref, "no-such-version")
        self.assertNotIn(FAKE_SECRET, str(caught.exception))

    def test_ssh_private_key_loads_in_memory_and_bad_records_fail_sanitized(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        pem = Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption(),
        ).decode()
        key_ref = make_reference("r1-automation-sshkey")
        self.provider.initialize(key_ref, pem)
        self.assertEqual(load_ssh_private_key(key_ref, path=self.path).get_name(), "ssh-ed25519")
        kwargs = ssh_auth_kwargs(key_ref, path=self.path)
        self.assertEqual((kwargs["use_keys"], kwargs["allow_agent"]), (True, False))
        self.assertEqual(ssh_auth_kwargs(None), {})

        self.provider.initialize(self.ref, FAKE_SECRET)
        with self.assertRaises(SecretProviderError) as caught:
            load_ssh_private_key(self.ref, path=self.path)
        self.assertNotIn(FAKE_SECRET, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
