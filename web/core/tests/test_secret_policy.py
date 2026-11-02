from django.test import TestCase

from core.services import secret_policy


class SecretShapedKeyRejectionTests(TestCase):
    def test_forbidden_substrings_rejected(self):
        for term in secret_policy.FORBIDDEN_METADATA_KEY_SUBSTRINGS:
            with self.subTest(term=term):
                with self.assertRaises(ValueError):
                    secret_policy.assert_no_secret_shaped_keys({f"device_{term}": "x"})

    def test_raw_password_key_rejected(self):
        with self.assertRaises(ValueError):
            secret_policy.assert_no_secret_shaped_keys({"password": "hunter2"})

    def test_raw_token_key_rejected(self):
        with self.assertRaises(ValueError):
            secret_policy.assert_no_secret_shaped_keys({"api_token": "abc123"})

    def test_nested_dict_is_checked(self):
        with self.assertRaises(ValueError):
            secret_policy.assert_no_secret_shaped_keys({"interfaces": {"Ethernet1": {"secret": "x"}}})

    def test_list_of_dicts_is_checked(self):
        with self.assertRaises(ValueError):
            secret_policy.assert_no_secret_shaped_keys({"items": [{"ok": 1}, {"webhook_url": "x"}]})

    def test_ref_suffixed_keys_are_exempt(self):
        data = {"secret_ref": "device/R1/admin", "credential_ref": "vault://x", "priv_key_ref": "vault://y"}
        result = secret_policy.assert_no_secret_shaped_keys(data)
        self.assertEqual(result, data)

    def test_safe_keys_allowed(self):
        data = {"device": "R5", "affected_feature": "ecmp", "candidate_iteration": 2}
        result = secret_policy.assert_no_secret_shaped_keys(data)
        self.assertEqual(result, data)
