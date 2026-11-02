"""V2 Phase 1: the centralized redaction policy used by request / identity audit (core.services.secret_policy)."""

from django.test import RequestFactory, SimpleTestCase

from core.services import secret_policy
from core.services.identity import audit


class RedactionPolicyTests(SimpleTestCase):
    def test_secret_shaped_keys_are_redacted_recursively(self):
        data = {
            "username": "alice", "password": "p", "password_confirmation": "p", "new_password2": "p", "otp_code": "123456",
            "totp_secret": "S", "recovery_code": "r", "csrfmiddlewaretoken": "c", "sessionid": "s", "Authorization": "Bearer x",
            "cloudflare_api_token": "t", "radius_secret": "r", "private_key": "k", "api_key": "a", "device_credential": "d",
            "credential_ref": "runtime://device-credentials/r1", "protocol": "ospf", "nested": [{"seed": "x", "ok": 1}],
        }
        out = secret_policy.redact(data)
        for key in data:
            if key in ("username", "credential_ref", "protocol", "nested"):
                continue
            self.assertEqual(out[key], secret_policy.REDACTED, key)
        self.assertEqual((out["username"], out["credential_ref"], out["protocol"]), ("alice", "runtime://device-credentials/r1", "ospf"))
        self.assertEqual(out["nested"], [{"seed": secret_policy.REDACTED, "ok": 1}])

    def test_secret_value_formats_are_redacted_inside_strings(self):
        pem = "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nAAAA\n-----END " + "OPENSSH PRIVATE KEY-----"  # split: no literal key header in Git
        text = ("cfg " + pem + " tail "
                "Authorization: Bearer abcdefghijklmnop otpauth://totp/NMAS:alice?secret=JBSWY3DPEHPK3PXP")
        out = secret_policy.redact_text(text)
        for leaked in ("AAAA", "abcdefghijklmnop", "JBSWY3DPEHPK3PXP", "otpauth://"):
            self.assertNotIn(leaked, out)
        self.assertTrue(out.startswith("cfg "))

    def test_strings_are_bounded(self):
        self.assertTrue(secret_policy.redact("x" * 2000, max_string=100).endswith("...[truncated]"))

    def test_credential_headers_are_dropped(self):
        out = secret_policy.redact_headers({"Cookie": "a", "Authorization": "b", "Cf-Access-Jwt-Assertion": "c",
                                            "X-CSRFToken": "d", "User-Agent": "UA"})
        self.assertEqual(out, {"User-Agent": "UA"})

    def test_rejecting_policy_is_unchanged(self):
        # The pre-existing hard check keeps its exact behaviour (no new forbidden substrings were added to it).
        secret_policy.assert_no_secret_shaped_keys({"session_state": 1, "protocol": "x", "secret_ref": "r"})
        with self.assertRaises(ValueError):
            secret_policy.assert_no_secret_shaped_keys({"password": "x"})

    def test_request_details_never_contain_values(self):
        request = RequestFactory().post("/accounts/login/?next=/x&token=abc", {
            "username": "alice", "password": "hunter2-secret", "otp_code": "123456", "csrfmiddlewaretoken": "zzz",
        })
        details = audit.request_details(request)
        self.assertEqual(details["fields"], ["username"])
        self.assertEqual(details["redacted_fields"], 3)
        self.assertEqual(details["query"]["token"], secret_policy.REDACTED)
        for leaked in ("hunter2-secret", "123456", "zzz", "abc"):
            self.assertNotIn(leaked, str(details))
