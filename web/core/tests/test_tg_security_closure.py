"""Lab 7 closure -- website identity: audit helpers, request context, MFA seed / reset / failures, RBAC presentation,
the audit signals, the account-security pages and the two administrative commands, each called directly.

Everything runs against the test database with a RequestFactory or a signed-in test client; no password, seed or OTP
is printed, and no network-device credential or MFA is touched.  POSITIVE: the exact principal, address, fingerprint,
stamp, throttle verdict and role grant.  NEGATIVE: anonymous actors, malformed or untrusted addresses, invalid seeds,
missing users, unconfirmed resets and mismatched passwords are refused -- and a secret never reaches the ledger.
"""

from __future__ import annotations

import hashlib
from unittest import mock

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.management import CommandError, call_command
from django.test import Client, RequestFactory, TestCase, override_settings
from django.urls import reverse

from core import models, signals
from core.services.identity import audit, context as audit_context, mfa, policy
from core.services.identity.policy import Action
from core.tests import test_identity_access as ia
from core.tests.runner import make_test_operator, sign_in

SEED = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def request_with(**meta):
    return RequestFactory().get("/", **meta)


@override_settings(NMAS_TRUSTED_PROXY_IPS=("127.0.0.1",))
class RequestIdentityTests(TestCase):
    def test_source_ip_of_a_direct_peer_and_through_a_trusted_proxy(self):
        self.assertEqual(audit.source_ip(request_with(REMOTE_ADDR="10.1.2.3")), "10.1.2.3")
        self.assertEqual(audit.source_ip(request_with(REMOTE_ADDR="127.0.0.1", HTTP_X_FORWARDED_FOR="203.0.113.5, 10.0.0.1")), "203.0.113.5")

    def test_source_ip_never_trusts_forwarded_for_from_an_untrusted_peer_or_a_malformed_address(self):
        self.assertEqual(audit.source_ip(request_with(REMOTE_ADDR="10.1.2.3", HTTP_X_FORWARDED_FOR="203.0.113.5")), "10.1.2.3")
        self.assertIsNone(audit.source_ip(request_with(REMOTE_ADDR="not-an-ip")))
        self.assertIsNone(audit.source_ip(request_with(REMOTE_ADDR="127.0.0.1", HTTP_X_FORWARDED_FOR="evil<script>")))

    def test_session_fingerprint_is_a_truncated_digest_of_the_session_key(self):
        request = request_with()
        request.session = mock.Mock(session_key="abc123")
        self.assertEqual(audit.session_fingerprint(request), hashlib.sha256(f"{settings.SECRET_KEY}:abc123".encode()).hexdigest()[:16])
        self.assertNotIn("abc123", audit.session_fingerprint(request))

    def test_session_fingerprint_without_a_session_is_empty(self):
        self.assertEqual(audit.session_fingerprint(request_with()), "")
        request = request_with()
        request.session = mock.Mock(session_key=None)
        self.assertEqual(audit.session_fingerprint(request), "")

    def test_username_of_and_actor_for_an_authenticated_user(self):
        user = make_test_operator("ida")
        request = request_with()
        request.user = user
        self.assertEqual((audit.username_of(user), audit.actor_for(request)), ("ida", "ida"))

    def test_username_of_and_actor_for_an_anonymous_or_missing_user_are_refused(self):
        self.assertEqual((audit.username_of(AnonymousUser()), audit.username_of(None)), ("", ""))
        request = request_with()
        request.user = AnonymousUser()
        with self.assertRaises(PermissionError):
            audit.actor_for(request)
        with self.assertRaises(PermissionError):
            audit.actor_for(request_with())

    def failures(self, count, *, username="eve", ip="198.51.100.7"):
        for _ in range(count):
            models.AuditEvent.objects.create(event_type=models.AuditEventType.AUTH_LOGIN_FAILED, summary="Login failed",
                                             metadata={"attempted_username": username}, source_ip=ip)

    def test_login_throttled_by_user_or_by_address_at_the_limit(self):
        self.failures(settings.NMAS_LOGIN_FAILURE_LIMIT)
        self.assertTrue(audit.login_throttled("EVE", None))
        self.failures(settings.NMAS_LOGIN_FAILURE_LIMIT * 2, username="other")
        self.assertTrue(audit.login_throttled("", "198.51.100.7"))

    def test_login_throttled_is_false_below_the_limit_or_without_a_username_and_address(self):
        self.failures(settings.NMAS_LOGIN_FAILURE_LIMIT - 1)
        self.assertFalse(audit.login_throttled("eve", "198.51.100.7"))
        self.assertFalse(audit.login_throttled("", None))
        self.assertFalse(audit.login_throttled("mallory", "203.0.113.1"))


class ContextAndSignalTests(TestCase):
    CTX = audit_context.RequestAuditContext("req-12345678", None, "ida", "POST", "core:home", "10.1.2.3", "agent")

    def test_current_returns_the_bound_context_until_reset(self):
        token = audit_context.bind(self.CTX)
        try:
            self.assertIs(audit_context.current(), self.CTX)
        finally:
            audit_context.reset(token)
        self.assertIsNone(audit_context.current())

    def test_stamp_request_context_copies_the_request_into_blank_fields(self):
        token = audit_context.bind(self.CTX)
        try:
            event = models.AuditEvent(event_type=models.AuditEventType.WEB_ACTION, summary="s", actor="explicit")
            signals.stamp_request_context(models.AuditEvent, event)
        finally:
            audit_context.reset(token)
        self.assertEqual((event.request_id, event.actor, event.http_method, event.route, event.source_ip, event.user_agent),
                         ("req-12345678", "explicit", "POST", "core:home", "10.1.2.3", "agent"))

    def test_stamp_request_context_without_a_request_or_for_a_saved_row_changes_nothing(self):
        event = models.AuditEvent(event_type=models.AuditEventType.WEB_ACTION, summary="s")
        signals.stamp_request_context(models.AuditEvent, event)
        self.assertEqual((event.request_id, event.actor, event.route, event.source_ip), ("", "", "", None))
        saved = models.AuditEvent.objects.create(event_type=models.AuditEventType.WEB_ACTION, summary="s")
        token = audit_context.bind(self.CTX)
        try:
            signals.stamp_request_context(models.AuditEvent, saved)
        finally:
            audit_context.reset(token)
        self.assertEqual(saved.request_id, "")

    def test_audit_login_failure_records_the_lowercased_username_only(self):
        with self.subTest(case="records the lowercased username ok"):
            signals.audit_login_failure(None, {"username": "Eve", "password": "hunter2-pw"}, request=request_with(REMOTE_ADDR="10.1.2.3"))
        event = models.AuditEvent.objects.get(event_type=models.AuditEventType.AUTH_LOGIN_FAILED)
        self.assertEqual((event.actor, event.metadata, event.outcome, event.source_ip), ("Eve", {"attempted_username": "eve"}, audit.OUTCOME_FAILURE, "10.1.2.3"))
        self.assertNotIn("hunter2-pw", str(list(models.AuditEvent.objects.values())))

    def test_audit_login_failure_without_credentials_or_request_is_still_recorded_empty(self):
        signals.audit_login_failure(None, None)
        event = models.AuditEvent.objects.get(event_type=models.AuditEventType.AUTH_LOGIN_FAILED)
        self.assertEqual((event.actor, event.metadata, event.source_ip), ("", {"attempted_username": ""}, None))


class MfaAndPolicyTests(TestCase):
    def test_validate_seed_returns_a_well_formed_seed(self):
        self.assertEqual(mfa.validate_seed(SEED), SEED)

    def test_validate_seed_refuses_malformed_seeds_never_echoing_them(self):
        for name, seed in (("short", SEED[:-1]), ("lowercase", SEED.lower()), ("padding", SEED[:-1] + "="), ("none", None), ("digits 0189", "0189" + SEED[4:])):
            with self.subTest(case=f"invalid {name}"), self.assertRaises(mfa.MfaError) as caught:
                mfa.validate_seed(seed)
            self.assertNotIn(str(seed), str(caught.exception))

    def test_register_failure_counts_per_session(self):
        session = {}
        with self.subTest(case="counts per session ok"):
            self.assertEqual((mfa.register_failure(session), mfa.register_failure(session)), (1, 2))
        self.assertEqual(session[mfa.SESSION_FAILURES_KEY], 2)

    def test_reset_of_a_user_without_an_authenticator_removes_nothing(self):
        user = ia.make_user("nobody-enrolled")
        other = ia.make_user("enrolled")
        ia.enroll(other)
        self.assertFalse(mfa.reset(user))
        self.assertEqual(models.AppMfaDevice.objects.filter(user=other).count(), 1)

    def test_user_actions_lists_every_granted_action(self):
        actions = policy.user_actions(make_test_operator("all-actions"))
        self.assertEqual(actions, {a.value.removeprefix("nmas_"): True for a in Action})

    def test_user_actions_of_a_user_without_roles_or_anonymous_are_all_false(self):
        expected = {a.value.removeprefix("nmas_"): False for a in Action}
        self.assertEqual(policy.user_actions(ia.make_user("no-roles")), expected)
        self.assertEqual(policy.user_actions(AnonymousUser()), expected)


class AccountPageTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = ia.make_user("bob", "NMAS Operator")

    def test_mfa_status_shows_the_enrolled_authenticator_and_roles(self):
        ia.enroll(self.user)
        sign_in(self.client, self.user)
        page = self.client.get(reverse("core:mfa_status"))
        self.assertEqual((page.status_code, page.context["device"].user, page.context["groups"]), (200, self.user, ["NMAS Operator"]))

    def test_mfa_status_of_an_unenrolled_user_has_no_device(self):
        sign_in(self.client, self.user)
        page = self.client.get(reverse("core:mfa_status"))
        self.assertIsNone(page.context["device"])
        self.assertFalse(page.context["actions"]["execute"])

    def test_mfa_enroll_and_verify_refuse_the_wrong_step(self):
        sign_in(self.client, self.user, mfa_verified=False)
        self.assertEqual(self.client.get(reverse("core:mfa_verify") + "?next=/nsot/")["Location"], f"{reverse('core:mfa_enroll')}?next=/nsot/")
        ia.enroll(self.user)
        self.assertEqual(self.client.get(reverse("core:mfa_enroll"))["Location"], f"{reverse('core:mfa_verify')}?next=")

    def test_audit_log_filters_unknown_types_or_actors_to_an_empty_page(self):
        admin = ia.make_user("sam", "NMAS Security Admin")
        sign_in(self.client, admin)
        models.AuditEvent.objects.create(event_type=models.AuditEventType.WEB_ACTION, summary="x", actor="sam")
        self.assertEqual(list(self.client.get(reverse("core:audit_log"), {"type": "NOT_A_TYPE"}).context["events"]), [])
        self.assertEqual(list(self.client.get(reverse("core:audit_log"), {"actor": "nobody-at-all"}).context["events"]), [])


class AdminCommandTests(TestCase):
    def test_grant_roles_creates_a_user_with_every_role(self):
        with mock.patch("getpass.getpass", side_effect=["S3cure-pass-phrase-77", "S3cure-pass-phrase-77"]):
            call_command("nmas_grant_roles", "--username", "newbie", "--all-roles", "--create", stdout=mock.MagicMock())
        user = get_user_model().objects.get(username="newbie")
        self.assertEqual(sorted(user.groups.values_list("name", flat=True)), sorted(policy.ROLE_PERMISSIONS))
        self.assertTrue(user.check_password("S3cure-pass-phrase-77"))
        event = models.AuditEvent.objects.get(event_type=models.AuditEventType.WEB_ACTION, object_id=str(user.pk))
        self.assertNotIn("S3cure-pass-phrase-77", str(event.metadata) + event.summary)

    def test_grant_roles_refuses_a_missing_user_or_mismatched_passwords(self):
        with self.assertRaisesRegex(CommandError, "No NMAS user named 'ghost'"):
            call_command("nmas_grant_roles", "--username", "ghost", "--role", "NMAS Viewer")
        with mock.patch("getpass.getpass", side_effect=["a-Long-pass-1", "b-Long-pass-2"] * 3), self.assertRaisesRegex(CommandError, "No acceptable password"):
            call_command("nmas_grant_roles", "--username", "ghost", "--create", stderr=mock.MagicMock())
        self.assertFalse(get_user_model().objects.filter(username="ghost").exists())

    def test_mfa_reset_refuses_without_confirm_or_for_an_unknown_user(self):
        user = ia.make_user("bob")
        ia.enroll(user)
        with self.assertRaisesRegex(CommandError, "Refusing without --confirm"):
            call_command("nmas_app_mfa_reset", "--username", "bob")
        with self.assertRaisesRegex(CommandError, "No NMAS user named 'ghost'"):
            call_command("nmas_app_mfa_reset", "--username", "ghost", "--confirm")
        self.assertEqual(models.AppMfaDevice.objects.filter(user=user).count(), 1)
