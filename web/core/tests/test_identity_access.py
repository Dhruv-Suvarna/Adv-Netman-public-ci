"""V2 Phase 1: website authentication, MFA gate, RBAC and request audit -- the access boundary itself.

These tests use a PLAIN django.test.Client (never the runner's auto-signed-in OperatorClient), so every assertion is
about real enforcement.
"""

import ast
from pathlib import Path
from unittest import mock

import pyotp
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import Client, TestCase, override_settings
from django.urls import get_resolver, reverse

from core import models
from core.migrations import __path__ as MIGRATIONS_PATH
from core.services.identity import mfa, policy
from core.tests.runner import make_test_operator, sign_in

PASSWORD = "correct-horse-battery-9"


def make_user(username, *roles, password=PASSWORD, **extra):
    user = get_user_model().objects.create_user(username=username, password=password, **extra)
    for role in roles:
        user.groups.add(Group.objects.get(name=role))
    return get_user_model().objects.get(pk=user.pk)


def enroll(user):
    seed = pyotp.random_base32(32)
    models.AppMfaDevice.objects.create(user=user, encrypted_seed=mfa._encrypt(seed), confirmed_at="2026-10-01T00:00:00Z")
    return seed


def core_route_names():
    resolver = get_resolver()
    names = set()
    for pattern in resolver.url_patterns:
        if getattr(pattern, "namespace", None) == "core":
            names |= {p.name for p in pattern.url_patterns if p.name}
    return names


class PolicyContractTests(TestCase):
    def test_every_core_route_is_classified_exactly_once(self):
        buckets = [policy.PUBLIC_ROUTES, policy.MFA_PENDING_ROUTES, policy.READ_ROUTES, set(policy.MUTATION_ROUTES)]
        names = core_route_names()
        for name in names:
            hits = sum(name in b for b in buckets)
            self.assertEqual(hits, 1, f"{name!r} must be classified exactly once (found {hits})")
        for bucket in buckets:
            self.assertFalse(set(bucket) - names, f"policy names unknown routes: {set(bucket) - names}")

    def test_require_post_views_are_mutation_routes(self):
        tree = ast.parse(Path(__file__).resolve().parents[1].joinpath("views.py").read_text())
        post_only = {
            node.name for node in tree.body if isinstance(node, ast.FunctionDef)
            and any(getattr(d, "id", "") == "require_POST" for d in node.decorator_list)
        }
        resolver = get_resolver()
        core = next(p for p in resolver.url_patterns if getattr(p, "namespace", None) == "core")
        for pattern in core.url_patterns:
            if getattr(pattern.callback, "__name__", "") in post_only:
                self.assertIn(pattern.name, policy.MUTATION_ROUTES, f"POST-only view {pattern.name} needs a mutation action")

    def test_seeded_groups_match_policy(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("seed", Path(MIGRATIONS_PATH[0]) / "0019_v2_phase1_seed_nmas_roles.py")
        seed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(seed)
        self.assertEqual({k: tuple(v) for k, v in seed.ROLES.items()},
                         {k: tuple(a.value for a in v) for k, v in policy.ROLE_PERMISSIONS.items()})
        for name, actions in policy.ROLE_PERMISSIONS.items():
            perms = set(Group.objects.get(name=name).permissions.values_list("codename", flat=True))
            self.assertEqual(perms, {a.value for a in actions})

    def test_unknown_route_is_denied(self):
        self.assertEqual(policy.required_action("some_future_route", "GET"), (policy.Decision.DENY, None))
        self.assertEqual(policy.required_action("home", "POST")[0], policy.Decision.METHOD_NOT_ALLOWED)
        self.assertEqual(policy.required_action("change_execute_run", "POST"), (policy.Decision.ALLOW, policy.Action.EXECUTE))


class AuthenticationTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = make_user("alice", "NMAS Viewer")

    def test_anonymous_is_redirected_to_login(self):
        response = self.client.get(reverse("core:home"))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response["Location"].startswith(reverse("core:login")))
        self.assertTrue(response.has_header("X-Request-ID"))

    def test_anonymous_json_route_gets_401(self):
        self.assertEqual(self.client.get(reverse("core:topology_data")).status_code, 401)

    def test_anonymous_mutation_is_refused_and_audited(self):
        response = self.client.post(reverse("core:device_builder_create_change"), {"title": "x"})
        self.assertEqual(response.status_code, 302)
        self.assertFalse(models.Change.objects.exists())
        event = models.AuditEvent.objects.get(event_type=models.AuditEventType.ACCESS_DENIED)
        self.assertEqual((event.outcome, event.status_code, event.http_method), ("DENIED", 401, "POST"))

    def test_public_routes(self):
        self.assertEqual(self.client.get(reverse("core:healthz")).status_code, 200)
        self.assertEqual(self.client.get(reverse("core:login")).status_code, 200)

    def test_login_success_is_audited_without_password(self):
        response = self.client.post(reverse("core:login"), {"username": "alice", "password": PASSWORD})
        self.assertEqual(response.status_code, 302)
        event = models.AuditEvent.objects.get(event_type=models.AuditEventType.AUTH_LOGIN_SUCCEEDED)
        self.assertEqual((event.actor, event.actor_user, event.outcome), ("alice", self.user, "SUCCESS"))
        self.assertTrue(event.request_id)
        self.assertNotIn(PASSWORD, str(list(models.AuditEvent.objects.values())))

    def test_login_failure_is_audited_and_safe(self):
        response = self.client.post(reverse("core:login"), {"username": "alice", "password": "wrong-password-xx"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Please enter a correct username and password")
        event = models.AuditEvent.objects.get(event_type=models.AuditEventType.AUTH_LOGIN_FAILED)
        self.assertEqual((event.outcome, event.metadata["attempted_username"]), ("FAILURE", "alice"))
        self.assertNotIn("wrong-password-xx", str(list(models.AuditEvent.objects.values())))

    @override_settings(NMAS_LOGIN_FAILURE_LIMIT=3)
    def test_login_is_throttled_after_repeated_failures(self):
        for _ in range(3):
            self.client.post(reverse("core:login"), {"username": "alice", "password": "nope-nope-1"})
        response = self.client.post(reverse("core:login"), {"username": "alice", "password": PASSWORD})
        self.assertContains(response, "Too many failed sign-in attempts")
        self.assertTrue(models.AuditEvent.objects.filter(event_type=models.AuditEventType.AUTH_LOGIN_THROTTLED).exists())
        self.assertFalse(models.AuditEvent.objects.filter(event_type=models.AuditEventType.AUTH_LOGIN_SUCCEEDED).exists())

    def test_logout_is_post_only_and_audited(self):
        sign_in(self.client, self.user)
        self.assertEqual(self.client.get(reverse("core:logout")).status_code, 405)
        response = self.client.post(reverse("core:logout"))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(models.AuditEvent.objects.filter(event_type=models.AuditEventType.AUTH_LOGOUT, actor_user=self.user).exists())
        self.assertEqual(self.client.get(reverse("core:home")).status_code, 302)

    def test_inactive_user_cannot_sign_in(self):
        self.user.is_active = False
        self.user.save()
        response = self.client.post(reverse("core:login"), {"username": "alice", "password": PASSWORD})
        self.assertEqual(response.status_code, 200)

    def test_open_redirect_after_login_is_refused(self):
        response = self.client.post(reverse("core:login") + "?next=https://evil.example/", {"username": "alice", "password": PASSWORD})
        self.assertNotIn("evil.example", response["Location"])


class MfaGateTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = make_user("bob", "NMAS Operator")

    def test_password_only_session_must_enroll(self):
        sign_in(self.client, self.user, mfa_verified=False)
        response = self.client.get(reverse("core:home"))
        self.assertTrue(response["Location"].startswith(reverse("core:mfa_enroll")))

    def test_enrolled_password_only_session_must_verify(self):
        enroll(self.user)
        sign_in(self.client, self.user, mfa_verified=False)
        response = self.client.get(reverse("core:device_builder"))
        self.assertTrue(response["Location"].startswith(reverse("core:mfa_verify")))

    def test_fresh_login_clears_previous_verification(self):
        enroll(self.user)
        self.client.post(reverse("core:login"), {"username": "bob", "password": PASSWORD})
        self.assertFalse(mfa.session_verified(self.client.session))

    def test_enrollment_flow(self):
        sign_in(self.client, self.user, mfa_verified=False)
        page = self.client.get(reverse("core:mfa_enroll"))
        self.assertEqual(page.status_code, 200)
        self.assertIn("no-store", page["Cache-Control"])
        self.assertContains(page, "data:image/svg+xml;base64,")
        seed = mfa._decrypt(self.client.session[mfa.SESSION_PENDING_KEY])
        self.assertContains(self.client.post(reverse("core:mfa_enroll"), {"otp_code": "000000"}), "not valid")
        response = self.client.post(reverse("core:mfa_enroll"), {"otp_code": pyotp.TOTP(seed).now()})
        self.assertEqual(response.status_code, 302)
        device = models.AppMfaDevice.objects.get(user=self.user)
        self.assertNotIn(seed, device.encrypted_seed)
        self.assertEqual(mfa._decrypt(device.encrypted_seed), seed)
        self.assertTrue(mfa.session_verified(self.client.session))
        self.assertNotIn(mfa.SESSION_PENDING_KEY, self.client.session)
        self.assertTrue(models.AuditEvent.objects.filter(event_type=models.AuditEventType.APP_MFA_ENROLLED, actor_user=self.user).exists())
        everything = str(list(models.AuditEvent.objects.values()))
        self.assertNotIn(seed, everything)
        self.assertNotIn("otpauth", everything)
        self.assertEqual(self.client.get(reverse("core:home")).status_code, 200)

    def test_verify_valid_invalid_and_replay(self):
        seed = enroll(self.user)
        sign_in(self.client, self.user, mfa_verified=False)
        bad = self.client.post(reverse("core:mfa_verify"), {"otp_code": "123456" if pyotp.TOTP(seed).now() != "123456" else "654321"})
        self.assertEqual(bad.status_code, 200)
        self.assertTrue(models.AuditEvent.objects.filter(event_type=models.AuditEventType.APP_MFA_FAILED).exists())
        code = pyotp.TOTP(seed).now()
        ok = self.client.post(reverse("core:mfa_verify") + "?next=/nsot/", {"otp_code": code, "next": "/nsot/"})
        self.assertEqual((ok.status_code, ok["Location"]), (302, "/nsot/"))
        self.assertTrue(models.AuditEvent.objects.filter(event_type=models.AuditEventType.APP_MFA_VERIFIED).exists())
        other = Client()
        sign_in(other, self.user, mfa_verified=False)
        replay = other.post(reverse("core:mfa_verify"), {"otp_code": code})
        self.assertEqual(replay.status_code, 200, "an already-accepted code must not be accepted again")
        self.assertFalse(mfa.session_verified(other.session))

    def test_repeated_mfa_failures_sign_the_session_out(self):
        enroll(self.user)
        sign_in(self.client, self.user, mfa_verified=False)
        for _ in range(5):
            response = self.client.post(reverse("core:mfa_verify"), {"otp_code": "abc"})
        self.assertEqual(response["Location"], reverse("core:login"))
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_admin_requires_website_mfa_after_login(self):
        staff = make_user("carol", is_staff=True, is_superuser=True)
        sign_in(self.client, staff, mfa_verified=False)
        self.assertTrue(self.client.get("/admin/")["Location"].startswith(reverse("core:mfa_enroll")))
        anonymous = Client()
        self.assertTrue(anonymous.get("/admin/")["Location"].startswith("/admin/login/"))
        self.assertEqual(anonymous.get("/admin/login/").status_code, 200)
        sign_in(self.client, staff)
        self.assertEqual(self.client.get("/admin/").status_code, 200)

    def test_mfa_reset_command(self):
        from django.core.management import call_command
        enroll(self.user)
        call_command("nmas_app_mfa_reset", "--username", "bob", "--confirm", stdout=mock.MagicMock())
        self.assertFalse(models.AppMfaDevice.objects.filter(user=self.user).exists())
        self.assertTrue(models.AuditEvent.objects.filter(event_type=models.AuditEventType.APP_MFA_RESET).exists())

    def test_website_mfa_is_separate_from_device_mfa(self):
        related = {f.related_model for f in models.AppMfaDevice._meta.get_fields() if f.is_relation}
        self.assertEqual(related, {get_user_model()})
        imported = set()
        for path in Path(mfa.__file__).parent.glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.ImportFrom):
                    imported.add(f"{'.' * node.level}{node.module or ''}")
                    imported |= {alias.name for alias in node.names}
                elif isinstance(node, ast.Import):
                    imported |= {alias.name for alias in node.names}
        for forbidden in ("credentials", "credential_service", "device_credentials", "health", "execution", "privacyidea"):
            self.assertFalse(any(forbidden in name for name in imported), f"identity package imports {forbidden}: {imported}")


class AuthorizationTests(TestCase):
    def client_for(self, username, *roles):
        client = Client()
        sign_in(client, make_user(username, *roles))
        return client

    def test_viewer_can_read_but_not_mutate(self):
        viewer = self.client_for("vera", "NMAS Viewer")
        self.assertEqual(viewer.get(reverse("core:device_builder")).status_code, 200)
        response = viewer.post(reverse("core:device_builder_create_change"), {"title": "nope"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(models.Change.objects.exists())
        event = models.AuditEvent.objects.get(event_type=models.AuditEventType.ACCESS_DENIED)
        self.assertIn("core.nmas_edit", event.metadata["reason"])
        self.assertEqual(event.actor_user.username, "vera")

    def test_execute_requires_execute_permission_server_side(self):
        with mock.patch("core.views.execution_service.execute_change") as execute:
            operator = self.client_for("olga", "NMAS Operator")
            self.assertEqual(operator.post(reverse("core:change_execute_run", args=["CHG-20260101-0001"])).status_code, 403)
            execute.assert_not_called()
            approver = self.client_for("abe", "NMAS Approver")
            self.assertEqual(approver.post(reverse("core:change_execute_run", args=["CHG-20260101-0001"])).status_code, 403)
            executor = self.client_for("eve", "NMAS Executor")
            # Authorized: the request reaches the view (which 404s on the unknown Change) -- not a 403.
            self.assertNotEqual(executor.post(reverse("core:change_execute_run", args=["CHG-20260101-0001"])).status_code, 403)

    def test_approval_routes_require_approve(self):
        operator = self.client_for("otto", "NMAS Operator")
        self.assertEqual(operator.post(reverse("core:soak_decision", args=["SOAK-1"]), {"decision": "APPROVE"}).status_code, 403)
        self.assertEqual(operator.post(reverse("core:bootstrap_approve", args=["RUN-1"])).status_code, 403)

    def test_security_reads_require_security_admin(self):
        operator = self.client_for("oscar", "NMAS Operator")
        self.assertEqual(operator.get(reverse("core:credential_status")).status_code, 403)
        self.assertEqual(operator.get(reverse("core:audit_log")).status_code, 403)
        admin = self.client_for("sam", "NMAS Security Admin")
        self.assertEqual(admin.get(reverse("core:audit_log")).status_code, 200)

    def test_read_only_route_refuses_unsafe_methods(self):
        viewer = self.client_for("rita", "NMAS Viewer", "NMAS Operator", "NMAS Executor")
        self.assertEqual(viewer.post(reverse("core:home")).status_code, 405)

    def test_user_without_any_role_is_denied(self):
        nobody = self.client_for("nobody")
        self.assertEqual(nobody.get(reverse("core:home")).status_code, 403)

    def test_superuser_and_direct_permissions_work(self):
        root = Client()
        sign_in(root, make_user("root", is_superuser=True))
        self.assertEqual(root.get(reverse("core:audit_log")).status_code, 200)
        direct = Client()
        sign_in(direct, make_test_operator("direct", actions=[policy.Action.VIEW]))
        self.assertEqual(direct.get(reverse("core:home")).status_code, 200)


class AuditAttributionTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = make_user("dana", "NMAS Operator")
        sign_in(self.client, self.user)

    def test_authenticated_user_reaches_domain_records_and_request_audit(self):
        response = self.client.post(reverse("core:device_builder_create_change"), {"title": "attribution check", "description": "d"})
        self.assertEqual(response.status_code, 302)
        change = models.Change.objects.get()
        self.assertEqual(change.created_by, "dana")
        rid = response["X-Request-ID"]
        domain = models.AuditEvent.objects.get(event_type=models.AuditEventType.CHANGE_CREATED)
        self.assertEqual((domain.actor, domain.actor_user, domain.request_id), ("dana", self.user, rid))
        web = models.AuditEvent.objects.get(event_type=models.AuditEventType.WEB_ACTION)
        self.assertEqual((web.actor, web.request_id, web.outcome, web.http_method), ("dana", rid, "SUCCESS", "POST"))
        self.assertEqual(web.route, "core:device_builder_create_change")
        self.assertEqual(web.metadata["category"], "edit")
        self.assertIn("title", web.metadata["fields"])
        self.assertNotIn("attribution check", str(web.metadata), "submitted VALUES are never recorded")

    def test_upstream_request_id_is_reused_when_well_formed(self):
        response = self.client.get(reverse("core:home"), HTTP_X_REQUEST_ID="cf-ray-1234567890ab")
        self.assertEqual(response["X-Request-ID"], "cf-ray-1234567890ab")
        bad = self.client.get(reverse("core:home"), HTTP_X_REQUEST_ID="<script>")
        self.assertNotEqual(bad["X-Request-ID"], "<script>")

    def test_plain_reads_and_static_assets_do_not_flood_the_ledger(self):
        before = models.AuditEvent.objects.count()
        self.client.get(reverse("core:home"))
        self.client.get(reverse("core:nsot"))
        self.client.get("/static/core/css/base.css")
        self.assertEqual(models.AuditEvent.objects.count(), before)

    def test_sensitive_reads_are_audited(self):
        admin = Client()
        sign_in(admin, make_user("sec", "NMAS Security Admin"))
        admin.get(reverse("core:credential_status_json"))
        event = models.AuditEvent.objects.get(event_type=models.AuditEventType.SENSITIVE_READ)
        self.assertEqual((event.actor, event.metadata["category"]), ("sec", "sensitive_read"))

    def test_failed_action_is_recorded_as_failure(self):
        response = self.client.post(reverse("core:device_builder_delete_change", args=["CHG-20991231-9999"]), {"confirmation": "x"})
        self.assertEqual(response.status_code, 404)
        web = models.AuditEvent.objects.get(event_type=models.AuditEventType.WEB_ACTION)
        self.assertEqual((web.outcome, web.status_code), ("FAILURE", 404))

    def test_source_ip_honours_forwarded_for_only_from_trusted_proxy(self):
        self.client.post(reverse("core:notification_mark_all_read"), HTTP_X_FORWARDED_FOR="203.0.113.9", REMOTE_ADDR="127.0.0.1")
        self.client.post(reverse("core:notification_mark_all_read"), HTTP_X_FORWARDED_FOR="203.0.113.9", REMOTE_ADDR="198.51.100.7")
        ips = list(models.AuditEvent.objects.filter(event_type=models.AuditEventType.WEB_ACTION).order_by("id").values_list("source_ip", flat=True))
        self.assertEqual(ips, ["203.0.113.9", "198.51.100.7"])

    def test_theme_redirect_is_never_open(self):
        response = self.client.post(reverse("core:set_theme"), {"theme": "default", "next": "https://evil.example/x"})
        self.assertEqual(response["Location"], "/")
