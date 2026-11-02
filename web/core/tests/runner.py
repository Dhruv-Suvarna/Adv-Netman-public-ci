"""Test runner for the NMAS website access boundary (V2 Phase 1).

Hundreds of pre-existing view tests exercise views, not the access boundary.  This runner makes Django's default test
client an ``OperatorClient``: before its first request it signs in a dedicated test operator who holds every NMAS
action permission (granted through real Django permissions, not a superuser bypass) and has completed website MFA.

The boundary itself is proven separately (test_identity_access.py and friends) with an explicit plain
``django.test.Client`` -- anonymous, limited-role and MFA-pending -- so enforcement is never assumed.
"""

from __future__ import annotations

from django.test import Client, SimpleTestCase
from django.test.runner import DiscoverRunner

TEST_OPERATOR_USERNAME = "nmas-test-operator"


def make_test_operator(username: str = TEST_OPERATOR_USERNAME, *, actions=None):
    from django.contrib.auth import get_user_model
    from django.contrib.auth.models import Permission

    from core.services.identity.policy import Action

    user, _ = get_user_model().objects.get_or_create(username=username)
    wanted = [a.value for a in (actions or Action)]
    user.user_permissions.set(Permission.objects.filter(content_type__app_label="core", codename__in=wanted))
    return get_user_model().objects.get(pk=user.pk)  # drop the cached permission set


def sign_in(client: Client, user, *, mfa_verified: bool = True) -> None:
    from core.services.identity import mfa

    client.force_login(user)
    if mfa_verified:
        session = client.session
        session[mfa.SESSION_VERIFIED_KEY] = "test"
        session.save()


class OperatorClient(Client):
    nmas_auto_login = True

    def request(self, **request):
        if self.nmas_auto_login and not getattr(self, "_nmas_signed_in", False):
            self._nmas_signed_in = True
            sign_in(self, make_test_operator())
        return super().request(**request)

    def logout(self):
        self.nmas_auto_login = False
        super().logout()


def _no_device_session(device):
    """V2 Phase 5C: the automated test environment has no device to read.  A soak start / sample that was not handed an explicit fake
    session gets this one, so no unit test can open a real device session by accident."""
    from core.services.health.live import LiveError

    raise LiveError("CONNECTION_FAILED")


class NmasTestRunner(DiscoverRunner):
    _tg_tracer = None

    def run_suite(self, suite, **kwargs):
        # Lab 7 test governance: only when NMAS_TG_TRACE_OUT is set (Tier-3 full evidence / ``test_governance run``) is the
        # direct-invocation tracer installed; otherwise the suite runs exactly as before.
        from core.services.test_governance.session import trace_output, traced_session

        output = trace_output()
        if not output:
            return super().run_suite(suite, **kwargs)
        with traced_session(output, suite="django") as tracer:
            self._tg_tracer = tracer
            try:
                return super().run_suite(suite, **kwargs)
            finally:
                self._tg_tracer = None

    def get_resultclass(self):
        base = super().get_resultclass()
        if self._tg_tracer is None:
            return base
        import unittest

        from core.services.test_governance.tracer import make_result_class

        return make_result_class(base or unittest.TextTestResult, self._tg_tracer)

    def setup_test_environment(self, **kwargs):
        super().setup_test_environment(**kwargs)
        SimpleTestCase.client_class = OperatorClient
        # A soak pins a real configuration digest at start in every real environment.  Tests that exercise that rule turn it on
        # explicitly (``override_settings``) and pass a fake session; every other test starts soaks without a device.
        from django.conf import settings

        from core.services.soak import config_state

        settings.PROBATION_SOAK_REQUIRE_BASELINE_DIGEST = False
        # Configuration Validation dispatches to GitHub and gates execution in every real environment.  Its own tests turn it on
        # (``override_settings``) with a fake GitHub transport; every other test validates and executes without it.
        settings.NMAS_CONFIGURATION_VALIDATION_ENABLED = False
        config_state.SESSION_FACTORY = _no_device_session
