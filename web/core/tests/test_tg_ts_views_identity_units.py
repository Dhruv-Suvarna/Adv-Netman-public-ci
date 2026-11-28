"""Direct tests for the Troubleshooter web views and their intake/qualification/research helpers, and the single-admin
lab exception (core/troubleshooting_views.py, troubleshooting/intake_scope.py, qualification.py, research.py,
identity/single_admin_exception.py).

Every view resolves its principal first; another tenant's case is not found rather than forbidden; an escalation or run
that NMAS refuses is reported as refused; and the single-admin exception authorizes only one exact, unreplayed target.
Views are called directly with RequestFactory requests; TLS, DNS and the inventory reader are fakes where a network
would otherwise be touched.
"""

from __future__ import annotations

import io
import json
import socket
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth.models import AnonymousUser
from django.http import Http404
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings

from core import troubleshooting_views as tv
from core.services.identity import single_admin_exception as exception
from core.services.troubleshooting import intake_scope, qualification, repository as repo, research
from core.tests import test_single_admin_lab_exception as SAE
from core.tests import test_troubleshooting_views as V

# The api()/_ui() decorators resolve and inject the principal argument, so the views are called with (request, *url_args).
# pylint: disable=no-value-for-parameter


def get(user, path="/api/v1/troubleshooting/"):
    request = RequestFactory().get(path)
    request.user = user
    return request


def post(user, data=None, path="/troubleshooting/x/"):
    request = RequestFactory().post(path, data or {})
    request.user = user
    return request


def body(response):
    return json.loads(response.content)


# ======================================================================================================== views
class ViewUnitTests(TestCase):
    setUp = V.ViewsBase.setUp
    # set by ViewsBase.setUp
    alice: object
    viewer: object
    mallory: object
    noroles: object
    case: object

    def test_api_decorator_returns_the_view_for_an_authorized_principal(self):
        view = tv.api("viewer")(lambda request, p: tv._envelope({"who": p.actor.name}))   # pylint: disable=protected-access  # the module's own envelope
        self.assertEqual(body(view(get(self.viewer)))["data"], {"who": "vera"})

    def test_api_decorator_refuses_anonymous_roleless_or_underprivileged_callers(self):
        view = tv.api("operator")(lambda request, p: tv._envelope({}))                     # pylint: disable=protected-access  # the module's own envelope
        for label, user, status in (("anonymous", AnonymousUser(), 401), ("no role", self.noroles, 401), ("a viewer", self.viewer, 403)):
            with self.subTest(f"{label} is refused"):
                self.assertEqual(view(get(user)).status_code, status)

    def test_default_principal_returns_the_tenant_scoped_roles(self):
        principal = tv.default_principal(get(self.alice))
        self.assertEqual((principal.actor.tenant, principal.roles), ("acme", frozenset({"operator"})))

    def test_default_principal_without_a_role_or_session_is_none(self):
        self.assertIsNone(tv.default_principal(get(self.noroles)))
        self.assertIsNone(tv.default_principal(get(AnonymousUser())))

    def test_case_read_views_return_their_envelopes(self):
        for view, kind in ((tv.api_ai, "ai_investigation"), (tv.api_evidence, "evidence_list"), (tv.api_remediation, "remediation")):
            with self.subTest(view=view.__name__):
                response = view(get(self.viewer), self.case.case_id)
                self.assertEqual((response.status_code, body(response)["kind"]), (200, kind))

    def test_api_metrics_of_another_tenant_never_count_this_tenants_cases(self):
        mine, theirs = body(tv.api_metrics(get(self.viewer)))["data"], body(tv.api_metrics(get(self.mallory)))["data"]
        self.assertNotEqual(mine, theirs)
        self.assertNotIn(self.case.case_id, json.dumps(theirs))

    def test_ui_escalate_reports_an_unexhausted_case_as_refused(self):
        response = tv.ui_escalate(post(self.alice, {"uncertainty": "rules cannot conclude on this flow"}), self.case.case_id)
        self.assertEqual(response.status_code, 302)
        self.assertIn("refused", response["Location"])

    def test_ui_run_returns_the_run_notice(self):
        response = tv.ui_run(post(self.alice, {"run_key": "tg-ui-run"}), self.case.case_id)
        self.assertEqual(response.status_code, 302)
        self.assertIn("diagnostic+run", response["Location"])

    def test_ui_run_of_another_tenants_case_is_refused(self):
        response = tv.ui_run(post(self.mallory, {"run_key": "x"}), self.case.case_id)
        self.assertIn("refused", response["Location"])

    def test_ui_plan_action_of_an_unknown_plan_is_not_found(self):
        with self.assertRaises(Http404):                     # no existence oracle: an unknown plan is indistinguishable from a foreign one
            tv.ui_plan_action(post(self.alice), self.case.case_id, "TSPLAN-UNKNOWN", "approve")

    @mock.patch.object(tv.intake_scope, "options", return_value={"devices": [{"name": "r1", "platform": "ceos", "lifecycle": "IN_SERVICE",
                                                                            "diagnostic_ready": True, "reason": ""}], "links": []})
    def test_ui_intake_refuses_a_device_outside_the_displayed_scope(self, _options):
        response = tv.ui_intake(post(self.alice, {"devices": "r9", "protocol": "tcp", "ports": "443"}, path="/troubleshooting/new/"))
        self.assertEqual(response.status_code, 400)
        self.assertFalse(tv.m.TsCase.objects.filter(affected_scope__devices=["r9"]).exists())


# =================================================================================================== intake scope
LINKS = {"links": [{"value": "r1:Ethernet1|r2:Ethernet1", "scope": {"a": "r1", "b": "r2"}}]}


class IntakeScopeTests(TestCase):
    def test_options_returns_the_visible_inventory_devices(self):
        devices = intake_scope.options(repo.Actor("alice", "user", tenant="acme"))["devices"]
        self.assertTrue(devices)
        self.assertTrue(all(not row["diagnostic_ready"] for row in devices))      # no approved paths in the test database

    def test_options_of_an_actor_without_visible_devices_is_empty(self):
        self.assertEqual(intake_scope.options(repo.Actor("eve", "user", tenant="acme", devices=frozenset({"none-such"})))["devices"], [])

    def test_readiness_reason_returns_the_ready_path_statement(self):
        self.assertEqual(intake_scope.readiness_reason("IN_SERVICE", "", True), "ACTIVE, HEALTHY, approved ManagementPath")

    def test_selected_link_returns_the_exact_current_link(self):
        self.assertEqual(intake_scope.selected_link(LINKS, "r1:Ethernet1|r2:Ethernet1"), {"a": "r1", "b": "r2"})

    def test_selected_link_of_arbitrary_input_is_none(self):
        self.assertIsNone(intake_scope.selected_link(LINKS, "r1:Ethernet9|r7:Ethernet1"))
        self.assertIsNone(intake_scope.selected_link(LINKS, ""))


# ================================================================================================== qualification
class QualificationTests(TestCase):
    def test_management_paths_returns_the_registered_summary(self):
        from core.tests.helpers import lifecycle as L

        L.adopt("S1")
        out = qualification.management_paths("S1")
        self.assertEqual((out["registered"], out["approved_order"], out["source"]), (0, [], "management-registry"))

    def test_management_paths_of_an_unregistered_device_is_none(self):
        self.assertIsNone(qualification.management_paths("R99")["registered"])

    def test_report_cfg_returns_a_copy_of_the_given_config(self):
        cfg = {"inventory": "x"}
        self.assertEqual(qualification.report_cfg(cfg), cfg)
        self.assertIsNot(qualification.report_cfg(cfg), cfg)

    @override_settings(NMAS_TS_DEPLOYMENT=["not", "a", "mapping"])
    def test_report_cfg_of_an_invalid_deployment_setting_is_empty(self):
        self.assertEqual(qualification.report_cfg(None), {})


# ======================================================================================================= research
class FakeTls:
    def __init__(self, response: bytes):
        self.sent, self.closed, self.response = b"", False, response

    def sendall(self, data):
        self.sent += data

    def makefile(self, *_args, **_kwargs):
        return io.BytesIO(self.response)

    def close(self):
        self.closed = True


class ResearchTransportTests(SimpleTestCase):
    def fetch(self, response: bytes, max_bytes=1024):
        tls = FakeTls(response)
        context = SimpleNamespace(wrap_socket=lambda raw, server_hostname: tls)
        pinned = research._PinnedHTTPS(timeout=2.0, context=context)        # pylint: disable=protected-access  # the pinned transport under test
        with mock.patch.object(research.socket, "create_connection", return_value=mock.Mock()) as connect:
            out = pinned.request(host="docs.example.test", ip="192.0.2.10", method="GET", target="/x", max_bytes=max_bytes)
        connect.assert_called_once_with(("192.0.2.10", 443), timeout=2.0)
        return out, tls

    def test_pinned_https_request_returns_the_status_headers_and_body(self):
        (status, headers, payload), tls = self.fetch(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok")
        self.assertEqual((status, headers["content-type"], payload), (200, "text/plain", b"ok"))
        self.assertIn(b"Host: docs.example.test", tls.sent)
        self.assertTrue(tls.closed)

    def test_pinned_https_request_refuses_an_oversized_response(self):
        with self.assertRaises(research.ResearchRefused) as caught:
            self.fetch(b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n" + b"x" * 4096)
        self.assertEqual(caught.exception.code, "RESPONSE_TOO_LARGE")

    def test_system_resolver_returns_sorted_unique_answers(self):
        rows = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.2", 443)), (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 443))] * 2
        with mock.patch.object(research.socket, "getaddrinfo", return_value=rows):
            self.assertEqual(research.system_resolver("docs.example.test", (socket.AF_INET,)), ("192.0.2.1", "192.0.2.2"))

    def test_system_resolver_never_queries_a_disabled_family(self):
        with mock.patch.object(research.socket, "getaddrinfo", return_value=[]) as lookup:
            self.assertEqual(research.system_resolver("docs.example.test", (socket.AF_INET,)), ())
        self.assertEqual([call.kwargs["family"] for call in lookup.call_args_list], [socket.AF_INET])

    @override_settings(NMAS_TS_RESEARCH={"allowed_destinations": {"docs.example.com": ["93.184.215.14"]}, "timeout": 3})
    def test_broker_from_settings_builds_the_allowlisted_broker(self):
        self.assertIsInstance(research.broker_from_settings(), research.ResearchBroker)


# ============================================================================================ single-admin exception
class SingleAdminExceptionUnitTests(TestCase):
    setUp = SAE.SingleAdminExceptionTests.setUp
    capability = SAE.SingleAdminExceptionTests.capability
    activate = SAE.SingleAdminExceptionTests.activate
    # set by SingleAdminExceptionTests.setUp
    now: object
    nmas: object

    def target(self):
        return self.nmas.attachment_id

    def test_deployment_lab_id_returns_the_tracked_lab(self):
        self.assertEqual(exception.deployment_lab_id(), "srlceos01")

    def test_load_refuses_any_path_but_the_fixed_capability_file(self):
        self.assertEqual(exception.load(exception.CONFIG_PATH.with_name("other.json")).codes, ["EXCEPTION_PATH_INVALID"])

    def test_state_and_authorize_accept_an_activated_in_scope_target(self):
        cap = self.capability()
        self.activate(cap)
        self.assertTrue(exception.state(cap, now=self.now).ok)
        self.assertTrue(exception.authorize(cap, action="NMAS_ATTACHMENT_APPROVE", target=self.target(), actor="dhruv", now=self.now).ok)

    def test_consume_records_one_use_of_the_exact_target(self):
        cap = self.capability()
        self.activate(cap)
        used = exception.consume(cap, action="NMAS_ATTACHMENT_APPROVE", target=self.target(), actor="dhruv", original_requester="dhruv",
                                 now=self.now)
        self.assertTrue(used.ok)
        self.assertEqual(len(self.uses(cap)), 1)

    def test_consume_refuses_a_replayed_or_out_of_scope_target(self):
        cap = self.capability()
        self.activate(cap)
        kw = {"action": "NMAS_ATTACHMENT_APPROVE", "actor": "dhruv", "original_requester": "dhruv", "now": self.now}
        exception.consume(cap, target=self.target(), **kw)
        self.assertEqual(exception.consume(cap, target=self.target(), **kw).codes, ["EXCEPTION_REPLAY"])
        self.assertEqual(exception.consume(cap, target="NMASATT-OTHER", **kw).codes, ["EXCEPTION_TARGET_OUT_OF_SCOPE"])
        self.assertEqual(len(self.uses(cap)), 1)

    def test_revoke_records_the_revocation_and_ends_the_exception(self):
        cap = self.capability()
        self.activate(cap)
        self.assertTrue(exception.revoke(cap, actor="dhruv", reason="owner finished").ok)
        self.assertEqual(exception.state(cap, now=self.now).codes, ["EXCEPTION_REVOKED"])

    uses = SAE.SingleAdminExceptionTests.uses
