"""Direct tests for the remaining Troubleshooter service helpers: the research worker, readiness rendering, notifications,
verification outcomes, the target policy, reconciliation, route-intent expectations and the HTML report
(troubleshooting/research_worker.py, readiness.py, notify.py, verification.py, target_policy.py, reconcile.py,
route_intent.py, reporting.py).

Readiness never reports a runbook ready without an admitted device, a failed verification is never resolved, a report
escapes every operator-supplied string, and the research worker answers only a well-formed request.  The research
broker, mail backend and intake engine are fakes where they would otherwise reach the network.
"""

from __future__ import annotations

import os
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.core import mail
from django.test import SimpleTestCase, TestCase, override_settings

from core.services.troubleshooting import governance as gov, intake, notify, readiness, reconcile, reporting, research_worker as rw
from core.services.troubleshooting import repository as repo, route_intent, verification
from core.services.troubleshooting.research import ResearchResult
from core.services.troubleshooting.target_policy import AuthorizationRefused
from core.tests import test_troubleshooting_governance as G
from core.tests import test_troubleshooting_target_policy as TP

KEY = "k" * 40


# ================================================================================================ research worker
class FakeBroker:
    def fetch(self, url, *, purpose, principal, method):
        return ResearchResult(url=url, status=200, content_type="text/plain", body="ok", sha256="0" * 64, bytes_read=2)


def research_envelope(**over):
    return {"principal": "nmas-troubleshooter", "payload": {"schema": rw.RESEARCH_SCHEMA, "url": "https://docs.example.com/x",
                                                            "purpose": "vendor doc", "method": "GET", **over}}


class ResearchWorkerTests(SimpleTestCase):
    def test_research_handler_returns_the_broker_result(self):
        out = rw.ResearchHandler(FakeBroker())(research_envelope())
        self.assertEqual((out["schema"], out["status"], out["untrusted_external_content"]), (rw.RESEARCH_RESULT_SCHEMA, 200, True))

    def environment(self, tmp):
        return {"NMAS_TS_RESEARCH_IPC_KEY": KEY, "NMAS_TS_RESEARCH_CLIENT_UID": str(os.getuid()),
                "NMAS_TS_RESEARCH_ALLOWED_DESTINATIONS": '{"docs.example.com": ["93.184.215.14"]}',
                "NMAS_TS_RESEARCH_SOCKET": f"{tmp}/worker.sock", "NMAS_TS_RESEARCH_REPLAY_DB": f"{tmp}/replay.sqlite3",
                "NMAS_TS_RESEARCH_AUDIT_LOG": f"{tmp}/audit.jsonl", "NMAS_TS_RESEARCH_SOCKET_GROUP": ""}

    def test_server_from_environment_builds_the_allowlisted_research_server(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, self.environment(tmp)):
            server = rw.server_from_environment()
        self.assertEqual((server.config.kind, type(server.handler)), ("research", rw.ResearchHandler))

    def test_main_returns_zero_after_a_clean_serve(self):
        with mock.patch.object(rw, "server_from_environment", return_value=SimpleNamespace(serve=lambda: None)):
            self.assertEqual(rw.main(), 0)


# ======================================================================================================= readiness
def readiness_report(*, admitted=True, problems=()):
    return {"version": "unit", "deployment_problems": list(problems), "sources": {"cli": True, "snmp": False},
            "devices": [{"device": "R1", "platform": "ceos", "admission": "ADMITTED" if admitted else "NOT_ADMITTED", "admitted": admitted,
                         "blockers": [] if admitted else [{"code": "NO_PATH", "owner": "operator", "action": "approve a management path"}],
                         "warnings": []}]}


class ReadinessTests(SimpleTestCase):
    def test_runbook_readiness_without_an_admitted_device_is_never_ready(self):
        rows = readiness.runbook_readiness(readiness_report(admitted=False))
        self.assertTrue(rows)
        self.assertTrue(all(r["status"] in ("NOT_READY", "EXTERNALLY_BLOCKED_HARDWARE") for r in rows))

    def test_render_text_renders_the_bound_sources_and_runbooks(self):
        report = readiness_report()
        text = readiness.render_text(report, readiness.runbook_readiness(report))
        self.assertIn("bound sources: cli", text)
        self.assertNotIn("deployment problems", text)

    def test_readiness_text_never_hides_deployment_problems_or_blockers(self):
        report = readiness_report(admitted=False, problems=["unknown NMAS_TS_DEPLOYMENT keys"])
        with self.subTest("a blocked deployment is never hidden"):
            text = readiness.render_text(report, readiness.runbook_readiness(report))
        self.assertIn("deployment problems: unknown NMAS_TS_DEPLOYMENT keys", text)
        self.assertIn("[NO_PATH] (operator) approve a management path", text)


# ===================================================================================================== notify
class NotifyTests(SimpleTestCase):
    @override_settings(NMAS_TS_ALERT_EMAILS=("noc@example.test", ""), EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_recipients_and_send_deliver_to_the_configured_addresses(self):
        self.assertEqual(notify.recipients(), ["noc@example.test"])
        self.assertTrue(notify.send("recovered", "R1 Ethernet1 restored"))
        self.assertEqual(mail.outbox[-1].to, ["noc@example.test"])

    @override_settings(NMAS_TS_ALERT_EMAILS=())
    def test_send_without_recipients_or_with_a_failing_backend_is_false(self):
        self.assertFalse(notify.send("x", "y"))
        with override_settings(NMAS_TS_ALERT_EMAILS=("noc@example.test",)), \
                mock.patch.object(notify, "send_mail", side_effect=ConnectionRefusedError("smtp down")):
            self.assertFalse(notify.send("x", "y"))


# ================================================================================================= verification
class VerificationTests(TestCase):
    def setUp(self):
        self.case = G.make_case(key="tg-verify")
        self.ev = G.seed_deterministic(self.case)

    def test_abort_failed_verification_without_a_failed_verification_is_refused(self):
        plan = G.propose(self.case, self.ev)
        with self.assertRaisesRegex(gov.GovernanceRefused, "NO_FAILED_VERIFICATION"):
            verification.abort_failed_verification(G.PROPOSER, plan.record_id, G.make_ports())

    def test_finalize_of_an_inconclusive_case_never_resolves_it(self):
        doc = verification.finalize(G.PROPOSER, self.case, now=G.T0)
        self.assertEqual((doc["outcome"], doc["closed"]), ("INCONCLUSIVE_ESCALATED", True))
        self.assertEqual(repo.get_case(G.PROPOSER, self.case.case_id).state, "UNRESOLVED")   # honest disposition, not RESOLVED_VERIFIED

    def test_metrics_of_another_tenant_has_no_cases(self):
        out = verification.metrics(repo.Actor("mallory", "user", tenant="other"), now=G.T0)
        self.assertEqual((out["cases"], out["mttr_seconds"]), (0, None))


# ================================================================================================ target policy
class TargetPolicyUnitTests(SimpleTestCase):
    setUp = TP.TargetPolicyTests.setUp
    request = TP.TargetPolicyTests.request
    # set by TargetPolicyTests.setUp
    policy: object

    def test_decide_returns_an_allowed_decision_for_the_exact_device(self):
        decision, target = self.policy.decide(self.request())
        self.assertTrue(decision.allowed)
        self.assertEqual(target.device, "R6")

    def test_authorization_error_carries_its_code_and_reasons(self):
        with self.subTest("builds the coded message"):
            err = AuthorizationRefused("TARGET_REFUSED", ["cross-tenant request", "device absent"])
        self.assertEqual((err.code, str(err)), ("TARGET_REFUSED", "TARGET_REFUSED: cross-tenant request; device absent"))

    def test_authorization_refused_without_reasons_is_the_bare_code(self):
        self.assertEqual(str(AuthorizationRefused("CAPABILITY_REFUSED")), "CAPABILITY_REFUSED")


# ================================================================================ reconcile / route intent / report
class ReconcileAndIntentTests(SimpleTestCase):
    def test_verdict_as_dict_returns_every_field(self):
        out = reconcile.Verdict("TS-1", outcome="RETAIN", reasons=["fault persists"]).as_dict()
        self.assertEqual((out["case"], out["outcome"], out["applied"]), ("TS-1", "RETAIN", False))

    def test_default_route_intent_check_returns_the_fresh_intake_record(self):
        record = {"state": "MATCH", "target": "h1->h2"}

        class FakeIntake:
            def __init__(self, cfg):
                self.cfg = cfg

            def _intent_route_incidents(self, _now):
                return [], [record]

        binding = {"bound": True, "intent_file": "/etc/nmas/route-intent.json", "topology_revision": "rev-1", "max_age_seconds": "60"}
        with mock.patch.object(intake, "unit_route_intent_binding", return_value=binding), mock.patch.object(intake, "Intake", FakeIntake):
            self.assertEqual(reconcile.default_route_intent_check(), record)

    def test_rib_entry_returns_the_expected_route(self):
        expectation = route_intent.PrefixExpectation("T1", "forward", "10.2.2.0/24", "R1", "ipv4", "10.2.2.0/24", "ospf", ("10.0.12.2",))
        entry = expectation.rib_entry()
        self.assertEqual((entry.prefix, entry.source, entry.next_hops), ("10.2.2.0/24", "ospf", (("10.0.12.2", ""),)))


class ReportHtmlTests(TestCase):
    def test_to_html_never_emits_raw_operator_markup(self):
        case = G.make_case(key="tg-report", title="<script>alert(1)</script>")
        report = reporting.build_report(G.PROPOSER, case, now=G.T0)
        html = reporting.to_html(report)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn(case.case_id, html)


