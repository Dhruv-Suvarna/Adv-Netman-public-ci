"""Direct tests for the AI handoff gate (troubleshooting/ai.py) and the model continuation runtime helpers
(troubleshooting/ai_runtime.py).

Delegation needs evidenced deterministic exhaustion; a handoff is visible only inside its tenant; the model request is
bounded and redacted; a model response is structurally validated before NMAS acts on it; and the diagnostic runner runs
only registered read-only tests.  The model and its provider are scripted doubles: no model is called.
"""

from __future__ import annotations

import os
from unittest import mock

from django.test import SimpleTestCase, TestCase, override_settings

from core import models as m
from core.services.troubleshooting import ai, ai_runtime as air
from core.services.troubleshooting import runtime as rt
from core.services.troubleshooting import repository as repo
from core.tests import test_troubleshooting_ai as AI
from core.tests import test_troubleshooting_ai_runtime as AIR
from core.tests.test_troubleshooting_governance import CATALOG, PROPOSER, T0

OTHER_TENANT = repo.Actor("mallory", "user", tenant="other-tenant")


class StubProvider:
    def identity(self):
        return {"provider": "stub", "model_id": "stub-1", "model_version": "0"}

    def complete(self, request):
        return {"action": "conclude", "conclude": {"outcome": "INCONCLUSIVE", "summary": str(request.get("seq"))}}


def make_provider():
    return StubProvider()


# ===================================================================================================== ai.py gate
class AiExceptionTests(SimpleTestCase):
    def test_exception_carries_its_code_message_and_details(self):
        err = ai.AiRefused("UNCERTAINTY_REQUIRED", "state why", field="uncertainty")
        self.assertEqual((err.code, err.details, str(err)), ("UNCERTAINTY_REQUIRED", {"field": "uncertainty"}, "UNCERTAINTY_REQUIRED: state why"))

    def test_exception_without_a_message_is_the_bare_code(self):
        err = ai.AiRefused("TOOL_NOT_REGISTERED")
        self.assertEqual((str(err), err.details), ("TOOL_NOT_REGISTERED", {}))


class HandoffGateUnitTests(TestCase):
    setUp = AI.AiBase.setUp
    handoff = AI.AiBase.handoff
    # set by AiBase.setUp
    case: m.TsCase

    def test_catalog_ids_for_an_unregistered_runbook_is_none(self):
        self.assertIsNone(ai.catalog_ids_for(self.case))

    def test_exhaustion_report_accepts_a_fully_examined_catalog(self):
        report = ai.exhaustion_report(PROPOSER, self.case, catalog_ids=CATALOG)
        self.assertEqual((report["exhausted"], report["gaps"]), (True, []))

    def test_exhaustion_report_refuses_an_unexamined_or_missing_catalog(self):
        with self.subTest("an unexamined test is a gap"):
            report = ai.exhaustion_report(PROPOSER, self.case, catalog_ids=[*CATALOG, "HC99"])
            self.assertFalse(report["exhausted"])
            self.assertIn("HC99: no recorded outcome", " ".join(report["gaps"]))
        with self.subTest("an empty catalog cannot demonstrate exhaustion"):
            self.assertFalse(ai.exhaustion_report(PROPOSER, self.case, catalog_ids=[])["exhausted"])

    def test_handoff_document_of_another_tenant_is_denied(self):
        h = self.handoff()
        with self.assertRaises(repo.AccessDenied):
            ai.handoff_document(OTHER_TENANT, h.record_id)

    def test_close_handoff_never_reopens_a_closed_handoff_or_crosses_tenants(self):
        h = self.handoff()
        closed = ai.close_handoff(PROPOSER, h.record_id, status="ESCALATED", reason="model could not discriminate", now=T0)
        with self.subTest("a closed handoff is not reopened"):
            again = ai.close_handoff(PROPOSER, h.record_id, status="COMPLETED", reason="late", now=T0)
            self.assertEqual((closed.status, again.status), ("ESCALATED", "ESCALATED"))
        with self.subTest("another tenant is refused"), self.assertRaises(repo.AccessDenied):
            ai.close_handoff(OTHER_TENANT, h.record_id, status="BLOCKED", reason="x", now=T0)

    def test_resume_returns_the_checkpoint_and_clears_a_stale_inflight_marker(self):
        h = self.handoff()
        cp = h.checkpoint
        cp["inflight"], cp["inflight_until"] = "nonce-1", "2000-01-01T00:00:00Z"
        h.checkpoint = cp
        h.save()
        out = ai.resume(PROPOSER, h.record_id)
        self.assertEqual((out["status"], out["stale_inflight_cleared"]), ("OPEN", True))
        self.assertFalse(ai.resume(PROPOSER, h.record_id)["stale_inflight_cleared"])


# ============================================================================================ ai_runtime helpers
class ModelIoTests(SimpleTestCase):
    def test_load_provider_returns_the_configured_factory_product(self):
        provider = air.load_provider(f"{__name__}:make_provider")
        self.assertIsInstance(provider, StubProvider)

    @override_settings(TROUBLESHOOTING_AI_PROVIDER="")
    def test_load_provider_refuses_a_missing_or_unloadable_provider(self):
        for label, path in (("no configured provider", None), ("an unknown module", "core.nonexistent_ai_provider:make"),
                            ("a provider without complete()", f"{__name__}:OTHER_TENANT")):
            with self.subTest(f"{label} is refused"), self.assertRaises(air.ProviderUnavailable):
                air.load_provider(path)

    def test_load_research_broker_returns_the_isolated_worker_client(self):
        with override_settings(NMAS_TS_RESEARCH_WORKER={"socket": "/run/nmas/research.sock", "key_env": "TG_RESEARCH_KEY", "timeout": 3}), \
                mock.patch.dict(os.environ, {"TG_RESEARCH_KEY": "k" * 40}):
            client = air.load_research_broker("nmas-troubleshooter")
        self.assertEqual(client.ipc.principal, "nmas-troubleshooter")

    def test_load_research_broker_without_configuration_is_none(self):
        for label, cfg in (("no configuration", {}), ("no key", {"socket": "/run/x.sock"}), ("not a mapping", ["socket"])):
            with self.subTest(f"{label} gives no broker"), override_settings(NMAS_TS_RESEARCH_WORKER=cfg):
                self.assertIsNone(air.load_research_broker())

    def test_provider_identity_returns_the_declared_identity(self):
        self.assertEqual(air.provider_identity(StubProvider()), {"provider": "stub", "model_id": "stub-1", "model_version": "0"})

    def test_provider_identity_of_an_undeclared_provider_is_unknown(self):
        self.assertEqual(air.provider_identity(object()), {"provider": "object", "model_id": "unknown", "model_version": ""})

    def test_build_request_that_exceeds_the_bound_truncates_only_volatile_context(self):
        context = {"recent_tests": [{"test_id": f"HC{i:02d}", "summary": "x" * 400} for i in range(300)],
                   "last_result": {"ok": True, "error_code": "", "data": {"blob": "y" * 1000}}}
        req = air.build_request(context, identity={"provider": "stub"}, catalog=[], seq=1)
        self.assertEqual((len(req["context"]["recent_tests"]), req["context"]["last_result"]["data"]), (10, "truncated"))
        self.assertIn("Read-only investigation", req["instructions"])

    def test_validate_response_accepts_a_tool_or_conclude_action(self):
        tool = {"action": "tool", "tool": "get_case_summary", "args": {}}
        conclude = {"action": "conclude", "conclude": {"outcome": "INCONCLUSIVE", "summary": "s", "hypotheses": []}}
        self.assertEqual((air.validate_response(tool), air.validate_response(conclude)), (tool, conclude))

    def test_validate_response_rejects_malformed_responses(self):
        for label, resp in (("a non-object", []), ("another schema", {"schema": "x/1", "action": "tool", "tool": "t"}),
                            ("an extra field", {"action": "tool", "tool": "t", "command": "show run"}), ("an unknown action", {"action": "exec"}),
                            ("a nameless tool", {"action": "tool", "tool": ""}), ("a summary-less conclusion", {"action": "conclude", "conclude": {}}),
                            ("malformed hypotheses", {"action": "tool", "tool": "t", "hypotheses": ["x"]})):
            with self.subTest(f"{label} is rejected"), self.assertRaises(air.ModelResponseInvalid):
                air.validate_response(resp)

    def test_content_nonce_returns_the_same_nonce_for_an_identical_request(self):
        self.assertEqual(air.content_nonce("t", {"a": 1, "b": 2}), air.content_nonce("t", {"b": 2, "a": 1}))

    def test_content_nonce_of_different_arguments_is_a_mismatch(self):
        self.assertNotEqual(air.content_nonce("t", {"a": 1}), air.content_nonce("t", {"a": 2}))

    def test_continuation_result_as_dict_returns_every_field(self):
        out = air.ContinuationResult("COMPLETED", "HO-1", handoff_status="COMPLETED", model_requests=2).as_dict()
        self.assertEqual((out["status"], out["model_requests"], out["tool_calls"]), ("COMPLETED", 2, 0))


class RuntimeDiagnosticRunnerUnitTests(TestCase):
    setUp = AIR.Base.setUp
    # set by the runtime suite's Base.setUp
    case: m.TsCase
    deps: rt.RuntimeDeps
    runner: air.RuntimeDiagnosticRunner

    def test_runner_catalog_returns_the_runbook_tests(self):
        runner = air.RuntimeDiagnosticRunner(AIR.ACTOR, self.case.case_id, self.deps, scope_key="tg")
        self.assertEqual({t["test_id"] for t in runner.catalog()}, set(runner.read_only_tests))
        self.assertEqual(ai.catalog_ids_for(self.case), [t["test_id"] for t in runner.catalog()])

    def test_runner_run_returns_a_recorded_verdict_for_a_registered_test(self):
        result = self.runner.run("LF01", "R1", AIR.FORCE)
        self.assertEqual((result["test_id"], result["target"]), ("LF01", "R1"))
        self.assertIn(result["verdict"], ("PASS", "FAIL", "INCONCLUSIVE", "SKIPPED", "UNAVAILABLE"))
        self.assertEqual(self.runner.executed, [("LF01", "R1")])

    def test_runner_run_refuses_an_unregistered_test(self):
        with self.assertRaises(ai.AiRefused) as caught:
            self.runner.run("RAW_SHELL", "R1", {})
        self.assertEqual((caught.exception.code, self.runner.executed), ("TEST_NOT_READ_ONLY_ALLOWLISTED", []))
