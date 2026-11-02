"""Lab 7 closure -- Health run persistence, the Fleet snapshot record, postcheck recording, scope evidence collection
and the plan evaluator entry point, each called directly.

Only the test database is written; telemetry is synthetic and live reads are disabled or faked, so no device or
monitoring system is contacted.  POSITIVE: a bounded report, a stored run read back by id / mode / device, a
serialized fleet and snapshot run, a PASS postcheck and satisfied plan requirements.  NEGATIVE: an oversized report
drops its heavy sections, a secret-shaped key never survives serialization, a malformed or unknown run id is None,
a failed evaluation adds the plan-level FAIL row, and an unmanaged scope device is marked NOT_MANAGED without a live
read.
"""

from __future__ import annotations

import uuid
from unittest import mock

from django.test import TestCase

from core import models
from core.services import health_service
from core.services.health import evaluators, persistence, postchecks, prechecks, requirements, results, scope
from core.services.health.codes import CheckStatus as S, Health, Mode, Phase, PostcheckResult, Role
from core.services.health.fleet import get_fleet_health
from core.tests.helpers import execution as x
from core.tests.helpers import health as h


def check(status=S.PASS, device="R1"):
    return results.CheckResult("DEVICE_REACHABLE" if status == S.PASS else "DEVICE_UNREACHABLE", status, device, "m", "LIVE")


class ReportTests(TestCase):
    def test_build_report_returns_counts_rows_and_summary(self):
        report, summary = persistence.build_report(Mode.DEVICE_DEEP, Health.HEALTHY, [check()], {"facts": {"x": 1}, "summary": {"device": "R1"}})
        self.assertEqual((report["mode"], report["status"], report["counts"]["PASS"], report["results_truncated"], report["facts"]),
                         (Mode.DEVICE_DEEP, Health.HEALTHY, 1, False, {"x": 1}))
        self.assertNotIn("truncated_sections", report)
        self.assertEqual(summary, {"counts": report["counts"], "results": 1, "results_truncated": False, "device": "R1"})

    def test_build_report_never_keeps_heavy_sections_when_oversized(self):
        heavy = {f"k{i}": "v" * 200 for i in range(25)}
        with mock.patch.object(persistence, "MAX_REPORT_BYTES", 2000):
            report, _summary = persistence.build_report(Mode.DEVICE_DEEP, Health.UNKNOWN, [check()], {"evidence": heavy, "facts": heavy, "fleet_devices": heavy})
        self.assertEqual(report["truncated_sections"], ["evidence", "facts", "fleet_devices"])
        self.assertNotIn("evidence", report)

    def test_bound_document_preserves_non_secret_documents(self):
        document = {"run": {"status": "PASS", "credential_ref": "runtime://x"}, "rows": [{"a": 1}]}
        self.assertEqual(persistence.bound_document(document), document)

    def test_bound_document_never_keeps_secret_keys_at_any_depth(self):
        found = persistence.bound_document({"rows": [{"password": "fake-Secret-2", "ok": True}], "token": "fake-Token-3"})
        self.assertEqual(found, {"rows": [{"password": "[REDACTED]", "ok": True}], "token": "[REDACTED]"})


class StoredRunTests(TestCase):
    def record(self, device="R1", mode=Mode.DEVICE_DEEP):
        return persistence.record_run(mode=mode, status=Health.HEALTHY, results=[check(device=device)], actor="tester", device=device)

    def test_stored_runs_are_returned_by_id_mode_and_device(self):
        first, second, other = self.record(), self.record(), self.record("S1")
        self.assertEqual(persistence.get_run(str(first.run_id)), first)
        self.assertEqual(persistence.recent_runs(mode=Mode.DEVICE_DEEP, device="R1"), [second, first])
        self.assertEqual(persistence.latest_run(mode=Mode.DEVICE_DEEP, device="S1"), other)
        document = persistence.serialize_health_run(first)
        self.assertEqual((document["run_id"], document["mode"], document["device"], document["created_by"], document["change_id"]),
                         (str(first.run_id), Mode.DEVICE_DEEP, "R1", "tester", ""))

    def test_malformed_or_unknown_run_ids_and_empty_history_are_none(self):
        self.assertEqual((persistence.get_run("not-a-uuid"), persistence.get_run(uuid.uuid4()), persistence.latest_run(mode=Mode.CHANGE_POSTCHECK)),
                         (None, None, None))
        self.assertEqual(persistence.recent_runs(mode=Mode.FLEET_QUICK, limit=0), [])

    def test_serialize_health_run_never_exposes_a_secret_shaped_key(self):
        run = self.record()
        models.OperationalCheckRun.objects.filter(pk=run.pk).update(report={"api_secret": "fake-Secret-4", "status": "x"})
        document = persistence.serialize_health_run(models.OperationalCheckRun.objects.get(pk=run.pk))
        self.assertEqual(document["report"], {"api_secret": "[REDACTED]", "status": "x"})


class FleetSnapshotTests(TestCase):
    def test_serialize_fleet_and_record_fleet_snapshot_return_the_fleet_document(self):
        fleet = get_fleet_health(snapshot=h.snapshot(), now=h.NOW, include_sources=False)
        document = health_service.serialize_fleet(fleet)
        self.assertEqual((document["overall"], document["topology_available"], document["counts"]["total"]), (Health.HEALTHY, True, len(h.MANAGED)))
        run = health_service.record_fleet_snapshot(actor="tester", fleet=fleet)
        self.assertEqual((run.mode, run.status, len(run.report["fleet_devices"]), run.created_by), (Mode.FLEET_QUICK, Health.HEALTHY, len(h.MANAGED), "tester"))
        self.assertEqual(models.AuditEvent.objects.filter(object_id=str(run.run_id)).count(), 1)

    def test_serialize_fleet_and_snapshot_of_an_unavailable_topology_are_unknown(self):
        fleet = get_fleet_health(snapshot=h.snapshot(summary=h.unavailable_topology()), now=h.NOW, include_sources=False)
        document = health_service.serialize_fleet(fleet)
        self.assertEqual((document["overall"], document["topology_available"], document["counts"]["unknown"]), (Health.UNKNOWN, False, len(h.MANAGED)))
        run = health_service.record_fleet_snapshot(fleet=fleet)
        self.assertEqual((run.status, run.report["conditions"][0]["status"]), (Health.UNKNOWN, S.FAIL))


class PlanRunTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.plan = x.prepared().plan

    def evaluation(self, result, statuses):
        rows = [results.CheckResult("DEVICE_REACHABLE", status, "R1", "m", "LIVE", cfg_id=f"CFG-{i}") for i, status in enumerate(statuses)]
        return evaluators.RequirementEvaluation(Phase.POSTCHECK, result, rows, results.count_by_status(rows), {"total": len(rows)})

    def test_record_postcheck_run_stores_a_passing_evaluation(self):
        run = postchecks.record_postcheck_run(self.plan, self.evaluation(PostcheckResult.PASS, [S.PASS]), actor="tester", cfg_ids={"CFG-0"})
        self.assertEqual((run.mode, run.status, run.plan_id, run.change_id, run.report["cfg_ids"]), (Mode.CHANGE_POSTCHECK, "PASS", self.plan.pk, self.plan.change_id, ["CFG-0"]))
        self.assertEqual(run.report["provenance"]["plan_hash"], self.plan.plan_hash)

    def test_record_postcheck_run_of_a_failed_evaluation_adds_the_plan_level_failure(self):
        run = postchecks.record_postcheck_run(self.plan, self.evaluation(PostcheckResult.FAIL, [S.FAIL, S.PASS]))
        failure = [r for r in run.report["results"] if r["check_code"] == "POSTCHECK_REQUIREMENT_FAILED"]
        self.assertEqual((run.status, len(failure), failure[0]["observed"], failure[0]["role"]), ("FAIL", 1, {"failed": ["CFG-0:DEVICE_REACHABLE"]}, Role.PLAN))

    def test_evaluate_plan_requirements_passes_satisfied_postcheck_evidence(self):
        reqs = requirements.normalize_plan(self.plan)
        found = evaluators.evaluate_plan_requirements(self.plan, Phase.POSTCHECK, h.satisfied_evidence(reqs))
        self.assertEqual((found.phase, found.result), (Phase.POSTCHECK, PostcheckResult.PASS))
        self.assertEqual(found.counts["FAIL"], 0)

    def test_collect_scope_evidence_returns_telemetry_for_each_scope_device(self):
        affected = scope.build_affected_scope(self.plan)
        with mock.patch("core.services.health.live.read_device", side_effect=AssertionError("no live read")):
            found = prechecks.collect_scope_evidence(affected, h.snapshot(), live_reads=False, dhcp_needed=True, dhcp_state={"nmas": {}}, now=h.NOW)
        self.assertEqual(sorted(found.devices), affected.names())
        self.assertEqual((found.pipeline["available"], found.services, found.device(affected.names()[0]).group("telemetry").available),
                         (True, {"dhcp": {"nmas": {}}}, True))

    def test_collect_scope_evidence_marks_unmanaged_devices_without_a_live_read(self):
        affected = scope.AffectedScope(devices={"GHOST": scope.ScopeDevice("GHOST", Role.PEER)})
        with mock.patch("core.services.health.live.read_device", side_effect=AssertionError("no live read")):
            found = prechecks.collect_scope_evidence(affected, h.snapshot(summary=h.unavailable_topology()), now=h.NOW)
        self.assertEqual((found.device("GHOST").live_error, found.pipeline["available"], found.services), ("NOT_MANAGED", False, {}))
