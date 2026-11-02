"""Lab 7 closure -- Change validation and network-configuration validation run services, each called directly.

Fixtures are the Phase-13 helpers (a /31 pair that validates PASS; in-memory source bundles): no NetBox call, no device.
POSITIVE: runs are found through their Change, serialized, filtered, named and listed exactly; a running configuration
is assessed without remediation.  NEGATIVE: a malformed or foreign run id, unknown filter values, secret-shaped keys, a
never-run or changed Change and an empty postcheck all fail closed (None, ignored, redacted, NEVER_RUN/STALE, FAIL).
"""

from __future__ import annotations

import uuid
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from core import models
from core.services import change_validation_service as cvs
from core.services import network_config_validation as ncv
from core.tests.helpers import execution as x
from core.tests.helpers import validation as vh


class ChangeValidationRunTests(TestCase):
    def setUp(self):
        self.fixture = vh.simple_pass_change()
        self.run = vh.validate(self.fixture.change, self.fixture.sources)

    def test_build_source_snapshot_collects_the_read_only_bundle(self):
        bundle = vh.make_sources()
        with mock.patch.object(cvs.sources_module, "build_source_bundle", return_value=bundle) as build:
            self.assertIs(cvs.build_source_snapshot(self.fixture.change), bundle)
        build.assert_called_once_with()

    def test_build_source_snapshot_reports_an_outage_as_a_result_never_raising(self):
        down = vh.make_sources(netbox=None)
        with mock.patch.object(cvs.sources_module, "build_source_bundle", return_value=down):
            self.assertFalse(cvs.build_source_snapshot().netbox.available)

    def test_get_validation_run_through_its_change(self):
        self.assertEqual(cvs.get_validation_run(self.fixture.change, str(self.run.run_id)), self.run)

    def test_get_validation_run_none_for_a_malformed_or_foreign_id(self):
        other = vh.new_change("other")
        self.assertIsNone(cvs.get_validation_run(self.fixture.change, "not-a-uuid"))
        self.assertIsNone(cvs.get_validation_run(other, self.run.run_id))
        self.assertIsNone(cvs.get_validation_run(self.fixture.change, uuid.uuid4()))

    def test_serialize_validation_run_and_report_filename(self):
        found = cvs.serialize_validation_run(self.run)
        self.assertEqual((found["run_id"], found["change_id"], found["status"]), (str(self.run.run_id), self.fixture.change.change_id, self.run.status))
        self.assertEqual(cvs.report_filename(self.run), f"{self.fixture.change.change_id}-validation-{str(self.run.run_id)[:8]}.json")

    def test_serialize_validation_run_redacts_secret_shaped_keys_never_values_it_did_not_store(self):
        leaky = vh.clone_run(self.run, report={**self.run.report, "password": "hunter2-secret", "nested": [{"api_token": "abc"}]})
        found = cvs.serialize_validation_run(leaky)
        self.assertNotIn("hunter2-secret", str(found))
        self.assertNotIn("'abc'", str(found))

    def test_sanitize_report_keeps_ordinary_keys(self):
        self.assertEqual(cvs.sanitize_report({"device": "R1", "findings": [{"code": "X"}]}), {"device": "R1", "findings": [{"code": "X"}]})

    def test_sanitize_report_never_keeps_secret_keys_at_any_depth(self):
        self.assertEqual(cvs.sanitize_report({"a": [{"secret": "x", "b": {"password": "y"}}]}), {"a": [{"secret": "[REDACTED]", "b": {"password": "[REDACTED]"}}]})

    def test_report_filename_of_a_distinct_run_is_never_shared(self):
        other = vh.clone_run(self.run)
        self.assertNotEqual(cvs.report_filename(other), cvs.report_filename(self.run))


FINDINGS = [{"code": "A", "severity": "ERROR", "category": "ADDRESSING", "device": "R1", "related_devices": [], "blocking": True},
            {"code": "B", "severity": "WARNING", "category": "ROUTING", "device": "R2", "related_devices": ["R1"], "blocking": False}]


class PresentationTests(TestCase):
    def test_filter_findings_by_severity_category_device_and_blocking(self):
        self.assertEqual([f["code"] for f in cvs.filter_findings(FINDINGS, severity="WARNING", category="ROUTING")], ["B"])
        self.assertEqual([f["code"] for f in cvs.filter_findings(FINDINGS, severity="ERROR")], ["A"])
        self.assertEqual([f["code"] for f in cvs.filter_findings(FINDINGS, device="R1")], ["A", "B"])
        self.assertEqual([f["code"] for f in cvs.filter_findings(FINDINGS, blocking_only=True)], ["A"])

    def test_filter_findings_ignores_unknown_filter_values(self):
        self.assertEqual(cvs.filter_findings(FINDINGS, severity="NOT_A_SEVERITY", category="NOT_A_CATEGORY"), FINDINGS)
        self.assertEqual(cvs.filter_findings(FINDINGS, device="R9"), [])

    def test_dependency_rows_label_edges_and_mark_cycles(self):
        graph = {"nodes": [{"id": "n1", "label": "R1 Ethernet1"}, {"id": "n2", "label": "R1 OSPF"}],
                 "edges": [{"from": "n2", "to": "n1", "type": "BINDS", "status": "RESOLVED"}], "cycles": [["n1", "n2"]]}
        self.assertEqual(cvs.dependency_rows(graph), [{"object": "R1 OSPF", "depends_on": "R1 Ethernet1", "edge_type": "BINDS", "status": "RESOLVED", "reason": "", "in_cycle": True}])

    def test_dependency_rows_of_an_empty_graph_and_unlabelled_nodes(self):
        self.assertEqual(cvs.dependency_rows({}), [])
        row = cvs.dependency_rows({"edges": [{"from": "x", "to": "y", "type": "T", "status": "UNRESOLVED", "reason": "missing"}]})[0]
        self.assertEqual((row["object"], row["depends_on"], row["in_cycle"], row["reason"]), ("x", "y", False, "missing"))


class NetworkConfigRunTests(TestCase):
    def setUp(self):
        self.fixture = vh.simple_pass_change()
        self.sources = vh.make_sources(netbox=vh.netbox_data(managed_devices=["R1", "R2"], prefixes=[vh.nb_prefix("192.0.2.0/31")]))

    def test_latest_currency_list_and_serialize_after_a_candidate_run(self):
        run = ncv.validate_candidate(self.fixture.change, actor="alice", sources=self.sources)
        self.assertEqual(ncv.get_latest(self.fixture.change), run)
        self.assertEqual(ncv.get_latest(self.fixture.change, operations=(models.NetworkConfigValidationOperation.CANDIDATE,)), run)
        self.assertEqual(ncv.list_runs(self.fixture.change), [run])
        currency = ncv.get_currency(self.fixture.change, sources=self.sources)
        self.assertEqual((currency["state"], currency["reasons"]), ("CURRENT", []))
        found = ncv.serialize(run)
        self.assertEqual((found["run_id"], found["change_id"], found["created_by"], found["operation_type"]),
                         (str(run.run_id), self.fixture.change.change_id, "alice", models.NetworkConfigValidationOperation.CANDIDATE))

    def test_latest_none_currency_never_run_and_no_runs_before_any_validation(self):
        self.assertIsNone(ncv.get_latest(self.fixture.change))
        self.assertEqual(ncv.get_currency(self.fixture.change)["state"], "NEVER_RUN")
        self.assertEqual(ncv.list_runs(self.fixture.change), [])
        ncv.validate_candidate(self.fixture.change, sources=self.sources)
        self.assertIsNone(ncv.get_latest(self.fixture.change, operations=(models.NetworkConfigValidationOperation.RUNNING,)))
        self.assertEqual(ncv.list_runs(self.fixture.change, limit=0), [])

    def test_currency_is_stale_when_the_intent_or_the_sources_changed(self):
        ncv.validate_candidate(self.fixture.change, sources=self.sources)
        moved = vh.make_sources(netbox=vh.netbox_data(managed_devices=["R1"]))
        self.assertEqual(ncv.get_currency(self.fixture.change, sources=moved), {**ncv.get_currency(self.fixture.change, sources=moved), "state": "STALE",
                                                                                "reasons": ["SOURCE_CHANGED_OR_UNAVAILABLE"]})
        self.fixture.r1.address(self.fixture.r1.iface("Ethernet2"), "198.51.100.1/31")
        stale = ncv.get_currency(self.fixture.change, sources=self.sources)
        self.assertEqual((stale["state"], stale["reasons"]), ("STALE", ["ACCEPTED_INTENT_CHANGED"]))

    def test_validate_running_assesses_a_clean_configuration_read_only(self):
        snapshot = models.RunningConfigSnapshot.objects.create(device_name="R1", platform=models.Platform.ARISTA_CEOS, digest="b" * 64,
                                                               text="hostname R1\ninterface Ethernet1\n   ip address 192.0.2.0/31\n", line_count=3,
                                                               source="test", captured_at=timezone.now())
        run = ncv.validate_running(snapshot, actor="bob", sources=self.sources)
        self.assertEqual((run.operation_type, run.device, run.input_hash, run.created_by), (models.NetworkConfigValidationOperation.RUNNING, "R1", "b" * 64, "bob"))
        self.assertEqual(run.semantic_result, {"auto_remediation": False})
        self.assertNotEqual(run.status, models.NetworkConfigValidationStatus.BLOCKED)


class LiveValidationRecordTests(TestCase):
    """The post-write record of a finished fake execution (FakeWorld: no device), read from its Phase-15 postcheck."""

    def setUp(self):
        self.run = x.run(x.prepared(), x.FakeWorld()).run
        self.op = self.run.postcheck_run

    def test_record_live_validation_of_a_clean_postcheck_is_verified(self):
        found = ncv.record_live_validation(self.run, self.op, actor="carol")
        self.assertEqual((found.operation_type, found.status, found.created_by),
                         (models.NetworkConfigValidationOperation.POST_PUSH, models.NetworkConfigValidationStatus.PASS, "carol"))
        self.assertEqual(found.live_result, {"operational_status": self.op.status, "operational_run_id": str(self.op.run_id), "post_write_verified": True})
        self.assertEqual({row["status"] for row in found.checks}, {"PASS"})
        self.assertEqual(found.provenance, {"execution_run_id": str(self.run.run_id), "plan_id": str(self.run.plan.plan_id)})

    def test_record_live_validation_without_evidence_or_with_a_failed_check_is_not_verified(self):
        self.op.report = {"results": []}
        empty = ncv.record_live_validation(self.run, self.op)
        self.assertEqual(([row["check"] for row in empty.checks], empty.status, empty.live_result["post_write_verified"]),
                         (["LIVE_EVIDENCE"], models.NetworkConfigValidationStatus.FAIL, False))
        self.op.report = {"results": [{"check_code": "ROUTE", "status": "FAIL", "device": "R1"}, {"requirement": "LINK", "status": "UNKNOWN"}]}
        failed = ncv.record_live_validation(self.run, self.op)
        self.assertEqual([(row["check"], row["status"]) for row in failed.checks], [("LIVE_ROUTE", "FAIL"), ("LIVE_LINK", "BLOCKED")])
        self.assertEqual(failed.status, models.NetworkConfigValidationStatus.FAIL)
