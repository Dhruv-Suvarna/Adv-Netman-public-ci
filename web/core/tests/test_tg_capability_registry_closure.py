"""Lab 7 closure -- the capability evidence registry and per-cell assessments, each called directly.

This is the code behind the binary SUPPORTED / UNSUPPORTED matrix, so both directions are pinned exactly.  POSITIVE: a
cell whose fourteen probes all pass live is complete and SUPPORTED, its record reads LIVE_VERIFIED, and persisted rows
come back as the same assessment.  NEGATIVE: a failed prerequisite gates the live stages, an incomplete or merely
claimed live probe never turns a cell green, a failed live axis reads LIVE_FAILED, and the ledger refuses a cell
outside the selection.  Pure model code and the test database only: no runtime is booted and no device is contacted.
"""

from __future__ import annotations

import dataclasses

from django.test import TestCase

from core import models
from core.services.capabilities import assessment, batch, evidence, features, registry
from core.services.capabilities.axes import Axis, EvidenceKind, EvidenceStatus, Summary, TerminalStatus

HEAD = "4adec06ef04161d01340a1b94e5e1b2440a7e37c"
CELL = ("arista_ceos", "interface.LOOPBACK")


def probe(name, outcome="PASS", reason=""):
    live = name in assessment.LIVE_PROBES
    return {"outcome": outcome, "detail": "observed", "reason": reason, "test_type": "LIVE" if live else "FIXTURE",
            "reference": "live:cap-test" if live else "fixture:cap-test"}


def supported_cell(platform=CELL[0], feature=CELL[1]):
    return assessment.CellAssessment(platform, feature, HEAD, "ceos:4.36.2F", {name: probe(name) for name in assessment.PROBES})


def gated_cell():
    probes = {name: probe(name) for name in assessment.PROBES}
    probes["renderer"] = probe("renderer", "FAIL", "RENDERER_ABSENT")
    for name in assessment.LIVE_PROBES:
        probes[name] = {**probe(name, "BLOCKED", "RENDERER_ABSENT"), "reference": f"{assessment.GATE_PREFIX}arista_ceos/interface.LOOPBACK"}
    return assessment.CellAssessment(*CELL, HEAD, "ceos:4.36.2F", probes)


def verified(axes, *names, status=EvidenceStatus.VERIFIED):
    out = dict(axes)
    for axis in names:
        out[axis] = dataclasses.replace(out[axis], status=status, kind=EvidenceKind.EMPIRICAL)
    return out


class CellAssessmentTests(TestCase):
    def test_a_fully_live_cell_is_complete_and_supported(self):
        cell = supported_cell()
        self.assertEqual((cell.complete, cell.status, cell.blockers, cell.gated, cell.reasons), (True, "SUPPORTED", [], False, []))
        found = cell.as_dict()
        self.assertEqual((found["final_status"], found["assessment_basis"], found["strongest_test_type"], found["postcheck"]),
                         ("SUPPORTED", "RUNTIME_INVESTIGATION", "LIVE", "PASS"))
        self.assertEqual(found["evidence_references"], ["fixture:cap-test", "live:cap-test"])

    def test_a_prerequisite_failure_gates_the_cell_unsupported(self):
        cell = gated_cell()
        self.assertEqual((cell.complete, cell.status, cell.blockers, cell.gated, cell.reasons), (True, "UNSUPPORTED", ["renderer"], True, ["RENDERER_ABSENT"]))
        self.assertEqual(cell.as_dict()["assessment_basis"], "PREREQUISITE_GATE")

    def test_a_cell_with_a_pending_or_claimed_live_probe_is_never_complete(self):
        pending = supported_cell()
        pending.probes["live_write"] = {**probe("live_write"), "outcome": "PENDING"}
        claimed = supported_cell()
        claimed.probes["live_write"] = {**probe("live_write"), "test_type": "FIXTURE"}
        unreasoned = supported_cell()
        unreasoned.probes["executor"] = probe("executor", "FAIL", "")
        for name, cell in (("pending", pending), ("claimed", claimed), ("unreasoned", unreasoned)):
            with self.subTest(case=f"incomplete {name}"):
                self.assertEqual((cell.complete, cell.status), (False, "UNSUPPORTED"))
        self.assertEqual(pending.as_dict()["assessment_basis"], "INCOMPLETE")

    def test_persisted_rows_return_the_same_assessment(self):
        cell = supported_cell()
        assessment.persist(cell, actor="tester")
        found = assessment.latest_assessments()[CELL]
        self.assertEqual((found.platform, found.feature, found.repository_head, found.probes, found.assessment_id, found.status),
                         (*CELL, HEAD, cell.probes, cell.assessment_id, "SUPPORTED"))
        self.assertEqual(found.evidence_ids, cell.evidence_ids)

    def test_from_row_of_an_incomplete_assessment_is_unsupported(self):
        cell = supported_cell()
        cell.probes["compensation"] = {**probe("compensation"), "outcome": "PENDING"}
        assessment.persist(cell, actor="tester")
        found = assessment.from_row(models.CapabilityAssessment.objects.get(pk=cell.assessment_id))
        self.assertEqual((found.complete, found.status), (False, "UNSUPPORTED"))

    def test_last_observed_runtime_reports_only_live_contacted_cells(self):
        live = supported_cell()
        self.assertEqual(batch.last_observed_runtime({CELL: live}), {"arista_ceos": "ceos:4.36.2F"})
        self.assertEqual(batch.BatchResult(actions={"a": "SKIPPED", "b": "ASSESSED", "c": "SKIPPED"}).counts(), {"ASSESSED": 1, "SKIPPED": 2})

    def test_last_observed_runtime_never_reports_gated_or_unversioned_cells(self):
        unversioned = supported_cell(feature="interface.SVI")
        unversioned.runtime_version = ""
        self.assertEqual(batch.last_observed_runtime({CELL: gated_cell(), ("arista_ceos", "interface.SVI"): unversioned}), {})


class RegistryDerivationTests(TestCase):
    def axes(self, platform="arista_ceos", key="interface.LOOPBACK"):
        return registry.registry_axes(platform, features.by_key()[key])

    def test_derive_summary_and_terminal_status_of_fully_verified_axes(self):
        axes = verified(self.axes(), *Axis)
        self.assertEqual((registry.derive_summary(axes), registry.resolve_terminal_status(axes)), (Summary.LIVE_VERIFIED, TerminalStatus.SUPPORTED))
        record = registry.CapabilityRecord("arista_ceos", features.by_key()["interface.LOOPBACK"], axes)
        self.assertEqual((record.summary_label, record.unsupported_reason), (registry.SUMMARY_LABELS[Summary.LIVE_VERIFIED],
                                                                             "All mandatory implementation and empirical axes are satisfied."))
        self.assertEqual(axes[Axis.LIVE_WRITE].label, registry.AXIS_LABELS[Axis.LIVE_WRITE])

    def test_derive_summary_and_terminal_status_fail_closed_for_failed_or_claimed_axes(self):
        failed = verified(verified(self.axes(), *Axis), Axis.COMPENSATION, status=EvidenceStatus.FAILED)
        self.assertEqual((registry.derive_summary(failed), registry.resolve_terminal_status(failed)), (Summary.LIVE_FAILED, TerminalStatus.UNSUPPORTED))
        claimed = dict(verified(self.axes(), *Axis))
        claimed[Axis.LIVE_WRITE] = dataclasses.replace(claimed[Axis.LIVE_WRITE], kind=EvidenceKind.REGISTRY)
        self.assertEqual(registry.resolve_terminal_status(claimed), TerminalStatus.UNSUPPORTED)
        record = registry.CapabilityRecord("arista_ceos", features.by_key()["interface.LOOPBACK"], failed)
        self.assertTrue(record.unsupported_reason.startswith(f"{registry.AXIS_LABELS[Axis.COMPENSATION]} failed: "))

    def test_registry_axes_never_claim_live_support_without_an_executor(self):
        axes = self.axes("cisco_iosxr")
        self.assertEqual((axes[Axis.RENDERER].status, axes[Axis.LIVE_WRITE].status), (EvidenceStatus.IMPLEMENTED, EvidenceStatus.NOT_IMPLEMENTED))
        self.assertEqual(registry.derive_summary(axes), Summary.RENDER_ONLY)

    def test_evidence_matrix_counts_every_cell_once(self):
        matrix = registry.evidence_matrix()
        self.assertEqual(sum(matrix["summary_counts"].values()), 396)
        self.assertEqual(matrix["assessment_counts"]["total"], 396)
        self.assertEqual(len(matrix["rows"]), len(features.catalogue()))
        self.assertEqual(len(registry.evidence_matrix(family="interface")["rows"]), sum(f.family == "interface" for f in features.catalogue()))

    def test_latest_evidence_prefers_live_over_newer_static_rows(self):
        common = dict(platform="arista_ceos", feature="interface.LOOPBACK", axis="LIVE_WRITE", source="t", repository_head=HEAD, recorded_by="t")
        live = evidence.record_evidence(status=EvidenceStatus.VERIFIED, evidence_type="LIVE", evidence_ref="live:a", **common)
        evidence.record_evidence(status=EvidenceStatus.FAILED, evidence_type="STATIC", evidence_ref="static:b", **common)
        self.assertEqual(evidence.latest_evidence()[("arista_ceos", "interface.LOOPBACK", "LIVE_WRITE")].pk, live.pk)


class LedgerTests(TestCase):
    def test_matrix_report_and_summary_of_one_supported_cell(self):
        assessment.persist(supported_cell(), actor="tester")
        report = batch.matrix_report(platforms=["arista_ceos"], keys=["interface.LOOPBACK"])
        self.assertEqual((report["total"], report["assessed"], report["supported"], report["unassessed"]), (1, 1, 1, 0))
        markdown = batch.summary_markdown(report)
        self.assertIn("**COMPLETE** — total 1, assessed 1, unassessed 0, supported 1, unsupported 0", markdown)
        self.assertIn("- `arista_ceos` `interface.LOOPBACK`", markdown)

    def test_matrix_report_without_assessments_is_incomplete_and_lists_none(self):
        report = batch.matrix_report(platforms=["arista_ceos"], keys=["interface.LOOPBACK", "interface.SVI"])
        self.assertEqual((report["assessed"], report["unassessed"], report["supported"]), (0, 2, 0))
        markdown = batch.summary_markdown(report)
        self.assertIn("**INCOMPLETE** — total 2, assessed 0, unassessed 2, supported 0, unsupported 2", markdown)
        self.assertIn("## Supported cells\n\n- none", markdown)
        with self.assertRaises(ValueError):
            assessment.report([supported_cell(platform="arista_ceos")], selected_platforms=["sonic"])
