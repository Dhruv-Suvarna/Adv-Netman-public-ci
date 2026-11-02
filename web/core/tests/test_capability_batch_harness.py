"""Batch capability harness: prerequisite gate, individual evidence, completeness."""

import json
import tempfile
from copy import deepcopy
from io import StringIO
from pathlib import Path

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase

from core import models
from core.services.capabilities import assessment, batch, features
from core.services.capabilities.offline_verify import verify_cell

HEAD = "4adec06ef04161d01340a1b94e5e1b2440a7e37c"
SURVIVOR = ("arista_ceos", "service_policy.FHRP_VARP_IPV4")   # every NMAS prerequisite layer passes offline
GATED = ("arista_ceos", "interface.LAG")                      # renderer absent


class CommittedLedgerCompletenessTests(SimpleTestCase):
    def test_exhaustive_matrix_has_no_unassessed_cells(self):
        ledger = Path(__file__).resolve().parents[3] / "docs/evidence/v2-phase4-exhaustive/progress-ledger.json"
        report = json.loads(ledger.read_text())
        self.assertEqual((report["total"], report["assessed"], report["unassessed"]), (396, 396, 0))
        self.assertEqual(len(report["cells"]), 396)
        self.assertTrue(all(cell["assessment_complete"] for cell in report["cells"]))
        batch.check_report(report)


def _live_pass(cell):
    cell.runtime_version = "test-runtime"
    for name in assessment.LIVE_PROBES:
        cell.probes[name] = assessment.probe("PASS", "isolated behavioural probe passed", test_type="LIVE",
                                             reference="live:test-lab/probe")


class FullMatrixBatchTests(TestCase):
    """One batch over the whole matrix; no runtime is contacted."""

    @classmethod
    def setUpTestData(cls):
        cls.platforms, cls.keys = batch.select()
        cls.outcome = batch.assess_batch(cls.platforms, cls.keys, head=HEAD, actor="test")
        cls.report = batch.matrix_report()
        cls.cells = {(c["platform"], c["feature"]): c for c in cls.report["cells"]}

    def test_every_platform_and_feature_is_enumerated(self):
        self.assertEqual(set(self.platforms), set(features.platforms()))
        self.assertEqual(set(self.keys), set(features.by_key()))
        expected = {(p, k) for p in features.platforms() for k in features.by_key()}
        self.assertEqual(len(expected), 396)
        self.assertEqual(set(self.outcome.actions), expected)
        self.assertEqual(set(self.cells), expected)

    def test_every_cell_received_its_own_deliberate_record(self):
        self.assertEqual(models.CapabilityAssessment.objects.count(), 396)
        self.assertNotIn(batch.KEPT, self.outcome.actions.values())
        for key, cell in self.cells.items():
            offline = [n for n in assessment.PROBES if n not in assessment.LIVE_PROBES]
            self.assertTrue(all(cell["probes"][n]["outcome"] in {"PASS", "FAIL", "BLOCKED"} for n in offline), key)
            self.assertTrue(cell["repository_head"] and cell["timestamp"] and cell["evidence_ids"], key)

    def test_family_gate_emits_individual_cell_evidence(self):
        gated = [c for c in self.cells.values() if c["assessment_basis"] == "PREREQUISITE_GATE"]
        self.assertGreater(len(gated), 100)
        references = [c["probes"]["live_write"]["reference"] for c in gated]
        self.assertEqual(len(set(references)), len(gated))        # no shared blanket reference
        for cell in gated:
            self.assertTrue(cell["assessment_complete"])
            self.assertEqual(cell["final_status"], "UNSUPPORTED")
            self.assertIn(f"{cell['platform']}/{cell['feature']}@", cell["probes"]["live_write"]["reference"])
            self.assertIn(cell["probes"]["live_write"]["reason"], cell["unsupported_reasons"])
            self.assertTrue(cell["runtime_version"])
            self.assertEqual(cell["live_write"], "BLOCKED")

    def test_missing_prerequisite_marks_cell_assessed_and_unsupported(self):
        cell = self.cells[GATED]
        self.assertEqual(self.outcome.actions[GATED], batch.GATED)
        self.assertEqual((cell["assessment_complete"], cell["final_status"], cell["renderer"]), (True, "UNSUPPORTED", "FAIL"))
        self.assertIn("RENDERER_ABSENT", cell["unsupported_reasons"])
        self.assertIn("No device was contacted", cell["probes"]["runtime_validation"]["detail"])

    def test_cells_passing_every_prerequisite_stay_unassessed_without_live_probe(self):
        self.assertEqual(self.outcome.actions[SURVIVOR], batch.PENDING_LIVE)
        self.assertFalse(self.cells[SURVIVOR]["assessment_complete"])
        self.assertGreater(self.report["unassessed"], 0)
        with self.assertRaises(ValueError):
            assessment.require_complete(self.report)

    def test_report_totals_and_binary_vocabulary(self):
        report = self.report
        self.assertEqual(report["total"], 396)
        self.assertEqual(report["assessed"] + report["unassessed"], 396)
        self.assertEqual(report["supported"] + report["unsupported"], 396)
        self.assertEqual(report["assessed"], sum(c["assessment_complete"] for c in report["cells"]))
        self.assertEqual(report["supported"], 0)                  # nothing is green without live evidence
        self.assertEqual(sum(r["assessed"] for r in report["per_platform"].values()), report["assessed"])
        self.assertEqual({c["final_status"] for c in report["cells"]}, {"UNSUPPORTED"})
        for cell in report["cells"]:
            if cell["assessment_complete"]:
                self.assertTrue(cell["unsupported_reasons"], cell["feature"])
                self.assertFalse({r["outcome"] for r in cell["probes"].values()} & {"PENDING", "UNKNOWN", "NOT_TESTED", ""})
        self.assertEqual({r["feature"] for r in report["remaining_cells"]} | {""}, {
            c["feature"] for c in report["cells"] if not c["assessment_complete"]} | {""})
        summary = batch.summary_markdown(report)
        self.assertIn("**INCOMPLETE**", summary)
        self.assertIn(f"assessed {report['assessed']}, unassessed {report['unassessed']}", summary)

    def test_rerun_keeps_completed_assessments(self):
        before = models.CapabilityAssessment.objects.filter(platform=GATED[0], feature=GATED[1]).count()
        again = batch.assess_batch((GATED[0],), (GATED[1],), head=HEAD, actor="test")
        self.assertEqual(again.actions[GATED], batch.KEPT)
        self.assertEqual(models.CapabilityAssessment.objects.filter(platform=GATED[0], feature=GATED[1]).count(), before)
        forced = batch.assess_batch((GATED[0],), (GATED[1],), head=HEAD, actor="test", reassess=True)
        self.assertEqual(forced.actions[GATED], batch.GATED)
        self.assertEqual(models.CapabilityAssessment.objects.filter(platform=GATED[0], feature=GATED[1]).count(), before + 1)


class GateContractTests(TestCase):
    def test_gate_refuses_cell_whose_prerequisites_all_pass(self):
        cell = verify_cell(*[SURVIVOR[0], features.by_key()[SURVIVOR[1]]], head=HEAD)
        self.assertFalse(batch.apply_gate(cell))
        self.assertEqual(cell.probes["live_write"]["outcome"], "PENDING")
        # A hand-forged gate reference is not an assessment either.
        for name in assessment.LIVE_PROBES:
            cell.probes[name] = assessment.probe("BLOCKED", "forged", reason="EXECUTOR_ABSENT", test_type="STATIC",
                                                 reference="gate:forged")
        cell.runtime_version = "x"
        self.assertFalse(cell.complete)

    def test_live_evidence_is_not_replaced_by_a_batch(self):
        cell = verify_cell(SURVIVOR[0], features.by_key()[SURVIVOR[1]], head=HEAD)
        _live_pass(cell)
        row = assessment.persist(cell, actor="test")
        outcome = batch.assess_batch((SURVIVOR[0],), (SURVIVOR[1],), head=HEAD, actor="test")
        self.assertEqual(outcome.actions[SURVIVOR], batch.KEPT)
        self.assertEqual(assessment.latest_assessments()[SURVIVOR].assessment_id, row.pk)

    def test_registered_live_probe_completes_surviving_cell(self):
        outcome = batch.assess_batch((SURVIVOR[0],), (SURVIVOR[1],), head=HEAD, actor="test", live_probes={SURVIVOR: _live_pass})
        self.assertEqual(outcome.actions[SURVIVOR], batch.LIVE)
        report = batch.matrix_report((SURVIVOR[0],), (SURVIVOR[1],))
        self.assertEqual((report["assessed"], report["supported"], report["unassessed"]), (1, 1, 0))
        assessment.require_complete(report)

    def test_failed_live_probe_leaves_cell_unassessed(self):
        def boom(cell):
            cell.probes["live_write"] = assessment.probe("PASS", "half done", test_type="LIVE", reference="live:x")
            raise RuntimeError("lab unavailable")

        outcome = batch.assess_batch((SURVIVOR[0],), (SURVIVOR[1],), head=HEAD, actor="test", live_probes={SURVIVOR: boom})
        self.assertEqual(outcome.actions[SURVIVOR], batch.LIVE_ERROR)
        self.assertIn("RuntimeError", outcome.errors[SURVIVOR])
        latest = assessment.latest_assessments()[SURVIVOR]
        self.assertFalse(latest.complete)
        self.assertEqual(latest.probes["live_write"]["outcome"], "PENDING")

    def test_supported_requires_mandatory_live_evidence(self):
        cell = verify_cell(SURVIVOR[0], features.by_key()[SURVIVOR[1]], head=HEAD)
        _live_pass(cell)
        report = assessment.report([cell], selected_platforms=(SURVIVOR[0],), selected_features=(SURVIVOR[1],))
        batch.check_report(report)
        for name, change in (("compensation", {"test_type": "FIXTURE"}), ("live_write", {"reference": "gate:x"}),
                             ("renderer", {"outcome": "FAIL"})):
            doctored = deepcopy(report)
            doctored["cells"][0]["probes"][name].update(change)
            with self.subTest(name=name), self.assertRaises(ValueError):
                batch.check_report(doctored)

    def test_unsupported_requires_classified_reason_and_no_unknown_escapes(self):
        with self.assertRaises(ValueError):
            assessment.probe("FAIL", "no reason")
        with self.assertRaises(ValueError):
            assessment.probe("BLOCKED", "invented", reason="NOT_TESTED")
        with self.assertRaises(ValueError):
            assessment.probe("UNKNOWN", "x")
        cell = verify_cell(GATED[0], features.by_key()[GATED[1]], head=HEAD)
        self.assertTrue(batch.apply_gate(cell))
        report = assessment.report([cell], selected_platforms=(GATED[0],), selected_features=(GATED[1],))
        batch.check_report(report)
        for mutate in (lambda c: c.update(unsupported_reasons=[]), lambda c: c.update(final_status="UNKNOWN"),
                       lambda c: c.update(unsupported_reasons=["PENDING"]),
                       lambda c: c["probes"]["live_read"].update(outcome="PENDING")):
            doctored = deepcopy(report)
            mutate(doctored["cells"][0])
            with self.assertRaises(ValueError):
                batch.check_report(doctored)
        doctored = deepcopy(report)
        doctored["assessed"] = 0
        with self.assertRaises(ValueError):
            batch.check_report(doctored)

    def test_selection_by_family_and_match(self):
        _, nat = batch.select("arista_ceos", family="service_policy", match="NAT_")
        self.assertEqual(len(nat), 11)
        self.assertTrue(all(".NAT_" in key for key in nat))
        _, interfaces = batch.select("all", family="interface")
        self.assertEqual(len(interfaces), 16)
        with self.assertRaises(ValueError):
            batch.select("arista_ceos", match="NO_SUCH_FEATURE")


class VerifyMatrixCommandTests(TestCase):
    def test_family_batch_writes_ledger_and_fails_while_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger, summary = Path(tmp) / "ledger.json", Path(tmp) / "summary.md"
            args = ("nmas_capabilities", "verify-matrix", "--platform", "arista_ceos", "--family", "service_policy",
                    "--match", "FHRP_", "--remaining", "--report", str(ledger), "--summary", str(summary))
            with self.assertRaisesMessage(CommandError, "still require probes"):
                call_command(*args, stdout=StringIO())
            out = StringIO()
            call_command(*args, "--allow-incomplete", stdout=out)
            data = json.loads(ledger.read_text())
            self.assertEqual((data["total"], data["assessed"], data["unassessed"], data["supported"]), (10, 8, 2, 0))
            self.assertIn("IN-PROGRESS", out.getvalue())
            self.assertIn("FHRP_VARP_IPV4", summary.read_text())
            for cell in data["cells"]:
                for field in ("platform", "feature", "assessment_complete", "status", "unsupported_reasons", "strongest_test_type",
                              "semantic", "renderer", "parser", "validator", "executor", "live_read", "live_write", "postcheck",
                              "compensation", "runtime_test", "evidence_references", "repository_head", "runtime_version", "timestamp"):
                    self.assertIn(field, cell)

    def test_write_flags_must_be_explicit_and_paired(self):
        for extra in (("--allow-write",), ("--isolated-live",), ("--live",), ("--device", "R1"), ("--remaining", "--reassess")):
            with self.subTest(extra=extra), self.assertRaises(CommandError):
                call_command("nmas_capabilities", "verify-matrix", "--platform", "arista_ceos", "--feature", "interface.LAG",
                             *extra, stdout=StringIO())
