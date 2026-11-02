"""V2 Phase 9 closure ledger: every new function called directly, accepting and refusing."""

from __future__ import annotations

import io
import json
import shutil
import tempfile
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

from core.management.commands import nmas_phase9_ledger
from core.services.capabilities import phase9_ledger as P
from core.services.capabilities.vocabulary import CLOSURE_TO_STATUS, ClosureClass

REPO = Path(settings.BASE_DIR).resolve().parent
LIVE = {"outcome": "PASS", "detail": "x", "reason": "", "test_type": "LIVE", "reference": "live:x"}
FIXTURE = {"outcome": "PASS", "detail": "x", "reason": "", "test_type": "FIXTURE", "reference": ""}


def probes(**override):
    names = ("semantic_model", "device_builder_ui", "field_validation", "renderer", "candidate_generation", "config_validation",
             "parser_import", "automated_tests", "executor", "live_read", "live_write", "live_post_write_validation",
             "compensation", "runtime_validation")
    live = {"live_read", "live_write", "live_post_write_validation", "compensation", "runtime_validation"}
    result = {n: dict(LIVE if n in live else FIXTURE) for n in names}
    for name, outcome in override.items():
        result[name] = {**result[name], **outcome}
    return result


def cell(final="UNSUPPORTED", complete=True, reasons=(), **override):
    return {"platform": "arista_ceos", "feature": "routing.OSPFV2", "final_status": final, "assessment_complete": complete,
            "unsupported_reasons": list(reasons), "probes": probes(**override)}


BLOCK = {"outcome": "BLOCKED", "reason": "RUNTIME_IMAGE_UNAVAILABLE", "test_type": "LIVE"}
FAIL = {"outcome": "FAIL", "reason": "EXECUTOR_ABSENT"}


class ClosureVocabularyTests(SimpleTestCase):
    def test_closure_classes_map_onto_four_value_vocabulary(self):
        self.assertEqual(CLOSURE_TO_STATUS[ClosureClass.SUPPORTED], "SUPPORTED")
        self.assertEqual(CLOSURE_TO_STATUS[ClosureClass.PARTIAL], "NOT_IMPLEMENTED")
        self.assertEqual(set(CLOSURE_TO_STATUS), set(ClosureClass))

    def test_closure_class_refuses_unknown_value(self):
        with self.assertRaises(ValueError):
            ClosureClass("MAYBE")


class StageTests(SimpleTestCase):
    def test_stages_for_all_ten_present(self):
        self.assertTrue(all(P.stages_for(probes()).values()))

    def test_stages_for_fixture_only_live_probe_is_missing(self):
        stages = P.stages_for(probes(runtime_validation={"test_type": "FIXTURE"}, executor=FAIL))
        self.assertFalse(stages["live"])
        self.assertFalse(stages["execution"])
        self.assertTrue(stages["renderer"])


class ClassifyTests(SimpleTestCase):
    def test_classify_supported_and_partial_and_render_validate_only(self):
        self.assertEqual(P.classify(cell("SUPPORTED"))[0], "SUPPORTED")
        self.assertEqual(P.classify(cell(reasons=["FUNCTIONAL_TEST_FAILED"], runtime_validation={"outcome": "FAIL",
                                                                                                 "reason": "FUNCTIONAL_TEST_FAILED"}))[0],
                         "LIVE_EVIDENCE_MISSING")
        partial = cell(reasons=["EXECUTOR_ABSENT"], executor=FAIL, automated_tests={"outcome": "PASS"})
        self.assertEqual(P.classify(partial)[0], "PARTIAL")
        names = ("executor", "live_read", "live_write", "live_post_write_validation", "compensation", "runtime_validation",
                 "automated_tests", "parser_import")
        only = cell(reasons=["EXECUTOR_ABSENT"], **{n: FAIL for n in names})
        self.assertEqual(P.classify(only)[0], "RENDER_VALIDATE_ONLY")
        blocked = cell(reasons=["RUNTIME_IMAGE_UNAVAILABLE"], live_write=BLOCK, runtime_validation=BLOCK)
        self.assertEqual(P.classify(blocked)[0], "BLOCKED_BY_ENVIRONMENT")

    def test_classify_unsupported_platform_and_not_implemented(self):
        self.assertEqual(P.classify(cell(reasons=["PLATFORM_DOES_NOT_SUPPORT"], renderer=FAIL))[0], "UNSUPPORTED")
        self.assertEqual(P.classify(cell(reasons=["RENDERER_ABSENT"], renderer=FAIL))[0], "NOT_IMPLEMENTED")

    def test_classify_refuses_mismatch_with_final_status(self):
        with self.assertRaises(ValueError):
            P.classify(cell("UNSUPPORTED"))          # all ten stages pass, but the ledger says UNSUPPORTED
        with self.assertRaises(ValueError):
            P.classify(cell("SUPPORTED", renderer=FAIL))


class Option82RowTests(SimpleTestCase):
    def test_option82_row_from_live_evidence_is_partial_execution_engine_pending(self):
        evidence = json.loads((REPO / "docs/evidence/v2-phase7-9/phase9/option82-ceos-live.json").read_text())
        row = P.option82_row(evidence, evidence_path="e.json")
        self.assertEqual((row["closure_class"], row["missing_stages"]), ("PARTIAL", ["execution"]))
        self.assertTrue(row["stages"]["restoration"] and row["stages"]["live"])

    def test_option82_row_without_evidence_is_never_supported(self):
        row = P.option82_row(None)
        self.assertNotEqual(row["closure_class"], "SUPPORTED")
        self.assertIn("live", row["missing_stages"])


class BuildTests(SimpleTestCase):
    def test_build_counts_per_platform_and_renders_summary(self):
        ledger = {"cells": [cell("SUPPORTED"), {**cell(reasons=["RENDERER_ABSENT"], renderer=FAIL), "platform": "sonic"}]}
        result = P.build(ledger)
        self.assertEqual((result["matrix_total"], result["matrix_supported"]), (2, 1))
        self.assertEqual(result["per_platform"]["sonic"]["NOT_IMPLEMENTED"], 1)
        text = P.summary_markdown(result)
        self.assertIn("| **all** | 2 | 1 |", text)
        self.assertIn("`arista_ceos` `routing.OSPFV2`", text)

    def test_build_refuses_inconsistent_ledger_cell(self):
        with self.assertRaises(ValueError):
            P.build({"cells": [cell("SUPPORTED", executor=FAIL)]})

    def test_summary_markdown_lists_none_when_no_live_gap(self):
        """'- none' is printed when no cell is LIVE_EVIDENCE_MISSING (an empty-section refusal to invent candidates)."""
        text = P.summary_markdown(P.build({"cells": [cell("SUPPORTED")]}))
        self.assertIn("- none", text)


class ClosureOutlookTests(SimpleTestCase):
    def test_environment_reason_list_returns_the_runtime_image_reason(self):
        blocked = cell(reasons=["EXECUTOR_ABSENT"], executor=FAIL, live_write=FAIL, live_read=BLOCK, runtime_validation=BLOCK)
        self.assertEqual(P.environment_blocker(blocked), ["RUNTIME_IMAGE_UNAVAILABLE"])

    def test_environment_blocker_lists_none_for_a_renderer_absent_block(self):
        """A live probe BLOCKED by missing software (not the host) is no environment blocker."""
        software = {"outcome": "BLOCKED", "reason": "RENDERER_ABSENT", "test_type": "LIVE"}
        self.assertEqual(P.environment_blocker(cell(reasons=["RENDERER_ABSENT"], renderer=FAIL, runtime_validation=software)), [])
        self.assertEqual(P.environment_blocker({"platform": "sonic"}), [])

    def test_closure_outlook_counts_each_cell_once_and_matches_total(self):
        ledger = {"cells": [
            cell("SUPPORTED"),
            {**cell(reasons=["EXECUTOR_ABSENT"], executor=FAIL, live_read=BLOCK, runtime_validation=BLOCK), "platform": "cisco_iosxr"},
            {**cell(reasons=["RENDERER_ABSENT"], renderer=FAIL), "platform": "sonic"},
        ]}
        outlook = P.closure_outlook(P.build(ledger)["cells"])
        self.assertEqual(outlook, P.build(ledger)["closure_outlook"])
        self.assertEqual(outlook, {"total": 3, "supported": 1, "unsupported_or_out_of_scope": 0, "environment_blocked": 1,
                                   "technically_feasible_remaining": 1, "environment_blocked_by_platform": {"cisco_iosxr": 1}})
        self.assertIn("- Environment-blocked (a live probe is blocked by the host environment, so stage 10 cannot run here): "
                      "1 (cisco_iosxr 1)", P.summary_markdown(P.build(ledger)))

    def test_closure_outlook_keeps_an_unsupported_cell_out_of_the_environment_count(self):
        """A recorded platform decision wins over an environment block, and is no feasible work either."""
        decided = cell(reasons=["PLATFORM_DOES_NOT_SUPPORT"], runtime_validation=BLOCK)
        outlook = P.closure_outlook(P.build({"cells": [decided]})["cells"])
        self.assertEqual((outlook["unsupported_or_out_of_scope"], outlook["environment_blocked"],
                          outlook["technically_feasible_remaining"]), (1, 0, 0))


class WriteTests(SimpleTestCase):
    def setUp(self):
        self.out = Path(tempfile.mkdtemp(prefix="nmas-p9-ledger-"))
        self.addCleanup(shutil.rmtree, self.out, True)

    def test_write_regenerates_the_committed_ledger_exactly(self):
        result = P.write(REPO, self.out)
        committed = REPO / "docs/evidence/v2-phase7-9/phase9"
        self.assertEqual((self.out / "capability-ledger.json").read_text(), (committed / "capability-ledger.json").read_text())
        self.assertEqual((self.out / "capability-summary.md").read_text(), (committed / "capability-summary.md").read_text())
        self.assertEqual(result["matrix_total"], 396)
        outlook = result["closure_outlook"]
        self.assertEqual(outlook["environment_blocked_by_platform"], {"cisco_iosxr": 66})
        self.assertEqual(sum(outlook[k] for k in ("supported", "unsupported_or_out_of_scope", "environment_blocked",
                                                  "technically_feasible_remaining")), 396)

    def test_write_refuses_missing_source_ledger(self):
        with self.assertRaises(FileNotFoundError):
            P.write(self.out, self.out / "x")

    def test_command_handle_writes_ledger(self):
        command = nmas_phase9_ledger.Command(stdout=io.StringIO())
        command.handle(out=str(self.out.relative_to(REPO)) if self.out.is_relative_to(REPO) else str(self.out))
        self.assertTrue((self.out / "capability-ledger.json").exists())
        self.assertIn("matrix 396", command.stdout.getvalue())

    def test_command_handle_refuses_unwritable_output(self):
        blocker = self.out / "file"
        blocker.write_text("x")
        with self.assertRaises(OSError):
            nmas_phase9_ledger.Command(stdout=io.StringIO()).handle(out=str(blocker / "sub"))

    def test_command_add_arguments_registers_out(self):
        import argparse
        parser = argparse.ArgumentParser()
        nmas_phase9_ledger.Command().add_arguments(parser)
        self.assertEqual(parser.parse_args([]).out, "docs/evidence/v2-phase7-9/phase9")

    def test_command_add_arguments_rejects_unknown_option(self):
        import argparse
        parser = argparse.ArgumentParser(exit_on_error=False)
        nmas_phase9_ledger.Command().add_arguments(parser)
        with self.assertRaises((SystemExit, argparse.ArgumentError)):
            parser.parse_args(["--bogus"])
