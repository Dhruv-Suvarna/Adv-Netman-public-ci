"""V2 Lifecycle Phase 2: the four-value capability vocabulary, derived from the binary ledger without rewriting it."""

from __future__ import annotations

import json
from pathlib import Path

from django.test import SimpleTestCase, TestCase

from core.services.capabilities import assessment, batch, lifecycle_features, registry, vocabulary
from core.services.capabilities.axes import CapabilityStatus, Feasibility
from core.tests.test_tg_capability_registry_closure import gated_cell, supported_cell

LEDGER = Path(__file__).resolve().parents[3] / "docs/evidence/v2-phase4-exhaustive/progress-ledger.json"


class ClassifyTests(SimpleTestCase):
    def test_classify_supported_and_platform_limit_and_nmas_gap(self):
        self.assertEqual(vocabulary.classify("SUPPORTED", complete=True), ("SUPPORTED", "PROVEN"))
        self.assertEqual(vocabulary.classify("UNSUPPORTED", complete=True, reasons=["PLATFORM_DOES_NOT_SUPPORT", "RENDERER_ABSENT"]),
                         ("UNSUPPORTED", "PLATFORM_LIMITATION"))
        self.assertEqual(vocabulary.classify("UNSUPPORTED", complete=True, reasons=["RENDERER_ABSENT"]), ("NOT_IMPLEMENTED", "NMAS_GAP"))

    def test_classify_unknown_feasibility_never_becomes_supported_or_unsupported(self):
        for reasons in (["RUNTIME_IMAGE_UNAVAILABLE"], ["HARNESS_ERROR", "RENDERER_ABSENT"], ["UNSAFE_TO_AUTOMATE"], []):
            with self.subTest(reasons=reasons):
                self.assertEqual(vocabulary.classify("UNSUPPORTED", complete=True, reasons=reasons), ("NOT_IMPLEMENTED", "UNKNOWN"))
        self.assertEqual(vocabulary.classify("UNSUPPORTED", complete=False, reasons=["PLATFORM_DOES_NOT_SUPPORT"]),
                         ("NOT_IMPLEMENTED", "UNASSESSED"))

    def test_classify_recorded_exclusion_is_out_of_scope(self):
        self.assertEqual(vocabulary.classify("UNSUPPORTED", complete=True, platform="p", feature="f", exclusions={("p", "f"): "decided"}),
                         ("OUT_OF_SCOPE", "EXCLUDED"))
        self.assertEqual(vocabulary.SCOPE_EXCLUSIONS, {})

    def test_classify_refuses_non_binary_status(self):
        with self.assertRaises(ValueError):
            vocabulary.classify("MAYBE", complete=True)

    def test_classify_cell_returns_derived_fields(self):
        self.assertEqual(vocabulary.classify_cell({"final_status": "SUPPORTED", "assessment_complete": True}),
                         {"capability_status": "SUPPORTED", "feasibility": "PROVEN"})

    def test_classify_cell_missing_final_status_raises(self):
        with self.assertRaises(KeyError):
            vocabulary.classify_cell({})

    def test_counts_returns_every_status(self):
        found = vocabulary.counts([{"final_status": "SUPPORTED", "assessment_complete": True},
                                   {"final_status": "UNSUPPORTED", "assessment_complete": False}])
        self.assertEqual(found, {"SUPPORTED": 1, "NOT_IMPLEMENTED": 1, "UNSUPPORTED": 0, "OUT_OF_SCOPE": 0})

    def test_counts_of_no_cells_is_zero(self):
        self.assertEqual(set(vocabulary.counts([]).values()), {0})

    def test_committed_ledger_keeps_its_63_supported_cells(self):
        ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
        batch.check_report(ledger)                     # historical rows without derived fields still pass
        derived = vocabulary.counts(ledger["cells"])
        self.assertEqual((ledger["supported"], derived["SUPPORTED"]), (63, 63))
        self.assertEqual(sum(derived.values()), 396)
        self.assertEqual({c["feature"] for c in ledger["cells"] if c["final_status"] == "SUPPORTED"},
                         {c["feature"] for c in ledger["cells"] if vocabulary.classify_cell(c)["capability_status"] == "SUPPORTED"})
        self.assertTrue(all("capability_status" not in c or
                            c["capability_status"] == vocabulary.classify_cell(c)["capability_status"]
                            for c in ledger["cells"]))


class LedgerIntegrationTests(TestCase):
    def test_cell_dict_carries_derived_fields_next_to_binary_status(self):
        found = supported_cell().as_dict()
        self.assertEqual((found["final_status"], found["capability_status"], found["feasibility"]), ("SUPPORTED", "SUPPORTED", "PROVEN"))
        gated = gated_cell().as_dict()
        self.assertEqual((gated["final_status"], gated["capability_status"], gated["feasibility"]), ("UNSUPPORTED", "NOT_IMPLEMENTED", "NMAS_GAP"))

    def test_check_report_rejects_disagreeing_capability_status(self):
        assessment.persist(supported_cell(), actor="tester")
        report = batch.matrix_report(platforms=["arista_ceos"], keys=["interface.LOOPBACK"])
        self.assertEqual(report["capability_counts"]["SUPPORTED"], 1)
        report["cells"][0]["capability_status"] = "UNSUPPORTED"
        with self.assertRaises(ValueError):
            batch.check_report(report)

    def test_summary_markdown_renders_capability_status_table(self):
        report = batch.matrix_report(platforms=["arista_ceos"], keys=["interface.LOOPBACK", "interface.SVI"])
        markdown = batch.summary_markdown(report)
        self.assertIn("## Capability status", markdown)
        self.assertIn("| NOT_IMPLEMENTED | 2 |", markdown)
        self.assertIn("## Supported cells\n\n- none", markdown)

    def test_evidence_matrix_counts_and_record_vocabulary(self):
        assessment.persist(supported_cell(), actor="tester")
        matrix = registry.evidence_matrix()
        self.assertEqual(sum(matrix["capability_counts"].values()), sum(matrix["summary_counts"].values()))
        self.assertEqual(matrix["capability_counts"]["SUPPORTED"], matrix["summary_counts"]["SUPPORTED"])
        cells = [c for row in matrix["rows"] for c in row["cells"]]
        supported = next(c for c in cells if c.status.value == "SUPPORTED")
        self.assertEqual((supported.capability_status, supported.feasibility, supported.capability_status_label), ("SUPPORTED", "PROVEN", "Supported"))
        unassessed = next(c for c in cells if c.assessment is None)
        self.assertEqual((unassessed.capability_status, unassessed.feasibility), ("NOT_IMPLEMENTED", "UNASSESSED"))


class LifecycleFeatureTests(SimpleTestCase):
    # Phase 3 replaced the single "lifecycle.ZTP" row (NOT_IMPLEMENTED) with one row per native-ZTP adapter derived from the
    # adapter's evidence class; the remaining rows are still owned by later phases and stay NOT_IMPLEMENTED.
    # Phase 4 rows are SUPPORTED / PROVEN only through committed live evidence (management.capability_evidence.LIVE).
    LATER_PHASES = {"lifecycle.DECOMMISSION", "lifecycle.EXACT_RESTORATION"}
    # Phases 5 / 6 rows follow commissioning.capability_evidence.LIVE (like the Phase 4 rows)
    COMMISSIONING_ROWS = {"lifecycle.ISOLATION": "arista_ceos:live:ISOLATION", "lifecycle.COMMISSION": "arista_ceos:live:COMMISSION",
                          "lifecycle.ADMISSION": "arista_ceos:live:ADMISSION"}
    MANAGEMENT_ROWS = {"lifecycle.CREDENTIAL_ONBOARDING": "arista_ceos:live:BCRED", "lifecycle.MGMT_VRF": "arista_ceos:live:MGMT_VRF",
                       "lifecycle.MGMT_FAILOVER": "arista_ceos:live:MGMT_FAILOVER"}

    def test_lifecycle_capabilities_are_defined_and_later_phases_are_not_supported(self):
        from core.services.ztp.adapters import ADAPTERS
        keys = self.LATER_PHASES | set(self.MANAGEMENT_ROWS) | set(self.COMMISSIONING_ROWS) | {"lifecycle.BOOTSTRAP_DELIVERY"} | {f"lifecycle.ZTP.{name}" for name in ADAPTERS}
        self.assertEqual(set(lifecycle_features.by_key()), keys)
        for key in self.LATER_PHASES:
            with self.subTest(key):
                capability = lifecycle_features.by_key()[key]
                self.assertEqual(capability.status, CapabilityStatus.NOT_IMPLEMENTED)
                self.assertIn(capability.feasibility, {Feasibility.NMAS_GAP, Feasibility.UNKNOWN})
                self.assertEqual(capability.as_dict()["capability_status"], "NOT_IMPLEMENTED")

    def test_commissioning_rows_follow_committed_live_evidence(self):
        from unittest import mock

        from core.services.commissioning import capability_evidence

        root = Path(__file__).resolve().parents[3]
        for key, evidence_key in self.COMMISSIONING_ROWS.items():
            with self.subTest(key):
                row = lifecycle_features.by_key()[key]
                if capability_evidence.LIVE.get(evidence_key):
                    self.assertEqual((row.status, row.feasibility), (CapabilityStatus.SUPPORTED, Feasibility.PROVEN))
                    self.assertTrue((root / capability_evidence.LIVE[evidence_key]).is_file())
                else:
                    self.assertEqual((row.status, row.feasibility), (CapabilityStatus.NOT_IMPLEMENTED, Feasibility.UNKNOWN))
        with mock.patch.dict(capability_evidence.LIVE, {}, clear=True):
            for row in lifecycle_features._commissioning_rows():
                self.assertEqual((row.status, row.feasibility), (CapabilityStatus.NOT_IMPLEMENTED, Feasibility.UNKNOWN))
        with mock.patch.dict(capability_evidence.LIVE, {"arista_ceos:live:ISOLATION": "x.json"}, clear=True):
            row = next(r for r in lifecycle_features._commissioning_rows() if r.key == "lifecycle.ISOLATION")
            self.assertEqual((row.status, row.feasibility, row.owner_phase), (CapabilityStatus.SUPPORTED, Feasibility.PROVEN, 5))
            self.assertIn("x.json", row.basis)

    def test_management_rows_are_supported_only_with_committed_live_evidence(self):
        from unittest import mock

        from core.services.management import capability_evidence

        root = Path(__file__).resolve().parents[3]
        for key, evidence_key in self.MANAGEMENT_ROWS.items():
            with self.subTest(key):
                row = lifecycle_features.by_key()[key]
                self.assertEqual((row.status, row.feasibility), (CapabilityStatus.SUPPORTED, Feasibility.PROVEN))
                self.assertTrue((root / capability_evidence.LIVE[evidence_key]).is_file())
                self.assertIn(capability_evidence.LIVE[evidence_key], row.basis)
        with mock.patch.dict(capability_evidence.LIVE, {}, clear=True):
            for row in lifecycle_features._management_rows():
                self.assertEqual((row.status, row.feasibility), (CapabilityStatus.NOT_IMPLEMENTED, Feasibility.UNKNOWN))

    def test_ztp_rows_are_supported_only_with_committed_live_evidence(self):
        from core.services.ztp.adapters import ADAPTERS
        root = Path(__file__).resolve().parents[3]
        supported = []
        for name, adapter in ADAPTERS.items():
            row = lifecycle_features.by_key()[f"lifecycle.ZTP.{name}"]
            with self.subTest(name):
                live = adapter.capability.evidence_status == "SUPPORTED_AND_LIVE_VERIFIED"
                self.assertEqual(row.status == CapabilityStatus.SUPPORTED, live)
                if live:
                    supported.append(name)
                    self.assertEqual(row.feasibility, Feasibility.PROVEN)
                    self.assertTrue(adapter.capability.evidence and (root / adapter.capability.evidence).is_file(), adapter.capability.evidence)
        delivery = lifecycle_features.by_key()["lifecycle.BOOTSTRAP_DELIVERY"]
        self.assertEqual(delivery.status == CapabilityStatus.SUPPORTED, bool(supported))

    def test_lifecycle_capabilities_never_enter_the_matrix(self):
        self.assertFalse({c.key for c in lifecycle_features.CAPABILITIES} & set(registry.by_key()))
