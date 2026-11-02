"""Lab 7 closure -- the configuration-bundle lifecycle: ``bundles.legacy`` (gate, payload contract, residue, candidate, initial Golden,
legacy integrity), ``bundles.persistence`` (seal, list, integrity-failure audit), ``bundles.integrity.verify_manifest``, ``bundles.snapshot``,
``bundles.eligibility`` lookups and ``bundles.export.export_document``, each called directly.

Hermetic: legacy bundles come from a REAL capture of the simulated ``helpers.bootstrap.World``; execution-lineage bundles from the REAL Phase-17
engine on ``helpers.execution.FakeWorld``; the observation runs on the controlled ``bh.T0`` clock; Slack is never configured.  No device, NetBox,
Slack or socket is reached.  POSITIVE: exact bundles, digests, documents, audit rows.  NEGATIVE: a closed gate, malformed payloads, stored secret
residue, a non-legacy or unobserved candidate, malformed manifests and provenance mismatches are refused or reported; nothing is written.
"""
from __future__ import annotations

import copy
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.test import TestCase

from core import models
from core.services import bootstrap_service as bs, slack_service
from core.services.bootstrap import capture
from core.services.bundles import canonical, eligibility, export, integrity, legacy, persistence, snapshot
from core.services.bundles.codes import LEGACY_BUILDER_VERSION
from core.tests.helpers import bootstrap as bh, bundles as bundle_helper

T0, END = bh.T0, bh.END


class LegacyBundleTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.candidate, cls.world = bh.candidate_of()

    def setUp(self):
        patcher = mock.patch.object(slack_service, "is_configured", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def observed(self):
        run = bs.start_bootstrap(self.candidate, actor="operator", now=T0).run
        bh.drive(self.world, start=T0, until=END + timedelta(seconds=bh.INTERVAL))
        run.refresh_from_db()
        self.assertTrue(run.is_technical_pass, (run.state, run.result, run.terminal_reason))
        when = run.finished_at + timedelta(seconds=30)
        recheck = capture.recheck_configuration(self.candidate, session_factory=self.world.factory, now=when)
        return run, recheck, when

    def payload(self):
        reads = capture.read_all(capture.managed_scope(), session_factory=self.world.factory, now=T0)
        payload, problems = capture.build_payload(reads, capture_started_at=T0, capture_finished_at=T0, snapshot=bh.snapshot(T0), policy_version="P")
        self.assertEqual(problems, [])
        return payload

    def test_check_create_initial_golden_and_legacy_golden_seal_the_observed_candidate(self):
        self.assertEqual(legacy.gate_blockers(), [])
        run, recheck, when = self.observed()
        self.assertEqual(legacy.check_initial_golden(self.candidate, run, recheck, now=when), [])
        result = legacy.create_initial_golden(self.candidate, evidence=run, recheck=recheck, actor="operator", reason="adopt", now=when)
        golden = result.bundle
        self.assertTrue(result.created)
        self.assertEqual((golden.kind, golden.payload_digest, golden.parent_id), (models.BundleKind.GOLDEN, self.candidate.payload_digest, self.candidate.pk))
        self.assertEqual(legacy.legacy_golden().pk, golden.pk)
        report = integrity.IntegrityReport()
        self.assertIsNone(legacy.verify_bundle(golden, golden.manifest, report, 0))
        self.assertEqual((report.findings, report.checks), ([], ["legacy"]))

    def test_check_initial_golden_refuses_a_non_legacy_candidate_or_a_missing_observation(self):
        probation = bundle_helper.probation_of(bundle_helper.uat_of(bundle_helper.partial_run()))
        with self.subTest("refused non-legacy"):
            self.assertEqual([b["code"] for b in legacy.check_initial_golden(probation, None, None, now=T0)], ["CANDIDATE_NOT_LEGACY"])
        with self.subTest("refused without observation"):
            codes = [b["code"] for b in legacy.check_initial_golden(self.candidate, None, {"result": "MATCH"}, now=T0)]
            self.assertEqual(codes, ["OBSERVATION_NOT_PASSED"])
        self.assertFalse(models.ConfigurationBundle.objects.filter(kind=models.BundleKind.GOLDEN).exists())

    def test_device_config_digest_of_sections_missing_a_hash_raises(self):
        with self.assertRaises(KeyError):
            legacy.device_config_digest([{"name": "running-config"}])

    def test_validate_payload_and_secret_residue_accept_the_captured_candidate(self):
        self.assertEqual(legacy.validate_payload(self.candidate.payload), [])
        self.assertEqual(legacy.secret_residue(self.candidate.manifest), [])

    def test_validate_payload_and_secret_residue_report_malformed_or_unredacted_content(self):
        payload = copy.deepcopy(self.candidate.payload)
        payload["baseline"]["devices"][0]["sections"][0]["sanitized"] += "username x secret sha512 $6$leftover$hash\n"
        with self.subTest("refused malformed"):
            self.assertEqual(legacy.validate_payload({"provenance_type": "OTHER"}), ["SHAPE"])
            self.assertEqual(legacy.validate_payload(dict(payload, baseline={"devices": []})), ["NO_DEVICES"])
            self.assertTrue(any(p.startswith("SECTION_HASH:") for p in legacy.validate_payload(payload)))
        with self.subTest("refused unredacted residue"):
            hits = legacy.secret_residue({"payload": payload})
            self.assertEqual(hits[0]["device"], payload["baseline"]["devices"][0]["device"])
            self.assertNotIn("$6$leftover", repr(hits))

    def test_seal_candidate_and_seal_bundle_return_new_legacy_baselines(self):
        payload = self.payload()
        result = legacy.seal_candidate(payload, actor="operator", policy_version="LEGACY_BOOTSTRAP_POLICY_V1")
        self.assertTrue(result.created)
        self.assertEqual((result.bundle.kind, result.bundle.payload_digest), (models.BundleKind.LEGACY_BASELINE, canonical.payload_digest(payload)))
        lineage = legacy._candidate_lineage()
        direct = persistence.seal_bundle(kind=models.BundleKind.LEGACY_BASELINE, payload=payload, lineage=lineage, refs={}, item_specs=[], actor="operator",
                                         provenance=models.BundleProvenance.LEGACY_BOOTSTRAP, builder_version=LEGACY_BUILDER_VERSION)
        self.assertEqual((direct.payload_digest, direct.builder_version), (result.bundle.payload_digest, LEGACY_BUILDER_VERSION))
        self.assertTrue(direct.bundle_id.startswith("BND-LEGACY-"))

    def test_verify_bundle_reports_a_provenance_column_mismatch(self):
        report = integrity.IntegrityReport()
        legacy.verify_bundle(SimpleNamespace(provenance=models.BundleProvenance.EXECUTION_LINEAGE), self.candidate.manifest, report, 0)
        self.assertEqual((report.codes, report.checks), (["LEGACY_PROVENANCE_MISMATCH"], []))

    def test_verify_manifest_accepts_the_stored_manifest(self):
        c = self.candidate
        report = integrity.IntegrityReport()
        self.assertTrue(integrity.verify_manifest(c.manifest, kind=c.kind, stored_payload_digest=c.payload_digest, stored_bundle_digest=c.bundle_digest,
                                                  schema_version=c.schema_version, report=report))
        self.assertIn("schema", report.checks)

    def test_verify_manifest_refuses_malformed_or_unsupported_manifests(self):
        c = self.candidate
        for label, manifest, schema, code in (("refused malformed", {"payload": "x"}, c.schema_version, "MANIFEST_MALFORMED"),
                                              ("refused unsupported schema", c.manifest, 999, "SCHEMA_UNSUPPORTED")):
            with self.subTest(label):
                report = integrity.IntegrityReport()
                self.assertFalse(integrity.verify_manifest(manifest, kind=c.kind, stored_payload_digest=c.payload_digest, stored_bundle_digest=c.bundle_digest,
                                                           schema_version=schema, report=report))
                self.assertEqual(report.codes, [code])

    def test_export_document_and_list_bundles_return_the_candidate(self):
        document = export.export_document(self.candidate)
        self.assertEqual((document["bundle"]["bundle_id"], document["bundle"]["provenance"], document["sources"]["change_id"]),
                         (self.candidate.bundle_id, models.BundleProvenance.LEGACY_BOOTSTRAP, ""))
        self.assertEqual(document["export_digest"], canonical.export_digest({k: v for k, v in document.items() if k != "export_digest"}))
        self.assertEqual([b.pk for b in persistence.list_bundles(kind=models.BundleKind.LEGACY_BASELINE)], [self.candidate.pk])

    def test_record_integrity_failure_writes_one_bounded_audit_event(self):
        report = integrity.IntegrityReport(findings=[{"code": "ITEMS_MISMATCH"}])
        with self.subTest("one bounded audit event recorded"):
            persistence.record_integrity_failure(self.candidate, report, actor="operator", context="closure")
        event = models.AuditEvent.objects.filter(event_type=models.AuditEventType.BUNDLE_INTEGRITY_FAILED).get()
        self.assertEqual((event.object_id, event.metadata["finding_codes"], event.metadata["result"]), (self.candidate.bundle_id, ["ITEMS_MISMATCH"], "FAILED"))

    def test_record_integrity_failure_of_an_unsaved_bundle_raises_and_writes_nothing(self):
        with self.assertRaises(AttributeError):
            persistence.record_integrity_failure(SimpleNamespace(change=None, change_id=None), integrity.IntegrityReport(), actor="operator", context="x")
        self.assertFalse(models.AuditEvent.objects.filter(event_type=models.AuditEventType.BUNDLE_INTEGRITY_FAILED).exists())


class ExecutionBundleTests(TestCase):
    def test_existing_uat_and_existing_child_return_sealed_bundles(self):
        p = bundle_helper.partial_run()
        uat = bundle_helper.uat_of(p)
        probation = bundle_helper.probation_of(uat)
        self.assertEqual((eligibility.existing_uat(p.run).pk, eligibility.existing_child(uat, models.BundleKind.PROBATION).pk), (uat.pk, probation.pk))

    def test_existing_lookups_before_sealing_are_none(self):
        p = bundle_helper.partial_run()
        with self.subTest("none before sealing"):
            self.assertIsNone(eligibility.existing_uat(p.run))
            self.assertIsNone(eligibility.existing_deployed(p.run))
            self.assertIsNone(eligibility.existing_child(bundle_helper.uat_of(p), models.BundleKind.PROBATION))

    def test_snapshot_collect_and_existing_deployed_return_the_deployed_bundle(self):
        c = bundle_helper.complete_run()
        snap = snapshot.collect(c.run, kind=models.BundleKind.DEPLOYED)
        self.assertTrue(snap.ok, snap.blockers)
        self.assertEqual(snap.payload["scope"]["requested"], c.cfgs)
        deployed = persistence.create_deployed_bundle(c.run, actor="operator").bundle
        self.assertEqual(eligibility.existing_deployed(c.run).pk, deployed.pk)
