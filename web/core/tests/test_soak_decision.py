"""Phase-20 operator decision and Golden creation: technical PASS is not promotion; every decision-time recheck; immutability; provenance tamper
detection; and the simulated end-to-end lifecycle (shortened TEST duration on a controlled clock -- NOT the real seven-day soak)."""

from __future__ import annotations

import copy
import json
import logging
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.db import IntegrityError, transaction

from core import models
from core.services import bundle_service as bs, soak_service as ss
from core.services.bundles import canonical, golden as golden_module
from core.services.soak import evaluator, lifecycle
from core.tests.helpers import bundles as bh, health as h, soak as sh

SR, SS, SRes = models.SoakSampleResult, models.SoakState, models.SoakResult
T0, END = sh.T0, sh.END
SoakFixture = sh.SoakFixture


def codes(blockers):
    return [b["code"] for b in blockers]


class Base(SoakFixture):
    def passed(self):
        return sh.passed(self.f)

    def approve(self, run=None, **kwargs):
        run = run or self.run_row()
        options = dict(decision="APPROVE", actor="operator", confirm=sh.confirm_of(run), now=run.finished_at)
        options.update(kwargs)
        return ss.decide(run, **options)


class GoldenApprovalTests(Base):
    def test_explicit_approve_seals_the_exact_probation_payload_into_a_new_golden_bundle_and_pins_the_soak_and_decision(self):
        self.passed()
        run = self.run_row()
        prob_before = models.ConfigurationBundle.objects.get(pk=self.f.prob.pk)
        uat_before = models.ConfigurationBundle.objects.get(pk=self.f.uat.pk)
        rows_before = list(prob_before.items.values_list("item_digest", "payload_hash"))
        self.assertTrue(bs.check_golden_eligibility(prob_before, run, now=run.finished_at).eligible, "technically ready ...")
        self.assertFalse(models.ConfigurationBundle.objects.filter(kind="GOLDEN").exists(), "... but nothing is promoted until the operator decides")
        result = self.approve()
        golden = result.bundle
        self.assertTrue(result.created and golden.kind == "GOLDEN" and golden.bundle_id == "BND-GOLD-000001")
        # identical configuration, different identity
        self.assertEqual(golden.manifest["payload"], prob_before.manifest["payload"])
        self.assertEqual(golden.payload_digest, prob_before.payload_digest)
        self.assertNotEqual(golden.bundle_digest, prob_before.bundle_digest)
        self.assertEqual(list(golden.items.values_list("payload_hash", flat=True)), [payload for _, payload in rows_before])
        self.assertEqual((golden.parent_id, golden.source_uat_id, golden.execution_run_id, golden.plan_id), (prob_before.pk, self.f.uat.pk, prob_before.execution_run_id, prob_before.plan_id))
        # lineage pins the soak, its evidence and the decision
        promotion = golden.lineage["promotion"]
        self.assertEqual({k: promotion[k] for k in ("soak_id", "evidence_digest", "probation_bundle_digest", "decision", "decided_by", "soak_policy_version", "soak_duration_seconds")},
                         {"soak_id": run.soak_id, "evidence_digest": run.evidence_digest, "probation_bundle_digest": prob_before.bundle_digest, "decision": "APPROVE",
                          "decided_by": "operator", "soak_policy_version": "20.0.0", "soak_duration_seconds": 7200})
        self.assertEqual((promotion["observation_started_at"], promotion["observation_completed_at"]), (evaluator.iso(run.started_at), evaluator.iso(run.finished_at)))
        decision = models.GoldenDecision.objects.get()
        self.assertEqual((decision.run_id, decision.bundle_id, decision.decision, decision.golden_bundle_id, decision.evidence_digest),
                         (run.pk, prob_before.pk, "APPROVE", golden.pk, run.evidence_digest))
        self.assertEqual(golden.builder_version, "20.0.0")
        self.assertTrue(bs.verify_bundle_integrity(golden).ok, bs.verify_bundle_integrity(golden).findings)
        self.assertEqual(bs.lineage_of(golden)["golden"].pk, golden.pk)
        # nothing earlier was touched
        prob_after, uat_after = (models.ConfigurationBundle.objects.get(pk=b.pk) for b in (prob_before, uat_before))
        self.assertEqual((prob_after.manifest, prob_after.bundle_digest, uat_after.bundle_digest, list(prob_after.items.values_list("item_digest", "payload_hash"))),
                         (prob_before.manifest, prob_before.bundle_digest, uat_before.bundle_digest, rows_before))
        self.assertEqual(models.Change.objects.get(pk=self.f.prob.change_id).lifecycle_state, "DRAFT", "the Change lifecycle is not advanced")
        audit = models.AuditEvent.objects.get(event_type="GOLDEN_APPROVED")
        self.assertEqual((audit.object_id, audit.metadata["soak_id"], audit.metadata["evidence_digest"], audit.actor), (golden.bundle_id, run.soak_id, run.evidence_digest, "operator"))
        self.assertEqual(models.Notification.objects.filter(event_type="GOLDEN_APPROVED").count(), 1)

    def test_approve_is_idempotent_and_the_database_refuses_a_second_golden_or_a_second_decision(self):
        self.passed()
        first = self.approve()
        second = self.approve()
        self.assertEqual((second.created, second.bundle.pk, second.decision.pk), (False, first.bundle.pk, first.decision.pk))
        self.assertEqual((models.ConfigurationBundle.objects.filter(kind="GOLDEN").count(), models.GoldenDecision.objects.count()), (1, 1))
        self.assertEqual(models.AuditEvent.objects.filter(event_type="GOLDEN_APPROVED").count(), 1)
        run = self.run_row()
        with self.assertRaises(IntegrityError), transaction.atomic():
            models.GoldenDecision.objects.create(run=run, bundle=self.f.prob, decision="REJECT", decided_by="x", decided_at=T0, probation_bundle_digest="0" * 64,
                                                 evidence_digest="0" * 64, policy_version="20.0.0")
        for label, kwargs in (("APPROVE without a bundle", dict(decision="APPROVE")), ("REJECT with a bundle", dict(decision="REJECT", golden_bundle=first.bundle))):
            with self.subTest(case=label), self.assertRaises(IntegrityError), transaction.atomic():
                models.GoldenDecision.objects.create(run=models.ProbationSoakRun.objects.create(
                    bundle=self.f.prob, bundle_digest="0" * 64, state="CANCELLED", finished_at=T0, policy_version="20.0.0", policy=run.policy, started_at=T0,
                    required_end_at=END, started_by="x"), bundle=self.f.prob, decided_by="x", decided_at=T0, probation_bundle_digest="0" * 64, evidence_digest="0" * 64,
                    policy_version="20.0.0", **kwargs)

    def test_a_racing_approval_that_loses_returns_the_winners_golden_bundle_and_creates_nothing(self):
        self.passed()
        run = self.run_row()
        winner = self.approve()
        real = golden_module.eligibility.existing_child
        calls = []

        def stale_first_look(parent, kind):    # the loser's first existence check ran BEFORE the winner committed
            calls.append(kind)
            return None if len(calls) == 1 else real(parent, kind)

        with mock.patch.object(golden_module.eligibility, "existing_child", side_effect=stale_first_look):
            loser = golden_module.create_golden_bundle(self.f.prob, evidence=run, actor="operator", now=run.finished_at)
        self.assertEqual(loser.bundle.pk, winner.bundle.pk)
        self.assertEqual(models.ConfigurationBundle.objects.filter(kind="GOLDEN").count(), 1)

    def test_a_soak_that_is_not_a_technical_pass_can_never_be_approved_or_rejected(self):
        broken = lambda: copy.deepcopy(self.f.world)                                     # noqa: E731
        failing = broken()
        failing.state["R1"]["interfaces"].pop("Ethernet1")
        scenarios = {
            "running": lambda: self.start(),
            "failed": lambda: (self.start(), sh.tick(T0, failing))[0],
            "incomplete": lambda: (self.start(), sh.tick(T0, broken()), sh.tick(END, broken()))[0],
            "invalidated": lambda: (self.start(), sh.tick(T0, broken()), history_run(self.f.prob, ["R1"]), sh.tick(sh.at(60), broken()))[0],
            "cancelled": lambda: (self.start(), ss.cancel_soak(self.f.run, actor="op", now=sh.at(5)))[0],
        }
        history_run = sh.history_run
        for label, arrange in scenarios.items():
            for decision in ("APPROVE", "REJECT"):
                with self.subTest(soak=label, decision=decision), bh.rolled_back():
                    arrange()
                    run = self.run_row()
                    before = bh.table_counts()
                    result = ss.decide(run, decision=decision, actor="operator", confirm=sh.confirm_of(run), now=END)
                    self.assertTrue(result.refused and result.bundle is None and result.decision is None, (run.state, run.result))
                    self.assertIn("SOAK_NOT_PASSED", codes(result.blockers))
                    self.assertEqual(bh.count_changes(before, bh.table_counts()), {}, "a refused decision writes nothing")
                    self.assertFalse(models.ConfigurationBundle.objects.filter(kind="GOLDEN").exists())

    def test_the_operator_may_reject_a_technically_passed_soak_and_a_rejection_is_final_for_that_soak(self):
        self.passed()
        run = self.run_row()
        before = bh.table_counts()
        with mock.patch("core.services.health.live.read_device", side_effect=AssertionError("a rejection must not read a device")):
            rejected = ss.decide(run, decision="REJECT", actor="operator", reason="Not comfortable with the change window.", confirm=sh.confirm_of(run), now=run.finished_at)
        self.assertEqual(set(bh.count_changes(before, bh.table_counts())), {"GoldenDecision", "AuditEvent", "Notification"}, "a rejection writes the decision, an audit event and a notification only")
        decision = rejected.decision
        self.assertEqual((decision.decision, decision.golden_bundle, decision.reason, rejected.bundle), ("REJECT", None, "Not comfortable with the change window.", None))
        self.assertFalse(models.ConfigurationBundle.objects.filter(kind="GOLDEN").exists())
        self.assertEqual(models.Notification.objects.filter(event_type="GOLDEN_REJECTED").count(), 1)
        self.assertEqual(models.AuditEvent.objects.filter(event_type="GOLDEN_REJECTED").count(), 1)
        again = ss.decide(run, decision="REJECT", actor="operator", confirm=sh.confirm_of(run), now=run.finished_at)
        self.assertEqual((again.decision.pk, again.created), (decision.pk, False), "the same explicit decision again is idempotent")
        flipped = self.approve()
        self.assertTrue(flipped.refused)
        self.assertEqual(codes(flipped.blockers), ["DECISION_ALREADY_RECORDED"], "a REJECT is never edited into an APPROVE")
        for label, action in (("field", lambda: (setattr(decision, "decision", "APPROVE"), decision.save())), ("delete", decision.delete),
                              ("queryset update", lambda: models.GoldenDecision.objects.filter(pk=decision.pk).update(decision="APPROVE")),
                              ("queryset delete", lambda: models.GoldenDecision.objects.all().delete())):
            with self.subTest(case=label), self.assertRaises(ValueError):
                action()
        # nothing was deleted, the Probation bundle and the evidence are intact, and a NEW soak may be started to reconsider
        self.assertEqual((self.run_row().samples.count() > 0, bs.verify_bundle_integrity(self.f.prob).ok), (True, True))
        self.assertTrue(ss.check_soak_start(self.f.prob).eligible)

    def test_a_rejected_soak_can_be_followed_by_a_new_soak_that_is_then_approved(self):
        self.passed()
        run = self.run_row()
        ss.decide(run, decision="REJECT", actor="operator", confirm=sh.confirm_of(run), now=run.finished_at)
        later = END + timedelta(days=1)
        self.f.run = None
        second = sh.passed(self.f, start=later)
        outcome = ss.decide(second.run, decision="APPROVE", actor="operator", confirm=sh.confirm_of(second.run), now=second.run.finished_at)
        self.assertTrue(outcome.created)
        self.assertEqual(outcome.bundle.lineage["promotion"]["soak_id"], second.run.soak_id)
        self.assertEqual(models.GoldenDecision.objects.order_by("id").values_list("decision", flat=True)[:2].__len__(), 2)


class DecisionTimeRecheckTests(Base):
    """Immediately before Golden creation, nothing is trusted from 'yesterday's READY flag'."""

    def refused(self, expected, **kwargs):
        run = self.run_row()
        before = bh.table_counts()
        result = self.approve(run, **kwargs)
        self.assertTrue(result.refused and result.bundle is None, codes(result.blockers))
        self.assertIn(expected, codes(result.blockers))
        self.assertFalse(models.ConfigurationBundle.objects.filter(kind="GOLDEN").exists())
        return {k: v for k, v in bh.count_changes(before, bh.table_counts()).items() if k != "AuditEvent"}

    def test_an_execution_after_the_technical_pass_but_before_approval_blocks_the_decision(self):
        self.passed()
        sh.history_run(self.f.prob, ["R1"], after=7 * 3600)
        self.assertEqual(self.refused("INTERFERENCE_DETECTED"), {}, "no long-lived lock existed to prevent it: the recheck detects it")
        self.assertEqual(self.run_row().state, SS.COMPLETED, "and nothing is rewritten")

    def test_an_integrity_failure_after_the_technical_pass_blocks_the_decision_and_is_audited(self):
        self.passed()
        bh.oob(models.ConfigurationBundle).filter(pk=self.f.prob.pk).update(payload_digest="0" * 64)
        self.refused("SOURCE_INTEGRITY_FAILED")
        self.assertTrue(models.AuditEvent.objects.filter(event_type=models.AuditEventType.BUNDLE_INTEGRITY_FAILED).exists())

    def test_the_technical_pass_expires_after_the_policys_decision_window(self):
        self.passed()
        run = self.run_row()
        just_inside = self.approve(run, now=run.finished_at + timedelta(seconds=7200))
        self.assertTrue(just_inside.created, "exactly at the pinned window is still eligible")

    def test_an_expired_technical_pass_is_refused(self):
        self.passed()
        run = self.run_row()
        self.refused("SOAK_EVIDENCE_EXPIRED", now=run.finished_at + timedelta(seconds=7201))

    def test_tampered_soak_evidence_or_a_different_artifact_is_refused(self):
        self.passed()
        run = self.run_row()
        cases = {
            "a sample edited out of band": ("SOAK_EVIDENCE_INVALID", lambda: bh.oob(models.ProbationSoakSample).filter(run=run, bucket=3).update(result="INCOMPLETE")),
            "an evidence digest edited": ("SOAK_EVIDENCE_INVALID", lambda: bh.oob(models.ProbationSoakRun).filter(pk=run.pk).update(evidence_digest="1" * 64)),
            "the summary edited": ("SOAK_EVIDENCE_INVALID", lambda: bh.oob(models.ProbationSoakRun).filter(pk=run.pk).update(evaluation={**run.evaluation, "technical_result": "PASS", "coverage": {}})),
            "a sample deleted": ("SOAK_EVIDENCE_INVALID", lambda: bh.oob(models.ProbationSoakSample).filter(run=run, bucket=5).delete()),
            "the observed bundle digest changed": ("PROBATION_DIGEST_CHANGED", lambda: bh.oob(models.ProbationSoakRun).filter(pk=run.pk).update(bundle_digest="2" * 64)),
            "the pinned end moved earlier": ("SOAK_DURATION_NOT_MET", lambda: bh.oob(models.ProbationSoakRun).filter(pk=run.pk).update(finished_at=run.required_end_at - timedelta(seconds=1))),
        }
        for label, (expected, tamper) in cases.items():
            with self.subTest(case=label), bh.rolled_back():
                tamper()
                self.refused(expected, confirm=sh.confirm_of(run) if expected != "PROBATION_DIGEST_CHANGED" else {**sh.confirm_of(run), "bundle_digest": "2" * 64})

    def test_confirmation_reason_and_decision_inputs_are_checked_and_nothing_is_written_when_refused(self):
        self.passed()
        run = self.run_row()
        good = sh.confirm_of(run)
        cases = {
            "no confirmation": (dict(confirm=None), "CONFIRMATION_MISMATCH"), "another soak id": (dict(confirm={**good, "soak_id": "SOAK-999999"}), "CONFIRMATION_MISMATCH"),
            "another bundle": (dict(confirm={**good, "bundle_id": "BND-PROB-000099"}), "CONFIRMATION_MISMATCH"),
            "a replaced digest": (dict(confirm={**good, "bundle_digest": "0" * 64}), "CONFIRMATION_MISMATCH"),
            "a credential in the comment": (dict(reason="enable secret 0 hunter2hunter2"), "REASON_SECRET_SHAPED"),
            "an unknown decision": (dict(decision="PROMOTE"), "DECISION_INVALID"),
            "a lower-case decision": (dict(decision="approve"), "DECISION_INVALID"),
        }
        for label, (kwargs, expected) in cases.items():
            with self.subTest(case=label):
                self.assertEqual(self.refused(expected, **kwargs), {})
        self.assertEqual(models.GoldenDecision.objects.count(), 0)


class ProvenanceIntegrityTests(Base):
    """A Golden bundle is only as good as its recorded provenance: tampering with the soak, the decision or the manifest is DETECTED."""

    def golden(self):
        self.passed()
        return self.approve().bundle

    def test_the_provenance_cross_checks_against_the_stored_soak_and_decision(self):
        golden = self.golden()
        report = bs.verify_bundle_integrity(golden)
        self.assertTrue(report.ok and "promotion" in report.checks)
        run = self.run_row()
        decision = models.GoldenDecision.objects.get()

        def edit_manifest(change):
            manifest = copy.deepcopy(golden.manifest)
            change(manifest)
            bh.oob(models.ConfigurationBundle).filter(pk=golden.pk).update(manifest=manifest)

        cases = {
            "the recorded decision edited in the manifest": (lambda: edit_manifest(lambda m: m["lineage"]["promotion"].update(decided_by="someone-else")), {"BUNDLE_DIGEST_MISMATCH", "PROMOTION_MISMATCH"}),
            "the provenance removed from the manifest": (lambda: edit_manifest(lambda m: m["lineage"].pop("promotion")), {"PROMOTION_MISSING", "BUNDLE_DIGEST_MISMATCH"}),
            "the decision row deleted": (lambda: bh.oob(models.GoldenDecision).filter(pk=decision.pk).delete(), {"PROMOTION_MISMATCH"}),
            "the decision row's evidence digest edited": (lambda: bh.oob(models.GoldenDecision).filter(pk=decision.pk).update(evidence_digest="3" * 64), {"PROMOTION_MISMATCH"}),
            "the soak's evidence digest edited": (lambda: bh.oob(models.ProbationSoakRun).filter(pk=run.pk).update(evidence_digest="4" * 64), {"PROMOTION_MISMATCH"}),
            "a soak sample edited": (lambda: bh.oob(models.ProbationSoakSample).filter(run=run, bucket=2).update(telemetry_freshness="STALE"), {"PROMOTION_MISMATCH"}),
            "the soak turned into a failure": (lambda: bh.oob(models.ProbationSoakRun).filter(pk=run.pk).update(result="FAIL"), {"PROMOTION_MISMATCH"}),
        }
        for label, (tamper, expected) in cases.items():
            with self.subTest(case=label), bh.rolled_back():
                tamper()
                found = set(bs.verify_bundle_integrity(models.ConfigurationBundle.objects.get(pk=golden.pk)).codes)
                self.assertTrue(expected <= found, (label, found))

    def test_the_exported_golden_manifest_verifies_without_the_database_and_a_tampered_one_does_not(self):
        golden = self.golden()
        document = json.loads(bs.export_json(golden))
        self.assertEqual(document["manifest"]["lineage"]["promotion"]["soak_id"], self.run_row().soak_id)
        self.assertTrue(bs.verify_export(document).ok)
        forged = copy.deepcopy(document)
        forged["manifest"]["lineage"]["promotion"]["decision"] = "REJECT"
        self.assertFalse(bs.verify_export(forged).ok)
        stripped = copy.deepcopy(document)
        del stripped["manifest"]["lineage"]["promotion"]
        self.assertIn("PROMOTION_MISSING", bs.verify_export(stripped).codes)

    def test_only_a_golden_bundle_may_carry_provenance_and_the_uat_and_probation_digests_are_unchanged(self):
        golden = self.golden()
        self.assertNotIn("promotion", self.f.prob.manifest["lineage"])
        self.assertNotIn("promotion", self.f.uat.manifest["lineage"])
        self.assertEqual(self.f.prob.bundle_digest, canonical.bundle_digest(kind="PROBATION", payload_digest=self.f.prob.payload_digest,
                                                                            parent_bundle_digest=self.f.uat.bundle_digest, source_uat_bundle_digest=self.f.uat.bundle_digest))
        edited = copy.deepcopy(self.f.prob.manifest)
        edited["lineage"]["promotion"] = golden.lineage["promotion"]
        bh.oob(models.ConfigurationBundle).filter(pk=self.f.prob.pk).update(manifest=edited)
        self.assertIn("LINEAGE_INVALID", bs.verify_bundle_integrity(models.ConfigurationBundle.objects.get(pk=self.f.prob.pk)).codes)


class NoDeviceActionTests(Base):
    def test_approval_and_rejection_never_execute_reach_a_device_or_save_a_configuration(self):
        self.passed()
        run = self.run_row()
        before = bh.table_counts()
        with bh.no_device_or_network(), mock.patch("core.services.health.live.read_device", side_effect=AssertionError("approval must not read a device")), \
                self.assertLogs(lifecycle.log, logging.ERROR):
            result = self.approve(run)
        self.assertTrue(result.created, "the (blocked) notification never corrupts the decision")
        self.assertEqual(set(bh.count_changes(before, bh.table_counts())), {"ConfigurationBundle", "ConfigurationBundleItem", "GoldenDecision", "AuditEvent"})
        self.assertEqual(models.ChangeExecutionRun.objects.count(), 1, "no execution run was started")


# =============================================================================================================================
class SimulatedEndToEndTests(Base):
    """The 20A acceptance rehearsal: a SHORTENED TEST soak on a controlled clock.  This is NOT the real seven-day soak (Phase 20B)."""

    def test_the_complete_lifecycle_and_every_way_it_can_fail(self):
        stages = []
        # 1 eligible Probation -> explicit start (server-side timestamps)
        self.assertTrue(ss.check_soak_start(self.f.prob).eligible)
        run = self.start().run
        stages.append(("started", run.started_at, run.required_end_at))
        self.assertEqual(run.required_end_at - run.started_at, timedelta(seconds=7200))
        # 2 scheduled samples while the (controlled) clock advances; interference / integrity are re-checked on every tick
        world = copy.deepcopy(self.f.world)
        sh.drive(world, start=T0, until=END - timedelta(seconds=1))
        mid = self.run_row()
        self.assertEqual((mid.state, mid.samples.count()), (SS.RUNNING, 12))
        # 3 the window elapses -> technical PASS, and STILL no Golden
        sh.tick(END, world)
        done = self.run_row()
        self.assertEqual((done.state, done.result, done.samples.count()), (SS.COMPLETED, SRes.PASS, 13))
        self.assertEqual((models.ConfigurationBundle.objects.filter(kind="GOLDEN").count(), models.GoldenDecision.objects.count()), (0, 0))
        self.assertEqual(sh.tick(END + timedelta(seconds=600), world).runs, [], "the collector never touches a finished run and never promotes it")
        # 4 explicit operator APPROVE -> Golden, verified
        result = self.approve(done)
        golden = result.bundle
        self.assertTrue(bs.verify_bundle_integrity(golden).ok)
        self.assertEqual(golden.payload_digest, self.f.prob.payload_digest)
        self.assertEqual(golden.lineage["promotion"]["evidence_digest"], done.evidence_digest)
        self.assertEqual(evaluator.verify_run(done), [])
        stages.append(("approved", golden.bundle_id))
        self.assertEqual(len(stages), 2)

    def test_the_other_endings_stale_evidence_interference_failed_health_and_reject(self):
        for label, arrange, expected in (
            ("stale telemetry through the window", lambda w: sh.drive(w, start=T0, until=END, telemetry_at=lambda t: {"ages": {"R1": 500}}), (SS.COMPLETED, SRes.INCOMPLETE)),
            ("interference mid-window", lambda w: (sh.drive(w, start=T0, until=T0 + timedelta(seconds=1800)), sh.history_run(self.f.prob, ["R1"]),
                                                   sh.tick(sh.at(1860), w)), (SS.INVALIDATED, "")),
            ("failed health", lambda w: (w.state["R2"]["interfaces"].pop("Ethernet1"), sh.drive(w, start=T0, until=END)), (SS.COMPLETED, SRes.FAIL)),
        ):
            with self.subTest(ending=label), bh.rolled_back():
                self.start()
                arrange(copy.deepcopy(self.f.world))
                run = self.run_row()
                self.assertEqual((run.state, run.result), expected)
                blocked = ss.decide(run, decision="APPROVE", actor="operator", confirm=sh.confirm_of(run), now=END)
                self.assertTrue(blocked.refused and not models.ConfigurationBundle.objects.filter(kind="GOLDEN").exists())
        with bh.rolled_back():
            self.passed()
            run = self.run_row()
            ss.decide(run, decision="REJECT", actor="operator", confirm=sh.confirm_of(run), now=run.finished_at)
            self.assertFalse(models.ConfigurationBundle.objects.filter(kind="GOLDEN").exists())
