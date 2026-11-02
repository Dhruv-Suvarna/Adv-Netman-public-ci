"""Lab 7 closure -- the evidence models' own ``save`` / ``delete`` guards and small properties, each called directly.

Every other test reaches these through a service, which the governance tracer (correctly) does not count as a direct
call.  Here each guard is exercised on its own row: a standalone model is built field by field; a model that only exists
inside a lineage (bundle -> soak -> Golden, legacy candidate -> observation -> initial Golden) is first produced by the
real test factories (simulated network, controlled clock, no device) and then a FRESH copy of one of its rows is saved
directly.  POSITIVE: a valid new row is persisted with the exact values.  NEGATIVE: re-saving an append-only row, an
invalid state, or editing an immutable field is refused and the stored row is unchanged.

Nothing here touches a device, NetBox or a credential; it is the test database only.
"""

from __future__ import annotations

import copy
from datetime import timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from core import models
from core.tests.helpers import bootstrap as bh, bundles as bundles_helper, soak as sh

HEX = "a" * 64
HEX2 = "b" * 64
NOW = timezone.now()


def fresh_copy(row, **changes):
    """An unsaved duplicate of ``row`` (new primary key on save) with ``changes`` applied."""
    clone = copy.copy(type(row)._base_manager.get(pk=row.pk))
    clone.pk = None
    clone.id = None
    clone._state.adding = True
    for name, value in changes.items():
        setattr(clone, name, value)
    return clone


def reinsert(row):
    """Remove ``row`` out of band and hand back the same values as an unsaved row (for one-per-parent records)."""
    clone = fresh_copy(row)
    bundles_helper.oob(type(row)).filter(pk=row.pk).delete()
    return clone


def change(change_id="CHG-T-1"):
    row = models.Change(change_id=change_id, title="model guard test")
    row.save()
    return row


def provisioning_run(**extra):
    row = models.ProvisioningRun(device_name="R9", platform="frr", role="edge", requested_by="tester", **extra)
    row.save()
    return row


class StandaloneRowTests(TestCase):
    def test_capability_evidence_and_assessment_save_a_new_row(self):
        evidence = models.CapabilityEvidence(platform="frr", feature="ospf", axis="render", status="PASS", source="unit")
        evidence.save()
        assessment = models.CapabilityAssessment(platform="frr", feature="ospf", repository_head="c" * 40)
        assessment.save()
        self.assertEqual(models.CapabilityEvidence.objects.get(pk=evidence.pk).status, "PASS")
        self.assertEqual(models.CapabilityAssessment.objects.get(pk=assessment.pk).repository_head, "c" * 40)

    def test_capability_assessment_resave_is_refused_append_only(self):
        assessment = models.CapabilityAssessment(platform="frr", feature="ospf", repository_head="c" * 40)
        assessment.save()
        assessment.repository_head = "d" * 40
        with self.assertRaisesRegex(ValueError, "append-only"):
            assessment.save()
        self.assertEqual(models.CapabilityAssessment.objects.get(pk=assessment.pk).repository_head, "c" * 40)

    def test_network_config_validation_and_operational_check_runs_save(self):
        validation = models.NetworkConfigValidationRun(operation_type="CANDIDATE", status="PASS", engine_version="t1", input_hash=HEX)
        validation.save()
        check = models.OperationalCheckRun(mode="FLEET_QUICK", status="HEALTHY", engine_version="t1", started_at=NOW, finished_at=NOW)
        check.save()
        self.assertEqual(models.NetworkConfigValidationRun.objects.get(pk=validation.pk).input_hash, HEX)
        self.assertEqual(models.OperationalCheckRun.objects.get(pk=check.pk).status, "HEALTHY")

    def test_state_reconciliation_saves_with_digests(self):
        row = models.StateReconciliation(record_id="REC-900001", device_name="R9", cause="OUTSIDE_NMAS_CHANGE", actor="tester",
                                         reason="r", acknowledgement="ack", observed_at=NOW, previous_expected_digest=HEX,
                                         accepted_digest=HEX2, record_digest="c" * 64)
        row.save()
        self.assertEqual(models.StateReconciliation.objects.get(pk=row.pk).accepted_digest, HEX2)

    def test_maintenance_evidence_saves_a_chain_entry(self):
        record = models.MaintenanceRecord(device_name="R9", state="REQUESTED", requested_by="tester", reason="r", requested_at=NOW,
                                          requested_duration_seconds=600)
        record.save()
        entry = models.MaintenanceEvidence(record=record, sequence=1, kind="REQUESTED", at=NOW, actor="tester", payload_digest=HEX, entry_digest=HEX2)
        entry.save()
        self.assertEqual(list(models.MaintenanceEvidence.objects.filter(record=record).values_list("entry_digest", flat=True)), [HEX2])

    def test_change_lifecycle_event_and_plan_save_and_change_url(self):
        row = change()
        event = models.ChangeLifecycleEvent(change=row, to_state="DRAFT")
        event.save()
        validation = models.ChangeValidationRun(change=row, status="PASS", engine_version="t1", input_hash=HEX, source_hash=HEX2)
        validation.save()
        plan = models.ChangePlan(change=row, validation_run=validation, planner_version="t1", validation_input_hash=HEX,
                                 validation_source_hash=HEX2, validation_engine_version="t1", plan_hash="c" * 64)
        plan.save()
        self.assertEqual((models.ChangeLifecycleEvent.objects.get(pk=event.pk).to_state, models.ChangePlan.objects.get(pk=plan.pk).plan_hash),
                         ("DRAFT", "c" * 64))
        self.assertEqual(row.get_absolute_url(), reverse("core:device_builder_change_detail", args=[row.change_id]))

    def test_configlet_execution_result_saves_and_finalises_once(self):
        row = change()
        validation = models.ChangeValidationRun(change=row, status="PASS", engine_version="t1", input_hash=HEX, source_hash=HEX2)
        validation.save()
        plan = models.ChangePlan(change=row, validation_run=validation, planner_version="t1", validation_input_hash=HEX,
                                 validation_source_hash=HEX2, validation_engine_version="t1", plan_hash="c" * 64)
        plan.save()
        run = models.ChangeExecutionRun(change=row, plan=plan, validation_run=validation, mode="COMPLETE", engine_version="t1",
                                        plan_hash="c" * 64, validation_input_hash=HEX, validation_source_hash=HEX2, started_at=NOW,
                                        lease_expires_at=NOW + timedelta(minutes=5))
        run.save()
        result = models.ConfigletExecutionResult(run=run, cfg_id="CFG-001", sequence=1, device="R9", status="IN_PROGRESS", started_at=NOW)
        result.save()
        result.status = "APPLIED"
        result.save()
        self.assertEqual(models.ConfigletExecutionResult.objects.get(pk=result.pk).status, "APPLIED")

    def test_raw_configlet_revision_and_verification_save(self):
        row = change()
        raw = models.RawConfiglet(change=row, raw_id="RAW-001", sequence=1)
        raw.save()
        revision = models.RawConfigletRevision(raw=raw, revision=1, name="n", target_device="R9", platform="frr", priority=100,
                                               content="hostname R9\n", content_hash=HEX, policy_version="t1")
        revision.save()
        verification = models.RawConfigletVerificationRun(revision=revision, content_hash=HEX, platform="frr", verifier_version="t1",
                                                          policy_version="t1", started_at=NOW, lease_expires_at=NOW + timedelta(minutes=5))
        verification.save()
        self.assertEqual(raw.full_identifier, f"{row.change_id} / RAW-001")
        self.assertEqual((models.RawConfigletRevision.objects.get(pk=revision.pk).content_hash,
                          models.RawConfigletVerificationRun.objects.get(pk=verification.pk).state), (HEX, "RUNNING"))

    def test_configuration_template_and_draft_version_save_then_the_draft_deletes(self):
        template = models.ConfigurationTemplate(template_id="TPL-T-001", name="t")
        template.save()
        version = models.ConfigurationTemplateVersion(template=template, version=1, digest=HEX)
        version.save()
        self.assertEqual(models.ConfigurationTemplateVersion.objects.get(pk=version.pk).status, "DRAFT")
        pk = version.pk
        version.delete()
        self.assertFalse(models.ConfigurationTemplateVersion.objects.filter(pk=pk).exists())

    def test_provisioning_run_event_and_device_save(self):
        run = provisioning_run()
        event = models.ProvisioningEvent(run=run, sequence=1, stage="IDENTITY", outcome="ADVANCED", from_status="DRAFT", to_status="IDENTIFIED")
        event.save()
        device = models.ProvisionedDevice(name="R9", platform="frr", run=run, transport="docker")
        device.save()
        run.status = "IDENTIFIED"
        run.save()
        self.assertEqual((models.ProvisioningRun.objects.get(pk=run.pk).status, models.ProvisioningEvent.objects.get(pk=event.pk).to_status,
                          models.ProvisionedDevice.objects.get(pk=device.pk).state), ("IDENTIFIED", "IDENTIFIED", "ADMITTED"))

    def test_provisioned_device_with_an_unknown_state_or_a_moved_run_is_refused(self):
        run = provisioning_run()
        device = models.ProvisionedDevice(name="R9", platform="frr", run=run, transport="docker", state="BOGUS")
        with self.assertRaisesRegex(ValueError, "Invalid provisioned-device state"):
            device.save()
        device.state = "ADMITTED"
        device.save()
        device.platform = "ceos"
        with self.assertRaisesRegex(ValueError, "ProvisionedDevice.platform is immutable"):
            device.save()
        self.assertEqual(models.ProvisionedDevice.objects.get(pk=device.pk).platform, "frr")

    def test_traffic_run_is_active_until_finished(self):
        row = models.TrafficRun(operator="tester", source="H1", destination="H2", address_family="IPV4", family="ICMP", protocol="icmp")
        self.assertTrue(row.is_active)
        row.status = "PASSED"
        self.assertFalse(row.is_active)


class BundleLineageRowTests(TestCase):
    """A real UAT -> Probation -> soak -> Golden lineage, then a fresh copy of each row saved directly."""

    def test_bundle_item_soak_run_and_golden_decision_rows_save(self):
        p = bundles_helper.partial_run()
        uat = bundles_helper.uat_of(p)
        golden = sh.golden_from(bundles_helper.probation_of(uat))
        run = models.ProbationSoakRun.objects.get(bundle=golden.parent)
        self.assertEqual(run.get_absolute_url(), reverse("core:soak_detail", args=[run.soak_id]))
        self.assertEqual(uat.item_count, len(uat.payload["items"]))
        self.assertGreater(uat.item_count, 0)
        self.assertEqual(uat.get_absolute_url(), reverse("core:bundle_detail", args=[uat.bundle_id]))

        item = fresh_copy(uat.items.order_by("sequence").first(), sequence=99, cfg_id="CFG-T-99")
        item.save()
        soak = fresh_copy(run)
        soak.save()
        event = fresh_copy(models.ChangeLifecycleEvent.objects.filter(change=p.change).first())
        event.save()
        decision = reinsert(models.GoldenDecision.objects.get(run=run))
        decision.save()
        self.assertEqual(models.ConfigurationBundleItem.objects.get(pk=item.pk).cfg_id, "CFG-T-99")
        self.assertEqual((models.ProbationSoakRun.objects.get(pk=soak.pk).result, models.GoldenDecision.objects.get(pk=decision.pk).decision),
                         (run.result, "APPROVE"))
        self.assertNotEqual(soak.soak_id, run.soak_id)


class LegacyBootstrapRowTests(TestCase):
    """A real legacy-baseline capture, 30-minute observation and approval, then a fresh copy of each row saved directly."""

    def test_candidate_bundle_run_sample_and_decision_rows_save(self):
        _result, run, candidate, _world = bh.approved()
        self.assertFalse(run.is_running)
        self.assertEqual(run.get_absolute_url(), reverse("core:bootstrap_run_detail", args=[run.run_id]))

        bundle = fresh_copy(candidate, sequence=2, bundle_id="BND-LEGACY-000002")
        bundle.save()
        observation = fresh_copy(run)
        observation.save()
        sample = fresh_copy(run.samples.order_by("bucket").first(), bucket=99)
        sample.save()
        decision = reinsert(models.LegacyBootstrapDecision.objects.get(run=run))
        decision.save()
        self.assertEqual(models.ConfigurationBundle.objects.get(pk=bundle.pk).payload_digest, candidate.payload_digest)
        self.assertEqual((models.LegacyBootstrapRun.objects.get(pk=observation.pk).result, models.LegacyBootstrapSample.objects.get(pk=sample.pk).bucket),
                         (run.result, 99))
        self.assertEqual(models.LegacyBootstrapDecision.objects.get(pk=decision.pk).evidence_digest, run.evidence_digest)

    def test_legacy_bootstrap_decision_resave_is_refused_append_only(self):
        _result, run, _candidate, _world = bh.approved()
        decision = models.LegacyBootstrapDecision.objects.get(run=run)
        decision.decided_by = "someone-else"
        with self.assertRaisesRegex(ValueError, "append-only"):
            decision.save()
        self.assertEqual(models.LegacyBootstrapDecision.objects.get(pk=decision.pk).decided_by, "operator")
