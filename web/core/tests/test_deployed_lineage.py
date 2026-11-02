"""V2 Phase 5 -- the Complete -> Deployed -> Probation lineage for an ORDINARY configuration Change.

A SUCCEEDED Complete execution is the root of normal probation whether the Change is an ordinary configuration Change or a new-device
provisioning Change.  Sealing is an explicit, approval-gated, idempotent artifact creation: it never derives a Probation bundle, never
starts a soak, never shortens the seven-day policy and never touches the legacy bootstrap.  Partial (UAT) keeps its own meaning.
"""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import IntegrityError, transaction
from django.test import Client, TestCase
from django.urls import reverse

from core import models
from core.services import bundle_service as bs, soak_service as ss
from core.services.bundles import persistence, snapshot
from core.tests.helpers import bundles as bh, execution as ex, soak as sh
from core.tests.runner import sign_in

KIND = models.BundleKind
SEAL_BUTTON = "Seal Deployed bundle</button>"


def codes(result) -> list[str]:
    return [b["code"] for b in result.blockers]


class DeployedLineageFixture(TestCase):
    @classmethod
    def setUpTestData(cls):
        good = bh.complete_run()
        assert good.run.outcome == models.ExecutionOutcome.SUCCEEDED, good.run.outcome
        cls.run_pk, cls.change_id = good.run.pk, good.change.change_id

    def run_row(self, pk=None):
        return models.ChangeExecutionRun.objects.get(pk=pk or self.run_pk)

    def urls(self, run=None):
        run = run or self.run_row()
        cid = run.change.change_id
        return {"execution": reverse("core:change_execution_detail", args=[cid, run.run_id]),
                "create": reverse("core:change_execution_bundle_create", args=[cid, run.run_id])}


class OrdinaryCompleteChangeSealingTests(DeployedLineageFixture):
    def test_a_succeeded_ordinary_complete_run_is_eligible_and_seals_one_deployed_root(self):
        run = self.run_row()
        self.assertEqual(run.change.category, models.ChangeCategory.CONFIGURATION_CHANGE)
        self.assertFalse(models.ProvisioningRun.objects.exists())   # no provisioning reference exists or is invented
        gate = bs.check_deployed_eligibility(run)
        self.assertTrue(gate.eligible, codes(gate))
        self.assertEqual(gate.verification_state, "VERIFIED")
        result = bs.create_deployed_bundle(run, actor="approver")
        bundle = result.bundle
        self.assertTrue(result.created)
        self.assertEqual((bundle.kind, bundle.bundle_id[:8], bundle.created_by), (KIND.DEPLOYED, "BND-DEP-", "approver"))
        self.assertEqual((bundle.parent_id, bundle.source_uat_id), (None, None))
        self.assertEqual((bundle.change_id, bundle.plan_id, bundle.validation_run_id, bundle.execution_run_id, bundle.postcheck_run_id),
                         (run.change_id, run.plan_id, run.validation_run_id, run.pk, run.postcheck_run_id))
        source = bundle.payload["source"]
        self.assertEqual(source["change_id"], self.change_id)
        self.assertEqual((source["execution"]["run_id"], source["execution"]["mode"], source["execution"]["outcome"]),
                         (str(run.run_id), "COMPLETE", "SUCCEEDED"))
        self.assertEqual(source["execution"]["precheck_run_id"], str(run.precheck_run.run_id))
        self.assertEqual((source["plan"]["plan_id"], source["plan"]["plan_hash"]), (str(run.plan.plan_id), run.plan.plan_hash))
        self.assertEqual(source["validation"]["run_id"], str(run.validation_run.run_id))
        self.assertEqual(bundle.payload["verification"]["postcheck"]["run_id"], str(run.postcheck_run.run_id))
        self.assertIn(bundle.payload["verification"]["postcheck"]["result"], ("PASS", "PASS_WITH_WARNINGS"))
        self.assertEqual(bundle.payload["scope"]["requested"], list(run.plan.configlets.order_by("sequence").values_list("cfg_id", flat=True)))
        self.assertEqual(models.AuditEvent.objects.filter(event_type=models.AuditEventType.DEPLOYED_BUNDLE_CREATED).count(), 1)

    def test_sealing_is_artifact_creation_only_and_never_starts_probation(self):
        before = bh.table_counts()
        with bh.no_device_or_network():
            bundle = bs.create_deployed_bundle(self.run_row(), actor="approver").bundle
        changed = bh.count_changes(before, bh.table_counts())
        self.assertEqual(set(changed), {"ConfigurationBundle", "ConfigurationBundleItem", "AuditEvent"}, changed)
        self.assertEqual(models.ConfigurationBundle.objects.exclude(kind=KIND.DEPLOYED).count(), 0)   # no Probation, no Golden, no UAT
        self.assertFalse(models.ProbationSoakRun.objects.exists())
        self.assertEqual(self.run_row().change.lifecycle_state, bundle.change.lifecycle_state)

    def test_sealing_is_idempotent_and_the_database_refuses_a_second_root_for_the_run(self):
        first = bs.create_deployed_bundle(self.run_row(), actor="approver")
        again = bs.create_deployed_bundle(self.run_row(), actor="someone-else")
        self.assertEqual((again.bundle.pk, again.created, again.refused), (first.bundle.pk, False, False))
        self.assertEqual(again.bundle.created_by, "approver")
        gate = bs.check_deployed_eligibility(self.run_row())
        self.assertEqual((gate.eligible, gate.existing.pk), (False, first.bundle.pk))
        run = self.run_row()
        snap = snapshot.collect(run, kind=KIND.DEPLOYED)
        refs = dict(change=run.change, plan=run.plan, validation_run=run.validation_run, execution_run=run, postcheck_run=run.postcheck_run)
        with self.assertRaises(IntegrityError), transaction.atomic():   # the uniqueness constraint itself, without the service's own check
            persistence.seal_bundle(kind=KIND.DEPLOYED, payload=snap.payload, lineage={"parent_bundle_digest": "", "source_uat_bundle_digest": ""},
                                    refs=refs, item_specs=snap.item_specs, actor="racer")
        self.assertEqual(models.ConfigurationBundle.objects.filter(kind=KIND.DEPLOYED).count(), 1)

    def test_the_bundle_verifies_and_its_execution_reference_is_immutable(self):
        bundle = bs.create_deployed_bundle(self.run_row(), actor="approver").bundle
        report = bs.verify_bundle_integrity(bundle)
        self.assertTrue(report.ok, report.codes)
        with self.assertRaises(ValueError):
            bundle.save()
        other = bh.complete_run().run
        bh.oob(models.ConfigurationBundle).filter(pk=bundle.pk).update(execution_run=other)   # tampering, bypassing every guard
        tampered = bs.verify_bundle_integrity(models.ConfigurationBundle.objects.get(pk=bundle.pk))
        self.assertFalse(tampered.ok)

    def test_a_tampered_deployed_root_cannot_be_derived(self):
        bundle = bs.create_deployed_bundle(self.run_row(), actor="approver").bundle
        bh.oob(models.ConfigurationBundle).filter(pk=bundle.pk).update(payload_digest="0" * 64)
        refused = bs.derive_probation_bundle(models.ConfigurationBundle.objects.get(pk=bundle.pk), actor="approver")
        self.assertEqual((refused.bundle, codes(refused)), (None, ["SOURCE_INTEGRITY_FAILED"]))


class RefusalTests(TestCase):
    def assert_refused(self, run, expected):
        gate = bs.check_deployed_eligibility(run)
        self.assertFalse(gate.eligible)
        result = bs.create_deployed_bundle(run, actor="approver")
        self.assertEqual((result.bundle, result.refused, codes(result)), (None, True, expected))
        self.assertFalse(models.ConfigurationBundle.objects.exists())

    def test_partial_uat_never_produces_deployed_and_keeps_its_uat_lineage(self):
        partial = bh.partial_run(through=1)
        self.assert_refused(partial.run, ["MODE_NOT_COMPLETE", "OUTCOME_NOT_DEPLOYED"])
        uat = bs.create_uat_bundle(partial.run, actor="tester").bundle
        self.assertEqual((uat.kind, uat.bundle_id[:8]), (KIND.UAT, "BND-UAT-"))
        self.assertEqual(bs.derive_probation_bundle(uat, actor="tester").bundle.source_uat.kind, KIND.UAT)

    def test_a_complete_run_is_still_refused_as_a_uat_bundle(self):
        self.assertIn("MODE_NOT_PARTIAL_UAT", codes(bs.create_uat_bundle(bh.complete_run().run, actor="tester")))

    def test_a_blocked_run_is_refused(self):
        prepared = ex.prepared()
        world = ex.FakeWorld()
        world.fail_assess[ex.cfg_ids(prepared)[0]] = "PLATFORM_EXECUTION_UNSUPPORTED"
        result = ex.run(prepared, world)
        self.assertIn(result.outcome, (models.ExecutionOutcome.BLOCKED, models.ExecutionOutcome.FAILED_NO_MUTATION), result.outcome)
        self.assert_refused(result.run, ["OUTCOME_NOT_DEPLOYED"])

    def test_a_failed_and_compensated_run_is_refused(self):
        prepared = ex.prepared()
        world = ex.FakeWorld()
        world.fail_apply[ex.cfg_ids(prepared)[-1]] = ("COMMAND_REJECTED", False)
        result = ex.run(prepared, world)
        self.assertEqual(result.outcome, models.ExecutionOutcome.FAILED_ROLLED_BACK)
        self.assertTrue(result.run.results.filter(phase=models.ExecutionResultPhase.COMPENSATE).exists())
        self.assert_refused(result.run, ["OUTCOME_NOT_DEPLOYED"])

    def test_a_failed_postcheck_is_refused(self):
        prepared = ex.prepared()
        result = ex.run(prepared, ex.FakeWorld(), evidence_provider=lambda plan, cfg_ids: ex.h.evidence_set(ex.h.device_evidence("R1")))
        self.assertNotEqual(result.outcome, models.ExecutionOutcome.SUCCEEDED)
        self.assertIn("POSTCHECK", result.outcome)
        self.assert_refused(result.run, ["OUTCOME_NOT_DEPLOYED"])

    def test_a_succeeded_run_whose_postcheck_evidence_is_gone_or_not_passing_is_refused(self):
        run = bh.complete_run().run
        bh.oob(models.OperationalCheckRun).filter(pk=run.postcheck_run_id).update(status="FAIL")
        self.assert_refused(models.ChangeExecutionRun.objects.get(pk=run.pk), ["POSTCHECK_EVIDENCE_INVALID"])

    def test_a_run_that_is_not_finished_is_refused(self):
        run = bh.complete_run().run
        bh.oob(models.ChangeExecutionRun).filter(pk=run.pk).update(state=models.ExecutionRunState.RUNNING)
        self.assert_refused(models.ChangeExecutionRun.objects.get(pk=run.pk), ["RUN_NOT_FINISHED"])


class ProbationFromDeployedTests(DeployedLineageFixture):
    def test_probation_derives_from_the_deployed_root_and_a_normal_soak_can_start_without_any_golden(self):
        self.assertFalse(models.ConfigurationBundle.objects.filter(kind__in=(KIND.GOLDEN, KIND.LEGACY_BASELINE)).exists())
        root = bs.create_deployed_bundle(self.run_row(), actor="approver").bundle
        gate = bs.check_probation_eligibility(root)
        self.assertTrue(gate.eligible, codes(gate))
        probation = bs.derive_probation_bundle(root, actor="approver").bundle
        self.assertEqual((probation.kind, probation.parent_id, probation.source_uat_id), (KIND.PROBATION, root.pk, root.pk))
        self.assertEqual(probation.payload_digest, root.payload_digest)
        self.assertTrue(bs.verify_bundle_integrity(probation).ok)
        self.assertEqual(bs.lineage_of(probation)["uat"].pk, root.pk)
        self.assertFalse(models.ProbationSoakRun.objects.exists())          # deriving the candidate starts nothing
        start = ss.check_soak_start(probation)
        self.assertTrue(start.eligible, codes(start))                       # with NO current Golden: the first Golden comes from this path
        started = ss.start_soak(probation, actor="approver", now=sh.T0)
        self.assertIsNotNone(started.run, codes(started))
        self.assertEqual(started.run.required_end_at - started.run.started_at, timedelta(days=7))
        self.assertFalse(models.GoldenDecision.objects.exists())
        self.assertFalse(models.ConfigurationBundle.objects.filter(kind=KIND.GOLDEN).exists())

    def test_the_seven_day_policy_is_unchanged_and_no_bootstrap_path_is_used(self):
        policy = ss.current_policy()
        self.assertEqual((settings.SOAK_PRODUCTION_DURATION_SECONDS, policy.duration_seconds, policy.production_duration_seconds),
                         (604800, 604800, 604800))
        self.assertTrue(policy.is_production_duration)
        root = bs.create_deployed_bundle(self.run_row(), actor="approver").bundle
        bs.derive_probation_bundle(root, actor="approver")
        self.assertFalse(models.ConfigurationBundle.objects.filter(provenance=models.BundleProvenance.LEGACY_BOOTSTRAP).exists())
        self.assertEqual((models.LegacyBootstrapRun.objects.count(), models.LegacyBootstrapDecision.objects.count()), (0, 0))


class DeployedUiTests(DeployedLineageFixture):
    def test_the_execution_page_offers_sealing_then_the_bundle_page_offers_probation_and_nothing_starts_by_itself(self):
        page = self.client.get(self.urls()["execution"])
        self.assertContains(page, SEAL_BUTTON)
        self.assertNotContains(page, "Create UAT bundle</button>")
        self.assertFalse(models.ConfigurationBundle.objects.exists())      # GET never seals
        created = self.client.post(self.urls()["create"], {"kind": "UAT", "bundle_id": "BND-GOLD-000001", "actor": "mallory"})
        bundle = models.ConfigurationBundle.objects.get()
        self.assertEqual((bundle.kind, bundle.execution_run_id), (KIND.DEPLOYED, self.run_pk))   # the kind comes from the run, never the browser
        self.assertNotEqual(bundle.created_by, "mallory")
        self.assertEqual(created["Location"], f"{reverse('core:bundle_detail', args=[bundle.bundle_id])}?notice=DEPLOYED_CREATED")
        detail = self.client.get(created["Location"])
        self.assertContains(detail, "Deployed bundle sealed")
        self.assertContains(detail, "Create Probation bundle</button>")
        self.assertContains(detail, "Complete execution")
        self.assertNotContains(detail, "<h3>Golden bundle</h3>")           # a Deployed root is never presented as Golden
        self.assertNotContains(detail, "Start soak")
        self.assertEqual((models.ConfigurationBundle.objects.count(), models.ProbationSoakRun.objects.count()), (1, 0))
        again = self.client.post(self.urls()["create"])
        self.assertTrue(again["Location"].endswith("?notice=DEPLOYED_EXISTS"))
        self.assertEqual(models.ConfigurationBundle.objects.count(), 1)
        after = self.client.get(self.urls()["execution"])
        self.assertContains(after, bundle.bundle_id)
        self.assertNotContains(after, SEAL_BUTTON)
        listing = self.client.get(reverse("core:bundles_list"), {"change": self.change_id})
        self.assertContains(listing, bundle.bundle_id)

    def test_probation_is_a_separate_confirmed_action_and_the_soak_a_third(self):
        self.client.post(self.urls()["create"])
        root = models.ConfigurationBundle.objects.get()
        derive = reverse("core:bundle_derive_probation", args=[root.bundle_id])
        self.assertTrue(self.client.post(derive)["Location"].endswith("?notice=CONFIRM_REQUIRED"))
        self.assertEqual(models.ConfigurationBundle.objects.count(), 1)
        made = self.client.post(derive, {"confirm": "on"})
        probation = models.ConfigurationBundle.objects.get(kind=KIND.PROBATION)
        self.assertEqual(probation.parent_id, root.pk)
        page = self.client.get(made["Location"])
        self.assertContains(page, "Probation candidate")
        self.assertContains(page, f"Deployed <code>{root.bundle_id}</code>")
        self.assertContains(page, reverse("core:bundle_soak_start", args=[probation.bundle_id]))
        self.assertFalse(models.ProbationSoakRun.objects.exists())
        overview = self.client.get(reverse("core:probation_overview"))
        self.assertEqual(overview.status_code, 200)

    def test_an_ineligible_complete_run_shows_blockers_and_the_server_refuses_a_forced_post(self):
        prepared = ex.prepared()
        world = ex.FakeWorld()
        world.fail_apply[ex.cfg_ids(prepared)[-1]] = ("COMMAND_REJECTED", False)
        failed = ex.run(prepared, world).run
        page = self.client.get(self.urls(failed)["execution"])
        self.assertContains(page, "Not eligible for a Deployed bundle")
        self.assertContains(page, "OUTCOME_NOT_DEPLOYED")
        self.assertNotContains(page, SEAL_BUTTON)
        refused = self.client.post(self.urls(failed)["create"])
        self.assertTrue(refused["Location"].endswith("?bundle=refused"))
        self.assertContains(self.client.get(refused["Location"]), "not sealed")
        self.assertFalse(models.ConfigurationBundle.objects.exists())

    def test_a_partial_uat_run_page_offers_no_deployed_sealing(self):
        partial = bh.partial_run(through=1)
        page = self.client.get(self.urls(partial.run)["execution"])
        self.assertContains(page, "Create UAT bundle</button>")
        self.assertNotContains(page, SEAL_BUTTON)
        self.client.post(self.urls(partial.run)["create"])
        self.assertEqual(list(models.ConfigurationBundle.objects.values_list("kind", flat=True)), [KIND.UAT])

    def test_sealing_is_post_only_and_csrf_protected(self):
        self.assertEqual(self.client.get(self.urls()["create"]).status_code, 405)
        strict = self.client_class(enforce_csrf_checks=True)
        self.assertEqual(strict.post(self.urls()["create"]).status_code, 403)
        self.assertFalse(models.ConfigurationBundle.objects.exists())


class DeployedAuthorizationTests(DeployedLineageFixture):
    def client_for(self, username, *roles, mfa_verified=True):
        user = get_user_model().objects.create_user(username=username, password="x-not-used-0123456789")
        for role in roles:
            user.groups.add(Group.objects.get(name=role))
        client = Client()
        sign_in(client, get_user_model().objects.get(pk=user.pk), mfa_verified=mfa_verified)
        return client

    def test_sealing_requires_the_approve_permission_server_side(self):
        for name, roles in (("vera", ("NMAS Viewer",)), ("olga", ("NMAS Viewer", "NMAS Operator")), ("eve", ("NMAS Viewer", "NMAS Executor"))):
            with self.subTest(roles=roles):
                denied = self.client_for(name, *roles).post(self.urls()["create"])
                self.assertEqual(denied.status_code, 403)
        self.assertFalse(models.ConfigurationBundle.objects.exists())
        self.assertEqual(models.AuditEvent.objects.filter(event_type=models.AuditEventType.ACCESS_DENIED).count(), 3)
        approver = self.client_for("anna", "NMAS Viewer", "NMAS Approver")
        self.assertEqual(approver.post(self.urls()["create"]).status_code, 302)
        bundle = models.ConfigurationBundle.objects.get()
        self.assertEqual((bundle.kind, bundle.created_by), (KIND.DEPLOYED, "anna"))

    def test_anonymous_and_mfa_pending_sessions_cannot_seal(self):
        anonymous = Client().post(self.urls()["create"])
        self.assertEqual(anonymous.status_code, 302)
        self.assertIn(reverse("core:login"), anonymous["Location"])
        pending = self.client_for("pat", "NMAS Viewer", "NMAS Approver", mfa_verified=False).post(self.urls()["create"])
        self.assertEqual(pending.status_code, 302)
        self.assertIn("/accounts/mfa/", pending["Location"])
        self.assertFalse(models.ConfigurationBundle.objects.exists())

    def test_probation_and_soak_start_stay_approval_gated_for_a_deployed_lineage(self):
        root = bs.create_deployed_bundle(self.run_row(), actor="approver").bundle
        operator = self.client_for("otto", "NMAS Viewer", "NMAS Operator", "NMAS Executor")
        self.assertEqual(operator.post(reverse("core:bundle_derive_probation", args=[root.bundle_id]), {"confirm": "on"}).status_code, 403)
        probation = bs.derive_probation_bundle(root, actor="approver").bundle
        self.assertEqual(operator.post(reverse("core:bundle_soak_start", args=[probation.bundle_id]), {"confirm": "on"}).status_code, 403)
        self.assertFalse(models.ProbationSoakRun.objects.exists())
