"""Phase-19 immutable configuration bundles (UAT -> Probation -> Golden foundations): service + model contracts.

Every bundle in these tests is built from a REAL finished run of the production Phase-17 engine on the simulated network (no device,
NetBox, Slack, Docker or socket).  History that must be "corrupted" is corrupted OUT OF BAND (``bh.oob`` = the unguarded manager, i.e. what
a raw SQL edit looks like) and undone in a savepoint, so one real run serves a whole matrix.  Matrices use ``subTest``; a new case is a
new row, not a new method.  HTTP behaviour lives in ``test_bundle_views``; import / side-effect contracts in ``test_contracts``.
"""

from __future__ import annotations

import copy
import hashlib
import inspect
import json
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.db import IntegrityError, transaction
from django.db.models import ProtectedError, RestrictedError
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from core import models
from core.services import bundle_service as bs, raw_configlet_service as rcs, secret_policy
from core.services.bundles import canonical, eligibility, persistence, snapshot
from core.tests.helpers import bundles as bh, execution as ex, raw as rh

REPO_ROOT = Path(__file__).resolve().parents[3]
KIND = models.BundleKind


def codes(items) -> list[str]:
    return [item["code"] for item in items]


# =============================================================================================================================
class CanonicalizationTests(SimpleTestCase):
    VECTOR = {"b": [1, {"y": 2, "x": None}], "a": "text", "n": True}
    # Pinned test vectors: any accidental change to canonicalization or to a digest domain fails here.
    PAYLOAD = "6a83fc91b64f6099098f438135cdb5a7b97b5eb2916b9f4c496604e36a75c610"
    ITEM = "e9e61927a379136bb69370a59a69325d67a1b04582e88c78acd88618914fec56"
    UAT = "ea1b5987c80dcea6f1ac480efc42ea0e131665787430b36b4f0506da2b6a6635"
    PROBATION = "3401f59e09fe92a62deac2ebc7ea4c58695d431c90914eeb6a606b23f781d2a5"
    EXPORT = "2c85af1c13237120b66a1acc639c9d313714932ddbaa5c8dcf35c188892507e8"

    def test_canonical_json_is_deterministic_strict_and_never_a_repr(self):
        reordered = {"n": True, "a": "text", "b": [1, {"x": None, "y": 2}]}
        self.assertEqual(canonical.canonical_json(self.VECTOR), '{"a":"text","b":[1,{"x":null,"y":2}],"n":true}')
        self.assertEqual(canonical.canonical_json(reordered), canonical.canonical_json(self.VECTOR))
        pretty = json.loads(json.dumps(self.VECTOR, indent=4))   # whitespace in a source document is irrelevant
        self.assertEqual(canonical.payload_digest(pretty), canonical.payload_digest(self.VECTOR))
        for label, value in (("datetime", {"t": datetime.now()}), ("set", {"s": {1}}), ("object", {"o": object()}), ("NaN", {"f": float("nan")})):
            with self.subTest(refused=label), self.assertRaises((TypeError, ValueError)):
                canonical.canonical_json(value)   # never silently stringified into something unstable

    def test_fixed_vectors_domain_separation_and_an_independent_recomputation(self):
        self.assertEqual(canonical.payload_digest(self.VECTOR), self.PAYLOAD)
        self.assertEqual(canonical.item_digest(self.VECTOR), self.ITEM)
        self.assertEqual(canonical.bundle_digest(kind="UAT", payload_digest=self.PAYLOAD), self.UAT)
        self.assertEqual(canonical.bundle_digest(kind="PROBATION", payload_digest=self.PAYLOAD, parent_bundle_digest="a" * 64,
                                                 source_uat_bundle_digest="a" * 64), self.PROBATION)
        self.assertEqual(canonical.export_digest({"k": 1}), self.EXPORT)
        independent = hashlib.sha256(json.dumps({"domain": "clab.bundle.payload", "schema": 1, "value": self.VECTOR},
                                                sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(independent, self.PAYLOAD)
        self.assertEqual(canonical.text_hash("interface Ethernet1\n"), hashlib.sha256(b"interface Ethernet1\n").hexdigest())
        # the same bytes under different domains never collide
        self.assertEqual(len({canonical.payload_digest(self.VECTOR), canonical.item_digest(self.VECTOR), canonical.export_digest(self.VECTOR)}), 3)

    def test_what_each_digest_covers(self):
        base = {
            "source": {"plan": {"plan_hash": "p" * 64}, "git": {"repository_head": "abc"}}, "verification": {"state": "VERIFIED"},
            "items": [
                {"order": 1, "cfg_id": "CFG-001", "payload": "interface Ethernet1", "raw": None},
                {"order": 2, "cfg_id": "CFG-002", "payload": "x", "raw": {"revision_content_hash": "r" * 64, "verification": {"run_id": "v1"}}},
            ],
        }
        baseline = canonical.payload_digest(base)
        rows = [   # (what changes, must the PAYLOAD digest change?)
            ("configlet payload text", lambda p: p["items"][0].update(payload="interface Ethernet2"), True),
            ("configlet ORDER", lambda p: p["items"].reverse(), True),
            ("raw revision hash", lambda p: p["items"][1]["raw"].update(revision_content_hash="f" * 64), True),
            ("raw verification run", lambda p: p["items"][1]["raw"]["verification"].update(run_id="v2"), True),
            ("plan hash (source provenance)", lambda p: p["source"]["plan"].update(plan_hash="q" * 64), True),
            ("repository head (source provenance)", lambda p: p["source"]["git"].update(repository_head="def"), True),
            ("verification quality", lambda p: p["verification"].update(state="UNVERIFIED"), True),
        ]
        for label, mutate, changes in rows:
            with self.subTest(change=label):
                variant = copy.deepcopy(base)
                mutate(variant)
                self.assertEqual(canonical.payload_digest(variant) != baseline, changes)
        with self.subTest(change="dict insertion order"):
            self.assertEqual(canonical.payload_digest(dict(reversed(list(base.items())))), baseline)
        # the bundle digest additionally covers kind, lineage, schema version and the payload digest
        uat = canonical.bundle_digest(kind="UAT", payload_digest=baseline)
        for label, other in (
            ("kind", canonical.bundle_digest(kind="PROBATION", payload_digest=baseline)),
            ("parent digest", canonical.bundle_digest(kind="UAT", payload_digest=baseline, parent_bundle_digest="a" * 64)),
            ("source UAT digest", canonical.bundle_digest(kind="UAT", payload_digest=baseline, source_uat_bundle_digest="a" * 64)),
            ("schema version", canonical.bundle_digest(kind="UAT", payload_digest=baseline, schema_version=2)),
            ("payload digest", canonical.bundle_digest(kind="UAT", payload_digest="0" * 64)),
        ):
            with self.subTest(bundle_digest_covers=label):
                self.assertNotEqual(uat, other)


# =============================================================================================================================
class BundleFixture(TestCase):
    """One REAL, verified Partial (UAT) run (two of a four-Configlet plan) and one failed run, shared by every test of a subclass."""

    @classmethod
    def setUpTestData(cls):
        good = bh.partial_run(through=1)
        cls.run_pk, cls.cfgs, cls.change_id = good.run.pk, good.cfgs, good.change.change_id
        cls.failed_pk = bh.partial_run(through=3, fail={"CFG-003": ("COMMAND_REJECTED", True)}).run.pk

    def run_row(self, pk=None):
        return models.ChangeExecutionRun.objects.get(pk=pk or self.run_pk)

    def make_uat(self):
        return bh.uat_of(SimpleNamespace(run=self.run_row()))


class ModelImmutabilityTests(BundleFixture):
    def test_identity_kinds_and_per_kind_sequences(self):
        uat = self.make_uat()
        prob = bh.probation_of(uat)
        golden = bh.golden_from(prob)
        self.assertEqual([(b.bundle_id, b.kind, b.sequence) for b in (uat, prob, golden)],
                         [("BND-UAT-000001", KIND.UAT, 1), ("BND-PROB-000001", KIND.PROBATION, 1), ("BND-GOLD-000001", KIND.GOLDEN, 1)])
        self.assertEqual(sorted(KIND.values), ["DEPLOYED", "GOLDEN", "LEGACY_BASELINE", "PROBATION", "UAT"])   # an explicit typed enum; no DRAFT_GOLDEN / SOAKING / PROMOTED (LEGACY_BASELINE: the one-time bootstrap candidate)
        self.assertFalse(hasattr(models.ConfigurationBundle, "soak_state"))
        self.assertFalse(any("soak" in f.name or "promot" in f.name for f in models.ConfigurationBundle._meta.get_fields() if f.concrete))   # no soak column on a bundle
        self.assertEqual((uat.parent, uat.source_uat, prob.parent, prob.source_uat, golden.parent, golden.source_uat), (None, None, uat, uat, prob, uat))

    def test_a_persisted_bundle_and_its_items_cannot_be_changed_or_deleted(self):
        uat = self.make_uat()
        prob = bh.probation_of(uat)
        item = uat.items.first()
        snapshot_before = {"bundle": models.ConfigurationBundle.objects.filter(pk=uat.pk).values().get(),
                           "item": models.ConfigurationBundleItem.objects.filter(pk=item.pk).values().get()}
        row_edits = [
            ("kind", lambda b: setattr(b, "kind", KIND.GOLDEN)), ("manifest", lambda b: setattr(b, "manifest", {})),
            ("bundle digest", lambda b: setattr(b, "bundle_digest", "0" * 64)), ("payload digest", lambda b: setattr(b, "payload_digest", "0" * 64)),
            ("sequence", lambda b: setattr(b, "sequence", 9)), ("parent", lambda b: setattr(b, "parent", prob)),
            ("source execution", lambda b: setattr(b, "execution_run_id", b.execution_run_id + 1)), ("nothing at all", lambda b: None),
        ]
        for label, edit in row_edits:
            with self.subTest(bundle_field=label):
                target = models.ConfigurationBundle.objects.get(pk=uat.pk)
                edit(target)
                with self.assertRaises(ValueError):
                    target.save()
        for label, edit in (("payload", lambda i: setattr(i, "payload", "x")), ("payload hash", lambda i: setattr(i, "payload_hash", "0" * 64)),
                            ("sequence", lambda i: setattr(i, "sequence", 9)), ("record", lambda i: setattr(i, "record", {}))):
            with self.subTest(item_field=label):
                target = models.ConfigurationBundleItem.objects.get(pk=item.pk)
                edit(target)
                with self.assertRaises(ValueError):
                    target.save()
        bulk = [
            ("bundle queryset update", lambda: models.ConfigurationBundle.objects.filter(pk=uat.pk).update(kind="GOLDEN")),
            ("bundle bulk_update", lambda: models.ConfigurationBundle.objects.bulk_update([uat], ["kind"])),
            ("bundle queryset delete", lambda: models.ConfigurationBundle.objects.filter(pk=uat.pk).delete()),
            ("bundle instance delete", lambda: uat.delete()),
            ("item queryset update", lambda: models.ConfigurationBundleItem.objects.filter(pk=item.pk).update(payload="x")),
            ("item queryset delete", lambda: uat.items.all().delete()),
            ("item instance delete", lambda: item.delete()),
        ]
        for label, attempt in bulk:
            with self.subTest(bulk=label), self.assertRaises(ValueError):
                attempt()
        self.assertEqual(models.ConfigurationBundle.objects.filter(pk=uat.pk).values().get(), snapshot_before["bundle"])
        self.assertEqual(models.ConfigurationBundleItem.objects.filter(pk=item.pk).values().get(), snapshot_before["item"])

    def test_lineage_rules_are_enforced_on_write_and_backstopped_by_the_database(self):
        uat = self.make_uat()
        prob = bh.probation_of(uat)
        golden = bh.golden_from(prob)
        common = dict(schema_version=1, builder_version="t", payload_digest=uat.payload_digest, bundle_digest="c" * 64, manifest=uat.manifest,
                      change=uat.change, plan=uat.plan, validation_run=uat.validation_run, execution_run=uat.execution_run, postcheck_run=uat.postcheck_run)
        invalid = [   # (case, kwargs) -- every row must be REFUSED by the model
            ("a UAT bundle that has a parent", dict(bundle_id="BND-UAT-000900", kind=KIND.UAT, sequence=900, parent=uat, source_uat=uat)),
            ("a Probation bundle without a parent", dict(bundle_id="BND-PROB-000900", kind=KIND.PROBATION, sequence=900)),
            ("a Probation bundle from a Probation bundle", dict(bundle_id="BND-PROB-000901", kind=KIND.PROBATION, sequence=901, parent=prob, source_uat=uat)),
            ("a Probation bundle from a Golden bundle", dict(bundle_id="BND-PROB-000902", kind=KIND.PROBATION, sequence=902, parent=golden, source_uat=uat)),
            ("a Golden bundle straight from a UAT bundle", dict(bundle_id="BND-GOLD-000900", kind=KIND.GOLDEN, sequence=900, parent=uat, source_uat=uat)),
            ("a Golden bundle from a Golden bundle", dict(bundle_id="BND-GOLD-000901", kind=KIND.GOLDEN, sequence=901, parent=golden, source_uat=uat)),
            ("a derived bundle with a different payload", dict(bundle_id="BND-PROB-000903", kind=KIND.PROBATION, sequence=903, parent=uat, source_uat=uat, payload_digest="d" * 64)),
            ("an id that does not match the kind", dict(bundle_id="BND-GOLD-000904", kind=KIND.PROBATION, sequence=904, parent=uat, source_uat=uat)),
            ("an unknown kind", dict(bundle_id="BND-UAT-000905", kind="DRAFT_GOLDEN", sequence=905)),
            ("a malformed digest", dict(bundle_id="BND-UAT-000906", kind=KIND.UAT, sequence=906, bundle_digest="not-a-digest")),
        ]
        for label, extra in invalid:
            with self.subTest(refused=label), self.assertRaises(ValueError):
                models.ConfigurationBundle(**{**common, **extra}).save()
        # the database is the second layer (bulk_create skips save()): shape, idempotency and sequence uniqueness
        db_rules = [
            ("a UAT bundle that has a parent", dict(bundle_id="BND-UAT-000910", kind=KIND.UAT, sequence=910, parent=uat, source_uat=uat)),
            ("a Probation bundle without a parent", dict(bundle_id="BND-PROB-000910", kind=KIND.PROBATION, sequence=910)),
            ("a second UAT bundle for the same execution", dict(bundle_id="BND-UAT-000911", kind=KIND.UAT, sequence=911)),
            ("a second Probation bundle for the same UAT", dict(bundle_id="BND-PROB-000912", kind=KIND.PROBATION, sequence=912, parent=uat, source_uat=uat)),
            ("a second Golden bundle for the same Probation", dict(bundle_id="BND-GOLD-000913", kind=KIND.GOLDEN, sequence=913, parent=prob, source_uat=uat)),
            ("a duplicate per-kind sequence", dict(bundle_id="BND-PROB-000914", kind=KIND.PROBATION, sequence=1, parent=uat, source_uat=uat)),
        ]
        for label, extra in db_rules:
            with self.subTest(database=label), self.assertRaises(IntegrityError), transaction.atomic():
                models.ConfigurationBundle.objects.bulk_create([models.ConfigurationBundle(**{**common, **extra})])
        with self.subTest(database="a kind edit that breaks the shape (out-of-band UPDATE)"), self.assertRaises(IntegrityError), transaction.atomic():
            bh.oob(models.ConfigurationBundle).filter(pk=prob.pk).update(kind=KIND.UAT)   # a Probation row cannot be turned into a parented UAT row

    def test_history_a_bundle_pins_cannot_be_deleted_from_under_it(self):
        run = self.run_row()
        first_result = run.results.filter(phase="APPLY").order_by("sequence").first()
        first_configlet = run.plan.configlets.order_by("sequence").first()
        with bh.rolled_back():   # baseline: WITHOUT a bundle these rows are deletable, so the protection below is the bundle's
            models.ConfigletExecutionResult.objects.get(pk=first_result.pk).delete()
            models.Configlet.objects.get(pk=first_configlet.pk).delete()
        uat = self.make_uat()
        for label, target in (("execution result", models.ConfigletExecutionResult.objects.get(pk=first_result.pk)),
                              ("plan Configlet", models.Configlet.objects.get(pk=first_configlet.pk)),
                              ("plan", uat.plan), ("execution run", uat.execution_run), ("validation run", uat.validation_run),
                              ("postcheck run", uat.postcheck_run), ("change", uat.change), ("the bundle itself", uat)):
            with self.subTest(pinned=label), bh.rolled_back(), self.assertRaises((ProtectedError, RestrictedError, ValueError)):
                target.delete()
        self.assertEqual(models.ConfigurationBundle.objects.count(), 1)

    def test_golden_is_representable_structurally_and_verifies(self):
        prob = bh.probation_of(self.make_uat())
        golden = bh.golden_from(prob)
        self.assertEqual((golden.kind, golden.parent_id, golden.source_uat_id), (KIND.GOLDEN, prob.pk, prob.source_uat_id))
        self.assertEqual(golden.payload_digest, prob.payload_digest)
        self.assertTrue(bs.verify_bundle_integrity(golden).ok)
        self.assertEqual({k: (v.bundle_id if v is not None and hasattr(v, "bundle_id") else None) for k, v in bs.lineage_of(golden).items() if k != "execution"},
                         {"uat": "BND-UAT-000001", "probation": "BND-PROB-000001", "golden": "BND-GOLD-000001"})
        self.assertEqual(golden.items.count(), prob.items.count())


# =============================================================================================================================
class EligibilityTests(BundleFixture):
    def refused(self, run):
        result = bs.create_uat_bundle(run, actor="tester")
        self.assertTrue(result.refused and result.bundle is None)
        self.assertEqual(models.ConfigurationBundle.objects.count(), 0, "a refused request creates nothing")
        return codes(result.blockers)

    def test_a_successful_partial_uat_run_is_eligible_and_bundles_exactly_once(self):
        run = self.run_row()
        check = bs.check_uat_eligibility(run)
        self.assertEqual((check.eligible, check.blockers, check.existing, check.verification_state), (True, [], None, "VERIFIED"))
        first = bs.create_uat_bundle(run, actor="tester")
        again = bs.create_uat_bundle(run, actor="someone-else")
        self.assertEqual((first.created, again.created, again.existing, again.bundle.pk), (True, False, True, first.bundle.pk))
        self.assertEqual(models.ConfigurationBundle.objects.count(), 1)
        self.assertEqual(models.AuditEvent.objects.filter(event_type="UAT_BUNDLE_CREATED").count(), 1)
        self.assertFalse(bs.check_uat_eligibility(run).eligible)          # once bundled, the existing artifact is shown instead
        self.assertEqual(bs.check_uat_eligibility(run).existing.pk, first.bundle.pk)

    def test_only_a_terminal_applied_partial_uat_run_is_a_uat_candidate(self):
        unacknowledged = ex.prepared(mode=models.ExecutionMode.PARTIAL_UAT)   # refused for missing acknowledgements => a real BLOCKED run
        blocked_run = ex.run(unacknowledged, ex.FakeWorld(), through=ex.cfg_ids(unacknowledged)[1], acks=None).run
        complete = bh.complete_run()
        rows = [   # (case, run, must include these blocker codes)
            ("failed Partial run", self.run_row(self.failed_pk), {"OUTCOME_NOT_BUNDLEABLE"}),
            ("blocked run", blocked_run, {"OUTCOME_NOT_BUNDLEABLE"}),
            ("successful COMPLETE run", complete.run, {"MODE_NOT_PARTIAL_UAT", "OUTCOME_NOT_BUNDLEABLE"}),
        ]
        self.assertEqual((blocked_run.outcome, complete.run.outcome), ("BLOCKED", "SUCCEEDED"))
        for case, run, expected in rows:
            with self.subTest(case=case):
                check = bs.check_uat_eligibility(run)
                self.assertFalse(check.eligible)
                self.assertTrue(expected <= set(codes(check.blockers)), codes(check.blockers))
                self.assertTrue(bs.create_uat_bundle(run, actor="tester").refused)
        self.assertEqual(models.ConfigurationBundle.objects.count(), 0)
        oob_rows = [   # a run whose recorded state contradicts a clean UAT (out-of-band history edits, undone per row)
            ("still RUNNING", dict(state="RUNNING"), "RUN_NOT_FINISHED"),
            ("interrupted", dict(outcome="INTERRUPTED"), "OUTCOME_NOT_BUNDLEABLE"),
            ("unknown outcome", dict(outcome="SOMETHING_ELSE"), "OUTCOME_NOT_BUNDLEABLE"),
            ("postcheck failed", dict(outcome="UAT_SCOPE_APPLIED_POSTCHECK_FAILED"), "OUTCOME_NOT_BUNDLEABLE"),
            ("Complete recorded as the mode", dict(mode="COMPLETE"), "MODE_NOT_PARTIAL_UAT"),
        ]
        for case, edit, expected in oob_rows:
            with self.subTest(case=case), bh.rolled_back():
                bh.oob(models.ChangeExecutionRun).filter(pk=self.run_pk).update(**edit)
                self.assertIn(expected, self.refused(self.run_row()))

    def test_an_active_execution_of_the_change_or_its_devices_blocks_bundling(self):
        run = self.run_row()
        now = timezone.now()
        active = models.ChangeExecutionRun.objects.create(
            change=run.change, plan=run.plan, validation_run=run.validation_run, mode="PARTIAL_UAT", state="RUNNING", engine_version="17.0.0",
            plan_hash=run.plan_hash, validation_input_hash=run.validation_input_hash, validation_source_hash=run.validation_source_hash,
            started_at=now, lease_expires_at=now + timedelta(minutes=5),
        )
        self.assertIn("ACTIVE_EXECUTION", self.refused(run))
        with bh.rolled_back():   # ... and a device lock held by another run blocks it too
            bh.oob(models.ChangeExecutionRun).filter(pk=active.pk).update(state="FINISHED", outcome="BLOCKED")
            models.ExecutionDeviceLock.objects.create(device=run.devices[0], run=self.run_row(active.pk))
            self.assertIn("ACTIVE_EXECUTION", self.refused(run))

    def test_corrupted_or_incomplete_history_blocks_bundling_with_stable_codes(self):
        plan = self.run_row().plan
        first = plan.configlets.get(cfg_id="CFG-001")
        rows = [   # (case, edit, expected blocker code)
            ("scope record missing", lambda: bh.oob(models.ChangeExecutionRun).filter(pk=self.run_pk).update(scope={}), "SCOPE_UNKNOWN"),
            ("scope is not a plan prefix", lambda: bh.oob(models.ChangeExecutionRun).filter(pk=self.run_pk).update(
                scope={**self.run_row().scope, "requested": ["CFG-002", "CFG-001"], "through_cfg_id": "CFG-001"}), "SCOPE_UNKNOWN"),
            ("devices disagree with the scope", lambda: bh.oob(models.ChangeExecutionRun).filter(pk=self.run_pk).update(devices=["R9"]), "SCOPE_UNKNOWN"),
            ("run plan hash differs from the plan's", lambda: bh.oob(models.ChangeExecutionRun).filter(pk=self.run_pk).update(plan_hash="0" * 64), "PLAN_PROVENANCE_INVALID"),
            ("plan hash missing", lambda: bh.oob(models.ChangePlan).filter(pk=plan.pk).update(plan_hash=""), "PLAN_HASH_MISSING"),
            ("validation did not pass", lambda: bh.oob(models.ChangeValidationRun).filter(pk=plan.validation_run_id).update(status="BLOCKED"), "VALIDATION_NOT_PASSING"),
            ("a Configlet result is missing", lambda: self.run_row().results.filter(cfg_id="CFG-002").delete(), "RESULT_MISSING"),
            ("a Configlet result failed", lambda: bh.oob(models.ConfigletExecutionResult).filter(run_id=self.run_pk, cfg_id="CFG-002").update(status="FAILED"), "RESULT_NOT_APPLIED"),
            ("an applied result outside the scope", lambda: models.ConfigletExecutionResult.objects.create(
                run=self.run_row(), cfg_id="CFG-004", sequence=4, device="R1", phase="APPLY", status="APPLIED", started_at=timezone.now()), "RESULT_OUT_OF_SCOPE"),
            ("a plan Configlet no longer resolves", lambda: models.Configlet.objects.filter(plan=plan, cfg_id="CFG-004").delete(), "PLAN_CONFIGLETS_MISSING"),
            ("a prerequisite is outside the prefix", lambda: models.ConfigletDependency.objects.create(
                configlet=first, depends_on=plan.configlets.get(cfg_id="CFG-003")), "DEPENDENCY_SCOPE_INCONSISTENT"),
            ("the postcheck evidence is gone", lambda: bh.oob(models.ChangeExecutionRun).filter(pk=self.run_pk).update(postcheck_run=None), "POSTCHECK_EVIDENCE_INVALID"),
            ("the postcheck run contradicts the outcome", lambda: bh.oob(models.OperationalCheckRun).filter(pk=self.run_row().postcheck_run_id).update(status="FAIL"), "POSTCHECK_EVIDENCE_INVALID"),
        ]
        for case, edit, expected in rows:
            with self.subTest(case=case), bh.rolled_back():
                edit()
                self.assertIn(expected, self.refused(self.run_row()))

    def test_a_secret_shaped_payload_blocks_bundling_and_is_never_redacted_into_the_artifact(self):
        secret = "hunter2-do-not-leak"
        rows = [
            ("keyword with a value", lambda c: c.update(rendered_config=f"username admin secret {secret}")),
            ("credential format", lambda c: c.update(rendered_config="token ghp_" + "A" * 36)),
            ("secret-shaped descriptor key", lambda c: c.update(verification_spec={"requirements": [{"api_token": "x"}], "schema_version": 1})),
        ]
        for case, edit in rows:
            with self.subTest(case=case), bh.rolled_back():
                edit(models.Configlet.objects.filter(plan=self.run_row().plan, cfg_id="CFG-001"))
                result = bs.create_uat_bundle(self.run_row(), actor="tester")
                self.assertIn("SECRET_SHAPED_PAYLOAD", codes(result.blockers))
                self.assertNotIn(secret, json.dumps(result.blockers, default=str))   # findings carry pattern NAMES and line numbers only
                self.assertEqual(models.ConfigurationBundle.objects.count(), 0)


# =============================================================================================================================
class PrefixTests(BundleFixture):
    def test_the_bundle_is_exactly_the_executed_prefix_and_nothing_else(self):
        run = self.run_row()
        uat = self.make_uat()
        plan_texts = {c.cfg_id: c.rendered_config for c in run.plan.configlets.all()}
        self.assertEqual(self.cfgs, ["CFG-001", "CFG-002", "CFG-003", "CFG-004"])
        self.assertEqual([(i.sequence, i.cfg_id) for i in uat.items.all()], [(1, "CFG-001"), (2, "CFG-002")])
        scope = uat.payload["scope"]
        self.assertEqual((scope["requested"], scope["through_cfg_id"], scope["out_of_scope"]), (["CFG-001", "CFG-002"], "CFG-002", ["CFG-003", "CFG-004"]))
        manifest_text = canonical.canonical_json(uat.manifest)
        for later in ("CFG-003", "CFG-004"):   # the unapplied remainder is named (as out of scope) but its payload is never included
            with self.subTest(excluded=later):
                self.assertNotIn(canonical.canonical_json(plan_texts[later]), manifest_text)   # no JSON string value equals its text
                self.assertNotIn(plan_texts[later], [i["payload"] for i in uat.payload["items"]])
                self.assertNotIn(later, [i["cfg_id"] for i in uat.payload["items"]])
        self.assertTrue(all(e["configlet"] in scope["requested"] and e["depends_on"] in scope["requested"] for e in uat.payload["dependencies"]))
        self.assertEqual(scope["devices"], sorted({i.device for i in uat.items.all()}))

    def test_a_single_configlet_prefix_is_a_valid_scope(self):
        single = bh.partial_run(through=0)
        uat = bh.uat_of(single)
        self.assertEqual([i.cfg_id for i in uat.items.all()], ["CFG-001"])
        self.assertEqual(uat.payload["scope"]["out_of_scope"], ["CFG-002", "CFG-003", "CFG-004"])

    def test_later_changes_never_leak_into_an_existing_bundle(self):
        uat = self.make_uat()
        digest, manifest = uat.bundle_digest, copy.deepcopy(uat.manifest)
        run = self.run_row()
        # writable execution-phase fields are rewritten by execution history and are deliberately NOT part of any payload
        models.Configlet.objects.filter(plan=run.plan).update(execution_status="FAILED", previous_state_ref={"changed": True}, metadata={"changed": True})
        # a newer Configlet appended to the plan afterwards (a newer plan modification) is not part of the executed scope
        models.Configlet.objects.create(change=run.change, plan=run.plan, cfg_id="CFG-005", sequence=5, target_device="R1", feature_namespace="interfaces",
                                        operation_type="CREATE_DEFINE", deployment_priority=2, rendered_config="interface Loopback55")
        fresh = bs.get_bundle(uat.bundle_id)
        self.assertEqual((fresh.bundle_digest, fresh.manifest), (digest, manifest))
        self.assertTrue(bs.verify_bundle_integrity(fresh).ok)
        self.assertEqual([i.cfg_id for i in fresh.items.all()], ["CFG-001", "CFG-002"])
        self.assertEqual(bs.create_uat_bundle(run, actor="tester").bundle.pk, uat.pk)   # idempotent: no second, "newer" artifact


# =============================================================================================================================
class ProbationTests(BundleFixture):
    def test_derivation_seals_the_same_payload_as_a_new_artifact_and_leaves_the_uat_untouched(self):
        uat = self.make_uat()
        uat_row = models.ConfigurationBundle.objects.filter(pk=uat.pk).values().get()
        uat_items = list(uat.items.values())
        check = bs.check_probation_eligibility(uat)
        self.assertEqual((check.eligible, check.blockers, check.existing, check.integrity.ok), (True, [], None, True))
        result = bs.derive_probation_bundle(uat, actor="tester")
        prob = result.bundle
        self.assertTrue(result.created)
        self.assertEqual((prob.kind, prob.parent_id, prob.source_uat_id, prob.bundle_id), (KIND.PROBATION, uat.pk, uat.pk, "BND-PROB-000001"))
        self.assertEqual(prob.manifest["payload"], uat.manifest["payload"])                 # configuration equivalence
        self.assertEqual(prob.payload_digest, uat.payload_digest)                            # ... demonstrated by the payload digest
        self.assertNotEqual(prob.bundle_digest, uat.bundle_digest)                           # kind + lineage give a distinct artifact identity
        self.assertEqual(prob.lineage, {"parent_bundle_digest": uat.bundle_digest, "source_uat_bundle_digest": uat.bundle_digest})
        self.assertEqual([(i.cfg_id, i.payload_hash, i.item_digest, i.configlet_id, i.raw_revision_id) for i in prob.items.all()],
                         [(i.cfg_id, i.payload_hash, i.item_digest, i.configlet_id, i.raw_revision_id) for i in uat.items.all()])
        self.assertEqual(models.ConfigurationBundle.objects.filter(pk=uat.pk).values().get(), uat_row)   # the UAT bundle is byte-for-byte unchanged
        self.assertEqual(list(uat.items.values()), uat_items)
        self.assertEqual(uat.kind, KIND.UAT)
        self.assertTrue(bs.verify_bundle_integrity(prob).ok and bs.verify_bundle_integrity(uat).ok)
        audit = models.AuditEvent.objects.get(event_type="PROBATION_BUNDLE_CREATED")
        self.assertEqual((audit.object_id, audit.metadata["parent_bundle_id"], audit.metadata["result"]), (prob.bundle_id, uat.bundle_id, "CREATED"))

    def test_derivation_is_idempotent_and_a_lost_race_returns_the_winner(self):
        uat = self.make_uat()
        first = bs.derive_probation_bundle(uat, actor="a")
        again = bs.derive_probation_bundle(uat, actor="b")
        self.assertEqual((again.created, again.existing, again.bundle.pk), (False, True, first.bundle.pk))
        self.assertEqual(models.ConfigurationBundle.objects.filter(kind=KIND.PROBATION).count(), 1)
        self.assertFalse(bs.check_probation_eligibility(uat).eligible)
        # two RACING requests: the loser saw no child (its existence checks ran before the winner committed), then loses the
        # database uniqueness race and must return the winner's artifact rather than create a second one
        with mock.patch.object(eligibility, "existing_child", side_effect=[None, None, first.bundle]):
            loser = bs.derive_probation_bundle(uat, actor="loser")
        self.assertEqual((loser.created, loser.bundle.pk), (False, first.bundle.pk))
        self.assertEqual(models.ConfigurationBundle.objects.filter(kind=KIND.PROBATION).count(), 1)

    def test_concurrent_uat_creation_never_produces_two_artifacts(self):
        run = self.run_row()
        winner = self.make_uat()
        with mock.patch.object(eligibility, "existing_uat", side_effect=[None, winner]):
            loser = bs.create_uat_bundle(run, actor="loser")
        self.assertEqual((loser.created, loser.bundle.pk), (False, winner.pk))
        self.assertEqual(models.ConfigurationBundle.objects.filter(kind=KIND.UAT).count(), 1)
        # a lost race on the per-kind SEQUENCE (not on the artifact) is retried with the next number, never surfaced as an error
        other = bh.partial_run(through=0)
        with mock.patch.object(persistence, "_next_sequence", side_effect=[1, 2]):
            retried = bs.create_uat_bundle(other.run, actor="tester")
        self.assertEqual((retried.created, retried.bundle.bundle_id), (True, "BND-UAT-000002"))

    def sealed_uat(self, mutate):
        """A UAT bundle whose (digest-consistent) payload was edited BEFORE sealing: it verifies, yet its evidence is bad."""
        run = self.run_row()
        snap = snapshot.collect(run)
        mutate(snap.payload)
        refs = dict(change=run.change, plan=run.plan, validation_run=run.validation_run, execution_run=run, postcheck_run=run.postcheck_run)
        return persistence.seal_bundle(kind=KIND.UAT, payload=snap.payload, lineage={"parent_bundle_digest": "", "source_uat_bundle_digest": ""},
                                       refs=refs, item_specs=snap.item_specs, actor="factory", audit=False)

    def test_ineligible_sources_are_refused_with_stable_codes_and_create_nothing(self):
        evidence_rows = [
            ("a failed included Configlet result", lambda p: p["items"][0]["execution"].update(status="FAILED"), "RESULT_NOT_APPLIED"),
            ("a failed postcheck result", lambda p: p["verification"]["postcheck"].update(result="FAIL"), "POSTCHECK_NOT_ACCEPTABLE"),
        ]
        for case, mutate, expected in evidence_rows:
            with self.subTest(case=case), bh.rolled_back():
                bad = self.sealed_uat(mutate)
                self.assertTrue(bs.verify_bundle_integrity(bad).ok, "the evidence is bad, not the digest")
                self.assertIn(expected, codes(bs.derive_probation_bundle(bad, actor="tester").blockers))
                self.assertFalse(models.ConfigurationBundle.objects.filter(kind=KIND.PROBATION, parent=bad).exists())
        raw_unverified = bh.raw_run()
        prob = bh.probation_of(self.make_uat())
        rows = [   # (case, source bundle factory, blocker codes that must be reported)
            ("an UNVERIFIED UAT scope", lambda: bh.uat_of(raw_unverified), {"SOURCE_UNVERIFIED", "POSTCHECK_NOT_ACCEPTABLE"}),
            ("a Probation source", lambda: prob, {"SOURCE_NOT_UAT"}),
            ("a Golden source", lambda: bh.golden_from(prob), {"SOURCE_NOT_UAT"}),
        ]
        for case, source, expected in rows:
            with self.subTest(case=case), bh.rolled_back():
                bundle = source()
                before = models.ConfigurationBundle.objects.filter(kind=KIND.PROBATION).count()
                result = bs.derive_probation_bundle(bundle, actor="tester")
                self.assertTrue(result.refused and result.bundle is None)
                self.assertTrue(expected <= set(codes(result.blockers)), codes(result.blockers))
                self.assertEqual(models.ConfigurationBundle.objects.filter(kind=KIND.PROBATION).count(), before)

    def test_an_integrity_failure_blocks_derivation_is_audited_once_and_is_never_repaired(self):
        uat = self.make_uat()
        tampered = copy.deepcopy(uat.manifest)
        tampered["payload"]["items"][0]["payload"] = "interface Ethernet9"
        bh.oob(models.ConfigurationBundle).filter(pk=uat.pk).update(manifest=tampered)
        uat = bs.get_bundle(uat.bundle_id)
        result = bs.derive_probation_bundle(uat, actor="tester")
        self.assertEqual(codes(result.blockers), ["SOURCE_INTEGRITY_FAILED"])
        self.assertIn("PAYLOAD_DIGEST_MISMATCH", result.blockers[0]["details"]["findings"])
        self.assertFalse(models.ConfigurationBundle.objects.filter(kind=KIND.PROBATION).exists())
        audit = models.AuditEvent.objects.get(event_type="BUNDLE_INTEGRITY_FAILED")
        self.assertEqual((audit.object_id, audit.metadata["result"], audit.metadata["context"]), (uat.bundle_id, "FAILED", "probation derivation refused"))
        self.assertLess(len(json.dumps(audit.metadata)), 800)                 # bounded: codes, never the manifest
        self.assertNotIn("Ethernet9", json.dumps(audit.metadata))
        self.assertEqual(bs.get_bundle(uat.bundle_id).manifest, tampered)      # nothing was silently repaired
        self.assertFalse(bs.verify_bundle_integrity(uat).ok)


# =============================================================================================================================
class GoldenBoundaryTests(BundleFixture):
    def test_promotion_needs_soak_evidence_and_nothing_else_is_accepted_as_evidence(self):
        prob = bh.probation_of(self.make_uat())
        before = bh.table_counts()
        for label, evidence in (("no evidence", None), ("fabricated evidence", SimpleNamespace(soak_passed=True, decided_by="operator")),
                                ("a bare string", "approved"), ("a dict", {"golden": True})):
            with self.subTest(evidence=label):
                check = bs.check_golden_eligibility(prob, evidence)
                expected = "PHASE20_EVIDENCE_REQUIRED" if evidence is None else "EVIDENCE_TYPE_UNSUPPORTED"   # only a ProbationSoakRun is evidence
                self.assertEqual((check.eligible, codes(check.blockers)), (False, [expected]))
                result = bs.create_golden_bundle(prob, evidence=evidence, actor="tester")
                self.assertTrue(result.refused and result.bundle is None)
                self.assertEqual(codes(result.blockers), [expected])
                self.assertFalse(bs.can_create_golden_from(prob, evidence))
        self.assertEqual(bh.count_changes(before, bh.table_counts()), {}, "a refused Golden request writes nothing, not even an audit event")
        self.assertFalse(models.ConfigurationBundle.objects.filter(kind=KIND.GOLDEN).exists())

    def test_only_a_verified_probation_bundle_is_even_a_golden_source(self):
        uat = self.make_uat()
        self.assertEqual(codes(bs.check_golden_eligibility(uat).blockers), ["SOURCE_NOT_PROBATION"])
        prob = bh.probation_of(uat)
        bh.oob(models.ConfigurationBundle).filter(pk=prob.pk).update(bundle_digest="0" * 64)
        self.assertEqual(codes(bs.check_golden_eligibility(bs.get_bundle(prob.bundle_id)).blockers), ["SOURCE_INTEGRITY_FAILED", "PHASE20_EVIDENCE_REQUIRED"])

    def test_creating_bundles_never_creates_golden_or_starts_a_soak_and_a_bundle_carries_no_soak_state(self):
        prob = bh.probation_of(self.make_uat())
        self.assertFalse(models.ConfigurationBundle.objects.filter(kind=KIND.GOLDEN).exists())
        self.assertFalse(models.ProbationSoakRun.objects.exists() or models.GoldenDecision.objects.exists())   # deriving Probation starts no soak
        self.assertEqual(models.Change.objects.get(change_id=self.change_id).lifecycle_state, "DRAFT")   # the Change lifecycle is untouched
        forbidden = ("soak_passed", "soak_state", "soak_started_at", "soak_ends_at", "promoted_at", "golden_decision")
        self.assertEqual({f.name for f in models.ConfigurationBundle._meta.get_fields() if f.concrete} & set(forbidden), set())
        self.assertEqual(set(prob.verification) & set(forbidden), set())
        self.assertNotIn("soak", canonical.canonical_json(prob.manifest).lower())   # a Probation manifest says nothing about a soak
        self.assertFalse(hasattr(models, "GoldenBundle") or hasattr(models, "SoakTimer"))   # the Phase-8 absence guard still holds


# =============================================================================================================================
class RawBundleTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        unverified, verified = bh.raw_run(), bh.raw_run(assertions=[bh.ADDRESS_ASSERTION], effect=bh.LOOPBACK_PRESENT)
        cls.unverified_pk, cls.verified_pk = unverified.run.pk, verified.run.pk
        cls.raw_pk = unverified.raw.raw.pk

    def run_row(self, pk):
        return models.ChangeExecutionRun.objects.get(pk=pk)

    def test_the_exact_revision_and_verification_are_pinned_and_a_newer_revision_is_ignored(self):
        run = self.run_row(self.unverified_pk)
        raw = models.RawConfiglet.objects.get(pk=self.raw_pk)
        pinned = run.plan.configlets.get(origin="RAW")
        self.assertEqual(run.outcome, "UAT_SCOPE_APPLIED_UNVERIFIED")
        newer, created = rcs.save_revision(raw, target_device="R1", name="Loopback", content=rh.EOS_TEXT_2, priority=6, actor="tester")
        self.assertTrue(created and newer.revision == 2)
        uat = bs.create_uat_bundle(run, actor="tester").bundle           # created AFTER the newer revision exists
        item = uat.items.get(origin="RAW")
        self.assertEqual((item.raw_revision_id, item.raw_verification_id), (pinned.raw_revision_id, pinned.raw_verification_id))
        self.assertEqual(item.raw_revision.revision, 1)
        self.assertEqual(item.payload, pinned.raw_revision.content)     # the immutable revision text, not the newer one
        record = item.record["raw"]
        self.assertEqual((record["raw_id"], record["revision"], record["revision_content_hash"]), ("RAW-001", 1, pinned.raw_revision.content_hash))
        self.assertEqual(record["verification"]["run_id"], str(pinned.raw_verification.run_id))
        self.assertNotIn("Loopback98", canonical.canonical_json(uat.manifest))   # the newer revision's text is nowhere in the bundle
        self.assertEqual(item.payload_hash, canonical.text_hash(pinned.raw_revision.content))
        self.assertTrue(bs.verify_bundle_integrity(uat).ok)

    def test_a_syntax_pass_is_never_presented_as_operational_verification(self):
        uat = bs.create_uat_bundle(self.run_row(self.unverified_pk), actor="tester").bundle
        verification = uat.items.get(origin="RAW").record["raw"]["verification"]
        self.assertEqual((verification["result"], verification["scope"], verification["semantics_verified"]), ("PASS", "SYNTAX_ONLY", False))
        self.assertEqual(uat.verification_state, "UNVERIFIED")           # the sandbox PASS did not upgrade the scope
        self.assertEqual([(u["cfg_id"], u["requirement"]) for u in uat.verification["unverified"]], [("CFG-005", "RAW_CONFIG_APPLIED")])
        self.assertEqual(uat.verification["postcheck"]["result"], "INCOMPLETE")
        self.assertEqual(uat.verification["raw_cfg_ids"], ["CFG-005"])

    def test_an_unverified_scope_may_be_bundled_but_can_never_enter_probation(self):
        uat = bs.create_uat_bundle(self.run_row(self.unverified_pk), actor="tester").bundle
        check = bs.check_probation_eligibility(uat)
        self.assertEqual((check.eligible, {"SOURCE_UNVERIFIED", "POSTCHECK_NOT_ACCEPTABLE"} <= set(codes(check.blockers))), (False, True))
        self.assertTrue(bs.derive_probation_bundle(uat, actor="tester").refused)
        verified = bs.create_uat_bundle(self.run_row(self.verified_pk), actor="tester").bundle
        self.assertEqual((self.run_row(self.verified_pk).outcome, verified.verification_state), ("UAT_SCOPE_APPLIED", "VERIFIED"))
        prob = bs.derive_probation_bundle(verified, actor="tester").bundle    # a declared, confirmed assertion IS operational evidence
        self.assertEqual(prob.items.get(origin="RAW").raw_revision_id, verified.items.get(origin="RAW").raw_revision_id)

    def test_missing_or_altered_raw_provenance_blocks_bundling(self):
        run = self.run_row(self.unverified_pk)
        cfg = run.plan.configlets.get(origin="RAW")
        rows = [   # (case, out-of-band edit, expected blocker code)
            ("the plan's revision pin is gone", lambda: bh.oob(models.Configlet).filter(pk=cfg.pk).update(raw_revision=None), "RAW_PROVENANCE_MISSING"),
            ("the plan's verification pin is gone", lambda: bh.oob(models.Configlet).filter(pk=cfg.pk).update(raw_verification=None), "RAW_PROVENANCE_MISSING"),
            ("the recorded pin names another content hash", lambda: bh.oob(models.Configlet).filter(pk=cfg.pk).update(
                desired_state_ref={**cfg.desired_state_ref, "raw": {**cfg.desired_state_ref["raw"], "content_hash": "0" * 64}}), "RAW_PROVENANCE_MISSING"),
            ("the run report has no raw pin", lambda: bh.oob(models.ChangeExecutionRun).filter(pk=run.pk).update(report={**run.report, "raw_configlets": []}), "RAW_PROVENANCE_MISSING"),
            ("the immutable revision text was altered", lambda: bh.oob(models.RawConfigletRevision).filter(pk=cfg.raw_revision_id).update(content="interface Loopback1\n"), "RAW_REVISION_INTEGRITY"),
            ("the pinned verification is not acceptable", lambda: bh.oob(models.RawConfigletVerificationRun).filter(pk=cfg.raw_verification_id).update(result="BLOCKED"), "RAW_VERIFICATION_INVALID"),
        ]
        for case, edit, expected in rows:
            with self.subTest(case=case), bh.rolled_back():
                edit()
                result = bs.create_uat_bundle(self.run_row(self.unverified_pk), actor="tester")
                self.assertIn(expected, codes(result.blockers))
                self.assertEqual(models.ConfigurationBundle.objects.count(), 0)

    def test_creation_takes_no_browser_text_and_the_bundle_reuses_no_verification(self):
        self.assertEqual(list(inspect.signature(bs.create_uat_bundle).parameters), ["run", "actor"])
        self.assertEqual(list(inspect.signature(bs.derive_probation_bundle).parameters), ["uat", "actor"])
        runs_before = models.RawConfigletVerificationRun.objects.count()
        with bh.no_device_or_network():
            bs.create_uat_bundle(self.run_row(self.unverified_pk), actor="tester")
        self.assertEqual(models.RawConfigletVerificationRun.objects.count(), runs_before)   # nothing was re-verified, no sandbox started


# =============================================================================================================================
class IntegrityTests(BundleFixture):
    def build(self):
        uat = self.make_uat()
        return uat, bh.probation_of(uat)

    def report(self, bundle):
        return bs.verify_bundle_integrity(bs.get_bundle(bundle.bundle_id))

    def test_an_untouched_lineage_verifies_and_verification_is_read_only(self):
        uat, prob = self.build()
        before = bh.table_counts()
        for bundle in (uat, prob):
            report = bs.verify_bundle_integrity(bundle)
            self.assertEqual((report.ok, report.state, report.findings), (True, "INTACT", []))
            self.assertEqual(report.checks, ["schema", "payload_digest", "bundle_digest", "secret_hygiene", "lineage", "promotion", "items", "sources"])
        self.assertEqual(bh.count_changes(before, bh.table_counts()), {}, "verifying writes nothing, not even an audit event")
        self.assertEqual(models.AuditEvent.objects.filter(event_type="BUNDLE_INTEGRITY_FAILED").count(), 0)

    def test_tampering_is_detected_wherever_it_happens(self):
        uat, prob = self.build()
        other_run = self.run_row(self.failed_pk)

        def edit_manifest(bundle, mutate):
            manifest = copy.deepcopy(bundle.manifest)
            mutate(manifest)
            bh.oob(models.ConfigurationBundle).filter(pk=bundle.pk).update(manifest=manifest)

        def item(bundle, seq=1):
            return bh.oob(models.ConfigurationBundleItem).filter(bundle=bundle, sequence=seq)

        rows = [   # (case, tamper, bundle to verify, finding codes that must be reported)
            ("manifest item payload edited", lambda: edit_manifest(prob, lambda m: m["payload"]["items"][0].update(payload="interface X")), prob,
             {"PAYLOAD_DIGEST_MISMATCH", "ITEM_PAYLOAD_HASH_MISMATCH"}),
            ("manifest configlet order swapped", lambda: edit_manifest(prob, lambda m: m["payload"]["items"].reverse()), prob, {"PAYLOAD_DIGEST_MISMATCH", "ITEMS_MISMATCH"}),
            ("manifest schema version bumped", lambda: edit_manifest(prob, lambda m: m.update(manifest_schema_version=2)), prob, {"SCHEMA_UNSUPPORTED"}),
            ("manifest kind rewritten", lambda: edit_manifest(prob, lambda m: m.update(kind="GOLDEN")), prob, {"KIND_MISMATCH"}),
            ("manifest emptied", lambda: bh.oob(models.ConfigurationBundle).filter(pk=prob.pk).update(manifest={}), prob, {"MANIFEST_MALFORMED"}),
            ("a secret-shaped key injected", lambda: edit_manifest(prob, lambda m: m["payload"]["source"].update(api_token="x")), prob, {"SECRET_SHAPED_CONTENT", "PAYLOAD_DIGEST_MISMATCH"}),
            ("a secret line injected into a payload", lambda: edit_manifest(prob, lambda m: m["payload"]["items"][0].update(payload="username a secret hunter2")), prob, {"SECRET_SHAPED_CONTENT"}),
            ("payload digest column", lambda: bh.oob(models.ConfigurationBundle).filter(pk=prob.pk).update(payload_digest="0" * 64), prob, {"PAYLOAD_DIGEST_MISMATCH", "PAYLOAD_NOT_EQUIVALENT"}),
            ("bundle digest column", lambda: bh.oob(models.ConfigurationBundle).filter(pk=prob.pk).update(bundle_digest="0" * 64), prob, {"BUNDLE_DIGEST_MISMATCH"}),
            ("kind column", lambda: bh.oob(models.ConfigurationBundle).filter(pk=prob.pk).update(kind="GOLDEN"), prob, {"KIND_MISMATCH", "LINEAGE_INVALID", "BUNDLE_DIGEST_MISMATCH"}),
            ("parent pointer", lambda: bh.oob(models.ConfigurationBundle).filter(pk=prob.pk).update(parent=prob), prob, {"LINEAGE_INVALID"}),
            ("source execution swapped", lambda: bh.oob(models.ConfigurationBundle).filter(pk=prob.pk).update(execution_run=other_run), prob, {"SOURCE_PIN_MISMATCH"}),
            ("postcheck pin removed", lambda: bh.oob(models.ConfigurationBundle).filter(pk=prob.pk).update(postcheck_run=None), prob, {"SOURCE_PIN_MISMATCH"}),
            ("item row deleted", lambda: item(prob, 2).delete(), prob, {"ITEMS_MISMATCH"}),
            ("item sequence renumbered", lambda: item(prob, 2).update(sequence=5), prob, {"ITEMS_MISMATCH"}),
            ("item payload column edited", lambda: item(prob).update(payload="interface X"), prob, {"ITEM_PAYLOAD_HASH_MISMATCH"}),
            ("item record edited", lambda: item(prob).update(record={"order": 1}), prob, {"ITEM_RECORD_MISMATCH"}),
            ("item digest edited", lambda: item(prob).update(item_digest="0" * 64), prob, {"ITEM_DIGEST_MISMATCH"}),
            ("item pinned to another Configlet", lambda: item(prob).update(configlet=prob.plan.configlets.get(cfg_id="CFG-003")), prob, {"SOURCE_REFERENCE_INVALID"}),
            ("an ANCESTOR was tampered with", lambda: edit_manifest(uat, lambda m: m["payload"]["items"][0].update(payload="interface X")), prob, {"ANCESTOR_INTEGRITY_FAILED"}),
        ]
        for case, tamper, target, expected in rows:
            with self.subTest(case=case), bh.rolled_back():
                self.assertTrue(self.report(target).ok, "the untampered baseline verifies")
                tamper()
                report = self.report(target)
                self.assertFalse(report.ok)
                self.assertTrue(expected <= set(report.codes), f"expected {expected}, got {report.codes}")
        self.assertTrue(self.report(prob).ok and self.report(uat).ok, "every tamper was rolled back")

    def test_a_raw_pin_that_no_longer_matches_is_detected(self):
        raw_run = bh.raw_run(assertions=[bh.ADDRESS_ASSERTION], effect=bh.LOOPBACK_PRESENT)
        uat = bh.uat_of(raw_run)
        item = bh.oob(models.ConfigurationBundleItem).filter(bundle=uat, origin="RAW")
        rows = [
            ("verification pin removed", lambda: item.update(raw_verification=None)),
            ("revision pin removed", lambda: item.update(raw_revision=None)),
            ("revision text altered", lambda: bh.oob(models.RawConfigletRevision).filter(pk=item.get().raw_revision_id).update(content="interface Loopback1\n")),
        ]
        for case, tamper in rows:
            with self.subTest(case=case), bh.rolled_back():
                tamper()
                self.assertIn("RAW_PIN_MISMATCH", self.report(uat).codes)

    def test_a_failed_bundle_stays_failed_and_cannot_be_repaired_through_the_application(self):
        uat, prob = self.build()
        bh.oob(models.ConfigurationBundle).filter(pk=prob.pk).update(bundle_digest="0" * 64)
        with self.assertRaises(ValueError):   # the immutable row still cannot be "fixed" through the application either
            models.ConfigurationBundle.objects.get(pk=prob.pk).save()
        report = self.report(prob)
        self.assertEqual((report.state, report.ok), ("FAILED", False))
        self.assertEqual(bs.check_golden_eligibility(bs.get_bundle(prob.bundle_id)).blockers[0]["code"], "SOURCE_INTEGRITY_FAILED")


# =============================================================================================================================
class ExportTests(BundleFixture):
    def test_the_export_is_deterministic_read_only_bounded_and_self_verifying(self):
        prob = bh.probation_of(self.make_uat())
        before = bh.table_counts()
        first, second = bs.export_json(prob), bs.export_json(bs.get_bundle(prob.bundle_id))
        self.assertEqual(first, second)
        document = json.loads(first)
        self.assertEqual(bh.count_changes(before, bh.table_counts()), {})
        self.assertEqual(set(document), {"export_schema_version", "bundle", "lineage", "sources", "manifest", "export_digest"})
        self.assertEqual((document["bundle"]["kind"], document["bundle"]["digest_algorithm"], document["bundle"]["bundle_id"]), ("PROBATION", "sha256", "BND-PROB-000001"))
        self.assertEqual(document["lineage"], {"parent_bundle_id": "BND-UAT-000001", "source_uat_bundle_id": "BND-UAT-000001"})
        self.assertEqual(document["manifest"], prob.manifest)
        self.assertNotIn("children", first)                       # children change over time: they are not part of a deterministic export
        self.assertEqual(bs.export_filename(prob), "BND-PROB-000001.manifest.json")
        self.assertTrue(bs.verify_export(document).ok and bs.verify_export(first).ok and bs.verify_export(first.encode()).ok)
        secret_policy.assert_no_secret_shaped_keys(document, context="export")     # no credential-shaped key anywhere in the artifact
        self.assertLess(len(first), 200_000)

    def test_a_tampered_or_malformed_export_fails_verification_without_raising(self):
        document = json.loads(bs.export_json(self.make_uat()))
        rows = [
            ("item payload edited", lambda d: d["manifest"]["payload"]["items"][0].update(payload="interface X"), {"PAYLOAD_DIGEST_MISMATCH", "EXPORT_DIGEST_MISMATCH"}),
            ("payload digest edited", lambda d: d["bundle"].update(payload_digest="0" * 64), {"PAYLOAD_DIGEST_MISMATCH", "EXPORT_DIGEST_MISMATCH"}),
            ("bundle digest edited", lambda d: d["bundle"].update(bundle_digest="0" * 64), {"BUNDLE_DIGEST_MISMATCH", "EXPORT_DIGEST_MISMATCH"}),
            ("metadata edited (creator)", lambda d: d["bundle"].update(created_by="mallory"), {"EXPORT_DIGEST_MISMATCH"}),
            ("export digest edited", lambda d: d.update(export_digest="0" * 64), {"EXPORT_DIGEST_MISMATCH"}),
            ("manifest removed", lambda d: d.pop("manifest"), {"MANIFEST_MALFORMED"}),
        ]
        for case, tamper, expected in rows:
            with self.subTest(case=case):
                variant = copy.deepcopy(document)
                tamper(variant)
                self.assertTrue(expected <= set(bs.verify_export(variant).codes), bs.verify_export(variant).codes)
        for label, garbage in (("not json", "{{{"), ("a list", [1, 2]), ("nothing", None), ("wrong types", {"bundle": 1, "manifest": 2, "export_digest": 3})):
            with self.subTest(garbage=label):
                self.assertFalse(bs.verify_export(garbage).ok)

    def test_a_manifest_that_turned_secret_shaped_is_never_released(self):
        uat = self.make_uat()
        manifest = copy.deepcopy(uat.manifest)
        manifest["payload"]["items"][0]["payload"] = "username admin secret hunter2"
        bh.oob(models.ConfigurationBundle).filter(pk=uat.pk).update(manifest=manifest)
        with self.assertRaises(bs.BundleExportBlocked):
            bs.export_document(bs.get_bundle(uat.bundle_id))


# =============================================================================================================================
class SideEffectAndAuditTests(BundleFixture):
    def test_every_bundle_action_is_database_and_audit_only(self):
        """create UAT, derive Probation, verify, export, list, read: no execute, executor, subprocess, socket, notification or credential."""
        run = self.run_row()
        change = run.change
        before, change_before = bh.table_counts(), models.Change.objects.filter(pk=change.pk).values().get()
        lifecycle_before = models.ChangeLifecycleEvent.objects.filter(change=change).count()
        with bh.no_device_or_network():
            uat = bs.create_uat_bundle(run, actor="tester").bundle
            prob = bs.derive_probation_bundle(uat, actor="tester").bundle
            for bundle in (uat, prob):
                bs.verify_bundle_integrity(bundle), bs.export_json(bundle), bs.lineage_of(bundle)
            bs.list_bundles(), bs.get_bundle(prob.bundle_id), bs.check_golden_eligibility(prob), bs.check_uat_eligibility(run)
        self.assertEqual(bh.count_changes(before, bh.table_counts()),
                         {"ConfigurationBundle": 2, "ConfigurationBundleItem": 4, "AuditEvent": 2})
        self.assertEqual(models.Change.objects.filter(pk=change.pk).values().get(), change_before, "the Change (including its lifecycle) is untouched")
        self.assertEqual(models.Notification.objects.count(), 0)
        self.assertEqual(models.ChangeLifecycleEvent.objects.filter(change=change).count(), lifecycle_before)

    def test_audit_events_are_bounded_secret_free_and_never_carry_the_manifest(self):
        prob = bh.probation_of(self.make_uat())
        events = list(models.AuditEvent.objects.filter(event_type__in=("UAT_BUNDLE_CREATED", "PROBATION_BUNDLE_CREATED")))
        self.assertEqual(len(events), 2)
        allowed = {"bundle_id", "kind", "bundle_digest", "payload_digest", "parent_bundle_id", "source_uat_bundle_id", "source_execution_run_id",
                   "verification_state", "items", "result"}
        for event in events:
            with self.subTest(event=event.event_type):
                self.assertEqual(set(event.metadata), allowed)
                self.assertLess(len(json.dumps(event.metadata)), 900)
                self.assertNotIn("interface", json.dumps(event.metadata))
                self.assertEqual((event.change_id, event.object_type, event.actor), (prob.change_id, "ConfigurationBundle", "tester"))
                secret_policy.assert_no_secret_shaped_keys(event.metadata, context="audit")

    def test_the_documentation_states_the_lifecycle_and_the_phase20_boundary(self):
        text = (REPO_ROOT / "docs" / "IMMUTABLE_CONFIGURATION_BUNDLES.md").read_text()
        for phrase in ("Phase 20", "PHASE20_EVIDENCE_REQUIRED", "UNVERIFIED", "payload digest", "bundle digest", "immutable", "SYNTAX_ONLY",
                       "Probation is not soak success", "No Phase-19 action creates a Golden bundle"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)
