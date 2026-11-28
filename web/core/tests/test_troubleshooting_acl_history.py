"""Restart-safe scoped ACL counter history + deployment binding -- stable IDs ACLHIST-001 .. ACLHIST-010 (extends ACLSRC / HC18).

PROVENANCE: SIMULATED (hand-built EOS-shaped ACL documents, in-process DB).  No gateway-recorded run; no live claim.  A "restart" is modelled by building
a brand-new ``PersistentAclHistory`` over the same database, which shares no process memory with the first.
"""

from __future__ import annotations

import json
from datetime import timedelta

from django.test import TestCase

from core import models as m
from core.services.troubleshooting import deployment as dep
from core.services.troubleshooting import normalization as nz
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting.adapters import acl as acl_ad
from core.tests.test_troubleshooting_acl_source import DENY_WEB, T0, acl, nr, rdoc
from core.tests.test_troubleshooting_deployment import CFG

ACME = repo.Actor("alice", "user", tenant="acme")
OTHER = repo.Actor("mallory", "user", tenant="globex")
BEFORE = [(10, DENY_WEB, 400), (20, "permit ip any any", 40)]
NOW = [(10, DENY_WEB, 460), (20, "permit ip any any", 50)]


def open_case(actor, key, devices=("r1",)):
    return repo.open_case(actor, trigger_source="alert:test", idempotency_key=key, service_intent={"service": "acl"}, affected_scope={"devices": list(devices)},
                          target_states={d: "VERIFIED" for d in devices}, runbook="HC18", now=T0 - timedelta(minutes=30))


def hist(actor, case, **kw):
    return acl_ad.PersistentAclHistory(actor, case.case_id, **kw)


def sample(rules, at, history, name="EDGE-IN", device="r1"):
    return nr(rdoc(acl(name, rules)), at=at, history=history, device=device)["observations"][0]["value"]["rules"]


def seed(h, name="EDGE-IN", device="r1"):
    sample(BEFORE, T0 - timedelta(seconds=60), h, name, device)


def refs(case=None):
    qs = m.TsEvidenceRef.objects.filter(adapter=acl_ad.HISTORY_ADAPTER)
    return qs.filter(case=case) if case else qs


class PersistentHistoryTests(TestCase):
    def test_ACLHIST_001_restart_continuity_yields_delta(self):
        case = open_case(ACME, "a1")
        seed(hist(ACME, case))
        h2 = hist(ACME, case)                                   # "restart"
        rules = sample(NOW, T0, h2)
        self.assertEqual([r["prev_hits"] for r in rules], [400, 40])
        self.assertEqual({r["history"] for r in rules}, {"ok"})
        self.assertEqual(h2.problems, [])

    def test_ACLHIST_002_matches_in_memory_reference(self):
        case = open_case(ACME, "a2")
        mem = nz.AclHistory()
        seed(mem)
        seed(hist(ACME, case))
        a = sample(NOW, T0, mem)
        b = sample(NOW, T0, hist(ACME, case))
        self.assertEqual(a, b)

    def test_ACLHIST_003_no_history_after_restart_is_unknown(self):
        case = open_case(ACME, "a3")
        rules = sample(NOW, T0, hist(ACME, case))
        self.assertEqual({r["history"] for r in rules}, {"no_history"})
        self.assertEqual([r["prev_hits"] for r in rules], [None, None])

    def test_ACLHIST_004_stale_short_reset_changed_survive_restart(self):
        case = open_case(ACME, "a4")
        sample(BEFORE, T0 - timedelta(hours=1), hist(ACME, case))
        self.assertEqual({r["history"] for r in sample(NOW, T0, hist(ACME, case))}, {"stale_history"})
        c2 = open_case(ACME, "a4b")
        sample(BEFORE, T0 - timedelta(seconds=2), hist(ACME, c2))
        self.assertEqual({r["history"] for r in sample(NOW, T0, hist(ACME, c2))}, {"short_history"})
        c3 = open_case(ACME, "a4c")
        seed(hist(ACME, c3))
        reset = sample([(10, DENY_WEB, 3), (20, "permit ip any any", 50)], T0, hist(ACME, c3))
        self.assertEqual([r["history"] for r in reset], ["counter_reset", "ok"])
        c4 = open_case(ACME, "a4d")
        seed(hist(ACME, c4))
        chg = sample([(10, "permit tcp 10.1.1.0/24 10.2.2.0/24 eq 443", 460), (20, "permit ip any any", 50)], T0, hist(ACME, c4))
        self.assertEqual([r["history"] for r in chg], ["rule_changed", "ok"])

    def test_ACLHIST_005_partial_and_nonmonotonic_do_not_persist(self):
        case = open_case(ACME, "a5")
        h = hist(ACME, case)
        seed(h)
        n = refs(case).count()
        self.assertEqual(n, 1)
        # partial parse (unsupported grammar -> notes) is never recorded
        sample([(10, DENY_WEB, 460), (10, "permit ip any any", 50)], T0, hist(ACME, case))      # duplicate sequence => PARTIAL
        self.assertEqual(refs(case).count(), n)
        # older sample than stored one is not recorded
        late = hist(ACME, case)
        sample(NOW, T0 - timedelta(seconds=120), late)
        self.assertEqual(refs(case).count(), n)

    def test_ACLHIST_006_scope_isolation_case_tenant_device_acl_parser(self):
        case = open_case(ACME, "a6", ("r1", "r2"))
        seed(hist(ACME, case))
        self.assertIsNone(hist(ACME, open_case(ACME, "a6b")).previous("r1", "EDGE-IN"))          # other case
        self.assertIsNone(hist(ACME, case).previous("r2", "EDGE-IN"))                            # other device
        self.assertIsNone(hist(ACME, case).previous("r1", "OTHER-ACL"))                          # other ACL
        self.assertIsNone(hist(ACME, case, parser_version="0.0-other").previous("r1", "EDGE-IN"))   # other parser version
        foreign = hist(OTHER, case)
        self.assertIsNone(foreign.previous("r1", "EDGE-IN"))                                     # other tenant
        self.assertTrue(foreign.problems)
        self.assertIsNotNone(hist(ACME, case).previous("r1", "EDGE-IN"))

    def test_ACLHIST_007_foreign_corrupt_or_inconsistent_evidence_ignored(self):
        case = open_case(ACME, "a7")
        h = hist(ACME, case)
        good = h._scope("r1", "EDGE-IN")
        at = T0 - timedelta(seconds=60)
        rid = acl_ad._rule_id(10, DENY_WEB)
        rule = {"seq": 10, "text": DENY_WEB, "hits": 400, "id": rid}

        def plant(scope, raw, when):
            repo.store_evidence(ACME, case, source_type="replay", device="r1", command_or_api=h._command("EDGE-IN"), adapter=acl_ad.HISTORY_ADAPTER,
                                parser_version=h.parser_version, collected_at=when, raw=raw, scope=scope)

        def doc(**kw):
            base = {"scope": good, "complete": True, "at": at.isoformat(), "rules": [rule]}
            base.update(kw)
            return json.dumps(base)

        def check(label, scope, raw):
            plant(scope, raw, at)
            probe = hist(ACME, case)
            self.assertIsNone(probe.previous("r1", "EDGE-IN"), label)
            plant_count = refs(case).count()
            return plant_count, probe
        # each planted row is the newest ref in turn (store_evidence ids are content hashed; vary collected_at)
        cases = [("scope-field", {**good, "acl": "X"}, doc()),
                 ("doc-scope", good, doc(scope={**good, "case_id": "other"})),
                 ("incomplete", good, doc(complete=False)),
                 ("identity", good, doc(rules=[{**rule, "text": "permit ip any any"}])),
                 ("negative-hits", good, doc(rules=[{**rule, "hits": -1}])),
                 ("string-hits", good, doc(rules=[{**rule, "hits": "400"}])),
                 ("dup-seq", good, doc(rules=[rule, rule])),
                 ("time-mismatch", good, doc(at=(at + timedelta(seconds=5)).isoformat())),
                 ("not-json", good, "not json")]
        for i, (label, scope, raw) in enumerate(cases):
            when = at + timedelta(seconds=i + 1)
            plant(scope, raw.replace(at.isoformat(), when.isoformat()) if label != "time-mismatch" else raw, when)
            probe = hist(ACME, case)
            self.assertIsNone(probe.previous("r1", "EDGE-IN"), label)
        self.assertTrue(probe.problems)                       # not-json reported by class only
        self.assertNotIn("not json", str(probe.problems))

    def test_ACLHIST_008_persistence_failure_is_contained(self):
        case = open_case(ACME, "a8")
        h = acl_ad.PersistentAclHistory(ACME, "no-such-case")
        rules = sample(BEFORE, T0 - timedelta(seconds=60), h)            # must not raise
        self.assertEqual({r["history"] for r in rules}, {"no_history"})
        self.assertTrue(h.problems)
        self.assertEqual(refs(case).count(), 0)
        self.assertEqual(refs().count(), 0)

    def test_ACLHIST_009_evidence_immutable(self):
        case = open_case(ACME, "a9")
        seed(hist(ACME, case))
        ref = refs(case).first()
        ref.quality = "BAD"
        with self.assertRaises(Exception):
            ref.save()

    def test_ACLHIST_010_construction_makes_no_db_access(self):
        case = open_case(ACME, "a10")
        with self.assertNumQueries(0):
            acl_ad.persistent_acl_context(ACME, case.case_id)
            hist(ACME, case)


class BindingTests(TestCase):
    def test_ACLHIST_011_both_factory_consumers_lazy_typed_failsafe(self):
        case = open_case(ACME, "a11")
        calls: list = []

        def provider():
            calls.append(1)
            return acl_ad.persistent_acl_context(ACME, case.case_id)
        for build in (lambda **k: dep.build_runtime_deps(**k), lambda **k: dep.runtime_deps({**CFG, **k})):
            calls.clear()
            d = build(acl_context_provider=provider)
            self.assertEqual(calls, [])
            self.assertEqual(refs().count(), 0)
            self.assertIsInstance(d.acl_context.history, acl_ad.PersistentAclHistory)
            self.assertEqual(len(calls), 1)
            d = build(acl_context_provider=lambda: object())
            self.assertIs(type(d.acl_context.history), nz.AclHistory)
            self.assertIn("acl_context: TypeError", d.deployment_problems)

            def boom():
                raise RuntimeError("password=hunter2")
            d = build(acl_context_provider=boom)
            self.assertIs(type(d.acl_context.history), nz.AclHistory)
            self.assertIn("acl_context: RuntimeError", d.deployment_problems)
            self.assertNotIn("hunter2", str(d.deployment_problems))
        d = dep.runtime_deps({**CFG, "acl_context_provider": "no.such.provider"})
        self.assertIs(d.acl_context, None)
        self.assertTrue(any("acl_context_provider" in p for p in d.deployment_problems))
        self.assertIsNone(dep.build_runtime_deps().acl_context)

    def test_ACLHIST_012_runtime_acl_context_contract_unchanged(self):
        import dataclasses
        from core.services.troubleshooting import runtime as rt
        f = {x.name: x for x in dataclasses.fields(rt.RuntimeDeps)}["acl_context"]
        self.assertIsNone(f.default)
