"""Restart-safe scoped L2 MAC history -- stable IDs L2HIST-001 .. L2HIST-010 (extends HC09 / L2SRC-004..006).

PROVENANCE: SIMULATED (hand-built EOS-shaped MAC tables, in-process DB).  No gateway-recorded run; no live claim.  A "restart" is modelled by building
a brand-new ``PersistentMacHistory`` over the same database, which shares no process memory with the first.
"""

from __future__ import annotations

from datetime import timedelta

from django.test import TestCase

from core import models as m
from core.services.troubleshooting import deployment as dep
from core.services.troubleshooting import normalization as nz
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting.adapters import l2 as l2_ad
from core.tests.test_troubleshooting_l2_source import H1, T0, moved, nm, stable, vlan_obs
from core.tests.test_troubleshooting_deployment import CFG

ACME = repo.Actor("alice", "user", tenant="acme")
OTHER = repo.Actor("mallory", "user", tenant="globex")


def open_case(actor, key, devices=("sw1",)):
    return repo.open_case(actor, trigger_source="alert:test", idempotency_key=key, service_intent={"service": "l2"}, affected_scope={"devices": list(devices)},
                          target_states={d: "VERIFIED" for d in devices}, runbook="HC09", now=T0 - timedelta(minutes=30))


def hist(actor, case, **kw):
    return l2_ad.PersistentMacHistory(actor, case.case_id, **kw)


def seed(h, device="sw1"):
    nm(moved("Ethernet1", "Ethernet2"), T0 - timedelta(minutes=4), history=h)
    nm(moved("Ethernet2", "Ethernet2"), T0 - timedelta(minutes=3), history=h)


class PersistentHistoryTests(TestCase):
    def test_L2HIST_001_restart_continuity_yields_movement(self):
        case = open_case(ACME, "k1")
        seed(hist(ACME, case))
        h2 = hist(ACME, case)                              # "restart": fresh object, no memory
        o = vlan_obs(nm(moved("Ethernet1", "Ethernet2"), T0 - timedelta(minutes=2), history=h2), "10")[0]
        self.assertEqual(o["value"]["move_count_window"], 2)
        self.assertEqual(o["quality"], "OK")
        self.assertEqual(h2.problems, [])

    def test_L2HIST_002_matches_in_memory_reference(self):
        case = open_case(ACME, "k2")
        mem = nz.MacHistory()
        seed(mem)
        seed(hist(ACME, case))
        a = vlan_obs(nm(moved("Ethernet1", "Ethernet2"), T0 - timedelta(minutes=2), history=mem), "10")[0]["value"]
        b = vlan_obs(nm(moved("Ethernet1", "Ethernet2"), T0 - timedelta(minutes=2), history=hist(ACME, case)), "10")[0]["value"]
        self.assertEqual(a, b)

    def test_L2HIST_003_no_history_after_restart_is_unknown_not_zero(self):
        case = open_case(ACME, "k3")
        o = vlan_obs(nm(stable(), T0, history=hist(ACME, case)), "10")[0]
        self.assertIsNone(o["value"]["moves_per_min"])
        self.assertIn("MAC_HISTORY_UNKNOWN", o["flags"])

    def test_L2HIST_004_gap_and_short_safeguards_survive_restart(self):
        case = open_case(ACME, "k4")
        nm(stable(), T0 - timedelta(hours=1), history=hist(ACME, case))
        g = vlan_obs(nm(stable(), T0, history=hist(ACME, case)), "10")[0]
        self.assertIn("mac_history_gap", g["value"]["uncertain"])
        self.assertIsNone(g["value"]["moves_per_min"])
        case2 = open_case(ACME, "k4b")
        nm(moved("Ethernet1", "Ethernet2"), T0 - timedelta(seconds=20), history=hist(ACME, case2))
        s = vlan_obs(nm(moved("Ethernet2", "Ethernet2"), T0, history=hist(ACME, case2)), "10")[0]
        self.assertIn("mac_history_too_short", s["value"]["uncertain"])

    def test_L2HIST_005_nonmonotonic_and_partial_do_not_persist(self):
        case = open_case(ACME, "k5")
        h = hist(ACME, case)
        nm(stable(), T0 - timedelta(minutes=2), history=h)
        n = m.TsEvidenceRef.objects.filter(adapter=l2_ad.HISTORY_ADAPTER).count()
        o = vlan_obs(nm(stable(), T0 - timedelta(minutes=3), history=hist(ACME, case)), "10")[0]
        self.assertIn("non_monotonic_sample", o["value"]["uncertain"])
        self.assertEqual(m.TsEvidenceRef.objects.filter(adapter=l2_ad.HISTORY_ADAPTER).count(), n)

    def test_L2HIST_006_scope_isolation_case_tenant_device_vlan_parser(self):
        case = open_case(ACME, "k6", ("sw1", "sw2"))
        seed(hist(ACME, case))
        other_case = open_case(ACME, "k6b")
        self.assertIsNone(hist(ACME, other_case).previous("sw1", "10"))          # other case
        self.assertIsNone(hist(ACME, case).previous("sw2", "10"))                # other device
        self.assertIsNone(hist(ACME, case).previous("sw1", "99"))                # other VLAN
        self.assertIsNone(hist(ACME, case, parser_version="0.0-other").previous("sw1", "10"))   # other parser version
        foreign = hist(OTHER, case)                                                # other tenant cannot read it
        self.assertIsNone(foreign.previous("sw1", "10"))
        self.assertTrue(foreign.problems)
        self.assertIsNotNone(hist(ACME, case).previous("sw1", "10"))

    def test_L2HIST_007_foreign_scope_or_malformed_evidence_ignored(self):
        import json
        case = open_case(ACME, "k7")
        h = hist(ACME, case)
        def plant(scope, raw, at):
            repo.store_evidence(ACME, case, source_type="replay", device="sw1", command_or_api="l2.mac_history@vlan10", adapter=l2_ad.HISTORY_ADAPTER,
                                parser_version=h.parser_version, collected_at=at, raw=raw, scope=scope)
        good = h._scope("sw1", "10")
        plant({**good, "vlan": "11"}, "{}", T0 - timedelta(minutes=3))                        # scope field mismatch
        self.assertIsNone(hist(ACME, case).previous("sw1", "10"))
        plant(good, json.dumps({"scope": {**good, "case_id": "other"}, "macs": {}, "at": T0.isoformat(), "coverage_start": T0.isoformat(), "events": []}),
              T0 - timedelta(minutes=2))                                                      # document scope mismatch
        self.assertIsNone(hist(ACME, case).previous("sw1", "10"))
        plant(good, "not json", T0 - timedelta(minutes=1))                                    # malformed
        h3 = hist(ACME, case)
        self.assertIsNone(h3.previous("sw1", "10"))
        self.assertTrue(h3.problems)

    def test_L2HIST_008_persistence_failure_is_contained(self):
        case = open_case(ACME, "k8")
        h = l2_ad.PersistentMacHistory(ACME, "no-such-case")
        o = vlan_obs(nm(stable(), T0 - timedelta(minutes=3), history=h), "10")[0]     # must not raise
        self.assertIn("MAC_HISTORY_UNKNOWN", o["flags"])
        self.assertTrue(h.problems)
        self.assertEqual(m.TsEvidenceRef.objects.filter(case=case).count(), 0)

    def test_L2HIST_009_evidence_immutable_and_redacted_store_used(self):
        case = open_case(ACME, "k9")
        seed(hist(ACME, case))
        ref = m.TsEvidenceRef.objects.filter(case=case, adapter=l2_ad.HISTORY_ADAPTER).first()
        ref.quality = "BAD"
        with self.assertRaises(Exception):
            ref.save()


class BindingTests(TestCase):
    def provider(self, calls, case):
        def load():
            calls.append(1)
            return l2_ad.persistent_l2_context(ACME, case.case_id)
        return load

    def test_L2HIST_010_both_factory_consumers_lazy_typed_failsafe(self):
        case = open_case(ACME, "k10")
        calls: list = []
        for build in (lambda **k: dep.build_runtime_deps(**k), lambda **k: dep.runtime_deps({**CFG, **k})):
            calls.clear()
            d = build(l2_context_provider=self.provider(calls, case))
            self.assertEqual(calls, [])                                       # construction contacts nothing
            self.assertEqual(m.TsEvidenceRef.objects.count(), 0)
            self.assertIsInstance(d.l2_context.history, l2_ad.PersistentMacHistory)
            self.assertEqual(len(calls), 1)
            d = build(l2_context_provider=lambda: object())                   # wrong type -> in-memory fallback, problem logged
            self.assertIs(type(d.l2_context.history), nz.MacHistory)
            self.assertIn("l2_context: TypeError", d.deployment_problems)
            def boom():
                raise RuntimeError("password=hunter2")
            d = build(l2_context_provider=boom)
            self.assertIs(type(d.l2_context.history), nz.MacHistory)
            self.assertNotIn("hunter2", str(d.deployment_problems))
        d = dep.runtime_deps({**CFG, "l2_context_provider": "no.such.provider"})
        self.assertIs(d.l2_context, None)
        self.assertTrue(any("l2_context_provider" in p for p in d.deployment_problems))
        self.assertIsNone(dep.build_runtime_deps().l2_context)
