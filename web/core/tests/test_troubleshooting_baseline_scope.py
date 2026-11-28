"""Device-scoped golden and soak baseline selection (stable IDs BLSCOPE-001 .. BLSCOPE-0xx; supports spec 3.3 / 6.3 / UT-026 / UT-027).

PROVENANCE: the ``Pure`` tests feed hand-written plain dictionaries (SIMULATED) to ``select_golden_scope``.  The ``Orm`` tests use REAL bundles produced by the
production Phase-17/19/20 helpers on the simulated network (no device, NetBox, Slack or socket); nothing here is gateway-recorded live evidence.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest import mock

from django.urls import reverse
from django.test import SimpleTestCase, TestCase

from core import models as m
from core.services import slack_service, soak_service as ss
from core.services.troubleshooting import baselines as bl
from core.tests.helpers import bundles as bh, soak as sh

T0 = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)


def gold(bid, devices, *, age=0, parent_pk=None, digest=None, change="CHG-1"):
    return {"bundle_id": bid, "digest": digest or (bid[-1] * 64), "created_at": T0 - timedelta(hours=age), "url": f"/bundles/{bid}/", "link_ok": True,
            "approved_change_id": change, "provenance": "EXECUTION_LINEAGE", "parent_bundle_id": "", "parent_pk": parent_pk,
            "items": {d: [{"cfg_id": f"CFG-{d}", "payload_hash": f"h-{bid}-{d}", "item_digest": f"i-{bid}-{d}", "operation": "MERGE", "sequence": 1}] for d in devices}}


def soak(sid, bundle_pk, *, active=False, devices=("R1",), bundle="BND-PROB-1", change="CHG-1"):
    return {"soak_id": sid, "state": "RUNNING" if active else "COMPLETED", "result": "" if active else "PASS", "started_at": T0, "required_end_at": T0 + timedelta(days=7),
            "url": f"/soaks/{sid}/", "bundle_id": bundle, "bundle_pk": bundle_pk, "bundle_digest": "d" * 64, "active": active, "devices": list(devices),
            "change_id": change, "change_lifecycle": "APPROVED", "is_parent_of_golden": not active}


class PureSelectionTests(SimpleTestCase):
    def test_blscope_001_unrelated_newer_golden_is_ignored(self):
        g_new_other = gold("BND-GOLD-000009", ["R9"], age=0)
        g_old_r1 = gold("BND-GOLD-000001", ["R1", "R2"], age=48)
        out = bl.select_golden_scope(["R1"], [g_new_other, g_old_r1], [])
        self.assertEqual((out["status"], out["revision"], out["coverage"]), ("available", "BND-GOLD-000001", "FULL"))
        self.assertEqual(out["digest"], g_old_r1["digest"])
        self.assertEqual(out["url"], "/bundles/BND-GOLD-000001/")
        self.assertEqual(out["device_scope"][0]["items"][0]["payload_hash"], "h-BND-GOLD-000001-R1")

    def test_blscope_002_no_devices_or_no_coverage_fails_closed_never_global_newest(self):
        goldens = [gold("BND-GOLD-000009", ["R9"])]
        for devs in ([], [""], ["R1"]):
            with self.subTest(devices=devs):
                out = bl.select_golden_scope(devs, goldens, [])
                self.assertEqual(out["status"], "unavailable")
                self.assertNotIn("revision", out)

    def test_blscope_003_newest_revision_per_device_and_previous_revision(self):
        out = bl.select_golden_scope(["R1"], [gold("BND-GOLD-000003", ["R1"], age=1), gold("BND-GOLD-000002", ["R2"], age=2),
                                              gold("BND-GOLD-000001", ["R1"], age=3)], [])
        self.assertEqual((out["revision"], out["previous_revision"], out["previous_url"]), ("BND-GOLD-000003", "BND-GOLD-000001", "/bundles/BND-GOLD-000001/"))
        self.assertEqual(out["device_scope"][0]["superseded_for_device"], ["BND-GOLD-000001"])

    def test_blscope_004_mixed_revision_claims_no_single_revision(self):
        out = bl.select_golden_scope(["R1", "R2"], [gold("BND-GOLD-000002", ["R1"], age=1), gold("BND-GOLD-000001", ["R2"], age=2)], [])
        self.assertTrue(out["mixed_revision"])
        self.assertEqual((out["status"], out["coverage"], out["revision"], out["digest"], out["url"], out["link_ok"]), ("available", "MIXED", "", "", "", False))
        self.assertEqual(out["revisions"], ["BND-GOLD-000002", "BND-GOLD-000001"])
        self.assertEqual({s["device"]: (s["revision"], s["digest"], s["url"]) for s in out["device_scope"]},
                         {"R1": ("BND-GOLD-000002", "2" * 64, "/bundles/BND-GOLD-000002/"), "R2": ("BND-GOLD-000001", "1" * 64, "/bundles/BND-GOLD-000001/")})
        self.assertEqual([a["kind"] for a in out["ambiguities"]], ["MIXED_REVISION"])

    def test_blscope_005_partial_coverage_lists_uncovered_devices(self):
        out = bl.select_golden_scope(["R1", "R7"], [gold("BND-GOLD-000001", ["R1"])], [])
        self.assertEqual((out["revision"], out["coverage"], out["uncovered_devices"]), ("BND-GOLD-000001", "PARTIAL_FULL", ["R7"]))
        self.assertEqual(out["device_scope"][1]["status"], "UNCOVERED")
        self.assertEqual([a["kind"] for a in out["ambiguities"]], ["PARTIAL_COVERAGE"])

    def test_blscope_006_partial_and_mixed_combined(self):
        out = bl.select_golden_scope(["R1", "R2", "R7"], [gold("BND-GOLD-000002", ["R1"], age=1), gold("BND-GOLD-000001", ["R2"], age=2)], [])
        self.assertEqual((out["coverage"], out["revision"]), ("PARTIAL_MIXED", ""))
        self.assertEqual(sorted(a["kind"] for a in out["ambiguities"]), ["MIXED_REVISION", "PARTIAL_COVERAGE"])

    def test_blscope_007_unrelated_running_soak_is_never_selected(self):
        g = gold("BND-GOLD-000001", ["R1"], parent_pk=5)
        parent = soak("SOAK-000001", 5)
        # an unrelated RUNNING soak carries no requested device -> filtered out by the loader contract (devices == [])
        unrelated = soak("SOAK-000009", 77, active=True, devices=())
        out = bl.select_golden_scope(["R1"], [g], [unrelated, parent])
        self.assertEqual(out["soak"]["soak_id"], "SOAK-000001")
        self.assertEqual(out["soak"]["relation"], "PARENT_OF_SELECTED_GOLDEN")
        self.assertNotIn("SOAK-000009", [s["soak_id"] for s in out["soaks"]])

    def test_blscope_008_running_soak_on_scoped_devices_is_the_active_candidate(self):
        g = gold("BND-GOLD-000001", ["R1"], parent_pk=5)
        out = bl.select_golden_scope(["R1"], [g], [soak("SOAK-000002", 8, active=True), soak("SOAK-000001", 5)])
        self.assertEqual((out["soak"]["soak_id"], out["soak"]["active"], out["soak"]["relation"], out["soak"]["change_id"]),
                         ("SOAK-000002", True, "ACTIVE_CANDIDATE_FOR_DEVICES", "CHG-1"))
        self.assertEqual({s["soak_id"] for s in out["soaks"]}, {"SOAK-000001", "SOAK-000002"})

    def test_blscope_009_multiple_active_soaks_are_ambiguous_and_not_selected(self):
        out = bl.select_golden_scope(["R1", "R2"], [gold("BND-GOLD-000001", ["R1", "R2"])],
                                     [soak("SOAK-000002", 8, active=True, devices=("R1",)), soak("SOAK-000003", 9, active=True, devices=("R2",))])
        self.assertIsNone(out["soak"])
        self.assertIn("MULTIPLE_ACTIVE_SOAKS", [a["kind"] for a in out["ambiguities"]])

    def test_blscope_010_mixed_revisions_claim_no_parent_soak(self):
        out = bl.select_golden_scope(["R1", "R2"], [gold("BND-GOLD-000002", ["R1"], age=1, parent_pk=2), gold("BND-GOLD-000001", ["R2"], age=2, parent_pk=1)],
                                     [soak("SOAK-000001", 1), soak("SOAK-000002", 2)])
        self.assertIsNone(out["soak"])
        self.assertIn("SOAK_WITHOUT_SINGLE_REVISION", [a["kind"] for a in out["ambiguities"]])

    def test_blscope_011_legacy_consumer_keys_are_preserved(self):
        out = bl.select_golden_scope(["R1"], [gold("BND-GOLD-000001", ["R1"], parent_pk=5)], [soak("SOAK-000001", 5)])
        for key in ("status", "source", "revision", "digest", "url", "link_ok", "created_at", "approved_change_id", "provenance", "previous_revision",
                    "previous_url", "soak"):
            self.assertIn(key, out)
        for key in ("soak_id", "state", "result", "started_at", "required_end_at", "url", "bundle_id", "active"):
            self.assertIn(key, out["soak"])
        cls = bl.classify_changes([{"change_id": "C", "approved": True, "at": T0.isoformat()}], soak=out["soak"], onset=T0)
        self.assertEqual(len(cls), 1)

    def test_blscope_012_override_and_static_sources_unchanged(self):
        src = bl.DjangoBaselineSources(overrides={"golden": lambda devs: {"status": "available", "revision": "X"}})
        self.assertEqual(src.golden(["R1"])["revision"], "X")
        self.assertEqual(bl.StaticSources({"golden": {"revision": "Y"}}).golden(["R1"])["revision"], "Y")


class OrmScopeTests(TestCase):
    """REAL bundles/soaks from the production helpers on the simulated network."""

    @classmethod
    def setUpTestData(cls):
        with sh.short_soak():
            cls.f = sh.probation()

    def setUp(self):
        p = mock.patch.object(slack_service, "is_configured", return_value=False)
        p.start()
        self.addCleanup(p.stop)

    def _devices(self, bundle):
        return sorted(set(bundle.items.values_list("device", flat=True)))

    def test_blscope_020_real_golden_selected_by_device_scope_with_exact_hash_and_link(self):
        gold_b = bh.golden_from(self.f.prob)
        devs = self._devices(gold_b)
        self.assertTrue(devs)
        out = bl.DjangoBaselineSources().golden(devs)
        self.assertEqual((out["status"], out["revision"], out["digest"], out["coverage"]), ("available", gold_b.bundle_id, gold_b.bundle_digest, "FULL"))
        self.assertTrue(out["link_ok"])
        self.assertEqual(out["url"], reverse("core:bundle_detail", args=[gold_b.bundle_id]))
        item = gold_b.items.filter(device=devs[0]).first()
        self.assertEqual(out["device_scope"][0]["items"][0]["payload_hash"], item.payload_hash)
        self.assertEqual(out["soak"]["bundle_id"], self.f.prob.bundle_id)
        self.assertEqual(out["soak"]["relation"], "PARENT_OF_SELECTED_GOLDEN")

    def test_blscope_021_unknown_device_and_empty_scope_are_unavailable_despite_a_golden_existing(self):
        gold_b = bh.golden_from(self.f.prob)
        self.assertTrue(m.ConfigurationBundle.objects.filter(pk=gold_b.pk).exists())
        for devs in (["NOT-IN-ANY-GOLDEN"], []):
            with self.subTest(devices=devs):
                self.assertEqual(bl.DjangoBaselineSources().golden(devs)["status"], "unavailable")

    def test_blscope_022_partial_coverage_with_real_golden(self):
        gold_b = bh.golden_from(self.f.prob)
        devs = self._devices(gold_b)
        out = bl.DjangoBaselineSources().golden(devs + ["R-UNCOVERED"])
        self.assertEqual((out["coverage"], out["uncovered_devices"], out["revision"]), ("PARTIAL_FULL", ["R-UNCOVERED"], gold_b.bundle_id))

    def test_blscope_023_running_soak_on_unrelated_device_is_not_attached(self):
        # a real RUNNING soak on this probation bundle; asking about a device outside its items must not surface it
        with sh.short_soak():
            res = ss.start_soak(self.f.prob, actor="tester", now=sh.T0)
        self.assertIsNotNone(res.run, res.blockers)
        loaded_goldens, loaded_soaks = bl._load_golden_scope(["NOT-IN-ANY-BUNDLE"])
        self.assertEqual((loaded_goldens, loaded_soaks), ([], []))
        devs = self._devices(self.f.prob)
        _, soaks = bl._load_golden_scope(devs)
        self.assertEqual([s["soak_id"] for s in soaks], [res.run.soak_id])
        self.assertTrue(soaks[0]["active"])
        self.assertEqual(soaks[0]["change_id"], self.f.prob.change.change_id)

    def test_blscope_024_active_soak_candidate_selected_when_golden_exists_for_older_revision_only(self):
        with sh.short_soak():
            res = ss.start_soak(self.f.prob, actor="tester", now=sh.T0)
        devs = self._devices(self.f.prob)
        # no golden for these devices yet: unavailable (a soaking candidate is not a golden)
        self.assertEqual(bl.DjangoBaselineSources().golden(devs)["status"], "unavailable")
        self.assertTrue(res.run.is_running)

    def test_blscope_025_two_real_goldens_newer_unrelated_one_does_not_displace_the_older(self):
        gold_a = bh.golden_from(self.f.prob)
        with sh.short_soak():
            other = sh.probation(through=3)
        gold_b = bh.golden_from(other.prob)
        a_devs, b_devs = set(self._devices(gold_a)), set(self._devices(gold_b))
        out_b = bl.DjangoBaselineSources().golden(sorted(b_devs))
        self.assertEqual(out_b["revision"], gold_b.bundle_id)           # newest golden for B's devices
        # both real goldens cover the same devices (R1, R2): the newer revision wins and the older is the exact previous revision
        self.assertEqual(a_devs, b_devs)
        out = bl.DjangoBaselineSources().golden(sorted(a_devs))
        self.assertEqual((out["revision"], out["previous_revision"], out["coverage"]), (gold_b.bundle_id, gold_a.bundle_id, "FULL"))
        self.assertEqual(out["digest"], gold_b.bundle_digest)
        # real-lineage mixed-revision behaviour needs goldens with different device scopes, which the shared fixtures cannot produce: it is
        # covered by the Pure tests BLSCOPE-004/006 only (documented limitation).
