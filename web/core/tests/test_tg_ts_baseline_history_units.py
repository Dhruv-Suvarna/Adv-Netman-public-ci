"""Direct tests for the snapshot / history baseline readers (troubleshooting/adapters/baseline_history.py).

Golden payloads are verified against their recorded hash; snapshots are tenant and device scoped and integrity checked;
Flux queries only name catalogued series; and history samples drop invalid, future and duplicate points instead of
inventing values.
"""

from __future__ import annotations

from datetime import timedelta

from django.test import SimpleTestCase, TestCase

from core import models
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting.adapters import baseline_history as bh
from core.tests import test_troubleshooting_baseline_history as BH
from core.tests.helpers import bundles as bundle_helper

NOW = BH.NOW
SERIES = {"device": "R1", "measurement": "gnmi_telemetry", "field": "cpu_total_pct", "start": "-30d"}
CSV = ",result,table,_time,_value\n,_result,0,2026-11-09T11:00:00Z,12.5\n,_result,0,2026-11-09T11:05:00Z,abc\n"


class LineAndSampleTests(SimpleTestCase):
    def test_norm_lines_returns_normalised_unique_lines(self):
        self.assertEqual(bh.norm_lines("interface Ethernet1\n   mtu  9214\ninterface Ethernet1\n"), ["interface Ethernet1", "mtu 9214"])

    def test_norm_lines_of_comments_or_none_is_empty(self):
        self.assertEqual(bh.norm_lines("! comment\n# frr comment\n   \n"), [])
        self.assertEqual(bh.norm_lines(None), [])

    def test_parse_flux_samples_rejects_malformed_rows(self):
        self.assertEqual(bh.parse_flux_samples(CSV), [{"t": "2026-11-09T11:00:00Z", "value": 12.5}])
        self.assertEqual(bh.parse_flux_samples(",_time,_value\n,bad"), [])

    def test_clean_samples_drops_invalid_future_and_duplicate_points_and_never_rates_a_reset(self):
        def t(seconds):
            return (NOW - timedelta(seconds=seconds)).isoformat()

        samples = [{"t": t(30), "value": 10}, {"t": t(30), "value": 11}, {"t": t(20), "value": 5}, {"t": t(10), "value": 15},
                   {"t": (NOW + timedelta(seconds=5)).isoformat(), "value": 1}, {"t": "bad", "value": 1}, {"t": t(5), "value": True}]
        out = bh.clean_samples(samples, kind="counter", now=NOW, max_points=10)
        self.assertEqual((out["dropped"], out["resets"], [s["value"] for s in out["samples"]]),
                         ({"invalid": 2, "future": 1, "duplicate": 1}, 1, [1.0]))


class FluxReaderTests(SimpleTestCase):
    def test_flux_history_reader_refuses_an_uncatalogued_series_without_querying(self):
        queries = []
        reader = bh.FluxHistoryReader(lambda flux: queries.append(flux) or CSV, "lab")
        for label, series in (("an uncatalogued field", {**SERIES, "field": "nope"}), ("an injected device", {**SERIES, "device": 'R1" or true'})):
            with self.subTest(f"{label} is refused"), self.assertRaises(ValueError):
                reader(series)
        self.assertEqual(queries, [])


class OrmReaderTests(TestCase):
    ACTOR = BH.OrmSnapshotAndPersistTests.ACTOR

    def setUp(self):
        self.case = repo.open_case(self.ACTOR, trigger_source="alert:t", idempotency_key="tg-blhist", service_intent={"s": 1},
                                   affected_scope={"devices": ["R1", "R2"]}, now=NOW)

    def store(self, text, device="R1"):
        return repo.store_evidence(self.ACTOR, self.case, source_type="config", device=device, command_or_api="show running-config", adapter="t",
                                   collected_at=NOW - timedelta(hours=1), raw=text, scope={"platform": "ceos"})

    def test_orm_snapshot_reader_refuses_another_tenant_or_a_hidden_device(self):
        self.store(BH.GOLD_TEXT)
        self.assertEqual(bh.orm_snapshot_reader(repo.Actor("o", "user", tenant="other"), ["R1"], now=NOW), {})
        self.assertEqual(bh.orm_snapshot_reader(repo.Actor("r2", "user", devices=frozenset({"R2"})), ["R1"], now=NOW), {})

    def test_from_orm_reports_a_device_without_a_snapshot_as_unknown(self):
        adapter = bh.ConfigSnapshotBaseline.from_orm(self.ACTOR, BH.golden, payload_loader=BH.loader, now=lambda: NOW)
        out = adapter.configs(["R1"])
        self.assertEqual((out["status"], out["unknown_devices"]["R1"]["reason"]), ("unavailable", "NO_SNAPSHOT"))

    def test_orm_payload_loader_of_an_unknown_bundle_is_empty(self):
        self.assertEqual(bh.orm_payload_loader("R1", "BND-UNKNOWN", ["CFG-1"]), [])


class OrmPayloadLoaderTests(TestCase):
    def test_orm_payload_loader_returns_hash_verified_golden_items(self):
        bundle = bundle_helper.uat_of(bundle_helper.partial_run())
        item = models.ConfigurationBundleItem.objects.filter(bundle=bundle).order_by("sequence").first()
        rows = bh.orm_payload_loader(item.device, bundle.bundle_id, [item.cfg_id])
        self.assertEqual([(r["cfg_id"], r["integrity"], r["payload_hash"]) for r in rows], [(item.cfg_id, "OK", item.payload_hash)])
