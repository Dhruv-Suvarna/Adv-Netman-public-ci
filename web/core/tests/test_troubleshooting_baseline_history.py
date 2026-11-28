"""Historical + snapshot baseline adapters (stable IDs BLHIST-001 .. BLHIST-0xx; supports spec 3.3 / 6.3 / UT-026 / UT-027).

PROVENANCE: SIMULATED -- injected readers / hand-written dicts and the ORM test database (TsEvidenceRef snapshots written by the production
``repository.store_evidence``).  No device, Influx, NetBox or socket; nothing here is gateway-recorded live evidence.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase, TestCase

from core.services.troubleshooting import baselines as bl, repository as repo
from core.services.troubleshooting.adapters import baseline_history as bh

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
HASH = lambda t: __import__("hashlib").sha256(t.encode()).hexdigest()  # noqa: E731
GOLD_TEXT = "interface Ethernet1\n   mtu 9214\nrouter ospf 1\n   router-id 1.1.1.1\n"


def golden(devs=("R1",), *, created=NOW - timedelta(days=2), status="available", change="CHG-1"):
    scope = [{"device": d, "status": "COVERED", "revision": "BND-GOLD-000001", "digest": "d" * 64, "url": "/b/1/", "created_at": created.isoformat(),
              "items": [{"cfg_id": f"CFG-{d}", "payload_hash": HASH(GOLD_TEXT), "operation": "CREATE_DEFINE", "sequence": 1}]} for d in devs]
    return {"status": status, "device_scope": scope, "approved_change_id": change, "reason": "x"}


def loader(dev, bundle, cfgs, text=GOLD_TEXT, integrity="OK"):
    return [{"cfg_id": i, "platform": "ceos", "operation": "CREATE_DEFINE", "payload": text, "payload_hash": HASH(GOLD_TEXT), "integrity": integrity} for i in cfgs]


def snap(text, *, age=3600, integrity="OK", platform="ceos", eid="EV-1"):
    return {"text": text, "collected_at": NOW - timedelta(seconds=age), "platform": platform, "evidence_id": eid, "integrity": integrity, "sha256": HASH(text)}


def adapter(snaps, gold=None, **kw):
    kw.setdefault("payload_loader", loader)
    reader = snaps if callable(snaps) else (lambda devs: {d: s for d, s in snaps.items() if d in devs})
    return bh.ConfigSnapshotBaseline(golden_provider=lambda devs: gold or golden(devs), snapshot_reader=reader, now=lambda: NOW, **kw)


class ConfigSnapshotTests(SimpleTestCase):
    def test_blhist_001_conforming_scope_only(self):
        out = adapter({"R1": snap(GOLD_TEXT + "hostname R1\nusername x secret [REDACTED]\n")}).configs(["R1"])
        self.assertEqual(out["status"], "available")
        d = out["devices"]["R1"]
        self.assertEqual((d["diffs"], d["compared_lines"], d["golden_revision"], d["snapshot_evidence_id"]), ([], 4, "BND-GOLD-000001", "EV-1"))
        rows = bl.assess_drift(out, changes=[], production_impact="NONE")
        self.assertEqual(rows[0]["drift_kind"], "NONE")

    def test_blhist_002_missing_snapshot_is_unknown_not_conforming(self):
        out = adapter({}).configs(["R1"])
        self.assertEqual(out["status"], "unavailable")
        self.assertEqual(out["unknown_devices"]["R1"]["reason"], "NO_SNAPSHOT")
        self.assertEqual(bl.assess_drift(out, changes=[], production_impact="NONE")[0]["drift_kind"], "UNKNOWN")

    def test_blhist_003_mixed_devices_partial(self):
        g = golden(["R1", "R2"])
        out = adapter({"R1": snap(GOLD_TEXT), "R2": snap(GOLD_TEXT, age=3 * 86400)}, g).configs(["R1", "R2", "R9"])
        self.assertEqual((sorted(out["devices"]), out["coverage"]), (["R1"], "PARTIAL"))
        self.assertEqual({k: v["reason"] for k, v in out["unknown_devices"].items()}, {"R2": "STALE_SNAPSHOT", "R9": "NO_GOLDEN_COVERAGE"})
        kinds = {r["subject"]: r["drift_kind"] for r in bl.assess_drift(out, changes=[], production_impact="UNKNOWN")}
        self.assertEqual(kinds, {"R1": "NONE", "R2": "UNKNOWN", "R9": "UNKNOWN"})

    def test_blhist_004_scope_guards(self):
        old = golden(created=NOW - timedelta(days=9))
        late = golden(created=NOW - timedelta(hours=2))
        cases = [("SNAPSHOT_PREDATES_GOLDEN", snap(GOLD_TEXT, age=3 * 3600), late), ("SCOPE_MISMATCH", snap(GOLD_TEXT, platform="iosxe"), old),
                 ("SNAPSHOT_INTEGRITY", snap(GOLD_TEXT, integrity="FAILED"), old)]
        for code, s, g in cases:
            with self.subTest(code=code):
                self.assertEqual(adapter({"R1": s}, g).configs(["R1"])["unknown_devices"]["R1"]["reason"], code)

    def test_blhist_005_golden_payload_integrity_and_bad_operation(self):
        out = adapter({"R1": snap(GOLD_TEXT)}, payload_loader=lambda d, b, c: loader(d, b, c, integrity="FAILED")).configs(["R1"])
        self.assertEqual(out["unknown_devices"]["R1"]["reason"], "GOLDEN_INTEGRITY")
        bad = lambda d, b, c: [{**i, "operation": "REPLACE"} for i in loader(d, b, c)]  # noqa: E731
        self.assertEqual(adapter({"R1": snap(GOLD_TEXT)}, payload_loader=bad).configs(["R1"])["unknown_devices"]["R1"]["reason"], "UNSUPPORTED_OPERATION")

    def test_blhist_006_denied_and_failing_readers_fail_closed(self):
        def deny(devs):
            raise PermissionError("no")
        out = adapter(deny).configs(["R1"])
        self.assertEqual((out["status"], out.get("denied")), ("unavailable", True))
        def boom(devs):
            raise RuntimeError("secret-detail")
        out = adapter(boom).configs(["R1"])
        self.assertEqual(out["status"], "unavailable")
        self.assertNotIn("secret-detail", out["reason"])
        self.assertEqual(adapter({}, gold={"status": "unavailable", "reason": "none"}).configs(["R1"])["status"], "unavailable")
        self.assertEqual(adapter({}).configs([])["status"], "unavailable")

    def test_blhist_007_approved_vs_unapproved_drift(self):
        text = "interface Ethernet1\n   mtu 1500\nrouter ospf 1\n   router-id 1.1.1.1\n"
        explain = lambda dev, line, g: "CHG-9" if "mtu" in line else ""  # noqa: E731
        out = adapter({"R1": snap(text.replace("router-id 1.1.1.1", "router-id 9.9.9.9"))}, explain=explain).configs(["R1"])
        self.assertEqual(len(out["devices"]["R1"]["diffs"]), 2)
        rows = bl.assess_drift(out, changes=[{"change_id": "CHG-9", "approved": True}], production_impact="NONE")
        by = {r["subject"].split(": ")[-1]: r for r in rows}
        self.assertEqual(by["mtu 9214"]["drift_kind"], "APPROVED")
        self.assertEqual(by["mtu 9214"]["approved_change_id"], "CHG-9")
        self.assertEqual(by["router-id 1.1.1.1"]["drift_kind"], "UNAPPROVED")
        self.assertEqual(bl.decide_preserve_or_remediate(by["mtu 9214"], soak_active=True, causal_evidence=False)["decision"], "PRESERVE")
        # approval is unknown to the change source -> NOT approved
        rows = bl.assess_drift(out, changes=[], production_impact="NONE")
        self.assertTrue(all(r["drift_kind"] == "UNAPPROVED" for r in rows if r["subject"] != "R1"))

    def test_blhist_008_redacted_only_scope_is_unknown(self):
        red = "username a secret [REDACTED]\n"
        ld = lambda d, b, c: [{"cfg_id": i, "platform": "ceos", "operation": "CREATE_DEFINE", "payload": red, "payload_hash": HASH(GOLD_TEXT), "integrity": "OK"} for i in c]  # noqa: E731
        self.assertEqual(adapter({"R1": snap(red)}, payload_loader=ld).configs(["R1"])["unknown_devices"]["R1"]["reason"], "NOTHING_COMPARABLE")


class SeriesFixture:
    @staticmethod
    def gauge(n=40, step=300, end_age=60, base=10.0):
        return [{"t": (NOW - timedelta(seconds=end_age + i * step)).isoformat(), "value": base + (i % 3)} for i in range(n)]


FLOW = {"history_series": [{"ref": "R1:cpu", "device": "R1", "measurement": "gnmi_telemetry", "field": "cpu_total_pct"}]}


class HistoryTests(SimpleTestCase):
    def test_blhist_020_no_reader_or_no_declared_series_unavailable(self):
        self.assertEqual(bh.HistoryBaseline(None)(FLOW, ["R1"], NOW)["status"], "unavailable")
        self.assertEqual(bh.HistoryBaseline(lambda r: [])({}, ["R1"], NOW)["status"], "unavailable")

    def test_blhist_021_learned_fresh_with_pointer_fields(self):
        seen = []
        def reader(req):
            seen.append(req)
            return SeriesFixture.gauge()
        out = bh.HistoryBaseline(reader)(FLOW, ["R1"], NOW)
        st = out["stats"]["R1:cpu"]
        self.assertEqual((out["status"], st["state"], st["sample_freshness"], out["coverage"]), ("available", "LEARNED", "FRESH", "FULL"))
        self.assertEqual(out["lkg_at"], st["newest"])
        self.assertEqual((seen[0]["device"], seen[0]["max_points"]), ("R1", 2000))

    def test_blhist_022_stale_partial_and_aged_samples(self):
        out = bh.HistoryBaseline(lambda r: SeriesFixture.gauge(end_age=40 * 86400))(FLOW, ["R1"], NOW)
        self.assertEqual(out["stats"]["R1:cpu"]["state"], "STALE")
        self.assertEqual(out["coverage"], "NONE")
        out = bh.HistoryBaseline(lambda r: SeriesFixture.gauge(end_age=7200))(FLOW, ["R1"], NOW)
        self.assertEqual((out["stats"]["R1:cpu"]["state"], out["stats"]["R1:cpu"]["sample_freshness"]), ("LEARNED", "AGED"))
        out = bh.HistoryBaseline(lambda r: SeriesFixture.gauge(n=3))(FLOW, ["R1"], NOW)
        self.assertEqual(out["stats"]["R1:cpu"]["state"], "UNKNOWN")
        self.assertEqual(bl.anomaly(99.0, out["stats"]["R1:cpu"])["anomalous"], None)

    def test_blhist_023_mixed_devices_out_of_scope_denied_not_queried(self):
        flow = {"history_series": FLOW["history_series"] + [{"ref": "R2:cpu", "device": "R2", "measurement": "gnmi_telemetry", "field": "cpu_total_pct"},
                                                           {"ref": "bad ref!", "device": "R1"}]}
        calls = []
        def reader(req):
            calls.append(req["device"])
            if req["device"] == "R1":
                return SeriesFixture.gauge()
            raise AssertionError("must not be queried")
        out = bh.HistoryBaseline(reader)(flow, ["R1"], NOW)
        self.assertEqual((calls, out["series_state"]["R2:cpu"]["state"], out["refused"][0]["reason"], out["coverage"]), (["R1"], "DENIED", "INVALID_SERIES", "PARTIAL"))
        self.assertEqual((out["devices_covered"], out["devices_uncovered"]), (["R1"], []))

    def test_blhist_024_denied_reader(self):
        def deny(req):
            raise PermissionError("no")
        out = bh.HistoryBaseline(deny)(FLOW, ["R1"], NOW)
        self.assertEqual((out["status"], out["series_state"]["R1:cpu"]["state"]), ("unavailable", "DENIED"))

    def test_blhist_025_counter_reset_and_sample_hygiene(self):
        vals = [100, 200, 300, 10, 110, 210]  # reset between 300 -> 10
        samples = [{"t": (NOW - timedelta(seconds=600 - i * 60)).isoformat(), "value": v} for i, v in enumerate(vals)]
        samples += [{"t": (NOW + timedelta(hours=1)).isoformat(), "value": 5}, {"t": "junk", "value": 1}, {"t": samples[0]["t"], "value": 7}, {"t": samples[1]["t"], "value": True}]
        r = bh.clean_samples(samples, kind="counter", now=NOW, max_points=100)
        self.assertEqual((r["resets"], r["dropped"]), (1, {"invalid": 2, "future": 1, "duplicate": 1}))
        self.assertTrue(all(s["value"] > 0 for s in r["samples"]) and len(r["samples"]) == 4)
        self.assertAlmostEqual(r["samples"][0]["value"], 100 / 60)
        self.assertTrue(bh.clean_samples(SeriesFixture.gauge(50), kind="gauge", now=NOW, max_points=10)["truncated"])

    def test_blhist_026_flux_query_validated_and_parsed(self):
        s = {"device": "R1", "measurement": "gnmi_telemetry", "field": "cpu_total_pct"}
        q = bh.flux_series_query("lab", s, start="-30d")
        self.assertIn('r._field == "cpu_total_pct"', q)
        for bad in ({**s, "field": "nope"}, {**s, "device": 'R1" or true'}, {**s, "measurement": "other"}):
            with self.assertRaises(ValueError):
                bh.flux_series_query("lab", bad, start="-30d")
        with self.assertRaises(ValueError):
            bh.flux_series_query("lab", s, start="-1d) |> evil")
        csv_text = ",result,table,_time,_value\n,_result,0,2026-11-09T11:00:00Z,12.5\n,_result,0,2026-11-09T11:05:00Z,abc\n"
        self.assertEqual(bh.parse_flux_samples(csv_text), [{"t": "2026-11-09T11:00:00Z", "value": 12.5}])
        reader = bh.FluxHistoryReader(lambda f: csv_text, "lab")
        self.assertEqual(len(reader({**s, "start": "-30d"})), 1)


class DjangoSourcesWiringTests(SimpleTestCase):
    def test_blhist_030_defaults_remain_explicit_unavailable_without_collaborators(self):
        src = bl.DjangoBaselineSources(nsot=object(), topology=object())
        self.assertEqual(src.history(FLOW, ["R1"], NOW)["status"], "unavailable")
        self.assertEqual(src.configs(["R1"])["status"], "unavailable")

    def test_blhist_031_injected_reader_and_adapter_are_used(self):
        src = bl.DjangoBaselineSources(history_reader=lambda r: SeriesFixture.gauge(), config_adapter=adapter({"R1": snap(GOLD_TEXT)}))
        self.assertEqual(src.history(FLOW, ["R1"], NOW)["status"], "available")
        self.assertEqual(src.configs(["R1"])["status"], "available")
        g = bl.gather(bl.StaticSources({}), devices=["R1"], flow={}, now=NOW, onset=NOW)
        self.assertEqual(g["history"]["status"], "unavailable")


class OrmSnapshotAndPersistTests(TestCase):
    ACTOR = repo.Actor("tester", "user", devices=frozenset({"R1", "R2"}))

    def _case(self, key="k1"):
        return repo.open_case(self.ACTOR, trigger_source="alert:t", idempotency_key=key, service_intent={"s": 1}, affected_scope={"devices": ["R1", "R2"]}, now=NOW)

    def _store(self, case, dev, text, at, **kw):
        return repo.store_evidence(self.ACTOR, case, source_type="config", device=dev, command_or_api="show running-config", adapter="t", collected_at=at, raw=text,
                                   scope={"platform": "ceos"}, **kw)

    def test_blhist_040_orm_reader_newest_per_device_tenant_scoped_and_integrity(self):
        case = self._case()
        self._store(case, "R1", "old\n", NOW - timedelta(hours=5))
        new = self._store(case, "R1", GOLD_TEXT + "username a secret hunter2\n", NOW - timedelta(hours=1))
        repo.store_evidence(self.ACTOR, case, source_type="cli", device="R2", command_or_api="show version", adapter="t", collected_at=NOW, raw="x")
        got = bh.orm_snapshot_reader(self.ACTOR, ["R1", "R2"], now=NOW)
        self.assertEqual(list(got), ["R1"])
        self.assertEqual((got["R1"]["evidence_id"], got["R1"]["integrity"], got["R1"]["platform"]), (new.evidence_id, "OK", "ceos"))
        self.assertNotIn("hunter2", got["R1"]["text"])
        other = repo.Actor("o", "user", tenant="other")
        self.assertEqual(bh.orm_snapshot_reader(other, ["R1"], now=NOW), {})
        self.assertEqual(bh.orm_snapshot_reader(repo.Actor("r2", "user", devices=frozenset({"R2"})), ["R1"], now=NOW), {})
        blob = new.raw_blob
        from django.db import connection
        with connection.cursor() as cur:  # bypass the append-only ORM guard to simulate storage corruption
            cur.execute(f"UPDATE {blob._meta.db_table} SET content = %s WHERE id = %s", ["tampered", blob.pk])
        bad = bh.orm_snapshot_reader(self.ACTOR, ["R1"], now=NOW)["R1"]
        self.assertEqual((bad["integrity"], bad["text"]), ("FAILED", None))

    def test_blhist_041_end_to_end_drift_persisted_in_report_baselines(self):
        case = self._case("k2")
        self._store(case, "R1", GOLD_TEXT.replace("9214", "1500"), NOW - timedelta(hours=1))
        ad = bh.ConfigSnapshotBaseline.from_orm(self.ACTOR, lambda devs: golden(devs), payload_loader=loader, now=lambda: NOW)
        src = bl.DjangoBaselineSources(config_adapter=ad, overrides={"intent": lambda d, f: bl.unavailable("intent", "t"), "golden": lambda d: golden(d),
                                                                      "changes": lambda d, s, u: {"status": "available", "changes": [{"change_id": "CHG-1", "approved": True, "at": (NOW - timedelta(days=1)).isoformat()}]}})
        bs = bl.gather(src, devices=["R1"], flow=FLOW, now=NOW, onset=NOW)
        self.assertEqual(bs["configs"]["status"], "available")
        drift = bl.assess_drift(bs["configs"], changes=bs["classified_changes"], production_impact="NONE")
        self.assertEqual([r["drift_kind"] for r in drift], ["UNAPPROVED"])
        records, ev = bl.persist_baselines(self.ACTOR, case, bs, now=NOW)
        self.assertEqual(sorted(r.baseline_type for r in records), ["GOLDEN_CONFIG", "INTENT", "LEARNED_HISTORICAL", "SLO"])
        hist = next(r for r in records if r.baseline_type == "LEARNED_HISTORICAL")
        self.assertEqual(hist.data["status"], "unavailable")  # no reader wired: persisted as unavailable, not invented
        self.assertEqual(ev["history"].quality, "MISSING")

    def test_blhist_042_persisted_history_baseline_carries_freshness_and_lkg(self):
        case = self._case("k3")
        src = bl.DjangoBaselineSources(history_reader=lambda r: SeriesFixture.gauge(),
                                       overrides={"intent": lambda d, f: bl.unavailable("intent", "t"), "golden": lambda d: golden(d),
                                                  "changes": lambda d, s, u: {"status": "available", "changes": []}})
        bs = bl.gather(src, devices=["R1"], flow=FLOW, now=NOW, onset=NOW)
        records, _ = bl.persist_baselines(self.ACTOR, case, bs, now=NOW)
        hist = next(r for r in records if r.baseline_type == "LEARNED_HISTORICAL")
        self.assertEqual(hist.data["stats"]["R1:cpu"]["sample_freshness"], "FRESH")
        self.assertEqual(hist.data["lkg_at"], bs["history"]["lkg_at"])
        gold = next(r for r in records if r.baseline_type == "GOLDEN_CONFIG")
        self.assertEqual((gold.data["device_scope"][0]["revision"], gold.approved_change_id), ("BND-GOLD-000001", "CHG-1"))
