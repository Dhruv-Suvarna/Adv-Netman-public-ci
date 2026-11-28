"""Bounded physical-state evidence source -> RB01 / RB07 / HC04 / HC05.  Stable IDs PHYSRC-001 .. PHYSRC-020.

PROVENANCE: every physical-source document below is SIMULATED (hand-written to the ``nmas.troubleshooting.physical-source/1`` contract); the readers are in-process fakes and the
gateway dict carries ``live=false``.  Nothing is gateway-recorded, so NO live verification is claimed.  Qualification against real cEOS / IOS-XE / FRR optics, FEC and counter
APIs is documented in docs/troubleshooting/physical-source.md as INCOMPLETE_WORK.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase, TestCase

from core import models as m
from core.services.troubleshooting import baselines as bl
from core.services.troubleshooting import collectors as col
from core.services.troubleshooting import normalization as nz
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting import runtime as rt
from core.services.troubleshooting.adapters import physical as phy

ACTOR = repo.Actor("alice", "user", tenant="acme")
T0 = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
GW = {"live": False, "fixture_id": "simulated-physical", "note": "SIMULATED: not gateway-recorded"}
EV = {"evidence_id": "ev-phy", "source_type": "STATE_SNAPSHOT", "command_or_api": "physical-state read", "collected_at": T0.isoformat()}
SRC = {"id": "sim-phy-agent", "kind": "phy-agent", "read_only": True}
REQ = {"interfaces": ["Ethernet1"], "include": ["optics", "fec", "counters", "events"], "window_s": 3600}
KEYS = ("interface.transceiver", "interface.fec", "interface.l1_events")


def ts(sec_before=0):
    return (T0 - timedelta(seconds=sec_before)).isoformat()


def optics(**over):
    o = {"present": True, "virtual": False, "part": "QSFP-100G-SR4", "type": "100GBASE-SR4", "supported": True, "wavelength_nm": 850, "reach_m": 100, "speed_mbps": 100000,
         "rx_dbm": -2.0, "tx_dbm": -1.0, "temp_c": 40.0, "measured_at": ts(5),
         "thresholds": {"rx_low_warn": -8.0, "rx_high_warn": 3.0, "tx_low_warn": -7.0, "tx_high_warn": 3.0, "temp_high_warn": 70.0, "rx_low_alarm": -10.0}}
    o.update(over)
    return o


def series(pairs, boot="b1", **fields):
    """pairs = (seconds-before-T0, {field: value})"""
    return {"boot_id": boot, "samples": [{"at": ts(s), **vals} for s, vals in pairs]}


FEC_OK = series([(60, {"uncorrected": 0, "corrected": 10}), (0, {"uncorrected": 0, "corrected": 40})])
CNT_OK = series([(60, {"in_crc_errors": 10, "in_fcs_errors": 0}), (0, {"in_crc_errors": 70, "in_fcs_errors": 0})])


def iface(name="Ethernet1", **over):
    r = {"interface": name, "optics": optics(), "fec": {"mode": "RS-544", "counters": FEC_OK}, "counters": CNT_OK, "events": [{"at": ts(30), "kind": "LOS", "detail": "x"}], "events_complete": True}
    r.update(over)
    return r


def doc(rows=None, *, device="r1", platform="ceos", version="4.36.2F", scope=("Ethernet1",), source=None, capability=None, provenance=None, **over):
    d = {"schema": nz.PHY_SCHEMA, "device": device, "platform": platform, "os_version": version, "source_identity": dict(SRC, **(source or {})),
         "capability": capability if capability is not None else {"status": "SUPPORTED", "api": "simulated phy read"}, "scope": {"interfaces": list(scope)},
         "interfaces": rows if rows is not None else [iface()],
         "provenance": provenance if provenance is not None else {"label": "SIMULATED", "collected_at": T0.isoformat()}}
    d.update(over)
    return d


def norm(d, request=REQ, platform="ceos", version="4.36.2F"):
    return nz.normalize_physical_state(d, platform=platform, os_version=version, device="r1", evidence=EV, request=request, now=T0)


def by_key(res, key):
    return [o for o in res["observations"] if o["key"] == key]


def miss_keys(res):
    return {(r["extra"]["engine_key"], r["extra"].get("subject")): r["reason"] for r in res["missing"]}


class Reader:
    def __init__(self, docs):
        self.docs, self.calls = docs, []

    def read(self, request):
        self.calls.append(request)
        d = self.docs.get(request["device"])
        if isinstance(d, Exception):
            raise d
        return d

    def provenance(self):
        return GW


class UnitTests(SimpleTestCase):
    def test_PHYSRC_001_valid_document_yields_all_contract_observations(self):
        res = norm(doc())
        self.assertEqual(res["missing"], [])
        (t,) = by_key(res, "interface.transceiver")
        self.assertEqual((t["quality"], t["value"]["rx_dbm"], t["value"]["rx_low_warn"], t["value"]["part"], t["value"]["supported"]), ("OK", -2.0, -8.0, "QSFP-100G-SR4", True))
        self.assertEqual(t["value"]["source"]["id"], "sim-phy-agent")
        self.assertEqual(t["value"]["provenance"]["label"], "SIMULATED")
        (f,) = by_key(res, "interface.fec")
        self.assertEqual((f["value"]["mode"], f["value"]["uncorrected"], f["value"]["corrected"], f["quality"]), ("rs-544", 0, 30, "OK"))
        (r,) = by_key(res, "interface.rate.in_crc_errors")
        self.assertEqual(r["value"], 1.0)                               # 60 errors / 60 s
        (e,) = by_key(res, "interface.l1_events")
        self.assertEqual([x["kind"] for x in e["value"]["events"]], ["LOS"])

    def test_PHYSRC_002_identity_platform_capability_scope_provenance_gates(self):
        cases = [({"source": {"read_only": False}}, nz.Missing.UNSUPPORTED_OPERATION), ({"source": {"kind": "rib"}}, nz.Missing.UNSUPPORTED_OPERATION),
                 ({"source": {"id": ""}}, nz.Missing.UNSUPPORTED_OPERATION), ({"platform": "iosxe"}, nz.Missing.UNSUPPORTED_PLATFORM),
                 ({"capability": {"status": "UNSUPPORTED", "api": "x"}}, nz.Missing.UNSUPPORTED_OPERATION), ({"capability": {}}, nz.Missing.UNSUPPORTED_OPERATION),
                 ({"scope": ("Ethernet2",)}, nz.Missing.SCOPE_MISMATCH), ({"provenance": {}}, nz.Missing.PARSE_FAILED),
                 ({"provenance": {"label": "TRUSTME", "collected_at": ts()}}, nz.Missing.PARSE_FAILED),
                 ({"provenance": {"label": "SIMULATED", "collected_at": "yesterday-ish"}}, nz.Missing.PARSE_FAILED), ({"interfaces": "x"}, nz.Missing.PARSE_FAILED)]
        for patch, reason in cases:
            d = doc(**{k: v for k, v in patch.items() if k != "interfaces"})
            if "interfaces" in patch:
                d["interfaces"] = patch["interfaces"]
            res = norm(d)
            self.assertEqual(res["observations"], [], patch)
            self.assertEqual(miss_keys(res), {(k, "Ethernet1"): reason for k in KEYS}, patch)
        d = doc()
        d["os_version"] = "4.30.0F"
        self.assertEqual(set(miss_keys(norm(d)).values()), {nz.Missing.UNSUPPORTED_PLATFORM})
        self.assertEqual(set(miss_keys(norm("not json")).values()), {nz.Missing.PARSE_FAILED})
        self.assertEqual(set(miss_keys(norm(doc(device="r9"))).values()), {nz.Missing.UNSUPPORTED_PLATFORM})
        self.assertEqual(set(miss_keys(norm(doc(), request={"interfaces": []})).values()), {nz.Missing.SCOPE_MISMATCH})

    def test_PHYSRC_003_peer_scope_is_never_reattributed(self):
        d = doc([iface("Ethernet1"), iface("Ethernet2")], scope=("Ethernet1", "Ethernet2"))
        self.assertEqual(set(miss_keys(norm(d)).values()), {nz.Missing.SCOPE_MISMATCH})             # scope wider than asked
        d = doc([iface("Ethernet2")], scope=("Ethernet1",))                                          # entry for a port that was not asked
        res = norm(d)
        self.assertEqual(res["observations"], [])
        self.assertEqual(set(miss_keys(res).values()), {nz.Missing.EMPTY})
        d = doc([iface(), iface()])
        self.assertEqual(norm(d)["observations"], [])                                                # duplicate entry is ambiguous
        res = norm(doc([iface("Eth1")]))                                                             # alias is canonicalised, not rejected
        self.assertEqual(len(by_key(res, "interface.transceiver")), 1)

    def test_PHYSRC_004_virtual_or_absent_optics_stay_unknown(self):
        for o in (optics(virtual=True), optics(present=False), {"virtual": True}):
            res = norm(doc([iface(optics=o)]))
            self.assertEqual(by_key(res, "interface.transceiver"), [])
            self.assertEqual(miss_keys(res)[("interface.transceiver", "Ethernet1")], nz.Missing.UNSUPPORTED_OPERATION)
        res = norm(doc([iface(optics=None)]))
        self.assertEqual(miss_keys(res)[("interface.transceiver", "Ethernet1")], nz.Missing.EMPTY)
        res = norm(doc([iface(optics={"present": None, "part": "x"})]))
        self.assertEqual(miss_keys(res)[("interface.transceiver", "Ethernet1")], nz.Missing.EMPTY)

    def test_PHYSRC_005_missing_thresholds_or_measurements_block_the_verdict(self):
        for patch in ({"thresholds": {}}, {"thresholds": {"rx_low_warn": -8.0, "rx_high_warn": 3.0, "tx_low_warn": -7.0, "tx_high_warn": 3.0}},
                      {"thresholds": {"rx_low_warn": 3.0, "rx_high_warn": -8.0, "tx_low_warn": -7.0, "tx_high_warn": 3.0, "temp_high_warn": 70}},
                      {"rx_dbm": None}, {"tx_dbm": "n/a"}, {"temp_c": float("nan")}, {"rx_dbm": True}, {"part": ""}, {"supported": "yes"}):
            with self.subTest(patch=patch):
                (t,) = by_key(norm(doc([iface(optics=optics(**patch))])), "interface.transceiver")
                self.assertEqual(t["quality"], "UNTRUSTED_PARSE")
                self.assertIn("PARTIAL_PARSE", t["flags"])
                self.assertEqual(rt.QUALITY[t["quality"]], "UNTRUSTED")                 # Ctx.need refuses UNTRUSTED observations
        res = norm(doc([iface(optics=optics(measured_at="garbage"))]))
        self.assertEqual(miss_keys(res)[("interface.transceiver", "Ethernet1")], nz.Missing.PARSE_FAILED)

    def test_PHYSRC_006_stale_and_future_measurements(self):
        (t,) = by_key(norm(doc([iface(optics=optics(measured_at=ts(500)))])), "interface.transceiver")
        self.assertEqual((t["quality"], "STALE_MEASUREMENT" in t["flags"]), ("STALE", True))
        (t,) = by_key(norm(doc([iface(optics=optics(measured_at=ts(-600)))])), "interface.transceiver")
        self.assertEqual(t["quality"], "UNTRUSTED_PARSE")

    def test_PHYSRC_007_fec_delta_requires_one_epoch_and_span(self):
        def fec(s, boot="b1"):
            return norm(doc([iface(fec={"mode": "RS-544", "counters": s})]))
        # a lifetime counter is not a window: one sample, short span, stale, unordered, no epoch -> no value
        for s in (series([(0, {"uncorrected": 900})]), series([(4, {"uncorrected": 1}), (0, {"uncorrected": 9})]), series([(500, {"uncorrected": 1}), (400, {"uncorrected": 9})]),
                  series([(0, {"uncorrected": 1}), (60, {"uncorrected": 9})]), series([(60, {"uncorrected": 1}), (0, {"uncorrected": 9})], boot=None),
                  series([(60, {"corrected": 1}), (0, {"corrected": 9})])):
            res = fec(s)
            self.assertEqual(by_key(res, "interface.fec"), [], s)
            self.assertIn(("interface.fec", "Ethernet1"), miss_keys(res))
        (f,) = by_key(fec(series([(60, {"uncorrected": 5}), (0, {"uncorrected": 125})])), "interface.fec")
        self.assertEqual(f["value"]["uncorrected"], 120)
        res = norm(doc([iface(fec={"counters": FEC_OK})]))                                       # mode absent
        self.assertEqual(miss_keys(res)[("interface.fec", "Ethernet1")], nz.Missing.PARSE_FAILED)
        res = norm(doc([iface(fec=None)]))
        self.assertEqual(miss_keys(res)[("interface.fec", "Ethernet1")], nz.Missing.EMPTY)

    def test_PHYSRC_008_counter_reset_is_an_event_never_a_rate(self):
        for s in (series([(60, {"in_crc_errors": 500}), (0, {"in_crc_errors": 3})]),
                  {"boot_id": "b1", "samples": [{"at": ts(60), "in_crc_errors": 5}, {"at": ts(0), "in_crc_errors": 9, "boot_id": "b2"}]}):
            res = norm(doc([iface(counters=s, fec=None)]))
            self.assertEqual([o for o in res["observations"] if o["key"].startswith("interface.rate.")], [])
            (ev,) = by_key(res, "interface.counter_event")
            self.assertEqual(ev["value"], "reset")
        res = norm(doc([iface(fec={"mode": "RS-544", "counters": series([(60, {"uncorrected": 500}), (0, {"uncorrected": 1})])}, counters=None)]))
        self.assertEqual([o["value"] for o in by_key(res, "interface.counter_event")], ["reset"])
        self.assertEqual(by_key(res, "interface.fec"), [])

    def test_PHYSRC_009_short_stale_or_malformed_counters_give_no_rate(self):
        for s in (series([(0, {"in_crc_errors": 9})]), series([(4, {"in_crc_errors": 1}), (0, {"in_crc_errors": 9})]), series([(500, {"in_crc_errors": 1}), (400, {"in_crc_errors": 9})]),
                  series([(60, {"in_crc_errors": -1}), (0, {"in_crc_errors": 9})]), series([(60, {"in_crc_errors": 1.5}), (0, {"in_crc_errors": 9})]), "x", {"samples": "x"}):
            res = norm(doc([iface(counters=s)]))
            self.assertEqual([o for o in res["observations"] if o["key"].startswith("interface.rate.")], [], s)
            self.assertEqual(by_key(res, "interface.counter_event"), [])

    def test_PHYSRC_010_error_history_needs_complete_wellformed_events(self):
        res = norm(doc([iface(events=[], events_complete=True)]))
        (e,) = by_key(res, "interface.l1_events")
        self.assertEqual(e["value"]["events"], [])
        for r in (iface(events_complete=False), iface(events=None), iface(events=[{"at": "bad", "kind": "LOS"}], events_complete=True),
                  iface(events=[{"at": ts(1), "kind": "WIZARDS"}], events_complete=True),
                  iface(events=[{"at": ts(i), "kind": "LOS"} for i in range(nz.PHY_MAX_EVENTS + 1)], events_complete=True)):
            res = norm(doc([r]))
            self.assertEqual(by_key(res, "interface.l1_events"), [])
            self.assertIn(("interface.l1_events", "Ethernet1"), miss_keys(res))

    def test_PHYSRC_011_adapter_requests_target_and_peer_only(self):
        tgt = {"device": "r1", "interface": "Ethernet1"}
        ctx = phy.PhysicalContext(links=({"a": "r1", "a_if": "Ethernet1", "b": "r2", "b_if": "Ethernet7"},))
        w = {"interface.transceiver", "interface.fec"}
        self.assertEqual(phy.requests_for_device(tgt, "r1", w, ctx)[0]["interfaces"], ["Ethernet1"])
        self.assertEqual(phy.requests_for_device(tgt, "r2", w, ctx)[0]["interfaces"], ["Ethernet7"])
        self.assertEqual(phy.requests_for_device(tgt, "r3", w, ctx), [])
        self.assertEqual(phy.requests_for_device(tgt, "r2", w, None), [])                  # no link map: peer not guessed
        self.assertEqual(phy.requests_for_device(tgt, "r1", {"route.rib"}, ctx), [])
        self.assertEqual(phy.requests_for_device({}, "r1", w, ctx), [])
        self.assertIn("NOT_CONFIGURED", phy.gap_reason(False, False))
        self.assertIn("SCOPE_MISMATCH", phy.gap_reason(True, False))


def target(platform="ceos"):
    return col.Target(device="r1", platform=platform, os_version="4.36.2F")


def collector(**kw):
    return col.PhysicalCollector(now=lambda: T0, capability_probe=lambda plat, src: {"status": "SUPPORTED", "evidence": "test", "transport": "test"}, **kw)


class CollectorTests(SimpleTestCase):
    def test_PHYSRC_012_collector_reads_once_and_records_provenance(self):
        rd = Reader({"r1": doc()})
        b = collector().collect(target(), [REQ, REQ], rd)
        self.assertEqual(len(rd.calls), 1)                                  # one bounded read per device
        self.assertEqual(rd.calls[0]["device"], "r1")
        self.assertEqual(rd.calls[0]["interfaces"], ["Ethernet1"])
        self.assertEqual({o["key"] for o in b["observations"]}, {"interface.transceiver", "interface.fec", "interface.l1_events", "interface.rate.in_crc_errors", "interface.rate.in_fcs_errors"})
        self.assertFalse(b["run"]["gateway"]["live"])
        self.assertEqual(b["run"]["privileges"], "read-only")

    def test_PHYSRC_013_failures_become_key_and_subject_bound_gaps(self):
        for exc, reason in ((col.PermissionDenied(), nz.Missing.PERMISSION_DENIED), (col.TransportError("x"), nz.Missing.TRANSPORT_ERROR), (TimeoutError(), nz.Missing.TRANSPORT_ERROR)):
            b = collector().collect(target(), [REQ], Reader({"r1": exc}))
            self.assertEqual(b["observations"], [])
            self.assertEqual({(r["extra"]["engine_key"], r["extra"]["subject"]): r["reason"] for r in b["missing"]}, {(k, "Ethernet1"): reason for k in KEYS})

    def test_PHYSRC_014_budgets_are_enforced(self):
        b = collector(budget=col.Budget(max_bytes=50)).collect(target(), [REQ], Reader({"r1": doc()}))
        self.assertEqual(b["observations"], [])
        self.assertEqual({r["reason"] for r in b["missing"]}, {nz.Missing.OUTPUT_TOO_LARGE})
        rd = Reader({"r1": doc()})
        b = collector(budget=col.Budget(max_commands=0)).collect(target(), [REQ], rd)
        self.assertEqual((rd.calls, b["observations"]), ([], []))
        self.assertEqual({r["reason"] for r in b["missing"]}, {nz.Missing.BUDGET_EXCEEDED})
        big = [f"Ethernet{i}" for i in range(1, 30)]
        rd = Reader({"r1": doc([iface(n) for n in big[:nz.PHY_MAX_INTERFACES]], scope=big[:nz.PHY_MAX_INTERFACES])})
        collector().collect(target(), [dict(REQ, interfaces=big)], rd)
        self.assertEqual(len(rd.calls[0]["interfaces"]), nz.PHY_MAX_INTERFACES)      # request bound

    def test_PHYSRC_015_unadmitted_device_is_never_read(self):
        rd = Reader({"r1": doc()})
        t = col.Target(device="r1", platform="ceos", os_version="4.36.2F", lifecycle_state="WITHDRAWN", withdrawn=True)
        b = collector().collect(t, [REQ], rd)
        self.assertEqual((rd.calls, b["observations"]), ([], []))
        self.assertTrue(b["missing"])

    def test_PHYSRC_016_restart_has_no_hidden_state(self):
        """A restarted collector (new instance, same reader) re-reads and re-derives the same observations; a device reboot (new boot id) is a reset, not health."""
        d1 = doc()
        first = collector().collect(target(), [REQ], Reader({"r1": d1}))
        again = collector().collect(target(), [REQ], Reader({"r1": copy.deepcopy(d1)}))
        self.assertEqual(sorted((o["key"], str(o["value"])) for o in first["observations"]), sorted((o["key"], str(o["value"])) for o in again["observations"]))
        rebooted = doc([iface(counters={"boot_id": "b1", "samples": [{"at": ts(60), "in_crc_errors": 40}, {"at": ts(0), "in_crc_errors": 2, "boot_id": "b2"}]})])
        b = collector().collect(target(), [REQ], Reader({"r1": rebooted}))
        self.assertIn("reset", [o["value"] for o in b["observations"] if o["key"] == "interface.counter_event"])
        self.assertFalse([o for o in b["observations"] if o["key"].startswith("interface.rate.")])


class RuntimeMappingTests(SimpleTestCase):
    def test_PHYSRC_017_map_observations_keeps_quality_and_adds_no_defaults(self):
        res = norm(doc([iface(optics=optics(thresholds={}))]))
        mapped = rt.map_observations(res["observations"], device="r1", run_key="r", unit_id="u")
        by = {o["key"]: o for o in mapped}
        self.assertEqual(by["interface.transceiver@Ethernet1"]["quality"], "UNTRUSTED")
        self.assertEqual(by["interface.fec@Ethernet1"]["quality"], "GOOD")
        self.assertIn("interface.l1_events@Ethernet1", by)
        self.assertEqual(by["interface.counter_reset@Ethernet1"]["value"]["event"], "rate-sample-ok")
        self.assertNotIn("interface.rate.in_runts@Ethernet1", by)                    # unreported counters are not synthesised
        res = norm(doc([iface(counters=series([(60, {"in_crc_errors": 90}), (0, {"in_crc_errors": 1})]))]))
        by = {o["key"]: o for o in rt.map_observations(res["observations"], device="r1", run_key="r", unit_id="u")}
        self.assertTrue(by["interface.counter_reset@Ethernet1"]["value"]["reset"])


class RuntimeTests(TestCase):
    def _provider(self, source, *, ctx="default", wanted=None):
        links = ({"a": "r1", "a_if": "Ethernet1", "b": "r2", "b_if": "Ethernet7"},)
        case = repo.open_case(ACTOR, trigger_source="alert:test", idempotency_key="phy-1",
                              service_intent={"target": {"device": "r1", "interface": "Ethernet1"}}, flow_scope={}, affected_scope={"devices": ["r1", "r2"]},
                              target_states={"r1": "VERIFIED", "r2": "VERIFIED"}, severity="HIGH", runbook="RB07", worked_before=True, first_detected_at=T0 - timedelta(minutes=10),
                              last_known_good_at=T0 - timedelta(hours=3), now=T0 - timedelta(minutes=5))
        d = rt.RuntimeDeps(admission=rt.InventoryAdmission(inventory=lambda: {x: {"platform": "ceos", "os_version": "4.36.2F"} for x in ("r1", "r2")}),
                           phy_source=(lambda info: source) if source is not None else None,
                           phy_context=phy.PhysicalContext(links=links) if ctx == "default" else ctx, sources=bl.StaticSources({}), clock=lambda: 0.0, sleep=lambda s: None, now=lambda: T0,
                           capability_probe=lambda plat, src: {"status": "SUPPORTED", "evidence": "test", "transport": "test"})
        actor = ACTOR
        budget = rt.RuntimeBudget()
        adm = rt.resolve_admission(actor, case, d, budget, T0)
        return rt.CollectorProvider(actor, case, d, adm, budget, "r1"), case

    def _keys(self, bundles, kind):
        return {o["key"] for b in bundles for o in b["observations"] if bool(o.get("is_missing_data")) == (kind == "missing")}

    def test_PHYSRC_018_runtime_target_and_peer_reads_and_default_gaps(self):
        peer_doc = doc([iface("Ethernet7")], device="r2", scope=("Ethernet7",))
        rd = Reader({"r1": doc(), "r2": peer_doc})
        p, case = self._provider(rd)
        wanted = ["interface.transceiver", "interface.fec", "interface.l1_events"]
        b1 = p.collect(case.case_id, "r1", wanted, T0)
        b2 = p.collect(case.case_id, "r2", wanted, T0)
        self.assertEqual([(c["device"], c["interfaces"]) for c in rd.calls], [("r1", ["Ethernet1"]), ("r2", ["Ethernet7"])])
        self.assertIn("interface.transceiver@Ethernet1", self._keys(b1, "value"))
        self.assertIn("interface.fec@Ethernet7", self._keys(b2, "value"))
        # no source -> explicit NOT_CONFIGURED gap, no value
        p, case = self._provider(None)
        b = p.collect(case.case_id, "r1", wanted, T0)
        self.assertFalse([k for k in self._keys(b, "value") if k.startswith("interface.")])
        reasons = [o.get("missing_reason", "") for x in b for o in x["observations"] if o.get("is_missing_data") and o["key"] in wanted]
        self.assertTrue(reasons and all(r.startswith("NOT_CONFIGURED") for r in reasons), reasons)

    def test_PHYSRC_019_runtime_without_link_map_does_not_guess_the_peer(self):
        rd = Reader({"r1": doc(), "r2": doc([iface("Ethernet7")], device="r2", scope=("Ethernet7",))})
        p, case = self._provider(rd, ctx=None)
        b = p.collect(case.case_id, "r2", ["interface.transceiver"], T0)
        self.assertEqual(rd.calls, [])
        reasons = [o.get("missing_reason", "") for x in b for o in x["observations"] if o.get("is_missing_data") and o["key"] == "interface.transceiver"]
        self.assertTrue(reasons and all(r.startswith("SCOPE_MISMATCH") for r in reasons), reasons)

    def test_PHYSRC_020_virtual_optics_reach_the_engine_as_unavailable_not_healthy(self):
        rd = Reader({"r1": doc([iface(optics=optics(virtual=True))])})
        p, case = self._provider(rd)
        b = p.collect(case.case_id, "r1", ["interface.transceiver"], T0)
        self.assertNotIn("interface.transceiver@Ethernet1", self._keys(b, "value"))
        miss = [o for x in b for o in x["observations"] if o.get("is_missing_data") and o["key"] == "interface.transceiver@Ethernet1"]
        self.assertTrue(miss and miss[0]["missing_reason"].startswith("UNSUPPORTED_OPERATION"), miss)
