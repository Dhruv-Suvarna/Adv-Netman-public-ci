"""Bounded routing-protocol evidence source -> RB03 (capability.protocol, protocol.config, routing.neighbor.detail).  Stable IDs PROTOSRC-001 .. PROTOSRC-024.

PROVENANCE: every protocol-source document below is SIMULATED (hand-written to the ``nmas.troubleshooting.protocol-source/1`` contract); readers are in-process fakes and the
gateway dict carries ``live=false``.  Nothing is gateway-recorded, so NO live verification is claimed (see docs/troubleshooting/protocol-source.md, INCOMPLETE_WORK).
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase, TestCase

from core.services.troubleshooting import baselines as bl
from core.services.troubleshooting import collectors as col
from core.services.troubleshooting import normalization as nz
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting import runtime as rt
from core.services.troubleshooting.adapters import protocol as pa

ACTOR = repo.Actor("alice", "user", tenant="acme")
T0 = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
GW = {"live": False, "fixture_id": "simulated-protocol", "note": "SIMULATED: not gateway-recorded"}
EV = {"evidence_id": "ev-proto", "source_type": "STATE_SNAPSHOT", "command_or_api": "protocol-state read", "collected_at": T0.isoformat()}
SRC = {"id": "sim-proto-agent", "kind": "proto-agent", "read_only": True}
SECRET = "S3cr3tKeyMaterial!"
FP = "ab" * 20
REQ = {"protocol": "ospf", "af": "ipv4", "vrf": "default", "interface": "Ethernet1", "peer": "r2", "include": ["capability", "config", "neighbor"]}
TARGET = {"device": "r1", "neighbor_device": "r2", "protocol": "ospf", "af": "ipv4", "vrf": "default", "interface": "Ethernet1", "neighbor_interface": "Ethernet2"}


def ts(sec_before=0):
    return (T0 - timedelta(seconds=sec_before)).isoformat()


def cfg(**over):
    c = {"collected_at": ts(5), "area": "0.0.0.0", "network_type": "point-to-point", "stub": False, "timers": {"hello": 10, "dead": 40},
         "auth": {"configured": True, "key_id": "1", "algorithm": "hmac-sha256", "fingerprint": FP}}
    c.update(over)
    return c


def doc(*, device="r1", platform="ceos", version="4.36.2F", req=REQ, source=None, capability=None, provenance=None, config=None, neighbor="default", complete=True, scope=None, **over):
    d = {"schema": nz.PROTO_SCHEMA, "device": device, "platform": platform, "os_version": version, "source_identity": dict(SRC, **(source or {})),
         "capability": capability if capability is not None else {"status": "SUPPORTED", "api": "simulated protocol read", "protocols": {"ospf": ["ipv4", "ipv6"], "bgp": ["ipv4"]}},
         "scope": scope if scope is not None else {k: req[k] for k in ("protocol", "af", "vrf", "interface", "peer")},
         "provenance": provenance if provenance is not None else {"label": "SIMULATED", "collected_at": T0.isoformat()},
         "config_complete": complete, "config": config if config is not None else cfg(),
         "neighbor": {"peer": req["peer"], "state": "ExStart", "since_s": 120, "last_error": "MTU mismatch", "observed_at": ts(3), "complete": True} if neighbor == "default" else neighbor}
    d.update(over)
    return d


def norm(d, request=REQ, platform="ceos", version="4.36.2F", now=T0):
    return nz.normalize_protocol_state(d, platform=platform, os_version=version, device="r1", evidence=EV, request=request, now=now)


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
        return copy.deepcopy(d)

    def provenance(self):
        return GW


class UnitTests(SimpleTestCase):
    def test_PROTOSRC_001_valid_document_yields_the_three_contract_observations(self):
        res = norm(doc())
        self.assertEqual(res["missing"], [])
        (c,) = by_key(res, "capability.protocol")
        self.assertEqual((c["value"]["supported"], c["target"]["protocol"], c["quality"]), (True, "ospf", "OK"))
        (p,) = by_key(res, "protocol.config")
        self.assertEqual((p["quality"], p["value"]["area"], p["value"]["timers"], p["value"]["stub"]), ("OK", "0.0.0.0", {"hello": 10, "dead": 40}, False))
        self.assertEqual(p["value"]["auth"], {"configured": True, "key_id": "1", "algorithm": "hmac-sha256", "fingerprint": FP})
        self.assertEqual(p["value"]["source"]["id"], "sim-proto-agent")
        (n,) = by_key(res, "routing.neighbor.detail")
        self.assertEqual((n["value"]["state"], n["value"]["last_error"], n["value"]["since_s"], n["target"]["neighbor"]), ("ExStart", "MTU mismatch", 120, "r2"))

    def test_PROTOSRC_002_identity_platform_capability_scope_provenance_gates(self):
        cases = [({"source": {"read_only": False}}, nz.Missing.UNSUPPORTED_OPERATION), ({"source": {"kind": "rib"}}, nz.Missing.UNSUPPORTED_OPERATION),
                 ({"source": {"id": ""}}, nz.Missing.UNSUPPORTED_OPERATION), ({"platform": "iosxe"}, nz.Missing.UNSUPPORTED_PLATFORM), ({"version": "9.9"}, nz.Missing.UNSUPPORTED_PLATFORM),
                 ({"device": "r9"}, nz.Missing.UNSUPPORTED_PLATFORM), ({"capability": {"status": "UNSUPPORTED", "api": "x", "protocols": {}}}, nz.Missing.UNSUPPORTED_OPERATION),
                 ({"capability": {}}, nz.Missing.UNSUPPORTED_OPERATION), ({"provenance": {}}, nz.Missing.PARSE_FAILED),
                 ({"provenance": {"label": "TRUSTME", "collected_at": ts()}}, nz.Missing.PARSE_FAILED), ({"provenance": {"label": "SIMULATED", "collected_at": "soon"}}, nz.Missing.PARSE_FAILED)]
        for patch, reason in cases:
            res = norm(doc(**patch))
            self.assertEqual(res["observations"], [], patch)
            self.assertEqual(set(miss_keys(res)), {("capability.protocol", "ospf"), ("protocol.config", "ospf"), ("routing.neighbor.detail", "r2")}, patch)
            self.assertEqual({r["reason"] for r in res["missing"]}, {reason}, patch)
        self.assertEqual(norm(doc(), version="4.36.2F")["missing"], [])
        res = norm({"schema": "other/1"})
        self.assertEqual({r["reason"] for r in res["missing"]}, {nz.Missing.PARSE_FAILED})

    def test_PROTOSRC_003_wrong_scope_is_never_attributed(self):
        for field, val in (("protocol", "bgp"), ("af", "ipv6"), ("vrf", "red"), ("interface", "Ethernet9"), ("peer", "r9")):
            sc = {k: REQ[k] for k in ("protocol", "af", "vrf", "interface", "peer")}
            sc[field] = val
            res = norm(doc(scope=sc))
            self.assertEqual(res["observations"], [], field)
            self.assertEqual({r["reason"] for r in res["missing"]}, {nz.Missing.SCOPE_MISMATCH}, field)
        res = norm(doc(neighbor={"peer": "r9", "state": "Full", "since_s": 1, "observed_at": ts(1), "complete": True}))          # another peer's block
        self.assertEqual(miss_keys(res)[("routing.neighbor.detail", "r2")], nz.Missing.SCOPE_MISMATCH)
        self.assertFalse(by_key(res, "routing.neighbor.detail"))

    def test_PROTOSRC_004_unsupported_or_unscoped_requests_are_gaps(self):
        for bad in (dict(REQ, protocol="eigrp"), dict(REQ, protocol="ldp")):
            res = norm(doc(), request=bad)
            self.assertEqual({r["reason"] for r in res["missing"]}, {nz.Missing.UNSUPPORTED_OPERATION})
            self.assertEqual(res["observations"], [])
        for bad in (dict(REQ, af="ipx"), dict(REQ, vrf=""), dict(REQ, peer=""), dict(REQ, interface=None)):
            res = norm(doc(), request=bad)
            self.assertEqual({r["reason"] for r in res["missing"]}, {nz.Missing.SCOPE_MISMATCH}, bad)
        # BGP needs no interface
        bgp = dict(REQ, protocol="bgp", interface=None)
        res = norm(doc(req=bgp, config={"collected_at": ts(2), "local_as": 65001, "neighbor_remote_as": 65002, "neighbor_vrf": "default", "neighbor_afs": ["ipv4"],
                                       "auth": {"configured": False}}), request=bgp)
        self.assertEqual((res["missing"], by_key(res, "protocol.config")[0]["quality"]), ([], "OK"))
        self.assertEqual(by_key(res, "protocol.config")[0]["value"]["neighbor_afs"], ["ipv4"])

    def test_PROTOSRC_005_capability_lists_the_protocol_and_af_or_it_is_unavailable(self):
        d = doc(capability={"status": "SUPPORTED", "api": "x", "protocols": {"bgp": ["ipv4"]}})
        res = norm(d)
        (c,) = by_key(res, "capability.protocol")
        self.assertFalse(c["value"]["supported"])
        self.assertFalse(by_key(res, "protocol.config") or by_key(res, "routing.neighbor.detail"))
        self.assertEqual({r["reason"] for r in res["missing"]}, {nz.Missing.UNSUPPORTED_OPERATION})
        d = doc(capability={"status": "SUPPORTED", "api": "x", "protocols": {"ospf": ["ipv4"]}}, scope={**{k: REQ[k] for k in ("protocol", "vrf", "interface", "peer")}, "af": "ipv6"})
        res = norm(d, request=dict(REQ, af="ipv6"))
        self.assertFalse(by_key(res, "capability.protocol")[0]["value"]["supported"])

    def test_PROTOSRC_006_area_as_and_timer_values_are_reported_for_mismatch_detection(self):
        a, b = norm(doc()), norm(doc(config=cfg(area="0.0.0.1", timers={"hello": 10, "dead": 120}, network_type="broadcast")))
        va, vb = by_key(a, "protocol.config")[0]["value"], by_key(b, "protocol.config")[0]["value"]
        self.assertNotEqual(va["area"], vb["area"])
        self.assertNotEqual(va["timers"]["dead"], vb["timers"]["dead"])
        self.assertEqual((vb["area"], vb["network_type"], vb["timers"]), ("0.0.0.1", "broadcast", {"hello": 10, "dead": 120}))
        bgp = dict(REQ, protocol="bgp", interface=None)
        bc = {"collected_at": ts(2), "local_as": 65001, "neighbor_remote_as": 65099, "neighbor_vrf": "red", "neighbor_afs": ["ipv4", "ipv6"], "auth": {"configured": False}}
        v = by_key(norm(doc(req=bgp, config=bc), request=bgp), "protocol.config")[0]["value"]
        self.assertEqual((v["local_as"], v["neighbor_remote_as"], v["neighbor_vrf"], v["neighbor_afs"], v["timers"] if "timers" in v else None), (65001, 65099, "red", ["ipv4", "ipv6"], None))

    def test_PROTOSRC_007_missing_config_fields_are_never_inferred_as_matching(self):
        for drop in ("area", "network_type", "stub", "timers", "auth"):
            c = cfg()
            c.pop(drop)
            (p,) = by_key(norm(doc(config=c)), "protocol.config")
            self.assertEqual(p["quality"], "UNTRUSTED_PARSE", drop)
            self.assertIn("uncertain", p["value"])
            self.assertEqual(rt.QUALITY[p["quality"]], "UNTRUSTED")                      # Ctx.need refuses it
        for bad_timers in ({"hello": 10}, {"hello": "10", "dead": 40}, {"hello": True, "dead": 40}, {"hello": 0, "dead": 40}):
            (p,) = by_key(norm(doc(config=cfg(timers=bad_timers))), "protocol.config")
            self.assertEqual(p["quality"], "UNTRUSTED_PARSE", bad_timers)
        bgp = dict(REQ, protocol="bgp", interface=None)
        (p,) = by_key(norm(doc(req=bgp, config={"collected_at": ts(1), "local_as": 65001, "auth": {"configured": False}}), request=bgp), "protocol.config")
        self.assertEqual(p["quality"], "UNTRUSTED_PARSE")

    def test_PROTOSRC_008_partial_responses_are_untrusted_or_gaps(self):
        (p,) = by_key(norm(doc(complete=False)), "protocol.config")
        self.assertEqual(p["quality"], "UNTRUSTED_PARSE")
        (p,) = by_key(norm(doc(complete="yes")), "protocol.config")
        self.assertEqual(p["quality"], "UNTRUSTED_PARSE")
        res = norm(doc(config="not-a-dict", neighbor=None))
        self.assertEqual({k for k in miss_keys(res)}, {("protocol.config", "ospf"), ("routing.neighbor.detail", "r2")})
        (n,) = by_key(norm(doc(neighbor={"peer": "r2", "state": "Full", "since_s": 5, "observed_at": ts(1)})), "routing.neighbor.detail")        # no complete flag
        self.assertEqual(n["quality"], "UNTRUSTED_PARSE")
        res = norm(doc(neighbor={"peer": "r2", "state": "Weird", "observed_at": ts(1), "complete": True}))
        self.assertEqual(miss_keys(res)[("routing.neighbor.detail", "r2")], nz.Missing.PARSE_FAILED)

    def test_PROTOSRC_009_stale_or_future_data_is_not_live_state(self):
        res = norm(doc(provenance={"label": "SIMULATED", "collected_at": ts(900)}))
        self.assertEqual({r["reason"] for r in res["missing"]}, {nz.Missing.STALE_SOURCE})
        res = norm(doc(provenance={"label": "SIMULATED", "collected_at": (T0 + timedelta(minutes=10)).isoformat()}))
        self.assertEqual({r["reason"] for r in res["missing"]}, {nz.Missing.PARSE_FAILED})
        res = norm(doc(config=cfg(collected_at=ts(900))))
        self.assertEqual(miss_keys(res)[("protocol.config", "ospf")], nz.Missing.STALE_SOURCE)
        self.assertTrue(by_key(res, "routing.neighbor.detail"))                                  # sections age independently
        res = norm(doc(neighbor={"peer": "r2", "state": "Full", "since_s": 1, "observed_at": ts(900), "complete": True}))
        self.assertEqual(miss_keys(res)[("routing.neighbor.detail", "r2")], nz.Missing.STALE_SOURCE)
        res = norm(doc(config=cfg(collected_at="garbage")))
        self.assertEqual(miss_keys(res)[("protocol.config", "ospf")], nz.Missing.PARSE_FAILED)

    def test_PROTOSRC_010_authentication_is_safe_metadata_only(self):
        a = cfg(auth={"configured": True, "key_id": 7, "algorithm": "md5", "fingerprint": FP, "key_string": SECRET, "password": SECRET, "authentication-key": SECRET})
        scrubbed, n = nz.scrub_protocol_secrets(doc(config=a))
        self.assertGreaterEqual(n, 3)
        self.assertNotIn(SECRET, json.dumps(scrubbed))
        res = norm(scrubbed)
        (p,) = by_key(res, "protocol.config")
        self.assertEqual(p["quality"], "OK")
        self.assertEqual(p["value"]["auth"], {"configured": True, "key_id": "7", "algorithm": "md5", "fingerprint": FP})
        self.assertNotIn(SECRET, json.dumps(res, default=str))
        # a fingerprint that is not hash-shaped (i.e. possibly the secret itself) is refused and not echoed
        (p,) = by_key(norm(doc(config=cfg(auth={"configured": True, "key_id": "1", "fingerprint": SECRET}))), "protocol.config")
        self.assertEqual(p["quality"], "UNTRUSTED_PARSE")
        self.assertNotIn(SECRET, json.dumps(p, default=str))
        self.assertIsNone(p["value"]["auth"]["fingerprint"])
        (p,) = by_key(norm(doc(config=cfg(auth={"configured": True, "fingerprint": FP}))), "protocol.config")      # key id missing
        self.assertEqual(p["quality"], "UNTRUSTED_PARSE")
        (p,) = by_key(norm(doc(config=cfg(auth={"configured": False, "fingerprint": FP, "key_id": "9"}))), "protocol.config")
        self.assertEqual((p["quality"], p["value"]["auth"]), ("OK", {"configured": False, "key_id": None, "algorithm": None, "fingerprint": None}))
        # free text in the device error is redacted
        res = norm(doc(neighbor={"peer": "r2", "state": "Down", "since_s": 1, "observed_at": ts(1), "complete": True, "last_error": f"bad password: {SECRET}"}))
        self.assertNotIn(SECRET, json.dumps(res, default=str))

    def test_PROTOSRC_011_state_names_map_to_runbook_established_set(self):
        for raw, want in (("full", "Full"), ("Established", "Established"), ("ExStart", "ExStart"), ("Two_Way", "2-Way"), ("Idle", "Idle"), ("Open Sent", "OpenSent")):
            (n,) = by_key(norm(doc(neighbor={"peer": "r2", "state": raw, "since_s": 1, "observed_at": ts(1), "complete": True})), "routing.neighbor.detail")
            self.assertEqual(n["value"]["state"], want)

    def test_PROTOSRC_012_adapter_requests_target_and_neighbor_ends_only(self):
        w = {"capability.protocol", "protocol.config", "routing.neighbor.detail"}
        (a,) = pa.requests_for_device(TARGET, "r1", w, ("r1", "r2"))
        self.assertEqual((a["interface"], a["peer"], a["include"]), ("Ethernet1", "r2", ["capability", "config", "neighbor"]))
        (b,) = pa.requests_for_device(TARGET, "r2", w, ("r1", "r2"))
        self.assertEqual((b["interface"], b["peer"], b["include"]), ("Ethernet2", "r1", ["capability", "config"]))
        self.assertEqual(pa.requests_for_device(TARGET, "r3", w, ("r1", "r2", "r3")), [])
        self.assertEqual(pa.requests_for_device(TARGET, "r2", w, ("r1",)), [])               # neighbor not in case scope
        self.assertEqual(pa.requests_for_device(TARGET, "r1", {"route.rib"}, ()), [])
        self.assertEqual(pa.requests_for_device(dict(TARGET, protocol="eigrp"), "r1", w, ()), [])
        self.assertEqual(pa.requests_for_device(dict(TARGET, neighbor_interface=None), "r1", w, ()), [])
        self.assertEqual(pa.requests_for_device({}, "r1", w, ()), [])
        self.assertIn("UNSUPPORTED_OPERATION", pa.gap_reason(dict(TARGET, protocol="eigrp"), True, False))
        self.assertIn("NOT_CONFIGURED", pa.gap_reason(TARGET, False, True))
        self.assertIn("SCOPE_MISMATCH", pa.gap_reason(TARGET, True, False))


def target(platform="ceos"):
    return col.Target(device="r1", platform=platform, os_version="4.36.2F")


def collector(**kw):
    return col.ProtocolCollector(now=lambda: T0, capability_probe=lambda plat, src: {"status": "SUPPORTED", "evidence": "test", "transport": "test"}, **kw)


class CollectorTests(SimpleTestCase):
    def test_PROTOSRC_013_collector_reads_once_and_records_provenance(self):
        rd = Reader({"r1": doc()})
        b = collector().collect(target(), [REQ, REQ], rd)
        self.assertEqual(len(rd.calls), 1)
        self.assertEqual((rd.calls[0]["device"], rd.calls[0]["protocol"], rd.calls[0]["peer"]), ("r1", "ospf", "r2"))
        self.assertEqual({o["key"] for o in b["observations"]}, set(nz.PROTO_ENGINE_KEYS))
        self.assertFalse(b["run"]["gateway"]["live"])
        self.assertEqual(b["run"]["privileges"], "read-only")

    def test_PROTOSRC_014_failures_become_key_and_subject_bound_gaps(self):
        for exc, reason in ((col.PermissionDenied(), nz.Missing.PERMISSION_DENIED), (col.TransportError("x"), nz.Missing.TRANSPORT_ERROR), (TimeoutError(), nz.Missing.TRANSPORT_ERROR)):
            b = collector().collect(target(), [REQ], Reader({"r1": exc}))
            self.assertEqual(b["observations"], [])
            self.assertEqual({(r["extra"]["engine_key"], r["extra"]["subject"]): r["reason"] for r in b["missing"]},
                             {("capability.protocol", "ospf"): reason, ("protocol.config", "ospf"): reason, ("routing.neighbor.detail", "r2"): reason})

    def test_PROTOSRC_015_budgets_are_enforced(self):
        b = collector(budget=col.Budget(max_bytes=50)).collect(target(), [REQ], Reader({"r1": doc()}))
        self.assertEqual(b["observations"], [])
        self.assertEqual({r["reason"] for r in b["missing"]}, {nz.Missing.OUTPUT_TOO_LARGE})
        rd = Reader({"r1": doc()})
        b = collector(budget=col.Budget(max_commands=0)).collect(target(), [REQ], rd)
        self.assertEqual((rd.calls, b["observations"]), ([], []))
        self.assertEqual({r["reason"] for r in b["missing"]}, {nz.Missing.BUDGET_EXCEEDED})

    def test_PROTOSRC_016_unadmitted_device_is_never_read(self):
        rd = Reader({"r1": doc()})
        t = col.Target(device="r1", platform="ceos", os_version="4.36.2F", lifecycle_state="WITHDRAWN", withdrawn=True)
        b = collector().collect(t, [REQ], rd)
        self.assertEqual((rd.calls, b["observations"]), ([], []))
        self.assertTrue(b["missing"])

    def test_PROTOSRC_017_secrets_never_reach_raw_evidence_or_observations(self):
        d = doc(config=cfg(auth={"configured": True, "key_id": "1", "fingerprint": FP, "key_string": SECRET, "password": SECRET}), neighbor={
            "peer": "r2", "state": "Down", "since_s": 3, "observed_at": ts(1), "complete": True, "last_error": f"auth failed password={SECRET}"})
        b = collector().collect(target(), [REQ], Reader({"r1": d}))
        self.assertNotIn(SECRET, json.dumps(b, default=str))
        flags = {f for o in b["observations"] for f in o.get("flags", [])}
        self.assertIn("SECRETS_REDACTED", flags)
        self.assertTrue(any(o["key"] == "protocol.config" and o["quality"] == "OK" for o in b["observations"]))

    def test_PROTOSRC_018_restart_has_no_hidden_state(self):
        d1 = doc()
        first = collector().collect(target(), [REQ], Reader({"r1": d1}))
        again = collector().collect(target(), [REQ], Reader({"r1": copy.deepcopy(d1)}))
        self.assertEqual(sorted((o["key"], str(o["value"])) for o in first["observations"]), sorted((o["key"], str(o["value"])) for o in again["observations"]))
        # after the restart the device's adjacency changed: the new run reports the new state, nothing is carried over
        d2 = doc(neighbor={"peer": "r2", "state": "Full", "since_s": 1, "observed_at": ts(1), "complete": True})
        b = collector().collect(target(), [REQ], Reader({"r1": d2}))
        self.assertEqual([o["value"]["state"] for o in b["observations"] if o["key"] == "routing.neighbor.detail"], ["Full"])


class RuntimeMappingTests(SimpleTestCase):
    def test_PROTOSRC_019_map_observations_binds_subjects_and_keeps_quality(self):
        res = norm(doc(config=cfg(timers=None)))
        by = {o["key"]: o for o in rt.map_observations(res["observations"], device="r1", run_key="r", unit_id="u")}
        self.assertEqual(set(by), {"capability.protocol@ospf", "protocol.config@ospf", "routing.neighbor.detail@r2"})
        self.assertEqual(by["protocol.config@ospf"]["quality"], "UNTRUSTED")
        self.assertEqual(by["capability.protocol@ospf"]["quality"], "GOOD")
        self.assertEqual(by["routing.neighbor.detail@r2"]["value"]["state"], "ExStart")


class RuntimeTests(TestCase):
    def _provider(self, source, *, target=TARGET, devices=("r1", "r2"), device="r1"):
        case = repo.open_case(ACTOR, trigger_source="alert:test", idempotency_key="proto-1", service_intent={"target": dict(target)}, flow_scope={},
                              affected_scope={"devices": list(devices)}, target_states={d: "VERIFIED" for d in devices}, severity="HIGH", runbook="RB03", worked_before=True,
                              first_detected_at=T0 - timedelta(minutes=10), last_known_good_at=T0 - timedelta(hours=3), now=T0 - timedelta(minutes=5))
        d = rt.RuntimeDeps(admission=rt.InventoryAdmission(inventory=lambda: {x: {"platform": "ceos", "os_version": "4.36.2F"} for x in devices}),
                           proto_source=(lambda info: source) if source is not None else None, sources=bl.StaticSources({}), clock=lambda: 0.0, sleep=lambda s: None, now=lambda: T0,
                           capability_probe=lambda plat, src: {"status": "SUPPORTED", "evidence": "test", "transport": "test"})
        budget = rt.RuntimeBudget()
        adm = rt.resolve_admission(ACTOR, case, d, budget, T0)
        return rt.CollectorProvider(ACTOR, case, d, adm, budget, device), case

    def _keys(self, bundles, kind):
        return {o["key"] for b in bundles for o in b["observations"] if bool(o.get("is_missing_data")) == (kind == "missing")}

    def _reasons(self, bundles, keys):
        return [o.get("missing_reason", "") for b in bundles for o in b["observations"] if o.get("is_missing_data") and o["key"] in keys]

    WANTED = ["capability.protocol", "protocol.config", "routing.neighbor.detail"]

    def test_PROTOSRC_020_runtime_reads_both_ends_with_distinct_scopes(self):
        r2req = dict(REQ, interface="Ethernet2", peer="r1")
        rd = Reader({"r1": doc(), "r2": doc(device="r2", req=r2req, config=cfg(area="0.0.0.1"))})
        p, case = self._provider(rd)
        b1 = p.collect(case.case_id, "r1", self.WANTED, T0)
        b2 = p.collect(case.case_id, "r2", self.WANTED, T0)
        self.assertEqual([(c["device"], c["interface"], c["peer"]) for c in rd.calls], [("r1", "Ethernet1", "r2"), ("r2", "Ethernet2", "r1")])
        self.assertEqual(self._keys(b1, "value"), {"capability.protocol@ospf", "protocol.config@ospf", "routing.neighbor.detail@r2"})
        self.assertEqual(self._keys(b2, "value"), {"capability.protocol@ospf", "protocol.config@ospf"})
        self.assertFalse(self._keys(b2, "missing") & set(self.WANTED))        # the neighbor end is not asked for neighbor detail and gets no spurious gap

    def test_PROTOSRC_021_no_source_gives_not_configured_gaps(self):
        p, case = self._provider(None)
        b = p.collect(case.case_id, "r1", self.WANTED, T0)
        self.assertFalse([k for k in self._keys(b, "value") if k.split("@")[0] in self.WANTED])
        reasons = self._reasons(b, self.WANTED)
        self.assertTrue(reasons and all(r.startswith("NOT_CONFIGURED") for r in reasons), reasons)

    def test_PROTOSRC_022_unsupported_protocol_stays_unavailable_without_a_read(self):
        rd = Reader({"r1": doc()})
        p, case = self._provider(rd, target=dict(TARGET, protocol="eigrp"))
        b = p.collect(case.case_id, "r1", self.WANTED, T0)
        self.assertEqual(rd.calls, [])
        reasons = self._reasons(b, self.WANTED)
        self.assertTrue(reasons and all(r.startswith("UNSUPPORTED_OPERATION") for r in reasons), reasons)

    def test_PROTOSRC_023_device_outside_the_adjacency_is_not_read(self):
        rd = Reader({"r1": doc(), "r3": doc()})
        p, case = self._provider(rd, devices=("r1", "r2", "r3"), device="r3")
        b = p.collect(case.case_id, "r3", self.WANTED, T0)
        self.assertEqual(rd.calls, [])
        reasons = self._reasons(b, self.WANTED)
        self.assertTrue(reasons and all(r.startswith("SCOPE_MISMATCH") for r in reasons), reasons)

    def test_PROTOSRC_024_reader_failure_reaches_the_engine_as_subject_bound_gaps(self):
        p, case = self._provider(Reader({"r1": col.TransportError("down")}))
        b = p.collect(case.case_id, "r1", self.WANTED, T0)
        self.assertFalse([k for k in self._keys(b, "value") if k.split("@")[0] in self.WANTED])
        self.assertTrue({"capability.protocol@ospf", "protocol.config@ospf", "routing.neighbor.detail@r2"} <= self._keys(b, "missing"))
