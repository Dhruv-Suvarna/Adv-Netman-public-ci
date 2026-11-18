"""Directional QoS evidence source -> HC19.  Stable IDs QOSSRC-001 .. QOSSRC-016.

PROVENANCE: every QoS document below is SIMULATED (hand-written to the ``nmas.troubleshooting.qos-source/1`` contract); topology/RIB fixtures come from the SIMULATED
test_troubleshooting_forwarding_source / scenarios modules.  Nothing is gateway-recorded, so NO live verification is claimed (the injected gateway dict has ``live=false``).
External qualification against real cEOS / IOS-XE / FRR QoS APIs is documented in docs/troubleshooting/qos-source.md and is NOT performed here.
"""

from __future__ import annotations

import copy
from datetime import timedelta

from django.test import SimpleTestCase, TestCase

from core import models as m
from core.services.troubleshooting import baselines as bl
from core.services.troubleshooting import engine as eng
from core.services.troubleshooting import normalization as nz
from core.services.troubleshooting import runtime as rt
from core.services.troubleshooting.adapters import qos as qos_ad
from core.tests import test_troubleshooting_engine as EN
from core.tests import test_troubleshooting_forwarding_source as FS

S = EN.S
T0 = FS.T0
GW = {"live": False, "fixture_id": "simulated-qos", "note": "SIMULATED: not gateway-recorded"}
EV = {"evidence_id": "ev-qos", "source_type": "STATE_SNAPSHOT", "command_or_api": "qos-state read", "collected_at": T0.isoformat()}
SRC = {"id": "sim-qos-agent", "kind": "qos-agent", "read_only": True}
WEB = {"name": "WEB", "order": 10, "match": {"protocol": "tcp", "ports": [443], "src": ["10.1.1.0/24"], "dst": ["10.2.2.0/24"]}, "match_complete": True, "policer_bps": 1_000_000}
DEFAULT = {"name": "class-default", "order": 99, "match": {"any": True}, "match_complete": True}


def counters(*pairs, boot="b1"):
    """pairs = (seconds-before-T0, cumulative dropped)"""
    return {"boot_id": boot, "samples": [{"at": (T0 - timedelta(seconds=s)).isoformat(), "dropped_pkts": d} for s, d in pairs]}


def cls(base, *pairs, **over):
    c = dict(copy.deepcopy(base), **over)
    c["counters"] = counters(*pairs) if pairs else None
    return c


def att(interface="Ethernet2", direction="out", classes=(), **over):
    a = {"interface": interface, "direction": direction, "policy": "EDGE", "complete": True, "classes": list(classes)}
    a.update(over)
    return a


CLEAR = (60, 100), (0, 100)
DROPPING = (60, 100), (0, 400)


def qos_doc(device, attachments, *, platform="ceos", version="4.36.2F", vrf="default", source=None, capability=None, provenance=None, complete=True, **over):
    doc = {"schema": nz.QOS_SCHEMA, "device": device, "platform": platform, "os_version": version, "source_identity": dict(SRC, **(source or {})),
           "capability": capability if capability is not None else {"status": "SUPPORTED", "api": "simulated qos read"}, "scope": {"vrf": vrf}, "complete": complete,
           "attachments": list(attachments), "provenance": provenance if provenance is not None else {"label": "SIMULATED", "collected_at": T0.isoformat()}}
    doc.update(over)
    return doc


def good_r1(*, classes=None, **kw):
    return att(classes=classes if classes is not None else [cls(WEB, *CLEAR), cls(DEFAULT, *CLEAR)], **kw)


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


def run(key, docs=None, *, qos=True, reader=None):
    reader = reader if reader is not None else Reader(docs or {})
    case = FS.make_case(key)
    transports = {d: FS.Transport(t) for d, t in FS.v4_lab().items()}
    d = rt.RuntimeDeps(
        admission=rt.InventoryAdmission(inventory=lambda: {dev: {"platform": FS.PLATFORM[dev], "os_version": "8.4.4" if FS.PLATFORM[dev] == "linux" else "4.36.2F"} for dev in FS.S.DEVICES}),
        cli_transport=lambda info: transports[info.device], qos_source=(lambda info: reader) if qos else None,
        sources=bl.StaticSources({**FS.S.static_data(), "intent": FS.intent()}), forwarding_context=FS.fctx(), clock=lambda: 0.0, sleep=lambda s: None, now=lambda: T0,
        capability_probe=lambda plat, src: {"status": "SUPPORTED", "evidence": "test", "transport": "test"})
    res = rt.run_case(FS.ACTOR, case.case_id, d, run_key="r1", now=T0, engine_config=eng.EngineConfig(exhaustive=True))
    return case, res, reader


def hc19(case):
    t = m.TsDiagnosticTest.objects.filter(case=case, test_id="HC19").order_by("-seq", "-attempt").first()
    return t.verdict, f"{t.observed_summary} | {t.reason}"


def norm(doc, *, platform="ceos", version="4.36.2F", vrf="default"):
    return nz.normalize_qos_state(doc, platform=platform, os_version=version, device="r1", evidence=EV, request={"vrf": vrf, "directions": ["in", "out"], "flow": {}}, now=T0)


class UnitTests(SimpleTestCase):
    def test_QOSSRC_001_valid_document_normalizes_and_discards_matches_flow(self):
        poisoned = cls(WEB, *DROPPING, matches_flow=True, drop_rate_pps=900)
        res = norm(qos_doc("r1", [att(classes=[poisoned, cls(DEFAULT, *CLEAR)])]))
        (o,) = res["observations"]
        v = o["value"]
        self.assertEqual((o["key"], o["quality"], v["interface"], v["direction"], v["complete"]), ("qos.attachment", "OK", "Ethernet2", "out", True))
        web = v["classes"][0]
        self.assertNotIn("matches_flow", web)
        self.assertNotIn("drop_rate_pps", web)
        self.assertEqual((web["counters"]["status"], web["counters"]["delta_dropped"]), ("OK", 300))
        self.assertEqual((v["source"]["id"], v["provenance"]["label"]), ("sim-qos-agent", "SIMULATED"))

    def test_QOSSRC_002_identity_platform_capability_scope_provenance_gates(self):
        cases = [({"source": {"read_only": False}}, nz.Missing.UNSUPPORTED_OPERATION), ({"source": {"kind": "rib"}}, nz.Missing.UNSUPPORTED_OPERATION),
                 ({"source": {"id": ""}}, nz.Missing.UNSUPPORTED_OPERATION), ({"platform": "iosxe"}, nz.Missing.UNSUPPORTED_PLATFORM),
                 ({"version": "4.30.0F"}, nz.Missing.UNSUPPORTED_PLATFORM), ({"capability": {"status": "UNSUPPORTED", "api": "x"}}, nz.Missing.UNSUPPORTED_OPERATION),
                 ({"capability": {}}, nz.Missing.UNSUPPORTED_OPERATION), ({"vrf": "mgmt"}, nz.Missing.SCOPE_MISMATCH), ({"provenance": {}}, nz.Missing.PARSE_FAILED),
                 ({"provenance": {"label": "TRUSTME", "collected_at": T0.isoformat()}}, nz.Missing.PARSE_FAILED), ({"attachments": "x"}, nz.Missing.PARSE_FAILED)]
        for patch, reason in cases:
            doc = qos_doc("r1", [good_r1()], **{k: v for k, v in patch.items() if k not in ("version", "attachments")})
            if "version" in patch:
                doc["os_version"] = patch["version"]
            if "attachments" in patch:
                doc["attachments"] = patch["attachments"]
            res = norm(doc)
            self.assertEqual((res["observations"], res["missing"][0]["reason"]), ([], reason), patch)
            self.assertEqual(res["missing"][0]["extra"]["engine_key"], "qos.state")
        self.assertEqual(norm("not json")["missing"][0]["reason"], nz.Missing.PARSE_FAILED)
        self.assertEqual(norm(qos_doc("r9", [good_r1()]))["missing"][0]["reason"], nz.Missing.UNSUPPORTED_PLATFORM)

    def test_QOSSRC_003_counter_status_reset_short_stale_missing(self):
        def status(*pairs, boot_change=False, **kw):
            c = cls(WEB, *pairs)
            if boot_change:
                c["counters"]["samples"][-1]["boot_id"] = "b2"
            (o,) = norm(qos_doc("r1", [att(classes=[c])]))["observations"]
            return o["value"]["classes"][0]["counters"]["status"]
        self.assertEqual(status(*CLEAR), "OK")
        self.assertEqual(status((60, 500), (0, 5)), "RESET")
        self.assertEqual(status(*CLEAR, boot_change=True), "RESET")
        self.assertEqual(status((0, 100)), "SHORT")
        self.assertEqual(status((4, 100), (0, 400)), "SHORT")
        self.assertEqual(status((400, 100), (300, 400)), "STALE")
        self.assertEqual(status((0, 5), (60, 9)), "MISSING")                       # not time-ordered
        (o,) = norm(qos_doc("r1", [att(classes=[cls(WEB)])]))["observations"]        # counters absent
        self.assertEqual(o["value"]["classes"][0]["counters"]["status"], "MISSING")

    def test_QOSSRC_018_counter_epoch_must_be_known_and_well_typed(self):
        for boot in (None, "", " ", [], {}, 1, True):
            with self.subTest(boot=boot):
                c = cls(WEB, *DROPPING)
                c["counters"]["boot_id"] = boot
                (o,) = norm(qos_doc("r1", [att(classes=[c])]))["observations"]
                result = o["value"]["classes"][0]["counters"]
                self.assertEqual(result["status"], "MISSING")
                self.assertNotIn("delta_dropped", result)

    def test_QOSSRC_004_incomplete_or_unparsable_attachments_are_not_complete(self):
        (o,) = norm(qos_doc("r1", [good_r1(complete=False)]))["observations"]
        self.assertEqual((o["value"]["complete"], o["quality"]), (False, "PARTIAL"))
        (o,) = norm(qos_doc("r1", [good_r1()], complete=False))["observations"]
        self.assertFalse(o["value"]["complete"])
        bad = cls(WEB, *CLEAR, match={"ports": ["x"]})
        (o,) = norm(qos_doc("r1", [att(classes=[bad])]))["observations"]
        self.assertFalse(o["value"]["complete"])
        self.assertIsNone(o["value"]["classes"][0]["match"])
        res = norm(qos_doc("r1", [att(direction="sideways")]))
        self.assertEqual((res["observations"], res["missing"][0]["reason"]), ([], nz.Missing.EMPTY))

    def test_QOSSRC_005_classification_is_proven_from_the_tuple(self):
        flow = S.FLOW
        self.assertEqual(qos_ad.classify(WEB | {"match_complete": True}, flow)[0], True)
        self.assertEqual(qos_ad.classify(dict(WEB, match={"protocol": "udp"}), flow)[0], False)
        self.assertEqual(qos_ad.classify(dict(WEB, match={"ports": [80]}), flow)[0], False)
        self.assertEqual(qos_ad.classify(dict(WEB, match={"src": ["192.0.2.0/24"]}), flow)[0], False)
        self.assertIsNone(qos_ad.classify(dict(WEB, match={"dscp": [26]}), flow)[0])                   # flow does not state its DSCP
        self.assertEqual(qos_ad.classify(dict(WEB, match={"dscp": [26]}), dict(flow, dscp=26))[0], True)
        self.assertIsNone(qos_ad.classify(dict(WEB, match_complete=False), flow)[0])
        self.assertIsNone(qos_ad.classify(dict(WEB, unsupported="match access-group"), flow)[0])
        self.assertIsNone(qos_ad.classify(dict(WEB, match=None), flow)[0])
        self.assertEqual(qos_ad.classify(DEFAULT, flow)[0], True)
        self.assertIsNone(qos_ad.classify({"name": "x", "match_complete": True, "match": {"dst": ["10.2.2.0/24"]}}, dict(flow, dst_ip=None))[0])


def eng_obs(value, sub="Eth2-out", loss=None):
    ov = {("r1", "qos.state", "Eth2"): None, ("r1", "qos.state", "Eth2-out"): None, ("r1", "qos.state", sub): value}   # drop the healthy fixture's own record, then set ours
    if loss is not None:
        ov[("h1", "flow.health", "web")] = {"loss_pct": 5.0, "coverage_pct": 92, "baseline_loss_pct": 0.1, "samples": loss}
    return S.apply(S.healthy_obs(), ov)


def norm_value(attachment, **kw):
    (o,) = norm(qos_doc("r1", [attachment], **kw))["observations"]
    return o["value"]


def verdict(obs):
    _, st = EN.run_case("RB02", obs, cfg=eng.EngineConfig(exhaustive=True))
    r = EN.by_id(st)["HC19"]
    return r["verdict"], r["reason"], st


LOSS_ALIGNED = [{"at": (T0 - timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ"), "loss_pct": 5.0}, {"at": T0.strftime("%Y-%m-%dT%H:%M:%SZ"), "loss_pct": 6.0}]
LOSS_LATE = [{"at": (T0 + timedelta(seconds=900)).strftime("%Y-%m-%dT%H:%M:%SZ"), "loss_pct": 6.0}]


class Hc19EngineTests(TestCase):
    """HC19 on normalized values replayed through the deterministic engine (path r1 Eth1 -> Eth2)."""

    def test_QOSSRC_006_healthy_proven_class_no_drop_delta_passes(self):
        v, reason, st = verdict(eng_obs(norm_value(good_r1())))
        self.assertEqual(v, "PASS", reason)
        self.assertEqual(st["diagnosis"]["outcome"], "EXPECTED_BEHAVIOR_CONFIRMED", st["diagnosis"])

    def test_QOSSRC_017_shared_healthy_fixture_record_is_schema_conformant_and_passes(self):
        """scenarios.healthy_obs carries a hand-built normalized record; it must equal what normalize_qos_state yields for the equivalent SIMULATED document."""
        fx = S.healthy_obs()[("r1", "qos.state", "Eth2-out")]
        self.assertNotIn(("r1", "qos.state", "Eth2"), S.healthy_obs())
        built = norm_value(good_r1(classes=[cls(dict(WEB, name="AF31", policer_bps=1_000_000_000), *CLEAR), cls(DEFAULT, *CLEAR)], interface="Ethernet2"))
        self.assertEqual(fx["classes"][0]["counters"]["status"], "OK")
        for k in ("interface", "direction", "policy", "vrf", "complete", "uncertain", "classes", "source", "platform", "os_version", "provenance"):
            self.assertEqual(fx[k], built[k], k)
        v, reason, _ = verdict(S.healthy_obs())
        self.assertEqual(v, "PASS", reason)

    def test_QOSSRC_007_causal_fault_needs_proven_class_direction_delta_and_aligned_loss(self):
        v, reason, st = verdict(eng_obs(norm_value(att(classes=[cls(WEB, *DROPPING), cls(DEFAULT, *CLEAR)])), loss=LOSS_ALIGNED))
        self.assertEqual(v, "FAIL", reason)
        self.assertIn("F-qos-drop", repr(st["diagnosis"]) + repr(st["dossier"]))
        self.assertEqual(st["diagnosis"]["outcome"] != "EXPECTED_BEHAVIOR_CONFIRMED", True)

    def test_QOSSRC_008_drops_without_time_aligned_production_loss_are_inconclusive(self):
        dropping = norm_value(att(classes=[cls(WEB, *DROPPING), cls(DEFAULT, *CLEAR)]))
        for loss in (None, [], LOSS_LATE):
            v, reason, _ = verdict(eng_obs(dropping, loss=loss))
            self.assertEqual(v, "INCONCLUSIVE", (loss, reason))
        v, _, _ = verdict(eng_obs(dropping, loss=[]))                  # unavailable measurement (flow.health with no samples)

    def test_QOSSRC_009_drops_in_a_class_that_does_not_match_the_flow_are_not_blamed(self):
        other = dict(WEB, name="VOICE", match={"protocol": "udp", "ports": [5060]})
        value = norm_value(att(classes=[cls(other, *DROPPING), cls(WEB, *CLEAR), cls(DEFAULT, *CLEAR)]))
        v, reason, _ = verdict(eng_obs(value, loss=LOSS_ALIGNED))
        self.assertEqual(v, "PASS", reason)
        # a forged matches_flow claim on the wrong class changes nothing
        forged = cls(other, *DROPPING, matches_flow=True)
        v, reason, _ = verdict(eng_obs(norm_value(att(classes=[forged, cls(WEB, *CLEAR)])), loss=LOSS_ALIGNED))
        self.assertEqual(v, "PASS", reason)

    def test_QOSSRC_010_wrong_direction_or_untraversed_interface_is_never_a_fault_or_pass(self):
        for att_kw in (dict(direction="in"), dict(interface="Ethernet3")):       # flow leaves r1 via Eth2 (egress) and enters via Eth1
            sub = f"{att_kw.get('interface', 'Ethernet2')}-{att_kw.get('direction', 'out')}"
            v, reason, _ = verdict(eng_obs(norm_value(att(classes=[cls(WEB, *DROPPING)], **att_kw)), sub=sub, loss=LOSS_ALIGNED))
            self.assertEqual(v, "INCONCLUSIVE", (att_kw, reason))
            self.assertNotIn("dropped", reason.split("(")[0])

    def test_QOSSRC_011_reset_short_stale_missing_incomplete_and_unclassifiable_stay_inconclusive(self):
        cases = {"reset": att(classes=[cls(WEB, (60, 500), (0, 5)), cls(DEFAULT, *CLEAR)]), "short": att(classes=[cls(WEB, (2, 100), (0, 400))]),
                 "stale": att(classes=[cls(WEB, (500, 100), (400, 400))]), "missing": att(classes=[cls(WEB)]),
                 "incomplete": good_r1(complete=False), "unsupported": att(classes=[dict(cls(WEB, *DROPPING), unsupported="access-list"), cls(WEB, *CLEAR)]),
                 "unclassified": att(classes=[cls(dict(WEB, match={"protocol": "udp"}), *CLEAR)]), "dscp": att(classes=[cls(dict(WEB, match={"dscp": [26]}), *DROPPING)])}
        for name, a in cases.items():
            v, reason, _ = verdict(eng_obs(norm_value(a), loss=LOSS_ALIGNED))
            self.assertEqual(v, "INCONCLUSIVE", (name, reason))

    def test_QOSSRC_012_legacy_matches_flow_record_is_never_healthy(self):
        legacy = {"classes": [{"name": "AF31", "matches_flow": True, "drop_rate_pps": 0, "dropped_pkts": 0, "policer_bps": 1_000_000_000}]}
        v, reason, _ = verdict(S.apply(S.healthy_obs(), {("r1", "qos.state", "Eth2-out"): None, ("r1", "qos.state", "Eth2"): legacy}))   # legacy record (subject Eth2, no direction)
        self.assertEqual(v, "INCONCLUSIVE", reason)
        v, reason, _ = verdict(eng_obs(legacy | {"direction": "out", "complete": True}, sub="Eth2-out", loss=LOSS_ALIGNED))
        self.assertEqual(v, "INCONCLUSIVE", reason)
        legacy_bad = {"classes": [{"name": "AF31", "matches_flow": True, "drop_rate_pps": 50, "dropped_pkts": 900, "drop_samples": []}]}
        v, reason, _ = verdict(eng_obs(legacy_bad, loss=LOSS_ALIGNED))
        self.assertNotEqual(v, "FAIL", reason)


class RuntimeTests(TestCase):
    def docs(self, **r1):
        return {d: qos_doc(d, [att(classes=[cls(DEFAULT, *CLEAR)])]) for d in ("r2", "r3", "sw1")} | {"r1": r1.get("doc") or qos_doc("r1", [good_r1()])}

    def test_QOSSRC_013_without_an_injected_source_qos_is_an_explicit_gap_and_hc19_inconclusive(self):
        case, _, _ = run("qos-none", qos=False)
        self.assertFalse(m.TsObservation.objects.filter(case=case, key__startswith="qos.state@").exists())       # no value is ever invented
        self.assertEqual(hc19(case)[0], "INCONCLUSIVE")

    def test_QOSSRC_014_runtime_healthy_source_produces_qos_state_and_pass(self):
        case, _, reader = run("qos-ok", self.docs())
        o = m.TsObservation.objects.get(case=case, target="r1", key="qos.state@Ethernet2-out")
        self.assertEqual(o.value["classes"][0]["counters"]["status"], "OK")
        self.assertTrue(reader.calls and all(c["directions"] == ["in", "out"] for c in reader.calls))
        v, text = hc19(case)
        self.assertEqual(v, "PASS", text)

    def test_QOSSRC_015_runtime_negative_sources_stay_inconclusive_with_precise_gaps(self):
        wrong_dir = {d: qos_doc(d, [att(interface="Ethernet9", classes=[cls(DEFAULT, *CLEAR)])]) for d in ("r2", "r3", "sw1")}
        wrong_dir["r1"] = qos_doc("r1", [att(direction="in", classes=[cls(WEB, *DROPPING)])])
        reset = self.docs(doc=qos_doc("r1", [att(classes=[cls(WEB, (60, 500), (0, 5))])]))
        wrong_vrf = self.docs(doc=qos_doc("r1", [good_r1()], vrf="mgmt"))
        unsupported = self.docs(doc=qos_doc("r1", [good_r1()], capability={"status": "UNSUPPORTED", "api": "x"}))
        failing = self.docs(doc=TimeoutError("source timeout"))
        for i, (name, docs) in enumerate({"wrong_dir": wrong_dir, "reset": reset, "wrong_vrf": wrong_vrf, "unsupported": unsupported, "failing": failing}.items()):
            case, _, _ = run(f"qos-neg-{i}", docs)
            v, text = hc19(case)
            self.assertEqual(v, "INCONCLUSIVE", (name, text))

    def test_QOSSRC_016_runtime_never_issues_a_command_and_bounds_reads(self):
        case, _, reader = run("qos-bound", self.docs())
        self.assertLessEqual(len(reader.calls), len(FS.S.DEVICES))
        self.assertEqual(len({c["device"] for c in reader.calls}), len(reader.calls))          # one read per device per run
        self.assertTrue(all(set(c) == {"vrf", "directions", "flow", "device", "platform", "os_version"} for c in reader.calls))
