"""STP source (RB04) -- parser -> collector -> runtime -> RB04.  Stable IDs STPSRC-001 .. STPSRC-012 (supports UT-049 / IT-07).

PROVENANCE: every document below is SIMULATED (hand-written to the EOS ``show spanning-tree | json`` schema).  No gateway-recorded cEOS STP output
is pinned yet, so nothing here claims live verification; the injected gateway dict only proves provenance is carried verbatim.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase, TestCase

from core import models as m
from core.services.troubleshooting import baselines as bl
from core.services.troubleshooting import collectors as col
from core.services.troubleshooting import normalization as nz
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting import runtime as rt
from core.services.troubleshooting import engine as eng
from core.services.troubleshooting.adapters import stp as stp_ad
from core.tests.fixtures.troubleshooting_runbooks import scenarios as S

T0 = datetime(2026, 11, 9, 12, 0, 0, tzinfo=timezone.utc)
ACTOR = repo.Actor("alice", "user", tenant="acme")
ROOT = {"priority": 32778, "macAddress": "00:1c:73:aa:aa:aa"}
SW_MAC = {"sw1": "00:1c:73:aa:aa:aa", "sw2": "00:1c:73:bb:bb:bb", "sw3": "00:1c:73:cc:cc:cc"}
CMD = "show spanning-tree | json"
GW = {"live": False, "fixture_id": "simulated-stp", "note": "SIMULATED: not gateway-recorded"}
EV = {"evidence_id": "ev-1", "source_type": "CLI", "transport": "t", "adapter": "a", "command_or_api": CMD, "collected_at": T0.isoformat(), "raw_ref": {"hash": "h"}}


def port(state="forwarding", role="designated", **kw):
    return {"state": state, "role": role, "portType": "p2p", "bpduSent": 10, "bpduReceived": 10, **kw}


def doc(sw, *, ports=None, topology_changes=3, since_tc=7200.0, root=ROOT, instance="VL10", protocol="rapidPvst", extra=None):
    ports = ports if ports is not None else {"Ethernet1": port(), "Ethernet2": port()}
    body = {"protocol": protocol, "bridge": {"priority": 32778, "macAddress": SW_MAC[sw]}, "rootBridge": root, "interfaces": ports,
            "topologyChanges": topology_changes, "timeSinceLastTopologyChange": since_tc, **(extra or {})}
    return json.dumps({"spanningTreeInstances": {instance: body}})


def healthy(sw):
    ports = {"Ethernet1": port(), "Ethernet2": port()}
    if sw == "sw3":
        ports["Ethernet2"] = port("discarding", "alternate")
    return doc(sw, ports=ports)


def looped(sw):          # no port blocks anywhere and a TCN storm on sw2
    return doc(sw, topology_changes=60 if sw == "sw2" else 3, since_tc=5.0 if sw == "sw2" else 7200.0, extra={"lastTopologyChangeInterface": "Ethernet1"} if sw == "sw2" else None)


class UnitParserTests(SimpleTestCase):
    def norm(self, raw, version="4.36.2F", **kw):
        return nz.normalize_stp(raw, platform="ceos", os_version=version, device="sw1", evidence=EV, now=T0, observed_at=T0, **kw)

    def test_STPSRC_001_root_port_roles_and_bridge_ids(self):
        res = self.norm(doc("sw2", ports={"Ethernet1": port(role="root"), "Ethernet2": port("discarding", "alternate")}, extra={"rootPort": "Ethernet1"}))
        (o,) = [x for x in res["observations"] if x["key"] == "stp.state"]
        v = o["value"]
        self.assertEqual(o["target"]["vlan"], "10")
        self.assertEqual((v["root_id"], v["bridge_id"], v["is_root"]), ("32778/00:1c:73:aa:aa:aa", "32778/00:1c:73:bb:bb:bb", False))
        self.assertEqual({p["name"]: (p["role"], p["state"]) for p in v["ports"]}, {"Ethernet1": ("root", "forwarding"), "Ethernet2": ("alternate", "discarding")})
        self.assertEqual(res["parser"]["id"], "stp.state")
        self.assertEqual(res["parser"]["version"], "eos-json-1.0")

    def test_STPSRC_002_tcn_without_history_is_never_reported_as_zero_when_recent(self):
        v = self.norm(doc("sw1", topology_changes=9, since_tc=30.0))["observations"][0]
        self.assertEqual((v["value"]["tcn_count_1h"], v["value"]["tcn_basis"]), (1, "lower-bound"))
        self.assertEqual(v["quality"], "PARTIAL")
        self.assertIn("STP_TCN_LOWER_BOUND", v["flags"])
        self.assertIn("root_change_history_unknown", v["value"]["uncertain"])
        old = self.norm(doc("sw1", topology_changes=9, since_tc=9000.0))["observations"][0]
        self.assertEqual((old["value"]["tcn_count_1h"], old["value"]["tcn_basis"]), (0, "age-of-last-tc"))

    def test_STPSRC_003_history_gives_windowed_tcn_and_root_change(self):
        h = nz.StpHistory()
        self.norm(doc("sw1", topology_changes=10), history=h)
        later = nz.normalize_stp(doc("sw1", topology_changes=70, root={"priority": 4106, "macAddress": "00:1c:73:dd:dd:dd"}), platform="ceos", os_version="4.36.2F", device="sw1",
                                 evidence=EV, now=T0 + timedelta(minutes=10), observed_at=T0 + timedelta(minutes=10), history=h)
        v = later["observations"][0]["value"]
        self.assertEqual((v["tcn_count_1h"], v["root_changes_24h"], v["tcn_basis"]), (60, 1, "counter-delta"))
        self.assertNotIn("root_change_history_unknown", v["uncertain"])
        reset = nz.normalize_stp(doc("sw1", topology_changes=2), platform="ceos", os_version="4.36.2F", device="sw1", evidence=EV, now=T0 + timedelta(minutes=20),
                                 observed_at=T0 + timedelta(minutes=20), history=h)["observations"][0]
        self.assertIn("tcn_counter_reset", reset["value"]["uncertain"])

    def test_STPSRC_004_loop_indicators_and_port_protection(self):
        res = self.norm(doc("sw1", ports={"Ethernet1": port(loopInconsistent=True, bpduFilter=True, bpduGuard=False, loopGuard=True), "Ethernet2": port(portType="edge", bpduReceived=4, bpduGuard=False)}))
        st = next(o for o in res["observations"] if o["key"] == "stp.state")
        self.assertEqual(st["value"]["loop_indicators"], ["Ethernet1:loopInconsistent"])
        prot = {o["target"]["interface"]: o["value"] for o in res["observations"] if o["key"] == "stp.port_protection"}
        self.assertTrue(prot["Ethernet1"]["bpdu_filter"])
        self.assertEqual((prot["Ethernet2"]["link_type"], prot["Ethernet2"]["bpdu_rx_on_edge"]), ("edge", 4))

    def test_STPSRC_005_malformed_and_partial_documents_keep_uncertainty(self):
        for raw in ("{not json", json.dumps({"other": 1}), json.dumps({"spanningTreeInstances": {"VL10": {"bridge": {}}}})):
            res = self.norm(raw)
            self.assertEqual(res["observations"], [])
            self.assertEqual(res["missing"][0]["reason"], "PARSE_FAILED", raw)
        res = self.norm(doc("sw1", ports={"Ethernet1": port(), "Ethernet2": {"state": "weird", "role": "designated"}}))
        o = res["observations"][0]
        self.assertEqual((o["quality"], len(o["value"]["ports"])), ("PARTIAL", 1))
        self.assertIn("PARTIAL_PARSE", o["flags"])
        self.assertTrue(any(n.startswith("partial_parse:") for n in o["value"]["uncertain"]))

    def test_STPSRC_006_version_gate_fails_closed(self):
        for version, code in (("4.20.1F", "VERSION_UNSUPPORTED"), ("5.1.0F", "VERSION_UNSUPPORTED"), ("", "VERSION_UNKNOWN")):
            res = self.norm(doc("sw1"), version=version)
            self.assertEqual(res["observations"], [])
            self.assertEqual((res["missing"][0]["reason"], res["missing"][0]["extra"]["selection_error"]), ("PARSER_UNAVAILABLE", code))
        res = nz.normalize_stp(doc("sw1"), platform="iosxe", os_version="17.06.01a", device="sw1", evidence=EV, now=T0)
        self.assertEqual(res["missing"][0]["extra"]["selection_error"], "WRONG_PLATFORM")
        self.assertTrue(stp_ad.is_supported("ceos", "4.36.2F"))
        self.assertFalse(stp_ad.is_supported("iosxe", "17.06.01a"))

    def test_STPSRC_007_no_instances_is_empty_not_healthy(self):
        res = self.norm(json.dumps({"spanningTreeInstances": {}}))
        self.assertEqual((res["observations"], res["missing"][0]["reason"]), ([], "EMPTY"))
        self.assertIn("NOT evidence of a healthy", res["missing"][0]["detail"])

    def test_STPSRC_008_single_instance_modes_alias_requested_vlans_only(self):
        res = self.norm(doc("sw1", instance="MST0", protocol="mstp"), vlans=["10", "20"])
        subs = sorted(o["target"]["vlan"] for o in res["observations"] if o["key"] == "stp.state")
        self.assertEqual(subs, ["10", "20", "mst0"])
        self.assertTrue(all("STP_INSTANCE_ALIAS" in o["flags"] for o in res["observations"] if o["target"]["vlan"] in ("10", "20")))
        self.assertEqual([o["target"]["vlan"] for o in self.norm(doc("sw1"), vlans=["20"])["observations"]], ["10"])   # per-VLAN modes never alias

    def test_STPSRC_018_mst_alias_needs_single_common_instance(self):
        res = self.norm(doc("sw1", instance="MST1", protocol="mstp"), vlans=["10"])
        self.assertEqual([o["target"]["vlan"] for o in res["observations"]], ["mst1"])
        data = json.loads(doc("sw1", instance="MST0", protocol="mstp"))
        data["spanningTreeInstances"]["MST1"] = data["spanningTreeInstances"]["MST0"]
        res = self.norm(json.dumps(data), vlans=["10"])
        self.assertEqual(sorted(o["target"]["vlan"] for o in res["observations"]), ["mst0", "mst1"])

    def test_STPSRC_009_catalogue_is_read_only_and_labels_source_honestly(self):
        spec = col.COMMAND_CATALOG["ceos"]["spanning_tree"]
        col.validate_read_only("ceos", spec.command)
        self.assertEqual(spec.parser_id, "stp.state")
        self.assertIsNone(col.COMMAND_CATALOG["iosxe"]["spanning_tree"].parser_id)     # no IOS XE STP parser: evidence-only, honestly
        self.assertEqual(stp_ad.describe_source()["label"], "SIMULATED")
        self.assertEqual(stp_ad.describe_source(recorded=True)["label"], "RECORDED")
        self.assertFalse(stp_ad.describe_source(gateway={"live": False})["live"])
        self.assertEqual(stp_ad.describe_source(gateway={"live": True})["label"], "LIVE_GATEWAY_PINNED")


class Transport:
    def __init__(self, text, provenance=None):
        self.text = text
        if provenance:
            self.provenance = lambda: provenance

    def execute(self, rendered):
        return self.text if rendered == CMD else "{}"


def verdicts(case):
    return {t.test_id: t.verdict for t in m.TsDiagnosticTest.objects.filter(case=case)}


def make_case(key, runbook="RB04"):
    devs = ["sw1", "sw2", "sw3"]
    target = {"device": "sw1", "devices": devs, "vlan": 10, "links": [], "cables": [], "lag": None}
    return repo.open_case(ACTOR, trigger_source="alert:test", idempotency_key=key, service_intent={"service": "l2", "target": target},
                          flow_scope={"name": "l2", "src": "sw1", "dst": "sw3", "protocol": "tcp", "port": 443}, affected_scope={"devices": devs},
                          target_states={d: "VERIFIED" for d in devs}, severity="HIGH", runbook=runbook, worked_before=True,
                          first_detected_at=T0 - timedelta(minutes=10), last_known_good_at=T0 - timedelta(hours=3), now=T0 - timedelta(minutes=5))


def intent(mode="rapid-pvst"):
    i = S.stp_intent({d: mode for d in ("sw1", "sw2", "sw3")})
    i["l2"]["stp_root"] = {"10": "32778/00:1c:73:aa:aa:aa"}
    for l in i["links"]:
        l["a_if"], l["b_if"] = l["a_if"].replace("Eth", "Ethernet"), l["b_if"].replace("Eth", "Ethernet")
    return i


def deps(outputs, *, version="4.36.2F", mode="rapid-pvst", context=None, gw=GW, at=T0):
    return rt.RuntimeDeps(
        admission=rt.InventoryAdmission(inventory=lambda: {d: {"platform": "ceos", "os_version": version} for d in ("sw1", "sw2", "sw3")}),
        cli_transport=lambda info: Transport(outputs[info.device], gw), sources=bl.StaticSources({**S.static_data(), "intent": intent(mode)}),
        clock=lambda: 0.0, sleep=lambda s: None, now=lambda: at, stp_context=context,
        capability_probe=lambda plat, src: {"status": "SUPPORTED", "evidence": "test", "transport": "test"})


def run(key, outputs, **kw):
    case = make_case(key)
    res = rt.run_case(ACTOR, case.case_id, deps(outputs, **kw), run_key="r1", now=kw.get("at", T0), engine_config=eng.EngineConfig(exhaustive=True))
    return case, res



def seeded_context():
    ctx = stp_ad.StpContext()
    for dev in ("sw1", "sw2", "sw3"):
        ctx.history.record(dev, "10", {"tcn_total": 3, "root_id": "32778/00:1c:73:aa:aa:aa",
                                     "at": T0 - timedelta(minutes=10), "root_changes": [],
                                     "coverage_start": T0 - timedelta(days=2)})
    return ctx

class RuntimeToRb04Tests(TestCase):
    def test_STPSRC_010_fault_parser_to_runtime_to_rb04_with_provenance(self):
        ctx = seeded_context()
        ctx.history.record("sw2", "10", {"tcn_total": 10, "root_id": "32778/00:1c:73:aa:aa:aa", "at": T0 - timedelta(minutes=10), "root_changes": [], "coverage_start": T0 - timedelta(days=2)})
        case, res = run("stp10", {d: looped(d) for d in ("sw1", "sw2", "sw3")}, context=ctx)
        v = verdicts(case)
        self.assertEqual((v["ST03"], v["ST04"]), ("FAIL", "FAIL"), v)
        row = m.TsObservation.objects.get(case=case, target="sw2", key="stp.state@10", is_missing_data=False)
        self.assertEqual(row.value["tcn_count_1h"], 50)
        self.assertEqual(row.value["last_tc_port"], "Ethernet1")
        ev = m.TsEvidenceRef.objects.get(case=case, device="sw2", command_or_api=CMD)
        self.assertEqual((ev.parser, ev.parser_version), ("stp.state", "eos-json-1.0"))
        self.assertEqual(ev.scope["gateway"], GW)
        self.assertFalse(ev.scope["live"])
        self.assertRegex(ev.scope["raw_hash_as_received"], r"^(sha256:)?[0-9a-f]{64}$")
        self.assertIn("F-loop", json.dumps(res["diagnosis"]))

    def test_STPSRC_011_healthy_then_recovery(self):
        ctx = seeded_context()
        ctx.history.record("sw2", "10", {"tcn_total": 3, "root_id": "32778/00:1c:73:aa:aa:aa", "at": T0 - timedelta(minutes=10), "root_changes": [], "coverage_start": T0 - timedelta(days=2)})
        case, _ = run("stp11", {d: healthy(d) for d in ("sw1", "sw2", "sw3")}, context=ctx)
        v = verdicts(case)
        self.assertEqual((v["ST02"], v["ST03"], v["ST04"]), ("PASS", "PASS", "PASS"), v)
        row = m.TsObservation.objects.get(case=case, target="sw3", key="stp.state@10")
        self.assertEqual(row.value["root_id"], "32778/00:1c:73:aa:aa:aa")
        # "recovery": the same history after the fault -> counter delta 0 within the window
        self.assertEqual(m.TsObservation.objects.get(case=case, target="sw2", key="stp.state@10").value["tcn_count_1h"], 0)

    def test_STPSRC_012_malformed_unsupported_and_stp_free_are_gaps_not_verdicts(self):
        case, _ = run("stp12a", {d: "{not json" for d in ("sw1", "sw2", "sw3")})
        gaps = m.TsObservation.objects.filter(case=case, target="sw1", is_missing_data=True, key="stp.state")
        self.assertTrue(gaps.filter(missing_reason__startswith="PARSE_FAILED").exists())
        self.assertFalse(m.TsObservation.objects.filter(case=case, key__startswith="stp.state", is_missing_data=False).exists())
        self.assertNotIn("PASS", {verdicts(case).get(t) for t in ("ST02", "ST03", "ST04")})
        case, _ = run("stp12b", {d: healthy(d) for d in ("sw1", "sw2", "sw3")}, version="4.20.1F")
        self.assertTrue(m.TsObservation.objects.filter(case=case, target="sw1", is_missing_data=True, missing_reason__startswith="PARSER_UNAVAILABLE").exists())
        self.assertNotIn("PASS", {verdicts(case).get(t) for t in ("ST02", "ST03", "ST04")})
        case, _ = run("stp12c", {d: json.dumps({"spanningTreeInstances": {}}) for d in ("sw1", "sw2", "sw3")}, mode="evpn-vxlan")
        v = verdicts(case)
        self.assertEqual({v.get(t) for t in ("ST02", "ST03", "ST04", "ST05", "ST06")} - {None}, {"SKIPPED"}, v)
        self.assertTrue(m.TsObservation.objects.filter(case=case, target="sw1", is_missing_data=True, missing_reason__startswith="EMPTY").exists())

    def test_STPSRC_013_partial_and_unknown_history_never_pass_rb04(self):
        case, _ = run("stp13a", {d: healthy(d) for d in ("sw1", "sw2", "sw3")})
        self.assertNotIn("PASS", {verdicts(case).get(t) for t in ("ST02", "ST03", "ST04")})
        outputs = {d: doc(d, ports={"Ethernet1": port(), "Ethernet2": {"state": "bad"}}) for d in ("sw1", "sw2", "sw3")}
        case, _ = run("stp13b", outputs, context=seeded_context())
        self.assertNotIn("PASS", {verdicts(case).get(t) for t in ("ST02", "ST03", "ST04")})
        self.assertTrue(m.TsObservation.objects.filter(case=case, key="stp.state@10", quality="UNTRUSTED").exists())

    def test_STPSRC_014_reset_and_long_gap_are_unknown(self):
        for suffix, age, previous in (("reset", 10, 100), ("gap", 120, 0)):
            ctx = seeded_context()
            ctx.history.record("sw2", "10", {"tcn_total": previous, "root_id": "32778/00:1c:73:aa:aa:aa",
                "at": T0 - timedelta(minutes=age), "root_changes": [], "coverage_start": T0 - timedelta(days=2)})
            case, _ = run("stp14" + suffix, {d: healthy(d) for d in ("sw1", "sw2", "sw3")}, context=ctx)
            row = m.TsObservation.objects.get(case=case, target="sw2", key="stp.state@10", is_missing_data=False)
            self.assertIsNone(row.value["tcn_count_1h"])
            self.assertEqual(row.quality, "UNTRUSTED")
            self.assertNotEqual(verdicts(case)["ST03"], "PASS")

    def test_STPSRC_015_unsupported_version_does_not_contact_transport(self):
        class NoContact:
            def execute(self, command):
                raise AssertionError("unsupported STP command contacted a device")
        collector = col.CliCollector(capability_probe=lambda *args: {"status": "SUPPORTED"})
        bundle = collector.collect(col.Target(device="sw1", platform="ceos", os_version="5.1.0", verified=True, lifecycle_state="VERIFIED"),
                                   ["spanning_tree"], NoContact())
        self.assertEqual(bundle["observations"], [])
        self.assertEqual(bundle["missing"][0]["reason"], "PARSER_UNAVAILABLE")

    def test_STPSRC_016_fault_window_persists_then_recovers(self):
        ctx = seeded_context()
        outputs = {d: looped(d) for d in ("sw1", "sw2", "sw3")}
        fault_case, _ = run("stp16fault", outputs, context=ctx)
        self.assertEqual(verdicts(fault_case)["ST03"], "FAIL")
        # A zero delta on the next poll cannot erase a storm still inside the hour.
        still_case, _ = run("stp16still", outputs, context=ctx, at=T0 + timedelta(minutes=5))
        self.assertEqual(verdicts(still_case)["ST03"], "FAIL")
        # Continued samples establish an entire clean hour (no unobserved gap).
        for minute in (35, 65, 95):
            later = T0 + timedelta(minutes=minute)
            outputs = {d: doc(d, ports=json.loads(healthy(d))["spanningTreeInstances"]["VL10"]["interfaces"],
                              topology_changes=60 if d == "sw2" else 3, since_tc=minute * 60 + 5) for d in ("sw1", "sw2", "sw3")}
            recovery, _ = run("stp16recover" + str(minute), outputs, context=ctx, at=later)
        v = verdicts(recovery)
        self.assertEqual((v["ST02"], v["ST03"], v["ST04"]), ("PASS", "PASS", "PASS"), v)

    def test_STPSRC_017_bad_boolean_and_counter_remain_uncertain(self):
        ctx = seeded_context()
        outputs = {d: doc(d, topology_changes=-1, since_tc=-10,
                         ports={"Ethernet1": port(bpduFilter="false")}) for d in ("sw1", "sw2", "sw3")}
        case, _ = run("stp17", outputs, context=ctx)
        row = m.TsObservation.objects.get(case=case, target="sw1", key="stp.state@10", is_missing_data=False)
        self.assertEqual(row.quality, "UNTRUSTED")
        self.assertEqual(row.value["loop_indicators"], [])
        self.assertIsNone(row.value["tcn_total"])
        self.assertNotIn("PASS", {verdicts(case).get(t) for t in ("ST02", "ST03", "ST04", "ST06")})
