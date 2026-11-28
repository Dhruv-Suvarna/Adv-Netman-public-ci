"""L2 source (HC08 VLAN/port mode, HC09 MAC movement) -- parser -> collector -> runtime -> RB02/HC.  Stable IDs L2SRC-001 .. L2SRC-016.

PROVENANCE: every document below is SIMULATED (hand-written to the EOS ``show interfaces switchport | json`` / ``show mac address-table | json``
shape).  No gateway-recorded cEOS L2 output is pinned yet, so nothing here claims live verification; the injected gateway dict (live=False) only
proves provenance is carried verbatim.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase, TestCase

from core import models as m
from core.services.troubleshooting import baselines as bl
from core.services.troubleshooting import collectors as col
from core.services.troubleshooting import engine as eng
from core.services.troubleshooting import normalization as nz
from core.services.troubleshooting import repository as repo
from core.services.troubleshooting import runtime as rt
from core.services.troubleshooting.adapters import l2 as l2_ad
from core.tests.fixtures.troubleshooting_runbooks import scenarios as S

T0 = datetime(2026, 11, 9, 12, 0, 0, tzinfo=timezone.utc)
ACTOR = repo.Actor("alice", "user", tenant="acme")
SP_CMD, MAC_CMD = "show interfaces switchport | json", "show mac address-table | json"
GW = {"live": False, "fixture_id": "simulated-l2", "note": "SIMULATED: not gateway-recorded"}
EV = {"evidence_id": "ev-1", "source_type": "CLI", "transport": "t", "adapter": "a", "command_or_api": MAC_CMD, "collected_at": T0.isoformat(), "raw_ref": {"hash": "h"}}
H1, H2 = "aa:aa:aa:00:00:01", "aa:aa:aa:00:00:02"


def sp(name_info):
    return json.dumps({"switchports": {n: {"enabled": True, "switchportInfo": i} for n, i in name_info.items()}})


def good_sp(access_vlan=10, allowed="10,20-30"):
    return sp({"Ethernet1": {"mode": "access", "accessVlanId": access_vlan}, "Ethernet2": {"mode": "trunk", "trunkAllowedVlans": allowed, "trunkingNativeVlanId": 1}})


def mac(entries, total=None):
    rows = [{"vlanId": v, "macAddress": a, "entryType": t, "interface": i} for v, a, i, t in entries]
    tbl = {"tableEntries": rows}
    if total is not None:
        tbl["totalMacAddresses"] = total
    return json.dumps({"unicastTable": tbl})


def stable():
    return mac([(10, H1, "Ethernet1", "learnedDynamicMac"), (10, H2, "Ethernet2", "learnedDynamicMac"), (20, "bb:bb:bb:00:00:01", "Ethernet2", "learnedDynamicMac")])


def moved(a, b):
    return mac([(10, H1, a, "learnedDynamicMac"), (10, H2, b, "learnedDynamicMac"), (20, "bb:bb:bb:00:00:01", "Ethernet2", "learnedDynamicMac")])


def nm(raw, at=T0, version="4.36.2F", **kw):
    return nz.normalize_mac_table(raw, platform="ceos", os_version=version, device="sw1", evidence=EV, now=at, observed_at=at, **kw)


def vlan_obs(res, vlan):
    return [o for o in res["observations"] if o["target"].get("vlan") == vlan]


class SwitchportParserTests(SimpleTestCase):
    def norm(self, raw, version="4.36.2F"):
        return nz.normalize_l2_ports(raw, platform="ceos", os_version=version, device="sw1", evidence=EV, now=T0, observed_at=T0)

    def test_L2SRC_001_access_and_trunk_match_hc08_contract(self):
        res = self.norm(good_sp())
        by = {o["target"]["interface"]: o for o in res["observations"]}
        a, t = by["Ethernet1"], by["Ethernet2"]
        self.assertEqual((a["value"]["mode"], a["value"]["access_vlan"], a["quality"]), ("access", 10, "OK"))
        self.assertEqual((t["value"]["mode"], t["value"]["allowed_vlans"][:3], t["value"]["allowed_vlans"][-1]), ("trunk", [10, 20, 21], 30))
        self.assertEqual(res["parser"], {"id": "l2.port", "version": "eos-json-1.0", "template": "eos.show_interfaces_switchport.json", "input_kind": "json"})
        self.assertEqual(nz.parse_vlan_list("ALL")[-1], 4094)
        self.assertEqual(nz.parse_vlan_list("none"), [])

    def test_L2SRC_002_malformed_partial_and_unsupported_mode_never_trusted(self):
        for bad in ("10,x", "0-5", "30-20", "5000", ""):
            res = self.norm(sp({"Ethernet1": {"mode": "trunk", "trunkAllowedVlans": bad}}))
            (o,) = res["observations"]
            self.assertEqual(o["quality"], "UNTRUSTED_PARSE", bad)
        res = self.norm(sp({"Ethernet1": {"mode": "dot1q-tunnel"}, "Ethernet2": {"mode": "access", "accessVlanId": "10"}}))
        self.assertEqual({o["quality"] for o in res["observations"]}, {"UNTRUSTED_PARSE"})
        res = self.norm(json.dumps({"switchports": {"Ethernet1": {"switchportInfo": {"mode": "access", "accessVlanId": 10}}, "Ethernet2": "oops"}}))
        self.assertEqual([o["quality"] for o in res["observations"]], ["PARTIAL"])
        self.assertIn("PARTIAL_PARSE", res["observations"][0]["flags"])
        self.assertEqual(self.norm("{nope")["missing"][0]["reason"], nz.Missing.PARSE_FAILED)
        self.assertEqual(self.norm(json.dumps({"x": 1}))["missing"][0]["reason"], nz.Missing.PARSE_FAILED)
        self.assertEqual(self.norm(json.dumps({"switchports": {}}))["missing"][0]["reason"], nz.Missing.EMPTY)

    def test_L2SRC_003_version_gate_fails_closed(self):
        for v in ("4.20.1F", "5.0.0", "", "garbage"):
            self.assertEqual(self.norm(good_sp(), v)["missing"][0]["reason"], nz.Missing.PARSER_UNAVAILABLE, v)
        self.assertEqual(nz.normalize_l2_ports(good_sp(), platform="iosxe", os_version="17.6", device="x", evidence=EV, now=T0)["missing"][0]["reason"], nz.Missing.PARSER_UNAVAILABLE)


class MacParserTests(SimpleTestCase):
    def test_L2SRC_004_first_sample_has_no_movement_claim(self):
        res = nm(stable(), history=nz.MacHistory())
        o10 = vlan_obs(res, "10")[0]
        self.assertIsNone(o10["value"]["moves_per_min"])         # never a fabricated zero
        self.assertEqual(o10["quality"], "PARTIAL")
        self.assertIn("mac_movement_history_unknown", o10["value"]["uncertain"])
        self.assertIn("MAC_HISTORY_UNKNOWN", o10["flags"])
        self.assertEqual(vlan_obs(nm(stable()), "10")[0]["value"]["moves_per_min"], None)   # no history object at all

    def test_L2SRC_005_historical_samples_give_movement_and_flapping(self):
        h = nz.MacHistory()
        nm(moved("Ethernet1", "Ethernet2"), T0 - timedelta(minutes=4), history=h)
        nm(moved("Ethernet2", "Ethernet2"), T0 - timedelta(minutes=3), history=h)       # H1 moves Et1 -> Et2
        nm(moved("Ethernet1", "Ethernet2"), T0 - timedelta(minutes=2), history=h)       # H1 moves back
        o = vlan_obs(nm(moved("Ethernet2", "Ethernet2"), T0 - timedelta(minutes=1), history=h), "10")[0]
        self.assertEqual((o["value"]["move_count_window"], o["value"]["flapping_macs"]), (3, [H1]))
        self.assertEqual(o["value"]["moves_per_min"], 1.0)          # 3 moves over 3 observed minutes
        self.assertEqual(o["quality"], "OK")
        # stable table after stable history -> measured zero
        h2 = nz.MacHistory()
        nm(stable(), T0 - timedelta(minutes=3), history=h2)
        s = vlan_obs(nm(stable(), T0, history=h2), "10")[0]
        self.assertEqual((s["value"]["moves_per_min"], s["value"]["flapping_macs"], s["quality"]), (0.0, [], "OK"))

    def test_L2SRC_006_short_span_and_gap_stay_uncertain(self):
        h = nz.MacHistory()
        nm(moved("Ethernet1", "Ethernet2"), T0 - timedelta(seconds=20), history=h)
        o = vlan_obs(nm(moved("Ethernet2", "Ethernet2"), T0, history=h), "10")[0]
        self.assertIsNone(o["value"]["moves_per_min"])
        self.assertIn("mac_history_too_short", o["value"]["uncertain"])
        h = nz.MacHistory()
        nm(stable(), T0 - timedelta(hours=1), history=h)
        g = vlan_obs(nm(stable(), T0, history=h), "10")[0]
        self.assertIn("mac_history_gap", g["value"]["uncertain"])
        self.assertIsNone(g["value"]["moves_per_min"])
        # non-monotonic sample never advances history
        nm(stable(), T0 - timedelta(minutes=5), history=h)
        self.assertEqual(h.previous("sw1", "10")["at"], T0)

    def test_L2SRC_007_vlan_scope_other_vlan_flap_does_not_leak(self):
        h = nz.MacHistory()
        flap = lambda p: mac([(10, H1, "Ethernet1", "learnedDynamicMac"), (20, H2, p, "learnedDynamicMac")])
        nm(flap("Ethernet2"), T0 - timedelta(minutes=2), history=h)
        res = nm(flap("Ethernet3"), T0, history=h)
        self.assertEqual(vlan_obs(res, "10")[0]["value"]["moves_per_min"], 0.0)
        self.assertEqual(vlan_obs(res, "20")[0]["value"]["move_count_window"], 1)
        self.assertEqual(vlan_obs(res, "30"), [])                 # VLAN absent from the table: a gap, not "stable"
        self.assertEqual(sorted(o["target"]["vlan"] for o in res["observations"]), ["10", "20"])

    def test_L2SRC_008_static_entries_are_not_movement(self):
        h = nz.MacHistory()
        nm(mac([(10, H1, "Ethernet1", "staticConfigured")]), T0 - timedelta(minutes=2), history=h)
        o = vlan_obs(nm(mac([(10, H1, "Ethernet2", "staticConfigured")]), T0, history=h), "10")[0]
        self.assertEqual((o["value"]["moves_per_min"], o["value"]["dynamic_count"]), (0.0, 0))

    def test_L2SRC_009_empty_malformed_partial_tables_do_not_prove_absence(self):
        self.assertEqual(nm(mac([]))["missing"][0]["reason"], nz.Missing.EMPTY)
        self.assertEqual(nm("{bad")["missing"][0]["reason"], nz.Missing.PARSE_FAILED)
        self.assertEqual(nm(json.dumps({"unicastTable": {}}))["missing"][0]["reason"], nz.Missing.PARSE_FAILED)
        self.assertEqual(nm(mac([(10, "zz", "Ethernet1", "learnedDynamicMac")]))["missing"][0]["reason"], nz.Missing.PARSE_FAILED)
        h = nz.MacHistory()
        nm(stable(), T0 - timedelta(minutes=3), history=h)
        part = nm(mac([(10, H1, "Ethernet1", "learnedDynamicMac"), (10, "bad", "Ethernet2", "learnedDynamicMac")]), T0, history=h)
        o = vlan_obs(part, "10")[0]
        self.assertEqual(o["quality"], "PARTIAL")
        self.assertIn("PARTIAL_PARSE", o["flags"])
        self.assertEqual(h.previous("sw1", "10")["at"], T0 - timedelta(minutes=3))      # partial parse does not advance history
        trunc = nm(mac([(10, H1, "Ethernet1", "learnedDynamicMac")], total=5), T0, history=h)      # announced 5 entries, only 1 present
        self.assertEqual(vlan_obs(trunc, "10")[0]["quality"], "PARTIAL")
        dup = nm(mac([(10, H1, "Ethernet1", "learnedDynamicMac"), (10, H1, "Ethernet2", "learnedDynamicMac")]))
        self.assertIn("PARTIAL_PARSE", vlan_obs(dup, "10")[0]["flags"])

    def test_L2SRC_010_version_gate_fails_closed(self):
        for v in ("4.20.1F", "5.1", "", "x"):
            self.assertEqual(nm(stable(), version=v)["missing"][0]["reason"], nz.Missing.PARSER_UNAVAILABLE, v)


class Transport:
    def __init__(self, outputs, provenance=None):
        self.outputs, self.calls = outputs, []
        if provenance:
            self.provenance = lambda: provenance

    def execute(self, rendered):
        self.calls.append(rendered)
        return self.outputs.get(rendered, "{}")


class CollectorTests(SimpleTestCase):
    def target(self, version="4.36.2F", platform="ceos"):
        return col.Target(device="sw1", platform=platform, os_version=version, lifecycle_state="VERIFIED", verified=True, capabilities={col.SourceType.CLI: "SUPPORTED"})

    def test_L2SRC_011_catalogue_read_only_labels_and_no_contact_when_unsupported(self):
        for key, parser in (("switchport", "l2.port"), ("mac_table", "mac.table")):
            spec = col.COMMAND_CATALOG["ceos"][key]
            col.validate_read_only("ceos", spec.command)
            self.assertEqual(spec.parser_id, parser)
        self.assertIsNone(col.COMMAND_CATALOG["iosxe"]["mac_table"].parser_id)
        self.assertEqual(l2_ad.describe_source()["label"], "SIMULATED")
        self.assertEqual(l2_ad.describe_source(recorded=True)["label"], "RECORDED")
        self.assertFalse(l2_ad.describe_source(gateway={"live": False})["live"])
        self.assertEqual(l2_ad.describe_source(gateway={"live": True})["label"], "LIVE_GATEWAY_PINNED")
        self.assertTrue(l2_ad.is_supported("ceos", "4.36.2F"))
        self.assertFalse(l2_ad.is_supported("ceos", "4.20.1F"))
        tr = Transport({SP_CMD: good_sp(), MAC_CMD: stable()})
        bundle = col.CliCollector().collect(self.target("4.20.1F"), ["switchport", "mac_table"], tr)
        self.assertEqual(tr.calls, [])
        self.assertEqual({r["reason"] for r in bundle["missing"]}, {nz.Missing.PARSER_UNAVAILABLE})

    def test_L2SRC_012_collector_preserves_raw_hash_source_and_history(self):
        ctx = l2_ad.L2Context()
        c = col.CliCollector()
        c.l2_context = ctx
        tr = Transport({SP_CMD: good_sp(), MAC_CMD: stable()}, provenance=GW)
        b = c.collect(self.target(), ["switchport", "mac_table"], tr)
        self.assertEqual(sorted(tr.calls), sorted([SP_CMD, MAC_CMD]))
        keys = {o["key"] for o in b["observations"]}
        self.assertEqual(keys, {"l2.port", "mac.table"})
        self.assertEqual({e["command_or_api"] for e in b["evidence"]}, {SP_CMD, MAC_CMD})
        for o in b["observations"]:
            self.assertRegex(o["raw_hash"], r"^(sha256:)?[0-9a-f]{64}$")
            self.assertEqual(o["source"]["command_or_api"], SP_CMD if o["key"] == "l2.port" else MAC_CMD)
        self.assertEqual(b["run"]["gateway"], GW)
        self.assertIsNotNone(ctx.history.previous("sw1", "10"))       # history is recorded through the collector


def verdicts(case):
    return {t.test_id: t.verdict for t in m.TsDiagnosticTest.objects.filter(case=case)}


def intent():
    i = S.intent()
    for l in i["links"]:
        l["a_if"], l["b_if"] = (x.replace("Eth", "Ethernet") for x in (l["a_if"], l["b_if"]))
    return i


def make_case(key):
    devs = ["h1", "sw1", "r1", "r2", "h2"]
    target = {"device": "sw1", "devices": devs, "vlan": 10, "links": [], "cables": [], "lag": None}
    return repo.open_case(ACTOR, trigger_source="alert:test", idempotency_key=key, service_intent={"service": "web", "target": target},
                          flow_scope=dict(S.FLOW), affected_scope={"devices": devs}, target_states={d: "VERIFIED" for d in devs}, severity="HIGH", runbook="RB02",
                          worked_before=True, first_detected_at=T0 - timedelta(minutes=10), last_known_good_at=T0 - timedelta(hours=3), now=T0 - timedelta(minutes=5))


def deps(outputs, *, version="4.36.2F", context=None, tr=None):
    tr = tr or Transport(outputs, GW)
    return tr, rt.RuntimeDeps(
        admission=rt.InventoryAdmission(inventory=lambda: {d: {"platform": "ceos", "os_version": version} for d in ("h1", "sw1", "r1", "r2", "h2")}),
        cli_transport=lambda info: tr, sources=bl.StaticSources({**S.static_data(), "intent": intent()}), clock=lambda: 0.0, sleep=lambda s: None,
        now=lambda: T0, l2_context=context, capability_probe=lambda plat, src: {"status": "SUPPORTED", "evidence": "test", "transport": "test"})


def run(key, outputs, **kw):
    case = make_case(key)
    tr, d = deps(outputs, **kw)
    res = rt.run_case(ACTOR, case.case_id, d, run_key="r1", now=T0, engine_config=eng.EngineConfig(exhaustive=True))
    return case, res, tr


def seeded(macs=None, *, minutes=3):
    ctx = l2_ad.L2Context()
    nm(macs or stable(), T0 - timedelta(minutes=minutes), history=ctx.history)
    return ctx


class RuntimeToHcTests(TestCase):
    def test_L2SRC_013_hc08_pass_and_wrong_vlan_fault(self):
        case, _, _ = run("l2a", {SP_CMD: good_sp(), MAC_CMD: stable()}, context=seeded())
        self.assertEqual(verdicts(case)["HC08"], "PASS", verdicts(case))
        row = m.TsObservation.objects.get(case=case, target="sw1", key="l2.port@Ethernet1", is_missing_data=False)
        self.assertEqual(row.value["access_vlan"], 10)
        case, res, _ = run("l2b", {SP_CMD: good_sp(access_vlan=99), MAC_CMD: stable()}, context=seeded())
        self.assertEqual(verdicts(case)["HC08"], "FAIL", verdicts(case))
        self.assertIn("F-vlan", json.dumps(res["diagnosis"]))
        case, _, _ = run("l2c", {SP_CMD: sp({"Ethernet1": {"mode": "access", "accessVlanId": 10}, "Ethernet2": {"mode": "trunk", "trunkAllowedVlans": "20-30"}}), MAC_CMD: stable()},
                         context=seeded())
        self.assertEqual(verdicts(case)["HC08"], "FAIL", verdicts(case))

    def test_L2SRC_014_hc09_stable_flapping_and_wrong_vlan(self):
        case, _, _ = run("l2d", {SP_CMD: good_sp(), MAC_CMD: stable()}, context=seeded())
        self.assertEqual(verdicts(case)["HC09"], "PASS", verdicts(case))
        ctx = seeded(moved("Ethernet1", "Ethernet2"), minutes=1)
        # the MAC moves between polls and moves back: 2 moves in the observed span with H1 flapping
        nm(moved("Ethernet2", "Ethernet2"), T0 - timedelta(seconds=30), history=ctx.history)
        flap = {SP_CMD: good_sp(), MAC_CMD: moved("Ethernet1", "Ethernet2")}
        case, res, _ = run("l2e", flap, context=ctx)
        self.assertEqual(verdicts(case)["HC09"], "FAIL", verdicts(case))
        self.assertIn("F-macflap", json.dumps(res["diagnosis"]))
        # flapping confined to VLAN 20 must not fail the host VLAN 10
        h = l2_ad.L2Context()
        other = lambda p: mac([(10, H1, "Ethernet1", "learnedDynamicMac"), (20, H2, p, "learnedDynamicMac")])
        nm(other("Ethernet2"), T0 - timedelta(minutes=3), history=h.history)
        case, _, _ = run("l2f", {SP_CMD: good_sp(), MAC_CMD: other("Ethernet3")}, context=h)
        self.assertEqual(verdicts(case)["HC09"], "PASS", verdicts(case))

    def test_L2SRC_015_unknown_partial_empty_and_unsupported_never_pass(self):
        # no history -> UNKNOWN (HC09 cannot PASS) but HC08 is unaffected
        case, _, _ = run("l2g", {SP_CMD: good_sp(), MAC_CMD: stable()})
        v = verdicts(case)
        self.assertNotEqual(v.get("HC09"), "PASS", v)
        self.assertEqual(v["HC08"], "PASS")
        self.assertTrue(m.TsObservation.objects.filter(case=case, target="sw1", key="mac.table@10", quality="UNTRUSTED").exists())
        # partial MAC table with history
        part = mac([(10, H1, "Ethernet1", "learnedDynamicMac"), (10, "bad", "Ethernet2", "learnedDynamicMac")])
        case, _, _ = run("l2h", {SP_CMD: good_sp(), MAC_CMD: part}, context=seeded())
        self.assertNotEqual(verdicts(case).get("HC09"), "PASS")
        # empty / malformed MAC and switchport
        case, _, _ = run("l2i", {SP_CMD: sp({}), MAC_CMD: mac([])}, context=seeded())
        v = verdicts(case)
        self.assertNotIn("PASS", (v.get("HC08"), v.get("HC09")), v)
        self.assertTrue(m.TsObservation.objects.filter(case=case, target="sw1", is_missing_data=True, missing_reason__startswith="EMPTY").exists())
        # partial switchport (one port dropped) cannot pass HC08
        case, _, _ = run("l2j", {SP_CMD: json.dumps({"switchports": {"Ethernet1": {"switchportInfo": {"mode": "access", "accessVlanId": 10}}, "Ethernet2": 5}}), MAC_CMD: stable()},
                         context=seeded())
        self.assertNotEqual(verdicts(case).get("HC08"), "PASS")

    def test_L2SRC_016_unsupported_version_refuses_before_contact_and_evidence_provenance(self):
        case, _, tr = run("l2k", {SP_CMD: good_sp(), MAC_CMD: stable()}, version="4.20.1F", context=seeded())
        self.assertNotIn(SP_CMD, tr.calls)
        self.assertNotIn(MAC_CMD, tr.calls)
        v = verdicts(case)
        self.assertNotIn("PASS", (v.get("HC08"), v.get("HC09")))
        self.assertTrue(m.TsObservation.objects.filter(case=case, target="sw1", is_missing_data=True, missing_reason__startswith="PARSER_UNAVAILABLE").exists())
        case, _, _ = run("l2l", {SP_CMD: good_sp(), MAC_CMD: stable()}, context=seeded())
        ev = m.TsEvidenceRef.objects.get(case=case, device="sw1", command_or_api=MAC_CMD)
        self.assertEqual((ev.parser, ev.parser_version), ("mac.table", "eos-json-1.0"))
        self.assertEqual(ev.scope["gateway"], GW)
        self.assertFalse(ev.scope["live"])
        self.assertRegex(ev.scope["raw_hash_as_received"], r"^(sha256:)?[0-9a-f]{64}$")
