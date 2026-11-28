"""Routing-aware troubleshooting (``core.services.troubleshooting.routing``): REPLAY tests.

Every fixture under ``fixtures/troubleshooting_routing`` is a verbatim read-only capture from the live srlceos01 lab
(``CAPTURED_AT``): cEOS ``show ... | json`` and Linux/FRR ``ip -j`` / ``vtysh ... json``.  Each fault test applies ONE
mutation to a copy of the live healthy document.  These are replay-verified, not live-fault-verified.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from django.test import SimpleTestCase

from core.services.troubleshooting import correlation, faults
from core.services.troubleshooting import routing as r

FX = Path(__file__).resolve().parent / "fixtures" / "troubleshooting_routing"
REPO = Path(__file__).resolve().parents[3]
NOW = datetime(2026, 11, 17, 21, 18, tzinfo=timezone.utc)
CEOS_ROUTERS = ("R1", "R2", "R5")
WEB_V4, WEB_V6 = "172.30.50.10", "2001:db8:3050::10"


def load(name: str):
    return json.loads((FX / name).read_text(encoding="utf-8"))


def lab():
    """(ribs4, ribs6, addresses, links) from the live captures."""
    ribs4, ribs6, addrs = {}, {}, {}
    for d in ("R1", "R2", "R5", "S1", "S2"):
        ribs4[d], ribs6[d] = r.ceos_rib(load(f"{d}.rib4.json")), r.ceos_rib(load(f"{d}.rib6.json"))
    for d in ("R1", "R2", "R5", "S1", "S2", "S3", "S4"):
        addrs[d] = r.ceos_addresses(load(f"{d}.addr4.json"), load(f"{d}.addr6.json"))
    for d in ("R3", "R4", "H1", "H2"):
        ribs4[d], ribs6[d] = r.linux_rib(load(f"{d}.route4.json"), "ipv4"), r.linux_rib(load(f"{d}.route6.json"), "ipv6")
    for d in ("R3", "R4", "H1", "H2", "H3", "H4", "WebServer"):
        addrs[d] = r.linux_addresses(load(f"{d}.addr.json"))
    links = r.clab_links(yaml.safe_load((REPO / "srlceos01.clab.yml").read_text(encoding="utf-8")))
    return ribs4, ribs6, addrs, links


def ceos_docs(device: str) -> dict:
    return {k: load(f"{device}.{k}.json") for k in ("ospf", "ospf3", "bgp", "bgp6")}


def frr_docs(device: str) -> dict:
    return {"ospf": load(f"{device}.ospf.json"), "ospf6": load(f"{device}.ospf6.json"), "bgp": load(f"{device}.bgp.json")}


class AdjacencyParsingTests(SimpleTestCase):
    def test_live_ceos_and_frr_adjacencies_all_four_protocols(self):
        got = {d: sorted((a.protocol, a.neighbor, a.interface, a.state) for a in r.ceos_adjacency_samples(d, ceos_docs(d), NOW))
               for d in CEOS_ROUTERS}
        got |= {d: sorted((a.protocol, a.neighbor, a.interface, a.state) for a in r.frr_adjacency_samples(d, frr_docs(d), NOW))
                for d in ("R3", "R4")}
        self.assertIn(("ospfv3", "192.168.255.3", "Vlan101", "full"), got["R1"])
        self.assertEqual({p for p, *_ in got["R2"]}, {"ospf", "ospfv3"})                    # "BGP inactive" contributes nothing
        self.assertEqual({(p, s) for p, _n, _i, s in got["R5"]}, {("bgp", "Established"), ("bgp6", "Established")})
        self.assertIn(("ospf", "192.168.255.1", "Vlan101", "full"), got["R3"])              # FRR 'Full/Backup' and 'Vlan101:<addr>'
        self.assertIn(("bgp6", "2001:db8:205:1::2", "", "Established"), got["R3"])         # FRR 'state', not peerState "OK"
        self.assertTrue(all(a.healthy for d in ("R3", "R4") for a in r.frr_adjacency_samples(d, frr_docs(d), NOW)))

    def test_replay_ospfv3_loss_bgp6_active_and_frr_init_are_adjacency_failures(self):
        base = {d: r.ceos_adjacency_samples(d, ceos_docs(d), NOW) for d in CEOS_ROUTERS}
        base |= {d: r.frr_adjacency_samples(d, frr_docs(d), NOW) for d in ("R3", "R4")}
        r1 = ceos_docs("R1")
        entries = r1["ospf3"]["vrfs"]["default"]["instList"]["10"]["ospf3NeighborEntries"]
        r1["ospf3"]["vrfs"]["default"]["instList"]["10"]["ospf3NeighborEntries"] = [e for e in entries if e["interfaceName"] != "Vlan101"]
        r5 = ceos_docs("R5")
        next(iter(r5["bgp6"]["vrfs"]["default"]["peers"].values()))["peerState"] = "Active"
        r3 = frr_docs("R3")
        r3["ospf"]["neighbors"]["192.168.255.2"][0]["nbrState"] = "Init/DROther"
        cases = {"R1": (r.ceos_adjacency_samples("R1", r1, NOW), ("ospfv3", "192.168.255.3", "absent")),
                 "R5": (r.ceos_adjacency_samples("R5", r5, NOW), ("bgp6", None, "Active")),
                 "R3": (r.frr_adjacency_samples("R3", r3, NOW), ("ospf", "192.168.255.2", "init"))}
        for dev, (observed, (proto, nbr, state)) in cases.items():
            with self.subTest(dev=dev):
                failed = faults.classify_adjacency(base[dev], observed, now=NOW, expectation_source="LEARNED_BASELINE (test)")
                self.assertEqual(len(failed), 1)
                self.assertEqual(failed[0].category, faults.ROUTING_ADJACENCY_FAILURE)
                self.assertEqual(failed[0].scope["protocol"], proto)
                if nbr:
                    self.assertEqual(failed[0].scope["neighbor"], nbr)
                self.assertIn(state, failed[0].summary)
                self.assertEqual(faults.decide(failed[0])["outcome"], faults.DIAGNOSE_AND_ESCALATE)   # never a write


class RibParsingTests(SimpleTestCase):
    def test_sources_normalised_per_family_and_platform(self):
        ribs4, ribs6, _a, _l = lab()
        self.assertEqual(r.source_counts(ribs4["S1"])["rip"], load("S1.rsum4.json")["vrfs"]["default"]["rip"])   # RIB == summary
        self.assertEqual(r.source_counts(ribs4["R1"])["ospf_external"], 1)
        self.assertIn("isis", r.source_counts(ribs6["R1"]))
        self.assertIn("ospf3", r.source_counts(ribs6["R1"]))
        self.assertIn("ospf3", r.source_counts(ribs6["R3"]))                   # zebra's 'ospf' label for ospf6d routes on IPv6
        self.assertNotIn("ospf", r.source_counts(ribs6["R3"]))
        self.assertEqual(r.lpm(ribs4["S1"], WEB_V4).source, "rip")
        self.assertIsNone(r.ceos_rib({"errors": ["x"]}))                       # unreadable is None, never an empty RIB
        self.assertIsNone(r.linux_rib(None, "ipv4"))


class PathReconstructionTests(SimpleTestCase):
    def test_protected_flows_h1_h2_stay_inside_s1_both_families(self):
        ribs4, ribs6, addrs, links = lab()
        for dst, ribs in (("192.168.20.101", ribs4), ("2001:db8:20::2001", ribs6)):
            with self.subTest(dst=dst):
                p = r.reconstruct_path("H1", dst, ribs, addrs, links=links)
                self.assertEqual((p["verdict"], p["delivered_to"]), (r.DELIVERED, "H2"))
                self.assertEqual([h["device"] for h in p["hops"]], ["H1", "S1"])
                self.assertEqual(p["hops"][0]["how"], "sole topology peer on the egress link")      # VARP anycast gateway

    def test_h1_to_webserver_walks_both_ecmp_branches_through_the_redistribution_chain(self):
        ribs4, ribs6, addrs, links = lab()
        for dst, ribs, chain in ((WEB_V4, ribs4, ["static", "rip", "ospf_external", "bgp", "static"]),
                                 (WEB_V6, ribs6, ["ra", "isis", "ospf3", "bgp", "static"])):
            with self.subTest(dst=dst):
                single = r.reconstruct_path("H1", dst, ribs, addrs, links=links)
                self.assertEqual(single["verdict"], r.NO_EVIDENCE)                 # a single walk never picks an ECMP branch
                allp = r.reconstruct_all_paths("H1", dst, ribs, addrs, links=links)
                self.assertEqual(allp["verdict"], r.DELIVERED)
                self.assertEqual(sorted(b["hops"][3]["device"] for b in allp["branches"]), ["R3", "R4"])
                for b in allp["branches"]:
                    self.assertEqual([h["source"] for h in b["hops"]], chain)
                    self.assertEqual(b["delivered_to"], "WebServer")

    def test_replay_missing_route_and_default_is_blackhole_and_missing_rib_is_no_evidence(self):
        ribs4, _r6, addrs, links = lab()
        broken = {**ribs4, "R1": {k: v for k, v in ribs4["R1"].items() if k not in ("172.30.50.10/32", "0.0.0.0/0")}}
        p = r.reconstruct_all_paths("H1", WEB_V4, broken, addrs, links=links)
        self.assertEqual(p["verdict"], r.BLACKHOLE)
        self.assertEqual(p["branches"][0]["stopped_at"], "R1")
        partial = {k: v for k, v in ribs4.items() if k != "R3"}
        q = r.reconstruct_all_paths("H1", WEB_V4, partial, addrs, links=links)
        self.assertEqual(q["verdict"], r.NO_EVIDENCE)
        self.assertIn("no RIB collected for R3", [b.get("reason") for b in q["branches"]])

    def test_flow_impact_rerouted_and_broken(self):
        ribs4, _r6, addrs, links = lab()
        before = r.reconstruct_path("H1", "192.168.20.101", ribs4, addrs, links=links)
        self.assertEqual(r.flow_impact(before, before)["impact"], "UNCHANGED")
        bh = r.reconstruct_path("H1", WEB_V4, {**ribs4, "S1": {}}, addrs, links=links)
        self.assertEqual(r.flow_impact(before, bh)["impact"], "BROKEN")
        self.assertEqual(r.flow_impact(before, None)["impact"], "UNKNOWN")


class RouteClassificationTests(SimpleTestCase):
    SRC = "LEARNED_BASELINE (live capture, test)"

    def test_live_baseline_is_no_fault(self):
        ribs4, _r6, _a, _l = lab()
        for dev in ("S1", "R1"):
            exp = ribs4[dev]["172.30.50.10/32"]
            self.assertEqual(r.classify_route_change(dev, exp.prefix, exp, ribs4[dev], now=NOW, expectation_source=self.SRC).category,
                             faults.NO_FAULT)

    def test_replay_missing_route_reports_covering_route(self):
        ribs4, *_ = lab()
        exp = ribs4["S1"]["172.30.50.10/32"]
        cur = {k: v for k, v in ribs4["S1"].items() if k != exp.prefix}
        c = r.classify_route_change("S1", exp.prefix, exp, cur, now=NOW, expectation_source=self.SRC)
        self.assertEqual((c.category, c.evidence["subtype"]), (faults.ROUTE_OR_REACHABILITY_FAILURE, r.MISSING_ROUTE))
        self.assertEqual(c.evidence["covering_route"]["prefix"], "0.0.0.0/0")
        self.assertEqual(c.evidence["expectation_source"], self.SRC)
        self.assertEqual(faults.decide(c)["outcome"], faults.DIAGNOSE_AND_ESCALATE)

    def test_replay_wrong_next_hop_and_redistribution_mismatch(self):
        ribs4, *_ = lab()
        exp = ribs4["R1"]["172.30.50.10/32"]
        wrong = dict(ribs4["R1"])
        wrong[exp.prefix] = r.RibEntry(exp.prefix, exp.source, exp.raw_type, (("192.0.2.99", "Vlan999"),), "ipv4")
        c = r.classify_route_change("R1", exp.prefix, exp, wrong, now=NOW, expectation_source=self.SRC)
        self.assertEqual(c.evidence["subtype"], r.WRONG_NEXT_HOP)
        ecmp_member_lost = dict(ribs4["R1"])
        ecmp_member_lost[exp.prefix] = r.RibEntry(exp.prefix, exp.source, exp.raw_type, exp.next_hops[:1], "ipv4")
        self.assertEqual(r.classify_route_change("R1", exp.prefix, exp, ecmp_member_lost, now=NOW, expectation_source=self.SRC).category,
                         faults.NO_FAULT)                                  # one surviving ECMP member is not a wrong next hop
        redist = dict(ribs4["R1"])
        redist[exp.prefix] = r.RibEntry(exp.prefix, "static", "static", exp.next_hops, "ipv4")
        d = r.classify_route_change("R1", exp.prefix, exp, redist, now=NOW, expectation_source=self.SRC)
        self.assertEqual((d.evidence["subtype"], d.evidence["redistribution_related"]), (r.UNEXPECTED_SOURCE, True))
        self.assertIn("redistribution mismatch", d.summary)
        self.assertEqual(r.classify_route_change("R1", exp.prefix, exp, None, now=NOW, expectation_source=self.SRC).category,
                         faults.INDETERMINATE)

    def test_replay_source_collapse_rip_and_redistributed_externals(self):
        ribs4, *_ = lab()
        base = r.source_counts(ribs4["S1"])
        self.assertEqual(r.classify_source_counts("S1", "ipv4", base, base, now=NOW, expectation_source=self.SRC), [])
        gone = {**base, "rip": 0}
        [c] = r.classify_source_counts("S1", "ipv4", base, gone, now=NOW, expectation_source=self.SRC)
        self.assertEqual((c.scope["source"], c.evidence["subtype"]), ("rip", r.SOURCE_COLLAPSE))
        r1 = r.source_counts(ribs4["R1"])
        [e] = r.classify_source_counts("R1", "ipv4", r1, {**r1, "ospf_external": 0}, now=NOW, expectation_source=self.SRC)
        self.assertTrue(e.evidence["redistribution_related"])
        self.assertEqual(r.classify_source_counts("S1", "ipv4", base, None, now=NOW, expectation_source=self.SRC)[0].category,
                         faults.INDETERMINATE)

    def test_replay_redistribution_fault_domain_versus_origin_lost(self):
        """OSPF->RIP at R1: S1 and S2 learn 172.30.50.10/32 as RIP; R1 holds it as an OSPF external (BGP->OSPF at R3/R4)."""
        ribs4, *_ = lab()
        p = "172.30.50.10/32"
        ok = r.correlate_redistribution(p, redistributor="R1", redistributor_rib=ribs4["R1"], origin_sources=["ospf_external"],
                                        remote={"S1": ribs4["S1"], "S2": ribs4["S2"]}, redistributed_source="rip")
        self.assertEqual(ok["verdict"], "CONSISTENT")
        no_rip = {d: {k: v for k, v in ribs4[d].items() if k != p} for d in ("S1", "S2")}
        broken = r.correlate_redistribution(p, redistributor="R1", redistributor_rib=ribs4["R1"], origin_sources=["ospf_external"],
                                            remote=no_rip, redistributed_source="rip")
        self.assertEqual(broken["verdict"], "REDISTRIBUTION_FAULT_DOMAIN")
        origin_gone = {k: v for k, v in ribs4["R1"].items() if k != p}
        lost = r.correlate_redistribution(p, redistributor="R1", redistributor_rib=origin_gone, origin_sources=["ospf_external"],
                                          remote=no_rip, redistributed_source="rip")
        self.assertEqual(lost["verdict"], "ORIGIN_LOST")
        part = r.correlate_redistribution(p, redistributor="R1", redistributor_rib=ribs4["R1"], origin_sources=["ospf_external"],
                                          remote={"S1": no_rip["S1"], "S2": None}, redistributed_source="rip")
        self.assertEqual((part["verdict"], part["unreadable"], part["evidence_quality"]), ("REDISTRIBUTION_FAULT_DOMAIN", ["S2"], "PARTIAL"))


class PathAwareCorrelationTests(SimpleTestCase):
    def setUp(self):
        ribs4, _r6, addrs, self.links = lab()
        self.paths = {"H1-WEB-V4": r.reconstruct_all_paths("H1", WEB_V4, ribs4, addrs, links=self.links),
                      "H1-H2-V4": r.reconstruct_path("H1", "192.168.20.101", ribs4, addrs, links=self.links)}
        self.t0 = NOW

    def at(self, s):
        return (self.t0 + timedelta(seconds=s)).isoformat()

    def test_common_fault_one_incident_unrelated_fault_independent(self):
        alarms = [
            {"id": "a1", "device": "S1", "interface": "eth1", "kind": "LINK_DOWN", "at": self.at(0)},              # S1-R1 cable
            {"id": "a2", "device": "R1", "interface": "eth2", "kind": "LINK_DOWN", "at": self.at(1)},              # its far end
            {"id": "a3", "device": "H1", "kind": "FLOW_DEGRADED", "at": self.at(8), "flow": "H1-WEB-V4"},         # path symptom
            {"id": "a4", "device": "S2", "interface": "eth4", "kind": "LINK_DOWN", "at": self.at(20)},             # unrelated (H4)
            {"id": "a5", "device": "H1", "kind": "FLOW_DEGRADED", "at": self.at(9), "flow": "H1-H2-V4"},          # not on that link
        ]
        out =r.correlate_with_paths(alarms, self.links, vantage="mgmt_swt", baseline_paths=self.paths)
        primaries = sorted((g["primary"]["device"], g["primary"]["interface"]) for g in out["groups"])
        self.assertEqual(primaries, [("S1", "eth1"), ("S2", "eth4")])                      # two independent incidents
        g = next(g for g in out["groups"] if g["primary"]["device"] == "S1")
        self.assertEqual(sorted(s["id"] for s in g["symptoms"] if s["id"] in ("a2", "a3")), ["a2", "a3"])
        self.assertTrue(any(s["reason"].startswith("path: ") for s in g["symptoms"]))
        self.assertIn("R5 baseline forwarding path traversed the failed link (routing-aware)", g["rules"])
        self.assertNotIn("a5", g["alert_ids"])                                             # H1->H2 never used S1:eth1
        self.assertIn("a5", [u["id"] for u in out["unrelated"]])
        plain = correlation.correlate_alarms(alarms, self.links, vantage="mgmt_swt")
        self.assertNotIn("a3", next(x for x in plain["groups"] if x["primary"]["device"] == "S1")["alert_ids"])   # R3 alone rejects it

    def test_without_path_evidence_the_route_symptom_stays_rejected(self):
        alarms = [{"id": "a1", "device": "S1", "interface": "eth1", "kind": "LINK_DOWN", "at": self.at(0)},
                  {"id": "a3", "device": "H1", "kind": "FLOW_DEGRADED", "at": self.at(8), "flow": "UNKNOWN-FLOW"}]
        out = r.correlate_with_paths(alarms, self.links, vantage="mgmt_swt", baseline_paths=self.paths)
        self.assertNotIn("a3", out["groups"][0]["alert_ids"])

    def test_svi_hop_needs_explicit_l2_membership(self):
        failed = {"a": "S3", "a_if": "eth3", "b": "R1", "b_if": "eth1"}                    # R1's VLAN101 uplink toward R3
        sym = {"id": "x", "device": "R1", "kind": "ROUTE_WITHDRAWN", "flow": "H1-WEB-V4"}
        self.assertFalse(r.explain_by_path(sym, failed, self.paths)[0])
        ok, why = r.explain_by_path(sym, failed, self.paths, l2_members={("R1", "Vlan101"): ["eth1"]})
        self.assertTrue(ok, why)
        self.assertIn("ECMP", why)


class EvidenceQualityTests(SimpleTestCase):
    def test_stale_and_missing_evidence_is_reported(self):
        items = [r.EvidenceItem("R1", "rib4", NOW - timedelta(seconds=30)), r.EvidenceItem("S1", "rib4", NOW - timedelta(seconds=600)),
                 r.EvidenceItem("R3", "rib4", None)]
        q = r.evidence_quality(items, now=NOW, required_devices=["R1", "S1", "R3", "R4"])
        self.assertEqual(q["quality"], "PARTIAL")
        self.assertEqual(q["stale"], ["R3:rib4", "S1:rib4"])
        self.assertEqual(q["missing_devices"], ["R3", "R4", "S1"])
        self.assertEqual(r.evidence_quality([], now=NOW, required_devices=["R1"])["quality"], "NONE")


class FrrIntakeReaderTests(SimpleTestCase):
    def test_linux_interface_samples_cover_cabled_ports_only(self):
        links = [{"ifname": "lo", "flags": ["LOOPBACK", "UP", "LOWER_UP"]},
                 {"ifname": "eth0@if352", "flags": ["UP", "LOWER_UP"]},
                 {"ifname": "eth1@if366", "flags": ["BROADCAST", "UP", "LOWER_UP"],
                  "stats64": {"rx": {"errors": 3, "dropped": 1, "packets": 10}, "tx": {"errors": 0, "dropped": 0, "packets": 9}}},
                 {"ifname": "eth2@if397", "flags": ["BROADCAST", "UP"]},
                 {"ifname": "eth3", "flags": ["BROADCAST"]},
                 {"ifname": "Vlan200", "flags": ["UP", "LOWER_UP"]}, {"ifname": "eth1.101@eth1", "flags": ["UP", "LOWER_UP"]}]
        got = {s.interface: (s.admin, s.oper, s.link_status) for s in faults.linux_interface_samples("R3", links, NOW)}
        self.assertEqual(got, {"eth1": ("up", "up", "connected"), "eth2": ("up", "down", "notconnect"), "eth3": ("down", "down", "disabled")})
        eth1 = next(s for s in faults.linux_interface_samples("R3", links, NOW) if s.interface == "eth1")
        self.assertEqual((eth1.counters["totalInErrors"], eth1.counters["inDiscards"]), (3, 1))

    def test_frr_route_counts_use_selected_routes_and_ospf3_on_ipv6(self):
        from core.services.troubleshooting import intake

        doc4 = {"10.0.0.0/24": [{"protocol": "ospf", "selected": True}, {"protocol": "connected", "selected": False}],
                "10.1.0.0/24": [{"protocol": "bgp", "selected": True}], "10.2.0.0/24": [{"protocol": "ospf", "selected": False}]}
        self.assertEqual(intake._frr_route_counts(doc4, "ipv4")["ospf"], 1)          # pylint: disable=protected-access
        self.assertEqual(intake._frr_route_counts(doc4, "ipv4")["bgp"], 1)           # pylint: disable=protected-access
        doc6 = {"2001:db8::/64": [{"protocol": "ospf6", "selected": True}]}
        self.assertEqual(intake._frr_route_counts(doc6, "ipv6")["ospf3"], 1)         # pylint: disable=protected-access
        self.assertIsNone(intake._frr_route_counts(None, "ipv4"))                    # pylint: disable=protected-access
