"""Direct tests for RIB-based route classification and path reasoning (troubleshooting/routing.py).

Documents are minimal cEOS/FRR JSON shapes.  Unreadable evidence is always INDETERMINATE / INSUFFICIENT / UNKNOWN, never
"no fault", and a learned baseline is labelled as such rather than treated as intent.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase

from core.services.troubleshooting import faults
from core.services.troubleshooting import routing as rt

NOW = datetime(2026, 11, 27, 6, 0, tzinfo=timezone.utc)


def entry(prefix, source="ospf", hops=(("10.0.12.2", "Ethernet1"),), raw="O"):
    return rt.RibEntry(prefix, source, raw, tuple(hops), "ipv6" if ":" in prefix else "ipv4")


RIB = {"10.0.0.0/8": entry("10.0.0.0/8", "static", raw="S"), "10.2.2.0/24": entry("10.2.2.0/24")}


class AdjacencyParserTests(SimpleTestCase):
    def test_adjacency_parsers_skip_absent_or_error_documents(self):
        with self.subTest("an error document yields no ceos sample"):
            self.assertEqual(rt.ceos_adjacency_samples("R1", {"ospf": {"errors": ["not running"]}, "bgp": None}, NOW), [])
        with self.subTest("an empty frr document yields no sample"):
            self.assertEqual(rt.frr_adjacency_samples("R3", {"ospf": {}, "bgp": {"ipv4Unicast": None}}, NOW), [])

    def test_adjacency_parsers_return_one_sample_per_neighbour(self):
        ceos = {"ospf": {"vrfs": {"default": {"instList": {"1": {"ospfNeighborEntries": [
                    {"routerId": "2.2.2.2", "interfaceName": "Ethernet1", "adjacencyState": "full"}]}}}}},
                "bgp": {"vrfs": {"default": {"peers": {"10.0.0.2": {"peerState": "Established"}}}}}}
        self.assertEqual([(s.protocol, s.neighbor, s.state) for s in rt.ceos_adjacency_samples("R1", ceos, NOW)],
                         [("ospf", "2.2.2.2", "full"), ("bgp", "10.0.0.2", "Established")])
        frr = {"ospf": {"neighbors": {"1.1.1.1": [{"nbrState": "Full/DR", "ifaceName": "eth1:10.0.13.3"}]}},
               "bgp": {"ipv4Unicast": {"peers": {"10.0.0.1": {"state": "Established", "peerState": "OK"}}}}}
        self.assertEqual([(s.protocol, s.interface, s.state) for s in rt.frr_adjacency_samples("R3", frr, NOW)],
                         [("ospf", "eth1", "full"), ("bgp", "", "Established")])


class RibTests(SimpleTestCase):
    def test_rib_entry_addresses_interfaces_and_as_dict(self):
        e = entry("10.2.2.0/24", hops=(("10.0.12.2", "Ethernet1"), ("", "Ethernet2"), ("10.0.12.2", "Ethernet3")))
        self.assertEqual((e.addresses, e.interfaces), (["10.0.12.2"], ["Ethernet1", "Ethernet2", "Ethernet3"]))
        self.assertEqual(e.as_dict()["next_hops"][1], {"address": "", "interface": "Ethernet2"})

    def test_lpm_never_matches_another_family_or_an_uncovered_address(self):
        with self.subTest("the most specific prefix wins"):
            self.assertEqual(rt.lpm(RIB, "10.2.2.20").prefix, "10.2.2.0/24")
        with self.subTest("an uncovered address has no match"):
            self.assertIsNone(rt.lpm(RIB, "192.0.2.1"))
        with self.subTest("an ipv6 address never matches an ipv4 route"):
            self.assertIsNone(rt.lpm({"0.0.0.0/0": entry("0.0.0.0/0")}, "2001:db8::1"))

    def test_source_counts_of_an_empty_rib_is_empty(self):
        self.assertEqual(rt.source_counts({}), {})
        self.assertEqual(rt.source_counts(RIB), {"ospf": 1, "static": 1})

    def test_ceos_summary_counts_returns_normalised_sources(self):
        doc = {"vrfs": {"default": {"ospfCounts": {"ospfTotal": 10, "ospfExternal2": 3}, "bgpCounts": {"bgpTotal": 2}, "connected": 4}}}
        out = rt.ceos_summary_counts(doc, "ipv4")
        self.assertEqual((out["ospf"], out["ospf_external"], out["bgp"], out["connected"], out["rip"]), (7, 3, 2, 4, 0))
        six = rt.ceos_summary_counts({"vrfs": {"default": {"ospfCounts6": {"ospfTotal": 5}}}}, "ipv6")
        self.assertEqual((six["ospf3"], "rip" in six), (5, False))

    def test_ceos_summary_counts_of_an_unreadable_document_is_none(self):
        for label, doc in (("no document", None), ("no default vrf", {"vrfs": {}}), ("an error document", {"errors": ["x"]})):
            with self.subTest(f"{label} is unreadable"):
                self.assertIsNone(rt.ceos_summary_counts(doc, "ipv4"))


class ClassificationTests(SimpleTestCase):
    def test_classify_route_change_returns_no_fault_for_the_expected_route(self):
        out = rt.classify_route_change("R1", "10.2.2.0/24", RIB["10.2.2.0/24"], RIB, now=NOW, expectation_source="intent")
        self.assertEqual((out.category, out.cause_status), (faults.NO_FAULT, faults.CAUSE_CONFIRMED))
        as_dict = rt.classify_route_change("R1", "10.2.2.0/24", RIB["10.2.2.0/24"].as_dict() | {"next_hops": [["10.0.12.2", "Ethernet1"]]},
                                           RIB, now=NOW, expectation_source="learned-baseline")
        self.assertEqual(as_dict.evidence["expectation_source"], "learned-baseline")

    def test_classify_source_counts_flags_a_collapsed_or_unreadable_source(self):
        with self.subTest("an unreadable summary is indeterminate"):
            out = rt.classify_source_counts("R1", "ipv4", {"ospf": 10}, None, now=NOW, expectation_source="baseline")
            self.assertEqual([c.category for c in out], [faults.INDETERMINATE])
        with self.subTest("a halved redistributed source is a failure"):
            out = rt.classify_source_counts("R1", "ipv4", {"ospf": 10, "ospf_external": 4}, {"ospf": 9, "ospf_external": 2}, now=NOW,
                                            expectation_source="baseline")
            self.assertEqual([(c.scope["source"], c.evidence["redistribution_related"]) for c in out], [("ospf_external", True)])

    def test_correlate_redistribution_refuses_to_assume_unreadable_readers(self):
        origin = {"10.9.0.0/16": entry("10.9.0.0/16", "bgp")}
        cases = (("an unreadable redistributor", None, {}, "INSUFFICIENT_EVIDENCE"),
                 ("a lost origin", {}, {"R2": {}}, "ORIGIN_LOST"),
                 ("a missing redistribution", origin, {"R2": {}, "R3": {}}, "REDISTRIBUTION_FAULT_DOMAIN"),
                 ("a partial redistribution", origin, {"R2": {}, "R3": {"10.9.0.0/16": entry("10.9.0.0/16", "ospf_external")}}, "PARTIAL"))
        for label, rib, remote, verdict in cases:
            with self.subTest(f"{label} is {verdict}"):
                out = rt.correlate_redistribution("10.9.0.0/16", redistributor="R1", redistributor_rib=rib, origin_sources=["bgp"],
                                                  remote=remote, redistributed_source="ospf_external")
                self.assertEqual(out["verdict"], verdict)
        with self.subTest("an unreadable reader is never assumed consistent"):
            out = rt.correlate_redistribution("10.9.0.0/16", redistributor="R1", redistributor_rib=origin, origin_sources=["bgp"],
                                              remote={"R2": {"10.9.0.0/16": entry("10.9.0.0/16", "ospf_external")}, "R3": None},
                                              redistributed_source="ospf_external")
            self.assertEqual((out["verdict"], out["unreadable"], out["evidence_quality"]), ("CONSISTENT", ["R3"], "PARTIAL"))


PATH = {"verdict": rt.DELIVERED, "hops": [{"device": "R1", "egress": "Ethernet1", "next_device": "R2"},
                                         {"device": "R2", "egress": "Ethernet2", "next_device": "R3"}, {"device": "R3"}]}


class PathTests(SimpleTestCase):
    def test_owner_map_returns_every_owner_of_a_reused_address(self):
        out = rt.owner_map({"R1": {"fe80::1": "eth1", "10.0.0.1": "eth1"}, "R2": {"fe80::1": "eth2"}})
        self.assertEqual(out["fe80::1"], [("R1", "eth1"), ("R2", "eth2")])

    def test_owner_map_of_no_addresses_is_empty(self):
        self.assertEqual(rt.owner_map({"R1": {}}), {})

    def test_path_links_returns_each_resolved_hop(self):
        self.assertEqual(rt.path_links(PATH), [("R1", "Ethernet1", "R2"), ("R2", "Ethernet2", "R3")])

    def test_path_links_of_an_unresolved_path_is_empty(self):
        self.assertEqual(rt.path_links({"hops": [{"device": "R1", "next_device": None}]}), [])

    def test_explain_by_path_refuses_unrecorded_or_untraversed_links(self):
        failed = {"a": "R1", "a_if": "eth1", "b": "R2", "b_if": "eth1"}
        with self.subTest("a symptom without a baseline path is not explained"):
            self.assertFalse(rt.explain_by_path({"flow": "web"}, failed, {})[0])
        with self.subTest("an untraversed link is not explained"):
            self.assertFalse(rt.explain_by_path({"flow": "web"}, {"a": "R4", "a_if": "eth1", "b": "R5", "b_if": "eth1"}, {"web": PATH})[0])
        with self.subTest("a traversed link is explained"):
            self.assertTrue(rt.explain_by_path({"flow": "web"}, failed, {"web": PATH})[0])

    def test_flow_impact_returns_unchanged_rerouted_broken_or_unknown(self):
        rerouted = {"verdict": rt.DELIVERED, "hops": [{"device": "R1", "egress": "Ethernet3", "next_device": "R4"}, {"device": "R4"}]}
        self.assertEqual(rt.flow_impact(PATH, PATH)["impact"], "UNCHANGED")
        self.assertEqual(rt.flow_impact(PATH, rerouted)["impact"], "REROUTED")
        self.assertEqual(rt.flow_impact(PATH, {"verdict": rt.BLACKHOLE, "hops": []})["impact"], "BROKEN")
        self.assertEqual(rt.flow_impact(PATH, None)["impact"], "UNKNOWN")


class EvidenceFreshnessTests(SimpleTestCase):
    def test_evidence_item_fresh_within_its_age(self):
        self.assertTrue(rt.EvidenceItem("R1", "rib", NOW - timedelta(seconds=30)).fresh(NOW))

    def test_evidence_item_stale_future_or_undated_is_not_fresh(self):
        for label, at in (("a stale item", NOW - timedelta(seconds=121)), ("a future item", NOW + timedelta(seconds=5)), ("an undated item", None)):
            with self.subTest(f"{label} is not fresh"):
                self.assertFalse(rt.EvidenceItem("R1", "rib", at).fresh(NOW))

    def test_evidence_quality_returns_complete_partial_or_none(self):
        fresh, stale = rt.EvidenceItem("R1", "rib", NOW), rt.EvidenceItem("R2", "rib", NOW - timedelta(hours=1))
        self.assertEqual(rt.evidence_quality([fresh], now=NOW, required_devices=["R1"])["quality"], "COMPLETE")
        partial = rt.evidence_quality([fresh, stale], now=NOW, required_devices=["R1", "R2"])
        self.assertEqual((partial["quality"], partial["stale"], partial["missing_devices"]), ("PARTIAL", ["R2:rib"], ["R2"]))
        self.assertEqual(rt.evidence_quality([stale], now=NOW, required_devices=["R2"])["quality"], "NONE")
